use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as arch;

/// adc computes out <- a + b + carry, outputting a new carry.
///
/// `carry` must be 0, or 1. The return value will satisfy this constraint
#[inline]
fn adc(carry: u8, a: u64, b: u64, out: &mut u64) -> u8 {
    #[cfg(target_arch = "x86_64")]
    {
        // Using this intrinsic is perfectly safe
        unsafe { arch::_addcarry_u64(carry, a, b, out) }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // The largest result is 2 * (2^64 - 1) + 1 = 2^65 - 1, which needs exactly 65 bits
        // Hence, we use u128. Hopefully, Rust will realize that we don't really want to use
        // 128 bit operations, but rather want to use an `adc` instruction, or whatever equivalent
        // our ISA has, and insert that instead.
        let full_res = u128::from(a) + u128::from(b) + u128::from(carry);
        *out = full_res as u64;
        (full_res >> 64) as u8
    }
}

/// sbb computes out <- a - b - borrow, outputting a new borrow value
///
/// `borrow` must be 0, or 1. The return value will satisfy this constraint
#[inline]
fn sbb(borrow: u8, a: u64, b: u64, out: &mut u64) -> u8 {
    #[cfg(target_arch = "x86_64")]
    {
        // Using this intrinsic is perfectly safe
        unsafe { arch::_subborrow_u64(borrow, a, b, out) }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // Like with addition, we use a larger type to be able to have carry information
        // We also hope that Rust can figure out what we're doing, and replace this
        // sequence with an `sbb` instruction
        let full_res = i128::from(a) - i128::from(b) - i128::from(borrow);
        *out = full_res as u64;
        // NOTE: This might leak with odd code generation?
        // If this compiles to a branch instruction, then that would be an issue
        u8::from(full_res < 0)
    }
}

/// mulc computs out <- a * b + carry, outputting a new carry limb
#[inline]
fn mulc(carry: u64, a: u64, b: u64, out: &mut u64) -> u64 {
    let full_res = u128::from(a) * u128::from(b) + u128::from(carry);
    *out = full_res as u64;
    (full_res >> 64) as u64
}

/// Represents an element in the field Z/(2^255 - 19).
///
/// The operations in this field are defined through arithmetic modulo
/// P := 2^255 - 19
///
/// # Creation
///
/// Elements in the field can be created from `u64`:
///
/// ```
/// let z = Z25519::from(48662);
/// ```
#[derive(Clone, Copy, Debug)]
// Only implement equality for tests. This is to avoid the temptation to introduce
// a timing leak through equality comparison.
#[cfg_attr(test, derive(PartialEq))]
pub struct Z25519 {
    // This corresponds to a 4 "digit" number in base 2^64:
    //    limbs[3] * 2^192 + limbs[2] * 2^128 + limbs[1] * 2^64 + limbs[0]
    limbs: [u64; 4],
}

impl Z25519 {
    /// sub_with_borrow subtracts other from this elements in place, returning a borrow
    ///
    /// A borrow is generated (returning 1), when this subtraction underflows.
    fn sub_with_borrow(&mut self, other: Z25519) -> u8 {
        let mut borrow = 0;
        // Hopefully Rust unrolls this loop
        for i in 0..4 {
            // Each intermediate subtraction may underflow that limb, produces a borrow
            // which we need to daisy chain through the other subtractions.
            borrow = sbb(borrow, self.limbs[i], other.limbs[i], &mut self.limbs[i]);
        }
        borrow
    }

    /// cond_add adds another field element into this one, if choice is set.
    ///
    /// If choice is not set, then this function has no effect.
    ///
    /// This is done without leaking whether or not the addition happened.
    fn cond_add(&mut self, other: Z25519, choice: Choice) {
        let mut carry = 0;
        for i in 0..4 {
            // When choice is not set, we just add 0 each time, doing nothing
            let to_add = u64::conditional_select(&0, &other.limbs[i], choice);
            carry = adc(carry, self.limbs[i], to_add, &mut self.limbs[i]);
        }
    }

    /// reduce_after_addition reduces this element modulo P, after an addition.
    ///
    /// After an addition, we have at most 2P - 2, so at most one subtraction of P suffices.
    fn reduce_after_addition(&mut self, carry: u8) {
        let mut m_removed = *self;
        // The largest result we've just calculated is 2P - 2. Therefore, we might
        // need to subtract P once, if we have a result >= P.
        let borrow = m_removed.sub_with_borrow(P25519);
        // A few cases here:
        //
        // carry = 1, borrow = 0:
        //    Impossible: we would need a result ≥ 2²⁵⁶ + P
        // carry = 1, borrow = 1:
        //     We produced a result larger than 2^256, with an extra bit, so certainly
        //     we should subtract P. This will always produce a borrow, given our input ranges.
        // carry = 0, borrow = 1:
        //     Our result fits over 4 limbs, but is < P.
        //     We don't want to choose the subtraction
        // carry = 0, borrow = 0:
        //     Our result fits over 4 limbs, but is ≥ P.
        //     We want to choose the subtraction.
        self.conditional_assign(&m_removed, borrow.ct_eq(&carry))
    }
}

impl From<u64> for Z25519 {
    fn from(x: u64) -> Self {
        Z25519 {
            limbs: [x, 0, 0, 0],
        }
    }
}

impl ConditionallySelectable for Z25519 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Z25519 {
            limbs: [
                u64::conditional_select(&a.limbs[0], &b.limbs[0], choice),
                u64::conditional_select(&a.limbs[1], &b.limbs[1], choice),
                u64::conditional_select(&a.limbs[2], &b.limbs[2], choice),
                u64::conditional_select(&a.limbs[3], &b.limbs[3], choice),
            ],
        }
    }
}

impl AddAssign for Z25519 {
    fn add_assign(&mut self, other: Z25519) {
        let mut carry: u8 = 0;
        // Let's have confidence in Rust's ability to unroll this loop.
        for i in 0..4 {
            // Each intermediate result may generate up to 65 bits of output.
            // We need to daisy-chain the carries together, to get the right result.
            carry = adc(carry, self.limbs[i], other.limbs[i], &mut self.limbs[i]);
        }
        self.reduce_after_addition(carry);
    }
}

impl Add for Z25519 {
    type Output = Self;

    fn add(mut self, other: Z25519) -> Self::Output {
        self += other;
        self
    }
}

impl SubAssign for Z25519 {
    fn sub_assign(&mut self, other: Z25519) {
        // We perform the subtraction, and then add back P if we underflowed.
        let borrow = self.sub_with_borrow(other);
        self.cond_add(P25519, borrow.ct_eq(&1));
    }
}

impl Sub for Z25519 {
    type Output = Self;

    fn sub(mut self, other: Z25519) -> Self::Output {
        self -= other;
        self
    }
}

impl MulAssign<u64> for Z25519 {
    fn mul_assign(&mut self, small: u64) {
        // Let's say that:
        //     s⋅A = q⋅2²⁵⁵ + R
        // This means that:
        //     s⋅A = q⋅P + R + 19q
        // Modulo P, this entails:
        //     s⋅A ≡ R + 19q mod P
        // We can efficiently calculate k and R using shifting and masking.
        // Note that q ≤ s, so 19q fits over 2 limbs, and the addition can
        // be reduced by subtracting P at most once.

        // First, multiply this number by small
        let mut carry = 0;
        // Hopefully this gets unrolled
        for i in 0..4 {
            carry = mulc(carry, small, self.limbs[i], &mut self.limbs[i]);
        }
        // We pull in one bit from the top limb, in order to calculate the quotient
        let q = (carry << 1) | (self.limbs[3] >> 63);
        // Clear the top bit, thus calculating R
        self.limbs[3] &= 0x7FFF_FFFF_FFFF_FFFF;
        // Now we add in 19q
        let full_res = 19 * u128::from(q);
        let mut carry = 0;
        carry = adc(carry, full_res as u64, self.limbs[0], &mut self.limbs[0]);
        carry = adc(
            carry,
            (full_res >> 64) as u64,
            self.limbs[1],
            &mut self.limbs[1],
        );
        carry = adc(carry, 0, self.limbs[2], &mut self.limbs[2]);
        carry = adc(carry, 0, self.limbs[3], &mut self.limbs[3]);
        // Now remove P if necessary
        self.reduce_after_addition(carry);
    }
}

impl Mul<u64> for Z25519 {
    type Output = Z25519;

    fn mul(mut self, small: u64) -> Self::Output {
        self *= small;
        self
    }
}

// The prime number 2^255 - 19.
//
// We have this around, because for some operations, like modular addition,
// it's convenient to be able to do arithmetic using it.
const P25519: Z25519 = Z25519 {
    limbs: [
        0xFFFF_FFFF_FFFF_FFED,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0x7FFF_FFFF_FFFF_FFFF,
    ],
};

#[cfg(test)]
mod test {
    use super::Z25519;
    use proptest::prelude::*;

    prop_compose! {
        fn arb_z25519()(
            z0 in 0..(!0u64 - 19),
            z1 in any::<u64>(),
            z2 in any::<u64>(),
            z3 in 0..((1u64 << 63) - 19)) -> Z25519 {
            Z25519 {
                limbs: [z0, z1, z2, z3]
            }
        }
    }

    proptest! {
        #[test]
        fn test_addition_commutative(a in arb_z25519(), b in arb_z25519()) {
            assert_eq!(a + b, b + a);
        }
    }

    proptest! {
        #[test]
        fn test_addition_associative(a in arb_z25519(), b in arb_z25519(), c in arb_z25519()) {
            assert_eq!(a + (b + c), (a + b) + c);
        }
    }

    proptest! {
        #[test]
        fn test_add_zero_identity(a in arb_z25519()) {
            let zero = Z25519::from(0);
            assert_eq!(a + zero, a);
            assert_eq!(zero + a, a);
        }
    }

    proptest! {
        #[test]
        fn test_subtract_self_is_zero(a in arb_z25519()) {
            assert_eq!(a - a, 0.into());
        }
    }

    proptest! {
        #[test]
        fn test_doubling_is_just_addition(a in arb_z25519()) {
            assert_eq!(a * 2, a + a);
        }
    }

    #[test]
    fn test_addition_examples() {
        let z1 = Z25519 {
            limbs: [1, 1, 1, 1],
        };
        let z2 = Z25519 {
            limbs: [2, 2, 2, 2],
        };
        let z3 = Z25519 {
            limbs: [3, 3, 3, 3],
        };
        assert_eq!(z3, z1 + z2);

        let two_254 = Z25519 {
            limbs: [0, 0, 0, 1 << 62],
        };
        assert_eq!(two_254 + two_254, Z25519::from(19));
    }

    #[test]
    fn test_subtraction_examples() {
        let mut z1 = Z25519 {
            limbs: [1, 1, 1, 1],
        };
        z1 -= z1;
        assert_eq!(z1, 0.into());
        z1 -= 1.into();
        let p_minus_one = Z25519 {
            limbs: [
                0xFFFF_FFFF_FFFF_FFEC,
                0xFFFF_FFFF_FFFF_FFFF,
                0xFFFF_FFFF_FFFF_FFFF,
                0x7FFF_FFFF_FFFF_FFFF,
            ],
        };
        assert_eq!(z1, p_minus_one);
    }

    #[test]
    fn test_small_multiplication_examples() {
        let z1 = Z25519 { limbs: [1; 4] };
        assert_eq!(z1 + z1, z1 * 2);
        assert_eq!(z1 + z1 + z1, z1 * 3);
        let p_minus_one = Z25519 {
            limbs: [
                0xFFFF_FFFF_FFFF_FFEC,
                0xFFFF_FFFF_FFFF_FFFF,
                0xFFFF_FFFF_FFFF_FFFF,
                0x7FFF_FFFF_FFFF_FFFF,
            ],
        };
        assert_eq!(p_minus_one * 2, p_minus_one - 1.into());
        assert_eq!(p_minus_one * 3, p_minus_one - 2.into());
    }
}
