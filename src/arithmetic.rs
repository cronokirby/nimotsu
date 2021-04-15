use std::ops::{Add, AddAssign};
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
    /// Return a field element initialized to zero
    pub fn zero() -> Z25519 {
        Z25519 { limbs: [0; 4] }
    }

    fn sub_with_borrow(self, other: Z25519) -> (u8, Z25519) {
        let mut out = Self::zero();
        let mut borrow = 0;
        // Hopefully Rust unrolls this loop
        for i in 0..4 {
            borrow = sbb(borrow, self.limbs[i], other.limbs[i], &mut out.limbs[i]);
        }
        (borrow, out)
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
        // The largest result we've just calculated is 2P - 2. Therefore, we might
        // need to subtract P once, if we have a result >= P. 
        let (borrow, m_removed) = self.sub_with_borrow(P25519);
        // A few cases here:
        //
        // carry = 1, borrow = 0:
        //    Impossible: we would need a result >= 2^256 + P
        // carry = 1, borrow = 1:
        //     We produced a result larger than 2^256, with an extra bit, so certainly
        //     we should subtract P. This will always produce a borrow, given our input ranges.
        // carry = 0, borrow = 1:
        //     Our result fits over 4 limbs, but is < P.
        //     We don't want to choose the subtraction
        // carry = 0, borrow = 0:
        //     Our result fits over 4 limbs, but is >= P.
        //     We want to choose the subtraction.
        self.conditional_assign(&m_removed, borrow.ct_eq(&carry))
    }
}

impl Add for Z25519 {
    type Output = Self;

    fn add(self, rhs: Z25519) -> Self::Output {
        let mut out = self;
        out += rhs;
        out
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

    #[test]
    fn test_addition() {
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

        let two_254 =  Z25519 {
            limbs: [
                0,
                0,
                0,
                1 << 62
            ]
        };
        assert_eq!(two_254 + two_254, Z25519::from(19));
    }
}
