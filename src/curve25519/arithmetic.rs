use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::{
    array::TryFromSliceError,
    convert::{TryFrom, TryInto},
};
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
    pub limbs: [u64; 4],
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

    /// reduce_after_scaling reduces this element modulo P, after a scaling.
    ///
    /// After a scaling, this number fits over 5 limbs, and there's an efficient way
    /// to reduce it modulo P.
    fn reduce_after_scaling(&mut self, carry: u64) {
        // Let's say that:
        //     A = q⋅2²⁵⁵ + R
        // This means that:
        //     A = q⋅P + R + 19q
        // Modulo P, this entails:
        //     A ≡ R + 19q mod P
        // We can efficiently calculate q and R using shifting and masking.

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

    /// calculate z <- z * z mod P.
    ///
    /// This is equivalent to z *= z, but is a bit more efficient, because it takes
    /// advantage of the extra symmetry of this operation compared to the general case.
    pub fn square(&mut self) {
        // This function acts as a slight modification of `mul_assign`, doing doublings
        // in some places to take advantage of symmetry.

        // This calculates u:v = a * b, and then adds u:v to r2:r1:r0
        #[inline(always)]
        fn multiply_in(a: u64, b: u64, r0: &mut u64, r1: &mut u64, r2: &mut u64) {
            let uv = u128::from(a) * u128::from(b);
            let mut carry = 0;
            carry = adc(carry, uv as u64, *r0, r0);
            carry = adc(carry, (uv >> 64) as u64, *r1, r1);
            *r2 += u64::from(carry);
        }

        #[inline(always)]
        fn double_multiply_in(a: u64, b: u64, r0: &mut u64, r1: &mut u64, r2: &mut u64) {
            let mut uv = u128::from(a) * u128::from(b);
            let uv_top = (uv >> 127) as u64;
            uv <<= 1;
            let mut carry = 0;
            carry = adc(carry, uv as u64, *r0, r0);
            carry = adc(carry, (uv >> 64) as u64, *r1, r1);
            *r2 += u64::from(carry) + uv_top;
        }

        // Given r2:r1:r0, this sets limb = r0, and then shifts to get 0:r2:r1
        #[inline(always)]
        fn propagate(limb: &mut u64, r0: &mut u64, r1: &mut u64, r2: &mut u64) {
            *limb = *r0;
            *r0 = *r1;
            *r1 = *r2;
            *r2 = 0;
        }

        // See `mul_assign`.
        let mut low = Z25519::from(0);

        // This is essentially a 192 bit number
        let mut r0 = 0u64;
        let mut r1 = 0u64;
        let mut r2 = 0u64;

        // See `mul_assign`.

        multiply_in(self.limbs[0], self.limbs[0], &mut r0, &mut r1, &mut r2);
        propagate(&mut low.limbs[0], &mut r0, &mut r1, &mut r2);

        double_multiply_in(self.limbs[0], self.limbs[1], &mut r0, &mut r1, &mut r2);
        propagate(&mut low.limbs[1], &mut r0, &mut r1, &mut r2);

        double_multiply_in(self.limbs[0], self.limbs[2], &mut r0, &mut r1, &mut r2);
        multiply_in(self.limbs[1], self.limbs[1], &mut r0, &mut r1, &mut r2);
        propagate(&mut low.limbs[2], &mut r0, &mut r1, &mut r2);

        double_multiply_in(self.limbs[0], self.limbs[3], &mut r0, &mut r1, &mut r2);
        double_multiply_in(self.limbs[1], self.limbs[2], &mut r0, &mut r1, &mut r2);
        propagate(&mut low.limbs[3], &mut r0, &mut r1, &mut r2);

        double_multiply_in(self.limbs[1], self.limbs[3], &mut r0, &mut r1, &mut r2);
        multiply_in(self.limbs[2], self.limbs[2], &mut r0, &mut r1, &mut r2);
        propagate(&mut self.limbs[0], &mut r0, &mut r1, &mut r2);

        double_multiply_in(self.limbs[2], self.limbs[3], &mut r0, &mut r1, &mut r2);
        propagate(&mut self.limbs[1], &mut r0, &mut r1, &mut r2);

        multiply_in(self.limbs[3], self.limbs[3], &mut r0, &mut r1, &mut r2);
        propagate(&mut self.limbs[2], &mut r0, &mut r1, &mut r2);

        self.limbs[3] = r0;

        // See `mul_assign`.
        let mut carry = 0u64;
        for i in 0..4 {
            let full_res =
                u128::from(carry) + u128::from(low.limbs[i]) + 38 * u128::from(self.limbs[i]);
            self.limbs[i] = full_res as u64;
            carry = (full_res >> 64) as u64;
        }
        self.reduce_after_scaling(carry);
    }

    // inverse calculates self^-1 mod P, a number which multiplied by self returns 1
    //
    // This will work for every valid number, except 0.
    pub fn inverse(self) -> Z25519 {
        // By Fermat, we know that self ^ (P - 2) is an inverse.
        // We can do binary exponentiation, using the fact that we have
        // 0b01011, and then 250 one bits.
        let mut out = Z25519::from(1);
        let mut current_power = self;
        // Handling 0b01011
        out *= current_power;
        current_power.square();
        out *= current_power;
        current_power.square();
        current_power.square();
        out *= current_power;
        current_power.square();
        current_power.square();
        // Now, 250 one bits
        for _ in 0..250 {
            out *= current_power;
            current_power.square();
        }
        out
    }
}

impl From<[u8; 32]> for Z25519 {
    /// Convert 32 bytes into a Z25519.
    ///
    /// The MSB of these bytes is ignored, as per convention for x25519
    fn from(mut bytes: [u8; 32]) -> Self {
        let mut out = Z25519 { limbs: [0; 4] };
        bytes[31] &= 0x7F;
        for (i, chunk) in bytes.chunks_exact(8).enumerate() {
            out.limbs[i] = u64::from_le_bytes(chunk.try_into().unwrap())
        }
        out.reduce_after_addition(0);
        out
    }
}

impl Into<[u8; 32]> for Z25519 {
    fn into(self) -> [u8; 32] {
        let mut out = [0; 32];
        let mut i = 0;
        for limb in &self.limbs {
            for &b in &limb.to_le_bytes() {
                out[i] = b;
                i += 1;
            }
        }
        out
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

impl Neg for Z25519 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        // NOTE: Hopefully Rust inlines things, to avoid materializing 4 zeros in memory
        Self::from(0) - self
    }
}

impl MulAssign<u64> for Z25519 {
    fn mul_assign(&mut self, small: u64) {
        // First, multiply this number by small
        let mut carry = 0;
        // Hopefully this gets unrolled
        for i in 0..4 {
            carry = mulc(carry, small, self.limbs[i], &mut self.limbs[i]);
        }
        self.reduce_after_scaling(carry);
    }
}

impl Mul<u64> for Z25519 {
    type Output = Z25519;

    fn mul(mut self, small: u64) -> Self::Output {
        self *= small;
        self
    }
}

impl MulAssign for Z25519 {
    fn mul_assign(&mut self, other: Z25519) {
        // You can treat both of these functions as macros. They just exist to avoid
        // repeating this logic multiple times.

        // This calculates u:v = a * b, and then adds u:v to r2:r1:r0
        #[inline(always)]
        fn multiply_in(a: u64, b: u64, r0: &mut u64, r1: &mut u64, r2: &mut u64) {
            let uv = u128::from(a) * u128::from(b);
            let mut carry = 0;
            carry = adc(carry, uv as u64, *r0, r0);
            carry = adc(carry, (uv >> 64) as u64, *r1, r1);
            *r2 += u64::from(carry);
        }

        // Given r2:r1:r0, this sets limb = r0, and then shifts to get 0:r2:r1
        #[inline(always)]
        fn propagate(limb: &mut u64, r0: &mut u64, r1: &mut u64, r2: &mut u64) {
            *limb = *r0;
            *r0 = *r1;
            *r1 = *r2;
            *r2 = 0;
        }

        // We need 8 limbs to hold the full multiplication result, so we need an
        // extra buffer. By using the extra buffer to store the low limbs,
        // we can clobber self with the high limbs, without overwriting any limbs
        // necessary for further calculations.
        let mut low = Z25519::from(0);

        // This is essentially a 192 bit number
        let mut r0 = 0u64;
        let mut r1 = 0u64;
        let mut r2 = 0u64;

        // This is an unrolling of big loop that looks like:
        //    for k = 0..6
        //      for i in 0..3, j in 0..3 with i + j = k:
        //        multiply_in(self[i], other[j])
        //      propagate(out[k])
        //    propagate(out[7])
        //
        // The rough idea here is to add in all of the factors that contribute to a given
        // limb of the output, adding in carries from the previous step, and then propagating
        // a carry to the next step.

        multiply_in(self.limbs[0], other.limbs[0], &mut r0, &mut r1, &mut r2);
        propagate(&mut low.limbs[0], &mut r0, &mut r1, &mut r2);

        multiply_in(self.limbs[0], other.limbs[1], &mut r0, &mut r1, &mut r2);
        multiply_in(self.limbs[1], other.limbs[0], &mut r0, &mut r1, &mut r2);
        propagate(&mut low.limbs[1], &mut r0, &mut r1, &mut r2);

        multiply_in(self.limbs[0], other.limbs[2], &mut r0, &mut r1, &mut r2);
        multiply_in(self.limbs[1], other.limbs[1], &mut r0, &mut r1, &mut r2);
        multiply_in(self.limbs[2], other.limbs[0], &mut r0, &mut r1, &mut r2);
        propagate(&mut low.limbs[2], &mut r0, &mut r1, &mut r2);

        multiply_in(self.limbs[0], other.limbs[3], &mut r0, &mut r1, &mut r2);
        multiply_in(self.limbs[1], other.limbs[2], &mut r0, &mut r1, &mut r2);
        multiply_in(self.limbs[2], other.limbs[1], &mut r0, &mut r1, &mut r2);
        multiply_in(self.limbs[3], other.limbs[0], &mut r0, &mut r1, &mut r2);
        propagate(&mut low.limbs[3], &mut r0, &mut r1, &mut r2);

        multiply_in(self.limbs[1], other.limbs[3], &mut r0, &mut r1, &mut r2);
        multiply_in(self.limbs[2], other.limbs[2], &mut r0, &mut r1, &mut r2);
        multiply_in(self.limbs[3], other.limbs[1], &mut r0, &mut r1, &mut r2);
        propagate(&mut self.limbs[0], &mut r0, &mut r1, &mut r2);

        multiply_in(self.limbs[2], other.limbs[3], &mut r0, &mut r1, &mut r2);
        multiply_in(self.limbs[3], other.limbs[2], &mut r0, &mut r1, &mut r2);
        propagate(&mut self.limbs[1], &mut r0, &mut r1, &mut r2);

        multiply_in(self.limbs[3], other.limbs[3], &mut r0, &mut r1, &mut r2);
        propagate(&mut self.limbs[2], &mut r0, &mut r1, &mut r2);

        self.limbs[3] = r0;

        // At this point, we've multiplied things out, and have:
        //     self⋅2²⁵⁶ + low
        // Observe that 2²⁵⁶ = 2⋅(2²⁵⁵ - 19) + 38, so mod P, we have:
        //     low + 38⋅self
        // All that's left is to multiply self by 38, and then add in low
        let mut carry = 0u64;
        for i in 0..4 {
            let full_res =
                u128::from(carry) + u128::from(low.limbs[i]) + 38 * u128::from(self.limbs[i]);
            self.limbs[i] = full_res as u64;
            carry = (full_res >> 64) as u64;
        }
        self.reduce_after_scaling(carry);
    }
}

impl Mul for Z25519 {
    type Output = Z25519;

    fn mul(mut self, other: Z25519) -> Self::Output {
        self *= other;
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

    proptest! {
        #[test]
        fn test_multiplying_scaling(a in arb_z25519(), u in any::<u32>(), v in any::<u32>()) {
            let u = u as u64;
            let v = v as u64;
            assert_eq!((a * u) * v, a * (u * v))
        }
    }

    proptest! {
        #[test]
        fn test_adding_scaling(a in arb_z25519(), u in 0..(1u64 << 63), v in 0..(1u64 << 63)) {
            assert_eq!(a * (u + v), a * u + a * v)
        }
    }

    proptest! {
        #[test]
        fn test_adding_negation(a in arb_z25519()) {
            assert_eq!(a + -a, 0.into())
        }
    }

    proptest! {
        #[test]
        fn test_multiplication_commutative(a in arb_z25519(), b in arb_z25519()) {
            assert_eq!(a * b, b * a);
        }
    }

    proptest! {
        #[test]
        fn test_multiplication_associative(a in arb_z25519(), b in arb_z25519(), c in arb_z25519()) {
            assert_eq!(a * (b * c), (a * b) * c);
        }
    }

    proptest! {
        #[test]
        fn test_multiplication_distributive(a in arb_z25519(), b in arb_z25519(), c in arb_z25519()) {
            assert_eq!(a * (b + c), a * b + a * c);
        }
    }

    proptest! {
        #[test]
        fn test_multiply_one_identity(a in arb_z25519()) {
            let one = Z25519::from(1);
            assert_eq!(a * one, a);
            assert_eq!(one * a, a);
        }
    }

    proptest! {
        #[test]
        fn test_multiply_minus_one_is_negation(a in arb_z25519()) {
            let minus_one = -Z25519::from(1);
            assert_eq!(minus_one * a, -a);
            assert_eq!(a * minus_one, -a);
        }
    }

    proptest! {
        #[test]
        fn test_square_is_multiply(a in arb_z25519()) {
            let mut squared = a;
            squared.square();
            assert_eq!(squared, a * a);
        }
    }

    proptest! {
        #[test]
        fn test_inverse(
            a in arb_z25519()
                .prop_filter(
                    "zero cannot be inverted".to_owned(),
                    |x: &Z25519| *x != 0.into()
                )
        ) {
            assert_eq!(a * a.inverse(), 1.into());
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

    #[test]
    fn test_2192_times_zero() {
        let two192 = Z25519 {
            limbs: [0, 0, 0, 1],
        };
        assert_eq!(two192 * Z25519::from(0), 0.into());
    }

    #[test]
    fn test_minus_one_squared() {
        let mut minus_one = Z25519::from(0) - Z25519::from(1);
        minus_one.square();
        assert_eq!(minus_one, 1.into());
    }

    #[test]
    fn test_two_255() {
        let two_254 = Z25519 {
            limbs: [0, 0, 0, 0x4000000000000000],
        };
        assert_eq!(two_254 * Z25519::from(2), 19.into());
    }

    #[test]
    fn test_byte_conversion() {
        let mut one = [0; 32];
        one[0] = 1;
        assert_eq!(Z25519::from(one), Z25519::from(1));
        let mut two255minus_one = [0xFF; 32];
        two255minus_one[31] = 0x7F;
        assert_eq!(Z25519::from(two255minus_one), Z25519::from(18));
    }
}
