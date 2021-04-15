use std::ops::{Add, AddAssign};

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as arch;

/// adc computes out <- a + b + carry, outputting a new carry.
///
/// While carry is a `u8`, it should only be 0, or 1. The output also
/// satisfies this constraint.
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

impl From<u64> for Z25519 {
    fn from(x: u64) -> Self {
        Z25519 {
            limbs: [x, 0, 0, 0],
        }
    }
}

impl AddAssign for Z25519 {
    fn add_assign(&mut self, rhs: Z25519) {
        let mut carry: u8 = 0;
        // Let's have confidence in Rust's ability to unroll this loop
        for i in 0..4 {
            carry = adc(carry, self.limbs[i], rhs.limbs[i], &mut self.limbs[i]);
        }
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
// it's convenient to be able to do arithmetic using it
const P25519: Z25519 = Z25519 {
    limbs: [
        0xFFFF_FFFF_FFFF_FFED,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0x7FFF_FFFF_FFFF_FFFF,
    ],
};

mod test {
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
        assert_eq!(z3, z1 + z2)
    }
}
