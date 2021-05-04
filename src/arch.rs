#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as arch;

/// adc computes out <- a + b + carry, outputting a new carry.
///
/// `carry` must be 0, or 1. The return value will satisfy this constraint
#[inline]
pub fn adc(carry: u8, a: u64, b: u64, out: &mut u64) -> u8 {
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
pub fn sbb(borrow: u8, a: u64, b: u64, out: &mut u64) -> u8 {
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
pub fn mulc(carry: u64, a: u64, b: u64, out: &mut u64) -> u64 {
    let full_res = u128::from(a) * u128::from(b) + u128::from(carry);
    *out = full_res as u64;
    (full_res >> 64) as u64
}
