use subtle::ConditionallySelectable;

use crate::arithmetic::Z25519;

#[derive(Debug)]
struct Scalar {
    bytes: [u8; 32],
}

impl Scalar {
    fn act(&self, base_x: Z25519) -> Z25519 {
        let mut x2 = Z25519::from(1);
        let mut z2 = Z25519::from(0);
        let mut x3 = base_x;
        let mut z3 = Z25519::from(1);

        let mut swap: u8 = 0;
        for byte in self.bytes.iter().rev() {
            for j in (0..8).rev() {
                let bit = (byte >> j) & 1;
                swap ^= bit;
                let choice = swap.into();
                Z25519::conditional_swap(&mut x2, &mut x3, choice);
                Z25519::conditional_swap(&mut z2, &mut z3, choice);
                swap = bit;

                let a = x2 + z2;
                let aa = a.squared();
                let b = x2 - z2;
                let bb = b * b;
                let e = aa - bb;
                let c = x3 + z3;
                let d = x3 - z3;
                let da = d * a;
                let cb = c * b;
                x3 = (da + cb).squared();
                z3 = base_x * (da - cb).squared();
                x2 = aa * bb;
                z2 = e * (aa + e * 121665);
            }
        }
        let choice = swap.into();
        Z25519::conditional_swap(&mut x2, &mut x3, choice);
        Z25519::conditional_swap(&mut z2, &mut z3, choice);
        x2 * z2.inverse()
    }
}

impl From<[u8; 32]> for Scalar {
    fn from(bytes: [u8; 32]) -> Self {
        let mut out = Scalar { bytes };
        out.bytes[0] &= 248;
        out.bytes[31] &= 127;
        out.bytes[31] |= 64;
        out
    }
}

impl From<&[u8]> for Scalar {
    fn from(bytes: &[u8]) -> Self {
        if bytes.len() < 32 {
            panic!(
                "Expected at least 32 bytes to make Scalar, found: {}",
                bytes.len()
            );
        }
        let mut owned = [0u8; 32];
        owned.copy_from_slice(&bytes[..32]);
        Scalar::from(owned)
    }
}

pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let scalar = Scalar::from(*scalar);
    let mut point_bytes = *point;
    point_bytes[31] &= 0x7F;
    let point = Z25519::from(point_bytes);
    scalar.act(point).into()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_vector_1() {
        let scalar_bytes = [
            0xA5, 0x46, 0xE3, 0x6B, 0xF0, 0x52, 0x7C, 0x9D, 0x3B, 0x16, 0x15, 0x4B, 0x82, 0x46,
            0x5E, 0xDD, 0x62, 0x14, 0x4C, 0x0A, 0xC1, 0xFC, 0x5A, 0x18, 0x50, 0x6A, 0x22, 0x44,
            0xBA, 0x44, 0x9A, 0xC4,
        ];
        let point_bytes = [
            0xE6, 0xDB, 0x68, 0x67, 0x58, 0x30, 0x30, 0xDB, 0x35, 0x94, 0xC1, 0xA4, 0x24, 0xB1,
            0x5F, 0x7C, 0x72, 0x66, 0x24, 0xEC, 0x26, 0xB3, 0x35, 0x3B, 0x10, 0xA9, 0x03, 0xA6,
            0xD0, 0xAB, 0x1C, 0x4C,
        ];
        let expected = [
            0xC3, 0xDA, 0x55, 0x37, 0x9D, 0xE9, 0xC6, 0x90, 0x8E, 0x94, 0xEA, 0x4D, 0xF2, 0x8D,
            0x08, 0x4F, 0x32, 0xEC, 0xCF, 0x03, 0x49, 0x1C, 0x71, 0xF7, 0x54, 0xB4, 0x07, 0x55,
            0x77, 0xA2, 0x85, 0x52,
        ];
        assert_eq!(expected, x25519(&scalar_bytes, &point_bytes));
    }

    #[test]
    fn test_vector_2() {
        let scalar_bytes = [
            0x4B, 0x66, 0xE9, 0xD4, 0xD1, 0xB4, 0x67, 0x3C, 0x5A, 0xD2, 0x26, 0x91, 0x95, 0x7D,
            0x6A, 0xF5, 0xC1, 0x1B, 0x64, 0x21, 0xE0, 0xEA, 0x01, 0xD4, 0x2C, 0xA4, 0x16, 0x9E,
            0x79, 0x18, 0xBA, 0x0D,
        ];
        let point_bytes = [
            0xE5, 0x21, 0x0F, 0x12, 0x78, 0x68, 0x11, 0xD3, 0xF4, 0xB7, 0x95, 0x9D, 0x05, 0x38,
            0xAE, 0x2C, 0x31, 0xDB, 0xE7, 0x10, 0x6F, 0xC0, 0x3C, 0x3E, 0xFC, 0x4C, 0xD5, 0x49,
            0xC7, 0x15, 0xA4, 0x93,
        ];
        let expected = [
            0x95, 0xCB, 0xDE, 0x94, 0x76, 0xE8, 0x90, 0x7D, 0x7A, 0xAD, 0xE4, 0x5C, 0xB4, 0xB8,
            0x73, 0xF8, 0x8B, 0x59, 0x5A, 0x68, 0x79, 0x9F, 0xA1, 0x52, 0xE6, 0xF8, 0xF7, 0x64,
            0x7A, 0xAC, 0x79, 0x57,
        ];
        assert_eq!(expected, x25519(&scalar_bytes, &point_bytes));
    }
}
