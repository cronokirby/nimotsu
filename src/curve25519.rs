use subtle::{Choice, ConditionallySelectable};

use crate::arithmetic::Z25519;

#[derive(Clone, Copy, Debug)]
pub struct Projective {
    x: Z25519,
    z: Z25519,
}

impl Projective {
    fn new(x: Z25519, z: Z25519) -> Self {
        Projective { x, z }
    }

    pub fn project(&self) -> Z25519 {
        self.x * self.z.inverse()
    }
}

impl ConditionallySelectable for Projective {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Projective {
            x: Z25519::conditional_select(&a.x, &b.x, choice),
            z: Z25519::conditional_select(&a.z, &b.z, choice),
        }
    }
}

fn double_and_add(base_x: Z25519, pn: &Projective, pn1: &Projective) -> (Projective, Projective) {
    let double = Projective {
        x: (pn.x.squared() - pn.z.squared()).squared(),
        z: pn.x * pn.z * (pn.x.squared() + pn.x * pn.z * 486662 + pn.z.squared()) * 4,
    };
    let add = Projective {
        x: (pn.x * pn1.x - pn.z * pn1.z).squared() * 4,
        z: (pn.x * pn1.z - pn.z * pn1.x).squared() * base_x * 4,
    };
    (double, add)
}

#[derive(Debug)]
pub struct Scalar {
    bytes: [u8; 32],
}

impl Scalar {
    pub fn act(&self, base_x: Z25519) -> Projective {
        let mut pn = Projective::new(1.into(), 0.into());
        let mut pn1 = Projective::new(base_x, 1.into());
        let mut swap: u8 = 0;
        for byte in self.bytes.iter().rev() {
            for j in (0..8).rev() {
                let bit = (byte >> j) & 1;
                println!("bit {:X?} pn {:X?} pn1 {:X?}", bit, pn, pn1);
                swap ^= bit;
                Projective::conditional_swap(&mut pn, &mut pn1, swap.into());
                swap = bit;
                let (out1, out2) = double_and_add(base_x, &pn, &pn1);
                pn = out1;
                pn1 = out2;
            }
        }
        println!("pn {:X?} pn1 {:X?}", pn, pn1);
        Projective::conditional_select(&pn, &pn1, swap.into())
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
