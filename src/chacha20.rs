use rand::{CryptoRng, RngCore};
use std::convert::TryInto;
use subtle::{Choice, ConditionallySelectable};

use crate::arch::{adc, sbb};
/// A number that should only be used for a single encryption.
///
/// For the purposes of this crate, randomly generating it is fine,
/// since we encrypt things with ephemeral keys. Otherwise, you'd
/// probably want to use XChaCha20 instead, to allow a larger nonce
#[derive(Debug)]
pub struct Nonce {
    pub bytes: [u8; 12],
}

impl Nonce {
    /// Generate a Nonce randomly
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0; 12];
        rng.fill_bytes(&mut bytes);
        Nonce { bytes }
    }
}

/// A key to use for symmetric encryption.
#[derive(Debug)]
pub struct Key {
    pub bytes: [u8; 32],
}

/// Converting from bytes to words is somewhat tedious, but incrementing the counter word
/// is much easier. By using InitialState, we can keep around a block used to initialize
/// each step of our mixing state. ChaCha20 also requires us to add the mixed state
/// with the initial state of that step, making the use of this struct even more natural.
#[derive(Debug)]
struct InitialState([u32; 16]);

impl InitialState {
    /// Initialize this state with a nonce, a key, and a starting count
    fn new(nonce: &Nonce, key: &Key, starting_count: u32) -> Self {
        let mut out = [0; 16];
        out[0] = 0x61707865;
        out[1] = 0x3320646e;
        out[2] = 0x79622d32;
        out[3] = 0x6b206574;
        for (i, chunk) in key.bytes.chunks_exact(4).enumerate() {
            out[4 + i] = u32::from_le_bytes(chunk.try_into().unwrap())
        }
        out[12] = starting_count;
        for (i, chunk) in nonce.bytes.chunks_exact(4).enumerate() {
            out[13 + i] = u32::from_le_bytes(chunk.try_into().unwrap())
        }
        InitialState(out)
    }

    /// Increment the counter contained in this state.
    ///
    /// This should be done as we encrypt each block in our data.
    fn increment(&mut self) {
        let (next, overflow) = self.0[12].overflowing_add(1);
        if overflow {
            panic!("Encryption exceeded 256GB of data");
        }
        self.0[12] = next;
    }
}

/// The state we maintain to generate a block of our keystream.
///
/// The idea is to initialize this block with our entropy (key and nonce), as well as a counter,
/// and then mix it up real well, so that we end up with seemingly random data.
#[derive(Clone, Debug)]
struct MixingState([u32; 16]);

impl MixingState {
    /// An empty mixing state
    fn empty() -> Self {
        MixingState([0; 16])
    }

    /// Initialize the mixing state, given an initial state
    fn init(&mut self, initial_state: &InitialState) {
        self.0.clone_from_slice(&initial_state.0);
    }

    /// The quarter round is the basic building block of our mixing operation.
    ///
    /// We operate over 4 pieces of our state, mixing them together.
    fn quarter_round(&mut self, a: usize, b: usize, c: usize, d: usize) {
        self.0[a] = self.0[a].wrapping_add(self.0[b]);
        self.0[d] = (self.0[d] ^ self.0[a]).rotate_left(16);
        self.0[c] = self.0[c].wrapping_add(self.0[d]);
        self.0[b] = (self.0[b] ^ self.0[c]).rotate_left(12);
        self.0[a] = self.0[a].wrapping_add(self.0[b]);
        self.0[d] = (self.0[d] ^ self.0[a]).rotate_left(8);
        self.0[c] = self.0[c].wrapping_add(self.0[d]);
        self.0[b] = (self.0[b] ^ self.0[c]).rotate_left(7);
    }

    /// This performs a single round, mixing up the entire state matrix
    ///
    /// (This is really a double round, in ChaCha terminology)
    fn round(&mut self) {
        // We do a quarter round over each column, and then each diagonal
        self.quarter_round(0, 4, 8, 12);
        self.quarter_round(1, 5, 9, 13);
        self.quarter_round(2, 6, 10, 14);
        self.quarter_round(3, 7, 11, 15);
        self.quarter_round(0, 5, 10, 15);
        self.quarter_round(1, 6, 11, 12);
        self.quarter_round(2, 7, 8, 13);
        self.quarter_round(3, 4, 9, 14);
    }

    /// Mix up all of the state in this block, ready for use in encryption
    fn mix(&mut self, initial_state: &InitialState) {
        // 10 double rounds, for ChaCha20
        for _ in 0..10 {
            self.round();
        }
        for i in 0..16 {
            self.0[i] = self.0[i].wrapping_add(initial_state.0[i]);
        }
    }

    /// Use the mixed state to encrypt a chunk of at most 64 bytes
    fn encrypt(&self, chunk: &mut [u8]) {
        // First, handle the words that line up exactly with this chunk
        let mut i = 0;
        while i + 4 <= chunk.len() {
            let word = self.0[i >> 2];
            chunk[i] ^= word as u8;
            chunk[i + 1] ^= (word >> 8) as u8;
            chunk[i + 2] ^= (word >> 16) as u8;
            chunk[i + 3] ^= (word >> 24) as u8;
            i += 4;
        }
        // The start of the remaining bytes that aren't aligned to 4 bytes
        let remaining_start = chunk.len() & !0b11;
        // This avoids indexing past the end of our state, when we have a 64 byte chunk
        if remaining_start >= chunk.len() {
            return;
        }
        // Now just fold in the last bit of state, as much as necessary
        let mut last_word = self.0[remaining_start >> 2];
        for byte in &mut chunk[remaining_start..] {
            *byte ^= last_word as u8;
            last_word >>= 8;
        }
    }
}

/// encrypt a slice of data in place, using a unique nonce, and an encryption key.
///
/// The nonce should never be reused with the same key for different encryptions.
/// For our purposes in this crate, it's safe to generate the nonce randomly, because
/// we use ephemeral keys.
pub fn encrypt(nonce: &Nonce, key: &Key, data: &mut [u8]) {
    let mut initial_state = InitialState::new(nonce, key, 1);
    let mut mixing_state = MixingState::empty();
    for chunk in data.chunks_mut(64) {
        mixing_state.init(&initial_state);
        mixing_state.mix(&initial_state);
        mixing_state.encrypt(chunk);
        initial_state.increment();
    }
}

struct Tag {
    bytes: [u8; 16],
}

const P1305: [u64; 3] = [0xfffffffffffffffb, 0xffffffffffffffff, 0x3];

/// This consumes our input chunk by chunk, progressively calculating an authentication tag
///
/// The idea is to interpret the data as a polynomial with 128 bit coefficients, evaluating
/// it at the first secret r, and then finalizing by adding the final secret s.
#[derive(Debug)]
struct Poly1305Eater {
    /// The 128 bit value at which we evaluate the polynomial.
    ///
    /// This value should already be clamped.
    r: [u64; 2],
    /// The 128 bit value we add to finalize our tag calculation
    s: [u64; 2],
    /// The accumulator holding the current state we've calculated so far
    ///
    /// The top part of the accumulator should always be <= 5
    acc: [u64; 3],
}

impl Poly1305Eater {
    fn update(&mut self, data: &[u8]) {
        // Note: This code is inspired a great deal from:
        // https://blog.filippo.io/a-literate-go-implementation-of-poly1305/

        // A utility for (64, 64) -> 128 multiplication
        #[inline(always)]
        fn mul(a: u64, b: u64) -> u128 {
            u128::from(a) * u128::from(b)
        }

        debug_assert!(data.len() <= 16);

        // We want to interpret data as a 128 bit number, and then artificially
        // set one bit further than its most significant bit, before adding it
        // to our accumulator.
        // How we handle this depends on how many bytes are in data. Usually,
        // we have full 16 bytes, but our last chunk of data might have fewer.
        if data.len() == 16 {
            // In this case, our strategy is to add in the data as a 128 bit number,
            // and then add 1 to the highest limb of acc.
            let data_lo = u64::from_le_bytes(data[0..8].try_into().unwrap());
            let data_hi = u64::from_le_bytes(data[8..].try_into().unwrap());
            let mut carry = 0;
            carry = adc(carry, data_lo, self.acc[0], &mut self.acc[0]);
            carry = adc(carry, data_hi, self.acc[1], &mut self.acc[1]);
            self.acc[2] += 1 + u64::from(carry);
        }

        // Now, we calculate acc * r % 2^130 - 5

        // First, calculate all the 128 overlapping sections of the product
        let m0 = mul(self.acc[0], self.r[0]);
        // Because of masking r, these additions don't overflow
        let m1 = mul(self.acc[1], self.r[0]) + mul(self.acc[0], self.r[1]);
        // Because the top limb of acc is <= 5, we can multiply with smaller results
        let m2 = u128::from(self.acc[2] * self.r[0]) + mul(self.acc[1], self.r[1]);
        let m3 = self.acc[2] * self.r[1];
        // Now, combine all of the overlapping results together, over 4 limbs
        let mut cc1 = 0;
        self.acc[0] = m0 as u64;
        let mut carry = 0;
        carry = adc(carry, (m0 >> 64) as u64, m1 as u64, &mut self.acc[1]);
        carry = adc(carry, (m1 >> 64) as u64, m2 as u64, &mut self.acc[2]);
        adc(carry, (m2 >> 64) as u64, m3, &mut cc1);

        let mut cc0 = self.acc[2] & !0b11;
        self.acc[2] &= 0b11;

        // Now, we need to add 5 * c to acc, which we accomplish by adding cc, and then (cc >> 2)
        let mut carry = 0;
        carry = adc(carry, cc0, self.acc[0], &mut self.acc[0]);
        carry = adc(carry, cc1, self.acc[1], &mut self.acc[1]);
        self.acc[2] += u64::from(carry);
        // Shift cc by 2 to get c
        cc0 = (cc1 << 62) | (cc0 >> 2);
        cc1 >>= 2;

        carry = 0;
        carry = adc(carry, cc0, self.acc[0], &mut self.acc[0]);
        carry = adc(carry, cc1, self.acc[1], &mut self.acc[1]);
        self.acc[2] += u64::from(carry);
    }

    fn finalize(&mut self) -> Tag {
        let mut out_lo = 0;
        let mut out_hi = 0;

        let mut borrow = 0;
        borrow = sbb(borrow, self.acc[0], P1305[0], &mut out_lo);
        borrow = sbb(borrow, self.acc[1], P1305[1], &mut out_hi);
        let mut dont_care = 0;
        borrow = sbb(borrow, self.acc[2], P1305[2], &mut dont_care);

        let underflow = Choice::from(borrow);
        out_lo.conditional_assign(&self.acc[0], underflow);
        out_hi.conditional_assign(&self.acc[1], underflow);

        let mut carry = 0;
        carry = adc(carry, self.s[0], out_lo, &mut out_lo);
        adc(carry, self.s[1], out_hi, &mut out_hi);

        let mut tag_bytes = [0; 16];
        tag_bytes[..8].copy_from_slice(&out_lo.to_le_bytes());
        tag_bytes[8..].copy_from_slice(&out_hi.to_le_bytes());
        Tag { bytes: tag_bytes }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sunscreen() {
        let key = Key {
            bytes: [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa, 0xb, 0xc, 0xd,
                0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ],
        };
        let nonce = Nonce {
            bytes: [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
            ],
        };
        let text = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected: [u8; 114] = [
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d,
            0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc,
            0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59,
            0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
            0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d,
            0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d,
            0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9,
            0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d,
        ];
        let mut bytes = text.as_bytes().to_owned();
        encrypt(&nonce, &key, &mut bytes);
        assert_eq!(&expected[..], &bytes);
    }
}
