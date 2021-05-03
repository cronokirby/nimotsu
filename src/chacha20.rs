use rand::{CryptoRng, RngCore};
use std::convert::TryInto;

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