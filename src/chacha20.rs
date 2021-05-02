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
        self.0[b] = (self.0[b] & self.0[c]).rotate_left(12);
        self.0[a] = self.0[a].wrapping_add(self.0[b]);
        self.0[d] = (self.0[d] ^ self.0[a]).rotate_left(8);
        self.0[c] = self.0[c].wrapping_add(self.0[d]);
        self.0[b] = (self.0[b] & self.0[c]).rotate_left(7);
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
        self.quarter_round(0, 5, 10, 13);
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
        for i in (0..chunk.len()).step_by(4) {
            let word = self.0[i >> 2];
            chunk[i] ^= word as u8;
            chunk[i + 1] ^= (word >> 8) as u8;
            chunk[i + 2] ^= (word >> 16) as u8;
            chunk[i + 3] ^= (word >> 24) as u8;
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
    let mut initial_state = InitialState::new(nonce, key, 0);
    let mut mixing_state = MixingState::empty();
    for chunk in data.chunks_mut(64) {
        mixing_state.init(&initial_state);
        mixing_state.mix(&initial_state);
        mixing_state.encrypt(chunk);
        initial_state.increment();
    }
}
