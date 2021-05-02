/// The state we maintain to generate a block of our keystream.
///
/// The idea is to initialize this block with our entropy (key and nonce), as well as a counter,
/// and then mix it up real well, so that we end up with seemingly random data.
#[derive(Debug)]
struct BlockState([u32; 16]);

impl BlockState {
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
    fn mix(&mut self) {
        // We need to add our initial state back after doing the round mixing
        let initial_state = self.0.clone();
        // 10 double rounds, for ChaCha20
        for _ in 0..10 {
            self.round();
        }
        for i in 0..16 {
            self.0[i] = self.0[i].wrapping_add(initial_state[i]);
        }
    }

    /// Use the mixed state to encrypt a chunk of 64 bytes
    ///
    /// This will work if the chunk is aligned to 4 bytes, actually.
    fn encrypt_exact(&self, chunk: &mut [u8]) {
        // First, handle the words that line up exactly with this chunk
        for i in (0..chunk.len()).step_by(4) {
            let word = self.0[i >> 2];
            chunk[i] ^= word as u8;
            chunk[i + 1] ^= (word >> 8) as u8;
            chunk[i + 2] ^= (word >> 16) as u8;
            chunk[i + 3] ^= (word >> 24) as u8;
        }
    }
}
