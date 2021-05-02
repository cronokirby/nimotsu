/// Represents the current state we maintain while compressing input.
///
/// We use compression as a component of hashing, using the message we're hashing
/// to guide the evolution of our compression state.
#[derive(Debug)]
struct CompressionState([u32; 16]);

impl CompressionState {
    /// The quarter round is the basic building block of our compression function.
    ///
    /// We operate over 4 pieces of our state, using two words from the input to guide our mixing.
    fn quarter_round(&mut self, a: usize, b: usize, c: usize, d: usize, m0: u32, m1: u32) {
        self.0[a] = self.0[a] + self.0[b] + m0;
        self.0[d] = (self.0[d] ^ self.0[a]).rotate_right(16);
        self.0[c] = self.0[c] + self.0[d];
        self.0[b] = (self.0[b] ^ self.0[c]).rotate_right(12);
        self.0[a] = self.0[a] + self.0[b] + m1;
        self.0[d] = (self.0[d] ^ self.0[a]).rotate_right(8);
        self.0[c] = self.0[c] + self.0[d];
        self.0[b] = (self.0[b] ^ self.0[c]).rotate_right(7);
    }

    /// A round mixes up the entire state, using the message to guide the mixing
    fn round(&mut self, message: &[u32]) {
        // We do a quarter round for each column, and then for each diagonal.
        // We make use successive words of the message to guide the mixing at each step
        self.quarter_round(0, 4, 8, 12, message[0], message[1]);
        self.quarter_round(1, 5, 9, 13, message[2], message[3]);
        self.quarter_round(2, 6, 10, 14, message[4], message[5]);
        self.quarter_round(3, 7, 11, 15, message[6], message[7]);
        self.quarter_round(0, 5, 10, 15, message[8], message[9]);
        self.quarter_round(1, 6, 11, 12, message[10], message[11]);
        self.quarter_round(2, 7, 8, 13, message[12], message[13]);
        self.quarter_round(3, 4, 9, 14, message[14], message[15]);
    }
}
