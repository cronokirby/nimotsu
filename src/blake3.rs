/// Represents the current state we maintain while compressing input.
///
/// We use compression as a component of hashing, using the message we're hashing
/// to guide the evolution of our compression state.
#[derive(Debug)]
struct CompressionState([u32; 16]);

impl CompressionState {
    /// The quarter round is the basic building block of our round function.
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
}
