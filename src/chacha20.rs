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
}
