use std::ops::Index;

// This contains successive permutations of indices from 0 to 15.
// This is used to permute the part of the message we use for compression.
const PERMUTATIONS: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

// This is a convenient wrapper over a piece of our message, providing implicit
// permutations when indexing. Hopefully, the compiler can realize what we're doing,
// and inline the permutations for us.
#[derive(Debug)]
struct PermutedFragment<'a> {
    permutation: usize,
    fragment: &'a [u32; 16],
}

impl<'a> PermutedFragment<'a> {
    fn new(permutation: usize, fragment: &'a [u32; 16]) -> Self {
        debug_assert!(permutation < PERMUTATIONS.len());
        PermutedFragment {
            permutation,
            fragment,
        }
    }
}

impl<'a> Index<usize> for PermutedFragment<'a> {
    type Output = u32;

    fn index(&self, index: usize) -> &u32 {
        &self.fragment[PERMUTATIONS[self.permutation][index]]
    }
}

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
    fn round(&mut self, fragment: PermutedFragment) {
        // We do a quarter round for each column, and then for each diagonal.
        // We make use successive words of the message to guide the mixing at each step
        self.quarter_round(0, 4, 8, 12, fragment[0], fragment[1]);
        self.quarter_round(1, 5, 9, 13, fragment[2], fragment[3]);
        self.quarter_round(2, 6, 10, 14, fragment[4], fragment[5]);
        self.quarter_round(3, 7, 11, 15, fragment[6], fragment[7]);
        self.quarter_round(0, 5, 10, 15, fragment[8], fragment[9]);
        self.quarter_round(1, 6, 11, 12, fragment[10], fragment[11]);
        self.quarter_round(2, 7, 8, 13, fragment[12], fragment[13]);
        self.quarter_round(3, 4, 9, 14, fragment[14], fragment[15]);
    }

    // Compress the state, guided by part of the message, returning 256 bits of output
    //
    // In theory 512 bits can be produced by the compression function, but we don't need
    // all of that output for our purposes.
    fn compress(&mut self, message: &[u32; 16]) -> [u32; 8] {
        for i in 0..PERMUTATIONS.len() {
            self.round(PermutedFragment::new(i, message));
        }
        let mut out = [0; 8];
        for i in 0..8 {
            out[i] = self.0[i] ^ self.0[i + 8];
        }
        out
    }
}
