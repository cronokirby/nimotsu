use std::{convert::TryInto, ops::Index};

// Flags for domain separation
const FLAG_CHUNK_START: u32 = 1;
const FLAG_CHUNK_END: u32 = 1 << 1;
const FLAG_ROOT: u32 = 1 << 3;
const FLAG_DERIVE_KEY_CONTEXT: u32 = 1 << 5;
const FLAG_DERIVE_KEY_MATERIAL: u32 = 1 << 6;

// Initialization values used for the algorithm
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

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

/// This is a convenient wrapper over a piece of our message, providing implicit
/// permutations when indexing. Hopefully, the compiler can realize what we're doing,
/// and inline the permutations for us.
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
    /// Initialize this state as empty
    fn empty() -> Self {
        CompressionState([0; 16])
    }

    /// Initialize this compression state with new input values.
    ///
    /// The chaining value lets us link the hashing process of different blocks together.
    /// The counter lets us separate out the hash values of different chunks.
    /// The byte_count makes sure that shorter blocks give different hashses
    /// The domain allows us to separate out the hash values in different parts of the algorithm.
    fn init(&mut self, chaining: &[u32; 8], counter: u64, byte_count: u32, domain: u32) {
        // The first two rows are the chaining value
        for i in 0..8 {
            self.0[i] = chaining[i];
        }
        // The next row comes from the static IV for this algorithm
        for i in 0..4 {
            self.0[i + 8] = IV[i];
        }
        // Then we have the counters, and the domain flag
        self.0[12] = counter as u32;
        self.0[13] = (counter >> 32) as u32;
        self.0[14] = byte_count;
        self.0[15] = domain;
    }

    /// The quarter round is the basic building block of our compression function.
    ///
    /// We operate over 4 pieces of our state, using two words from the input to guide our mixing.
    fn quarter_round(&mut self, a: usize, b: usize, c: usize, d: usize, m0: u32, m1: u32) {
        self.0[a] = self.0[a].wrapping_add(self.0[b]).wrapping_add(m0);
        self.0[d] = (self.0[d] ^ self.0[a]).rotate_right(16);
        self.0[c] = self.0[c].wrapping_add(self.0[d]);
        self.0[b] = (self.0[b] ^ self.0[c]).rotate_right(12);
        self.0[a] = self.0[a].wrapping_add(self.0[b]).wrapping_add(m1);
        self.0[d] = (self.0[d] ^ self.0[a]).rotate_right(8);
        self.0[c] = self.0[c].wrapping_add(self.0[d]);
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

    /// Compress the state, guided by part of the message, returning 256 bits of output
    ///
    /// In theory 512 bits can be produced by the compression function, but we don't need
    /// all of that output for our purposes.
    fn compress(&mut self, fragment: &[u32; 16]) -> [u32; 8] {
        for i in 0..PERMUTATIONS.len() {
            self.round(PermutedFragment::new(i, fragment));
        }
        let mut out = [0; 8];
        for i in 0..8 {
            out[i] = self.0[i] ^ self.0[i + 8];
        }
        out
    }
}

// fill a fragment of words, using bytes in little endian order
//
// The remaining parts of the fragment will be filled with 0.
fn fill_fragment(fragment: &mut [u32; 16], data: &[u8]) {
    // Remove the remainder modulo 4
    let aligned_len = data.len() & !0b11;
    let mut i = 0;
    // For all of the aligned bytes, we can easily convert the data to words
    for quad in data[..aligned_len].chunks_exact(4) {
        fragment[i] = u32::from_le_bytes(quad.try_into().unwrap());
        i += 1;
    }
    for j in i..16 {
        fragment[j] = 0;
    }
    // The index right after we inserted in the aligned data might have a few bytes left
    for (index, &byte) in data[aligned_len..].iter().enumerate() {
        fragment[i] |= (byte as u32) << (index * 8);
    }
}

/// Calculate a hash of some data, given a base domain, and some chaining data
///
/// The domain allows us to use the hash function in different contexts.
/// The chaining data is used for initialization in different modes.
fn hash(base_domain: u32, mut chaining: [u32; 8], data: &[u8]) -> [u32; 8] {
    debug_assert!(data.len() <= 1024);

    let mut fragment = [0; 16];
    let mut compression_state = CompressionState::empty();
    // Easier to special case empty data
    if data.len() == 0 {
        let chunk_domain = base_domain | FLAG_CHUNK_START | FLAG_CHUNK_END | FLAG_ROOT;
        compression_state.init(&chaining, 0, 0, chunk_domain);
        return compression_state.compress(&fragment);
    }
    // This is the number of 64 byte chunks, minus one
    let last_chunk_index = ((data.len() + 63) >> 6) - 1;
    for (index, chunk) in data.chunks(64).enumerate() {
        let mut chunk_domain = base_domain;
        if index == 0 {
            chunk_domain |= FLAG_CHUNK_START;
        }
        if index == last_chunk_index {
            chunk_domain |= FLAG_CHUNK_END;
            chunk_domain |= FLAG_ROOT;
        }
        fill_fragment(&mut fragment, chunk);
        compression_state.init(&chaining, 0, chunk.len() as u32, chunk_domain);
        chaining = compression_state.compress(&fragment);
    }
    chaining
}

/// Take the output in words, and flatten it out into bytes in little endian order
fn flatten_output(thick: [u32; 8]) -> [u8; 32] {
    let mut out = [0; 32];
    let mut i = 0;
    for word in &thick {
        for &b in &word.to_le_bytes() {
            out[i] = b;
            i += 1;
        }
    }
    out
}

/// Derive a key given some context, and the material used to generate the key.
///
/// The context is used to ensure that different contexts receive different keys.
///
/// The context should be a static string, and different for each context and
/// version of an application.
pub fn derive_key(context: &'static str, key_material: &[u8]) -> [u8; 32] {
    let context_hash = hash(FLAG_DERIVE_KEY_CONTEXT, IV.clone(), context.as_bytes());
    flatten_output(hash(FLAG_DERIVE_KEY_MATERIAL, context_hash, key_material))
}

#[cfg(test)]
mod test {
    use super::*;

    const TEST_CONTEXT: &'static str = "BLAKE3 2019-12-27 16:29:52 test vectors context";

    #[test]
    fn test_vector_1() {
        let expected = [
            0x2c, 0xc3, 0x97, 0x83, 0xc2, 0x23, 0x15, 0x4f, 0xea, 0x8d, 0xfb, 0x7c, 0x1b, 0x16,
            0x60, 0xf2, 0xac, 0x2d, 0xcb, 0xd1, 0xc1, 0xde, 0x82, 0x77, 0xb0, 0xb0, 0xdd, 0x39,
            0xb7, 0xe5, 0x0d, 0x7d,
        ];
        assert_eq!(expected, derive_key(TEST_CONTEXT, &[]))
    }

    #[test]
    fn test_vector_2() {
        let expected = [
            0xb3, 0xe2, 0xe3, 0x40, 0xa1, 0x17, 0xa4, 0x99, 0xc6, 0xcf, 0x23, 0x98, 0xa1, 0x9e,
            0xe0, 0xd2, 0x9c, 0xca, 0x2b, 0xb7, 0x40, 0x4c, 0x73, 0x06, 0x33, 0x82, 0x69, 0x3b,
            0xf6, 0x6c, 0xb0, 0x6c,
        ];
        assert_eq!(expected, derive_key(TEST_CONTEXT, &[0]))
    }

    #[test]
    fn test_vector_3() {
        let expected = [
            0x1f, 0x16, 0x65, 0x65, 0xa7, 0xdf, 0x00, 0x98, 0xee, 0x65, 0x92, 0x2d, 0x7f, 0xea,
            0x42, 0x5f, 0xb1, 0x8b, 0x99, 0x43, 0xf1, 0x9d, 0x61, 0x61, 0xe2, 0xd1, 0x79, 0x39,
            0x35, 0x61, 0x68, 0xe6,
        ];
        assert_eq!(expected, derive_key(TEST_CONTEXT, &[0, 1]))
    }
}
