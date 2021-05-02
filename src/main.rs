use std::path::PathBuf;

use curve25519::{exchange, gen_keypair};
use rand::rngs::OsRng;
use structopt::StructOpt;

mod blake3;
mod chacha20;
mod curve25519;

#[derive(StructOpt, Debug)]
#[structopt(name = "nimotsu")]
enum Args {
    /// Generate a new keypair
    ///
    /// The public key will be printed out, the private key will be saved to a file
    Generate {
        /// The file to write the private key into
        #[structopt(short = "o", long = "out", parse(from_os_str))]
        out_file: PathBuf,
    },
    /// Encrypt a file for a given recipient
    Encrypt {
        /// The recipient to encrypt to
        #[structopt(short = "r", long = "recipient")]
        recipient: String,
        /// The file to write the encrypted data to
        #[structopt(short = "o", long = "out", parse(from_os_str))]
        out_file: PathBuf,
        /// The file contained the data to encrypt
        #[structopt(name = "INPUT_FILE", parse(from_os_str))]
        in_file: PathBuf,
    },
    /// Decrypt a file encrypted for you
    Decrypt {
        /// A path to your private key file
        #[structopt(short = "k", long = "key", parse(from_os_str))]
        key_file: PathBuf,
        /// The file contained the data to decrypt
        #[structopt(name = "INPUT_FILE", parse(from_os_str))]
        in_file: PathBuf,
        /// The file to write the decrypted to, or directly to the console
        #[structopt(short = "o", long = "out", parse(from_os_str))]
        out_file: Option<PathBuf>,
    },
}

fn main() {
    let args = Args::from_args();
    println!("{:?}", args);
}
