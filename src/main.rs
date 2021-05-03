use std::{
    convert::TryInto,
    path::{Path, PathBuf},
};
use std::{
    fs::File,
    io::{self, Write},
};
use std::{io::Read, time::SystemTime};

use blake3::derive_key;
use chacha20::{encrypt, Key, Nonce};
use curve25519::{exchange, gen_keypair, PubKey};
use rand::rngs::OsRng;
use structopt::StructOpt;

mod blake3;
mod chacha20;
mod curve25519;

const DERIVE_KEY_CONTEXT: &'static str = "荷物 2021-05-03 derive key context";

fn encrypt_to_recipient(recipient: &PubKey, data: &mut [u8]) -> (PubKey, Nonce) {
    let (ephemeral_pub, ephemeral_priv) = gen_keypair(&mut OsRng);
    let shared_secret = exchange(&ephemeral_priv, recipient);
    let derived_key = Key {
        bytes: derive_key(DERIVE_KEY_CONTEXT, &shared_secret.bytes),
    };
    let nonce = Nonce::random(&mut OsRng);
    encrypt(&nonce, &derived_key, data);
    (ephemeral_pub, nonce)
}

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

/// Represents the kind of error our application generatess
#[derive(Debug)]
enum AppError {
    /// A parse error, with a string for information.
    ///
    /// This could probably be improved further.
    ParseError(String),
    /// An error that happened while doing IO of some kind
    IO(io::Error),
}

impl From<io::Error> for AppError {
    fn from(err: io::Error) -> Self {
        AppError::IO(err)
    }
}

/// The type of result produced our application
type AppResult<T> = Result<T, AppError>;

fn bytes_to_hex<W: io::Write>(data: &[u8], writer: &mut W) -> io::Result<()> {
    for byte in data {
        write!(writer, "{:02X}", byte)?;
    }
    Ok(())
}

fn nibble_from_char(char: u8) -> AppResult<u8> {
    if (b'0'..=b'9').contains(&char) {
        return Ok(char - b'0');
    }
    if (b'A'..=b'F').contains(&char) {
        return Ok(char - b'A');
    }
    Err(AppError::ParseError(format!(
        "Invalid nibble value: {}",
        char
    )))
}

fn bytes_from_hex(data: &str, buf: &mut Vec<u8>) -> AppResult<()> {
    if data.len() & 1 != 0 {
        return Err(AppError::ParseError(format!(
            "hex string has an odd length: {}",
            data.len()
        )));
    }
    for chunk in data.as_bytes().chunks_exact(2) {
        let hi = nibble_from_char(chunk[0])?;
        let lo = nibble_from_char(chunk[1])?;
        buf.push((hi << 4) | lo);
    }
    Ok(())
}

fn generate(out_path: &Path) -> io::Result<()> {
    let (pub_key, priv_key) = curve25519::gen_keypair(&mut OsRng);
    print!("Public Key:\n荷物の公開鍵");
    bytes_to_hex(&pub_key.bytes, &mut io::stdout())?;
    println!();
    let mut out_file = File::create(out_path)?;
    write!(out_file, "# Public Key: 荷物の公開鍵")?;
    bytes_to_hex(&pub_key.bytes, &mut out_file)?;
    write!(out_file, "\n荷物の秘密鍵")?;
    bytes_to_hex(&priv_key.bytes, &mut out_file)?;
    Ok(())
}

fn do_encrypt(recipient: &str, out_path: &Path, in_path: &Path) -> AppResult<()> {
    let hex_string = recipient
        .strip_prefix("荷物の公開鍵")
        .ok_or(AppError::ParseError(
            "recipient does not have public key prefix '荷物の公開鍵'".into(),
        ))?;
    dbg!(&hex_string);
    if hex_string.len() != 64 {
        return Err(AppError::ParseError(format!(
            "invalid recipient size: {}",
            hex_string.len()
        )));
    }
    let mut pub_key_bytes = Vec::with_capacity(64);
    bytes_from_hex(hex_string, &mut pub_key_bytes)?;
    let recipient_key = curve25519::PubKey {
        // Unwrapping is fine, because we checked the length of the string earlier
        bytes: pub_key_bytes.try_into().unwrap(),
    };

    let mut input_buf = Vec::new();
    File::open(in_path)?.read_to_end(&mut input_buf)?;
    let (ephemeral_pub, nonce) = encrypt_to_recipient(&recipient_key, &mut input_buf);
    let mut out_file = File::create(out_path)?;
    // Header
    write!(out_file, "nimotsu")?;
    out_file.write_all(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])?;
    // Public key, and nonce
    out_file.write_all(&ephemeral_pub.bytes)?;
    out_file.write_all(&nonce.bytes)?;
    out_file.write_all(&input_buf)?;
    Ok(())
}

fn decrypt(key_file: &Path, in_file: &Path, out_file: Option<&Path>) -> io::Result<()> {
    unimplemented!()
}

fn main() -> AppResult<()> {
    let args = Args::from_args();
    match args {
        Args::Generate { out_file } => generate(&out_file)?,
        Args::Encrypt {
            recipient,
            out_file,
            in_file,
        } => do_encrypt(&recipient, &out_file, &in_file)?,
        Args::Decrypt {
            key_file,
            in_file,
            out_file,
        } => decrypt(&key_file, &in_file, out_file.as_ref().map(|x| &*x as &Path))?,
    };
    Ok(())
}
