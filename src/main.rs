use std::{
    convert::TryInto,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};
use std::{
    fs::File,
    io::{self, Write},
};
use std::{io::Read, time::SystemTime};

use blake3::derive_key;
use chacha20::{encrypt, Key, Nonce};
use curve25519::{exchange, gen_keypair, PrivKey, PubKey};
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

fn decrypt_from_sender(my_priv: &PrivKey, sender: &PubKey, nonce: &Nonce, data: &mut [u8]) {
    let shared_secret = exchange(my_priv, sender);
    let derived_key = Key {
        bytes: derive_key(DERIVE_KEY_CONTEXT, &shared_secret.bytes),
    };
    encrypt(&nonce, &derived_key, data);
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
    out_file.write_all(b"nimotsu\x00\x01\x00")?;
    // Public key, and nonce
    out_file.write_all(&ephemeral_pub.bytes)?;
    out_file.write_all(&nonce.bytes)?;
    out_file.write_all(&input_buf)?;
    Ok(())
}

fn decrypt(key_path: &Path, in_path: &Path, out_path: Option<&Path>) -> AppResult<()> {
    let mut priv_key_bytes = Vec::with_capacity(64);
    let mut maybe_priv_key = None;
    let key_file = File::open(key_path)?;
    let key_reader = BufReader::new(key_file);
    for maybe_line in key_reader.lines() {
        let line = maybe_line?;
        if line.starts_with("#") {
            continue;
        }
        let hex_string = line
            .strip_prefix("荷物の秘密鍵")
            .ok_or(AppError::ParseError(
                "key file does not have private key prefix '荷物の秘密鍵'".into(),
            ))?;
        if hex_string.len() != 64 {
            return Err(AppError::ParseError(format!(
                "invalid private key size size: {}",
                hex_string.len()
            )));
        }
        bytes_from_hex(hex_string, &mut priv_key_bytes)?;
        maybe_priv_key = Some(PrivKey {
            // We checked the length earlier
            bytes: priv_key_bytes.try_into().unwrap(),
        });
        break;
    }
    let priv_key = maybe_priv_key.ok_or(AppError::ParseError("No key in file".into()))?;

    let mut in_file = File::open(in_path)?;
    let mut header = [0u8; 10];
    in_file.read_exact(&mut header)?;
    if &header != b"nimotsu\x00\x01\x00" {
        return Err(AppError::ParseError("Invalid header".into()));
    }
    let mut sender_pub = PubKey { bytes: [0; 32] };
    in_file.read_exact(&mut sender_pub.bytes)?;
    let mut nonce = Nonce { bytes: [0; 12] };
    in_file.read_exact(&mut nonce.bytes)?;
    let mut encrypted_data = Vec::new();
    in_file.read_to_end(&mut encrypted_data)?;
    decrypt_from_sender(&priv_key, &sender_pub, &nonce, &mut encrypted_data);

    let mut out_writer: Box<dyn io::Write> = match out_path {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(io::stdout()),
    };
    out_writer.write_all(&encrypted_data)?;
    Ok(())
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
