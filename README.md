# nimotsu

(This is **experimental software**, that rolls its own crypto for the hell of it. Use at your own peril.)

# Usage

```
nimotsu 0.1.0

USAGE:
    nimotsu <SUBCOMMAND>

FLAGS:
    -h, --help       
            Prints help information

    -V, --version    
            Prints version information


SUBCOMMANDS:
    decrypt     Decrypt a file encrypted for you
    encrypt     Encrypt a file for a given recipient
    generate    Generate a new keypair
    help        Prints this message or the help of the given subcommand(s)
```

## Key Generation

```
nimotsu-generate 0.1.0
Generate a new keypair

The public key will be printed out, the private key will be saved to a file

USAGE:
    nimotsu generate --out <out-file>

FLAGS:
    -h, --help       
            Prints help information

    -V, --version    
            Prints version information


OPTIONS:
    -o, --out <out-file>    
            The file to write the private key into
```

## Encryption

```
nimotsu-encrypt 0.1.0
Encrypt a file for a given recipient

USAGE:
    nimotsu encrypt <INPUT_FILE> --out <out-file> --recipient <recipient>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -o, --out <out-file>           The file to write the encrypted data to
    -r, --recipient <recipient>    The recipient to encrypt to

ARGS:
    <INPUT_FILE>    The file contained the data to encrypt
```

## Decryption

```
nimotsu-decrypt 0.1.0
Decrypt a file encrypted for you

USAGE:
    nimotsu decrypt [OPTIONS] <INPUT_FILE> --key <key-file>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -k, --key <key-file>    A path to your private key file
    -o, --out <out-file>    The file to write the decrypted to, or directly to the console

ARGS:
    <INPUT_FILE>    The file contained the data to decrypt
```

# Internals

To encrypt data, the following algorithm is used:

```
def encrypt(pub_key, plaintext) {
  (new_pub, new_priv) := gen_keypair()
  shared_secret := exchange(new_priv, pub_key)
  shared_key := derive_key(shared_secret)
  nonce := gen_nonce()
  ciphertext := aead_encrypt(nonce, shared_key, plaintext)
  return (new_pub, nonce, ciphertext)
}
```

To decrypt data, a similar algorithm is used:

```
def decrypt(priv_key, send_key, nonce, ciphertext) {
  shared_secret := exchange(priv_key, send_key)
  shared_key := derive_key(shared_secret)
  plaintext := aead_decrypt(nonce, shared_key, ciphertext)
  return plaintext
}
```

Different algorithms can used for the components of this exchange, in practice the following are used:

- `x25519` for key-pairs, and for exchanging secrets
- `Blake3` for key derivation
- `ChaCha20` for encryption (I haven't implemented `Poly1305` yet)

This program is really just an excuse to having fun implementing all of these from scratch :)
`x25519` is the most fun to implement, btw.
