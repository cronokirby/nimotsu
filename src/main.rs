mod arithmetic;
mod curve25519;

use arithmetic::Z25519;
use curve25519::Scalar;

fn main() {
    let mut bytes = [0u8; 32];
    bytes[31] = 9;
    let k = Scalar::from_bytes(bytes.clone());
    let x = Z25519 {
        limbs: [0, 0, 0, 0x0900_0000_0000_0000]
    };
    println!("{:X?}", k.act(x).project());
}
