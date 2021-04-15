mod arithmetic;

use arithmetic::Z25519;

fn main() {
    let mut z = Z25519::from(0);
    z -= Z25519::from(1);
    println!("{:X?}", z)
}
