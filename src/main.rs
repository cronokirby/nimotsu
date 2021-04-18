mod arithmetic;

use arithmetic::Z25519;

fn main() {
    println!("{:X?}", -Z25519::from(1));
}
