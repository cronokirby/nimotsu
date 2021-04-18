mod arithmetic;

use arithmetic::Z25519;

fn main() {
    let mut x = Z25519::from(3);
    x.square();
    println!("{:X?}", x);
}
