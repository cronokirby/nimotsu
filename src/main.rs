mod arithmetic;

use arithmetic::Z25519;

fn main() {
    let mut x = Z25519::from(2);
    x = x.inverse();
    println!("{:X?}", x);
}
