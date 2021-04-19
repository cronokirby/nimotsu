mod arithmetic;

use arithmetic::Z25519;

fn main() {
    let mut x = Z25519::from(2);
    x = x.exp(255.into());
    println!("{:X?}", x);
}
