mod arithmetic;

use arithmetic::Z25519;

fn main() {
    let mut z = Z25519::from(48662);
    z += z;
    println!("{:?}", z)
}
