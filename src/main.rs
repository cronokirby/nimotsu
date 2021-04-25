extern crate rand;
use curve25519::{exchange, gen_keypair};
use rand::rngs::OsRng;

mod curve25519;

fn main() {
    let (pub1, priv1) = gen_keypair(&mut OsRng);
    println!("{:X?}\n{:X?}", pub1, priv1);
    let (pub2, priv2) = gen_keypair(&mut OsRng);
    println!("{:X?}\n{:X?}", pub2, priv2);
    println!("exchange(1, 2) {:X?}", exchange(&priv1, &pub2));
    println!("exchange(2, 1) {:X?}", exchange(&priv2, &pub1));
}
