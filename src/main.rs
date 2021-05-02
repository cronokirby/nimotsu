extern crate rand;
use curve25519::{exchange, gen_keypair};
use rand::rngs::OsRng;

mod blake3;
mod curve25519;

fn main() {
    let (pub1, priv1) = gen_keypair(&mut OsRng);
    println!("{:X?}\n{:X?}", pub1, priv1);
    let (pub2, priv2) = gen_keypair(&mut OsRng);
    println!("{:X?}\n{:X?}", pub2, priv2);
    let ex12 = exchange(&priv1, &pub2);
    println!("exchange(1, 2) {:X?}", ex12);
    let ex21 = exchange(&priv2, &pub1);
    println!("exchange(2, 1) {:X?}", ex21);
    println!("derived ctx1 {:X?}", blake3::derive_key("ctx1", &ex12.bytes));
    println!("derived ctx2 {:X?}", blake3::derive_key("ctx2", &ex12.bytes));
}
