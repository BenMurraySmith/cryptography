use std::ops::{Add, Mul, Sub};
use num_bigint::BigInt;
use crate::number_theory_primitives as helper;


fn main() {

    //initialise primes p and q
    let p: BigInt = BigInt::from(23);
    let q: BigInt = BigInt::from(59);

    //define plaintext
    let plaintext: BigInt = BigInt::from(999);

    //if plaintext > p*q, then plaintext changes as we reduce mod n
    assert!(plaintext < (&p).mul(&q), "plaintext must be strictly less than product of primes");

    println!("plaintext = {:?}", plaintext);

    let prime_pair: RsaPair = RsaPair { pair : (p, q) };

    //generate public and private keys
    let keys: KeyPair = prime_pair.key_generation();

    println!("public and private keys = {:?}", keys);

    //encrypt plaintext
    let ciphertext: BigInt = KeyPair::encrypt(plaintext, keys.k_pub);

    println!("ciphertext = {:?}", ciphertext);

    //decrypt ciphertext
    let plaintext2: BigInt = KeyPair::decrypt(ciphertext, keys.k_priv);
    
    println!("back to plaintext = {:?}", plaintext2);

}


#[derive(Debug)]
struct RsaPair {
    // p, q = large primes
    pair: (BigInt, BigInt),
}

#[derive(Debug)]
struct  KeyPair {
    k_pub: (BigInt, BigInt),
    k_priv: (BigInt, BigInt)
}

impl RsaPair {
    fn key_generation(self) -> KeyPair {
        let one: BigInt = BigInt::from(1);

        let (p,q) = self.pair;
        let n: BigInt = (&p).mul(&q);

        let phi_p: BigInt = p.sub(&one);
        let phi_q: BigInt = q.sub(&one);
        let phi_n: BigInt = BigInt::mul(phi_p, phi_q);
        
        //initialize
        let mut encryption_exponent:BigInt = BigInt::from(2);

        while !helper::is_coprime(encryption_exponent.clone(), phi_n.clone()) {
            encryption_exponent = encryption_exponent.add(&one);
        };

        let decryption_exponent: BigInt = helper::multiplicative_inverse(encryption_exponent.clone(), phi_n);
        
        KeyPair { k_pub: (n.clone(), encryption_exponent), k_priv: (n.clone(), decryption_exponent) }

    }

}


impl KeyPair {
    fn encrypt(plaintext: BigInt, k_pub: (BigInt, BigInt)) -> BigInt {
        let (n, encryption_exponent) = k_pub;

        let ciphertext: BigInt = helper::costly_modular_exponentiation(plaintext, encryption_exponent, n);

        ciphertext
    }

    fn decrypt(ciphertext:BigInt, k_priv: (BigInt, BigInt)) -> BigInt {
        let (n, decryption_exponent) = k_priv;

        let plaintext: BigInt = helper::costly_modular_exponentiation(ciphertext, decryption_exponent, n);
        
        plaintext
    }
}