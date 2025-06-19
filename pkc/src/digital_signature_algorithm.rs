use std::fmt::format;
use std::ops::{Add, Div, Rem};
use num_bigint::BigInt;
use num_bigint::BigUint;
use num_traits::One;
use rand::Rng;
use crate::number_theory_primitives as helper;
use sha2::{Sha256, Digest};


fn main(message:BigInt) {
    //implementation of DSA for small primes p and q
    //
    //main() generates a digital signature for integer message and
    //validates the signature

    // since 5|30
    let prime_pair = DsaPrimePair::new_small(p=31, q=5)

    //set private key d = 3
    let k_priv = DsaPrivateKey::new(d=3, q=prime_pair.q)

    //generate public parameters alpha and b and return pub/priv key pair
    let dsa_key_pair = DsaKeyPair::new(primes=&prime_pair, k_priv=&k_priv)

    //generate signature (r,s) by setting ephemeral_key equal to 4 only for this message
    let dsa_signature = dsa_key_pair.generate_signature(ephemeral_key=4 , primes=&prime_pair, m=&message)

    //validate signature
    let result = dsa_signature.verify_signature(m=&message, primes=&prime_pair, key_pair=&dsa_key_pair)

    if result==true{
        println!("Signature is valid")
    } else {
        println!("Signaure is invalid")
    }
}

// public primes
struct DsaPrimePair {
    p: BigInt,
    q: BigInt
}


impl DsaPrimePair {

    fn new(p: BigInt, q:BigInt) -> Self {
        //new() static method checks:
        // 1. proposed primes are sufficiently large (1023 < p < 1024 bits and 159 < q < 160 bits)
        // 2. q | phi(p)
        // 
        // returns DsaPrimePair object on success, otherwise program panics

        let p_min: BigInt = BigInt::from(2).pow(1023);
        let p_max: BigInt = BigInt::from(2).pow(1024);

        let q_min: BigInt = BigInt::from(2).pow(159);
        let q_max: BigInt = BigInt::from(2).pow(160);
        

        if p_min > p || p > p_max {
            panic!("prime p not within expected range")
        };

        if q_min > q || q > q_max {
            panic!("prime q not within expected range")
        };

        let p_minus_one = &p - BigInt::from(1);

        if !helper::does_divide(&q, &p_minus_one ) {
            panic!("primes p,q not configured properly: q does not divide p-1")
        }

        Self { p, q }
    }

    fn new_small(p: BigInt, q:BigInt) -> Self {
        //new_small() is a static method that checks:
        // 1. q | phi(p)
        // 
        //returns DsaPrimePair object on success, otherwise program panics
        //
        //used only in demonstration with small primes

        let p_minus_one = &p - BigInt::from(1);

        if !helper::does_divide(&q, &p_minus_one ) {
            panic!("primes p,q not configured properly: q does not divide p-1")
        }

        Self { p, q }
    }
}

//construct public key object containing
//1. primes p,q
//2. alpha
//3. B
//where alpha and B are computed during key generation
struct DsaPublicKey {
    p: BigInt,
    q: BigInt,
    alpha: BigInt,
    b: BigInt
}

//object to hold private key
struct DsaPrivatekey {
    d: BigInt
}

impl DsaPrivatekey {
    fn new(d: BigInt, q: BigInt) -> Self {
        //new() method validates size of d
        //on success returns back DsaPrivateKey object
        if BigInt::from(1) > d || d > q - BigInt::from(1) {
            panic!("private key d needs to satisfy: 1 <= d <= (q - 1)")
        };

        Self { d }
    }
}

//abstraction of previous key generation objects
struct DsaKeyPair {
    k_pub: DsaPublicKey,
    k_priv: DsaPrivatekey
}

impl DsaKeyPair {
    fn new(primes: DsaPrimePair, k_priv: DsaPrivatekey) -> Self {
        //new() method takes public parameters p,q, private d and
        //initializes g=2 as a generator of Z_q. 
        //
        //to compute alpha we loop through values of g until we find
        //an alpha such that alpha=g^e != 1 mod p.
        //
        //to compute B raise alpha to private key d mod p.
        //
        //finally return DsaKeyPair as an abstraction of public and private key interfaces
        let p = primes.p;
        let q = primes.q;
        let d = k_priv.d;

        let exponent = (&p - BigInt::from(1)).div(&q);
        let mut g = BigInt::from(2);
        let mut alpha = BigInt::ZERO;

        while g < p {
            alpha = g.modpow(&exponent, &p);
            if alpha != BigInt::from(1) {
                break
            }
            g+=BigInt::from(1);
        };

        let b = alpha.modpow(&d, &p);
        
        let k_pub = DsaPublicKey { p, q, alpha, b};
        let k_priv = DsaPrivatekey { d };

        Self { k_pub, k_priv }
    }

    fn validate_ephemeral_key(&self, eph_key:&BigInt, primes: &DsaPrimePair) -> bool {
        //validate_ephemeral_key() method checks 
        // 1. 1 <= eph_key <= q - 1
        // 2. gcd(eph_key, q) = 1
        let p = primes.p;
        let q = primes.q;

        //check size constaint
        if BigInt::ZERO > ephemeral_key || ephemeral_key > (q-1) {
            return false
        };
        
        //ephemeral key needs to be coprime to q
        if helper::gcd(&eph_key, &q) != BigInt::from(1) {
            return false
        };

        true
    }

    fn generate_signature(&self, ephemeral_key: BigInt, primes: &DsaPrimePair, m: &BigInt) -> DsaSignature {
        //generate_singature() method generates signature (r,s) using an ephemeral key (per-message secret)
        //
        //1. ensure ephemeral key satisfies size constraints
        //2. compute r parameter by raising alpha to ephemeral key mod p mod q
        //3. compute s parameter by 
        // - computing q-inverse of ephemeral key
        // - computing s = H(m) + d*r * eph_key_inv mod q
        //4. return (r,s) wrapped in DsaSignature struct

        let p = primes.p;
        let q = primes.q;
        if self.validate_ephemeral_key(&ephemeral_key, primes) == false {
            panic!("ephemeral key does not respect constraints.")
        }

        let r = (self.k_pub.alpha.modpow(&ephemeral_key, &p)).rem(&q);

        let hashed_message = hash(m);

        let ephemeral_key_inv = ephemeral_key.modinv(&q).unwrap();
        let s_ = (hashed_message + self.k_priv.d.checked_mul(&r).unwrap()).checked_mul(&ephemeral_key_inv).unwrap();
        let s = s_.rem(&q);

        DsaSignature { (r,s) }

    }

}

// (r,s) pair abstraction
struct DsaSignature {
    sig: (BigInt, BigInt)
}

impl DsaSignature {

    fn verify_signature(&self, m: &BigInt, primes: &DsaPrimePair, key_pair: &DsaKeyPair) -> bool {
        //verify_signature() method takes as input DsaSignature object, message m and primes p,q
        //and returns boolean
        //
        //1. pull r,s from DsaSignature object and compute q-inverse of s
        //2. compute parameter u_1 = s_inv * H(m) mod q
        //3. compute parameter u_2 = s_inv * r mod q
        //4. compute v = (alpha^u_1 mod p) * (B^u_2 mod p) mod p mod q
        //5. check that r equals v

        //unpack public information
        let p = primes.p;
        let q = primes.q;
        let r = &self.sig.0;
        let s_inv = &self.sig.1.modinv(&q).unwrap();
        let hashed_message = hash(m);
        let alpha = &key_pair.k_pub.alpha;
        let b = &key_pair.k_pub.b;

        let u_1 = s_inv.checked_mul(&hashed_message).unwrap().rem(&q);
        let u_2 = s_inv.checked_mul(&r).unwrap().rem(&q);

        let v = alpha.modpow(&u_1, &p)
            .checked_mul(&b.modpow(&u_2, &p))
            .unwrap()
            .rem(&p)
            .rem(&q);

        if r == v {
            return true
        }

        false


    }
}


fn hash(m: &BigInt) -> BigInt {
        //1. takes integer message m and converts to binary string
        //
        //2. instantiate sha256 hasher and pass in binary string
        // 
        //3. convert binary string output to integer hash
        let message = format!("b{}", m);
        let mut hasher = Sha256::new();
        hasher.update(&message);
        let hashed_m = hasher.finalize();
        BigInt::from_bytes_be(num_bigint::Sign::Plus, &hashed_m)
    }
