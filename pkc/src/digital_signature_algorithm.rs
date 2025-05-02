use std::fmt::format;
use std::ops::{Add, Div, Rem};
use num_bigint::BigInt;
use num_bigint::BigUint;
use num_traits::One;
use rand::Rng;
use crate::number_theory_primitives as helper;
use sha2::{Sha256, Digest};


fn main() {
    
}



struct DsaPrimePair {
    p: BigInt,
    q: BigInt
}


impl DsaPrimePair {
    fn new(p: BigInt, q:BigInt) -> Self {
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
}


struct DsaPublicKey {
    p: BigInt,
    q: BigInt,
    alpha: BigInt,
    B: BigInt
}


struct DsaPrivatekey {
    d: BigInt
}

impl DsaPrivatekey {
    fn new(d: BigInt, q: BigInt) -> Self {
        if BigInt::from(1) > d || d > q - BigInt::from(1) {
            panic!("private key d needs to satisfy: 1 <= d <= (q - 1)")
        };

        Self { d }
    }
}


struct DsaKeyPair {
    k_pub: DsaPublicKey,
    k_priv: DsaPrivatekey
}

impl DsaKeyPair {
    fn new(primes: DsaPrimePair, k_priv: DsaPrivatekey) -> Self {
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

        let B = alpha.modpow(&d, &p);
        
        let k_pub = DsaPublicKey { p, q, alpha, B};
        let k_priv = DsaPrivatekey { d };

        Self {
            k_pub,
            k_priv
        }
    }

    fn hash(m: &BigInt) -> BigInt {
        let message = format!("b{}", m);
        let mut hasher = Sha256::new();
        hasher.update(&message);
        let hashed_m = hasher.finalize();
        BigInt::from_bytes_be(num_bigint::Sign::Plus, &hashed_m)
    }

    fn generate_signature(&self, ephemeral_key: BigInt, primes: DsaPrimePair, m: BigInt) -> DsaSignature {
        let p = primes.p;
        let q = primes.q;
        if BigInt::ZERO > ephemeral_key || ephemeral_key > q {
            panic!("ephemeral key needs to satisfy: 1 <= k_e <= (q - 1)")
        };

        let r = (self.k_pub.alpha.modpow(&ephemeral_key, &p)).rem(&q);

        let hashed_message = Self::hash(&m);

        let ephemeral_key_inv = ephemeral_key.modinv(&q).unwrap();
        let s_ = (hashed_message + self.k_priv.d.checked_mul(&r).unwrap()).checked_mul(&ephemeral_key_inv).unwrap();
        let s = s_.rem(&q);

        DsaSignature { sig: (r,s) }

    }

    fn verify_signature(&self, signature: DsaSignature, m: BigInt, primes: DsaPrimePair) -> bool {
        let p = primes.p;
        let q = primes.q;
        let r = signature.sig.0;
        let s_inv = signature.sig.1.modinv(&q).unwrap();
        let hashed_message = Self::hash(&m);
        let alpha = &self.k_pub.alpha;
        let B = &self.k_pub.B;

        let u_1 = s_inv.checked_mul(&hashed_message).unwrap().rem(&q);
        let u_2 = s_inv.checked_mul(&r).unwrap().rem(&q);

        let v = alpha.modpow(&u_1, &p)
            .checked_mul(&B.modpow(&u_2, &p))
            .unwrap()
            .rem(&p)
            .rem(&q);

        if r == v.rem(&q) {
            return true
        }

        false


    }
}


struct DsaSignature {
    sig: (BigInt, BigInt)
}

