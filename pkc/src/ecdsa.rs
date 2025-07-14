use crate::elliptic_curve_primitives as elliptic_curve_helper;
use crate::number_theory_primitives as number_theory_helper;
use num_bigint::BigInt;
use sha2::{Sha256, Digest};
use std::ops::{Rem};

fn main(message:BigInt) {
    // example with
    // E: y^2 = x^3 + 2x + 2 mod 17, and generator point G = (5,11) 

    //instantiate a basic elliptic curve and define a pre-computed generator point
    let modulus = BigInt::from(17);
    let a = BigInt::from(2);
    let b = BigInt::from(2);

    let elliptic_curve = elliptic_curve_helper::EC {a,b, p:modulus.clone()};
    let generator = EcGroupElement { point:(BigInt::from(5), BigInt::from(1)) };

    //define private discrete logs q (private key) and k (randomness parameter) for Q = q*G and R = k*G resp.
    let q = DiscreteLog { dl: BigInt::from(5) };
    let k = DiscreteLog { dl: BigInt::from(6) };

    //hash message to be signed. Returns integer
    let h: BigInt = hash(&message);

    //generate public key Q=q*G from private key q
    let point_Q = EcGroupElement::new(q.dl.clone(), generator.point.clone(), &elliptic_curve);
    //generate randomness point R=k*G and only take the x coordinate: r = R.x
    let point_R = EcGroupElement::new(k.dl.clone(), generator.point.clone(), &elliptic_curve);
    let r = point_R.return_x_value();

    //compute s = (h+rp)/k
    let s:BigInt = compute_public_parameter_s(&h, &r, &q.dl, &k.dl, &modulus);
    
    //Prover sends (Q, h, r, s) to the Verifier.
    let package = ProverPackage {
        Q: point_Q,
        hashed_message: h,
        r,
        s,
        elliptic_curve,
        modulus,
        generator
    };

    let verifier = Verifier {
        package
    };

    let result = verifier.verify_signature();
    if result {
        println!("Signature is valid")
    } else {
        println!("Signature is invalid")
    }


}


//Given generator G use constructions below to both compute
// 1. Public key Q using private key q chosen by the prover. Computed as Q = q*G
// 2. pseudo-randomness parameter R given random field element k. Computed as R = k*G
struct DiscreteLog {
    dl: BigInt
}

struct EcGroupElement {
    point: (BigInt, BigInt)
}

impl EcGroupElement {
    fn new(dl: BigInt, generator:(BigInt, BigInt), ec: &elliptic_curve_helper::EC) -> Self {
        //Given the provers chosen private key, the elliptic curve and the ec's generator point, compute the public key Q
        let point = elliptic_curve_helper::EC::point_n_addition(ec, generator, dl);

        Self { point }
    }

    fn return_x_value(&self) -> BigInt {
        self.point.0.clone()
    }
    
}

fn compute_public_parameter_s(h:&BigInt, r:&BigInt, q:&BigInt, k:&BigInt, modulus:&BigInt) -> BigInt {
    // function computes s = (h + r*p) / k, 
    // which sets up verification step R = s^-1 (h*G + r*Q)
    let k_inv = number_theory_helper::multiplicative_inverse(k.clone(), modulus.clone());
    let numerator:BigInt = h + r*q;
    (k_inv*numerator).rem(modulus)
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



struct ProverPackage {
    Q: EcGroupElement,
    hashed_message: BigInt,
    r: BigInt,
    s: BigInt,
    elliptic_curve: elliptic_curve_helper::EC,
    modulus: BigInt,
    generator: EcGroupElement
}

struct Verifier {
    package: ProverPackage
}

impl Verifier {
    fn verify_signature(self) -> bool {
        let s_inv: BigInt = number_theory_helper::multiplicative_inverse(self.package.s, self.package.modulus);
        let hG: (BigInt, BigInt) = EcGroupElement::new(self.package.hashed_message, self.package.generator.point, &self.package.elliptic_curve).point;
        let rP: (BigInt, BigInt) = EcGroupElement::new(self.package.r.clone(), self.package.Q.point, &self.package.elliptic_curve).point;
        let intermediate_point = self.package.elliptic_curve.point_addition_unique(&hG, &rP);
        let result = self.package.elliptic_curve.point_n_addition(intermediate_point, s_inv);

        let result_x = result.0;


        if result_x == self.package.r {
            return true
        }

        false
    }
}