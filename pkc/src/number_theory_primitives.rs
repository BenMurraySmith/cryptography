use std::ops::{Add, Div, Rem};
use num_bigint::BigInt;

//by fundamental theorem of arithmetic
pub fn prime_factorsation(mut n:BigInt) -> Vec<(BigInt, BigInt)> {

    let mut factors:Vec<(BigInt, BigInt)> = Vec::new();
    let zero: BigInt = BigInt::ZERO;
    let one: BigInt = BigInt::from(1);
    let two: BigInt = BigInt::from(2);
    let mut n_clone: BigInt = n.clone();

    //get powers of 2 first
    let mut two_power:BigInt = BigInt::ZERO;

    //prepare modulus
    while (&n).rem(&two) == zero {
        two_power += &one;
        n = n.div(&two);
    }

    //add 2^i to list (if original number is even)
    if two_power > zero {
        factors.push((BigInt::from(2), two_power))
    };

    //prepare loop params for the rest
    let mut num: BigInt= BigInt::from(3);
    let upper_limit: BigInt = (&n_clone).div(&two);

    //get powers of 3 onwards
    while num <= upper_limit {
        //initialize
        let mut power: BigInt = BigInt::ZERO;

        while (&n_clone).rem(&num) == zero {
            power += &one;
            n_clone = n_clone.div(&num);
        }

        let num_clone = num.clone();

        if power > zero {
            factors.push((num, power));
        }

        // num = BigInt::add(num, &two);
        num = num_clone.add(&two);
    }

    //default case
    if factors.is_empty() {
        factors.push((n, BigInt::from(1)));
    }

    factors
}

//using formula
pub fn euler_totient_factors_small_n(factors: Vec<(u32, u32)>) -> u32 {
    let mut result: f32 = 1.0;

    for pair in factors {
        let (factor, power) = pair;
        result *= (1.0 - (1.0/(factor as f32))) * (factor.pow(power) as f32);
    };
    
    result.round() as u32
}

//using counter
pub fn euler_totient_loop_small_n(n:u32) -> u32 {
    let mut count: u32 = 1;

    for num in 2..n {
        if is_coprime(BigInt::from(count), BigInt::from(num)) {
            count+=1
        };
    };

    count
}

//Euclid's Algorithm
pub fn gcd(a:BigInt, b:BigInt) -> BigInt {
    if a < b {
        return gcd(b,a)
    };

    if b == BigInt::ZERO {
        return a
    } else {
        let b_clone = b.clone();
        return gcd(b, a % b_clone)
    };
}

//consequence
pub fn is_coprime(a:BigInt, b:BigInt) -> bool {

    if gcd(a, b) == BigInt::from(1) {
        return true
    }
    false
}

//for a = qb + r, function returns (q, r) using the Division Algorithm
pub fn compute_q_r(a:BigInt, b:BigInt) -> (BigInt, BigInt) {
    let mut a = a;
    let mut b = b;

    if a < b {
        (a, b) = (b, a)
    }
    let r = (&a).rem(&b);
    // let q = (a - a%b)/b;
    let q = a.div(b);

    (q,r)
}

//using Extended Euclidian Algorithm
pub fn multiplicative_inverse(a:BigInt, modb:BigInt) -> BigInt {
    let mut q: BigInt;
    let mut a: BigInt = a;
    let mut b: BigInt = modb.clone();
    if a < b {
        (a, b) = (b, a)
    };
    let mut r: BigInt=BigInt::from(1);
    let mut t_1: BigInt = BigInt::from(0);
    let mut t_2: BigInt = BigInt::from(1);
    let mut t: BigInt;


    while r != BigInt::ZERO {
        //find quotient and remainer
        r = (&a).rem(&b);
        q = a.div(&b);

        //finish T row
        t = t_1 - q*(t_2.clone());

        //update values for next iteration
        a = b;
        b = r.clone();
        t_1 = t_2;
        t_2 = t;
    }

    //make exponent > 0
    if t_1 < BigInt::from(0) {
        while t_1 < BigInt::from(0) {
            t_1+= &modb;
        }
    }

    t_1

}

//costly modular exponentiation
pub fn costly_modular_exponentiation(a:BigInt, e:BigInt, n:BigInt) -> BigInt {
    BigInt::modpow(&a, &e, &n)
}

//efficient modular exponentiation
pub fn montgomery_modular_exponentiation(a:BigInt, e:BigInt, n:BigInt) {}

//miller-rabin primality test
pub fn is_prime() {}