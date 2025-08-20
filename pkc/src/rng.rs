use rand;
use num_bigint::{ BigUint, RandBigInt};

pub fn generate_random_less_than(bound: &BigUint) -> BigUint {
        let mut rng = rand::thread_rng();

        rng.gen_biguint_below(bound)
    }