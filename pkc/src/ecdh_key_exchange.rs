use num_bigint::BigInt;
use crate::elliptic_curve_primitives::EC;

fn main() {
    // example with
    // E: y^2 = x^3 + 2x + 2 mod 17, and generator point G = (5,11) 

    let G = (BigInt::from(5), BigInt::from(1));
    let p = BigInt::from(17);
    let a = BigInt::from(2);
    let b = BigInt::from(2);

    let sc = SharedConfig {
        generator: G,
        prime: p,
        param_a: a,
        param_b: b
    };

    let p1 = PartyOne {
        cyclic_group: &sc,
        alpha: BigInt::from(3)
    };

    let p2 = PartyTwo {
        cyclic_group: &sc,
        beta: BigInt::from(11)
    };

    let p1_public = p1.config();
    let p2_public = p2.config();

    let p1_private = p1.compute_shared_key(p2_public);
    let p2_private = p2.compute_shared_key(p1_public);

    assert_eq!(p1_private, p2_private);
}

#[derive(Debug)]
struct SharedConfig {
    generator: (BigInt, BigInt),
    prime: BigInt,
    param_a: BigInt,
    param_b: BigInt
}
#[derive(Debug)]
struct PartyOne<'a> {
    cyclic_group: &'a SharedConfig,
    alpha: BigInt
}
#[derive(Debug)]
struct PartyTwo<'a> {
    cyclic_group: &'a SharedConfig,
    beta: BigInt
}

impl<'a> PartyOne<'a> {
    fn config(&self) -> (BigInt, BigInt) {
        let G: (BigInt, BigInt) = self.cyclic_group.generator.clone();
        let p: BigInt = self.cyclic_group.prime.clone();
        let a: BigInt = self.cyclic_group.param_a.clone();
        let b: BigInt = self.cyclic_group.param_b.clone();
        
        let E: EC = EC::new(a, b, p);
        let p1_public: (BigInt, BigInt) = EC::point_n_addition(&E, G, self.alpha.clone());

        p1_public
    }

    fn compute_shared_key(&self, p2_public: (BigInt, BigInt)) -> (BigInt, BigInt) {
        let p: BigInt = self.cyclic_group.prime.clone();
        let a: BigInt = self.cyclic_group.param_a.clone();
        let b: BigInt = self.cyclic_group.param_b.clone();
        
        let E: EC = EC::new(a, b, p);
        EC::point_n_addition(&E, p2_public, self.alpha.clone())
    }
}

impl<'a> PartyTwo<'a> {
    fn config(&self) -> (BigInt, BigInt) {
        let G: (BigInt, BigInt) = self.cyclic_group.generator.clone();
        let p: BigInt = self.cyclic_group.prime.clone();
        let a: BigInt = self.cyclic_group.param_a.clone();
        let b: BigInt = self.cyclic_group.param_b.clone();
        
        let E: EC = EC::new(a, b, p);
        let p1_public: (BigInt, BigInt) = EC::point_n_addition(&E, G, self.beta.clone());

        p1_public
    }

    fn compute_shared_key(&self, p1_public: (BigInt, BigInt)) -> (BigInt, BigInt) {
        let p: BigInt = self.cyclic_group.prime.clone();
        let a: BigInt = self.cyclic_group.param_a.clone();
        let b: BigInt = self.cyclic_group.param_b.clone();
        
        let E: EC = EC::new(a, b, p);
        EC::point_n_addition(&E, p1_public, self.beta.clone())
    }
}