use num_bigint::BigInt;

//main() is an example of dh key generation 
//
//program uses modulus p=17 and generator g=3 as public parameters.
//Alice and Bob have private params a=5 and b=9 resp.
//
//shared key is computed by both parties: g^(ab) mod p
fn main() {
    //3 is a generator of Z_17
    let p: BigInt = BigInt::from(17);
    let g: BigInt = BigInt::from(3);

    //public parameters
    let sc = SharedConfig {
        generator: g,
        prime: p
    };

    //p1 chooses secret a = 5
    let p1 = PartyOne {
        cyclic_group: &sc,
        a: BigInt::from(5)
    };

    //p2 chooses secret b = 9
    let p2 = PartyTwo {
        cyclic_group: &sc,
        b: BigInt::from(9)
    };

    //parties compute g^e mod p (e = a or b)
    let p1_setup: BigInt = p1.config();
    let p2_setup: BigInt = p2.config();
    
    let p1_key:BigInt = PartyOne::compute_shared_key(&p1, p2_setup);
    let p2_key:BigInt = PartyTwo::compute_shared_key(&p2, p1_setup);

    assert_eq!(p1_key, p2_key);

    println!("Shared key is: {:?}", p1_key);

}


//constructions of initial setup

struct SharedConfig {
    generator: BigInt,
    prime: BigInt,
}

//private param a
struct PartyOne<'a> {
    cyclic_group: &'a SharedConfig,
    a: BigInt
}

//private param b
struct PartyTwo<'a> {
    cyclic_group: &'a SharedConfig,
    b: BigInt
}

impl<'a> PartyOne<'a> {
    //Alice computes g^a mod p and sends result to Bob
    fn config(&self) -> BigInt {
        let g: BigInt = self.cyclic_group.generator.clone();
        let p: BigInt = self.cyclic_group.prime.clone();

        g.modpow(&self.a, &p)
    }

    //once received computation from Bob, Alice computes shared key (g^b)^a mod p
    fn compute_shared_key(&self, p2_setup: BigInt) -> BigInt {
        let p: BigInt = self.cyclic_group.prime.clone();

        p2_setup.modpow(&self.a, &p)
    }
}

impl<'a> PartyTwo<'a> {
    //Bob computes g^b mod p and sends result to Alice
    fn config(&self) -> BigInt {
        let g: BigInt = self.cyclic_group.generator.clone();
        let p: BigInt = self.cyclic_group.prime.clone();

        g.modpow(&self.b, &p)
    }

    //once received computation from Alice, Bob computes shared key (g^a)^b mod p
    fn compute_shared_key(&self, p1_setup: BigInt) -> BigInt {
        let p: BigInt = self.cyclic_group.prime.clone();

        p1_setup.modpow(&self.b, &p)
    }
}