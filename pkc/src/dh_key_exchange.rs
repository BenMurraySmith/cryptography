use num_bigint::BigInt;


fn main() {
    //3 is a generator of Z_17
    let p: BigInt = BigInt::from(17);
    let g: BigInt = BigInt::from(3);


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


struct SharedConfig {
    generator: BigInt,
    prime: BigInt,
}

struct PartyOne<'a> {
    cyclic_group: &'a SharedConfig,
    a: BigInt
}

struct PartyTwo<'a> {
    cyclic_group: &'a SharedConfig,
    b: BigInt
}

impl<'a> PartyOne<'a> {
    fn config(&self) -> BigInt {
        let g: BigInt = self.cyclic_group.generator.clone();
        let p: BigInt = self.cyclic_group.prime.clone();

        g.modpow(&self.a, &p)
    }

    fn compute_shared_key(&self, p2_setup: BigInt) -> BigInt {
        let p: BigInt = self.cyclic_group.prime.clone();

        p2_setup.modpow(&self.a, &p)
    }
}

impl<'a> PartyTwo<'a> {
    fn config(&self) -> BigInt {
        let g: BigInt = self.cyclic_group.generator.clone();
        let p: BigInt = self.cyclic_group.prime.clone();

        g.modpow(&self.b, &p)
    }

    fn compute_shared_key(&self, p1_setup: BigInt) -> BigInt {
        let p: BigInt = self.cyclic_group.prime.clone();

        p1_setup.modpow(&self.b, &p)
    }
}