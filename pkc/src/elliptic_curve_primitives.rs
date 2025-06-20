use num_bigint::BigInt;
use std::ops::Rem;


///elliptic curve construction:
/// E: y^2 = x^3 + ax + b (mod p), O = point at infinity
/// 
/// implementations:
/// 
/// 1. construction
/// 2. point addition
/// 3. point doubling
/// 4. double and add algorithm 
#[derive(Debug)]
pub struct EC {
    a: BigInt,
    b: BigInt,
    p: BigInt
}


impl EC {
    //p = large prime
    pub fn new(mut a: BigInt, mut b: BigInt, p: BigInt) -> EC {
        if a > p {
            a = a.rem(&p)
        }

        if b > p {
            b = b.rem(&p)
        }

        //assert non-singularity
        let expr: BigInt = BigInt::from(4)*a.pow(3) + BigInt::from(27)*b.pow(2);
        let expr_modp: BigInt = expr.rem(&p);

        assert_ne!(expr_modp, BigInt::ZERO);

        Self { a, b, p }
    }

    //add two unique points
    pub fn point_addition_unique(&self, P: &(BigInt, BigInt), Q: &(BigInt, BigInt)) -> (BigInt, BigInt) {
        
        let a = &self.a;
        let b = &self.b;
        let p = &self.p;

        let P_x = &P.0;
        let P_y = &P.1;
        let lhs = (&P_y.pow(2)).rem(p);
        let rhs = (&P_x.pow(3)+ a*P_x + b).rem(p);
        assert_eq!(lhs, rhs, "point {:?} does not lie on E", P);

        let Q_x = &Q.0;
        let Q_y = &Q.1;
        let lhs = (&Q_y.pow(2)).rem(p);
        let rhs = (&Q_x.pow(3)+ a*Q_x + b).rem(p);
        assert_eq!(lhs, rhs, "point {:?} does not lie on E", Q);

        let s = (P_y - Q_y)*((P_x - Q_x).modinv(p).unwrap());

        let mut R_x = (s.pow(2) - P_x - Q_x).rem(p);
        let mut R_y = (s*(P_x - &R_x) - P_y).rem(p);

        if R_x < BigInt::ZERO {
            while R_x < BigInt::ZERO {
                R_x = R_x.checked_add(p).unwrap();
            }
        }

        if R_y < BigInt::ZERO {
            while R_y < BigInt::ZERO {
                R_y = R_y.checked_add(p).unwrap();
            }
        }

        (R_x, R_y)
    }

    //point doubling
    pub fn point_double(&self, P: &(BigInt, BigInt)) -> (BigInt, BigInt) {
        let a = &self.a;
        let b = &self.b;
        let p = &self.p;

        let P_x = &P.0;
        let P_y = &P.1;
        let lhs = (&P_y.pow(2)).rem(p);
        let rhs = (&P_x.pow(3)+ a*P_x + b).rem(p);
        assert_eq!(lhs, rhs, "point {:?} does not lie on E", P);

        let s: BigInt = (3*P_x.pow(2) + a) * (BigInt::from(P_y*2)).modinv(p).unwrap();

        let mut R_x = (s.pow(2) - BigInt::from(2)*P_x).rem(p);
        let mut R_y = (s*(P_x - &R_x) - P_y).rem(p);

        if R_x < BigInt::ZERO {
            while R_x < BigInt::ZERO {
                R_x = R_x.checked_add(p).unwrap();
            }
        }

        if R_y < BigInt::ZERO {
            while R_y < BigInt::ZERO {
                R_y = R_y.checked_add(p).unwrap();
            }
        }

        (R_x, R_y)
    }

    //double and add algorithm
    pub fn point_n_addition(&self, P: (BigInt, BigInt), n: BigInt) -> (BigInt, BigInt) {

        let a = &self.a;
        let b = &self.b;
        let p = &self.p;

        let P_x = &P.0;
        let P_y = &P.1;
        let lhs = (&P_y.pow(2)).rem(p);
        let rhs = (&P_x.pow(3)+ a*P_x + b).rem(p);
        assert_eq!(lhs, rhs, "point {:?} does not lie on E", P);
        

        // -----------------------------------------
        let n_bin = format!("{:b}", n);

        //initialise R as point at infinity (placeholder values)
        let mut R:(BigInt, BigInt) = (BigInt::ZERO, BigInt::ZERO);

        for digit in n_bin.chars() {
            //adding point at infinity to orginial point P at first iteration
            if R == (BigInt::ZERO, BigInt::ZERO) {
                R = P.clone();
            }
            if digit == '1' {
                let twoR = self.point_double(&R);
                R = self.point_addition_unique(&twoR, &P);
            } else {
                R = self.point_double(&R)
            }
        }
        
        R
    }
}