//! Functions to convert between different bitcoin denominations

use crate::util::{Error, Result};
use std::fmt;

/// Denomination of a bitcoin amount
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Units {
    /// One bitcoin
    Bsv,
    /// One millionth of a bitcoin
    Bits,
    /// One hundred millionth of a bitcoin
    Sats,
}

impl Units {
    pub fn parse(s: &str) -> Result<Units> {
        let s = s.to_lowercase();
        if s == "bsv" || s == "bitcoin" {
            return Ok(Units::Bsv);
        } else if s == "bit" || s == "bits" {
            return Ok(Units::Bits);
        } else if s == "sat" || s == "sats" {
            return Ok(Units::Sats);
        } else {
            let msg = format!("Unknown units: {}", s);
            return Err(Error::BadArgument(msg));
        }
    }
}

/// An amount of bitcoin in satoshis
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct Amount(pub i64);

impl Amount {
    /// Creates from a given amount and unit
    pub fn from(amount: f64, units: Units) -> Amount {
        match units {
            Units::Bsv => Amount((amount * 100_000_000.) as i64),
            Units::Bits => Amount((amount * 100.) as i64),
            Units::Sats => Amount(amount as i64),
        }
    }

    /// Converts the amount to a given unit
    pub fn to(&self, units: Units) -> f64 {
        match units {
            Units::Bsv => self.0 as f64 / 100_000_000.,
            Units::Bits => self.0 as f64 / 100.,
            Units::Sats => self.0 as f64,
        }
    }
}
impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&format!("{} bsv", self.to(Units::Bsv)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_to() {
        assert!(Amount(0).to(Units::Bsv) == 0.);
        assert!(Amount(0).to(Units::Bits) == 0.);
        assert!(Amount(0).to(Units::Sats) == 0.);

        assert!(Amount(1).to(Units::Bsv) == 0.00000001);
        assert!(Amount(1).to(Units::Bits) == 0.01);
        assert!(Amount(1).to(Units::Sats) == 1.);

        assert!(Amount(9).to(Units::Bsv) == 0.00000009);
        assert!(Amount(9).to(Units::Bits) == 0.09);
        assert!(Amount(9).to(Units::Sats) == 9.);

        assert!(Amount::from(0., Units::Bsv).0 == 0);
        assert!(Amount::from(0., Units::Bits).0 == 0);
        assert!(Amount::from(0., Units::Sats).0 == 0);

        assert!(Amount::from(1., Units::Bsv).0 == 100_000_000);
        assert!(Amount::from(1., Units::Bits).0 == 100);
        assert!(Amount::from(1., Units::Sats).0 == 1);

        assert!(Amount::from(9., Units::Bsv).0 == 900_000_000);
        assert!(Amount::from(9., Units::Bits).0 == 900);
        assert!(Amount::from(9., Units::Sats).0 == 9);

        assert!(Amount::from(1., Units::Bsv).to(Units::Bsv) == 1.);
        assert!(Amount::from(0.01, Units::Bsv).to(Units::Bsv) == 0.01);
        assert!(Amount::from(99., Units::Bits).to(Units::Bits) == 99.);
        assert!(Amount::from(1., Units::Sats).to(Units::Sats) == 1.);
    }
}
