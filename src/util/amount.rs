//! Functions to convert between different bitcoin denominations

use std::fmt;

/// An amount of bitcoin in satoshis
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct Amount(pub i64);

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&format!("{} sats", self.0))
    }
}
