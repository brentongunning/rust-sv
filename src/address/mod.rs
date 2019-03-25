//! Address encoding and decoding
//!
//! # Examples
//!
//! Extract the public key hash and address type from a base-58 address:
//!
//! ```rust
//! use sv::address::addr_decode;
//! use sv::network::Network;
//!
//! let addr = "15wpV72HRpAFPMmosR3jvGq7axU7t6ghX5";
//! let (pubkeyhash, addr_type) = addr_decode(&addr, Network::Mainnet).unwrap();
//! ```
//!
//! Encode a public key hash into a base-58 address:
//!
//! ```rust
//! use sv::address::{addr_encode, AddressType};
//! use sv::network::Network;
//! use sv::util::hash160;
//!
//! let pubkeyhash = hash160(&[0; 33]);
//! let addr = addr_encode(&pubkeyhash, AddressType::P2PKH, Network::Mainnet);
//! ```
//!
use crate::network::Network;
use crate::util::{sha256d, Error, Hash160, Result};
use rust_base58::base58::{FromBase58, ToBase58};

/// Address type which is either P2PKH or P2SH
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// Pay-to-public-key-hash address
    P2PKH,
    /// Pay-to-script-hash address
    P2SH,
}

/// Converts a public key hash to its base-58 address
pub fn addr_encode(hash160: &Hash160, addr_type: AddressType, network: Network) -> String {
    let mut v = Vec::with_capacity(1 + hash160.0.len() + 2);
    v.push(match addr_type {
        AddressType::P2PKH => network.addr_pubkeyhash_flag(),
        AddressType::P2SH => network.addr_script_flag(),
    });
    v.extend_from_slice(&hash160.0);
    let checksum = sha256d(&v).0;
    v.push(checksum[0]);
    v.push(checksum[1]);
    v.push(checksum[2]);
    v.push(checksum[3]);
    let b: &[u8] = v.as_ref();
    b.to_base58()
}

/// Decodes a base-58 address to a public key hash
pub fn addr_decode(input: &str, network: Network) -> Result<(Hash160, AddressType)> {
    // Make sure addr is at least some minimum to verify checksum and addr type
    // We will check the private key size later.
    let v = input.from_base58()?;
    if v.len() < 6 {
        let msg = format!("Base58 address not long enough: {}", v.len());
        return Err(Error::BadData(msg));
    }

    // Verify checksum
    let v0 = &v[0..v.len() - 4];
    let v1 = &v[v.len() - 4..v.len()];
    let cs = sha256d(v0).0;
    if v1[0] != cs[0] || v1[1] != cs[1] || v1[2] != cs[2] || v1[3] != cs[3] {
        let msg = format!("Bad checksum: {:?} != {:?}", &cs[..4], v1);
        return Err(Error::BadData(msg));
    }

    // Extract address type
    let addr_type_byte = v0[0];
    let addr_type = if addr_type_byte == network.addr_pubkeyhash_flag() {
        AddressType::P2PKH
    } else if addr_type_byte == network.addr_script_flag() {
        AddressType::P2SH
    } else {
        let msg = format!("Unknown address type {}", addr_type_byte);
        return Err(Error::BadData(msg));
    };

    // Extract hash160 address and return
    if v0.len() != 21 {
        let msg = format!("Hash160 address not long enough: {}", v0.len() - 1);
        return Err(Error::BadData(msg));
    }
    let mut hash160addr = [0; 20];
    hash160addr.clone_from_slice(&v0[1..]);
    Ok((Hash160(hash160addr), addr_type))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hash160;
    use hex;

    #[test]
    fn to_addr() {
        let pubkey_hex = "04005937fd439b3c19014d5f328df8c7ed514eaaf41c1980b8aeab461dffb23fbf3317e42395db24a52ce9fc947d9c22f54dc3217c8b11dfc7a09c59e0dca591d3";
        let pubkeyhash = hash160(&hex::decode(pubkey_hex).unwrap());
        let addr = addr_encode(&pubkeyhash, AddressType::P2PKH, Network::Mainnet);
        assert!(addr == "1NM2HFXin4cEQRBLjkNZAS98qLX9JKzjKn");
    }

    #[test]
    fn from_addr() {
        let addr = "1NM2HFXin4cEQRBLjkNZAS98qLX9JKzjKn";
        let result = addr_decode(&addr, Network::Mainnet).unwrap();
        let hash160 = result.0;
        let addr_type = result.1;
        assert!(addr_type == AddressType::P2PKH);
        assert!(hex::encode(hash160.0) == "ea2407829a5055466b27784cde8cf463167946bf");
    }

    #[test]
    fn from_addr_errors() {
        assert!(addr_decode("0", Network::Mainnet).is_err());
        assert!(addr_decode("1000000000000000000000000000000000", Network::Mainnet).is_err());
    }
}
