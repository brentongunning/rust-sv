use crate::network::Network;
use crate::util::{hash160, sha256d, Error, Result, Serializable};
use byteorder::{BigEndian, WriteBytesExt};
use ring::digest::SHA512;
use ring::hmac;
use rust_base58::base58::{FromBase58, ToBase58};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::fmt;
use std::io;
use std::io::{Cursor, Read, Write};
use std::slice;

/// Maximum private key value (exclusive)
const SECP256K1_CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Index which begins the derived hardened keys
pub const HARDENED_KEY: u32 = 2147483648;

/// "xpub" prefix for public extended keys on mainnet
pub const MAINNET_PUBLIC_EXTENDED_KEY: u32 = 0x0488B21E;
/// "xprv" prefix for private extended keys on mainnet
pub const MAINNET_PRIVATE_EXTENDED_KEY: u32 = 0x0488ADE4;
/// "tpub" prefix for public extended keys on testnet
pub const TESTNET_PUBLIC_EXTENDED_KEY: u32 = 0x043587C;
/// "tprv" prefix for private extended keys on testnet
pub const TESTNET_PRIVATE_EXTENDED_KEY: u32 = 0x04358394;

/// Public or private key type
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ExtendedKeyType {
    Public,
    Private,
}

/// A private or public key in an hierarchial deterministic wallet
#[derive(Clone, Copy)]
pub struct ExtendedKey(pub [u8; 78]);

impl ExtendedKey {
    /// Creates a new extended public key
    pub fn new_public_key(
        network: Network,
        depth: u8,
        parent_fingerprint: &[u8],
        index: u32,
        chain_code: &[u8],
        public_key: &[u8],
    ) -> Result<ExtendedKey> {
        if parent_fingerprint.len() != 4 {
            return Err(Error::BadArgument("Fingerprint must be len 4".to_string()));
        }
        if chain_code.len() != 32 {
            return Err(Error::BadArgument("Chain code must be len 32".to_string()));
        }
        if public_key.len() != 33 {
            return Err(Error::BadArgument("Public key must be len 33".to_string()));
        }
        let mut extended_key = ExtendedKey([0; 78]);
        {
            let mut c = Cursor::new(&mut extended_key.0 as &mut [u8]);
            match network {
                Network::Mainnet => c
                    .write_u32::<BigEndian>(MAINNET_PUBLIC_EXTENDED_KEY)
                    .unwrap(),
                Network::Testnet => c
                    .write_u32::<BigEndian>(TESTNET_PUBLIC_EXTENDED_KEY)
                    .unwrap(),
            }
            c.write_u8(depth).unwrap();
            c.write(parent_fingerprint).unwrap();
            c.write_u32::<BigEndian>(index).unwrap();
            c.write(chain_code).unwrap();
            c.write(public_key).unwrap();
        }
        Ok(extended_key)
    }

    /// Creates a new extended private key
    pub fn new_private_key(
        network: Network,
        depth: u8,
        parent_fingerprint: &[u8],
        index: u32,
        chain_code: &[u8],
        private_key: &[u8],
    ) -> Result<ExtendedKey> {
        if parent_fingerprint.len() != 4 {
            return Err(Error::BadArgument("Fingerprint must be len 4".to_string()));
        }
        if chain_code.len() != 32 {
            return Err(Error::BadArgument("Chain code must be len 32".to_string()));
        }
        if private_key.len() != 32 {
            return Err(Error::BadArgument("Private key must be len 32".to_string()));
        }
        let mut extended_key = ExtendedKey([0; 78]);
        {
            let mut c = Cursor::new(&mut extended_key.0 as &mut [u8]);
            match network {
                Network::Mainnet => c
                    .write_u32::<BigEndian>(MAINNET_PRIVATE_EXTENDED_KEY)
                    .unwrap(),
                Network::Testnet => c
                    .write_u32::<BigEndian>(TESTNET_PRIVATE_EXTENDED_KEY)
                    .unwrap(),
            }
            c.write_u8(depth).unwrap();
            c.write(parent_fingerprint).unwrap();
            c.write_u32::<BigEndian>(index).unwrap();
            c.write(chain_code).unwrap();
            c.write_u8(0).unwrap();
            c.write(private_key).unwrap();
        }
        Ok(extended_key)
    }

    /// Gets the extended key version byte prefix
    pub fn version(&self) -> u32 {
        ((self.0[0] as u32) << 24)
            | ((self.0[1] as u32) << 16)
            | ((self.0[2] as u32) << 8)
            | ((self.0[3] as u32) << 0)
    }

    /// Gets the network
    pub fn network(&self) -> Result<Network> {
        let ver = self.version();
        if ver == MAINNET_PUBLIC_EXTENDED_KEY || ver == MAINNET_PRIVATE_EXTENDED_KEY {
            return Ok(Network::Mainnet);
        } else if ver == TESTNET_PUBLIC_EXTENDED_KEY || ver == TESTNET_PRIVATE_EXTENDED_KEY {
            return Ok(Network::Testnet);
        } else {
            let msg = format!("Unknown extended key version {:?}", ver);
            return Err(Error::BadData(msg));
        }
    }

    /// Gets the key type
    pub fn key_type(&self) -> Result<ExtendedKeyType> {
        let ver = self.version();
        if ver == MAINNET_PUBLIC_EXTENDED_KEY || ver == TESTNET_PUBLIC_EXTENDED_KEY {
            return Ok(ExtendedKeyType::Public);
        } else if ver == MAINNET_PRIVATE_EXTENDED_KEY || ver == TESTNET_PRIVATE_EXTENDED_KEY {
            return Ok(ExtendedKeyType::Private);
        } else {
            let msg = format!("Unknown extended key version {:?}", ver);
            return Err(Error::BadData(msg));
        }
    }

    /// Gets the depth
    pub fn depth(&self) -> u8 {
        self.0[4]
    }

    /// Gets the first 4 bytes of the parent key, or 0 if this is the master key
    pub fn parent_fingerprint(&self) -> [u8; 4] {
        [self.0[5], self.0[6], self.0[7], self.0[8]]
    }

    /// Get the index of this key as derived from the parent
    pub fn index(&self) -> u32 {
        ((self.0[9] as u32) << 24)
            | ((self.0[10] as u32) << 16)
            | ((self.0[11] as u32) << 8)
            | ((self.0[12] as u32) << 0)
    }

    /// Gets the chain code
    pub fn chain_code(&self) -> [u8; 32] {
        let mut chain_code = [0; 32];
        chain_code.clone_from_slice(&self.0[13..45]);
        chain_code
    }

    /// Gets the public key if this is an extended public key
    pub fn public_key(&self) -> Result<[u8; 33]> {
        match self.key_type()? {
            ExtendedKeyType::Public => {
                let mut public_key = [0; 33];
                public_key.clone_from_slice(&self.0[45..]);
                Ok(public_key)
            }
            ExtendedKeyType::Private => {
                let secp = Secp256k1::signing_only();
                let secp_secret_key = SecretKey::from_slice(&self.0[46..])?;
                let secp_public_key = PublicKey::from_secret_key(&secp, &secp_secret_key);
                Ok(secp_public_key.serialize())
            }
        }
    }

    /// Gets the private key if this is an extended private key
    pub fn private_key(&self) -> Result<[u8; 32]> {
        if self.key_type()? == ExtendedKeyType::Private {
            let mut private_key = [0; 32];
            private_key.clone_from_slice(&self.0[46..]);
            Ok(private_key)
        } else {
            let msg = "Cannot get private key of public extended key";
            Err(Error::BadData(msg.to_string()))
        }
    }

    /// Gets the fingerprint of the public key hash
    pub fn fingerprint(&self) -> Result<[u8; 4]> {
        let mut fingerprint = [0; 4];
        let public_key_hash = hash160(&self.public_key()?);
        fingerprint.clone_from_slice(&public_key_hash.0[..4]);
        Ok(fingerprint)
    }

    /// Gets the extenced public key for this key
    pub fn extended_public_key(&self) -> Result<ExtendedKey> {
        match self.key_type()? {
            ExtendedKeyType::Public => Ok(self.clone()),
            ExtendedKeyType::Private => {
                let private_key = &self.0[46..];
                let secp = Secp256k1::signing_only();
                let secp_secret_key = SecretKey::from_slice(&private_key)?;
                let secp_public_key = PublicKey::from_secret_key(&secp, &secp_secret_key);
                let public_key = secp_public_key.serialize();

                ExtendedKey::new_public_key(
                    self.network()?,
                    self.depth(),
                    &self.0[5..9],
                    self.index(),
                    &self.0[13..45],
                    &public_key,
                )
            }
        }
    }

    /// Derives an extended child private key from an extended parent private key
    pub fn derive_private_key(&self, index: u32) -> Result<ExtendedKey> {
        if self.key_type()? == ExtendedKeyType::Public {
            let msg = "Cannot derive private key from public key";
            return Err(Error::BadData(msg.to_string()));
        }
        let network = self.network()?;
        if self.depth() == 255 {
            let msg = "Cannot derive extended key. Depth already at max.";
            return Err(Error::BadData(msg.to_string()));
        }

        let secp = Secp256k1::signing_only();
        let private_key = &self.0[46..];
        let secp_par_secret_key = SecretKey::from_slice(&private_key)?;
        let chain_code = &self.0[13..45];
        let key = hmac::SigningKey::new(&SHA512, chain_code);

        let hmac = if index >= HARDENED_KEY {
            let mut v = Vec::<u8>::with_capacity(37);
            v.push(0);
            v.extend_from_slice(&private_key);
            v.write_u32::<BigEndian>(index)?;
            hmac::sign(&key, &v)
        } else {
            let mut v = Vec::<u8>::with_capacity(37);
            let secp_public_key = PublicKey::from_secret_key(&secp, &secp_par_secret_key);
            let public_key = secp_public_key.serialize();
            v.extend_from_slice(&public_key);
            v.write_u32::<BigEndian>(index)?;
            hmac::sign(&key, &v)
        };

        if hmac.as_ref().len() != 64 {
            return Err(Error::IllegalState("HMAC invalid length".to_string()));
        }

        if !is_private_key_valid(&hmac.as_ref()[..32]) {
            let msg = "Invalid key. Try next index.".to_string();
            return Err(Error::IllegalState(msg));
        }

        let mut secp_child_secret_key = SecretKey::from_slice(&hmac.as_ref()[..32])?;
        secp_child_secret_key.add_assign(&private_key)?;

        let child_chain_code = &hmac.as_ref()[32..];
        let fingerprint = self.fingerprint()?;
        let child_private_key =
            unsafe { slice::from_raw_parts(secp_child_secret_key.as_ptr(), 32) };

        ExtendedKey::new_private_key(
            network,
            self.depth() + 1,
            &fingerprint,
            index,
            child_chain_code,
            child_private_key,
        )
    }

    /// Derives an extended child public key from an extended parent public key
    pub fn derive_public_key(&self, index: u32) -> Result<ExtendedKey> {
        if index >= HARDENED_KEY {
            return Err(Error::BadArgument("i cannot be hardened".to_string()));
        }
        let network = self.network()?;
        if self.depth() == 255 {
            let msg = "Cannot derive extended key. Depth already at max.";
            return Err(Error::BadData(msg.to_string()));
        }

        let chain_code = &self.0[13..45];
        let key = hmac::SigningKey::new(&SHA512, chain_code);
        let mut v = Vec::<u8>::with_capacity(65);
        let public_key = self.public_key()?;
        v.extend_from_slice(&public_key);
        v.write_u32::<BigEndian>(index)?;
        let hmac = hmac::sign(&key, &v);

        if hmac.as_ref().len() != 64 {
            return Err(Error::IllegalState("HMAC invalid length".to_string()));
        }

        if !is_private_key_valid(&hmac.as_ref()[..32]) {
            let msg = "Invalid key. Try next index.".to_string();
            return Err(Error::IllegalState(msg));
        }

        let secp = Secp256k1::signing_only();
        let child_offset = SecretKey::from_slice(&hmac.as_ref()[..32])?;
        let child_offset = PublicKey::from_secret_key(&secp, &child_offset);
        let secp_par_public_key = PublicKey::from_slice(&public_key)?;
        let secp_child_public_key = secp_par_public_key.combine(&child_offset)?;
        let child_public_key = secp_child_public_key.serialize();

        let child_chain_code = &hmac.as_ref()[32..];
        let fingerprint = self.fingerprint()?;

        ExtendedKey::new_public_key(
            network,
            self.depth() + 1,
            &fingerprint,
            index,
            child_chain_code,
            &child_public_key,
        )
    }

    /// Encodes an extended key into a string
    pub fn encode(&self) -> String {
        let checksum = sha256d(&self.0);
        let mut v = Vec::with_capacity(82);
        v.extend_from_slice(&self.0);
        v.extend_from_slice(&checksum.0[..4]);
        v.to_base58()
    }

    /// Decodes an extended key from a string
    pub fn decode(s: &str) -> Result<ExtendedKey> {
        let v = s.from_base58()?;
        let checksum = sha256d(&v[..78]);
        if checksum.0[..4] != v[78..] {
            return Err(Error::BadArgument("Invalid checksum".to_string()));
        }
        let mut extended_key = ExtendedKey([0; 78]);
        extended_key.0.clone_from_slice(&v[..78]);
        Ok(extended_key)
    }
}

impl Serializable<ExtendedKey> for ExtendedKey {
    fn read(reader: &mut dyn Read) -> Result<ExtendedKey> {
        let mut k = ExtendedKey([0; 78]);
        reader.read(&mut k.0)?;
        Ok(k)
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write(&self.0)?;
        Ok(())
    }
}

impl fmt::Debug for ExtendedKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.encode())
    }
}

impl PartialEq for ExtendedKey {
    fn eq(&self, other: &ExtendedKey) -> bool {
        self.0.to_vec() == other.0.to_vec()
    }
}

impl Eq for ExtendedKey {}

/// Derives a key using the BIP-32 and BIP-44 shortened key notation
pub fn derive_extended_key(master: &ExtendedKey, path: &str) -> Result<ExtendedKey> {
    let parts: Vec<&str> = path.split('/').collect();
    let mut key_type = ExtendedKeyType::Public;

    if parts[0] == "m" {
        if master.key_type()? == ExtendedKeyType::Public {
            let msg = "Cannot derive private key from public master";
            return Err(Error::BadArgument(msg.to_string()));
        }
        key_type = ExtendedKeyType::Private;
    } else if parts[0] != "M" {
        let msg = "Path must start with m or M";
        return Err(Error::BadArgument(msg.to_string()));
    }

    let mut key = master.clone();

    for part in parts[1..].iter() {
        if part.len() == 0 {
            let msg = "Empty part";
            return Err(Error::BadArgument(msg.to_string()));
        }

        let index = if part.ends_with("'") || part.ends_with("h") || part.ends_with("H") {
            let index: u32 = part
                .trim_end_matches("'")
                .trim_end_matches("h")
                .trim_end_matches("H")
                .parse()?;
            if index >= HARDENED_KEY {
                let msg = "Key index is already hardened";
                return Err(Error::BadArgument(msg.to_string()));
            }
            index + HARDENED_KEY
        } else {
            part.parse()?
        };

        key = match key_type {
            ExtendedKeyType::Public => key.derive_public_key(index)?,
            ExtendedKeyType::Private => key.derive_private_key(index)?,
        };
    }

    Ok(key)
}

/// Checks that a private key is in valid SECP256K1 range
pub fn is_private_key_valid(key: &[u8]) -> bool {
    let mut is_below_order = false;
    if key.len() != 32 {
        return false;
    }
    for i in 0..32 {
        if key[i] < SECP256K1_CURVE_ORDER[i] {
            is_below_order = true;
            break;
        }
    }
    if !is_below_order {
        return false;
    }
    for i in 0..32 {
        if key[i] != 0 {
            return true;
        }
    }
    return false;
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn private_key_range() {
        // Valid
        let mut max = SECP256K1_CURVE_ORDER.clone();
        max[31] = max[31] - 1;
        assert!(is_private_key_valid(&max));
        assert!(is_private_key_valid(&[0x01; 32]));

        // Invalid
        assert!(!is_private_key_valid(&[0x00; 32]));
        assert!(!is_private_key_valid(&[0xff; 32]));
        assert!(!is_private_key_valid(&SECP256K1_CURVE_ORDER));
    }

    #[test]
    fn path() {
        // BIP-32 test vector 1
        let m = master_private_key("000102030405060708090a0b0c0d0e0f");
        assert!(derive_extended_key(&m, "m").unwrap().encode() == "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");
        assert!(derive_extended_key(&m, "m").unwrap().extended_public_key().unwrap().encode() == "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
        assert!(derive_extended_key(&m, "m/0H").unwrap().encode() == "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7");
        assert!(derive_extended_key(&m, "m/0H").unwrap().extended_public_key().unwrap().encode() == "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw");
        assert!(derive_extended_key(&m, "m/0h/1").unwrap().encode() == "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs");
        assert!(
            derive_extended_key(&m, "m/0h/1")
                .unwrap()
                .extended_public_key()
                .unwrap()
                .encode()
                == "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
        );
        assert!(derive_extended_key(&m, "m/0h/1/2'").unwrap().encode() == "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM");
        assert!(
            derive_extended_key(&m, "m/0h/1/2'")
                .unwrap()
                .extended_public_key()
                .unwrap()
                .encode()
                == "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
        );
        assert!(derive_extended_key(&m, "m/0H/1/2H/2").unwrap().encode() == "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334");
        assert!(
            derive_extended_key(&m, "m/0H/1/2H/2")
                .unwrap()
                .extended_public_key()
                .unwrap()
                .encode()
                == "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
        );
        assert!(
            derive_extended_key(&m, "m/0H/1/2H/2/1000000000")
                .unwrap()
                .encode()
                == "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
        );
        assert!(
            derive_extended_key(&m, "m/0H/1/2H/2/1000000000")
                .unwrap()
                .extended_public_key()
                .unwrap()
                .encode()
                == "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
        );

        // BIP-32 test vector 2
        let m = master_private_key("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");
        assert!(derive_extended_key(&m, "m").unwrap().encode() == "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U");
        assert!(derive_extended_key(&m, "m").unwrap().extended_public_key().unwrap().encode() == "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB");
        assert!(derive_extended_key(&m, "m/0").unwrap().encode() == "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt");
        assert!(derive_extended_key(&m, "m/0").unwrap().extended_public_key().unwrap().encode() == "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH");
        assert!(derive_extended_key(&m, "m/0/2147483647H").unwrap().encode() == "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9");
        assert!(derive_extended_key(&m, "m/0/2147483647H").unwrap().extended_public_key().unwrap().encode() == "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a");
        assert!(derive_extended_key(&m, "m/0/2147483647H/1").unwrap().encode() == "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef");
        assert!(derive_extended_key(&m, "m/0/2147483647H/1").unwrap().extended_public_key().unwrap().encode() == "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon");
        assert!(derive_extended_key(&m, "m/0/2147483647H/1/2147483646H").unwrap().encode() == "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc");
        assert!(derive_extended_key(&m, "m/0/2147483647H/1/2147483646H").unwrap().extended_public_key().unwrap().encode() == "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL");
        assert!(derive_extended_key(&m, "m/0/2147483647H/1/2147483646H/2").unwrap().encode() == "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j");
        assert!(derive_extended_key(&m, "m/0/2147483647H/1/2147483646H/2").unwrap().extended_public_key().unwrap().encode() == "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt");

        // BIP-32 test vector 3
        let m = master_private_key("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be");
        assert!(derive_extended_key(&m, "m").unwrap().encode() == "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6");
        assert!(derive_extended_key(&m, "m").unwrap().extended_public_key().unwrap().encode() == "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13");
        assert!(derive_extended_key(&m, "m/0H").unwrap().encode() == "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L");
        assert!(derive_extended_key(&m, "m/0H").unwrap().extended_public_key().unwrap().encode() == "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y");
    }

    #[test]
    fn new_public_key() {
        let key = ExtendedKey::new_public_key(
            Network::Testnet,
            111,
            &[0, 1, 2, 3],
            44,
            &[5; 32],
            &[6; 33],
        )
        .unwrap();
        assert!(key.network().unwrap() == Network::Testnet);
        assert!(key.key_type().unwrap() == ExtendedKeyType::Public);
        assert!(key.depth() == 111);
        assert!(key.parent_fingerprint() == [0_u8, 1_u8, 2_u8, 3_u8]);
        assert!(key.index() == 44);
        assert!(key.chain_code() == [5_u8; 32]);
        assert!(
            key.public_key().unwrap()[1..] == [6_u8; 32] && key.public_key().unwrap()[0] == 6_u8
        );

        // Errors
        assert!(ExtendedKey::new_public_key(
            Network::Testnet,
            111,
            &[0, 1, 2],
            44,
            &[5; 32],
            &[6; 33],
        )
        .is_err());
        assert!(ExtendedKey::new_public_key(
            Network::Testnet,
            111,
            &[0, 1, 2, 3],
            44,
            &[5; 31],
            &[6; 33],
        )
        .is_err());
        assert!(ExtendedKey::new_public_key(
            Network::Testnet,
            111,
            &[0, 1, 2, 3],
            44,
            &[5; 32],
            &[6; 32],
        )
        .is_err());
    }

    #[test]
    fn new_private_key() {
        let key = ExtendedKey::new_private_key(
            Network::Mainnet,
            255,
            &[4, 5, 6, 7],
            HARDENED_KEY + 100,
            &[7; 32],
            &[8; 32],
        )
        .unwrap();
        assert!(key.network().unwrap() == Network::Mainnet);
        assert!(key.key_type().unwrap() == ExtendedKeyType::Private);
        assert!(key.depth() == 255);
        assert!(key.parent_fingerprint() == [4_u8, 5_u8, 6_u8, 7_u8]);
        assert!(key.index() == HARDENED_KEY + 100);
        assert!(key.chain_code() == [7_u8; 32]);
        assert!(key.private_key().unwrap() == [8_u8; 32]);

        // Errors
        assert!(ExtendedKey::new_private_key(
            Network::Mainnet,
            255,
            &[4, 5, 6],
            HARDENED_KEY + 100,
            &[7; 32],
            &[8; 32],
        )
        .is_err());
        assert!(ExtendedKey::new_private_key(
            Network::Mainnet,
            255,
            &[4, 5, 6, 7],
            HARDENED_KEY + 100,
            &[7],
            &[8; 32],
        )
        .is_err());
        assert!(ExtendedKey::new_private_key(
            Network::Mainnet,
            255,
            &[4, 5, 6, 7],
            HARDENED_KEY + 100,
            &[7; 32],
            &[8; 33],
        )
        .is_err());
    }

    #[test]
    fn invalid() {
        let k = ExtendedKey([5; 78]);
        assert!(k.network().is_err());
        assert!(k.key_type().is_err());
    }

    #[test]
    fn encode_decode() {
        let k = master_private_key("0123456789abcdef");
        assert!(k == ExtendedKey::decode(&k.encode()).unwrap());
        let k = derive_extended_key(&k, "M/1/2/3/4/5").unwrap();
        assert!(k == ExtendedKey::decode(&k.encode()).unwrap());
    }

    fn master_private_key(seed: &str) -> ExtendedKey {
        let seed = hex::decode(seed).unwrap();
        let key = "Bitcoin seed".to_string();
        let key = hmac::SigningKey::new(&SHA512, &key.as_bytes());
        let hmac = hmac::sign(&key, &seed);
        ExtendedKey::new_private_key(
            Network::Mainnet,
            0,
            &[0; 4],
            0,
            &hmac.as_ref()[32..],
            &hmac.as_ref()[0..32],
        )
        .unwrap()
    }
}
