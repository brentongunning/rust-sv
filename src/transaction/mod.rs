//! Build and sign transactions
//!
//! # Examples
//!
//! Sign a transaction:
//!
//! ```rust
//! use sv::messages::{Tx, TxIn};
//! use sv::transaction::generate_signature;
//! use sv::transaction::p2pkh::{create_pk_script, create_sig_script};
//! use sv::transaction::sighash::{sighash, SigHashCache, SIGHASH_FORKID, SIGHASH_NONE};
//! use sv::util::{hash160, Amount};
//!
//! // Use real values here
//! let mut tx = Tx {
//!     inputs: vec![TxIn {
//!         ..Default::default()
//!     }],
//!     ..Default::default()
//! };
//! let private_key = [1; 32];
//! let public_key = [1; 33];
//!
//! let pk_script = create_pk_script(&hash160(&public_key));
//! let mut cache = SigHashCache::new();
//! let sighash_type = SIGHASH_NONE | SIGHASH_FORKID;
//! let sighash = sighash(&tx, 0, &pk_script.0, Amount(0), sighash_type, &mut cache).unwrap();
//! let signature = generate_signature(&private_key, &sighash, sighash_type).unwrap();
//! tx.inputs[0].sig_script = create_sig_script(&signature, &public_key);
//! ```

use crate::util::{Hash256, Result};
use secp256k1::{Message, Secp256k1, SecretKey};

pub mod p2pkh;
pub mod sighash;

/// Generates a signature for a transaction sighash
pub fn generate_signature(
    private_key: &[u8; 32],
    sighash: &Hash256,
    sighash_type: u8,
) -> Result<Vec<u8>> {
    let secp = Secp256k1::signing_only();
    let message = Message::from_slice(&sighash.0)?;
    let secret_key = SecretKey::from_slice(private_key)?;
    let mut signature = secp.sign(&message, &secret_key);
    signature.normalize_s();
    let mut sig = signature.serialize_der();
    sig.push(sighash_type);
    Ok(sig)
}
