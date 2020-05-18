//! Transaction sighash helpers

use crate::messages::{OutPoint, Payload, Tx, TxOut};
use crate::script::{next_op, op_codes, Script};
use crate::util::{sha256d, var_int, Error, Hash256, Result, Serializable};
use byteorder::{LittleEndian, WriteBytesExt};
use std::io::Write;

/// Signs all of the outputs
pub const SIGHASH_ALL: u8 = 0x01;
/// Sign none of the outputs so that they may be spent anywhere
pub const SIGHASH_NONE: u8 = 0x02;
/// Sign only the output paired with the the input
pub const SIGHASH_SINGLE: u8 = 0x03;
/// Sign only the input so others may inputs to the transaction
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;
/// Bitcoin Cash / SV sighash flag for use on outputs after the fork
pub const SIGHASH_FORKID: u8 = 0x40;

/// The 24-bit fork ID for Bitcoin Cash / SV
const FORK_ID: u32 = 0;

/// Generates a transaction digest for signing
///
/// This will use either BIP-143 or the legacy algorithm depending on if SIGHASH_FORKID is set.
///
/// # Arguments
///
/// * `tx` - Spending transaction
/// * `n_input` - Spending input index
/// * `script_code` - The lock_script of the output being spent. This may be a subset of the
/// lock_script if OP_CODESEPARATOR is used.
/// * `satoshis` - The satoshi amount in the output being spent
/// * `sighash_type` - Sighash flags
/// * `cache` - Cache to store intermediate values for future sighash calls.
pub fn sighash(
    tx: &Tx,
    n_input: usize,
    script_code: &[u8],
    satoshis: i64,
    sighash_type: u8,
    cache: &mut SigHashCache,
) -> Result<Hash256> {
    if sighash_type & SIGHASH_FORKID != 0 {
        bip143_sighash(tx, n_input, script_code, satoshis, sighash_type, cache)
    } else {
        legacy_sighash(tx, n_input, script_code, sighash_type)
    }
}

/// Cache for sighash intermediate values to avoid quadratic hashing
///
/// This is only valid for one transaction, but may be used for multiple signatures.
pub struct SigHashCache {
    hash_prevouts: Option<Hash256>,
    hash_sequence: Option<Hash256>,
    hash_outputs: Option<Hash256>,
}

impl SigHashCache {
    /// Creates a new cache
    pub fn new() -> SigHashCache {
        SigHashCache {
            hash_prevouts: None,
            hash_sequence: None,
            hash_outputs: None,
        }
    }
}

/// Generates a transaction digest for signing using BIP-143
///
/// This is to be used for all tranasctions after the August 2017 fork.
/// It fixing quadratic hashing and includes the satoshis spent in the hash.
fn bip143_sighash(
    tx: &Tx,
    n_input: usize,
    script_code: &[u8],
    satoshis: i64,
    sighash_type: u8,
    cache: &mut SigHashCache,
) -> Result<Hash256> {
    if n_input >= tx.inputs.len() {
        return Err(Error::BadArgument("input out of tx_in range".to_string()));
    }

    let mut s = Vec::with_capacity(tx.size());
    let base_type = sighash_type & 31;
    let anyone_can_pay = sighash_type & SIGHASH_ANYONECANPAY != 0;

    // 1. Serialize version
    s.write_u32::<LittleEndian>(tx.version)?;

    // 2. Serialize hash of prevouts
    if !anyone_can_pay {
        if cache.hash_prevouts.is_none() {
            let mut prev_outputs = Vec::with_capacity(OutPoint::SIZE * tx.inputs.len());
            for input in tx.inputs.iter() {
                input.prev_output.write(&mut prev_outputs)?;
            }
            cache.hash_prevouts = Some(sha256d(&prev_outputs));
        }
        s.write(&cache.hash_prevouts.unwrap().0)?;
    } else {
        s.write(&[0; 32])?;
    }

    // 3. Serialize hash of sequences
    if !anyone_can_pay && base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE {
        if cache.hash_sequence.is_none() {
            let mut sequences = Vec::with_capacity(4 * tx.inputs.len());
            for tx_in in tx.inputs.iter() {
                sequences.write_u32::<LittleEndian>(tx_in.sequence)?;
            }
            cache.hash_sequence = Some(sha256d(&sequences));
        }
        s.write(&cache.hash_sequence.unwrap().0)?;
    } else {
        s.write(&[0; 32])?;
    }

    // 4. Serialize prev output
    tx.inputs[n_input].prev_output.write(&mut s)?;

    // 5. Serialize input script
    var_int::write(script_code.len() as u64, &mut s)?;
    s.write(&script_code)?;

    // 6. Serialize satoshis
    s.write_i64::<LittleEndian>(satoshis)?;

    // 7. Serialize sequence
    s.write_u32::<LittleEndian>(tx.inputs[n_input].sequence)?;

    // 8. Serialize hash of outputs
    if base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE {
        if cache.hash_outputs.is_none() {
            let mut size = 0;
            for tx_out in tx.outputs.iter() {
                size += tx_out.size();
            }
            let mut outputs = Vec::with_capacity(size);
            for tx_out in tx.outputs.iter() {
                tx_out.write(&mut outputs)?;
            }
            cache.hash_outputs = Some(sha256d(&outputs));
        }
        s.write(&cache.hash_outputs.unwrap().0)?;
    } else if base_type == SIGHASH_SINGLE && n_input < tx.outputs.len() {
        let mut outputs = Vec::with_capacity(tx.outputs[n_input].size());
        tx.outputs[n_input].write(&mut outputs)?;
        s.write(&sha256d(&outputs).0)?;
    } else {
        s.write(&[0; 32])?;
    }

    // 9. Serialize lock_time
    s.write_u32::<LittleEndian>(tx.lock_time)?;

    // 10. Serialize hash type
    s.write_u32::<LittleEndian>((FORK_ID << 8) | sighash_type as u32)?;

    Ok(sha256d(&s))
}

/// Generates the transaction digest for signing using the legacy algorithm
///
/// This is used for all transaction validation before the August 2017 fork.
fn legacy_sighash(
    tx: &Tx,
    n_input: usize,
    script_code: &[u8],
    sighash_type: u8,
) -> Result<Hash256> {
    if n_input >= tx.inputs.len() {
        return Err(Error::BadArgument("input out of tx_in range".to_string()));
    }

    let mut s = Vec::with_capacity(tx.size());
    let base_type = sighash_type & 31;
    let anyone_can_pay = sighash_type & SIGHASH_ANYONECANPAY != 0;

    // Remove all instances of OP_CODESEPARATOR from the script_code
    let mut sub_script = Vec::with_capacity(script_code.len());
    let mut i = 0;
    while i < script_code.len() {
        let next = next_op(i, script_code);
        if script_code[i] != op_codes::OP_CODESEPARATOR {
            sub_script.extend_from_slice(&script_code[i..next]);
        }
        i = next;
    }

    // Serialize the version
    s.write_u32::<LittleEndian>(tx.version)?;

    // Serialize the inputs
    let n_inputs = if anyone_can_pay { 1 } else { tx.inputs.len() };
    var_int::write(n_inputs as u64, &mut s)?;
    for i in 0..tx.inputs.len() {
        let i = if anyone_can_pay { n_input } else { i };
        let mut tx_in = tx.inputs[i].clone();
        if i == n_input {
            tx_in.unlock_script = Script(Vec::with_capacity(4 + sub_script.len()));
            tx_in.unlock_script.0.extend_from_slice(&sub_script);
        } else {
            tx_in.unlock_script = Script(vec![]);
            if base_type == SIGHASH_NONE || base_type == SIGHASH_SINGLE {
                tx_in.sequence = 0;
            }
        }
        tx_in.write(&mut s)?;
        if anyone_can_pay {
            break;
        }
    }

    // Serialize the outputs
    let tx_out_list = if base_type == SIGHASH_NONE {
        vec![]
    } else if base_type == SIGHASH_SINGLE {
        if n_input >= tx.outputs.len() {
            return Err(Error::BadArgument("input out of tx_out range".to_string()));
        }
        let mut truncated_out = tx.outputs.clone();
        truncated_out.truncate(n_input + 1);
        truncated_out
    } else {
        tx.outputs.clone()
    };
    var_int::write(tx_out_list.len() as u64, &mut s)?;
    for i in 0..tx_out_list.len() {
        if i == n_input && base_type == SIGHASH_SINGLE {
            let empty = TxOut {
                satoshis: -1,
                lock_script: Script(vec![]),
            };
            empty.write(&mut s)?;
        } else {
            tx_out_list[i].write(&mut s)?;
        }
    }

    // Serialize the lock time
    s.write_u32::<LittleEndian>(tx.lock_time)?;

    // Append the sighash_type and finally double hash the result
    s.write_u32::<LittleEndian>(sighash_type as u32)?;
    Ok(sha256d(&s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::addr_decode;
    use crate::messages::{OutPoint, TxIn};
    use crate::network::Network;
    use crate::transaction::p2pkh;
    use hex;

    #[test]
    fn bip143_sighash_test() {
        let lock_script =
            hex::decode("76a91402b74813b047606b4b3fbdfb1a6e8e053fdb8dab88ac").unwrap();
        let addr = "mfmKD4cP6Na7T8D87XRSiR7shA1HNGSaec";
        let hash160 = addr_decode(addr, Network::Testnet).unwrap().0;
        let tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    hash: Hash256::decode(
                        "f671dc000ad12795e86b59b27e0c367d9b026bbd4141c227b9285867a53bb6f7",
                    )
                    .unwrap(),
                    index: 0,
                },
                unlock_script: Script(vec![]),
                sequence: 0,
            }],
            outputs: vec![
                TxOut {
                    satoshis: 100,
                    lock_script: p2pkh::create_lock_script(&hash160),
                },
                TxOut {
                    satoshis: 259899900,
                    lock_script: p2pkh::create_lock_script(&hash160),
                },
            ],
            lock_time: 0,
        };
        let mut cache = SigHashCache::new();
        let sighash_type = SIGHASH_ALL | SIGHASH_FORKID;
        let sighash =
            bip143_sighash(&tx, 0, &lock_script, 260000000, sighash_type, &mut cache).unwrap();
        let expected = "1e2121837829018daf3aeadab76f1a542c49a3600ded7bd74323ee74ce0d840c";
        assert!(sighash.0.to_vec() == hex::decode(expected).unwrap());
        assert!(cache.hash_prevouts.is_some());
        assert!(cache.hash_sequence.is_some());
        assert!(cache.hash_outputs.is_some());
    }

    #[test]
    fn legacy_sighash_test() {
        let lock_script =
            hex::decode("76a914d951eb562f1ff26b6cbe89f04eda365ea6bd95ce88ac").unwrap();
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    hash: Hash256::decode(
                        "bf6c1139ea01ca054b8d00aa0a088daaeab4f3b8e111626c6be7d603a9dd8dff",
                    )
                    .unwrap(),
                    index: 0,
                },
                unlock_script: Script(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                satoshis: 49990000,
                lock_script: Script(
                    hex::decode("76a9147865b0b301119fc3eadc7f3406ff1339908e46d488ac").unwrap(),
                ),
            }],
            lock_time: 0,
        };
        let sighash = legacy_sighash(&tx, 0, &lock_script, SIGHASH_ALL).unwrap();
        let expected = "ad16084eccf26464a84c5ee2f8b96b4daff9a3154ac3c1b320346aed042abe57";
        assert!(sighash.0.to_vec() == hex::decode(expected).unwrap());
    }
}
