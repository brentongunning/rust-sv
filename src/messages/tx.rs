use crate::messages::message::Payload;
use crate::messages::{OutPoint, TxIn, TxOut, COINBASE_OUTPOINT_HASH, COINBASE_OUTPOINT_INDEX};
use crate::script::{op_codes, Script, TransactionChecker};
use crate::transaction::sighash::SigHashCache;
use crate::util::{sha256d, var_int, Error, Hash256, Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use linked_hash_map::LinkedHashMap;
use std::fmt;
use std::io;
use std::io::{Read, Write};

/// Maximum number of satoshis possible
pub const MAX_SATOSHIS: i64 = 21_000_000 * 100_000_000;

/// Bitcoin transaction
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct Tx {
    /// Transaction version
    pub version: u32,
    /// Transaction inputs
    pub inputs: Vec<TxIn>,
    /// Transaction outputs
    pub outputs: Vec<TxOut>,
    /// The block number or timestamp at which this transaction is unlocked
    pub lock_time: u32,
}

impl Tx {
    /// Calculates the hash of the transaction also known as the txid
    pub fn hash(&self) -> Hash256 {
        let mut b = Vec::with_capacity(self.size());
        self.write(&mut b).unwrap();
        sha256d(&b)
    }

    /// Validates a non-coinbase transaction
    pub fn validate(
        &self,
        require_sighash_forkid: bool,
        utxos: &LinkedHashMap<OutPoint, TxOut>,
    ) -> Result<()> {
        // Make sure neither in or out lists are empty
        if self.inputs.len() == 0 {
            return Err(Error::BadData("inputs empty".to_string()));
        }
        if self.outputs.len() == 0 {
            return Err(Error::BadData("outputs empty".to_string()));
        }

        // Each output value, as well as the total, must be in legal money range
        let mut total_out = 0;
        for tx_out in self.outputs.iter() {
            if tx_out.amount.0 < 0 {
                return Err(Error::BadData("tx_out amount negative".to_string()));
            }
            total_out += tx_out.amount.0;
        }
        if total_out > MAX_SATOSHIS {
            return Err(Error::BadData("Total out exceeds max satoshis".to_string()));
        }

        // Make sure none of the inputs are coinbase transactions
        for tx_in in self.inputs.iter() {
            if tx_in.prev_output.hash == COINBASE_OUTPOINT_HASH
                && tx_in.prev_output.index == COINBASE_OUTPOINT_INDEX
            {
                return Err(Error::BadData("Unexpected coinbase".to_string()));
            }
        }

        // Check that lock_time <= INT_MAX because some clients interpret this differently
        if self.lock_time > 2_147_483_647 {
            return Err(Error::BadData("Lock time too large".to_string()));
        }

        // Check that all inputs are in the utxo set and are in legal money range
        let mut total_in = 0;
        for tx_in in self.inputs.iter() {
            let utxo = utxos.get(&tx_in.prev_output);
            if let Some(tx_out) = utxo {
                if tx_out.amount.0 < 0 {
                    return Err(Error::BadData("tx_out amount negative".to_string()));
                }
                total_in += tx_out.amount.0;
            } else {
                return Err(Error::BadData("utxo not found".to_string()));
            }
        }
        if total_in > MAX_SATOSHIS {
            return Err(Error::BadData("Total in exceeds max satoshis".to_string()));
        }

        // Check inputs spent > outputs received
        if total_in < total_out {
            return Err(Error::BadData("Output total exceeds input".to_string()));
        }

        // Verify each script
        let mut sighash_cache = SigHashCache::new();
        for input in 0..self.inputs.len() {
            let tx_in = &self.inputs[input];
            let tx_out = utxos.get(&tx_in.prev_output).unwrap();

            let mut script = Script::new();
            script.append_slice(&tx_in.sig_script.0);
            script.append(op_codes::OP_CODESEPARATOR);
            script.append_slice(&tx_out.pk_script.0);

            let mut tx_checker = TransactionChecker {
                tx: self,
                sig_hash_cache: &mut sighash_cache,
                input: input,
                amount: tx_out.amount,
                require_sighash_forkid,
            };

            script.eval(&mut tx_checker)?;
        }

        Ok(())
    }

    /// Returns whether the transaction is the block reward
    pub fn coinbase(&self) -> bool {
        return self.inputs.len() == 1
            && self.inputs[0].prev_output.hash == COINBASE_OUTPOINT_HASH
            && self.inputs[0].prev_output.index == COINBASE_OUTPOINT_INDEX;
    }
}

impl Serializable<Tx> for Tx {
    fn read(reader: &mut dyn Read) -> Result<Tx> {
        let version = reader.read_i32::<LittleEndian>()?;
        let version = version as u32;
        let n_inputs = var_int::read(reader)?;
        let mut inputs = Vec::with_capacity(n_inputs as usize);
        for _i in 0..n_inputs {
            inputs.push(TxIn::read(reader)?);
        }
        let n_outputs = var_int::read(reader)?;
        let mut outputs = Vec::with_capacity(n_outputs as usize);
        for _i in 0..n_outputs {
            outputs.push(TxOut::read(reader)?);
        }
        let lock_time = reader.read_u32::<LittleEndian>()?;
        Ok(Tx {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_u32::<LittleEndian>(self.version)?;
        var_int::write(self.inputs.len() as u64, writer)?;
        for tx_in in self.inputs.iter() {
            tx_in.write(writer)?;
        }
        var_int::write(self.outputs.len() as u64, writer)?;
        for tx_out in self.outputs.iter() {
            tx_out.write(writer)?;
        }
        writer.write_u32::<LittleEndian>(self.lock_time)?;
        Ok(())
    }
}

impl Payload<Tx> for Tx {
    fn size(&self) -> usize {
        let mut size = 8;
        size += var_int::size(self.inputs.len() as u64);
        for tx_in in self.inputs.iter() {
            size += tx_in.size();
        }
        size += var_int::size(self.outputs.len() as u64);
        for tx_out in self.outputs.iter() {
            size += tx_out.size();
        }
        size
    }
}

impl fmt::Debug for Tx {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let inputs_str = format!("[<{} inputs>]", self.inputs.len());
        let outputs_str = format!("[<{} outputs>]", self.outputs.len());

        f.debug_struct("Tx")
            .field("version", &self.version)
            .field(
                "inputs",
                if self.inputs.len() <= 3 {
                    &self.inputs
                } else {
                    &inputs_str
                },
            )
            .field(
                "outputs",
                if self.outputs.len() <= 3 {
                    &self.outputs
                } else {
                    &outputs_str
                },
            )
            .field("lock_time", &self.lock_time)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::OutPoint;
    use crate::util::{Amount, Hash256};
    use std::io::Cursor;

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let t = Tx {
            version: 1,
            inputs: vec![
                TxIn {
                    prev_output: OutPoint {
                        hash: Hash256([9; 32]),
                        index: 9,
                    },
                    sig_script: Script(vec![1, 3, 5, 7, 9]),
                    sequence: 100,
                },
                TxIn {
                    prev_output: OutPoint {
                        hash: Hash256([0; 32]),
                        index: 8,
                    },
                    sig_script: Script(vec![3; 333]),
                    sequence: 22,
                },
            ],
            outputs: vec![
                TxOut {
                    amount: Amount(99),
                    pk_script: Script(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 100, 99, 98, 97, 96]),
                },
                TxOut {
                    amount: Amount(199),
                    pk_script: Script(vec![56, 78, 90, 90, 78, 56]),
                },
            ],
            lock_time: 1000,
        };
        t.write(&mut v).unwrap();
        assert!(v.len() == t.size());
        assert!(Tx::read(&mut Cursor::new(&v)).unwrap() == t);
    }

    #[test]
    fn hash() {
        // The coinbase from block 2
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    hash: Hash256([0; 32]),
                    index: 4294967295,
                },
                sig_script: Script(vec![4, 255, 255, 0, 29, 1, 11]),
                sequence: 4294967295,
            }],
            outputs: vec![TxOut {
                amount: Amount(5000000000),
                pk_script: Script(vec![
                    65, 4, 114, 17, 168, 36, 245, 91, 80, 82, 40, 228, 195, 213, 25, 76, 31, 207,
                    170, 21, 164, 86, 171, 223, 55, 249, 185, 217, 122, 64, 64, 175, 192, 115, 222,
                    230, 200, 144, 100, 152, 79, 3, 56, 82, 55, 217, 33, 103, 193, 62, 35, 100, 70,
                    180, 23, 171, 121, 160, 252, 174, 65, 42, 227, 49, 107, 119, 172,
                ]),
            }],
            lock_time: 0,
        };
        let h = "9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5";
        assert!(tx.hash() == Hash256::decode(h).unwrap());
        assert!(tx.coinbase());
    }

    #[test]
    fn validate() {
        let utxo = (
            OutPoint {
                hash: Hash256([5; 32]),
                index: 3,
            },
            TxOut {
                amount: Amount(100),
                pk_script: Script(vec![]),
            },
        );
        let mut utxos = LinkedHashMap::new();
        utxos.insert(utxo.0.clone(), utxo.1.clone());

        let tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                prev_output: utxo.0.clone(),
                sig_script: Script(vec![op_codes::OP_1]),
                sequence: 0,
            }],
            outputs: vec![
                TxOut {
                    amount: Amount(10),
                    pk_script: Script(vec![]),
                },
                TxOut {
                    amount: Amount(20),
                    pk_script: Script(vec![]),
                },
            ],
            lock_time: 0,
        };
        assert!(tx.validate(false, &utxos).is_ok());

        let mut tx_test = tx.clone();
        tx_test.inputs = vec![];
        assert!(tx_test.validate(false, &utxos).is_err());

        let mut tx_test = tx.clone();
        tx_test.outputs = vec![];
        assert!(tx_test.validate(false, &utxos).is_err());

        let mut tx_test = tx.clone();
        tx_test.outputs[0].amount = Amount(-1);
        assert!(tx_test.validate(false, &utxos).is_err());

        let mut tx_test = tx.clone();
        tx_test.outputs[0].amount = Amount(0);
        tx_test.outputs[0].amount = Amount(0);
        assert!(tx_test.validate(false, &utxos).is_ok());

        let mut tx_test = tx.clone();
        tx_test.outputs[0].amount = Amount(MAX_SATOSHIS);
        tx_test.outputs[1].amount = Amount(MAX_SATOSHIS);
        assert!(tx_test.validate(false, &utxos).is_err());

        let mut tx_test = tx.clone();
        tx_test.outputs[1].amount = Amount(MAX_SATOSHIS + 1);
        assert!(tx_test.validate(false, &utxos).is_err());

        let mut tx_test = tx.clone();
        tx_test.inputs[0].prev_output.hash = COINBASE_OUTPOINT_HASH;
        tx_test.inputs[0].prev_output.index = COINBASE_OUTPOINT_INDEX;
        assert!(tx_test.validate(false, &utxos).is_err());

        let mut tx_test = tx.clone();
        tx_test.lock_time = 4294967295;
        assert!(tx_test.validate(false, &utxos).is_err());

        let mut tx_test = tx.clone();
        tx_test.inputs[0].prev_output.hash = Hash256([8; 32]);
        assert!(tx_test.validate(false, &utxos).is_err());

        let mut utxos_clone = utxos.clone();
        let prev_output = &tx.inputs[0].prev_output;
        utxos_clone.get_mut(prev_output).unwrap().amount = Amount(-1);
        assert!(tx.validate(false, &utxos_clone).is_err());

        let mut utxos_clone = utxos.clone();
        let prev_output = &tx.inputs[0].prev_output;
        utxos_clone.get_mut(prev_output).unwrap().amount = Amount(MAX_SATOSHIS + 1);
        assert!(tx.validate(false, &utxos_clone).is_err());

        let mut tx_test = tx.clone();
        tx_test.outputs[0].amount = Amount(100);
        assert!(tx_test.validate(false, &utxos).is_err());

        let mut utxos_clone = utxos.clone();
        let prev_output = &tx.inputs[0].prev_output;
        utxos_clone.get_mut(prev_output).unwrap().pk_script = Script(vec![op_codes::OP_0]);
        assert!(tx.validate(false, &utxos_clone).is_err());
    }
}
