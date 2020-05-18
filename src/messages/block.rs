use crate::messages::{BlockHeader, OutPoint, Payload, Tx, TxOut};
use crate::network::Network;
use crate::util::{
    sha256d, var_int, Error, Hash256, Result, Serializable, BITCOIN_CASH_FORK_HEIGHT_MAINNET,
    BITCOIN_CASH_FORK_HEIGHT_TESTNET, GENESIS_UPGRADE_HEIGHT_MAINNET,
    GENESIS_UPGRADE_HEIGHT_TESTNET,
};
use linked_hash_map::LinkedHashMap;
use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::io;
use std::io::{Read, Write};

/// Block of transactions
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct Block {
    /// Block header
    pub header: BlockHeader,
    /// Block transactions
    pub txns: Vec<Tx>,
}

impl Block {
    /// Returns a set of the inputs spent in this block
    pub fn inputs(&self) -> Result<HashSet<OutPoint>> {
        let mut inputs = HashSet::new();
        for txn in self.txns.iter() {
            if !txn.coinbase() {
                for input in txn.inputs.iter() {
                    if inputs.contains(&input.prev_output) {
                        let msg = "Input double spent".to_string();
                        return Err(Error::BadData(msg));
                    }
                    inputs.insert(input.prev_output.clone());
                }
            }
        }
        Ok(inputs)
    }

    /// Returns a map of the new outputs generated from this block including those spent within the block
    pub fn outputs(&self) -> Result<LinkedHashMap<OutPoint, TxOut>> {
        let mut outputs = LinkedHashMap::new();
        for txn in self.txns.iter() {
            let hash = txn.hash();
            for index in 0..txn.outputs.len() as u32 {
                outputs.insert(
                    OutPoint { hash, index },
                    txn.outputs[index as usize].clone(),
                );
            }
        }
        Ok(outputs)
    }

    /// Checks that the block is valid
    pub fn validate(
        &self,
        height: i32,
        network: Network,
        utxos: &LinkedHashMap<OutPoint, TxOut>,
        pregenesis_outputs: &HashSet<OutPoint>,
    ) -> Result<()> {
        if self.txns.len() == 0 {
            return Err(Error::BadData("Txn count is zero".to_string()));
        }

        if self.merkle_root() != self.header.merkle_root {
            return Err(Error::BadData("Bad merkle root".to_string()));
        }

        let mut has_coinbase = false;
        let require_sighash_forkid = match network {
            Network::Mainnet => height >= BITCOIN_CASH_FORK_HEIGHT_MAINNET,
            Network::Testnet => height >= BITCOIN_CASH_FORK_HEIGHT_TESTNET,
            Network::STN => true,
        };
        let use_genesis_rules = match network {
            Network::Mainnet => height >= GENESIS_UPGRADE_HEIGHT_MAINNET,
            Network::Testnet => height >= GENESIS_UPGRADE_HEIGHT_TESTNET,
            Network::STN => true,
        };
        for txn in self.txns.iter() {
            if !txn.coinbase() {
                txn.validate(
                    require_sighash_forkid,
                    use_genesis_rules,
                    utxos,
                    pregenesis_outputs,
                )?;
            } else if has_coinbase {
                return Err(Error::BadData("Multiple coinbases".to_string()));
            } else {
                has_coinbase = true;
            }
        }
        if !has_coinbase {
            return Err(Error::BadData("No coinbase".to_string()));
        }

        Ok(())
    }

    /// Calculates the merkle root from the transactions
    fn merkle_root(&self) -> Hash256 {
        let mut row = VecDeque::new();
        for tx in self.txns.iter() {
            row.push_back(tx.hash());
        }
        while row.len() > 1 {
            let mut n = row.len();
            while n > 0 {
                n -= 1;
                let h1 = row.pop_front().unwrap();
                let h2 = if n == 0 {
                    h1.clone()
                } else {
                    n -= 1;
                    row.pop_front().unwrap()
                };
                let mut h = Vec::with_capacity(64);
                h1.write(&mut h).unwrap();
                h2.write(&mut h).unwrap();
                row.push_back(sha256d(&h));
            }
        }
        return row.pop_front().unwrap();
    }
}

impl Serializable<Block> for Block {
    fn read(reader: &mut dyn Read) -> Result<Block> {
        let header = BlockHeader::read(reader)?;
        let txn_count = var_int::read(reader)?;
        let mut txns = Vec::with_capacity(txn_count as usize);
        for _i in 0..txn_count {
            txns.push(Tx::read(reader)?);
        }
        Ok(Block { header, txns })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        self.header.write(writer)?;
        var_int::write(self.txns.len() as u64, writer)?;
        for txn in self.txns.iter() {
            txn.write(writer)?;
        }
        Ok(())
    }
}

impl Payload<Block> for Block {
    fn size(&self) -> usize {
        let mut size = BlockHeader::SIZE;
        size += var_int::size(self.txns.len() as u64);
        for txn in self.txns.iter() {
            size += txn.size();
        }
        size
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.txns.len() <= 3 {
            f.debug_struct("Block")
                .field("header", &self.header)
                .field("txns", &self.txns)
                .finish()
        } else {
            let txns = format!("[<{} transactions>]", self.txns.len());
            f.debug_struct("Block")
                .field("header", &self.header)
                .field("txns", &txns)
                .finish()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{OutPoint, TxIn, TxOut};
    use crate::script::Script;
    use crate::util::Hash256;
    use hex;
    use std::io::Cursor;

    #[test]
    fn read_bytes() {
        let b = hex::decode("010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd610101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d010bffffffff0100f2052a010000004341047211a824f55b505228e4c3d5194c1fcfaa15a456abdf37f9b9d97a4040afc073dee6c89064984f03385237d92167c13e236446b417ab79a0fcae412ae3316b77ac00000000").unwrap();
        let block = Block::read(&mut Cursor::new(&b)).unwrap();
        assert!(
            block
                == Block {
                    header: BlockHeader {
                        version: 1,
                        prev_hash: Hash256::decode(
                            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
                        )
                        .unwrap(),
                        merkle_root: Hash256::decode(
                            "9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5",
                        )
                        .unwrap(),
                        timestamp: 1231469744,
                        bits: 486604799,
                        nonce: 1639830024,
                    },
                    txns: vec![Tx {
                        version: 1,
                        inputs: vec![TxIn {
                            prev_output: OutPoint {
                                hash: Hash256([0; 32]),
                                index: 4294967295,
                            },
                            unlock_script: Script(vec![4, 255, 255, 0, 29, 1, 11]),
                            sequence: 4294967295,
                        }],
                        outputs: vec![TxOut {
                            satoshis: 5000000000,
                            lock_script: Script(vec![
                                65, 4, 114, 17, 168, 36, 245, 91, 80, 82, 40, 228, 195, 213, 25,
                                76, 31, 207, 170, 21, 164, 86, 171, 223, 55, 249, 185, 217, 122,
                                64, 64, 175, 192, 115, 222, 230, 200, 144, 100, 152, 79, 3, 56, 82,
                                55, 217, 33, 103, 193, 62, 35, 100, 70, 180, 23, 171, 121, 160,
                                252, 174, 65, 42, 227, 49, 107, 119, 172,
                            ]),
                        }],
                        lock_time: 0,
                    }],
                }
        );
    }

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let block = Block {
            header: BlockHeader {
                version: 77,
                prev_hash: Hash256::decode(
                    "abcdabcdabcdabcd1234123412341234abcdabcdabcdabcd1234123412341234",
                )
                .unwrap(),
                merkle_root: Hash256::decode(
                    "1234567809876543123456780987654312345678098765431234567809876543",
                )
                .unwrap(),
                timestamp: 7,
                bits: 8,
                nonce: 9,
            },
            txns: vec![Tx {
                version: 7,
                inputs: vec![TxIn {
                    prev_output: OutPoint {
                        hash: Hash256([7; 32]),
                        index: 3,
                    },
                    unlock_script: Script(vec![9, 8, 7]),
                    sequence: 42,
                }],
                outputs: vec![TxOut {
                    satoshis: 23,
                    lock_script: Script(vec![1, 2, 3, 4, 5]),
                }],
                lock_time: 4,
            }],
        };
        block.write(&mut v).unwrap();
        assert!(v.len() == block.size());
        assert!(Block::read(&mut Cursor::new(&v)).unwrap() == block);
    }
}
