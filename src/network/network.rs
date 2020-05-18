use crate::messages::{Block, BlockHeader, OutPoint, Tx, TxIn, TxOut};
use crate::network::SeedIter;
use crate::script::Script;
use crate::util::{Error, Hash256, Result};
use hex;

/// Network type
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Network {
    Mainnet = 0,
    Testnet = 1,
    STN = 2,
}

impl Network {
    /// Converts an integer to a network type
    pub fn from_u8(x: u8) -> Result<Network> {
        match x {
            x if x == Network::Mainnet as u8 => Ok(Network::Mainnet),
            x if x == Network::Testnet as u8 => Ok(Network::Testnet),
            x if x == Network::STN as u8 => Ok(Network::STN),
            _ => {
                let msg = format!("Unknown network type: {}", x);
                Err(Error::BadArgument(msg))
            }
        }
    }

    /// Returns the default TCP port
    pub fn port(&self) -> u16 {
        match self {
            Network::Mainnet => 8333,
            Network::Testnet => 18333,
            Network::STN => 9333,
        }
    }

    /// Returns the magic bytes for the message headers
    pub fn magic(&self) -> [u8; 4] {
        match self {
            Network::Mainnet => [0xe3, 0xe1, 0xf3, 0xe8],
            Network::Testnet => [0xf4, 0xe5, 0xf3, 0xf4],
            Network::STN => [0xfb, 0xce, 0xc4, 0xf9],
        }
    }

    /// Returns the genesis block
    pub fn genesis_block(&self) -> Block {
        match self {
            Network::Mainnet => {
                let header = BlockHeader {
                    version: 1,
                    prev_hash: Hash256([0; 32]),
                    merkle_root: Hash256::decode(
                        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
                    )
                    .unwrap(),
                    timestamp: 1231006505,
                    bits: 0x1d00ffff,
                    nonce: 2083236893,
                };

                let tx = Tx {
                    version: 1,
                    inputs: vec![TxIn {
                        prev_output: OutPoint {
                            hash: Hash256([0; 32]),
                            index: 0xffffffff,
                        },
                        unlock_script: Script(hex::decode("04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73").unwrap()),
                        sequence: 0xffffffff,
                    }],
                    outputs: vec![TxOut {
                        satoshis: 5000000000,
                        lock_script: Script(hex::decode("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac").unwrap()),
                    }],
                    lock_time: 0,
                };

                Block {
                    header,
                    txns: vec![tx],
                }
            }
            Network::Testnet | Network::STN => {
                let header = BlockHeader {
                    version: 1,
                    prev_hash: Hash256([0; 32]),
                    merkle_root: Hash256::decode(
                        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
                    )
                    .unwrap(),
                    timestamp: 1296688602,
                    bits: 0x1d00ffff,
                    nonce: 414098458,
                };

                let tx = Tx {
                    version: 1,
                    inputs: vec![TxIn {
                        prev_output: OutPoint {
                            hash: Hash256([0; 32]),
                            index: 0xffffffff,
                        },
                        unlock_script: Script(hex::decode("04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73").unwrap()),
                        sequence: 0xffffffff,
                    }],
                    outputs: vec![TxOut {
                        satoshis: 5000000000,
                        lock_script: Script(hex::decode("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac").unwrap()),
                    }],
                    lock_time: 0,
                };

                Block {
                    header,
                    txns: vec![tx],
                }
            }
        }
    }

    /// Returns the genesis block hash
    pub fn genesis_hash(&self) -> Hash256 {
        match self {
            Network::Mainnet => {
                Hash256::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                    .unwrap()
            }
            Network::Testnet | Network::STN => {
                Hash256::decode("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")
                    .unwrap()
            }
        }
    }

    /// Returns the version byte flag for P2PKH-type addresses
    pub fn addr_pubkeyhash_flag(&self) -> u8 {
        match self {
            Network::Mainnet => 0x00,
            Network::Testnet => 0x6f,
            Network::STN => 0x6f,
        }
    }

    /// Returns the version byte flag for P2SH-type addresses
    pub fn addr_script_flag(&self) -> u8 {
        match self {
            Network::Mainnet => 0x05,
            Network::Testnet => 0xc4,
            Network::STN => 0xc4,
        }
    }

    /// Returns a list of DNS seeds for finding initial nodes
    pub fn seeds(&self) -> Vec<String> {
        match self {
            Network::Mainnet => vec![
                "seed.bitcoinsv.io".to_string(),
                "seed.cascharia.com".to_string(),
                "seed.satoshisvision.network".to_string(),
            ],
            Network::Testnet => vec![
                "testnet-seed.bitcoinsv.io".to_string(),
                "testnet-seed.cascharia.com".to_string(),
                "testnet-seed.bitcoincloud.net".to_string(),
            ],
            Network::STN => vec!["stn-seed.bitcoinsv.io".to_string()],
        }
    }

    /// Creates a new DNS seed iterator for this network
    pub fn seed_iter(&self) -> SeedIter {
        SeedIter::new(&self.seeds(), self.port())
    }
}
