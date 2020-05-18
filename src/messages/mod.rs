//! Peer-to-peer network protocol messages
//!
//! # Examples
//!
//! Decode a network message
//!
//! ```rust
//! use sv::messages::Message;
//! use sv::network::Network;
//! use std::io::Cursor;
//!
//! let bytes = [
//!     227, 225, 243, 232, 104, 101, 97, 100, 101, 114, 115,
//!     0, 0, 0, 0, 0, 1, 0, 0, 0, 20, 6, 224, 88, 0,
//! ];
//! let magic = Network::Mainnet.magic();
//! let message = Message::read(&mut Cursor::new(&bytes), magic).unwrap();
//!
//! match message {
//!     Message::Headers(headers) => { /* Handle headers message */ },
//!     _ => { /* All other messages */ }
//! }
//! ```
//!
//! Construct a transaction:
//!
//! ```rust
//! use sv::messages::{OutPoint, Tx, TxIn, TxOut};
//! use sv::transaction::p2pkh::{create_lock_script, create_unlock_script};
//! use sv::util::{hash160, Hash256};
//!
//! // Use real values here
//! let signature = [0; 72];
//! let public_key = [0; 33];
//! let prev_output = OutPoint {
//!     hash: Hash256([0; 32]),
//!     index: 0,
//! };
//!
//! let inputs = vec![TxIn {
//!     prev_output,
//!     unlock_script: create_unlock_script(&signature, &public_key),
//!     sequence: 0,
//! }];
//!
//! let outputs = vec![TxOut {
//!     satoshis: 1000,
//!     lock_script: create_lock_script(&hash160(&public_key)),
//! }];
//!
//! let tx = Tx {
//!     version: 2,
//!     inputs,
//!     outputs,
//!     lock_time: 0,
//! };
//! ```

mod addr;
mod block;
mod block_header;
mod block_locator;
mod fee_filter;
mod filter_add;
mod filter_load;
mod headers;
mod inv;
mod inv_vect;
mod merkle_block;
mod message;
mod message_header;
mod node_addr;
mod node_addr_ex;
mod out_point;
mod ping;
mod reject;
mod send_cmpct;
mod tx;
mod tx_in;
mod tx_out;
mod version;

pub use self::addr::Addr;
pub use self::block::Block;
pub use self::block_header::BlockHeader;
pub use self::block_locator::{BlockLocator, NO_HASH_STOP};
pub use self::fee_filter::FeeFilter;
pub use self::filter_add::{FilterAdd, MAX_FILTER_ADD_DATA_SIZE};
pub use self::filter_load::{
    FilterLoad, BLOOM_UPDATE_ALL, BLOOM_UPDATE_NONE, BLOOM_UPDATE_P2PUBKEY_ONLY,
};
pub use self::headers::{header_hash, Headers};
pub use self::inv::{Inv, MAX_INV_ENTRIES};
pub use self::inv_vect::{
    InvVect, INV_VECT_BLOCK, INV_VECT_COMPACT_BLOCK, INV_VECT_ERROR, INV_VECT_FILTERED_BLOCK,
    INV_VECT_TX,
};
pub use self::merkle_block::MerkleBlock;
pub use self::message::{commands, Message, Payload, MAX_PAYLOAD_SIZE, NO_CHECKSUM};
pub use self::message_header::MessageHeader;
pub use self::node_addr::NodeAddr;
pub use self::node_addr_ex::NodeAddrEx;
pub use self::out_point::{OutPoint, COINBASE_OUTPOINT_HASH, COINBASE_OUTPOINT_INDEX};
pub use self::ping::Ping;
pub use self::reject::{
    Reject, REJECT_CHECKPOINT, REJECT_DUPLICATE, REJECT_DUST, REJECT_INSUFFICIENT_FEE,
    REJECT_INVALID, REJECT_MALFORMED, REJECT_NONSTANDARD, REJECT_OBSOLETE,
};
pub use self::send_cmpct::SendCmpct;
pub use self::tx::{Tx, MAX_SATOSHIS};
pub use self::tx_in::TxIn;
pub use self::tx_out::TxOut;
pub use self::version::{
    Version, MIN_SUPPORTED_PROTOCOL_VERSION, NODE_BITCOIN_CASH, NODE_NETWORK, NODE_NONE,
    PROTOCOL_VERSION, UNKNOWN_IP,
};
