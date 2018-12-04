//! Node connection and message handling
//!
//! # Examples
//!
//! Send and receive a message to a node syncronously:
//!
//! ```no_run, rust
//! use sv::messages::{Message, Ping, Version, NODE_BITCOIN_CASH, PROTOCOL_VERSION};
//! use sv::network::Network;
//! use sv::peer::{Peer, SVPeerFilter};
//! use sv::util::rx::Observable;
//! use sv::util::secs_since;
//! use std::time::UNIX_EPOCH;
//!
//! let (ip, port) = Network::Mainnet.seed_iter().next().unwrap();
//! let version = Version {
//!     version: PROTOCOL_VERSION,
//!     services: NODE_BITCOIN_CASH,
//!     timestamp: secs_since(UNIX_EPOCH) as i64,
//!     user_agent: "rust-sv".to_string(),
//!     ..Default::default()
//! };
//!
//! let peer = Peer::connect(ip, port, Network::Mainnet, version, SVPeerFilter::new(0));
//! peer.connected_event().poll();
//!
//! let ping = Message::Ping(Ping { nonce: 0 });
//! peer.send(&ping).unwrap();
//!
//! let response = peer.messages().poll();
//! ```
//!
//! Handle node events asynronously:
//!
//! ```no_run, rust
//! use sv::messages::{Version, NODE_BITCOIN_CASH, PROTOCOL_VERSION};
//! use sv::network::Network;
//! use sv::peer::{Peer, PeerConnected, PeerDisconnected, PeerMessage, SVPeerFilter};
//! use sv::util::rx::{Observable, Observer};
//! use sv::util::secs_since;
//! use std::sync::Arc;
//! use std::time::UNIX_EPOCH;
//!
//! let (ip, port) = Network::Mainnet.seed_iter().next().unwrap();
//! let version = Version {
//!     version: PROTOCOL_VERSION,
//!     services: NODE_BITCOIN_CASH,
//!     timestamp: secs_since(UNIX_EPOCH) as i64,
//!     user_agent: "rust-sv".to_string(),
//!     ..Default::default()
//! };
//!
//! let peer = Peer::connect(ip, port, Network::Mainnet, version, SVPeerFilter::new(0));
//!
//! struct EventHandler {}
//!
//! impl Observer<PeerConnected> for EventHandler {
//!     fn next(&self, event: &PeerConnected) {
//!         // Handle node connected
//!     }
//! }
//!
//! impl Observer<PeerDisconnected> for EventHandler {
//!     fn next(&self, event: &PeerDisconnected) {
//!         // Handle node disconnected
//!     }
//! }
//!
//! impl Observer<PeerMessage> for EventHandler {
//!     fn next(&self, event: &PeerMessage) {
//!         // Handle message from node
//!     }
//! }
//!
//! let event_handler = Arc::new(EventHandler {});
//!
//! peer.connected_event().subscribe(&event_handler);
//! peer.disconnected_event().subscribe(&event_handler);
//! peer.messages().subscribe(&event_handler);
//! ```

pub(crate) mod atomic_reader;
mod peer;

pub use self::peer::{
    Peer, PeerConnected, PeerDisconnected, PeerFilter, PeerMessage, SVPeerFilter,
};
