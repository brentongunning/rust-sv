use crate::messages::message::Payload;
use crate::messages::node_addr::NodeAddr;
use crate::util::{secs_since, var_int, Error, Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};
use std::time::UNIX_EPOCH;

/// Protocol version supported by this library
pub const PROTOCOL_VERSION: u32 = 70015;

/// Minimum protocol version supported by this library
pub const MIN_SUPPORTED_PROTOCOL_VERSION: u32 = 70001;

/// Unknown IP address to use as a default
pub const UNKNOWN_IP: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1];

/// Service flag that node is not a full node. Used for SPV wallets.
pub const NODE_NONE: u64 = 0;

/// Service flag that node is a full node and implements all protocol features
pub const NODE_NETWORK: u64 = 1;

/// Service flag that node is a full node and implements all protocol features
pub const NODE_BITCOIN_CASH: u64 = 1 << 5;

/// Version payload defining a node's capabilities
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct Version {
    /// The protocol version being used by the node
    pub version: u32,
    /// Bitfield of features to be enabled for this connection
    pub services: u64,
    /// Time since the Unix epoch in seconds
    pub timestamp: i64,
    /// Network address of the node receiving this message
    pub recv_addr: NodeAddr,
    /// Network address of the node emitting this message
    pub tx_addr: NodeAddr,
    /// A random nonce which can help a node detect a connection to itself
    pub nonce: u64,
    /// User agent string
    pub user_agent: String,
    /// Height of the transmiting node's best block chain, or in the case of SPV wallets, block header chain
    pub start_height: i32,
    /// Whether the client wants to receive broadcast transactions before a filter is set
    pub relay: bool,
}

impl Version {
    /// Checks if the version message is valid
    pub fn validate(&self) -> Result<()> {
        if self.version < MIN_SUPPORTED_PROTOCOL_VERSION {
            let msg = format!("Unsupported protocol version: {}", self.version);
            return Err(Error::BadData(msg));
        }
        let now = secs_since(UNIX_EPOCH) as i64;
        if (self.timestamp - now).abs() > 2 * 60 * 60 {
            let msg = format!("Timestamp too old: {}", self.timestamp);
            return Err(Error::BadData(msg));
        }
        Ok(())
    }
}

impl Serializable<Version> for Version {
    fn read(reader: &mut dyn Read) -> Result<Version> {
        let mut ret = Version {
            ..Default::default()
        };
        ret.version = reader.read_u32::<LittleEndian>()?;
        ret.services = reader.read_u64::<LittleEndian>()?;
        ret.timestamp = reader.read_i64::<LittleEndian>()?;
        ret.recv_addr = NodeAddr::read(reader)?;
        ret.tx_addr = NodeAddr::read(reader)?;
        ret.nonce = reader.read_u64::<LittleEndian>()?;
        let user_agent_size = var_int::read(reader)? as usize;
        let mut user_agent_bytes = vec![0; user_agent_size];
        reader.read(&mut user_agent_bytes)?;
        ret.user_agent = String::from_utf8(user_agent_bytes)?;
        ret.start_height = reader.read_i32::<LittleEndian>()?;
        ret.relay = reader.read_u8()? == 0x01;
        Ok(ret)
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_u32::<LittleEndian>(self.version)?;
        writer.write_u64::<LittleEndian>(self.services)?;
        writer.write_i64::<LittleEndian>(self.timestamp)?;
        self.recv_addr.write(writer)?;
        self.tx_addr.write(writer)?;
        writer.write_u64::<LittleEndian>(self.nonce)?;
        var_int::write(self.user_agent.as_bytes().len() as u64, writer)?;
        writer.write(&self.user_agent.as_bytes())?;
        writer.write_i32::<LittleEndian>(self.start_height)?;
        writer.write_u8(if self.relay { 0x01 } else { 0x00 })?;
        Ok(())
    }
}

impl Payload<Version> for Version {
    fn size(&self) -> usize {
        33 + self.recv_addr.size()
            + self.tx_addr.size()
            + var_int::size(self.user_agent.as_bytes().len() as u64)
            + self.user_agent.as_bytes().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use std::io::Cursor;

    #[test]
    fn read_bytes() {
        let b = hex::decode("7f1101002500000000000000f2d2d25a00000000000000000000000000000000000000000000ffff2d32bffbdd1725000000000000000000000000000000000000000000000000008d501d3bb5369deb242f426974636f696e204142433a302e31362e30284542382e303b20626974636f7265292f6606080001".as_bytes()).unwrap();
        let v = Version::read(&mut Cursor::new(&b)).unwrap();
        assert!(v.version == 70015);
        assert!(v.services == 37);
        assert!(v.timestamp == 1523766002);
        assert!(v.recv_addr.services == 0);
        assert!(
            v.recv_addr.ip.octets() == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 45, 50, 191, 251]
        );
        assert!(v.recv_addr.port == 56599);
        assert!(v.tx_addr.services == 37);
        assert!(v.tx_addr.ip.octets() == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(v.tx_addr.port == 0);
        assert!(v.nonce == 16977786322265395341);
        assert!(v.user_agent == "/Bitcoin ABC:0.16.0(EB8.0; bitcore)/");
        assert!(v.start_height == 525926);
        assert!(v.relay == true);
    }

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let m = Version {
            version: MIN_SUPPORTED_PROTOCOL_VERSION,
            services: 77,
            timestamp: 1234,
            recv_addr: NodeAddr {
                ..Default::default()
            },
            tx_addr: NodeAddr {
                ..Default::default()
            },
            nonce: 99,
            user_agent: "dummy".to_string(),
            start_height: 22,
            relay: true,
        };
        m.write(&mut v).unwrap();
        assert!(v.len() == m.size());
        assert!(Version::read(&mut Cursor::new(&v)).unwrap() == m);
    }

    #[test]
    fn validate() {
        let m = Version {
            version: MIN_SUPPORTED_PROTOCOL_VERSION,
            services: 77,
            timestamp: secs_since(UNIX_EPOCH) as i64,
            recv_addr: NodeAddr {
                ..Default::default()
            },
            tx_addr: NodeAddr {
                ..Default::default()
            },
            nonce: 99,
            user_agent: "dummy".to_string(),
            start_height: 22,
            relay: true,
        };
        // Valid
        assert!(m.validate().is_ok());
        // Unsupported version
        let m2 = Version {
            version: 0,
            ..m.clone()
        };
        assert!(m2.validate().is_err());
        // Bad timestamp
        let m3 = Version {
            timestamp: 0,
            ..m.clone()
        };
        assert!(m3.validate().is_err());
    }
}
