use crate::util::{Result, Serializable};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr};

/// Network address for a node on the network
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct NodeAddr {
    /// Services flags for the node
    pub services: u64,
    /// IPV6 address for the node. IPV4 addresses may be used as IPV4-mapped IPV6 addresses.
    pub ip: Ipv6Addr,
    /// Port for Bitcoin P2P communication
    pub port: u16,
}

impl NodeAddr {
    /// Size of the NodeAddr in bytes
    pub const SIZE: usize = 26;

    /// Creates a NodeAddr from an IP address and port
    pub fn new(ip: IpAddr, port: u16) -> NodeAddr {
        NodeAddr {
            services: 0,
            ip: match ip {
                IpAddr::V4(ipv4) => ipv4.to_ipv6_mapped(),
                IpAddr::V6(ipv6) => ipv6,
            },
            port,
        }
    }

    /// Returns the size of the address in bytes
    pub fn size(&self) -> usize {
        NodeAddr::SIZE
    }
}

impl Serializable<NodeAddr> for NodeAddr {
    fn read(reader: &mut dyn Read) -> Result<NodeAddr> {
        let services = reader.read_u64::<LittleEndian>()?;
        let mut ip = [0; 16];
        reader.read(&mut ip)?;
        let ip = Ipv6Addr::from(ip);
        let port = reader.read_u16::<BigEndian>()?;
        Ok(NodeAddr { services, ip, port })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_u64::<LittleEndian>(self.services)?;
        writer.write(&self.ip.octets())?;
        writer.write_u16::<BigEndian>(self.port)?;
        Ok(())
    }
}

impl Default for NodeAddr {
    fn default() -> NodeAddr {
        NodeAddr {
            services: 0,
            ip: Ipv6Addr::from([0; 16]),
            port: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use std::io::Cursor;

    #[test]
    fn read_bytes() {
        let b =
            hex::decode("250000000000000000000000000000000000ffff2d32bffbddd3".as_bytes()).unwrap();
        let a = NodeAddr::read(&mut Cursor::new(&b)).unwrap();
        assert!(a.services == 37);
        assert!(a.ip.octets() == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 45, 50, 191, 251]);
        assert!(a.port == 56787);
    }

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let a = NodeAddr {
            services: 1,
            ip: Ipv6Addr::from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
            port: 123,
        };
        a.write(&mut v).unwrap();
        assert!(v.len() == a.size());
        assert!(NodeAddr::read(&mut Cursor::new(&v)).unwrap() == a);
    }
}
