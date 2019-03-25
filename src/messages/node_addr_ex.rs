use crate::messages::node_addr::NodeAddr;
use crate::util::{Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};

/// Node network address extended with a last connected time
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct NodeAddrEx {
    /// Last connected time in seconds since the unix epoch
    pub last_connected_time: u32,
    /// Node address
    pub addr: NodeAddr,
}

impl NodeAddrEx {
    /// Size of the NodeAddrEx in bytes
    pub const SIZE: usize = NodeAddr::SIZE + 4;

    /// Returns the size of the address in bytes
    pub fn size(&self) -> usize {
        NodeAddrEx::SIZE
    }
}

impl Serializable<NodeAddrEx> for NodeAddrEx {
    fn read(reader: &mut dyn Read) -> Result<NodeAddrEx> {
        Ok(NodeAddrEx {
            last_connected_time: reader.read_u32::<LittleEndian>()?,
            addr: NodeAddr::read(reader)?,
        })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_u32::<LittleEndian>(self.last_connected_time)?;
        self.addr.write(writer)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::Ipv6Addr;

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let a = NodeAddrEx {
            last_connected_time: 12345,
            addr: NodeAddr {
                services: 1,
                ip: Ipv6Addr::from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
                port: 123,
            },
        };
        a.write(&mut v).unwrap();
        assert!(v.len() == a.size());
        assert!(NodeAddrEx::read(&mut Cursor::new(&v)).unwrap() == a);
    }
}
