use crate::messages::message::Payload;
use crate::messages::node_addr_ex::NodeAddrEx;
use crate::util::{var_int, Error, Result, Serializable};
use std::fmt;
use std::io;
use std::io::{Read, Write};

/// Maximum number of addresses allowed in an Addr message
const MAX_ADDR_COUNT: u64 = 1000;

/// Known node addresses
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct Addr {
    /// List of addresses of known nodes
    pub addrs: Vec<NodeAddrEx>,
}

impl Serializable<Addr> for Addr {
    fn read(reader: &mut dyn Read) -> Result<Addr> {
        let mut ret = Addr { addrs: Vec::new() };
        let count = var_int::read(reader)?;
        if count > MAX_ADDR_COUNT {
            let msg = format!("Too many addrs: {}", count);
            return Err(Error::BadData(msg));
        }
        for _i in 0..count {
            ret.addrs.push(NodeAddrEx::read(reader)?);
        }
        Ok(ret)
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        var_int::write(self.addrs.len() as u64, writer)?;
        for item in self.addrs.iter() {
            item.write(writer)?;
        }
        Ok(())
    }
}

impl Payload<Addr> for Addr {
    fn size(&self) -> usize {
        var_int::size(self.addrs.len() as u64) + self.addrs.len() * NodeAddrEx::SIZE
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.addrs.len() <= 3 {
            f.debug_struct("Addr").field("addrs", &self.addrs).finish()
        } else {
            let s = format!("[<{} addrs>]", self.addrs.len());
            f.debug_struct("Addr").field("addrs", &s).finish()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::NodeAddr;
    use hex;
    use std::io::Cursor;
    use std::net::Ipv6Addr;

    #[test]
    fn read_bytes() {
        let b = hex::decode(
            "013c93dd5a250000000000000000000000000000000000ffff43cdb3a1479d".as_bytes(),
        )
        .unwrap();
        let a = Addr::read(&mut Cursor::new(&b)).unwrap();
        assert!(a.addrs.len() == 1);
        assert!(a.addrs[0].last_connected_time == 1524470588);
        assert!(a.addrs[0].addr.services == 37);
        let ip = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 67, 205, 179, 161];
        assert!(a.addrs[0].addr.ip.octets() == ip);
        assert!(a.addrs[0].addr.port == 18333);
    }

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let addr1 = NodeAddrEx {
            last_connected_time: 100,
            addr: NodeAddr {
                services: 900,
                ip: Ipv6Addr::from([1; 16]),
                port: 2000,
            },
        };
        let addr2 = NodeAddrEx {
            last_connected_time: 200,
            addr: NodeAddr {
                services: 800,
                ip: Ipv6Addr::from([2; 16]),
                port: 3000,
            },
        };
        let addr3 = NodeAddrEx {
            last_connected_time: 700,
            addr: NodeAddr {
                services: 900,
                ip: Ipv6Addr::from([3; 16]),
                port: 4000,
            },
        };
        let f = Addr {
            addrs: vec![addr1, addr2, addr3],
        };
        f.write(&mut v).unwrap();
        assert!(v.len() == f.size());
        assert!(Addr::read(&mut Cursor::new(&v)).unwrap() == f);
    }
}
