use crate::messages::message::Payload;
use crate::util::{Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};

/// Ping or pong payload
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct Ping {
    /// Unique identifier nonce
    pub nonce: u64,
}

impl Ping {
    /// Size of the ping or pong payload in bytes
    pub const SIZE: usize = 8;
}

impl Serializable<Ping> for Ping {
    fn read(reader: &mut dyn Read) -> Result<Ping> {
        let nonce = reader.read_u64::<LittleEndian>()?;
        Ok(Ping { nonce })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_u64::<LittleEndian>(self.nonce)
    }
}

impl Payload<Ping> for Ping {
    fn size(&self) -> usize {
        Ping::SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use std::io::Cursor;

    #[test]
    fn read_bytes() {
        let b = hex::decode("86b19332b96c657d".as_bytes()).unwrap();
        let f = Ping::read(&mut Cursor::new(&b)).unwrap();
        assert!(f.nonce == 9035747770062057862);
    }

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let p = Ping { nonce: 13579 };
        p.write(&mut v).unwrap();
        assert!(v.len() == p.size());
        assert!(Ping::read(&mut Cursor::new(&v)).unwrap() == p);
    }
}
