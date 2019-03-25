use crate::messages::message::Payload;
use crate::util::{Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};

/// Specifies whether compact blocks are supported
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct SendCmpct {
    /// Whether compact blocks may be sent
    pub enable: u8,
    /// Should always be 1
    pub version: u64,
}

impl SendCmpct {
    /// Size of the SendCmpct payload in bytes
    pub const SIZE: usize = 9;

    /// Returns whether compact blocks should be used
    pub fn use_cmpctblock(&self) -> bool {
        self.enable == 1 && self.version == 1
    }
}

impl Serializable<SendCmpct> for SendCmpct {
    fn read(reader: &mut dyn Read) -> Result<SendCmpct> {
        let enable = reader.read_u8()?;
        let version = reader.read_u64::<LittleEndian>()?;
        Ok(SendCmpct { enable, version })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_u8(self.enable)?;
        writer.write_u64::<LittleEndian>(self.version)
    }
}

impl Payload<SendCmpct> for SendCmpct {
    fn size(&self) -> usize {
        SendCmpct::SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use std::io::Cursor;

    #[test]
    fn read_bytes() {
        let b = hex::decode("000100000000000000".as_bytes()).unwrap();
        let f = SendCmpct::read(&mut Cursor::new(&b)).unwrap();
        assert!(f.enable == 0);
        assert!(f.version == 1);
    }

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let s = SendCmpct {
            enable: 1,
            version: 1,
        };
        s.write(&mut v).unwrap();
        assert!(v.len() == s.size());
        assert!(SendCmpct::read(&mut Cursor::new(&v)).unwrap() == s);
    }
}
