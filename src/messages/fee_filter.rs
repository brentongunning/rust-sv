use crate::messages::message::Payload;
use crate::util::{Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};

/// Specifies the minimum transaction fee this node accepts
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct FeeFilter {
    /// Minimum fee accepted by the node in sats/1000 bytes
    pub minfee: u64,
}

impl FeeFilter {
    /// Size of the fee filter payload in bytes
    pub const SIZE: usize = 8;
}

impl Serializable<FeeFilter> for FeeFilter {
    fn read(reader: &mut dyn Read) -> Result<FeeFilter> {
        let minfee = reader.read_u64::<LittleEndian>()?;
        Ok(FeeFilter { minfee })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_u64::<LittleEndian>(self.minfee)
    }
}

impl Payload<FeeFilter> for FeeFilter {
    fn size(&self) -> usize {
        FeeFilter::SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use std::io::Cursor;

    #[test]
    fn read_bytes() {
        let b = hex::decode("e803000000000000".as_bytes()).unwrap();
        let f = FeeFilter::read(&mut Cursor::new(&b)).unwrap();
        assert!(f.minfee == 1000);
    }

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let f = FeeFilter { minfee: 1234 };
        f.write(&mut v).unwrap();
        assert!(v.len() == f.size());
        assert!(FeeFilter::read(&mut Cursor::new(&v)).unwrap() == f);
    }
}
