use crate::util::{Hash256, Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};

/// The coinbase transaction input will have this hash
pub const COINBASE_OUTPOINT_HASH: Hash256 = Hash256([0; 32]);
/// The coinbase transaction input will have this index
pub const COINBASE_OUTPOINT_INDEX: u32 = 0xffffffff;

/// Reference to a transaction output
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct OutPoint {
    /// Hash of the referenced transaction
    pub hash: Hash256,
    /// Index of the output in the transaction, zero-indexed
    pub index: u32,
}

impl OutPoint {
    /// Size of the out point in bytes
    pub const SIZE: usize = 36;

    /// Returns the size of the out point in bytes
    pub fn size(&self) -> usize {
        OutPoint::SIZE
    }
}

impl Serializable<OutPoint> for OutPoint {
    fn read(reader: &mut dyn Read) -> Result<OutPoint> {
        let hash = Hash256::read(reader)?;
        let index = reader.read_u32::<LittleEndian>()?;
        Ok(OutPoint { hash, index })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        self.hash.write(writer)?;
        writer.write_u32::<LittleEndian>(self.index)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let t = OutPoint {
            hash: Hash256::decode(
                "123412345678567890ab90abcdefcdef123412345678567890ab90abcdefcdef",
            )
            .unwrap(),
            index: 0,
        };
        t.write(&mut v).unwrap();
        assert!(v.len() == t.size());
        assert!(OutPoint::read(&mut Cursor::new(&v)).unwrap() == t);
    }
}
