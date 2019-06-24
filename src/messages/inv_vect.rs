use crate::util::{Hash256, Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};

// Inventory vector types

/// May be ignored
pub const INV_VECT_ERROR: u32 = 0;
/// Hash of a transaction
pub const INV_VECT_TX: u32 = 1;
/// Hash of a block header.
pub const INV_VECT_BLOCK: u32 = 2;
/// Hash of a block header. Indicates the reply should be a merkleblock message.
pub const INV_VECT_FILTERED_BLOCK: u32 = 3;
/// Hash of a block header. Indicates the reply should be a cmpctblock message.
pub const INV_VECT_COMPACT_BLOCK: u32 = 4;

/// Inventory vector describing an object being requested or announced
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct InvVect {
    // Object type linked to this inventory
    pub obj_type: u32,
    /// Hash of the object
    pub hash: Hash256,
}

impl InvVect {
    /// Size of the inventory vector in bytes
    pub const SIZE: usize = 36;

    /// Returns the size of the inventory vector in bytes
    pub fn size(&self) -> usize {
        InvVect::SIZE
    }
}

impl Serializable<InvVect> for InvVect {
    fn read(reader: &mut dyn Read) -> Result<InvVect> {
        let inv_vect = InvVect {
            obj_type: reader.read_u32::<LittleEndian>()?,
            hash: Hash256::read(reader)?,
        };
        Ok(inv_vect)
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_u32::<LittleEndian>(self.obj_type as u32)?;
        self.hash.write(writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let iv = InvVect {
            obj_type: INV_VECT_TX,
            hash: Hash256([8; 32]),
        };
        iv.write(&mut v).unwrap();
        assert!(v.len() == iv.size());
        assert!(InvVect::read(&mut Cursor::new(&v)).unwrap() == iv);
    }
}
