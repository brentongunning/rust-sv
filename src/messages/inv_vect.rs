use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};
use util::{Error, Hash256, Result, Serializable};

/// Inventory vector type
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum InvVectType {
    /// May be ignored
    Error = 0,
    /// Hash of a transaction
    Tx = 1,
    /// Hash of a block header.
    Block = 2,
    /// Hash of a block header. Indicates the reply should be a merkleblock message.
    FilteredBlock = 3,
    /// Hash of a block header. Indicates the reply should be a cmpctblock message.
    CompactBlock = 4,
}

impl InvVectType {
    /// Converts an integer to a inventory vector type
    pub fn from_u32(x: u32) -> Result<InvVectType> {
        match x {
            x if x == InvVectType::Error as u32 => Ok(InvVectType::Error),
            x if x == InvVectType::Tx as u32 => Ok(InvVectType::Tx),
            x if x == InvVectType::Block as u32 => Ok(InvVectType::Block),
            x if x == InvVectType::FilteredBlock as u32 => Ok(InvVectType::FilteredBlock),
            x if x == InvVectType::CompactBlock as u32 => Ok(InvVectType::CompactBlock),
            _ => {
                let msg = format!("Unknown inventory vector type: {}", x);
                Err(Error::BadArgument(msg))
            }
        }
    }
}

/// Inventory vector describing an object being requested or announced
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct InvVect {
    // Object type linked to this inventory
    pub obj_type: InvVectType,
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
            obj_type: InvVectType::from_u32(reader.read_u32::<LittleEndian>()?)?,
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
            obj_type: InvVectType::Tx,
            hash: Hash256([8; 32]),
        };
        iv.write(&mut v).unwrap();
        assert!(v.len() == iv.size());
        assert!(InvVect::read(&mut Cursor::new(&v)).unwrap() == iv);
    }
}
