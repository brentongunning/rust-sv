use crate::messages::message::Payload;
use crate::util::{var_int, BloomFilter, Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};

/// Filter is not adjusted when a match is found
pub const BLOOM_UPDATE_NONE: u8 = 0;
/// Filter is updated to include the serialized outpoint if any data elements matched in its script pubkey
pub const BLOOM_UPDATE_ALL: u8 = 1;
/// Filter is updated simialr to BLOOM_UPDATE_ALL but only for P2PK or multisig transactions
pub const BLOOM_UPDATE_P2PUBKEY_ONLY: u8 = 2;

/// Loads a bloom filter using the specified parameters
#[derive(Default, Debug, PartialEq, Eq, Hash, Clone)]
pub struct FilterLoad {
    /// Bloom filter
    pub bloom_filter: BloomFilter,
    /// Flags that control how matched items are added to the filter
    pub flags: u8,
}

impl FilterLoad {
    /// Returns whether the FilterLoad message is valid
    pub fn validate(&self) -> Result<()> {
        self.bloom_filter.validate()
    }
}

impl Serializable<FilterLoad> for FilterLoad {
    fn read(reader: &mut dyn Read) -> Result<FilterLoad> {
        let num_filters = var_int::read(reader)?;
        let mut filter = vec![0; num_filters as usize];
        reader.read(&mut filter)?;
        let num_hash_funcs = reader.read_u32::<LittleEndian>()? as usize;
        let tweak = reader.read_u32::<LittleEndian>()?;
        let flags = reader.read_u8()?;
        Ok(FilterLoad {
            bloom_filter: BloomFilter {
                filter,
                num_hash_funcs,
                tweak,
            },
            flags,
        })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        var_int::write(self.bloom_filter.filter.len() as u64, writer)?;
        writer.write(&self.bloom_filter.filter)?;
        writer.write_u32::<LittleEndian>(self.bloom_filter.num_hash_funcs as u32)?;
        writer.write_u32::<LittleEndian>(self.bloom_filter.tweak)?;
        writer.write_u8(self.flags)?;
        Ok(())
    }
}

impl Payload<FilterLoad> for FilterLoad {
    fn size(&self) -> usize {
        var_int::size(self.bloom_filter.filter.len() as u64) + self.bloom_filter.filter.len() + 9
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use std::io::Cursor;

    #[test]
    fn read_bytes() {
        let b = hex::decode("02b50f0b0000000000000001".as_bytes()).unwrap();
        let f = FilterLoad::read(&mut Cursor::new(&b)).unwrap();
        assert!(f.bloom_filter.filter == vec![0xb5, 0x0f]);
        assert!(f.bloom_filter.num_hash_funcs == 11);
        assert!(f.bloom_filter.tweak == 0);
        assert!(f.flags == BLOOM_UPDATE_ALL);
    }

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let p = FilterLoad {
            bloom_filter: BloomFilter {
                filter: vec![0, 1, 2, 3, 4, 5],
                num_hash_funcs: 3,
                tweak: 100,
            },
            flags: 1,
        };
        p.write(&mut v).unwrap();
        assert!(v.len() == p.size());
        assert!(FilterLoad::read(&mut Cursor::new(&v)).unwrap() == p);
    }
}
