use crate::util::{sha256d, Error, Hash256, Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::cmp::min;
use std::io;
use std::io::{Read, Write};

/// Block header
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct BlockHeader {
    /// Block version specifying which validation rules to use
    pub version: u32,
    /// Hash of the previous block
    pub prev_hash: Hash256,
    /// Root of the merkle tree of this block's transaction hashes
    pub merkle_root: Hash256,
    /// Timestamp when this block was created as recorded by the miner
    pub timestamp: u32,
    /// Target difficulty bits
    pub bits: u32,
    /// Nonce used to mine the block
    pub nonce: u32,
}

impl BlockHeader {
    /// Size of the BlockHeader in bytes
    pub const SIZE: usize = 80;

    /// Returns the size of the block header in bytes
    pub fn size(&self) -> usize {
        BlockHeader::SIZE
    }

    /// Calculates the hash for this block header
    pub fn hash(&self) -> Hash256 {
        let mut v = Vec::with_capacity(80);
        v.write_u32::<LittleEndian>(self.version).unwrap();
        self.prev_hash.write(&mut v).unwrap();
        self.merkle_root.write(&mut v).unwrap();
        v.write_u32::<LittleEndian>(self.timestamp).unwrap();
        v.write_u32::<LittleEndian>(self.bits).unwrap();
        v.write_u32::<LittleEndian>(self.nonce).unwrap();
        sha256d(&v)
    }

    /// Checks that the block header is valid
    pub fn validate(&self, hash: &Hash256, prev_headers: &[BlockHeader]) -> Result<()> {
        // Timestamp > median timestamp of last 11 blocks
        if prev_headers.len() > 0 {
            let h = &prev_headers[prev_headers.len() - min(prev_headers.len(), 11)..];
            let mut timestamps: Vec<u32> = h.iter().map(|x| x.timestamp).collect();
            timestamps.sort();
            if self.timestamp < timestamps[timestamps.len() / 2] {
                let msg = format!("Timestamp is too old: {}", self.timestamp);
                return Err(Error::BadData(msg));
            }
        }

        // POW
        let target = self.difficulty_target()?;
        if hash > &target {
            return Err(Error::BadData("Invalid POW".to_string()));
        }

        Ok(())
    }

    /// Calculates the target difficulty hash
    fn difficulty_target(&self) -> Result<Hash256> {
        let exp = (self.bits >> 24) as usize;
        if exp < 3 || exp > 32 {
            let msg = format!("Difficulty exponent out of range: {:?}", self.bits);
            return Err(Error::BadArgument(msg));
        }
        let mut difficulty = [0_u8; 32];
        difficulty[exp - 1] = ((self.bits >> 16) & 0xff) as u8;
        difficulty[exp - 2] = ((self.bits >> 08) & 0xff) as u8;
        difficulty[exp - 3] = ((self.bits >> 00) & 0xff) as u8;
        Ok(Hash256(difficulty))
    }
}

impl Serializable<BlockHeader> for BlockHeader {
    fn read(reader: &mut dyn Read) -> Result<BlockHeader> {
        let version = reader.read_u32::<LittleEndian>()?;
        let prev_hash = Hash256::read(reader)?;
        let merkle_root = Hash256::read(reader)?;
        let ts = reader.read_u32::<LittleEndian>()?;
        let bits = reader.read_u32::<LittleEndian>()?;
        let nonce = reader.read_u32::<LittleEndian>()?;
        Ok(BlockHeader {
            version,
            prev_hash,
            merkle_root,
            timestamp: ts,
            bits,
            nonce,
        })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_u32::<LittleEndian>(self.version)?;
        self.prev_hash.write(writer)?;
        self.merkle_root.write(writer)?;
        writer.write_u32::<LittleEndian>(self.timestamp)?;
        writer.write_u32::<LittleEndian>(self.bits)?;
        writer.write_u32::<LittleEndian>(self.nonce)?;
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
        let block_header = BlockHeader {
            version: 12345,
            prev_hash: Hash256::decode(
                "7766009988776600998877660099887766009988776600998877660099887766",
            )
            .unwrap(),
            merkle_root: Hash256::decode(
                "2211554433221155443322115544332211554433221155443322115544332211",
            )
            .unwrap(),
            timestamp: 66,
            bits: 4488,
            nonce: 9999,
        };
        block_header.write(&mut v).unwrap();
        assert!(v.len() == block_header.size());
        assert!(BlockHeader::read(&mut Cursor::new(&v)).unwrap() == block_header);
    }

    #[test]
    fn hash() {
        let block_header = BlockHeader {
            version: 0x00000001,
            prev_hash: Hash256::decode(
                "00000000000008a3a41b85b8b29ad444def299fee21793cd8b9e567eab02cd81",
            )
            .unwrap(),
            merkle_root: Hash256::decode(
                "2b12fcf1b09288fcaff797d71e950e71ae42b91e8bdb2304758dfcffc2b620e3",
            )
            .unwrap(),
            timestamp: 0x4dd7f5c7,
            bits: 0x1a44b9f2,
            nonce: 0x9546a142,
        };
        let str_hash = block_header.hash().encode();
        let expected_hash = "00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d";
        assert!(str_hash == expected_hash);
    }

    #[test]
    fn validate() {
        let prev_hash =
            Hash256::decode("00000000000008a3a41b85b8b29ad444def299fee21793cd8b9e567eab02cd81")
                .unwrap();

        let mut headers = Vec::new();
        for i in 0..11 {
            headers.push(BlockHeader {
                timestamp: i * 10,
                ..Default::default()
            });
        }

        let valid = BlockHeader {
            version: 0x00000001,
            prev_hash,
            merkle_root: Hash256::decode(
                "2b12fcf1b09288fcaff797d71e950e71ae42b91e8bdb2304758dfcffc2b620e3",
            )
            .unwrap(),
            timestamp: 0x4dd7f5c7,
            bits: 0x1a44b9f2,
            nonce: 0x9546a142,
        };
        assert!(valid.validate(&valid.hash(), &headers).is_ok());

        // Bad timestamp
        let h = valid.clone();
        for header in headers.iter_mut() {
            header.timestamp = valid.timestamp + 1;
        }
        assert!(h.validate(&h.hash(), &headers).is_err());

        // Bad POW
        let mut h = valid.clone();
        h.nonce = 0;
        assert!(h.validate(&h.hash(), &headers).is_err());
    }
}
