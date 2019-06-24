use crate::messages::block_header::BlockHeader;
use crate::messages::message::Payload;
use crate::util::{sha256d, var_int, Error, Hash256, Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use hex;
use std::fmt;
use std::io;
use std::io::{Read, Write};

/// A block header and partial merkle tree for SPV nodes to validate transactions
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct MerkleBlock {
    /// Block header
    pub header: BlockHeader,
    /// Number of transactions in the block
    pub total_transactions: u32,
    /// Hashes in depth-first order
    pub hashes: Vec<Hash256>,
    /// Bit vector used to assign hashes to nodes in the partial merkle tree
    pub flags: Vec<u8>,
}

impl MerkleBlock {
    /// Validates the merkle block and partial merkle tree and returns the set of matched transactions
    pub fn validate(&self) -> Result<Vec<Hash256>> {
        if self.total_transactions == 0 {
            return Err(Error::BadData("No transactions".to_string()));
        }

        let mut preorder_node = 0;
        let mut flag_bits_used = 0;
        let mut hashes_used = 0;
        let mut matches = Vec::new();
        let tree_depth = (self.total_transactions as f32).log(2.).ceil() as usize;
        let mut row_len = self.total_transactions as usize;
        let mut total_nodes = row_len as usize;
        while row_len > 1 {
            row_len = (row_len + 1) / 2;
            total_nodes += row_len;
        }

        let merkle_root = self.traverse(
            &mut preorder_node,
            &mut flag_bits_used,
            &mut hashes_used,
            0,
            tree_depth,
            total_nodes,
            &mut matches,
        )?;

        if merkle_root != self.header.merkle_root {
            return Err(Error::BadData("Merkle root doesn't match".to_string()));
        }

        if hashes_used < self.hashes.len() {
            return Err(Error::BadData("Not all hashes consumed".to_string()));
        }

        if preorder_node < total_nodes {
            return Err(Error::BadData("Not all nodes consumed".to_string()));
        }

        if (flag_bits_used + 7) / 8 < self.flags.len() {
            return Err(Error::BadData("Not all flag bits consumed".to_string()));
        }

        Ok(matches)
    }

    fn traverse(
        &self,
        preorder_node: &mut usize,
        flag_bits_used: &mut usize,
        hashes_used: &mut usize,
        depth: usize,
        tree_depth: usize,
        total_nodes: usize,
        matches: &mut Vec<Hash256>,
    ) -> Result<Hash256> {
        let flag = self.consume_flag(flag_bits_used)?;
        if flag == 0 {
            *preorder_node += (1 << (tree_depth - depth + 1)) - 1;
            let hash = self.consume_hash(hashes_used)?;
            Ok(hash)
        } else if depth == tree_depth {
            *preorder_node += 1;
            let hash = self.consume_hash(hashes_used)?;
            matches.push(hash.clone());
            Ok(hash)
        } else {
            *preorder_node += 1;
            let left = self.traverse(
                preorder_node,
                flag_bits_used,
                hashes_used,
                depth + 1,
                tree_depth,
                total_nodes,
                matches,
            )?;
            if *preorder_node >= total_nodes {
                let mut concat = Vec::with_capacity(64);
                concat.extend_from_slice(&left.0);
                concat.extend_from_slice(&left.0);
                Ok(sha256d(&concat))
            } else {
                let right = self.traverse(
                    preorder_node,
                    flag_bits_used,
                    hashes_used,
                    depth + 1,
                    tree_depth,
                    total_nodes,
                    matches,
                )?;
                if left == right {
                    return Err(Error::BadData("Duplicate transactions".to_string()));
                } else {
                    let mut concat = Vec::with_capacity(64);
                    concat.extend_from_slice(&left.0);
                    concat.extend_from_slice(&right.0);
                    Ok(sha256d(&concat))
                }
            }
        }
    }

    fn consume_flag(&self, flag_bits_used: &mut usize) -> Result<u8> {
        if *flag_bits_used / 8 >= self.flags.len() {
            return Err(Error::BadData("Not enough flag bits".to_string()));
        }
        let flag = (self.flags[*flag_bits_used / 8] >> *flag_bits_used % 8) & 1;
        *flag_bits_used += 1;
        Ok(flag)
    }

    fn consume_hash(&self, hashes_used: &mut usize) -> Result<Hash256> {
        if *hashes_used >= self.hashes.len() {
            return Err(Error::BadData("Not enough hashes".to_string()));
        }
        let hash = self.hashes[*hashes_used];
        *hashes_used += 1;
        Ok(hash)
    }
}

impl Serializable<MerkleBlock> for MerkleBlock {
    fn read(reader: &mut dyn Read) -> Result<MerkleBlock> {
        let header = BlockHeader::read(reader)?;
        let total_transactions = reader.read_u32::<LittleEndian>()?;
        let num_hashes = var_int::read(reader)?;
        let mut hashes = Vec::with_capacity(num_hashes as usize);
        for _i in 0..num_hashes {
            hashes.push(Hash256::read(reader)?);
        }
        let flags_len = var_int::read(reader)?;
        let mut flags = vec![0; flags_len as usize];
        reader.read(&mut flags)?;
        Ok(MerkleBlock {
            header,
            total_transactions,
            hashes,
            flags,
        })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        self.header.write(writer)?;
        writer.write_u32::<LittleEndian>(self.total_transactions)?;
        var_int::write(self.hashes.len() as u64, writer)?;
        for hash in self.hashes.iter() {
            hash.write(writer)?;
        }
        var_int::write(self.flags.len() as u64, writer)?;
        writer.write(&self.flags)?;
        Ok(())
    }
}

impl Payload<MerkleBlock> for MerkleBlock {
    fn size(&self) -> usize {
        self.header.size()
            + 4
            + var_int::size(self.hashes.len() as u64)
            + self.hashes.len() * 32
            + var_int::size(self.flags.len() as u64)
            + self.flags.len()
    }
}

impl fmt::Debug for MerkleBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("MerkleBlock")
            .field("header", &self.header)
            .field("total_transactions", &self.total_transactions)
            .field("hashes", &self.hashes)
            .field("flags", &hex::encode(&self.flags))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use std::io::Cursor;

    #[test]
    fn read_bytes() {
        let b = hex::decode("0100000082bb869cf3a793432a66e826e05a6fc37469f8efb7421dc880670100000000007f16c5962e8bd963659c793ce370d95f093bc7e367117b3c30c1f8fdd0d9728776381b4d4c86041b554b852907000000043612262624047ee87660be1a707519a443b1c1ce3d248cbfc6c15870f6c5daa2019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b6541ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d06820d2a7bc994987302e5b1ac80fc425fe25f8b63169ea78e68fbaaefa59379bbf011d".as_bytes()).unwrap();
        let p = MerkleBlock::read(&mut Cursor::new(&b)).unwrap();
        assert!(p.header.version == 1);
        let prev_hash = "82bb869cf3a793432a66e826e05a6fc37469f8efb7421dc88067010000000000";
        assert!(p.header.prev_hash.0.to_vec() == hex::decode(prev_hash).unwrap());
        let merkle_root = "7f16c5962e8bd963659c793ce370d95f093bc7e367117b3c30c1f8fdd0d97287";
        assert!(p.header.merkle_root.0.to_vec() == hex::decode(merkle_root).unwrap());
        assert!(p.header.timestamp == 1293629558);
        assert!(p.total_transactions == 7);
        assert!(p.hashes.len() == 4);
        let hash1 = "3612262624047ee87660be1a707519a443b1c1ce3d248cbfc6c15870f6c5daa2";
        assert!(p.hashes[0].0.to_vec() == hex::decode(hash1).unwrap());
        let hash2 = "019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b65";
        assert!(p.hashes[1].0.to_vec() == hex::decode(hash2).unwrap());
        let hash3 = "41ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d068";
        assert!(p.hashes[2].0.to_vec() == hex::decode(hash3).unwrap());
        let hash4 = "20d2a7bc994987302e5b1ac80fc425fe25f8b63169ea78e68fbaaefa59379bbf";
        assert!(p.hashes[3].0.to_vec() == hex::decode(hash4).unwrap());
        assert!(p.flags.len() == 1 && p.flags[0] == 29);
    }

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let p = MerkleBlock {
            header: BlockHeader {
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
            },
            total_transactions: 14,
            hashes: vec![Hash256([1; 32]), Hash256([3; 32]), Hash256([5; 32])],
            flags: vec![24, 125, 199],
        };
        p.write(&mut v).unwrap();
        assert!(v.len() == p.size());
        assert!(MerkleBlock::read(&mut Cursor::new(&v)).unwrap() == p);
    }

    #[test]
    fn validate() {
        // Valid merkle block with 7 transactions
        let b = hex::decode("0100000082bb869cf3a793432a66e826e05a6fc37469f8efb7421dc880670100000000007f16c5962e8bd963659c793ce370d95f093bc7e367117b3c30c1f8fdd0d9728776381b4d4c86041b554b852907000000043612262624047ee87660be1a707519a443b1c1ce3d248cbfc6c15870f6c5daa2019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b6541ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d06820d2a7bc994987302e5b1ac80fc425fe25f8b63169ea78e68fbaaefa59379bbf011d".as_bytes()).unwrap();
        let p = MerkleBlock::read(&mut Cursor::new(&b)).unwrap();
        assert!(p.validate().unwrap().len() == 1);

        // Not enough hashes
        let mut p2 = p.clone();
        p2.hashes.truncate(p.hashes.len() - 1);
        assert!(p2.validate().is_err());

        // Too many hashes
        let mut p2 = p.clone();
        p2.hashes.push(Hash256([0; 32]));
        assert!(p2.validate().is_err());

        // Not enough flags
        let mut p2 = p.clone();
        p2.flags = vec![];
        assert!(p2.validate().is_err());

        // Too many flags
        let mut p2 = p.clone();
        p2.flags.push(0);
        assert!(p2.validate().is_err());

        // Merkle root doesn't match
        let mut p2 = p.clone();
        p2.hashes[0] = Hash256([1; 32]);
        assert!(p2.validate().is_err());
    }

    #[test]
    fn incomplete_tree() {
        let hash1 = Hash256([1; 32]);
        let hash2 = Hash256([2; 32]);
        let hash3 = Hash256([3; 32]);
        let hash4 = Hash256([4; 32]);
        let right = hash(&hash(&hash2, &hash3), &hash4);
        let merkle_root = hash(&hash1, &hash(&right, &right));
        let header = BlockHeader {
            version: 12345,
            prev_hash: Hash256([0; 32]),
            merkle_root,
            timestamp: 66,
            bits: 4488,
            nonce: 9999,
        };
        let merkle_block = MerkleBlock {
            header,
            total_transactions: 11,
            hashes: vec![hash1, hash2, hash3, hash4],
            flags: vec![0x5d],
        };
        assert!(merkle_block.validate().is_ok());
    }

    fn hash(a: &Hash256, b: &Hash256) -> Hash256 {
        let mut v = Vec::with_capacity(64);
        v.write(&a.0).unwrap();
        v.write(&b.0).unwrap();
        sha256d(&v)
    }
}
