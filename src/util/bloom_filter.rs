use crate::util::{var_int, Error, Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use hex;
use murmur3::murmur3_32;
use rand::random;
use std::fmt;
use std::io;
use std::io::{Cursor, Read, Write};
use std::num::Wrapping;

/// Maximum number of bytes in the bloom filter bit field
pub const BLOOM_FILTER_MAX_FILTER_SIZE: usize = 36000;

/// Maximum number of hash functions for the bloom filter
pub const BLOOM_FILTER_MAX_HASH_FUNCS: usize = 50;

/// Bloom filter used by SPV nodes to limit transactions received
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct BloomFilter {
    /// Filter bit field
    pub filter: Vec<u8>,
    /// Number of hash functions used
    pub num_hash_funcs: usize,
    /// Random tweak to generate the hash functions
    pub tweak: u32,
}

impl BloomFilter {
    /// Creates a new bloom filter
    ///
    /// * `insert` - Number of items expected to be inserted into the bloom filter
    /// * `pr_false_pos` - Desired probability of a false positive
    pub fn new(insert: f64, pr_false_pos: f64) -> Result<BloomFilter> {
        if !insert.is_normal() || insert < 0. {
            return Err(Error::BadArgument("insert not valid".to_string()));
        }
        if !pr_false_pos.is_normal() || pr_false_pos < 0. {
            return Err(Error::BadArgument("pr_false_po not valid".to_string()));
        }
        let ln2 = 2_f64.ln();
        let size = (-1_f64 / ln2.powf(2_f64) * insert * pr_false_pos.ln()) / 8_f64;
        let size = size.min(BLOOM_FILTER_MAX_FILTER_SIZE as f64);
        let num_hash_funcs = (size as f64) * 8_f64 / insert * ln2;
        let num_hash_funcs = num_hash_funcs.min(BLOOM_FILTER_MAX_HASH_FUNCS as f64);
        let size = size.ceil() as usize;
        let num_hash_funcs = num_hash_funcs.ceil() as usize;
        let tweak = random();
        debug!(
            "Creating bloom filter of size: {}, n_hash funcs: {}, tweak: {}",
            size, num_hash_funcs, tweak
        );
        Ok(BloomFilter {
            filter: vec![0; size],
            num_hash_funcs,
            tweak,
        })
    }

    /// Adds data to the bloom filter
    pub fn add(&mut self, data: &[u8]) {
        debug!("Adding to bloom filter: {:?}", hex::encode(&data));
        for i in 0..self.num_hash_funcs {
            let seed = Wrapping(i as u32) * Wrapping(0xFBA4C795) + Wrapping(self.tweak);
            let c = murmur3_32(&mut Cursor::new(&data), seed.0) % (self.filter.len() as u32 * 8);
            self.filter[c as usize / 8] |= 1 << (c % 8);
        }
    }

    /// Probabilistically returns whether the bloom filter contains the given data
    ///
    /// There may be false positives, but there won't be false negatives.
    pub fn contains(&self, data: &[u8]) -> bool {
        for i in 0..self.num_hash_funcs {
            let seed = Wrapping(i as u32) * Wrapping(0xFBA4C795) + Wrapping(self.tweak);
            let c = murmur3_32(&mut Cursor::new(&data), seed.0) % (self.filter.len() as u32 * 8);
            if self.filter[c as usize / 8] & 1 << (c % 8) == 0 {
                return false;
            }
        }
        true
    }

    /// Returns whether the BloomFilter is valid
    pub fn validate(&self) -> Result<()> {
        if self.filter.len() > BLOOM_FILTER_MAX_FILTER_SIZE {
            return Err(Error::BadData("Filter too long".to_string()));
        }
        if self.num_hash_funcs > BLOOM_FILTER_MAX_HASH_FUNCS {
            return Err(Error::BadData("Too many hash funcs".to_string()));
        }
        Ok(())
    }
}

impl Serializable<BloomFilter> for BloomFilter {
    fn read(reader: &mut dyn Read) -> Result<BloomFilter> {
        let filter_len = var_int::read(reader)? as usize;
        let mut bloom_filter = BloomFilter {
            filter: vec![0; filter_len],
            num_hash_funcs: 0,
            tweak: 0,
        };
        reader.read(&mut bloom_filter.filter)?;
        bloom_filter.num_hash_funcs = reader.read_u64::<LittleEndian>()? as usize;
        bloom_filter.tweak = reader.read_u32::<LittleEndian>()?;
        Ok(bloom_filter)
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        var_int::write(self.filter.len() as u64, writer)?;
        writer.write(&self.filter)?;
        writer.write_u64::<LittleEndian>(self.num_hash_funcs as u64)?;
        writer.write_u32::<LittleEndian>(self.tweak)?;
        Ok(())
    }
}

impl fmt::Debug for BloomFilter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("BloomFilter")
            .field("filter", &hex::encode(&self.filter))
            .field("num_hash_funcs", &self.num_hash_funcs)
            .field("tweak", &self.tweak)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std;

    #[test]
    fn write_read() {
        let mut bf = BloomFilter::new(20000., 0.001).unwrap();
        for i in 0..5 {
            bf.add(&vec![i; 32]);
        }
        let mut v = Vec::new();
        bf.write(&mut v).unwrap();
        assert!(BloomFilter::read(&mut Cursor::new(&v)).unwrap() == bf);
    }

    #[test]
    fn contains() {
        let mut bf = BloomFilter::new(20000., 0.001).unwrap();
        bf.add(&vec![5; 32]);
        assert!(bf.contains(&vec![5; 32]));
        assert!(!bf.contains(&vec![6; 32]));
    }

    #[test]
    fn invalid() {
        assert!(BloomFilter::new(0., 0.5).is_err());
        assert!(BloomFilter::new(1., 0.).is_err());
        assert!(BloomFilter::new(-1., 0.5).is_err());
        assert!(BloomFilter::new(1., -1.).is_err());
        assert!(BloomFilter::new(1., std::f64::NAN).is_err());
        assert!(BloomFilter::new(std::f64::NAN, 0.5).is_err());
    }

    #[test]
    fn validate() {
        let bf = BloomFilter {
            filter: vec![0, 1, 2, 3, 4, 5],
            num_hash_funcs: 30,
            tweak: 100,
        };
        assert!(bf.validate().is_ok());

        let mut bf_clone = bf.clone();
        bf_clone.filter = vec![0; BLOOM_FILTER_MAX_FILTER_SIZE + 1];
        assert!(bf_clone.validate().is_err());

        let mut bf_clone = bf.clone();
        bf_clone.num_hash_funcs = BLOOM_FILTER_MAX_HASH_FUNCS + 1;
        assert!(bf_clone.validate().is_err());
    }
}
