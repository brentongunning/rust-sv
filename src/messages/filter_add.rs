use crate::messages::message::Payload;
use crate::util::{var_int, Error, Result, Serializable};
use hex;
use std::fmt;
use std::io;
use std::io::{Read, Write};

/// Maximum size of a data element in the FilterAdd message
pub const MAX_FILTER_ADD_DATA_SIZE: usize = 520;

/// Adds a data element to the bloom filter
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct FilterAdd {
    /// Data element to be added
    pub data: Vec<u8>,
}

impl FilterAdd {
    /// Returns whether the FilterAdd message is valid
    pub fn validate(&self) -> Result<()> {
        if self.data.len() > MAX_FILTER_ADD_DATA_SIZE {
            return Err(Error::BadData("Data too long".to_string()));
        }
        Ok(())
    }
}

impl Serializable<FilterAdd> for FilterAdd {
    fn read(reader: &mut dyn Read) -> Result<FilterAdd> {
        let data_len = var_int::read(reader)?;
        let mut data = vec![0; data_len as usize];
        reader.read(&mut data)?;
        Ok(FilterAdd { data })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        var_int::write(self.data.len() as u64, writer)?;
        writer.write(&self.data)?;
        Ok(())
    }
}

impl Payload<FilterAdd> for FilterAdd {
    fn size(&self) -> usize {
        var_int::size(self.data.len() as u64) + self.data.len()
    }
}

impl fmt::Debug for FilterAdd {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("FilterAdd")
            .field("data", &hex::encode(&self.data))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read_bytes() {
        let b = hex::decode(
            "20fdacf9b3eb077412e7a968d2e4f11b9a9dee312d666187ed77ee7d26af16cb0b".as_bytes(),
        )
        .unwrap();
        let f = FilterAdd::read(&mut Cursor::new(&b)).unwrap();
        assert!(f.data.len() == 32);
    }

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let p = FilterAdd { data: vec![20; 20] };
        p.write(&mut v).unwrap();
        assert!(v.len() == p.size());
        assert!(FilterAdd::read(&mut Cursor::new(&v)).unwrap() == p);
    }

    #[test]
    fn validate() {
        let p = FilterAdd { data: vec![21; 21] };
        assert!(p.validate().is_ok());

        let p = FilterAdd {
            data: vec![21; MAX_FILTER_ADD_DATA_SIZE + 1],
        };
        assert!(p.validate().is_err());
    }
}
