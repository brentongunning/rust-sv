use crate::messages::block_header::BlockHeader;
use crate::messages::message::Payload;
use crate::util::{var_int, Error, Hash256, Result, Serializable};
use byteorder::{ReadBytesExt, WriteBytesExt};
use std::fmt;
use std::io;
use std::io::{Read, Write};

/// Collection of block headers
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct Headers {
    /// List of sequential block headers
    pub headers: Vec<BlockHeader>,
}

impl Serializable<Headers> for Headers {
    fn read(reader: &mut dyn Read) -> Result<Headers> {
        let n = var_int::read(reader)?;
        let mut headers = Vec::new();
        for _i in 0..n {
            headers.push(BlockHeader::read(reader)?);
            let _txn_count = reader.read_u8();
        }
        Ok(Headers { headers })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        var_int::write(self.headers.len() as u64, writer)?;
        for header in self.headers.iter() {
            header.write(writer)?;
            writer.write_u8(0)?;
        }
        Ok(())
    }
}

impl Payload<Headers> for Headers {
    fn size(&self) -> usize {
        var_int::size(self.headers.len() as u64) + (BlockHeader::SIZE + 1) * self.headers.len()
    }
}

impl fmt::Debug for Headers {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let h = format!("[<{} block headers>]", self.headers.len());
        f.debug_struct("Headers").field("headers", &h).finish()
    }
}

/// Returns the hash for a header at a particular index utilizing prev_hash if possible
pub fn header_hash(i: usize, headers: &Vec<BlockHeader>) -> Result<Hash256> {
    if i + 1 < headers.len() {
        return Ok(headers[i + 1].prev_hash);
    } else if i + 1 == headers.len() {
        return Ok(headers[i].hash());
    } else {
        return Err(Error::BadArgument("Index out of range".to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::Hash256;
    use std::io::Cursor;

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let p = Headers {
            headers: vec![
                BlockHeader {
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
                BlockHeader {
                    version: 67890,
                    prev_hash: Hash256::decode(
                        "1122334455112233445511223344551122334455112233445511223344551122",
                    )
                    .unwrap(),
                    merkle_root: Hash256::decode(
                        "6677889900667788990066778899006677889900667788990066778899006677",
                    )
                    .unwrap(),
                    timestamp: 77,
                    bits: 5599,
                    nonce: 1111,
                },
            ],
        };
        p.write(&mut v).unwrap();
        assert!(v.len() == p.size());
        assert!(Headers::read(&mut Cursor::new(&v)).unwrap() == p);
    }

    #[test]
    fn header_hash_test() {
        let header1 = BlockHeader {
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

        let header2 = BlockHeader {
            version: 67890,
            prev_hash: header1.hash(),
            merkle_root: Hash256::decode(
                "6677889900667788990066778899006677889900667788990066778899006677",
            )
            .unwrap(),
            timestamp: 77,
            bits: 5599,
            nonce: 1111,
        };

        assert!(header_hash(0, &vec![]).is_err());

        let headers = vec![header1.clone()];
        assert!(header_hash(0, &headers).unwrap() == header1.hash());
        assert!(header_hash(1, &headers).is_err());

        let headers = vec![header1.clone(), header2.clone()];
        assert!(header_hash(0, &headers).unwrap() == header1.hash());
        assert!(header_hash(1, &headers).unwrap() == header2.hash());
        assert!(header_hash(2, &headers).is_err());
    }
}
