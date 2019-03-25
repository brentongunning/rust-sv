use crate::util::{Error, Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use ring::digest;
use std::fmt;
use std::io;
use std::io::{Cursor, Read, Write};
use std::str;

/// Header that begins all messages
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct MessageHeader {
    /// Magic bytes indicating the network type
    pub magic: [u8; 4],
    /// Command name
    pub command: [u8; 12],
    /// Payload size
    pub payload_size: u32,
    /// First 4 bytes of SHA256(SHA256(payload))
    pub checksum: [u8; 4],
}

impl MessageHeader {
    /// Size of the message header in bytes
    pub const SIZE: usize = 24;

    /// Returns the size of the header in bytes
    pub fn size(&self) -> usize {
        MessageHeader::SIZE
    }

    /// Checks if the header is valid
    ///
    /// `magic` - Expected magic bytes for the network
    /// `max_size` - Max size in bytes for the payload
    pub fn validate(&self, magic: [u8; 4], max_size: u32) -> Result<()> {
        if self.magic != magic {
            let msg = format!("Bad magic: {:?}", self.magic);
            return Err(Error::BadData(msg));
        }
        if self.payload_size > max_size {
            let msg = format!("Bad size: {:?}", self.payload_size);
            return Err(Error::BadData(msg));
        }
        Ok(())
    }

    /// Reads the payload and verifies its checksum
    pub fn payload(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut p = vec![0; self.payload_size as usize];
        reader.read_exact(p.as_mut())?;
        let hash = digest::digest(&digest::SHA256, p.as_ref());
        let hash = digest::digest(&digest::SHA256, &hash.as_ref());
        let h = &hash.as_ref();
        let j = &self.checksum;
        if h[0] != j[0] || h[1] != j[1] || h[2] != j[2] || h[3] != j[3] {
            let msg = format!("Bad checksum: {:?} != {:?}", &h[..4], j);
            return Err(Error::BadData(msg));
        }
        Ok(p)
    }
}

impl Serializable<MessageHeader> for MessageHeader {
    fn read(reader: &mut dyn Read) -> Result<MessageHeader> {
        // Read all the bytes at once so that the stream doesn't get in a partially-read state
        let mut p = vec![0; MessageHeader::SIZE];
        reader.read_exact(p.as_mut())?;
        let mut c = Cursor::new(p);

        // Now parse the results from the stream
        let mut ret = MessageHeader {
            ..Default::default()
        };
        c.read(&mut ret.magic)?;
        c.read(&mut ret.command)?;
        ret.payload_size = c.read_u32::<LittleEndian>()?;
        c.read(&mut ret.checksum)?;

        Ok(ret)
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write(&self.magic)?;
        writer.write(&self.command)?;
        writer.write_u32::<LittleEndian>(self.payload_size)?;
        writer.write(&self.checksum)?;
        Ok(())
    }
}

// Prints so the command is easier to read
impl fmt::Debug for MessageHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let command = match str::from_utf8(&self.command) {
            Ok(s) => s.to_string(),
            Err(_) => format!("Not Ascii ({:?})", self.command),
        };
        write!(
            f,
            "Header {{ magic: {:?}, command: {:?}, payload_size: {}, checksum: {:?} }}",
            self.magic, command, self.payload_size, self.checksum
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use std::io::Cursor;

    #[test]
    fn read_bytes() {
        let b = hex::decode("f9beb4d976657273696f6e00000000007a0000002a1957bb".as_bytes()).unwrap();
        let h = MessageHeader::read(&mut Cursor::new(&b)).unwrap();
        assert!(h.magic == [0xf9, 0xbe, 0xb4, 0xd9]);
        assert!(h.command == *b"version\0\0\0\0\0");
        assert!(h.payload_size == 122);
        assert!(h.checksum == [0x2a, 0x19, 0x57, 0xbb]);
    }

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let h = MessageHeader {
            magic: [0x00, 0x01, 0x02, 0x03],
            command: *b"command\0\0\0\0\0",
            payload_size: 42,
            checksum: [0xa0, 0xa1, 0xa2, 0xa3],
        };
        h.write(&mut v).unwrap();
        assert!(v.len() == h.size());
        assert!(MessageHeader::read(&mut Cursor::new(&v)).unwrap() == h);
    }

    #[test]
    fn validate() {
        let magic = [0xa0, 0xa1, 0xa2, 0xa3];
        let h = MessageHeader {
            magic,
            command: *b"verack\0\0\0\0\0\0",
            payload_size: 88,
            checksum: [0x12, 0x34, 0x56, 0x78],
        };
        // Valid
        assert!(h.validate(magic, 100).is_ok());
        // Bad magic
        let bad_magic = [0xb0, 0xb1, 0xb2, 0xb3];
        assert!(h.validate(bad_magic, 100).is_err());
        // Bad size
        assert!(h.validate(magic, 50).is_err());
    }

    #[test]
    fn payload() {
        let p = [0x22, 0x33, 0x44, 0x00, 0x11, 0x22, 0x45, 0x67, 0x89];
        let hash = digest::digest(&digest::SHA256, &p);
        let hash = digest::digest(&digest::SHA256, hash.as_ref());
        let hash = hash.as_ref();
        let checksum = [hash[0], hash[1], hash[2], hash[3]];
        let header = MessageHeader {
            magic: [0x00, 0x00, 0x00, 0x00],
            command: *b"version\0\0\0\0\0",
            payload_size: p.len() as u32,
            checksum,
        };
        // Valid
        let v = header.payload(&mut Cursor::new(&p)).unwrap();
        assert!(v.as_ref() == p);
        // Bad checksum
        let p2 = [0xf2, 0xf3, 0xf4, 0xf0, 0xf1, 0xf2, 0xf5, 0xf7, 0xf9];
        assert!(header.payload(&mut Cursor::new(&p2)).is_err());
    }
}
