use byteorder::{ReadBytesExt, WriteBytesExt};
use messages::message::Payload;
use std::fmt;
use std::io;
use std::io::{Cursor, Read, Write};
use util::{var_int, Error, Hash256, Result, Serializable};

/// Message rejection error codes
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum RejectCode {
    RejectMalformed = 0x01,
    RejectInvalid = 0x10,
    RejectObsolete = 0x11,
    RejectDuplicate = 0x12,
    RejectNonstandard = 0x40,
    RejectDust = 0x41,
    RejectInsufficientFee = 0x42,
    RejectCheckpoint = 0x43,
}

impl RejectCode {
    /// Converts an integer to a reject code
    pub fn from_u8(x: u8) -> Result<RejectCode> {
        match x {
            x if x == RejectCode::RejectMalformed as u8 => Ok(RejectCode::RejectMalformed),
            x if x == RejectCode::RejectInvalid as u8 => Ok(RejectCode::RejectInvalid),
            x if x == RejectCode::RejectObsolete as u8 => Ok(RejectCode::RejectObsolete),
            x if x == RejectCode::RejectDuplicate as u8 => Ok(RejectCode::RejectDuplicate),
            x if x == RejectCode::RejectNonstandard as u8 => Ok(RejectCode::RejectNonstandard),
            x if x == RejectCode::RejectDust as u8 => Ok(RejectCode::RejectDust),
            x if x == RejectCode::RejectInsufficientFee as u8 => {
                Ok(RejectCode::RejectInsufficientFee)
            }
            x if x == RejectCode::RejectCheckpoint as u8 => Ok(RejectCode::RejectCheckpoint),
            _ => {
                let msg = format!("Unknown rejection code: {}", x);
                Err(Error::BadArgument(msg))
            }
        }
    }
}

/// Rejected message
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Reject {
    /// Type of message rejected
    pub message: String,
    /// Error code
    pub code: RejectCode,
    /// Reason for rejection
    pub reason: String,
    /// Optional extra data that may be present for some rejections
    ///
    /// Currently this is only a 32-byte hash of the block or transaction if applicable.
    pub data: Vec<u8>,
}

impl Serializable<Reject> for Reject {
    fn read(reader: &mut dyn Read) -> Result<Reject> {
        let message_size = var_int::read(reader)? as usize;
        let mut message_bytes = vec![0; message_size];
        reader.read(&mut message_bytes)?;
        let message = String::from_utf8(message_bytes)?;
        let code = RejectCode::from_u8(reader.read_u8()?)?;
        let reason_size = var_int::read(reader)? as usize;
        let mut reason_bytes = vec![0; reason_size];
        reader.read(&mut reason_bytes)?;
        let reason = String::from_utf8(reason_bytes)?;
        let mut data = vec![];
        if message == "block".to_string() || message == "tx".to_string() {
            data = vec![0_u8; 32];
            reader.read(&mut data)?;
        }
        Ok(Reject {
            message,
            code,
            reason,
            data,
        })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        var_int::write(self.message.as_bytes().len() as u64, writer)?;
        writer.write(&self.message.as_bytes())?;
        writer.write_u8(self.code as u8)?;
        var_int::write(self.reason.as_bytes().len() as u64, writer)?;
        writer.write(&self.reason.as_bytes())?;
        writer.write(&self.data)?;
        Ok(())
    }
}

impl Payload<Reject> for Reject {
    fn size(&self) -> usize {
        var_int::size(self.message.as_bytes().len() as u64)
            + self.message.as_bytes().len()
            + 1
            + var_int::size(self.reason.as_bytes().len() as u64)
            + self.reason.as_bytes().len()
            + self.data.len()
    }
}

impl fmt::Debug for Reject {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut data_str = "".to_string();
        if self.message == "block".to_string() || self.message == "tx".to_string() {
            let mut data = Cursor::new(&self.data);
            data_str = Hash256::read(&mut data).unwrap().encode();
        }
        f.debug_struct("Reject")
            .field("message", &self.message)
            .field("code", &self.code)
            .field("reason", &self.reason)
            .field("data", &data_str)
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
        let b = hex::decode("027478104f6d616e6461746f72792d7363726970742d7665726966792d666c61672d6661696c65642028536372697074206661696c656420616e204f505f455155414c564552494659206f7065726174696f6e292f174bfe9e5b6e32ef2fabd164df5469f44977d93e0625238465ded771083993".as_bytes()).unwrap();
        let m = Reject::read(&mut Cursor::new(&b)).unwrap();
        assert!(m.message == "tx".to_string());
        assert!(m.code == RejectCode::RejectInvalid);
        assert!(m.reason == "mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)".to_string());
        let data = "2f174bfe9e5b6e32ef2fabd164df5469f44977d93e0625238465ded771083993";
        assert!(m.data == hex::decode(data).unwrap());
    }

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let p = Reject {
            message: "block".to_string(),
            code: RejectCode::RejectInvalid,
            reason: "Block too small".to_string(),
            data: vec![5; 32],
        };
        p.write(&mut v).unwrap();
        assert!(v.len() == p.size());
        assert!(Reject::read(&mut Cursor::new(&v)).unwrap() == p);
    }
}
