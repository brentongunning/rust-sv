use crate::messages::message::Payload;
use crate::util::{var_int, Error, Hash256, Result, Serializable};
use byteorder::{ReadBytesExt, WriteBytesExt};
use std::fmt;
use std::io;
use std::io::{Cursor, Read, Write};

// Message rejection error codes
pub const REJECT_MALFORMED: u8 = 0x01;
pub const REJECT_INVALID: u8 = 0x10;
pub const REJECT_OBSOLETE: u8 = 0x11;
pub const REJECT_DUPLICATE: u8 = 0x12;
pub const REJECT_NONSTANDARD: u8 = 0x40;
pub const REJECT_DUST: u8 = 0x41;
pub const REJECT_INSUFFICIENT_FEE: u8 = 0x42;
pub const REJECT_CHECKPOINT: u8 = 0x43;

/// Rejected message
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct Reject {
    /// Type of message rejected
    pub message: String,
    /// Error code
    pub code: u8,
    /// Reason for rejection
    pub reason: String,
    /// Optional extra data that may be present for some rejections
    ///
    /// Currently this is only a 32-byte hash of the block or transaction if applicable.
    pub data: Vec<u8>,
}

impl Reject {
    /// Returns the transaction ID for this message
    pub fn txid(&self) -> Result<Hash256> {
        if self.data.len() != 32 {
            return Err(Error::InvalidOperation("No transaction hash".to_string()));
        }
        let mut txid = Hash256([0; 32]);
        txid.0.clone_from_slice(&self.data);
        Ok(txid)
    }
}

impl Serializable<Reject> for Reject {
    fn read(reader: &mut dyn Read) -> Result<Reject> {
        let message_size = var_int::read(reader)? as usize;
        let mut message_bytes = vec![0; message_size];
        reader.read(&mut message_bytes)?;
        let message = String::from_utf8(message_bytes)?;
        let code = reader.read_u8()?;
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
        writer.write_u8(self.code)?;
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
    fn txid() {
        let mut reject = Reject {
            data: vec![5; 32],
            ..Default::default()
        };
        assert!(reject.txid().is_ok());
        reject.data = vec![3; 33];
        assert!(reject.txid().is_err());
    }

    #[test]
    fn read_bytes() {
        let b = hex::decode("027478104f6d616e6461746f72792d7363726970742d7665726966792d666c61672d6661696c65642028536372697074206661696c656420616e204f505f455155414c564552494659206f7065726174696f6e292f174bfe9e5b6e32ef2fabd164df5469f44977d93e0625238465ded771083993".as_bytes()).unwrap();
        let m = Reject::read(&mut Cursor::new(&b)).unwrap();
        assert!(m.message == "tx".to_string());
        assert!(m.code == REJECT_INVALID);
        assert!(m.reason == "mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)".to_string());
        let data = "2f174bfe9e5b6e32ef2fabd164df5469f44977d93e0625238465ded771083993";
        assert!(m.data == hex::decode(data).unwrap());
    }

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let p = Reject {
            message: "block".to_string(),
            code: REJECT_INVALID,
            reason: "Block too small".to_string(),
            data: vec![5; 32],
        };
        p.write(&mut v).unwrap();
        assert!(v.len() == p.size());
        assert!(Reject::read(&mut Cursor::new(&v)).unwrap() == p);
    }
}
