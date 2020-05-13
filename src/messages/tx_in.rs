use crate::messages::OutPoint;
use crate::script::Script;
use crate::util::{var_int, Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};

/// Transaction input
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct TxIn {
    /// The previous output transaction reference
    pub prev_output: OutPoint,
    /// Signature script for confirming authorization
    pub unlock_script: Script,
    /// Transaction version as defined by the sender for replacement or negotiation
    pub sequence: u32,
}

impl TxIn {
    /// Returns the size of the transaction input in bytes
    pub fn size(&self) -> usize {
        OutPoint::SIZE
            + var_int::size(self.unlock_script.0.len() as u64)
            + self.unlock_script.0.len()
            + 4
    }
}

impl Serializable<TxIn> for TxIn {
    fn read(reader: &mut dyn Read) -> Result<TxIn> {
        let prev_output = OutPoint::read(reader)?;
        let script_len = var_int::read(reader)?;
        let mut unlock_script = Script(vec![0; script_len as usize]);
        reader.read(&mut unlock_script.0)?;
        let sequence = reader.read_u32::<LittleEndian>()?;
        Ok(TxIn {
            prev_output,
            unlock_script,
            sequence,
        })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        self.prev_output.write(writer)?;
        var_int::write(self.unlock_script.0.len() as u64, writer)?;
        writer.write(&self.unlock_script.0)?;
        writer.write_u32::<LittleEndian>(self.sequence)?;
        Ok(())
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
        let t = TxIn {
            prev_output: OutPoint {
                hash: Hash256([6; 32]),
                index: 8,
            },
            unlock_script: Script(vec![255; 254]),
            sequence: 100,
        };
        t.write(&mut v).unwrap();
        assert!(v.len() == t.size());
        assert!(TxIn::read(&mut Cursor::new(&v)).unwrap() == t);
    }
}
