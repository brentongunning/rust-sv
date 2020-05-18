use crate::script::Script;
use crate::util::{var_int, Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};

/// Transaction output
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct TxOut {
    /// Number of satoshis to spend
    pub satoshis: i64,
    /// Public key script to claim the output
    pub lock_script: Script,
}

impl TxOut {
    /// Returns the size of the transaction output in bytes
    pub fn size(&self) -> usize {
        8 + var_int::size(self.lock_script.0.len() as u64) + self.lock_script.0.len()
    }
}

impl Serializable<TxOut> for TxOut {
    fn read(reader: &mut dyn Read) -> Result<TxOut> {
        let satoshis = reader.read_i64::<LittleEndian>()?;
        let script_len = var_int::read(reader)?;
        let mut lock_script = Script(vec![0; script_len as usize]);
        reader.read(&mut lock_script.0)?;
        Ok(TxOut {
            satoshis,
            lock_script,
        })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_i64::<LittleEndian>(self.satoshis)?;
        var_int::write(self.lock_script.0.len() as u64, writer)?;
        writer.write(&self.lock_script.0)?;
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
        let t = TxOut {
            satoshis: 4400044000,
            lock_script: Script(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 100, 99, 98, 97, 96]),
        };
        t.write(&mut v).unwrap();
        assert!(v.len() == t.size());
        assert!(TxOut::read(&mut Cursor::new(&v)).unwrap() == t);
    }
}
