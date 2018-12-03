//! Functions to read and write variable length integers

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};

/// Returns the number of bytes required
pub fn size(n: u64) -> usize {
    return if n <= 252 {
        1
    } else if n <= 0xffff {
        3
    } else if n <= 0xffffffff {
        5
    } else {
        9
    };
}

/// Writes the var int to bytes
pub fn write(n: u64, writer: &mut dyn Write) -> io::Result<()> {
    if n <= 252 {
        writer.write_u8(n as u8)?;
    } else if n <= 0xffff {
        writer.write_u8(0xfd)?;
        writer.write_u16::<LittleEndian>(n as u16)?;
    } else if n <= 0xffffffff {
        writer.write_u8(0xfe)?;
        writer.write_u32::<LittleEndian>(n as u32)?;
    } else {
        writer.write_u8(0xff)?;
        writer.write_u64::<LittleEndian>(n)?;
    }
    Ok(())
}

/// Reads a var int from bytes
pub fn read(reader: &mut dyn Read) -> io::Result<u64> {
    let n0 = reader.read_u8()?;
    Ok(match n0 {
        0xff => reader.read_u64::<LittleEndian>()?,
        0xfe => reader.read_u32::<LittleEndian>()? as u64,
        0xfd => reader.read_u16::<LittleEndian>()? as u64,
        _ => n0 as u64,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    #[test]
    fn size() {
        assert!(super::size(0) == 1);
        assert!(super::size(253) == 3);
        assert!(super::size(u16::max_value() as u64) == 3);
        assert!(super::size(u32::max_value() as u64) == 5);
        assert!(super::size(u64::max_value()) == 9);
    }

    #[test]
    fn write_read() {
        write_read_value(0);
        write_read_value(253);
        write_read_value(u16::max_value() as u64);
        write_read_value(u32::max_value() as u64);
        write_read_value(u64::max_value());
    }

    fn write_read_value(n: u64) {
        let mut v = Vec::new();
        super::write(n, &mut v).unwrap();
        assert!(super::read(&mut Cursor::new(&v)).unwrap() == n);
    }
}
