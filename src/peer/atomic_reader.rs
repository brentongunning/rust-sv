use std::io;
use std::io::Read;

const MAX_BUFFER_SIZE_USIZE: usize = 2147483647;

/// Wraps a reader so reads become all-or-nothing
pub struct AtomicReader<'a> {
    buf: Vec<u8>,
    reader: &'a mut dyn Read,
}

impl<'a> AtomicReader<'a> {
    pub fn new(reader: &mut dyn Read) -> AtomicReader {
        let buf = Vec::new();
        AtomicReader { buf, reader }
    }
}

impl<'a> Read for AtomicReader<'a> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let buf_len = self.buf.len();
        let out_len = out.len();
        if buf_len >= out_len {
            // If we have enough in the buffer already, use it
            out.clone_from_slice(&self.buf[0..out_len]);
            self.buf = self.buf[out_len..].to_vec();
            Ok(out_len)
        } else if buf_len > 0 {
            // Copy what we have and try to read the rest
            out[0..buf_len].clone_from_slice(&self.buf[0..]);

            // Check the size of this read
            let size = if (out_len - buf_len) > MAX_BUFFER_SIZE_USIZE {
                self.reader
                    .read(&mut out[buf_len..buf_len + MAX_BUFFER_SIZE_USIZE])?
            } else {
                self.reader.read(&mut out[buf_len..])?
            };

            if size == 0 {
                Err(io::Error::new(io::ErrorKind::NotConnected, "Disconnected"))
            } else if buf_len + size < out_len {
                // Didn't read enough. Put what we read into the buffer.
                self.buf.extend_from_slice(&out[buf_len..buf_len + size]);
                Err(io::Error::new(io::ErrorKind::TimedOut, "Incomplete read"))
            } else {
                // Read enough. Clear the buffer and return.
                self.buf = Vec::new();
                Ok(out_len)
            }
        } else {
            // Check the size of this read
            let size = if out_len > MAX_BUFFER_SIZE_USIZE {
                self.reader.read(&mut out[0..MAX_BUFFER_SIZE_USIZE])?
            } else {
                self.reader.read(&mut out[0..])?
            };

            if size == 0 {
                Err(io::Error::new(io::ErrorKind::NotConnected, "Disconnected"))
            } else if size < out_len {
                // Didn't read enough. Put what we read into the buffer.
                self.buf.extend_from_slice(&out[0..size]);
                Err(io::Error::new(io::ErrorKind::TimedOut, "Incomplete read"))
            } else {
                // Read enough. Return.
                Ok(out_len)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read() {
        let mut o = [0; 10];

        // Success: Read expected
        let v = vec![0; 10];
        let mut c = Cursor::new(&v);
        let mut r = AtomicReader::new(&mut c);
        assert!(r.read(&mut o).is_ok());

        // Success: Read less than expected
        let v = vec![0; 12];
        let mut c = Cursor::new(&v);
        let mut r = AtomicReader::new(&mut c);
        assert!(r.read(&mut o).is_ok());

        // Success: Read buffered
        let v = vec![0; 0];
        let mut c = Cursor::new(&v);
        let mut r = AtomicReader::new(&mut c);
        r.buf = vec![1; 10];
        assert!(r.read(&mut o).is_ok());
        assert!(r.buf.len() == 0);

        // Success: Read partially buffered
        let v = vec![0; 6];
        let mut c = Cursor::new(&v);
        let mut r = AtomicReader::new(&mut c);
        r.buf = vec![1; 4];
        assert!(r.read(&mut o).is_ok());
        assert!(o == [1, 1, 1, 1, 0, 0, 0, 0, 0, 0]);

        // Error: Read empty
        let v = vec![0; 0];
        let mut c = Cursor::new(&v);
        let mut r = AtomicReader::new(&mut c);
        assert!(r.read(&mut o).is_err());

        // Error: Read incomplete
        let v = vec![0; 9];
        let mut c = Cursor::new(&v);
        let mut r = AtomicReader::new(&mut c);
        assert!(r.read(&mut o).is_err());
        assert!(r.buf.len() == 9);

        // Error: Read buffered and incomplete
        let v = vec![0; 0];
        let mut c = Cursor::new(&v);
        let mut r = AtomicReader::new(&mut c);
        r.buf = vec![1; 9];
        assert!(r.read(&mut o).is_err());
        assert!(r.buf.len() == 9);

        // Error: Read partially buffered and incomplete
        let v = vec![0; 6];
        let mut c = Cursor::new(&v);
        let mut r = AtomicReader::new(&mut c);
        r.buf = vec![1; 3];
        assert!(r.read(&mut o).is_err());
        assert!(r.buf.len() == 9);
    }
}
