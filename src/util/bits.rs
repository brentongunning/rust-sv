use std::cmp::min;

const LSHIFT_MASK: [u8; 8] = [0xff, 0x7f, 0x3f, 0x1f, 0x0f, 0x07, 0x03, 0x01];
const RSHIFT_MASK: [u8; 8] = [0xff, 0xfE, 0xfc, 0xf8, 0xf0, 0xe0, 0xc0, 0x80];

/// Manages an array of bits
#[derive(Debug, Default, Clone)]
pub struct Bits {
    pub data: Vec<u8>,
    pub len: usize,
}

impl Bits {
    /// Creates an empty bit array
    pub fn new() -> Bits {
        Bits {
            data: vec![],
            len: 0,
        }
    }

    /// Creates a bits array with default capacity for a certain size
    pub fn with_capacity(capacity: usize) -> Bits {
        Bits {
            data: Vec::with_capacity(capacity / 8),
            len: 0,
        }
    }

    /// Creates the bits from a slice
    pub fn from_slice(data: &[u8], len: usize) -> Bits {
        let mut vec = data.to_vec();
        let len = min(data.len() * 8, len);
        if len > vec.len() * 8 {
            vec.truncate((len + 7) / 8);
        }
        let rem = (len % 8) as u8;
        if rem != 0 {
            let last = vec.len() - 1;
            vec[last] &= (!((1 << (8_u8 - rem)) - 1)) as u8;
        }
        Bits { data: vec, len }
    }

    /// Appends data to the bit array
    pub fn append(&mut self, other: &Bits) {
        let mut i = 0;
        while i < other.len / 8 {
            self.append_byte(other.data[i], 8);
            i += 1;
        }
        let rem = other.len % 8;
        if rem != 0 {
            self.append_byte(other.data[i], rem);
        }
    }

    /// Appends a byte or less to the bit array
    fn append_byte(&mut self, byte: u8, len: usize) {
        let end = self.len % 8;
        if end == 0 {
            self.data.push(byte);
            self.len += len;
        } else {
            let last = self.data.len() - 1;
            self.data[last] |= byte >> end;
            if len > 8 - end {
                self.data.push(byte << (8 - end));
            }
            self.len += len;
        }
    }

    /// Gets a range out of the bit array, right-aligned
    pub fn extract(&self, i: usize, len: usize) -> u64 {
        let end = i + len;
        let mut curr: u64 = 0;
        let mut i = i;
        for j in i / 8..((i + len + 7) / 8) {
            let b_len = min(end - i, 8 - (i - j * 8));
            curr = (curr << b_len) | self.extract_byte(i, b_len) as u64;
            i += b_len;
        }
        curr
    }

    /// Extracts a byte or less from the bit array, right-aligned
    pub fn extract_byte(&self, i: usize, len: usize) -> u8 {
        let b = (self.data[i / 8] >> (8 - (i % 8) - len)) as u16;
        (b & ((1_u16 << len) - 1)) as u8
    }
}

pub fn lshift(v: &[u8], n: usize) -> Vec<u8> {
    let bit_shift = n % 8;
    let byte_shift = (n / 8) as i32;

    let mask = LSHIFT_MASK[bit_shift];
    let overflow_mask = !mask;

    let mut result = vec![0; v.len()];
    for i in (0..v.len()).rev() {
        let k = i as i32 - byte_shift;
        if k >= 0 {
            let mut val = v[i] & mask;
            val <<= bit_shift;
            result[k as usize] |= val;
        }
        if k - 1 >= 0 {
            let mut carryval = v[i] & overflow_mask;
            carryval >>= (8 - bit_shift) % 8;
            result[(k - 1) as usize] |= carryval;
        }
    }
    result
}

pub fn rshift(v: &[u8], n: usize) -> Vec<u8> {
    let bit_shift = n % 8;
    let byte_shift = n / 8;

    let mask = RSHIFT_MASK[bit_shift];
    let overflow_mask = !mask;

    let mut result = vec![0; v.len()];
    for i in 0..v.len() {
        let k = i + byte_shift;
        if k < v.len() {
            let mut val = v[i] & mask;
            val >>= bit_shift;
            result[k] |= val;
        }
        if k + 1 < v.len() {
            let mut carryval = v[i] & overflow_mask;
            carryval <<= (8 - bit_shift) % 8;
            result[k + 1] |= carryval;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append() {
        let mut b = Bits::from_slice(&[255], 8);
        b.append(&Bits::from_slice(&[0], 4));
        b.append(&Bits::from_slice(&[255], 2));
        b.append(&Bits::from_slice(&[63], 4));
        assert!(b.len == 18);
        assert!(b.data[0] == 255);
        assert!(b.data[1] == 12);
        assert!(b.data[2] == 192);
    }

    #[test]
    fn extract() {
        let b = Bits::from_slice(&[15, 23, 192], 24);
        let e = b.extract(4, 13);
        assert!(e == 7727);
    }

    #[test]
    fn lshift_test() {
        // Empty array
        assert!(lshift(&[], 0) == vec![]);
        assert!(lshift(&[], 1) == vec![]);
        assert!(lshift(&[], 999999) == vec![]);

        // No shifts
        assert!(lshift(&[0x80, 0x10, 0x30, 0x55], 0) == vec![0x80, 0x10, 0x30, 0x55]);
        assert!(lshift(&[0xff], 0) == vec![0xff]);

        // Shift one
        assert!(lshift(&[0x80, 0x00, 0x00, 0x01], 1) == vec![0x00, 0x00, 0x00, 0x02]);
        assert!(lshift(&[0x80, 0x00, 0x00, 0x00], 999999) == vec![0x00, 0x00, 0x00, 0x00]);

        // Shift four
        assert!(lshift(&[0x01, 0x23, 0x45, 0x67], 4) == vec![0x12, 0x34, 0x56, 0x70]);

        // Shift eight
        assert!(lshift(&[0x01, 0x23, 0x45, 0x67], 8) == vec![0x23, 0x45, 0x67, 0x00]);
    }

    #[test]
    fn rshift_test() {
        // Empty array
        assert!(rshift(&[], 0) == vec![]);
        assert!(rshift(&[], 1) == vec![]);
        assert!(rshift(&[], 999999) == vec![]);

        // No shifts
        assert!(rshift(&[0x80, 0x10, 0x30, 0x55], 0) == vec![0x80, 0x10, 0x30, 0x55]);
        assert!(rshift(&[0xff], 0) == vec![0xff]);

        // Shift one
        assert!(rshift(&[0x80, 0x00, 0x00, 0x02], 1) == vec![0x40, 0x00, 0x00, 0x01]);
        assert!(rshift(&[0x00, 0x00, 0x00, 0x01], 999999) == vec![0x00, 0x00, 0x00, 0x00]);

        // Shift four
        assert!(rshift(&[0x01, 0x23, 0x45, 0x67], 4) == vec![0x00, 0x12, 0x34, 0x56]);

        // Shift eight
        assert!(rshift(&[0x01, 0x23, 0x45, 0x67], 8) == vec![0x00, 0x01, 0x23, 0x45]);
    }
}
