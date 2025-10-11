//! Bitmap module for managing bit information.
use alloc::vec::Vec;
use std::fs::File;
use std::io::Read;

/// Bitmap structure used to store bit information.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Bitmap {
    /// Byte array storing the bit information.
    pub buf: Vec<u8>,
    /// popcount of the bitmap(number of bits set to 1)
    pub popcnt: usize,
}

/// Sparse bitmap structure used to store bit information.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SparseBitmap {
    /// Vector storing the indices of the set bits.
    pub indices: Vec<usize>,
    /// Length of the bitmap
    pub len: usize,
}

/// Trait for the bitmap structure.
pub trait BitmapTrait {
    /// Returns the length of the bitmap in bits.
    fn len(&self) -> usize;

    /// Retrieves the value of a specific bit index.
    ///
    /// # Arguments
    ///
    /// * `idx` - Index of the bit to query.
    ///
    /// # Returns
    ///
    /// Returns `true` if the bit is set, otherwise returns `false`.
    fn get(&self, idx: usize) -> bool;

    /// Get a specific byte index.
    fn get_ubyte(&self, idx: usize) -> u8;

    /// Set a specific byte index.
    fn set_ubyte(&mut self, idx: usize, byte: u8);

    /// Get the popcount of the bitmap in O(1).
    fn popcount(&self) -> usize;

    /// Sets a specific bit index.
    ///
    /// # Arguments
    ///
    /// * `idx` - Index of the bit to set.
    fn set(&mut self, idx: usize);

    /// Clears a specific bit index.
    ///
    /// # Arguments
    ///
    /// * `idx` - Index of the bit to clear.
    fn clear(&mut self, idx: usize);

    /// Clear all bits in the bitmap.
    fn clear_all(&mut self);
}

/// Popcount function for counting the number of set bits in a byte.
pub fn popcount8(b: u8) -> u8 {
    let mut count = 0;
    for i in 0..8 {
        count += (b >> i) & 1;
    }
    return count;
}

impl Bitmap {
    /// Creates a new instance of the bitmap.
    ///
    /// # Arguments
    ///
    /// * `len` - Total length of the bitmap in bits.
    pub fn new(len: usize) -> Bitmap {
        let rounded_len = (len + 7) / 8 * 8;
        Bitmap {
            buf: vec![0; ((rounded_len + 7) / 8).try_into().unwrap()],
            popcnt: 0,
        }
    }
}

impl SparseBitmap {
    /// Creates a new instance of the bitmap.
    ///
    /// # Arguments
    ///
    /// * `len` - Total length of the bitmap in bits.
    pub fn new(_len: usize) -> SparseBitmap {
        SparseBitmap { indices: Vec::new(), len: (_len + 7) / 8 * 8 }
    }
}

impl BitmapTrait for Bitmap {
    fn len(&self) -> usize {
        self.buf.len() * 8
    }

    fn get(&self, idx: usize) -> bool {
        if idx >= self.len() {
            panic!("index out of range");
        }

        let byte = self.buf[idx / 8];
        (byte & (1 << (idx % 8))) != 0
    }

    fn get_ubyte(&self, idx: usize) -> u8 {
        // the length of bitmap is always a multiple of 8
        assert_eq!(self.len() % 8, 0);

        if idx >= self.len() / 8 {
            panic!("index out of range");
        }

        let byte = self.buf[idx / 8];
        return byte;
    }

    fn set_ubyte(&mut self, idx: usize, byte: u8) {
        if idx >= self.len() / 8 {
            panic!("index out of range");
        }

        let old: u8 = self.buf[idx / 8];
        // increment by newly set bits
        self.popcnt += popcount8(byte) as usize;
        self.popcnt -= popcount8(old) as usize;
        self.buf[idx / 8] = byte;
    }

    fn popcount(&self) -> usize {
        return self.popcnt;
    }

    fn set(&mut self, idx: usize) {
        if idx >= self.len() {
            panic!("index out of range");
        }

        if self.buf[idx / 8] & (1 << (idx % 8)) == 0 {
            self.popcnt += 1;
        }

        self.buf[idx / 8] |= 1 << (idx % 8);
    }

    fn clear(&mut self, idx: usize) {
        if idx >= self.len() {
            panic!("index out of range");
        }

        if self.buf[idx / 8] & (1 << (idx % 8)) != 0 {
            self.popcnt -= 1;
        }

        self.buf[idx / 8] &= !(1 << (idx % 8));
    }

    fn clear_all(&mut self) {
        self.buf.fill(0);
        self.popcnt = 0;
    }
}

impl BitmapTrait for SparseBitmap {
    fn len(&self) -> usize {
        self.len
    }

    fn get(&self, idx: usize) -> bool {
        if idx >= self.len() {
            panic!("index out of range");
        }

        self.indices.contains(&idx)
    }

    fn get_ubyte(&self, idx: usize) -> u8 {
        if idx >= self.len() / 8 {
            panic!("index out of range");
        }
        let mut byte: u8 = 0;

        for i in 0..8 {
            if self.indices.contains(&(idx * 8 + i)) {
                byte |= 1 << i;
            }
        }

        return byte;
    }

    fn set(&mut self, idx: usize) {
        if idx >= self.len() {
            panic!("index out of range");
        }

        if !self.indices.contains(&idx) {
            self.indices.push(idx);
        }
    }

    fn set_ubyte(&mut self, idx: usize, byte: u8) {
        if idx >= self.len() / 8 {
            panic!("index out of range");
        }

        for i in 0..8 {
            if (byte & (1 << i)) != 0 {
                self.set(idx * 8 + i);
            } else {
                self.clear(idx * 8 + i);
            }
        }
    }

    fn popcount(&self) -> usize {
        return self.indices.len();
    }

    fn clear(&mut self, idx: usize) {
        if idx >= self.len() {
            panic!("index out of range");
        }

        if let Some(pos) = self.indices.iter().position(|&x| x == idx) {
            self.indices.remove(pos);
        }
    }

    fn clear_all(&mut self) {
        self.indices.clear();
    }
}

impl Default for Bitmap {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Open /dev/random and read 8 bytes to fill a 64-bit random number.
pub fn getrand64() -> usize {
    // open /dev/random
    let mut fobj: File = File::open("/dev/random").unwrap();
    let mut buf: [u8; 8] = [0; 8];
    fobj.read(&mut buf).unwrap();
    return usize::from_be_bytes(buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitmap() {
        let mut bitmap = Bitmap::new(8);
        assert_eq!(bitmap.len(), 8);
        for i in 0..bitmap.len() {
            assert_eq!(bitmap.get(i), false);
        }

        bitmap.set(0);
        assert_eq!(bitmap.get(0), true);
        assert_eq!(bitmap.popcount(), 1);

        bitmap.clear(0);
        assert_eq!(bitmap.get(0), false);
        assert_eq!(bitmap.popcount(), 0);

        bitmap.set_ubyte(0, 0x35);
        assert_eq!(bitmap.popcount(), popcount8(0x35) as usize);

        bitmap.set_ubyte(0, 0x47);
        assert_eq!(bitmap.popcount(), popcount8(0x47) as usize);

        bitmap.clear_all();
        assert_eq!(bitmap.popcount(), 0);
    }

    #[test]
    fn test_sparse_bitmap() {
        let mut bitmap = SparseBitmap::new(8);
        assert_eq!(bitmap.len(), 8);
        for i in 0..bitmap.len() {
            assert_eq!(bitmap.get(i), false);
        }

        bitmap.set(0);
        assert!(bitmap.indices.contains(&0));
        assert_eq!(bitmap.get(0), true);
        assert_eq!(bitmap.popcount(), 1);

        bitmap.clear(0);
        assert_eq!(bitmap.get(0), false);
        assert_eq!(bitmap.popcount(), 0);

        bitmap.set_ubyte(0, 0x35);
        assert_eq!(bitmap.popcount(), popcount8(0x35) as usize);

        bitmap.set_ubyte(0, 0x47);
        assert_eq!(bitmap.popcount(), popcount8(0x47) as usize);

        bitmap.clear_all();
        assert_eq!(bitmap.popcount(), 0);
    }

    #[test]
    fn test_random() {
        for _i in 0..5 {
            println!("{}", getrand64());
        }

        // OK
    }
}
