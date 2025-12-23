use std::io;
use std::io::Read;

use anyhow::{Result, bail};
use zeroize::Zeroize;

/// A proper ring buffer for efficient block processing
/// Data wraps around when reaching the end, no data movement required
pub struct RingBuffer {
    buffer: Vec<u8>,
    read_pos: usize,  // Position to read from
    write_pos: usize, // Position to write to
    count: usize,     // Number of bytes currently in buffer
}

impl RingBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: vec![0; capacity],
            read_pos: 0,
            write_pos: 0,
            count: 0,
        }
    }

    /// Returns the number of bytes available to read
    pub const fn available(&self) -> usize {
        self.count
    }

    /// Returns the buffer capacity
    pub const fn capacity(&self) -> usize {
        self.buffer.len()
    }

    /// Returns the number of bytes that can be written
    pub const fn space_available(&self) -> usize {
        self.capacity() - self.count
    }

    /// Reads data from reader into the buffer's available space
    /// May perform up to 2 reads if the data wraps around
    /// Returns the number of bytes read, or 0 if EOF
    pub fn fill_from<R: Read>(&mut self, reader: &mut R) -> io::Result<usize> {
        let space = self.space_available();
        if space == 0 {
            return Ok(0);
        }

        let mut total_read = 0;

        // Calculate how much we can write before wrapping
        let end = self.buffer.len();
        let first_write_len = (end - self.write_pos).min(space);

        // First write: from write_pos to end of buffer (or until space runs out)
        if first_write_len > 0 {
            let n =
                reader.read(&mut self.buffer[self.write_pos..self.write_pos + first_write_len])?;
            total_read += n;
            self.write_pos = (self.write_pos + n) % end;
            self.count += n;

            if n < first_write_len {
                // EOF or partial read
                return Ok(total_read);
            }
        }

        // Second write: wrap around to beginning if there's still space
        let remaining_space = space - first_write_len;
        if remaining_space > 0 && self.write_pos < self.read_pos {
            let n =
                reader.read(&mut self.buffer[self.write_pos..self.write_pos + remaining_space])?;
            total_read += n;
            self.write_pos = (self.write_pos + n) % end;
            self.count += n;
        }

        Ok(total_read)
    }

    /// Reads exactly `buf.len()` bytes into buf
    /// Returns an error if not enough data is available
    /// May copy from two regions if data wraps around
    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        if self.available() < buf.len() {
            bail!("Not enough data in ring buffer");
        }

        let end = self.buffer.len();
        let mut copied = 0;

        // First copy: from read_pos to end of buffer (or until we have enough)
        let first_copy_len = (end - self.read_pos).min(buf.len());
        buf[..first_copy_len]
            .copy_from_slice(&self.buffer[self.read_pos..self.read_pos + first_copy_len]);
        copied += first_copy_len;

        // Zeroize as we consume
        self.buffer[self.read_pos..self.read_pos + first_copy_len].zeroize();
        self.read_pos = (self.read_pos + first_copy_len) % end;

        // Second copy: wrap around to beginning if needed
        if copied < buf.len() {
            let remaining = buf.len() - copied;
            buf[copied..].copy_from_slice(&self.buffer[self.read_pos..self.read_pos + remaining]);

            // Zeroize as we consume
            self.buffer[self.read_pos..self.read_pos + remaining].zeroize();
            self.read_pos = (self.read_pos + remaining) % end;
        }

        self.count -= buf.len();
        Ok(())
    }
}

impl Drop for RingBuffer {
    fn drop(&mut self) {
        // Zeroize all data on drop
        self.buffer.zeroize();
    }
}

/// A reader wrapper that only reads up to a specified limit
pub struct LimitedReader<R: Read> {
    inner: R,
    limit: u64,
    position: u64,
}

impl<R: Read> LimitedReader<R> {
    pub const fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            limit,
            position: 0,
        }
    }
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.limit {
            return Ok(0);
        }

        let remaining = self.limit - self.position;
        let to_read = buf
            .len()
            .min(usize::try_from(remaining).expect("correctness"));
        let n = self.inner.read(&mut buf[..to_read])?;
        self.position += n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_ring_buffer_basic() {
        let ring = RingBuffer::new(10);
        assert_eq!(ring.capacity(), 10);
        assert_eq!(ring.available(), 0);
        assert_eq!(ring.space_available(), 10);
    }

    #[test]
    fn test_ring_buffer_fill_and_read() {
        let mut ring = RingBuffer::new(10);
        let data = b"hello";
        let mut cursor = Cursor::new(data);

        // Fill the ring buffer
        let n = ring.fill_from(&mut cursor).unwrap();
        assert_eq!(n, 5);
        assert_eq!(ring.available(), 5);
        assert_eq!(ring.space_available(), 5);

        // Read from the ring buffer
        let mut buf = [0u8; 5];
        ring.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");
        assert_eq!(ring.available(), 0);
        assert_eq!(ring.space_available(), 10);
    }

    #[test]
    fn test_ring_buffer_wrapping() {
        let mut ring = RingBuffer::new(10);

        // Fill with 8 bytes
        let mut cursor = Cursor::new(b"12345678");
        ring.fill_from(&mut cursor).unwrap();

        // Read 5 bytes
        let mut buf = [0u8; 5];
        ring.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"12345");
        assert_eq!(ring.available(), 3);

        // Fill more data, which should wrap around
        let mut cursor = Cursor::new(b"abcdefg");
        let n = ring.fill_from(&mut cursor).unwrap();
        assert_eq!(n, 7);
        assert_eq!(ring.available(), 10); // 3 + 7 = 10 (full)

        // Read all data
        let mut buf = [0u8; 10];
        ring.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"678abcdefg");
    }

    #[test]
    fn test_ring_buffer_read_exact_wrapping() {
        let mut ring = RingBuffer::new(10);

        // Fill buffer to capacity
        let mut cursor = Cursor::new(b"0123456789");
        ring.fill_from(&mut cursor).unwrap();

        // Read 7 bytes
        let mut buf = [0u8; 7];
        ring.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"0123456");

        // Add more data (wraps around)
        let mut cursor = Cursor::new(b"ABCDEFG");
        ring.fill_from(&mut cursor).unwrap();

        // Read data that spans the wrap
        // After reading 7 bytes, we have "789" left
        // After adding "ABCDEFG", we have "789ABCDEFG"
        let mut buf = [0u8; 8];
        ring.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"789ABCDE");
    }

    #[test]
    fn test_ring_buffer_not_enough_data() {
        let mut ring = RingBuffer::new(10);
        let mut cursor = Cursor::new(b"hello");
        ring.fill_from(&mut cursor).unwrap();

        let mut buf = [0u8; 10];
        let result = ring.read_exact(&mut buf);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Not enough data"));
    }

    #[test]
    fn test_ring_buffer_full() {
        let mut ring = RingBuffer::new(5);
        let mut cursor = Cursor::new(b"12345");
        let n = ring.fill_from(&mut cursor).unwrap();
        assert_eq!(n, 5);
        assert_eq!(ring.space_available(), 0);

        // Try to fill more - should return 0
        let mut cursor = Cursor::new(b"67890");
        let n = ring.fill_from(&mut cursor).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_limited_reader_exact_limit() {
        let data = b"Hello";
        let cursor = Cursor::new(data);
        let mut limited = LimitedReader::new(cursor, 5);

        let mut buf = [0u8; 10];
        let n = limited.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"Hello");

        // Second read should return 0 (EOF)
        let n = limited.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_limited_reader_multiple_reads() {
        let data = b"Hello, World!";
        let cursor = Cursor::new(data);
        let mut limited = LimitedReader::new(cursor, 8);

        let mut buf = [0u8; 5];
        let n = limited.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"Hello");

        let n = limited.read(&mut buf).unwrap();
        assert_eq!(n, 3); // Only 3 more bytes allowed
        assert_eq!(&buf[..3], b", W");

        // Third read should return 0
        let n = limited.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_limited_reader_zero_limit() {
        let data = b"Hello";
        let cursor = Cursor::new(data);
        let mut limited = LimitedReader::new(cursor, 0);

        let mut buf = [0u8; 10];
        let n = limited.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_limited_reader_large_limit() {
        let data = b"Hello";
        let cursor = Cursor::new(data);
        let mut limited = LimitedReader::new(cursor, 100);

        let mut buf = [0u8; 10];
        let n = limited.read(&mut buf).unwrap();
        assert_eq!(n, 5); // Limited by data size, not limit
        assert_eq!(&buf[..5], b"Hello");
    }
}
