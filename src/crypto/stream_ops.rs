use std::io;
use std::io::Read;

use anyhow::{Result, bail};
use cbc::cipher::typenum::Unsigned;
use cbc::cipher::{Block, BlockDecryptMut, BlockEncryptMut, BlockSizeUser};
use hmac::Mac;
use zeroize::Zeroize;

use super::utils::RingBuffer;
use crate::constants::READ_BUF_SIZE;

/// Generic block-based encryption function for V7 format
/// Reads from `reader`, encrypts blocks, updates HMAC, and writes to `writer`
/// Uses a ring buffer to eliminate unnecessary copies
pub fn encrypt_blocks_v7<R, W, C, M>(
    reader: &mut R,
    writer: &mut W,
    cipher: &mut C,
    mac: &mut M,
    pad_len: u8,
) -> Result<()>
where
    R: Read,
    W: io::Write,
    C: BlockEncryptMut + BlockSizeUser,
    M: Mac,
{
    let block_size = C::BlockSize::USIZE;
    let mut ring = RingBuffer::new(READ_BUF_SIZE);
    let mut eof = false;

    loop {
        // Fill ring buffer from reader
        if !eof {
            let n = ring.fill_from(reader)?;
            if n == 0 {
                eof = true;
            }
        }

        // Process complete blocks
        while ring.available() >= block_size {
            let mut block = Block::<C>::default();
            ring.read_exact(block.as_mut())?;

            cipher.encrypt_block_mut(&mut block);
            mac.update(&block);
            writer.write_all(&block)?;
        }

        // If EOF and we have remaining data, handle final padded block
        if eof {
            let remaining = ring.available();
            if remaining > 0 {
                // Read remaining data
                let mut block = Block::<C>::default();
                if remaining + usize::from(pad_len) != block_size {
                    anyhow::bail!("Unexpected stream size");
                }
                ring.read_exact(&mut block.as_mut()[0..remaining])?;

                // Encrypt final block
                cipher.encrypt_block_mut(&mut block);
                mac.update(&block);
                writer.write_all(&block)?;
            }
            break;
        }

        // If EOF and no data left, we're done
        if eof && ring.available() == 0 {
            break;
        }
    }

    Ok(())
}
/// Generic block-based decryption function for V7 format
/// Reads from `reader`, decrypts blocks, and writes to `writer`
/// Handles padding removal on the last block
/// Uses a ring buffer to eliminate unnecessary copies
pub fn decrypt_blocks_v7<R, W, C>(
    reader: &mut R,
    writer: &mut W,
    cipher: &mut C,
    pad_len: u8,
) -> Result<()>
where
    R: Read,
    W: io::Write,
    C: BlockDecryptMut + BlockSizeUser,
{
    let block_size = C::BlockSize::USIZE;
    let mut ring = RingBuffer::new(READ_BUF_SIZE);
    let mut eof = false;

    loop {
        // Fill ring buffer from reader
        if !eof {
            let n = ring.fill_from(reader)?;
            if n == 0 {
                eof = true;
            }
        }

        // Check if we have data
        if ring.available() == 0 && eof {
            break;
        }

        if ring.available() < block_size {
            if eof {
                bail!("Incorrect file size");
            }
            continue; // Keep reading
        }

        // Check if this is the last block
        let is_last_block = eof && ring.available() == block_size;

        // Read and decrypt block directly
        let mut block = Block::<C>::default();
        ring.read_exact(block.as_mut())?;
        cipher.decrypt_block_mut(&mut block);

        // Write block (remove padding from last block)
        if is_last_block {
            let last_block_len = block_size - pad_len as usize;
            writer.write_all(&block[..last_block_len])?;
        } else {
            writer.write_all(&block)?;
        }

        block.zeroize();
    }

    Ok(())
}
