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

        // If EOF and we have remaining data or need to write padding, handle final padded block
        if eof {
            let remaining = ring.available();

            // We need to write a final block if:
            // 1. We have remaining data that doesn't fill a complete block
            // 2. OR we need to add a full padding block (when pad_len == block_size)
            if remaining > 0 || usize::from(pad_len) == block_size {
                // Read remaining data (if any)
                let mut block = Block::<C>::default();
                if remaining > 0 {
                    if remaining + usize::from(pad_len) != block_size {
                        anyhow::bail!("Unexpected stream size");
                    }
                    ring.read_exact(&mut block.as_mut()[0..remaining])?;
                }

                // Fill padding bytes with pad_len value (PKCS7-style)
                for i in remaining..block_size {
                    block.as_mut()[i] = pad_len;
                }

                // Encrypt final block
                cipher.encrypt_block_mut(&mut block);
                mac.update(&block);
                writer.write_all(&block)?;
            }
            break;
        }
    }

    Ok(())
}
/// Generic block-based decryption function for V7 format
/// Reads from `reader`, decrypts blocks, and writes to `writer`
/// Handles padding removal on the last block
///
/// The `input_len` parameter is necessary because reader may provide
/// all data at once. Without tracking total bytes read, we can't identify the last
/// block until after we've already processed it (when the next read returns 0).
pub fn decrypt_blocks_v7<R, W, C>(
    reader: &mut R,
    writer: &mut W,
    cipher: &mut C,
    pad_len: u8,
    input_len: u64,
) -> Result<()>
where
    R: Read,
    W: io::Write,
    C: BlockDecryptMut + BlockSizeUser,
{
    let block_size = C::BlockSize::USIZE;
    let mut ring = RingBuffer::new(READ_BUF_SIZE);
    let mut eof = false;
    let mut total_read: u64 = 0;

    loop {
        // Fill ring buffer from reader
        if !eof {
            let n = ring.fill_from(reader)?;
            total_read += n as u64;
            if n == 0 || total_read >= input_len {
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

        let is_last_block = eof && ring.available() == block_size;

        // Read and decrypt block directly
        let mut block = Block::<C>::default();
        ring.read_exact(block.as_mut())?;
        cipher.decrypt_block_mut(&mut block);

        // Write decrypted data to output writer
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
