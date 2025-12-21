use std::io::{Read, Seek};
use std::mem::size_of;
use std::path::Path;
use std::{fs, io};

use aes::Block;
use anyhow::{Result, bail};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::Mac;
use rand::TryRngCore;
use zeroize::Zeroize;

use super::cipher::Cypher;
use crate::constants::{
    Aes256CbcDec, Aes256CbcEnc, BLOCK_SIZE, BlockBytes, HMAC_SIZE, HmacBytes, READ_BUF_SIZE,
};
use crate::security::is_debugger_attached;
use crate::version::{CypherVersion, Version7Header};

impl Cypher {
    pub fn encrypt_file<T: io::Write>(&self, path: &Path, out: &mut T) -> Result<()> {
        if is_debugger_attached() {
            bail!("Debugger detected");
        }

        match self.version() {
            CypherVersion::LegacyWithoutKdf => {
                bail!("Encryption with legacy version is not supported")
            }
            CypherVersion::V7WithKdf => self.encrypt_file_v7(path, out),
        }
    }

    fn encrypt_file_v7<T: io::Write>(&self, path: &Path, out: &mut T) -> Result<()> {
        let mut file = fs::File::open(path)?;
        let file_len = file.metadata()?.len();

        #[allow(clippy::cast_possible_truncation)]
        let pad_len = (BLOCK_SIZE - (file_len as usize % BLOCK_SIZE)) as u8;

        // Generate random IV
        let mut iv = BlockBytes::default();
        rand::rngs::OsRng.try_fill_bytes(&mut iv)?;

        // Prepare header without HMAC
        let header = Version7Header {
            version: (CypherVersion::V7WithKdf as u16).to_be_bytes(),
            salt: *self.key.salt(),
            pad_len,
            _reserved: 0,
            iv,
        };

        let mut mac = self.hmac_start();

        let mut header_bytes = [0u8; size_of::<Version7Header>()];
        bincode::encode_into_slice(&header, &mut header_bytes, bincode::config::standard())?;
        Mac::update(&mut mac, &header_bytes);
        out.write_all(&header_bytes[..])?;

        let mut cipher = Aes256CbcEnc::new(self.key.as_bytes().into(), &header.iv.into());

        let mut buffer = [0u8; READ_BUF_SIZE];

        // All read data goes into this vec
        let mut file_data = Vec::new();
        let mut pos: usize = 0;
        loop {
            while file_data.len() < READ_BUF_SIZE {
                let n = file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                file_data.extend_from_slice(&buffer[0..n]);
                buffer.zeroize();
            }
            if file_data.len() < BLOCK_SIZE {
                break;
            }

            while file_data.len() >= pos + BLOCK_SIZE {
                let mut block = Block::clone_from_slice(&file_data[pos..pos + BLOCK_SIZE]);
                pos += BLOCK_SIZE;

                cipher.encrypt_block_mut(&mut block);
                Mac::update(&mut mac, &block);
                out.write_all(&block)?;
            }
            file_data[0..pos].zeroize();
            file_data = file_data[pos..].to_vec();
            pos = 0;
        }

        if !file_data.is_empty() {
            for _ in 0..header.pad_len {
                file_data.push(header.pad_len);
            }

            // encrypt final padded block
            let mut block = Block::clone_from_slice(&file_data[pos..]);
            cipher.encrypt_block_mut(&mut block);
            Mac::update(&mut mac, &block);
            out.write_all(&block)?;
        }
        let computed_hmac = mac.finalize();
        out.write_all(&computed_hmac.into_bytes())?;

        Ok(())
    }

    pub fn decrypt_file<T: io::Write>(&self, input_path: &Path, out: &mut T) -> Result<()> {
        if is_debugger_attached() {
            bail!("Debugger detected");
        }

        let mut file = fs::File::open(input_path)?;
        let file_size = usize::try_from(file.metadata()?.len())
            .expect("Can't process files larger than 4Gb on a 32-bit platform");

        if file_size < 3 {
            bail!("File is too small");
        }
        let mut version_bytes = [0; 2];
        file.read_exact(&mut version_bytes)?;
        file.seek(std::io::SeekFrom::Start(0))?;

        let version = u16::from_be_bytes([version_bytes[0], version_bytes[1]]);

        match CypherVersion::try_from(version) {
            Ok(CypherVersion::V7WithKdf) => {
                if file_size < size_of::<Version7Header>() + HMAC_SIZE {
                    bail!("File is too small");
                }

                // First thing we do is to verify HMAC to make sure the file is correct and hasn't
                // been tampered. If it doesn't match we immediately exit to minimize exposure of
                // the code to the potential attacker.
                file.seek(std::io::SeekFrom::End(-i64::try_from(HMAC_SIZE)?))?;
                let mut hmac = HmacBytes::default();
                file.read_exact(&mut hmac)?;

                let computed_hmac =
                    self.compute_file_hmac(&mut file, 0, u64::try_from(file_size - HMAC_SIZE)?)?;

                computed_hmac.verify_slice(&hmac)?;

                // Read header
                file.seek(std::io::SeekFrom::Start(0))?;
                let header: Version7Header =
                    bincode::decode_from_std_read(&mut file, bincode::config::standard())?;
                header.validate()?;

                // Proceed with decryption
                let data_end = u64::try_from(file_size - HMAC_SIZE)?;
                let mut cipher = Aes256CbcDec::new(self.key.as_bytes().into(), &header.iv.into());
                let mut buffer = [0u8; READ_BUF_SIZE];

                // All read data goes into this vec
                let mut file_data = Vec::new();
                let mut pos: usize = 0;
                loop {
                    // Read only until data_end, not full file
                    while file_data.len() < READ_BUF_SIZE {
                        let current = file.stream_position()?;
                        if current >= data_end {
                            break;
                        }

                        let remaining = usize::try_from(data_end - current)?;
                        let to_read = remaining.min(READ_BUF_SIZE);

                        let n = file.read(&mut buffer[..to_read])?;
                        if n == 0 {
                            break;
                        }

                        file_data.extend_from_slice(&buffer[..n]);
                    }

                    if file_data.is_empty() {
                        break;
                    } else if file_data.len() < BLOCK_SIZE {
                        bail!("Incorrect file size");
                    }

                    let file_end = file.stream_position()? >= data_end;

                    while file_data.len() >= pos + BLOCK_SIZE {
                        let mut block = Block::clone_from_slice(&file_data[pos..pos + BLOCK_SIZE]);
                        pos += BLOCK_SIZE;

                        cipher.decrypt_block_mut(&mut block);

                        if file_end && file_data.len() == pos {
                            let last_block_len = BLOCK_SIZE - header.pad_len as usize;
                            out.write_all(&block[..last_block_len])?;
                        } else {
                            out.write_all(&block)?;
                        }
                        block.zeroize();
                    }

                    file_data = file_data[pos..].to_vec();
                    pos = 0;
                }
            }
            _ => bail!("Unsupported file encryption format: {version}"),
        }
        Ok(())
    }
}
