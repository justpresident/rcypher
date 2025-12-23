use std::io::{Read, Seek};
use std::mem::size_of;
use std::path::Path;
use std::{fs, io};

use anyhow::{Result, bail};
use cbc::cipher::KeyIvInit;
use hmac::Mac;
use rand::TryRngCore;

use super::LimitedReader;
use super::cipher::Cypher;
use crate::constants::{Aes256CbcDec, Aes256CbcEnc, BlockBytes, HMAC_SIZE, HmacBytes};
use crate::crypto::cipher::calculate_padding;
use crate::crypto::stream_ops::{decrypt_blocks_v7, encrypt_blocks_v7};
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

        let pad_len = calculate_padding(usize::try_from(file_len)?);

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

        // Use generic encryption function
        encrypt_blocks_v7(&mut file, out, &mut cipher, &mut mac, header.pad_len)?;
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

                // Create a limited reader that only reads encrypted data (excluding HMAC)
                let current_pos = file.stream_position()?;
                let remaining_bytes = data_end - current_pos;
                let mut limited_reader = LimitedReader::new(file, remaining_bytes);

                // Use generic decryption function
                decrypt_blocks_v7(
                    &mut limited_reader,
                    out,
                    &mut cipher,
                    header.pad_len,
                    remaining_bytes,
                )?;
            }
            _ => bail!("Unsupported file encryption format: {version}"),
        }
        Ok(())
    }
}
