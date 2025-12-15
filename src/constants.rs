use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use hmac::Hmac;
use sha2::Sha256;

pub const READ_BUF_SIZE: usize = 4096;
pub const BLOCK_SIZE: usize = 16;
pub const SALT_SIZE: usize = 32;
pub const HMAC_SIZE: usize = 32;
pub const KEY_LEN: usize = 32;

pub type HmacSha256 = Hmac<Sha256>;
pub type Aes256CbcEnc = Encryptor<Aes256>;
pub type Aes256CbcDec = Decryptor<Aes256>;

pub type KeyBytes = [u8; KEY_LEN];
pub type SaltBytes = [u8; SALT_SIZE];
pub type BlockBytes = [u8; BLOCK_SIZE];
pub type HmacBytes = [u8; HMAC_SIZE];
