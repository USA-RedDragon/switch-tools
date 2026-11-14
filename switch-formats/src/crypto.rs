//! The AES modes Switch containers use, over RustCrypto.

use aes::Aes128;
use aes::cipher::{
    Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit, KeyIvInit, StreamCipher,
    StreamCipherSeek,
};
use sha2::{Digest, Sha256};
use xts_mode::Xts128;

/// AES-128-ECB decrypt of one block (key-area keys and title keys).
pub fn ecb_decrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let c = Aes128::new(&Array(*key));
    let mut b = Array(*block);
    c.decrypt_block(&mut b);
    b.0
}

/// AES-128-ECB encrypt of one block (fixtures).
pub fn ecb_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let c = Aes128::new(&Array(*key));
    let mut b = Array(*block);
    c.encrypt_block(&mut b);
    b.0
}

fn xts(key: &[u8; 32]) -> Xts128<Aes128> {
    let mut k1 = [0u8; 16];
    let mut k2 = [0u8; 16];
    k1.copy_from_slice(&key[..16]);
    k2.copy_from_slice(&key[16..]);
    Xts128::new(Aes128::new(&Array(k1)), Aes128::new(&Array(k2)))
}

/// Nintendo's XTS tweak: the sector index, big-endian.
fn tweak(sector: u128) -> Array<u8, aes::cipher::consts::U16> {
    Array(sector.to_be_bytes())
}

/// AES-128-XTS decrypt in place, 0x200-byte sectors from `first_sector`.
pub fn xts_decrypt(key: &[u8; 32], data: &mut [u8], first_sector: u128) {
    xts(key).decrypt_area(data, 0x200, first_sector, tweak);
}

/// AES-128-XTS encrypt in place (fixtures).
pub fn xts_encrypt(key: &[u8; 32], data: &mut [u8], first_sector: u128) {
    xts(key).encrypt_area(data, 0x200, first_sector, tweak);
}

type Ctr = ctr::Ctr128BE<Aes128>;

/// AES-128-CTR over `data`, which sits at absolute byte `offset` of a stream
/// whose counter is `upper` (big-endian high half) and `offset / 16`. The
/// same call encrypts and decrypts.
pub fn ctr_apply(key: &[u8; 16], upper: [u8; 8], offset: u64, data: &mut [u8]) {
    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(&upper);
    iv[8..].copy_from_slice(&(offset / 16).to_be_bytes());
    let mut c = Ctr::new(&Array(*key), &Array(iv));
    c.seek(offset % 16);
    c.apply_keystream(data);
}

/// AES-128-CTR over `data` from a full 128-bit big-endian counter `iv`
/// (PRODINFO key blobs). The same call encrypts and decrypts.
pub fn ctr128_apply(key: &[u8; 16], iv: [u8; 16], data: &mut [u8]) {
    Ctr::new(&Array(*key), &Array(iv)).apply_keystream(data);
}

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
