//! The console's eTicket RSA-2048 key, which unwraps the title key of a
//! personalized (console-bound) ticket.
//!
//! A personalized ticket's title key block is RSA-2048-OAEP (SHA-256 for
//! both the label hash and MGF1, empty label) encrypted to one console's
//! eTicket key; the plaintext is the 16-byte title key, still wrapped with
//! the titlekek like a common ticket's (LibHac `Ticket.GetTitleKey`, MIT).
//!
//! The key pair comes from one of:
//!
//! - a raw key pair, [`KEYPAIR_SIZE`] bytes: the private exponent (0x100),
//!   the modulus (0x100), the public exponent (4, big-endian) and 0xC
//!   reserved bytes (LibHac's `RsaKeyPair`, and the `eticket_rsa_keypair`
//!   entry of a key file);
//! - the decrypted PRODINFO (`CAL0`) of the console: its
//!   `ExtendedRsa2048ETicketKey` at 0x3890 is a 16-byte AES-128-CTR counter
//!   followed by the encrypted key pair, decrypted with `eticket_rsa_kek`
//!   (or `eticket_rsa_kek_personalized`) of the key file.
//!
//! The private key never leaves this module and is never formatted.

use std::fmt;

use rsa::traits::PublicKeyParts;
use rsa::{BoxedUint, Oaep, PrivateKey};
use sha2::Sha256;

use crate::crypto::{ctr128_apply, sha256};
use crate::error::{Error, Result, malformed};
use crate::keys::Keys;

/// The size of a raw key pair: private exponent, modulus, public exponent
/// and reserved bytes.
pub const KEYPAIR_SIZE: usize = 0x210;

/// The size of the RSA-wrapped title key block of a personalized ticket.
pub const BLOCK_SIZE: usize = 0x100;

/// Where `ExtendedRsa2048ETicketKey` starts in PRODINFO.
pub const PRODINFO_KEY_AT: usize = 0x3890;

/// The size of `ExtendedRsa2048ETicketKey`.
pub const PRODINFO_KEY_SIZE: usize = 0x240;

/// The key file names tried, in order, to decrypt the PRODINFO key pair.
pub const KEK_NAMES: [&str; 2] = ["eticket_rsa_kek", "eticket_rsa_kek_personalized"];

const PUBLIC_EXPONENT: u32 = 0x10001;
const BITS: u32 = 2048;

/// A console's eTicket RSA-2048 key pair.
#[derive(Clone)]
pub struct EticketKey {
    key: PrivateKey,
}

impl fmt::Debug for EticketKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EticketKey").finish_non_exhaustive()
    }
}

fn uint(b: &[u8]) -> Result<BoxedUint> {
    BoxedUint::from_be_slice(b, BITS)
        .or_else(|_| malformed("eTicket RSA key: a component does not fit 2048 bits"))
}

impl EticketKey {
    /// Read a raw key pair ([`KEYPAIR_SIZE`] bytes; the 0xC reserved bytes
    /// may be left off).
    ///
    /// # Errors
    ///
    /// The wrong size, a public exponent other than 65537, or components
    /// that do not form a key pair.
    pub fn from_keypair(b: &[u8]) -> Result<EticketKey> {
        if b.len() != KEYPAIR_SIZE && b.len() != KEYPAIR_SIZE - 0xC {
            return malformed(format!(
                "eTicket RSA key pair: {:#x} bytes, want {KEYPAIR_SIZE:#x}",
                b.len()
            ));
        }
        let (d, rest) = b.split_at(0x100);
        let (n, rest) = rest.split_at(0x100);
        let e = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
        if e != PUBLIC_EXPONENT {
            return Err(Error::WrongKey(format!(
                "eTicket RSA key pair: public exponent {e:#x}, want 0x10001"
            )));
        }
        let key = PrivateKey::from_components(
            uint(n)?,
            BoxedUint::from(u64::from(e)),
            uint(d)?,
            Vec::new(),
        )
        .map_err(|_| Error::WrongKey("eTicket RSA key pair: not a valid RSA key pair".into()))?;
        Ok(EticketKey { key })
    }

    /// Derive the key pair from a console's decrypted PRODINFO with the
    /// key file's `eticket_rsa_kek` (then `eticket_rsa_kek_personalized`).
    ///
    /// # Errors
    ///
    /// Not a decrypted PRODINFO (no `CAL0` magic, too short, or a body hash
    /// mismatch), neither kek in the key file ([`Error::MissingKey`]), or
    /// no kek that decrypts a valid key pair ([`Error::WrongKey`]).
    pub fn from_prodinfo(prodinfo: &[u8], keys: &Keys) -> Result<EticketKey> {
        if prodinfo.len() < 0x40 || &prodinfo[..4] != b"CAL0" {
            return malformed(
                "PRODINFO: no CAL0 magic; give the decrypted PRODINFO partition of your console",
            );
        }
        let body = u32::from_le_bytes([prodinfo[8], prodinfo[9], prodinfo[10], prodinfo[11]]);
        let end = 0x40 + usize::try_from(body).unwrap_or(usize::MAX);
        if prodinfo.len() < PRODINFO_KEY_AT + PRODINFO_KEY_SIZE || prodinfo.len() < end {
            return malformed(format!(
                "PRODINFO: {:#x} bytes is too short for its body or the eTicket key",
                prodinfo.len()
            ));
        }
        if sha256(&prodinfo[0x40..end]) != prodinfo[0x20..0x40] {
            return Err(Error::Hash("PRODINFO: the body hash does not match".into()));
        }
        let blob = &prodinfo[PRODINFO_KEY_AT..PRODINFO_KEY_AT + PRODINFO_KEY_SIZE];
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&blob[..16]);
        let mut tried = Vec::new();
        for name in KEK_NAMES {
            let Some(kek) = keys.get_raw::<16>(name)? else {
                continue;
            };
            tried.push(name);
            let mut pair = blob[16..16 + KEYPAIR_SIZE].to_vec();
            ctr128_apply(&kek, iv, &mut pair);
            if let Ok(k) = EticketKey::from_keypair(&pair) {
                return Ok(k);
            }
        }
        if tried.is_empty() {
            return Err(Error::MissingKey(
                "eticket_rsa_kek is not in the key file (needed to decrypt the eTicket RSA key in PRODINFO)"
                    .into(),
            ));
        }
        Err(Error::WrongKey(format!(
            "{} does not decrypt the eTicket RSA key in PRODINFO (another console's PRODINFO, or a wrong kek)",
            tried.join(" or ")
        )))
    }

    /// Unwrap the title key block of a personalized ticket: the result is
    /// the titlekek-wrapped title key, as a common ticket stores it.
    ///
    /// # Errors
    ///
    /// The block does not decrypt to a 16-byte key: the ticket belongs to
    /// another console ([`Error::WrongKey`]).
    pub fn unwrap_title_key(&self, block: &[u8; BLOCK_SIZE]) -> Result<[u8; 16]> {
        let wrong = || {
            Error::WrongKey(
                "the eTicket RSA key does not unwrap this personalized ticket (it belongs to another console)"
                    .into(),
            )
        };
        let plain = self
            .key
            .decrypt(Oaep::<Sha256>::new(), block)
            .map_err(|_| wrong())?;
        <[u8; 16]>::try_from(plain.as_slice()).map_err(|_| wrong())
    }

    /// The modulus, big-endian (fixtures and diagnostics; public).
    pub fn modulus(&self) -> Vec<u8> {
        self.key.n().to_be_bytes().to_vec()
    }
}
