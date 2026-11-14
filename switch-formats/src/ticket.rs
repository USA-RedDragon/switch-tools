//! Tickets (`.tik`): the rights ID and the title key of a title.

use crate::bytes::{array, u8_at, u32_at};
use crate::error::{Error, Result, malformed};

/// How a ticket wraps its title key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TitleKeyType {
    /// The key is AES-encrypted with the titlekek; usable here.
    Common,
    /// The key is RSA-wrapped for one console; out of scope.
    Personalized,
}

/// A parsed ticket. The title key stays private.
#[derive(Clone)]
pub struct Ticket {
    /// The rights ID the key unlocks.
    pub rights_id: [u8; 16],
    /// How the key is wrapped.
    pub key_type: TitleKeyType,
    /// The master key revision the ticket names.
    pub master_key_revision: u8,
    key_block: [u8; 16],
}

impl std::fmt::Debug for Ticket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ticket")
            .field("rights_id", &crate::bytes::hex(&self.rights_id))
            .field("key_type", &self.key_type)
            .field("master_key_revision", &self.master_key_revision)
            .finish_non_exhaustive()
    }
}

/// The size of the signature block for each signature type, with padding.
fn signature_span(kind: u32) -> Result<usize> {
    match kind {
        0x10000 | 0x10003 => Ok(0x200 + 0x3c),
        0x10001 | 0x10004 => Ok(0x100 + 0x3c),
        0x10002 | 0x10005 => Ok(0x3c + 0x40),
        _ => malformed(format!("ticket: unknown signature type {kind:#x}")),
    }
}

impl Ticket {
    /// Parse a ticket file.
    ///
    /// # Errors
    ///
    /// Unknown signature type or a short file.
    pub fn parse(b: &[u8]) -> Result<Ticket> {
        let data = 4 + signature_span(u32_at(b, 0, "ticket")?)?;
        let key_type = match u8_at(b, data + 0x141, "ticket")? {
            0 => TitleKeyType::Common,
            1 => TitleKeyType::Personalized,
            t => return malformed(format!("ticket: unknown title key type {t}")),
        };
        Ok(Ticket {
            rights_id: array(b, data + 0x160, "ticket")?,
            key_type,
            master_key_revision: u8_at(b, data + 0x145, "ticket")?,
            key_block: array(b, data + 0x40, "ticket")?,
        })
    }

    /// The encrypted title key of a common ticket.
    ///
    /// # Errors
    ///
    /// The ticket is personalized.
    pub fn common_title_key(&self) -> Result<[u8; 16]> {
        match self.key_type {
            TitleKeyType::Common => Ok(self.key_block),
            TitleKeyType::Personalized => Err(Error::Unsupported(format!(
                "ticket for rights ID {} is personalized (console-bound); only common tickets are supported",
                crate::bytes::hex(&self.rights_id)
            ))),
        }
    }
}

/// Build a common ticket (RSA-2048 signature type, zero signature) for
/// fixtures.
pub fn build_common(rights_id: [u8; 16], encrypted_key: [u8; 16], revision: u8) -> Vec<u8> {
    build(rights_id, encrypted_key, revision, 0)
}

/// Build a ticket with an explicit title key type byte, for fixtures.
pub fn build(rights_id: [u8; 16], key: [u8; 16], revision: u8, key_type: u8) -> Vec<u8> {
    let data = 4 + 0x100 + 0x3c;
    let mut t = vec![0u8; data + 0x180];
    t[..4].copy_from_slice(&0x10004u32.to_le_bytes());
    t[data..data + 6].copy_from_slice(b"Root-C");
    t[data + 0x40..data + 0x50].copy_from_slice(&key);
    t[data + 0x140] = 2;
    t[data + 0x141] = key_type;
    t[data + 0x145] = revision;
    t[data + 0x160..data + 0x170].copy_from_slice(&rights_id);
    t
}
