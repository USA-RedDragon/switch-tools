//! Tickets (`.tik`): the rights ID and the title key of a title.

use crate::bytes::{array, u8_at, u32_at};
use crate::error::{Error, Result, malformed};
use crate::eticket::BLOCK_SIZE;
use crate::keys::Keys;

/// How a ticket wraps its title key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TitleKeyType {
    /// The key is AES-encrypted with the titlekek; usable here.
    Common,
    /// The key is RSA-wrapped for one console's eTicket key, then like a
    /// common key.
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
    key_block: [u8; BLOCK_SIZE],
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
    /// The ticket is personalized ([`Error::MissingKey`], as
    /// [`Ticket::title_key`] without an eTicket key).
    pub fn common_title_key(&self) -> Result<[u8; 16]> {
        self.title_key(&Keys::default())
    }

    /// The encrypted (titlekek-wrapped) title key: a common ticket's as
    /// stored, a personalized ticket's unwrapped with the console's eTicket
    /// RSA key from `keys`.
    ///
    /// # Errors
    ///
    /// A personalized ticket without an eTicket key in `keys`
    /// ([`Error::MissingKey`] naming the settings that give one), or with
    /// another console's key ([`Error::WrongKey`]).
    pub fn title_key(&self, keys: &Keys) -> Result<[u8; 16]> {
        let rights = crate::bytes::hex(&self.rights_id);
        match self.key_type {
            TitleKeyType::Common => {
                let mut k = [0u8; 16];
                k.copy_from_slice(&self.key_block[..16]);
                Ok(k)
            }
            TitleKeyType::Personalized => match keys.eticket_key() {
                None => Err(Error::MissingKey(format!(
                    "the ticket for rights ID {rights} is personalized (console-bound) and needs \
                     your console's eTicket RSA key: set prodinfo (your decrypted PRODINFO, with \
                     eticket_rsa_kek in the key file) or eticket-rsa-keypair"
                ))),
                Some(k) => k
                    .unwrap_title_key(&self.key_block)
                    .map_err(|e| crate::title::prefix(&format!("rights ID {rights}"), e)),
            },
        }
    }
}

/// Build a common ticket (RSA-2048 signature type, zero signature) for
/// fixtures.
pub fn build_common(rights_id: [u8; 16], encrypted_key: [u8; 16], revision: u8) -> Vec<u8> {
    build(rights_id, encrypted_key, revision, 0)
}

/// Build a personalized ticket whose title key block is `block` (an
/// RSA-OAEP ciphertext), for fixtures.
pub fn build_personalized(rights_id: [u8; 16], block: &[u8; BLOCK_SIZE], revision: u8) -> Vec<u8> {
    build_block(rights_id, block, revision, 1)
}

/// Build a ticket with an explicit title key type byte, for fixtures.
pub fn build(rights_id: [u8; 16], key: [u8; 16], revision: u8, key_type: u8) -> Vec<u8> {
    let mut block = [0u8; BLOCK_SIZE];
    block[..16].copy_from_slice(&key);
    build_block(rights_id, &block, revision, key_type)
}

fn build_block(
    rights_id: [u8; 16],
    block: &[u8; BLOCK_SIZE],
    revision: u8,
    key_type: u8,
) -> Vec<u8> {
    let data = 4 + 0x100 + 0x3c;
    let mut t = vec![0u8; data + 0x180];
    t[..4].copy_from_slice(&0x10004u32.to_le_bytes());
    t[data..data + 6].copy_from_slice(b"Root-C");
    t[data + 0x40..data + 0x40 + BLOCK_SIZE].copy_from_slice(block);
    t[data + 0x140] = 2;
    t[data + 0x141] = key_type;
    t[data + 0x145] = revision;
    t[data + 0x160..data + 0x170].copy_from_slice(&rights_id);
    t
}
