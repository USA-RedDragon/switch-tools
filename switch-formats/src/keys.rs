//! The console key file (`prod.keys`): `name = hex` lines.
//!
//! Values are held privately and never formatted: [`Keys`] implements
//! `Debug` by listing names only, and every error names the key it wanted.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use crate::bytes::unhex_vec;
use crate::error::{Error, Result};
use crate::eticket::EticketKey;

/// Which key-area key family an NCA's key area is wrapped with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAreaKind {
    /// `key_area_key_application_XX`.
    Application,
    /// `key_area_key_ocean_XX`.
    Ocean,
    /// `key_area_key_system_XX`.
    System,
}

impl KeyAreaKind {
    /// The kind for the NCA header's key-area index.
    ///
    /// # Errors
    ///
    /// An index above 2.
    pub fn from_index(i: u8) -> Result<KeyAreaKind> {
        match i {
            0 => Ok(KeyAreaKind::Application),
            1 => Ok(KeyAreaKind::Ocean),
            2 => Ok(KeyAreaKind::System),
            _ => Err(Error::Format(format!(
                "key area key index {i} is not 0, 1 or 2"
            ))),
        }
    }

    fn name(self) -> &'static str {
        match self {
            KeyAreaKind::Application => "application",
            KeyAreaKind::Ocean => "ocean",
            KeyAreaKind::System => "system",
        }
    }
}

/// A parsed key file, plus the console's eTicket RSA key when one was
/// given (as `eticket_rsa_keypair` in the file or with
/// [`Keys::set_eticket_key`]).
#[derive(Clone, Default)]
pub struct Keys {
    map: BTreeMap<String, Vec<u8>>,
    eticket: Option<EticketKey>,
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keys")
            .field("names", &self.map.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Keys {
    /// Parse key file text. Blank lines and lines starting with `;` or `#`
    /// are skipped.
    ///
    /// # Errors
    ///
    /// A line that is not `name = hex`; the error names the line, not its
    /// value.
    pub fn parse(text: &str) -> Result<Keys> {
        let mut map = BTreeMap::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            let Some((name, value)) = line.split_once('=') else {
                return Err(Error::Format(format!("key file line {}: no '='", n + 1)));
            };
            let name = name.trim().to_ascii_lowercase();
            let Some(bytes) = unhex_vec(value) else {
                return Err(Error::Format(format!(
                    "key file line {} ({name}): value is not hex",
                    n + 1
                )));
            };
            map.insert(name, bytes);
        }
        let eticket = match map.get("eticket_rsa_keypair") {
            Some(pair) => Some(
                EticketKey::from_keypair(pair)
                    .map_err(|e| crate::title::prefix("key file eticket_rsa_keypair", e))?,
            ),
            None => None,
        };
        Ok(Keys { map, eticket })
    }

    /// Read and parse a key file.
    ///
    /// # Errors
    ///
    /// The file cannot be read or does not parse.
    pub fn load(path: &Path) -> Result<Keys> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            Error::Io(std::io::Error::new(
                e.kind(),
                format!("key file {}: {e}", path.display()),
            ))
        })?;
        Keys::parse(&text)
    }

    /// Set a key (for synthetic fixtures and tools).
    pub fn insert(&mut self, name: &str, value: &[u8]) {
        self.map.insert(name.to_ascii_lowercase(), value.to_vec());
    }

    /// Whether the file holds `name`.
    pub fn has(&self, name: &str) -> bool {
        self.map.contains_key(name)
    }

    /// Set the console's eTicket RSA key, which unwraps personalized
    /// tickets.
    pub fn set_eticket_key(&mut self, key: EticketKey) {
        self.eticket = Some(key);
    }

    /// The console's eTicket RSA key, if one was given.
    pub fn eticket_key(&self) -> Option<&EticketKey> {
        self.eticket.as_ref()
    }

    /// `name` if the file holds it.
    ///
    /// # Errors
    ///
    /// Present with the wrong length.
    pub(crate) fn get_raw<const N: usize>(&self, name: &str) -> Result<Option<[u8; N]>> {
        if self.map.contains_key(name) {
            return self.get(name).map(Some);
        }
        Ok(None)
    }

    fn get<const N: usize>(&self, name: &str) -> Result<[u8; N]> {
        let v = self
            .map
            .get(name)
            .ok_or_else(|| Error::MissingKey(format!("{name} is not in the key file")))?;
        let mut out = [0u8; N];
        if v.len() != N {
            return Err(Error::Format(format!(
                "key {name} is {} bytes, want {N}",
                v.len()
            )));
        }
        out.copy_from_slice(v);
        Ok(out)
    }

    /// `header_key`, the AES-XTS key pair of NCA headers.
    ///
    /// # Errors
    ///
    /// Missing or the wrong length.
    pub fn header_key(&self) -> Result<[u8; 32]> {
        self.get("header_key")
    }

    /// `key_area_key_<kind>_<rev>`.
    ///
    /// # Errors
    ///
    /// Missing or the wrong length.
    pub fn key_area_key(&self, kind: KeyAreaKind, revision: u8) -> Result<[u8; 16]> {
        self.get(&format!("key_area_key_{}_{revision:02x}", kind.name()))
    }

    /// `titlekek_<rev>`.
    ///
    /// # Errors
    ///
    /// Missing or the wrong length.
    pub fn titlekek(&self, revision: u8) -> Result<[u8; 16]> {
        self.get(&format!("titlekek_{revision:02x}"))
    }
}

/// Encrypted title keys by rights ID, from tickets or a title key file.
#[derive(Clone, Default)]
pub struct TitleKeys {
    map: BTreeMap<[u8; 16], [u8; 16]>,
}

impl fmt::Debug for TitleKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TitleKeys")
            .field("rights_ids", &self.map.len())
            .finish()
    }
}

impl TitleKeys {
    /// Parse a title key file: `RIGHTSID = KEY` lines, both 32 hex digits
    /// (the `title.keys` format). Blank lines and lines starting with `;`
    /// or `#` are skipped.
    ///
    /// # Errors
    ///
    /// A line that is not `RIGHTSID = KEY` in hex; the error names the line,
    /// never its key.
    pub fn parse(text: &str) -> Result<TitleKeys> {
        let mut out = TitleKeys::default();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            let bad = || {
                Error::Format(format!(
                    "title key file line {}: want RIGHTSID = KEY, 32 hex digits each",
                    n + 1
                ))
            };
            let (r, k) = line.split_once('=').ok_or_else(bad)?;
            let rights = crate::bytes::unhex::<16>(r.trim()).ok_or_else(bad)?;
            let key = crate::bytes::unhex::<16>(k.trim()).ok_or_else(bad)?;
            out.insert(rights, key);
        }
        Ok(out)
    }

    /// Read and parse a title key file.
    ///
    /// # Errors
    ///
    /// The file cannot be read or does not parse.
    pub fn load(path: &Path) -> Result<TitleKeys> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            Error::Io(std::io::Error::new(
                e.kind(),
                format!("title key file {}: {e}", path.display()),
            ))
        })?;
        TitleKeys::parse(&text)
    }

    /// Add every key of `other`, replacing keys of the same rights ID.
    pub fn extend(&mut self, other: &TitleKeys) {
        self.map.extend(other.map.iter().map(|(r, k)| (*r, *k)));
    }

    /// Add the encrypted title key of `rights_id`.
    pub fn insert(&mut self, rights_id: [u8; 16], encrypted_key: [u8; 16]) {
        self.map.insert(rights_id, encrypted_key);
    }

    /// The encrypted title key of `rights_id`, if known.
    pub fn get(&self, rights_id: &[u8; 16]) -> Option<[u8; 16]> {
        self.map.get(rights_id).copied()
    }

    /// How many rights IDs are known.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether no title keys are known.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}
