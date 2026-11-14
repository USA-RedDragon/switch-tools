//! HFS0, the hashed flat archive inside XCI game cards: a PFS0 look-alike
//! whose entries carry the SHA-256 of the first bytes of their data.
//!
//! Layout: `HFS0`, entry count `u32`, string table size `u32`, a reserved
//! `u32`, then `count` entries of 0x40 bytes (data offset `u64` relative to
//! the end of the header, size `u64`, name offset `u32`, hashed region size
//! `u32`, reserved `u64`, SHA-256 of the first hashed-region-size bytes of
//! the data), then the string table. The header is 0x200-aligned in cards;
//! this reader does not require it.

use crate::bytes::{array, slice, u32_at, u64_at};
use crate::crypto::sha256;
use crate::error::{Error, Result, malformed};
use crate::storage::{Shared, SubStorage, read_vec};

/// The size of one entry in the table.
pub const ENTRY_SIZE: u64 = 0x40;

/// The size of the fixed header before the entry table.
pub const HEADER_SIZE: u64 = 0x10;

/// One file in an HFS0, every field as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hfs0Entry {
    /// The file name.
    pub name: String,
    /// The offset of the data in the archive storage (header size plus
    /// [`Hfs0Entry::rel_offset`]).
    pub offset: u64,
    /// The data offset as stored: relative to the end of the header.
    pub rel_offset: u64,
    /// The size in bytes.
    pub size: u64,
    /// The offset of the name in the string table.
    pub name_offset: u32,
    /// How many leading bytes of the data the hash covers.
    pub hashed_region_size: u32,
    /// The reserved field after the hashed region size.
    pub reserved: u64,
    /// SHA-256 of the first `hashed_region_size` bytes of the data.
    pub hash: [u8; 32],
}

/// An opened HFS0.
#[derive(Clone)]
pub struct Hfs0 {
    storage: Shared,
    header_size: u64,
    reserved: u32,
    string_table: Vec<u8>,
    entries: Vec<Hfs0Entry>,
}

impl Hfs0 {
    /// Parse the header of an HFS0 in `storage` and verify every entry's
    /// hash.
    ///
    /// # Errors
    ///
    /// Not an HFS0, an entry runs past the end, or [`Error::Hash`] naming
    /// the entry whose hashed region does not match.
    pub fn open(storage: Shared) -> Result<Hfs0> {
        let h = Hfs0::open_unverified(storage)?;
        h.verify()?;
        Ok(h)
    }

    /// Parse the header without checking entry hashes.
    ///
    /// # Errors
    ///
    /// Not an HFS0, or an entry runs past the end.
    pub fn open_unverified(storage: Shared) -> Result<Hfs0> {
        if storage.size() < HEADER_SIZE {
            return malformed("HFS0: shorter than its header");
        }
        let head = read_vec(&*storage, 0, HEADER_SIZE)?;
        if &head[..4] != b"HFS0" {
            return malformed("HFS0: bad magic");
        }
        let count = u64::from(u32_at(&head, 4, "HFS0")?);
        let strings = u64::from(u32_at(&head, 8, "HFS0")?);
        let reserved = u32_at(&head, 12, "HFS0")?;
        let table = count * ENTRY_SIZE;
        let header_size = HEADER_SIZE + table + strings;
        if header_size > storage.size() {
            return malformed("HFS0: header runs past the end");
        }
        let meta = read_vec(&*storage, HEADER_SIZE, table + strings)?;
        let table_len = usize::try_from(table).unwrap_or(usize::MAX);
        let string_table = meta[table_len..].to_vec();
        let mut entries = Vec::new();
        for i in 0..usize::try_from(count).unwrap_or(0) {
            let at = i * ENTRY_SIZE as usize;
            let rel_offset = u64_at(&meta, at, "HFS0 entry")?;
            let size = u64_at(&meta, at + 8, "HFS0 entry")?;
            let name_offset = u32_at(&meta, at + 0x10, "HFS0 entry")?;
            let hashed_region_size = u32_at(&meta, at + 0x14, "HFS0 entry")?;
            let reserved = u64_at(&meta, at + 0x18, "HFS0 entry")?;
            let hash = array::<32>(&meta, at + 0x20, "HFS0 entry")?;
            let name_at = name_offset as usize;
            let rest = slice(
                &string_table,
                name_at,
                string_table.len().saturating_sub(name_at),
                "HFS0 name",
            )?;
            let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            let name = String::from_utf8(rest[..end].to_vec())
                .or_else(|_| malformed(format!("HFS0 entry {i}: name is not UTF-8")))?;
            let offset = header_size
                .checked_add(rel_offset)
                .filter(|s| s.checked_add(size).is_some_and(|e| e <= storage.size()));
            let Some(offset) = offset else {
                return malformed(format!("HFS0 entry {name}: data runs past the end"));
            };
            if u64::from(hashed_region_size) > size {
                return malformed(format!(
                    "HFS0 entry {name}: hashed region is larger than the file"
                ));
            }
            entries.push(Hfs0Entry {
                name,
                offset,
                rel_offset,
                size,
                name_offset,
                hashed_region_size,
                reserved,
                hash,
            });
        }
        Ok(Hfs0 {
            storage,
            header_size,
            reserved,
            string_table,
            entries,
        })
    }

    /// Check every entry's hashed region against its stored hash.
    ///
    /// # Errors
    ///
    /// [`Error::Hash`] naming the first entry that does not match.
    pub fn verify(&self) -> Result<()> {
        for e in &self.entries {
            let data = read_vec(&*self.storage, e.offset, u64::from(e.hashed_region_size))?;
            if sha256(&data) != e.hash {
                return Err(Error::Hash(format!(
                    "HFS0 entry {}: hashed region does not match its hash",
                    e.name
                )));
            }
        }
        Ok(())
    }

    /// The size of the header (fixed part, entry table and string table).
    pub fn header_size(&self) -> u64 {
        self.header_size
    }

    /// The header's reserved word.
    pub fn reserved(&self) -> u32 {
        self.reserved
    }

    /// The string table as stored, padding included.
    pub fn string_table(&self) -> &[u8] {
        &self.string_table
    }

    /// The header bytes (what an XCI card header hashes for the root).
    ///
    /// # Errors
    ///
    /// The read fails.
    pub fn header_bytes(&self) -> Result<Vec<u8>> {
        read_vec(&*self.storage, 0, self.header_size)
    }

    /// The files, in archive order.
    pub fn entries(&self) -> &[Hfs0Entry] {
        &self.entries
    }

    /// The file named `name`.
    pub fn find(&self, name: &str) -> Option<&Hfs0Entry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// A storage over one file's data.
    ///
    /// # Errors
    ///
    /// Not reachable for entries of this archive.
    pub fn open_entry(&self, entry: &Hfs0Entry) -> Result<Shared> {
        SubStorage::shared(self.storage.clone(), entry.offset, entry.size)
    }

    /// One file's data in memory.
    ///
    /// # Errors
    ///
    /// The read fails.
    pub fn read(&self, entry: &Hfs0Entry) -> Result<Vec<u8>> {
        read_vec(&*self.storage, entry.offset, entry.size)
    }
}

/// The header size of an HFS0 whose first bytes are `head`, if they hold the
/// fixed header (for a builder laying out a parent).
pub fn header_len(head: &[u8]) -> Option<u64> {
    if head.get(..4)? != b"HFS0" {
        return None;
    }
    let count = u64::from(u32::from_le_bytes(head.get(4..8)?.try_into().ok()?));
    let strings = u64::from(u32::from_le_bytes(head.get(8..12)?.try_into().ok()?));
    Some(HEADER_SIZE + count * ENTRY_SIZE + strings)
}

/// Build an HFS0 holding `files`, each hashed over its first
/// `min(size, 0x200)` bytes, the header padded to 0x200 (for fixtures).
pub fn build(files: &[(&str, &[u8])]) -> Vec<u8> {
    let sized: Vec<(&str, &[u8], u32)> = files
        .iter()
        .map(|(n, d)| (*n, *d, u32::try_from(d.len().min(0x200)).unwrap_or(0x200)))
        .collect();
    build_hashed(&sized)
}

/// Build an HFS0 whose entries hash the given number of leading bytes
/// (for fixtures; a root partition table hashes each child's header).
pub fn build_hashed(files: &[(&str, &[u8], u32)]) -> Vec<u8> {
    let mut strings = Vec::new();
    let mut table = Vec::new();
    let mut offset = 0u64;
    for (name, data, hashed) in files {
        let n = usize::try_from(*hashed).unwrap_or(0).min(data.len());
        table.extend_from_slice(&offset.to_le_bytes());
        table.extend_from_slice(&(data.len() as u64).to_le_bytes());
        table.extend_from_slice(&u32::try_from(strings.len()).unwrap_or(0).to_le_bytes());
        table.extend_from_slice(&hashed.to_le_bytes());
        table.extend_from_slice(&0u64.to_le_bytes());
        table.extend_from_slice(&sha256(&data[..n]));
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        offset += data.len() as u64;
    }
    while !(HEADER_SIZE as usize + table.len() + strings.len()).is_multiple_of(0x200) {
        strings.push(0);
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"HFS0");
    out.extend_from_slice(&u32::try_from(files.len()).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&u32::try_from(strings.len()).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&table);
    out.extend_from_slice(&strings);
    for (_, data, _) in files {
        out.extend_from_slice(data);
    }
    out
}
