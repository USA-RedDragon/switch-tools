//! PFS0, the flat archive of NSPs and NCA exefs sections.

use crate::bytes::{slice, u32_at, u64_at};
use crate::error::{Result, malformed};
use crate::storage::{Shared, SubStorage, read_vec};

/// One file in a PFS0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pfs0Entry {
    /// The file name.
    pub name: String,
    /// The offset of the data in the archive storage.
    pub offset: u64,
    /// The size in bytes.
    pub size: u64,
}

/// An opened PFS0.
pub struct Pfs0 {
    storage: Shared,
    entries: Vec<Pfs0Entry>,
}

impl Pfs0 {
    /// Parse the header of a PFS0 in `storage`.
    ///
    /// # Errors
    ///
    /// Not a PFS0, or an entry runs past the end.
    pub fn open(storage: Shared) -> Result<Pfs0> {
        if storage.size() < 0x10 {
            return malformed("PFS0: shorter than its header");
        }
        let head = read_vec(&*storage, 0, 0x10)?;
        if &head[..4] != b"PFS0" {
            return malformed("PFS0: bad magic (not a PFS0/NSP)");
        }
        let count = u64::from(u32_at(&head, 4, "PFS0")?);
        let strings = u64::from(u32_at(&head, 8, "PFS0")?);
        let table = count * 0x18;
        let header_size = 0x10 + table + strings;
        if header_size > storage.size() {
            return malformed("PFS0: header runs past the end");
        }
        let meta = read_vec(&*storage, 0x10, table + strings)?;
        let table_len = usize::try_from(table).unwrap_or(usize::MAX);
        let names = &meta[table_len..];
        let mut entries = Vec::new();
        for i in 0..usize::try_from(count).unwrap_or(0) {
            let at = i * 0x18;
            let offset = u64_at(&meta, at, "PFS0 entry")?;
            let size = u64_at(&meta, at + 8, "PFS0 entry")?;
            let name_at = u32_at(&meta, at + 0x10, "PFS0 entry")? as usize;
            let rest = slice(
                names,
                name_at,
                names.len().saturating_sub(name_at),
                "PFS0 name",
            )?;
            let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            let name = String::from_utf8(rest[..end].to_vec())
                .or_else(|_| malformed(format!("PFS0 entry {i}: name is not UTF-8")))?;
            let abs = header_size
                .checked_add(offset)
                .filter(|s| s.checked_add(size).is_some_and(|e| e <= storage.size()));
            let Some(abs) = abs else {
                return malformed(format!("PFS0 entry {name}: data runs past the end"));
            };
            entries.push(Pfs0Entry {
                name,
                offset: abs,
                size,
            });
        }
        Ok(Pfs0 { storage, entries })
    }

    /// The files, in archive order.
    pub fn entries(&self) -> &[Pfs0Entry] {
        &self.entries
    }

    /// The file named `name`.
    pub fn find(&self, name: &str) -> Option<&Pfs0Entry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// A storage over one file's data.
    ///
    /// # Errors
    ///
    /// Not reachable for entries of this archive.
    pub fn open_entry(&self, entry: &Pfs0Entry) -> Result<Shared> {
        SubStorage::shared(self.storage.clone(), entry.offset, entry.size)
    }

    /// One file's data in memory.
    ///
    /// # Errors
    ///
    /// The read fails.
    pub fn read(&self, entry: &Pfs0Entry) -> Result<Vec<u8>> {
        read_vec(&*self.storage, entry.offset, entry.size)
    }
}

/// Build a PFS0 holding `files` (for fixtures and repacking).
pub fn build(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut strings = Vec::new();
    let mut table = Vec::new();
    let mut offset = 0u64;
    for (name, data) in files {
        table.extend_from_slice(&offset.to_le_bytes());
        table.extend_from_slice(&(data.len() as u64).to_le_bytes());
        table.extend_from_slice(&u32::try_from(strings.len()).unwrap_or(0).to_le_bytes());
        table.extend_from_slice(&0u32.to_le_bytes());
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        offset += data.len() as u64;
    }
    while (0x10 + table.len() + strings.len()) % 0x20 != 0 {
        strings.push(0);
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"PFS0");
    out.extend_from_slice(&u32::try_from(files.len()).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&u32::try_from(strings.len()).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&table);
    out.extend_from_slice(&strings);
    for (_, data) in files {
        out.extend_from_slice(data);
    }
    out
}
