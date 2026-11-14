//! Section integrity: hierarchical SHA-256 (exefs and other PFS0 sections)
//! and IVFC (romfs). Both hand back a storage over the data level that
//! fails any read whose blocks do not hash to the verified table.

use std::sync::{Arc, Mutex};

use crate::bytes::{u32_at, u64_at};
use crate::crypto::sha256;
use crate::error::{Error, Result, malformed};
use crate::nca::FsHeader;
use crate::storage::{Shared, Storage, SubStorage, check_range, read_vec};

/// How a short final block is hashed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tail {
    /// Only the bytes present (PFS0 sections).
    Exact,
    /// Zero-padded to the block size (romfs).
    Padded,
}

/// A data level whose blocks are checked against a verified hash table on
/// first read.
pub struct VerifiedStorage {
    data: Shared,
    hashes: Vec<u8>,
    block: u64,
    tail: Tail,
    what: String,
    seen: Mutex<Vec<u64>>,
}

impl VerifiedStorage {
    fn new(data: Shared, hashes: Vec<u8>, block: u64, tail: Tail, what: String) -> Result<Self> {
        if block == 0 {
            return malformed(format!("{what}: zero block size"));
        }
        let blocks = data.size().div_ceil(block);
        if (hashes.len() as u64) < blocks * 32 {
            return malformed(format!(
                "{what}: hash table covers fewer than its {blocks} blocks"
            ));
        }
        let words = usize::try_from(blocks.div_ceil(64)).unwrap_or(0);
        Ok(VerifiedStorage {
            data,
            hashes,
            block,
            tail,
            what,
            seen: Mutex::new(vec![0; words]),
        })
    }

    fn check(&self, index: u64, bytes: &[u8]) -> Result<()> {
        let at = usize::try_from(index * 32).unwrap_or(usize::MAX);
        let want = &self.hashes[at..at + 32];
        let got = if self.tail == Tail::Padded && (bytes.len() as u64) < self.block {
            let mut padded = bytes.to_vec();
            padded.resize(usize::try_from(self.block).unwrap_or(0), 0);
            sha256(&padded)
        } else {
            sha256(bytes)
        };
        if got != want {
            return Err(Error::Hash(format!("{} block {index}", self.what)));
        }
        Ok(())
    }

    /// Read and hash every block once.
    ///
    /// # Errors
    ///
    /// A block does not match.
    pub fn verify_all(&self) -> Result<()> {
        let chunk = self.block * (0x10_0000 / self.block).max(1);
        let mut buf = Vec::new();
        let mut off = 0;
        while off < self.size() {
            let n = chunk.min(self.size() - off);
            buf.resize(usize::try_from(n).unwrap_or(0), 0);
            self.read_at(off, &mut buf)?;
            off += n;
        }
        Ok(())
    }
}

impl Storage for VerifiedStorage {
    fn size(&self) -> u64 {
        self.data.size()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.size(), &self.what)?;
        if buf.is_empty() {
            return Ok(());
        }
        let first = offset / self.block;
        let last = (offset + buf.len() as u64 - 1) / self.block;
        let start = first * self.block;
        let end = ((last + 1) * self.block).min(self.size());
        let all_seen = {
            let seen = self
                .seen
                .lock()
                .map_err(|_| Error::Format("verifier lock poisoned".into()))?;
            (first..=last).all(|b| seen[(b / 64) as usize] & (1 << (b % 64)) != 0)
        };
        if all_seen {
            return self.data.read_at(offset, buf);
        }
        let span = read_vec(&*self.data, start, end - start)?;
        let block = usize::try_from(self.block).unwrap_or(usize::MAX);
        for (i, chunk) in span.chunks(block).enumerate() {
            let b = first + i as u64;
            self.check(b, chunk)?;
        }
        {
            let mut seen = self
                .seen
                .lock()
                .map_err(|_| Error::Format("verifier lock poisoned".into()))?;
            for b in first..=last {
                seen[(b / 64) as usize] |= 1 << (b % 64);
            }
        }
        let from = usize::try_from(offset - start).unwrap_or(0);
        buf.copy_from_slice(&span[from..from + buf.len()]);
        Ok(())
    }
}

/// The hierarchical SHA-256 layout of a PFS0 section.
#[derive(Clone, Copy, Debug)]
pub struct Sha256Info {
    /// The hash of the whole hash table.
    pub master: [u8; 32],
    /// The data block size.
    pub block: u64,
    /// The hash table's offset and size in the section.
    pub table: (u64, u64),
    /// The data's offset and size in the section.
    pub data: (u64, u64),
}

impl Sha256Info {
    /// Read it from an FS header.
    ///
    /// # Errors
    ///
    /// A level count other than 2.
    pub fn parse(fs: &FsHeader) -> Result<Sha256Info> {
        let b = fs.integrity_info();
        let mut master = [0u8; 32];
        master.copy_from_slice(&b[..32]);
        if u32_at(b, 0x24, "SHA-256 info")? != 2 {
            return Err(Error::Unsupported(
                "hierarchical SHA-256 with other than 2 levels".into(),
            ));
        }
        Ok(Sha256Info {
            master,
            block: u64::from(u32_at(b, 0x20, "SHA-256 info")?),
            table: (
                u64_at(b, 0x28, "SHA-256 info")?,
                u64_at(b, 0x30, "SHA-256 info")?,
            ),
            data: (
                u64_at(b, 0x38, "SHA-256 info")?,
                u64_at(b, 0x40, "SHA-256 info")?,
            ),
        })
    }

    /// Serialize into the integrity block of an FS header (fixtures).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = vec![0u8; 0xF8];
        b[..32].copy_from_slice(&self.master);
        b[0x20..0x24].copy_from_slice(&u32::try_from(self.block).unwrap_or(0).to_le_bytes());
        b[0x24..0x28].copy_from_slice(&2u32.to_le_bytes());
        b[0x28..0x30].copy_from_slice(&self.table.0.to_le_bytes());
        b[0x30..0x38].copy_from_slice(&self.table.1.to_le_bytes());
        b[0x38..0x40].copy_from_slice(&self.data.0.to_le_bytes());
        b[0x40..0x48].copy_from_slice(&self.data.1.to_le_bytes());
        b
    }
}

/// Verify a PFS0 section's hash table against the master hash and return
/// its data level, checked block by block.
///
/// # Errors
///
/// The master hash does not match (reported as a wrong key: the section
/// decrypted to garbage, or its table is corrupt).
pub fn open_sha256(section: Shared, info: &Sha256Info, what: &str) -> Result<VerifiedStorage> {
    let table = read_vec(&*section, info.table.0, info.table.1)?;
    if sha256(&table) != info.master {
        return Err(Error::WrongKey(format!(
            "{what}: hash table does not match the master hash (wrong key, or corrupt)"
        )));
    }
    let data = SubStorage::shared(section, info.data.0, info.data.1)?;
    VerifiedStorage::new(data, table, info.block, Tail::Exact, what.to_string())
}

/// One IVFC level: offset and size in the section, log2 block size.
#[derive(Clone, Copy, Debug)]
pub struct IvfcLevel {
    /// The level's offset in the section.
    pub offset: u64,
    /// The level's size.
    pub size: u64,
    /// log2 of the block size.
    pub block_log2: u32,
}

/// The IVFC layout of a romfs section.
#[derive(Clone, Debug)]
pub struct IvfcInfo {
    /// The hash of level 0's blocks.
    pub master: Vec<u8>,
    /// The levels, hash levels first, data last.
    pub levels: Vec<IvfcLevel>,
}

impl IvfcInfo {
    /// Read it from an FS header.
    ///
    /// # Errors
    ///
    /// Bad magic or level count.
    pub fn parse(fs: &FsHeader) -> Result<IvfcInfo> {
        let b = fs.integrity_info();
        if &b[..4] != b"IVFC" {
            return malformed("IVFC info: bad magic");
        }
        let master_size = u32_at(b, 8, "IVFC info")? as usize;
        let count = u32_at(b, 12, "IVFC info")? as usize;
        if !(2..=7).contains(&count)
            || !master_size.is_multiple_of(32)
            || master_size == 0
            || master_size > 0x38
        {
            return malformed(format!(
                "IVFC info: {count} levels, master hash {master_size:#x} bytes"
            ));
        }
        let mut levels = Vec::new();
        for i in 0..count - 1 {
            let at = 0x10 + i * 0x18;
            levels.push(IvfcLevel {
                offset: u64_at(b, at, "IVFC level")?,
                size: u64_at(b, at + 8, "IVFC level")?,
                block_log2: u32_at(b, at + 0x10, "IVFC level")?,
            });
        }
        Ok(IvfcInfo {
            master: b[0xC0..0xC0 + master_size].to_vec(),
            levels,
        })
    }

    /// Serialize into the integrity block of an FS header (fixtures).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = vec![0u8; 0xF8];
        b[..4].copy_from_slice(b"IVFC");
        b[4..8].copy_from_slice(&0x20000u32.to_le_bytes());
        b[8..12].copy_from_slice(&u32::try_from(self.master.len()).unwrap_or(0).to_le_bytes());
        b[12..16].copy_from_slice(
            &u32::try_from(self.levels.len() + 1)
                .unwrap_or(0)
                .to_le_bytes(),
        );
        for (i, l) in self.levels.iter().enumerate() {
            let at = 0x10 + i * 0x18;
            b[at..at + 8].copy_from_slice(&l.offset.to_le_bytes());
            b[at + 8..at + 16].copy_from_slice(&l.size.to_le_bytes());
            b[at + 16..at + 20].copy_from_slice(&l.block_log2.to_le_bytes());
        }
        b[0xC0..0xC0 + self.master.len()].copy_from_slice(&self.master);
        b
    }
}

/// Verify an IVFC section's hash levels top-down and return its data level
/// (the romfs), checked block by block.
///
/// # Errors
///
/// Level 0 does not match the master hash (reported as a wrong key), or a
/// deeper hash level does not match.
pub fn open_ivfc(section: Shared, info: &IvfcInfo, what: &str) -> Result<Arc<VerifiedStorage>> {
    let mut hashes = info.master.clone();
    let n = info.levels.len();
    for (i, l) in info.levels.iter().enumerate() {
        if l.block_log2 > 24 || l.block_log2 < 4 {
            return malformed(format!(
                "{what}: IVFC level {i} block size 2^{}",
                l.block_log2
            ));
        }
        let data = SubStorage::shared(section.clone(), l.offset, l.size)?;
        let level = VerifiedStorage::new(
            data,
            hashes,
            1 << l.block_log2,
            Tail::Padded,
            format!("{what} IVFC level {i}"),
        )?;
        if i + 1 == n {
            return Ok(Arc::new(level));
        }
        hashes = match read_all_level(&level) {
            Ok(h) => h,
            Err(Error::Hash(m)) if i == 0 => {
                return Err(Error::WrongKey(format!(
                    "{m}: level 0 does not match the master hash (wrong key, or corrupt)"
                )));
            }
            Err(e) => return Err(e),
        };
    }
    malformed(format!("{what}: IVFC without levels"))
}

fn read_all_level(level: &VerifiedStorage) -> Result<Vec<u8>> {
    read_vec(level, 0, level.size())
}

/// Build hierarchical SHA-256 section bytes for `data` (fixtures): returns
/// the section and its info.
pub fn build_sha256(data: &[u8], block: usize) -> (Vec<u8>, Sha256Info) {
    let mut table = Vec::new();
    for c in data.chunks(block) {
        table.extend_from_slice(&sha256(c));
    }
    let table_size = table.len() as u64;
    let data_off = table_size.div_ceil(0x200) * 0x200;
    let mut section = table.clone();
    section.resize(usize::try_from(data_off).unwrap_or(0), 0);
    section.extend_from_slice(data);
    section.resize(section.len().div_ceil(0x200) * 0x200, 0);
    let info = Sha256Info {
        master: sha256(&table),
        block: block as u64,
        table: (0, table_size),
        data: (data_off, data.len() as u64),
    };
    (section, info)
}

/// Build IVFC section bytes for `data` with `hash_levels` hash levels
/// above it, all with blocks of `1 << block_log2` (fixtures).
pub fn build_ivfc(data: &[u8], hash_levels: usize, block_log2: u32) -> (Vec<u8>, IvfcInfo) {
    let block = 1usize << block_log2;
    let hash = |level: &[u8]| -> Vec<u8> {
        let mut out = Vec::new();
        for c in level.chunks(block) {
            let mut p = c.to_vec();
            p.resize(block, 0);
            out.extend_from_slice(&sha256(&p));
        }
        out
    };
    let mut stack = vec![data.to_vec()];
    for _ in 0..hash_levels {
        let above = hash(stack.last().map_or(&[][..], |v| v));
        stack.push(above);
    }
    stack.reverse();
    let master = hash(&stack[0]);
    let mut section = Vec::new();
    let mut levels = Vec::new();
    for l in &stack {
        let offset = section.len() as u64;
        section.extend_from_slice(l);
        levels.push(IvfcLevel {
            offset,
            size: l.len() as u64,
            block_log2,
        });
        section.resize(section.len().div_ceil(block) * block, 0);
    }
    (section, IvfcInfo { master, levels })
}
