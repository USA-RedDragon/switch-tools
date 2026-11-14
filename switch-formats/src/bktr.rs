//! BKTR: the bucket trees of update NCAs. An indirect storage maps each
//! range of the patched section to the base section or the patch data, and
//! an AES-CTR-EX table gives each patch data range its counter generation.
//!
//! Ported from LibHac (`FsSystem/BucketTree.cs`, `FsSystem/IndirectStorage.cs`,
//! `Tools/FsSystem/Aes128CtrExStorage.cs`, `Tools/FsSystem/NcaUtils/Nca.cs`),
//! whose notice follows. The port reads every entry set into memory and
//! searches the flat entry list instead of walking LibHac's L1/L2 offset
//! nodes; the node layout, entry layouts, size formulas and counter rules
//! are LibHac's.
//!
//! ```text
//! MIT License
//!
//! Copyright (c) 2018 Alex Barney
//!
//! Permission is hereby granted, free of charge, to any person obtaining a copy
//! of this software and associated documentation files (the "Software"), to deal
//! in the Software without restriction, including without limitation the rights
//! to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//! copies of the Software, and to permit persons to whom the Software is
//! furnished to do so, subject to the following conditions:
//!
//! The above copyright notice and this permission notice shall be included in all
//! copies or substantial portions of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//! IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//! FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//! AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//! LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//! OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//! SOFTWARE.
//! ```

use crate::bytes::{i32_at, i64_at, u32_at};
use crate::crypto::ctr_apply;
use crate::error::{Error, Result, malformed};
use crate::nca::{FsHeader, fs_u64};
use crate::storage::{Shared, Storage, check_range, read_vec};

/// `BKTR`, little-endian.
pub const SIGNATURE: u32 = 0x5254_4B42;
/// The node size of both BKTR tables.
pub const NODE_SIZE: u64 = 0x4000;
/// The size of a node header: index, count, end offset.
const NODE_HEADER_SIZE: u64 = 0x10;
/// An indirect entry: virtual offset, physical offset, storage index.
pub const INDIRECT_ENTRY_SIZE: u64 = 0x14;
/// An AES-CTR-EX entry: offset, reserved, generation.
pub const CTR_EX_ENTRY_SIZE: u64 = 0x10;

/// A bucket tree header: signature, version, entry count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeHeader {
    /// The number of entries.
    pub entry_count: u32,
}

impl TreeHeader {
    /// Parse and verify a 0x10-byte tree header.
    ///
    /// # Errors
    ///
    /// Bad signature, a version above 1 or a negative count.
    pub fn parse(b: &[u8]) -> Result<TreeHeader> {
        if u32_at(b, 0, "BKTR header")? != SIGNATURE {
            return malformed("BKTR header: bad signature");
        }
        if u32_at(b, 4, "BKTR header")? > 1 {
            return Err(Error::Unsupported("BKTR version above 1".into()));
        }
        let count = i32_at(b, 8, "BKTR header")?;
        let entry_count =
            u32::try_from(count).or_else(|_| malformed("BKTR header: negative entry count"))?;
        Ok(TreeHeader { entry_count })
    }

    /// Serialize (fixtures).
    pub fn to_bytes(self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&SIGNATURE.to_le_bytes());
        b[4..8].copy_from_slice(&1u32.to_le_bytes());
        b[8..12].copy_from_slice(&self.entry_count.to_le_bytes());
        b
    }
}

fn entries_per_set(entry_size: u64) -> u64 {
    (NODE_SIZE - NODE_HEADER_SIZE) / entry_size
}

fn entry_set_count(entry_size: u64, entry_count: u64) -> u64 {
    entry_count.div_ceil(entries_per_set(entry_size))
}

fn node_l2_count(entry_size: u64, entry_count: u64) -> u64 {
    let offsets_per_node = (NODE_SIZE - NODE_HEADER_SIZE) / 8;
    let sets = entry_set_count(entry_size, entry_count);
    if sets <= offsets_per_node {
        return 0;
    }
    let l2 = sets.div_ceil(offsets_per_node);
    (sets - (offsets_per_node - (l2 - 1))).div_ceil(offsets_per_node)
}

/// `BucketTree.QueryNodeStorageSize`.
pub fn node_storage_size(entry_size: u64, entry_count: u64) -> u64 {
    if entry_count == 0 {
        return 0;
    }
    (1 + node_l2_count(entry_size, entry_count)) * NODE_SIZE
}

/// `BucketTree.QueryEntryStorageSize`.
pub fn entry_storage_size(entry_size: u64, entry_count: u64) -> u64 {
    if entry_count == 0 {
        return 0;
    }
    entry_set_count(entry_size, entry_count) * NODE_SIZE
}

/// Read every entry of a bucket tree stored at `table` (node storage then
/// entry storage). Returns the raw entries and the tree's end offset.
fn read_tree(table: &[u8], entry_size: u64, header: TreeHeader) -> Result<(Vec<&[u8]>, i64)> {
    let count = u64::from(header.entry_count);
    if count == 0 {
        return Ok((Vec::new(), 0));
    }
    let nodes = node_storage_size(entry_size, count);
    let sets = entry_set_count(entry_size, count);
    if (table.len() as u64) < nodes + sets * NODE_SIZE {
        return malformed("BKTR table: shorter than its node and entry storage");
    }
    let end = i64_at(table, 8, "BKTR L1 node")?;
    let per_set = entries_per_set(entry_size);
    let mut out = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    for s in 0..sets {
        let base = usize::try_from(nodes + s * NODE_SIZE).unwrap_or(usize::MAX);
        let index = i32_at(table, base, "BKTR entry set")?;
        let n = u64::try_from(i32_at(table, base + 4, "BKTR entry set")?).unwrap_or(u64::MAX);
        if i64::from(index) != i64::try_from(s).unwrap_or(-1) || n == 0 || n > per_set {
            return malformed(format!("BKTR entry set {s}: bad node header"));
        }
        for e in 0..n {
            let at = base + usize::try_from(NODE_HEADER_SIZE + e * entry_size).unwrap_or(0);
            let len = usize::try_from(entry_size).unwrap_or(0);
            out.push(
                table
                    .get(at..at + len)
                    .ok_or_else(|| Error::Format("BKTR entry past the end".into()))?,
            );
        }
    }
    if out.len() as u64 != count {
        return malformed(format!(
            "BKTR: entry sets hold {} entries, header says {count}",
            out.len()
        ));
    }
    Ok((out, end))
}

/// The patch info of an update section's FS header.
#[derive(Clone, Copy, Debug)]
pub struct PatchInfo {
    /// Where the relocation (indirect) table starts in the section; the
    /// patch data is everything before it.
    pub relocation_offset: u64,
    /// The relocation table's size.
    pub relocation_size: u64,
    /// The relocation table header.
    pub relocation_header: TreeHeader,
    /// Where the AES-CTR-EX table starts.
    pub encryption_offset: u64,
    /// The AES-CTR-EX table's size.
    pub encryption_size: u64,
    /// The AES-CTR-EX table header.
    pub encryption_header: TreeHeader,
}

impl PatchInfo {
    /// Read the patch info of an FS header.
    ///
    /// # Errors
    ///
    /// A bad tree header.
    pub fn parse(fs: &FsHeader) -> Result<PatchInfo> {
        let p = fs.patch_info();
        Ok(PatchInfo {
            relocation_offset: fs_u64(fs, 0x100)?,
            relocation_size: fs_u64(fs, 0x108)?,
            relocation_header: TreeHeader::parse(&p[0x10..0x20])?,
            encryption_offset: fs_u64(fs, 0x120)?,
            encryption_size: fs_u64(fs, 0x128)?,
            encryption_header: TreeHeader::parse(&p[0x30..0x40])?,
        })
    }

    /// Serialize (fixtures).
    pub fn to_bytes(&self) -> [u8; 0x40] {
        let mut b = [0u8; 0x40];
        b[0..8].copy_from_slice(&self.relocation_offset.to_le_bytes());
        b[8..16].copy_from_slice(&self.relocation_size.to_le_bytes());
        b[0x10..0x20].copy_from_slice(&self.relocation_header.to_bytes());
        b[0x20..0x28].copy_from_slice(&self.encryption_offset.to_le_bytes());
        b[0x28..0x30].copy_from_slice(&self.encryption_size.to_le_bytes());
        b[0x30..0x40].copy_from_slice(&self.encryption_header.to_bytes());
        b
    }
}

/// One AES-CTR-EX region: from `offset` on, the counter carries
/// `generation`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtrExEntry {
    /// The region start in the patch data.
    pub offset: u64,
    /// The counter generation.
    pub generation: u32,
}

/// Read the AES-CTR-EX table of a patch section from its plain-CTR view.
///
/// # Errors
///
/// A malformed table.
pub fn read_ctr_ex_table(tables: &dyn Storage, info: &PatchInfo) -> Result<Vec<CtrExEntry>> {
    let raw = read_vec(tables, info.encryption_offset, info.encryption_size)?;
    let (entries, end) = read_tree(&raw, CTR_EX_ENTRY_SIZE, info.encryption_header)?;
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        let offset = i64_at(e, 0, "CTR-EX entry")?;
        let offset =
            u64::try_from(offset).or_else(|_| malformed("CTR-EX entry: negative offset"))?;
        out.push(CtrExEntry {
            offset,
            generation: u32_at(e, 0xC, "CTR-EX entry")?,
        });
    }
    check_ascending(out.iter().map(|e| e.offset), end, "CTR-EX")?;
    Ok(out)
}

fn check_ascending(offsets: impl Iterator<Item = u64>, end: i64, what: &str) -> Result<()> {
    let end = u64::try_from(end).unwrap_or(0);
    let mut last = None;
    for o in offsets {
        if last.is_some_and(|l| o <= l) || o >= end.max(1) {
            return malformed(format!(
                "{what} table: entry offsets not ascending inside the tree"
            ));
        }
        last = Some(o);
    }
    Ok(())
}

/// The patch data of an update section, decrypted with per-region counter
/// generations.
pub struct CtrExStorage {
    data: Shared,
    key: [u8; 16],
    upper: [u8; 8],
    stream_offset: u64,
    entries: Vec<CtrExEntry>,
}

impl CtrExStorage {
    /// Wrap `data` (the section's patch data region, encrypted).
    ///
    /// # Errors
    ///
    /// The table does not start at offset 0.
    pub fn new(
        data: Shared,
        key: [u8; 16],
        upper: [u8; 8],
        stream_offset: u64,
        entries: Vec<CtrExEntry>,
    ) -> Result<CtrExStorage> {
        if data.size() > 0 && entries.first().is_none_or(|e| e.offset != 0) {
            return malformed("CTR-EX table does not start at offset 0");
        }
        Ok(CtrExStorage {
            data,
            key,
            upper,
            stream_offset,
            entries,
        })
    }
}

impl Storage for CtrExStorage {
    fn size(&self) -> u64 {
        self.data.size()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.size(), "AES-CTR-EX patch data")?;
        self.data.read_at(offset, buf)?;
        let mut i = self
            .entries
            .partition_point(|e| e.offset <= offset)
            .saturating_sub(1);
        let mut pos = offset;
        let mut done = 0usize;
        while done < buf.len() {
            let e = self.entries[i];
            let next = self.entries.get(i + 1).map_or(u64::MAX, |n| n.offset);
            let n = usize::try_from((next - pos).min((buf.len() - done) as u64)).unwrap_or(0);
            let mut upper = self.upper;
            upper[4..8].copy_from_slice(&e.generation.to_be_bytes());
            ctr_apply(
                &self.key,
                upper,
                self.stream_offset + pos,
                &mut buf[done..done + n],
            );
            done += n;
            pos += n as u64;
            i += 1;
        }
        Ok(())
    }
}

/// One relocation entry: from `virtual_offset` on, bytes come from
/// `storage` (0 base, 1 patch) at `physical_offset`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndirectEntry {
    /// The start in the patched section.
    pub virtual_offset: u64,
    /// The start in the source storage.
    pub physical_offset: u64,
    /// 0 for the base section, 1 for the patch data.
    pub storage: u8,
}

/// The patched section: base and patch data stitched by the relocation
/// table.
pub struct IndirectStorage {
    sources: [Shared; 2],
    entries: Vec<IndirectEntry>,
    size: u64,
}

impl IndirectStorage {
    /// Read the relocation table from the patch section's plain-CTR view
    /// and stitch `base` (the decrypted base section, or zeros) and `patch`
    /// (the decrypted patch data).
    ///
    /// # Errors
    ///
    /// A malformed table, or an entry outside its source.
    pub fn open(
        tables: &dyn Storage,
        info: &PatchInfo,
        base: Shared,
        patch: Shared,
    ) -> Result<IndirectStorage> {
        let raw = read_vec(tables, info.relocation_offset, info.relocation_size)?;
        let (entries, end) = read_tree(&raw, INDIRECT_ENTRY_SIZE, info.relocation_header)?;
        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            let v = i64_at(e, 0, "indirect entry")?;
            let p = i64_at(e, 8, "indirect entry")?;
            let s = i32_at(e, 0x10, "indirect entry")?;
            let (Ok(virtual_offset), Ok(physical_offset)) = (u64::try_from(v), u64::try_from(p))
            else {
                return malformed("indirect entry: negative offset");
            };
            let storage = match s {
                0 => 0,
                1 => 1,
                _ => return malformed(format!("indirect entry: storage index {s}")),
            };
            out.push(IndirectEntry {
                virtual_offset,
                physical_offset,
                storage,
            });
        }
        let size = u64::try_from(end).or_else(|_| malformed("indirect table: negative end"))?;
        IndirectStorage::from_entries([base, patch], out, size)
    }

    /// Stitch from parsed entries.
    ///
    /// # Errors
    ///
    /// Entries not ascending, not starting at 0, or pointing outside their
    /// source.
    pub fn from_entries(
        sources: [Shared; 2],
        entries: Vec<IndirectEntry>,
        size: u64,
    ) -> Result<IndirectStorage> {
        if size > 0 && entries.first().is_none_or(|e| e.virtual_offset != 0) {
            return malformed("indirect table does not start at offset 0");
        }
        check_ascending(
            entries.iter().map(|e| e.virtual_offset),
            i64::try_from(size).unwrap_or(i64::MAX),
            "indirect",
        )?;
        for (i, e) in entries.iter().enumerate() {
            let next = entries.get(i + 1).map_or(size, |n| n.virtual_offset);
            let len = next - e.virtual_offset;
            let src = &sources[usize::from(e.storage)];
            if e.physical_offset
                .checked_add(len)
                .is_none_or(|end| end > src.size())
            {
                return malformed(format!(
                    "indirect entry {i}: {len:#x} bytes at {:#x} run past storage {} ({:#x})",
                    e.physical_offset,
                    e.storage,
                    src.size()
                ));
            }
        }
        Ok(IndirectStorage {
            sources,
            entries,
            size,
        })
    }

    /// The relocation entries.
    pub fn entries(&self) -> &[IndirectEntry] {
        &self.entries
    }
}

impl Storage for IndirectStorage {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.size, "patched section")?;
        let mut i = self
            .entries
            .partition_point(|e| e.virtual_offset <= offset)
            .saturating_sub(1);
        let mut pos = offset;
        let mut done = 0usize;
        while done < buf.len() {
            let e = self.entries[i];
            let next = self
                .entries
                .get(i + 1)
                .map_or(self.size, |n| n.virtual_offset);
            let n = usize::try_from((next - pos).min((buf.len() - done) as u64)).unwrap_or(0);
            self.sources[usize::from(e.storage)].read_at(
                e.physical_offset + (pos - e.virtual_offset),
                &mut buf[done..done + n],
            )?;
            done += n;
            pos += n as u64;
            i += 1;
        }
        Ok(())
    }
}

/// Serialize a bucket tree (fixtures): node storage (one L1 node) then
/// entry sets. `entries` are raw entries whose first 8 bytes are the
/// little-endian start offset.
pub fn build_tree(entries: &[Vec<u8>], entry_size: u64, end: u64) -> Vec<u8> {
    let count = entries.len() as u64;
    let nodes = node_storage_size(entry_size, count);
    let per = usize::try_from(entries_per_set(entry_size)).unwrap_or(1);
    let sets: Vec<&[Vec<u8>]> = entries.chunks(per).collect();
    let mut out = vec![0u8; usize::try_from(nodes + sets.len() as u64 * NODE_SIZE).unwrap_or(0)];
    if count == 0 {
        return out;
    }
    let node = usize::try_from(NODE_SIZE).unwrap_or(0);
    out[4..8].copy_from_slice(&u32::try_from(sets.len()).unwrap_or(0).to_le_bytes());
    out[8..16].copy_from_slice(&end.to_le_bytes());
    for (s, set) in sets.iter().enumerate() {
        out[16 + s * 8..24 + s * 8].copy_from_slice(&set[0][..8]);
        let base = usize::try_from(nodes).unwrap_or(0) + s * node;
        let set_end = sets
            .get(s + 1)
            .map_or(end.to_le_bytes().to_vec(), |n| n[0][..8].to_vec());
        out[base..base + 4].copy_from_slice(&u32::try_from(s).unwrap_or(0).to_le_bytes());
        out[base + 4..base + 8]
            .copy_from_slice(&u32::try_from(set.len()).unwrap_or(0).to_le_bytes());
        out[base + 8..base + 16].copy_from_slice(&set_end);
        for (e, raw) in set.iter().enumerate() {
            let at = base + 16 + e * usize::try_from(entry_size).unwrap_or(0);
            out[at..at + raw.len()].copy_from_slice(raw);
        }
    }
    out
}
