//! NUP, the open container for already-decrypted Switch dumps (draft 1.0 of
//! the public NUP specification, written here from the spec text).
//!
//! A `.nup` holds, per package (the base, one update per version, one add-on
//! per DLC), the ExeFS files and the full RomFS tree, each file stored raw or
//! as one zstd frame with a SHA-256 of its content. [`Nup::open`] checks the
//! superblock and the table-of-contents hash before trusting anything in the
//! table; every file read verifies its SHA-256 as the bytes stream by.
//!
//! An update package holds the **full patched** RomFS tree and its own ExeFS
//! (spec 3.1.4: shared files are deduplicated, delta updates are a possible
//! v2 extension), so the effective title of base plus update takes the
//! update's trees whole when it has them, see [`Nup::effective_title`].
//!
//! The table is kept as plain data ([`Toc`] and its records) with every field
//! public, so a writer can serialize it back; [`build`] is the small writer
//! the tests use to make synthetic containers.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use crate::bytes::{array, slice, to_usize, u8_at, u16_at, u32_at, u64_at};
use crate::crypto::sha256;
use crate::error::{Error, Result, malformed};
use crate::npdm::Npdm;
use crate::storage::{Shared, Storage, check_range, read_vec};

/// The magic of the superblock: `NUP` and the major version.
pub const MAGIC: [u8; 4] = *b"NUP\x01";
/// The size of the superblock.
pub const SUPERBLOCK_SIZE: u64 = 0x80;
/// The size of a package record.
pub const PACKAGE_SIZE: usize = 0x40;
/// The size of a directory record.
pub const DIR_SIZE: usize = 0x18;
/// The size of a file record.
pub const FILE_SIZE: usize = 0x50;
/// The "no directory" value of `exefs_dir` and `romfs_dir`.
pub const NO_DIR: u32 = 0xFFFF_FFFF;

const TOC_HEADER: usize = 0x30;
const TOC_MAGIC: [u8; 4] = *b"TOC\x01";
const CHUNK: usize = 0x10_0000;

/// What a package holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageKind {
    /// The base application program.
    Base,
    /// A patch program for the base; a container may hold several.
    Update,
    /// Add-on content (DLC) with its own title id.
    Addon,
    /// Reserved by the spec.
    AddonUpdate,
    /// Reserved by the spec for system data.
    System,
}

impl PackageKind {
    /// The kind byte of a package record.
    pub fn code(self) -> u8 {
        match self {
            PackageKind::Base => 0,
            PackageKind::Update => 1,
            PackageKind::Addon => 2,
            PackageKind::AddonUpdate => 3,
            PackageKind::System => 4,
        }
    }

    /// The kind for a record byte.
    ///
    /// # Errors
    ///
    /// The byte is 5 or more, which readers must reject.
    pub fn from_code(c: u8) -> Result<PackageKind> {
        Ok(match c {
            0 => PackageKind::Base,
            1 => PackageKind::Update,
            2 => PackageKind::Addon,
            3 => PackageKind::AddonUpdate,
            4 => PackageKind::System,
            _ => return Err(Error::Unsupported(format!("NUP package kind {c}"))),
        })
    }

    /// A short lowercase name.
    pub fn name(self) -> &'static str {
        match self {
            PackageKind::Base => "base",
            PackageKind::Update => "update",
            PackageKind::Addon => "addon",
            PackageKind::AddonUpdate => "addon_update",
            PackageKind::System => "system",
        }
    }
}

/// How a file's extent is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Codec {
    /// The content as is.
    Raw,
    /// One standard Zstandard frame holding the whole file.
    Zstd,
}

impl Codec {
    /// The codec byte of a file record.
    pub fn code(self) -> u8 {
        match self {
            Codec::Raw => 0,
            Codec::Zstd => 1,
        }
    }

    /// The codec for a record byte.
    ///
    /// # Errors
    ///
    /// The codec is unknown (2 and 3 are reserved), which readers must
    /// reject.
    pub fn from_code(c: u8) -> Result<Codec> {
        match c {
            0 => Ok(Codec::Raw),
            1 => Ok(Codec::Zstd),
            _ => Err(Error::Unsupported(format!("NUP codec {c}"))),
        }
    }

    /// A short lowercase name.
    pub fn name(self) -> &'static str {
        match self {
            Codec::Raw => "raw",
            Codec::Zstd => "zstd",
        }
    }
}

/// The 0x80-byte superblock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Superblock {
    /// The size of this header, 0x80 in v1.
    pub header_size: u16,
    /// The header version, 1 in v1.
    pub header_version: u16,
    /// Where the table of contents starts; equals `header_size`.
    pub toc_offset: u64,
    /// The size of the table of contents.
    pub toc_size: u64,
    /// SHA-256 over the whole table of contents.
    pub toc_sha256: [u8; 32],
    /// Where the blob region starts, 16-byte aligned.
    pub blob_offset: u64,
    /// The size of the whole file.
    pub file_size: u64,
    /// The number of package records.
    pub package_count: u32,
    /// Flags, 0 in v1.
    pub flags: u32,
    /// The content-derived UUID, see [`uuid_of`].
    pub uuid: [u8; 16],
}

/// A package record of the table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageRecord {
    /// The raw 64-bit application or add-on id, verbatim from the dump.
    pub title_id: u64,
    /// The directory index of the package tree's root.
    pub root_dir: u32,
    /// The directory index of the ExeFS, or [`NO_DIR`].
    pub exefs_dir: u32,
    /// The directory index of the RomFS, or [`NO_DIR`].
    pub romfs_dir: u32,
    /// The NCM version, verbatim and opaque to the spec.
    pub version: u32,
    /// What the package holds.
    pub kind: PackageKind,
    /// Flags: bit 0 is `standalone_update`.
    pub flags: u8,
    /// The absolute offset of the meta block, or 0.
    pub meta_offset: u64,
    /// The size of the meta block, or 0.
    pub meta_size: u32,
}

/// A directory record of the table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirRecord {
    /// The offset of the name in the string pool.
    pub name_off: u32,
    /// The length of the name in bytes.
    pub name_len: u32,
    /// The index of the first child slot in the children array.
    pub first_child: u32,
    /// The number of child slots.
    pub child_count: u32,
}

/// A file record of the table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRecord {
    /// The offset of the name in the string pool.
    pub name_off: u32,
    /// The length of the name in bytes.
    pub name_len: u32,
    /// The uncompressed size.
    pub size: u64,
    /// The absolute offset of the extent, 0 for an empty file.
    pub extent_offset: u64,
    /// The stored size of the extent.
    pub extent_size: u64,
    /// SHA-256 of the uncompressed content.
    pub sha256: [u8; 32],
    /// How the extent is stored.
    pub codec: Codec,
}

/// The table of contents as plain data. Node ids in `children` below
/// `dirs.len()` name a directory, the rest name file `id - dirs.len()`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Toc {
    /// The package records.
    pub packages: Vec<PackageRecord>,
    /// The directory records.
    pub dirs: Vec<DirRecord>,
    /// The file records.
    pub files: Vec<FileRecord>,
    /// The flat children array.
    pub children: Vec<u32>,
    /// The string pool.
    pub strings: Vec<u8>,
}

impl Toc {
    /// The name `off..off+len` of the string pool.
    ///
    /// # Errors
    ///
    /// The range runs past the pool, or is not UTF-8.
    pub fn name(&self, off: u32, len: u32) -> Result<&str> {
        let b = slice(&self.strings, off as usize, len as usize, "NUP name")?;
        std::str::from_utf8(b).or_else(|_| malformed("NUP: a name is not UTF-8"))
    }
}

/// One record of a package's meta block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlvRecord {
    /// The record type, see the spec's registry.
    pub ty: u16,
    /// The payload.
    pub payload: Vec<u8>,
}

/// TLV type of the verbatim `main.npdm`.
pub const TLV_NPDM: u16 = 0x0001;
/// TLV type of the verbatim NACP.
pub const TLV_NACP: u16 = 0x0002;
/// TLV type of the default icon.
pub const TLV_ICON: u16 = 0x0003;
/// TLV type of the display version.
pub const TLV_DISPLAY_VERSION: u16 = 0x0004;
/// TLV type of the default title name.
pub const TLV_NAME: u16 = 0x0005;
/// TLV type of the publisher.
pub const TLV_PUBLISHER: u16 = 0x0006;
/// TLV type of the 32-byte build id.
pub const TLV_BUILD_ID: u16 = 0x0007;

/// A file in a package: where its bytes are and what they must hash to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NupEntry {
    /// The uncompressed size.
    pub size: u64,
    /// The absolute offset of the extent in the `.nup`.
    pub extent_offset: u64,
    /// The stored size of the extent.
    pub extent_size: u64,
    /// SHA-256 of the uncompressed content.
    pub sha256: [u8; 32],
    /// How the extent is stored.
    pub codec: Codec,
}

/// A package with its tree resolved to paths.
#[derive(Clone, Debug)]
pub struct Package {
    /// The package record.
    pub record: PackageRecord,
    /// The meta block records in file order.
    pub meta: Vec<TlvRecord>,
    /// Every file, as a `/`-separated path from the package root.
    pub files: Vec<(String, NupEntry)>,
    /// Every directory below the root, including empty ones.
    pub dirs: Vec<String>,
    /// The path of the ExeFS directory from the root, if the package has one.
    pub exefs_path: Option<String>,
    /// The path of the RomFS directory from the root, if the package has one.
    pub romfs_path: Option<String>,
}

fn under(prefix: &str, path: &str) -> Option<String> {
    if prefix.is_empty() {
        return Some(path.to_string());
    }
    path.strip_prefix(prefix)
        .and_then(|r| r.strip_prefix('/'))
        .map(str::to_string)
}

impl Package {
    /// Whether the `standalone_update` flag is set (an update-only dump).
    pub fn standalone_update(&self) -> bool {
        self.record.flags & 1 != 0
    }

    /// The first meta record of type `ty`.
    pub fn tlv(&self, ty: u16) -> Option<&[u8]> {
        self.meta
            .iter()
            .find(|r| r.ty == ty)
            .map(|r| r.payload.as_slice())
    }

    fn tlv_str(&self, ty: u16) -> Option<String> {
        self.tlv(ty)
            .and_then(|b| std::str::from_utf8(b).ok())
            .map(str::to_string)
    }

    /// The display version of the meta block (TLV 4).
    pub fn display_version(&self) -> Option<String> {
        self.tlv_str(TLV_DISPLAY_VERSION)
    }

    /// The default-language title name (TLV 5).
    pub fn name(&self) -> Option<String> {
        self.tlv_str(TLV_NAME)
    }

    /// The publisher (TLV 6).
    pub fn publisher(&self) -> Option<String> {
        self.tlv_str(TLV_PUBLISHER)
    }

    /// The build id (TLV 7).
    pub fn build_id(&self) -> Option<[u8; 32]> {
        self.tlv(TLV_BUILD_ID).and_then(|b| b.try_into().ok())
    }

    /// The program id of the NPDM in the meta block, if it parses.
    pub fn npdm_program_id(&self) -> Option<u64> {
        self.tlv(TLV_NPDM)
            .and_then(|b| Npdm::parse(b).ok())
            .map(|n| n.program_id)
    }

    /// The ExeFS files, named relative to the ExeFS directory.
    pub fn exefs(&self) -> Vec<(String, NupEntry)> {
        self.subtree(self.exefs_path.as_deref())
    }

    /// The RomFS files, named relative to the RomFS directory.
    pub fn romfs(&self) -> Vec<(String, NupEntry)> {
        self.subtree(self.romfs_path.as_deref())
    }

    /// The RomFS directories, relative to the RomFS directory, including
    /// empty ones.
    pub fn romfs_dirs(&self) -> Vec<String> {
        match self.romfs_path.as_deref() {
            Some(p) => self.dirs.iter().filter_map(|d| under(p, d)).collect(),
            None => Vec::new(),
        }
    }

    fn subtree(&self, prefix: Option<&str>) -> Vec<(String, NupEntry)> {
        let Some(prefix) = prefix else {
            return Vec::new();
        };
        self.files
            .iter()
            .filter_map(|(p, e)| under(prefix, p).map(|r| (r, e.clone())))
            .collect()
    }
}

/// Which update [`Nup::effective_title`] layers over the base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateSelect {
    /// The update with the highest version, if there is one.
    Newest,
    /// The base alone.
    None,
    /// The update with exactly this (NCM) version.
    Version(u32),
}

/// The program an importer needs: the effective ExeFS and RomFS files.
#[derive(Clone, Debug)]
pub struct NupTitle {
    /// The program id: the NPDM's if it parses, else the package record's.
    pub program_id: u64,
    /// The NCM version of the newest layer in use.
    pub version: u32,
    /// The display version of that layer's meta block, if it has one.
    pub display_version: Option<String>,
    /// The index of the base package in use.
    pub base: Option<usize>,
    /// The index of the update package in use.
    pub update: Option<usize>,
    /// The ExeFS files, named relative to the ExeFS directory.
    pub exefs: Vec<(String, NupEntry)>,
    /// The RomFS files, named relative to the RomFS directory.
    pub romfs: Vec<(String, NupEntry)>,
    /// The RomFS directories, including empty ones.
    pub romfs_dirs: Vec<String>,
}

/// An opened NUP container.
pub struct Nup {
    storage: Shared,
    superblock: Superblock,
    toc: Toc,
    packages: Vec<Package>,
}

fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']) {
        return malformed(format!("NUP: unsafe name {name:?}"));
    }
    Ok(())
}

fn parse_superblock(b: &[u8], size: u64) -> Result<Superblock> {
    if b[..3] != MAGIC[..3] {
        return malformed("NUP: bad magic (not a .nup file)");
    }
    if b[3] != MAGIC[3] {
        return Err(Error::Unsupported(format!("NUP major version {}", b[3])));
    }
    let w = "NUP superblock";
    let sb = Superblock {
        header_size: u16_at(b, 4, w)?,
        header_version: u16_at(b, 6, w)?,
        toc_offset: u64_at(b, 8, w)?,
        toc_size: u64_at(b, 0x10, w)?,
        toc_sha256: array(b, 0x18, w)?,
        blob_offset: u64_at(b, 0x38, w)?,
        file_size: u64_at(b, 0x40, w)?,
        package_count: u32_at(b, 0x48, w)?,
        flags: u32_at(b, 0x4C, w)?,
        uuid: array(b, 0x50, w)?,
    };
    if u64::from(sb.header_size) < SUPERBLOCK_SIZE {
        return malformed("NUP: header_size below 0x80");
    }
    if sb.toc_offset != u64::from(sb.header_size) {
        return malformed("NUP: toc_offset is not header_size");
    }
    let toc_end = sb.toc_offset.checked_add(sb.toc_size);
    if !sb.blob_offset.is_multiple_of(16) || toc_end.is_none_or(|e| sb.blob_offset < e) {
        return malformed("NUP: blob_offset is unaligned or inside the table");
    }
    if sb.file_size != size {
        return malformed(format!(
            "NUP: file_size {:#x} is not the stream length {size:#x}",
            sb.file_size
        ));
    }
    if sb.blob_offset > sb.file_size {
        return malformed("NUP: blob_offset past the end of the file");
    }
    if sb.flags != 0 {
        return Err(Error::Unsupported(format!(
            "NUP superblock flags {:#x}",
            sb.flags
        )));
    }
    if sb.package_count == 0 {
        return malformed("NUP: no packages");
    }
    Ok(sb)
}

fn parse_toc(b: &[u8], sb: &Superblock) -> Result<Toc> {
    let w = "NUP table of contents";
    if b.len() < TOC_HEADER || b[..4] != TOC_MAGIC {
        return malformed("NUP: bad table-of-contents magic");
    }
    let package_count = u32_at(b, 4, w)?;
    let dir_count = u64_at(b, 8, w)?;
    let file_count = u64_at(b, 0x10, w)?;
    let pool_off = u64_at(b, 0x18, w)?;
    let pool_size = u64_at(b, 0x20, w)?;
    if package_count != sb.package_count {
        return malformed("NUP: package counts of superblock and table differ");
    }
    let len = b.len() as u64;
    let fits = |count: u64, each: usize| count.checked_mul(each as u64).filter(|n| *n <= len);
    let (Some(pk), Some(dk), Some(fk)) = (
        fits(u64::from(package_count), PACKAGE_SIZE),
        fits(dir_count, DIR_SIZE),
        fits(file_count, FILE_SIZE),
    ) else {
        return malformed("NUP: record counts exceed the table");
    };
    let dirs_at = TOC_HEADER as u64 + pk;
    let files_at = dirs_at + dk;
    let children_at = files_at + fk;
    if children_at > len {
        return malformed("NUP: record arrays run past the table");
    }
    let pool_end = pool_off
        .checked_add(pool_size)
        .filter(|e| *e <= len)
        .ok_or_else(|| Error::Format("NUP: string pool runs past the table".into()))?;
    let at = |v: u64| to_usize(v, w);
    let mut toc = Toc {
        strings: slice(b, at(pool_off)?, at(pool_size)?, w)?.to_vec(),
        ..Toc::default()
    };
    for i in 0..at(u64::from(package_count))? {
        let r = slice(b, TOC_HEADER + i * PACKAGE_SIZE, PACKAGE_SIZE, w)?;
        toc.packages.push(PackageRecord {
            title_id: u64_at(r, 0, w)?,
            root_dir: u32_at(r, 8, w)?,
            exefs_dir: u32_at(r, 0xC, w)?,
            romfs_dir: u32_at(r, 0x10, w)?,
            version: u32_at(r, 0x14, w)?,
            kind: PackageKind::from_code(u8_at(r, 0x18, w)?)?,
            flags: u8_at(r, 0x19, w)?,
            meta_offset: u64_at(r, 0x20, w)?,
            meta_size: u32_at(r, 0x28, w)?,
        });
    }
    let mut slots = 0u64;
    for i in 0..at(dir_count)? {
        let r = slice(b, at(dirs_at)? + i * DIR_SIZE, DIR_SIZE, w)?;
        let d = DirRecord {
            name_off: u32_at(r, 0, w)?,
            name_len: u32_at(r, 4, w)?,
            first_child: u32_at(r, 8, w)?,
            child_count: u32_at(r, 0xC, w)?,
        };
        slots += u64::from(d.child_count);
        toc.dirs.push(d);
    }
    for i in 0..at(file_count)? {
        let r = slice(b, at(files_at)? + i * FILE_SIZE, FILE_SIZE, w)?;
        toc.files.push(FileRecord {
            name_off: u32_at(r, 0, w)?,
            name_len: u32_at(r, 4, w)?,
            size: u64_at(r, 8, w)?,
            extent_offset: u64_at(r, 0x10, w)?,
            extent_size: u64_at(r, 0x18, w)?,
            sha256: array(r, 0x20, w)?,
            codec: Codec::from_code(u8_at(r, 0x40, w)?)?,
        });
    }
    let children_end = slots
        .checked_mul(4)
        .and_then(|n| n.checked_add(children_at))
        .filter(|e| *e <= len)
        .ok_or_else(|| Error::Format("NUP: children array runs past the table".into()))?;
    if pool_size > 0 && pool_off < children_end && pool_end > TOC_HEADER as u64 {
        return malformed("NUP: string pool overlaps the record arrays");
    }
    for i in 0..at(slots)? {
        toc.children.push(u32_at(b, at(children_at)? + i * 4, w)?);
    }
    Ok(toc)
}

fn read_meta(storage: &dyn Storage, sb: &Superblock, r: &PackageRecord) -> Result<Vec<TlvRecord>> {
    if r.meta_size == 0 {
        return Ok(Vec::new());
    }
    let size = u64::from(r.meta_size);
    check_range(
        r.meta_offset,
        r.meta_size as usize,
        sb.file_size,
        "NUP meta block",
    )?;
    if r.meta_offset < sb.blob_offset {
        return malformed("NUP: meta block overlaps the header or table");
    }
    let b = read_vec(storage, r.meta_offset, size)?;
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 8 <= b.len() {
        let ty = u16_at(&b, at, "NUP meta")?;
        let n = u32_at(&b, at + 4, "NUP meta")? as usize;
        let payload = slice(&b, at + 8, n, "NUP meta record")?.to_vec();
        out.push(TlvRecord { ty, payload });
        at += 8 + n;
    }
    Ok(out)
}

struct Walk<'a> {
    toc: &'a Toc,
    dir_seen: Vec<bool>,
    file_seen: Vec<bool>,
}

impl Walk<'_> {
    fn package(&mut self, r: &PackageRecord, sb: &Superblock) -> Result<Package> {
        let toc = self.toc;
        let ndirs = toc.dirs.len();
        let ok = |d: u32| d == NO_DIR || (d as usize) < ndirs;
        if r.root_dir as usize >= ndirs || !ok(r.exefs_dir) || !ok(r.romfs_dir) {
            return malformed("NUP: package directory index out of range");
        }
        let mut files = Vec::new();
        let mut dirs = Vec::new();
        let (mut exefs_path, mut romfs_path) = (None, None);
        self.visit_dir(r.root_dir as usize)?;
        let mut stack = vec![(r.root_dir as usize, String::new())];
        while let Some((d, path)) = stack.pop() {
            if d as u32 == r.exefs_dir {
                exefs_path = Some(path.clone());
            }
            if d as u32 == r.romfs_dir {
                romfs_path = Some(path.clone());
            }
            if d as u32 != r.root_dir {
                dirs.push(path.clone());
            }
            let rec = &toc.dirs[d];
            let (first, count) = (rec.first_child as usize, rec.child_count as usize);
            let slots = first
                .checked_add(count)
                .and_then(|e| toc.children.get(first..e))
                .ok_or_else(|| Error::Format("NUP: child range runs past the array".into()))?;
            let mut names = HashSet::new();
            for &id in slots {
                let id = id as usize;
                let (name, is_dir) = if id < ndirs {
                    self.visit_dir(id)?;
                    let n = &toc.dirs[id];
                    (toc.name(n.name_off, n.name_len)?, true)
                } else {
                    let f = id - ndirs;
                    let Some(n) = toc.files.get(f) else {
                        return malformed("NUP: child id out of range");
                    };
                    if std::mem::replace(&mut self.file_seen[f], true) {
                        return malformed("NUP: a file is reachable twice");
                    }
                    (toc.name(n.name_off, n.name_len)?, false)
                };
                check_name(name)?;
                if !names.insert(name) {
                    return malformed(format!("NUP: duplicate name {name:?} in a directory"));
                }
                let child = if path.is_empty() {
                    name.to_string()
                } else {
                    format!("{path}/{name}")
                };
                if is_dir {
                    stack.push((id, child));
                } else {
                    files.push((child, entry(&toc.files[id - ndirs], sb)?));
                }
            }
        }
        let need = |dir: u32, path: &Option<String>, what: &str| {
            if dir != NO_DIR && path.is_none() {
                return malformed(format!("NUP: {what} directory is outside the package"));
            }
            Ok(())
        };
        need(r.exefs_dir, &exefs_path, "exefs")?;
        need(r.romfs_dir, &romfs_path, "romfs")?;
        files.sort_by(|a, b| a.0.cmp(&b.0));
        dirs.sort();
        Ok(Package {
            record: r.clone(),
            meta: Vec::new(),
            files,
            dirs,
            exefs_path,
            romfs_path,
        })
    }

    fn visit_dir(&mut self, d: usize) -> Result<()> {
        if std::mem::replace(&mut self.dir_seen[d], true) {
            return malformed("NUP: a directory is reachable twice");
        }
        Ok(())
    }
}

fn entry(f: &FileRecord, sb: &Superblock) -> Result<NupEntry> {
    if f.extent_size > 0 {
        let end = f.extent_offset.checked_add(f.extent_size);
        if f.extent_offset < sb.blob_offset
            || !f.extent_offset.is_multiple_of(16)
            || end.is_none_or(|e| e > sb.file_size)
        {
            return malformed("NUP: a file extent is outside the blob region or unaligned");
        }
    } else if f.size != 0 {
        return malformed("NUP: a file with no extent has a size");
    }
    if f.codec == Codec::Raw && f.extent_size != f.size {
        return malformed("NUP: a raw extent differs in size from its file");
    }
    Ok(NupEntry {
        size: f.size,
        extent_offset: f.extent_offset,
        extent_size: f.extent_size,
        sha256: f.sha256,
        codec: f.codec,
    })
}

/// The UUID the spec derives from the package list: the first 16 bytes of
/// the SHA-256 over `title_id ‖ version ‖ kind` of every package in order.
pub fn uuid_of(packages: &[PackageRecord]) -> [u8; 16] {
    let mut data = Vec::new();
    for p in packages {
        data.extend_from_slice(&p.title_id.to_le_bytes());
        data.extend_from_slice(&p.version.to_le_bytes());
        data.push(p.kind.code());
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&sha256(&data)[..16]);
    out
}

struct ExtentReader<'a> {
    storage: &'a dyn Storage,
    at: u64,
    left: u64,
}

impl Read for ExtentReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = usize::try_from(self.left).map_or(buf.len(), |l| l.min(buf.len()));
        if n == 0 {
            return Ok(0);
        }
        self.storage
            .read_at(self.at, &mut buf[..n])
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        self.at += n as u64;
        self.left -= n as u64;
        Ok(n)
    }
}

impl Nup {
    /// Open a `.nup` and verify its superblock and table.
    ///
    /// # Errors
    ///
    /// Not a NUP, malformed or out of bounds, an unsupported version, kind
    /// or codec ([`Error::Unsupported`]), or the table does not match its
    /// SHA-256 ([`Error::Hash`]).
    pub fn open(storage: Shared) -> Result<Nup> {
        let size = storage.size();
        if size < SUPERBLOCK_SIZE {
            return malformed("NUP: shorter than the superblock");
        }
        let head = read_vec(&*storage, 0, SUPERBLOCK_SIZE)?;
        let sb = parse_superblock(&head, size)?;
        let toc_end = sb.toc_offset.saturating_add(sb.toc_size);
        if toc_end > size {
            return malformed("NUP: table of contents runs past the end");
        }
        let toc_bytes = read_vec(&*storage, sb.toc_offset, sb.toc_size)?;
        if sha256(&toc_bytes) != sb.toc_sha256 {
            return Err(Error::Hash("NUP table of contents".into()));
        }
        let toc = parse_toc(&toc_bytes, &sb)?;
        drop(toc_bytes);
        let mut walk = Walk {
            toc: &toc,
            dir_seen: vec![false; toc.dirs.len()],
            file_seen: vec![false; toc.files.len()],
        };
        let mut packages = Vec::new();
        for r in &toc.packages {
            let mut p = walk.package(r, &sb)?;
            p.meta = read_meta(&*storage, &sb, r)?;
            packages.push(p);
        }
        let kinds = |k| packages.iter().filter(|p| p.record.kind == k).count();
        if kinds(PackageKind::Base) > 1 {
            return malformed("NUP: more than one base package");
        }
        Ok(Nup {
            storage,
            superblock: sb,
            toc,
            packages,
        })
    }

    /// The superblock.
    pub fn superblock(&self) -> &Superblock {
        &self.superblock
    }

    /// The table of contents as plain data.
    pub fn toc(&self) -> &Toc {
        &self.toc
    }

    /// The packages in table order.
    pub fn packages(&self) -> &[Package] {
        &self.packages
    }

    /// Whether the superblock UUID is the one [`uuid_of`] derives.
    pub fn uuid_matches(&self) -> bool {
        uuid_of(&self.toc.packages) == self.superblock.uuid
    }

    /// The index of the update `sel` names, if any.
    ///
    /// # Errors
    ///
    /// [`UpdateSelect::Version`] names no update.
    pub fn select_update(&self, sel: UpdateSelect) -> Result<Option<usize>> {
        let updates = self
            .packages
            .iter()
            .enumerate()
            .filter(|(_, p)| p.record.kind == PackageKind::Update);
        match sel {
            UpdateSelect::None => Ok(None),
            UpdateSelect::Newest => Ok(updates
                .rev()
                .max_by_key(|(_, p)| p.record.version)
                .map(|(i, _)| i)),
            UpdateSelect::Version(v) => updates
                .into_iter()
                .find(|(_, p)| p.record.version == v)
                .map(|(i, _)| Some(i))
                .ok_or_else(|| Error::Format(format!("NUP: no update with version {v:#x}"))),
        }
    }

    /// The program of one package alone.
    pub fn package_title(&self, index: usize) -> Option<NupTitle> {
        let p = self.packages.get(index)?;
        Some(NupTitle {
            program_id: p.npdm_program_id().unwrap_or(p.record.title_id),
            version: p.record.version,
            display_version: p.display_version(),
            base: (p.record.kind == PackageKind::Base).then_some(index),
            update: (p.record.kind == PackageKind::Update).then_some(index),
            exefs: p.exefs(),
            romfs: p.romfs(),
            romfs_dirs: p.romfs_dirs(),
        })
    }

    /// The program an importer builds: the base with the chosen update
    /// layered over it. The update's ExeFS and RomFS replace the base's
    /// whole when the update has them (an update holds the full patched
    /// tree, not a delta); a layer without an ExeFS or RomFS leaves the
    /// base's in place.
    ///
    /// # Errors
    ///
    /// A requested update version does not exist, or there is neither a base
    /// nor an update to build from.
    pub fn effective_title(&self, sel: UpdateSelect) -> Result<NupTitle> {
        let base = self
            .packages
            .iter()
            .position(|p| p.record.kind == PackageKind::Base);
        let update = self.select_update(sel)?;
        let Some(top) = update.or(base) else {
            return malformed("NUP: no base or update package to build a title from");
        };
        let mut t = self
            .package_title(top)
            .ok_or_else(|| Error::Format("NUP: package index out of range".into()))?;
        t.base = base;
        t.update = update;
        if let (Some(b), Some(_)) = (base, update) {
            let b = &self.packages[b];
            if t.exefs.is_empty() {
                t.exefs = b.exefs();
                t.program_id = b.npdm_program_id().unwrap_or(b.record.title_id);
            }
            if t.romfs.is_empty() && t.romfs_dirs.is_empty() {
                t.romfs = b.romfs();
                t.romfs_dirs = b.romfs_dirs();
            }
        }
        Ok(t)
    }

    /// Stream one file's verified content into `out`.
    ///
    /// The bytes reach `out` as they decode; the SHA-256 is checked at the
    /// end, so a caller writing through a streaming writer must not finish
    /// it when this fails.
    ///
    /// # Errors
    ///
    /// A read or write fails, the zstd frame is bad or does not decode to
    /// the recorded size ([`Error::Format`]), or the content does not match
    /// its SHA-256 ([`Error::Hash`]).
    pub fn copy(&self, e: &NupEntry, out: &mut dyn Write) -> Result<()> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        let mut total = 0u64;
        let mut sink = |b: &[u8]| -> Result<()> {
            hasher.update(b);
            out.write_all(b)?;
            total += b.len() as u64;
            Ok(())
        };
        let mut buf = vec![0u8; CHUNK.min(usize::try_from(e.size.max(1)).unwrap_or(CHUNK))];
        match e.codec {
            Codec::Raw => {
                let mut off = 0;
                while off < e.size {
                    let n = (buf.len() as u64).min(e.size - off);
                    let b = &mut buf[..usize::try_from(n).unwrap_or(0)];
                    self.storage.read_at(e.extent_offset + off, b)?;
                    sink(b)?;
                    off += n;
                }
            }
            Codec::Zstd => {
                let src = ExtentReader {
                    storage: &*self.storage,
                    at: e.extent_offset,
                    left: e.extent_size,
                };
                let mut dec = zstd::stream::read::Decoder::new(src)
                    .map_err(|x| Error::Format(format!("NUP zstd: {x}")))?
                    .single_frame()
                    .take(e.size.saturating_add(1));
                loop {
                    let n = dec
                        .read(&mut buf)
                        .map_err(|x| Error::Format(format!("NUP zstd: {x}")))?;
                    if n == 0 {
                        break;
                    }
                    sink(&buf[..n])?;
                }
            }
        }
        if total != e.size {
            return malformed(format!(
                "NUP: a file decoded to {total:#x} bytes, expected {:#x}",
                e.size
            ));
        }
        if <[u8; 32]>::from(hasher.finalize()) != e.sha256 {
            return Err(Error::Hash("NUP file content".into()));
        }
        Ok(())
    }

    /// One file's verified content in memory.
    ///
    /// # Errors
    ///
    /// As [`Nup::copy`], or the file does not fit in memory.
    pub fn read(&self, e: &NupEntry) -> Result<Vec<u8>> {
        let mut v = Vec::with_capacity(to_usize(e.size.min(1 << 28), "NUP file")?);
        self.copy(e, &mut v)?;
        Ok(v)
    }

    fn extract_files(
        &self,
        files: &[(String, NupEntry)],
        dirs: &[String],
        dir: &Path,
    ) -> Result<usize> {
        std::fs::create_dir_all(dir)?;
        for d in dirs {
            std::fs::create_dir_all(dir.join(safe_path(d)?))?;
        }
        let mut order: Vec<&(String, NupEntry)> = files.iter().collect();
        order.sort_by_key(|(_, e)| e.extent_offset);
        let mut written = 0;
        for (path, e) in order {
            let target = dir.join(safe_path(path)?);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut w = switch_io::StreamWriter::new(&target)?;
            self.copy(e, &mut w)?;
            if w.finish()? {
                written += 1;
            }
        }
        Ok(written)
    }

    /// Extract the effective RomFS under `dir`, verifying every file, with
    /// switch-io's streaming write-if-changed writer. Returns how many
    /// files were rewritten.
    ///
    /// # Errors
    ///
    /// A read, hash check or write fails, or a path is unsafe.
    pub fn extract_romfs(&self, t: &NupTitle, dir: &Path) -> Result<usize> {
        self.extract_files(&t.romfs, &t.romfs_dirs, dir)
    }

    /// Extract the effective ExeFS files under `dir`, as
    /// [`Nup::extract_romfs`].
    ///
    /// # Errors
    ///
    /// As [`Nup::extract_romfs`].
    pub fn extract_exefs(&self, t: &NupTitle, dir: &Path) -> Result<usize> {
        self.extract_files(&t.exefs, &[], dir)
    }

    /// Extract every file of one package (`exefs/`, `romfs/`, `data/`, ...)
    /// under `dir`, as [`Nup::extract_romfs`].
    ///
    /// # Errors
    ///
    /// As [`Nup::extract_romfs`], or `index` is out of range.
    pub fn extract_package(&self, index: usize, dir: &Path) -> Result<usize> {
        let Some(p) = self.packages.get(index) else {
            return malformed(format!("NUP: no package {index}"));
        };
        self.extract_files(&p.files, &p.dirs, dir)
    }
}

fn safe_path(p: &str) -> Result<PathBuf> {
    let path = Path::new(p);
    if p.is_empty() || !path.components().all(|c| matches!(c, Component::Normal(_))) {
        return malformed(format!("NUP: unsafe path {p:?}"));
    }
    Ok(path.to_path_buf())
}

/// A package to write with [`build`].
pub struct BuildPackage<'a> {
    /// The title id.
    pub title_id: u64,
    /// The NCM version.
    pub version: u32,
    /// The kind.
    pub kind: PackageKind,
    /// The `standalone_update` flag.
    pub standalone: bool,
    /// The files as (path from the package root, content), such as
    /// `exefs/main` and `romfs/dir/file.bin`.
    pub files: Vec<(&'a str, &'a [u8])>,
    /// Extra empty directories, as paths from the package root.
    pub empty_dirs: Vec<&'a str>,
    /// The meta records.
    pub meta: Vec<(u16, Vec<u8>)>,
}

#[derive(Default)]
struct Node<'a> {
    dirs: BTreeMap<&'a str, Node<'a>>,
    files: BTreeMap<&'a str, usize>,
}

enum Kid {
    Dir(usize),
    File(usize),
}

struct FileTmp<'a> {
    name: &'a str,
    data: &'a [u8],
}

struct Layout<'a> {
    dirs: Vec<(&'a str, Vec<(&'a str, Kid)>)>,
    files: Vec<FileTmp<'a>>,
}

fn flatten<'a>(
    node: &Node<'a>,
    name: &'a str,
    p: &BuildPackage<'a>,
    lay: &mut Layout<'a>,
) -> usize {
    let me = lay.dirs.len();
    lay.dirs.push((name, Vec::new()));
    let mut kids = Vec::new();
    for (n, d) in &node.dirs {
        kids.push((*n, Kid::Dir(flatten(d, n, p, lay))));
    }
    for (n, f) in &node.files {
        lay.files.push(FileTmp {
            name: n,
            data: p.files[*f].1,
        });
        kids.push((*n, Kid::File(lay.files.len() - 1)));
    }
    kids.sort_by(|a, b| a.0.cmp(b.0));
    lay.dirs[me].1 = kids;
    me
}

struct Pool {
    bytes: Vec<u8>,
    seen: HashMap<String, (u32, u32)>,
}

impl Pool {
    fn intern(&mut self, s: &str) -> (u32, u32) {
        if let Some(r) = self.seen.get(s) {
            return *r;
        }
        let r = (
            u32::try_from(self.bytes.len()).unwrap_or(0),
            u32::try_from(s.len()).unwrap_or(0),
        );
        self.bytes.extend_from_slice(s.as_bytes());
        self.seen.insert(s.to_string(), r);
        r
    }
}

fn align16(v: u64) -> u64 {
    v.div_ceil(16) * 16
}

/// Build a `.nup` holding `packages` (for fixtures). It follows the spec's
/// writer rules: sorted children, 16-byte-aligned extents, zstd level 3
/// only when it shrinks the file, equal contents sharing one extent.
pub fn build(packages: &[BuildPackage<'_>]) -> Vec<u8> {
    let mut lay = Layout {
        dirs: Vec::new(),
        files: Vec::new(),
    };
    let mut records = Vec::new();
    for p in packages {
        let mut root = Node::default();
        for (fi, (path, _)) in p.files.iter().enumerate() {
            let parts: Vec<&str> = path.split('/').collect();
            let mut cur = &mut root;
            for part in &parts[..parts.len() - 1] {
                cur = cur.dirs.entry(part).or_default();
            }
            cur.files.insert(parts[parts.len() - 1], fi);
        }
        for path in &p.empty_dirs {
            let mut cur = &mut root;
            for part in path.split('/') {
                cur = cur.dirs.entry(part).or_default();
            }
        }
        let root_dir = flatten(&root, "", p, &mut lay);
        let find = |name: &str| -> u32 {
            let mut cur = root_dir;
            for part in name.split('/') {
                let next = lay.dirs[cur].1.iter().find_map(|(n, k)| match k {
                    Kid::Dir(d) if *n == part => Some(*d),
                    _ => None,
                });
                match next {
                    Some(d) => cur = d,
                    None => return NO_DIR,
                }
            }
            u32::try_from(cur).unwrap_or(NO_DIR)
        };
        records.push(PackageRecord {
            title_id: p.title_id,
            root_dir: u32::try_from(root_dir).unwrap_or(0),
            exefs_dir: find("exefs"),
            romfs_dir: find("romfs"),
            version: p.version,
            kind: p.kind,
            flags: u8::from(p.standalone),
            meta_offset: 0,
            meta_size: 0,
        });
    }
    let ndirs = lay.dirs.len();

    let mut blob: Vec<u8> = Vec::new();
    let mut extents: HashMap<([u8; 32], u64), (u64, u64, Codec)> = HashMap::new();
    let mut pool = Pool {
        bytes: Vec::new(),
        seen: HashMap::new(),
    };
    let mut file_recs = Vec::new();
    for f in &lay.files {
        let hash = sha256(f.data);
        let size = f.data.len() as u64;
        let (extent_offset, extent_size, codec) = if size == 0 {
            (0, 0, Codec::Raw)
        } else {
            *extents.entry((hash, size)).or_insert_with(|| {
                let packed = zstd::bulk::compress(f.data, 3).unwrap_or_default();
                let (bytes, codec) = if !packed.is_empty() && packed.len() < f.data.len() {
                    (packed.as_slice(), Codec::Zstd)
                } else {
                    (f.data, Codec::Raw)
                };
                blob.resize(usize::try_from(align16(blob.len() as u64)).unwrap_or(0), 0);
                let at = blob.len() as u64;
                blob.extend_from_slice(bytes);
                (at, bytes.len() as u64, codec)
            })
        };
        let (name_off, name_len) = pool.intern(f.name);
        file_recs.push(FileRecord {
            name_off,
            name_len,
            size,
            extent_offset,
            extent_size,
            sha256: hash,
            codec,
        });
    }
    for (r, p) in records.iter_mut().zip(packages) {
        if p.meta.is_empty() {
            continue;
        }
        let mut b = Vec::new();
        for (ty, payload) in &p.meta {
            b.extend_from_slice(&ty.to_le_bytes());
            b.extend_from_slice(&0u16.to_le_bytes());
            b.extend_from_slice(&u32::try_from(payload.len()).unwrap_or(0).to_le_bytes());
            b.extend_from_slice(payload);
        }
        blob.resize(usize::try_from(align16(blob.len() as u64)).unwrap_or(0), 0);
        r.meta_offset = blob.len() as u64;
        r.meta_size = u32::try_from(b.len()).unwrap_or(0);
        blob.extend_from_slice(&b);
    }

    let mut dir_recs = Vec::new();
    let mut children = Vec::new();
    for (name, kids) in &lay.dirs {
        let (name_off, name_len) = pool.intern(name);
        dir_recs.push(DirRecord {
            name_off,
            name_len,
            first_child: u32::try_from(children.len()).unwrap_or(0),
            child_count: u32::try_from(kids.len()).unwrap_or(0),
        });
        for (_, k) in kids {
            children.push(match k {
                Kid::Dir(d) => u32::try_from(*d).unwrap_or(0),
                Kid::File(f) => u32::try_from(ndirs + f).unwrap_or(0),
            });
        }
    }

    let serialize = |blob_offset: u64| -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&TOC_MAGIC);
        t.extend_from_slice(&u32::try_from(records.len()).unwrap_or(0).to_le_bytes());
        t.extend_from_slice(&(dir_recs.len() as u64).to_le_bytes());
        t.extend_from_slice(&(file_recs.len() as u64).to_le_bytes());
        let pool_off = TOC_HEADER
            + records.len() * PACKAGE_SIZE
            + dir_recs.len() * DIR_SIZE
            + file_recs.len() * FILE_SIZE
            + children.len() * 4;
        t.extend_from_slice(&(pool_off as u64).to_le_bytes());
        t.extend_from_slice(&(pool.bytes.len() as u64).to_le_bytes());
        t.extend_from_slice(&0u64.to_le_bytes());
        for r in &records {
            let mut b = [0u8; PACKAGE_SIZE];
            b[0..8].copy_from_slice(&r.title_id.to_le_bytes());
            b[8..12].copy_from_slice(&r.root_dir.to_le_bytes());
            b[12..16].copy_from_slice(&r.exefs_dir.to_le_bytes());
            b[16..20].copy_from_slice(&r.romfs_dir.to_le_bytes());
            b[20..24].copy_from_slice(&r.version.to_le_bytes());
            b[24] = r.kind.code();
            b[25] = r.flags;
            let meta_at = if r.meta_size > 0 {
                blob_offset + r.meta_offset
            } else {
                0
            };
            b[32..40].copy_from_slice(&meta_at.to_le_bytes());
            b[40..44].copy_from_slice(&r.meta_size.to_le_bytes());
            t.extend_from_slice(&b);
        }
        for d in &dir_recs {
            t.extend_from_slice(&d.name_off.to_le_bytes());
            t.extend_from_slice(&d.name_len.to_le_bytes());
            t.extend_from_slice(&d.first_child.to_le_bytes());
            t.extend_from_slice(&d.child_count.to_le_bytes());
            t.extend_from_slice(&0u64.to_le_bytes());
        }
        for f in &file_recs {
            let mut b = [0u8; FILE_SIZE];
            b[0..4].copy_from_slice(&f.name_off.to_le_bytes());
            b[4..8].copy_from_slice(&f.name_len.to_le_bytes());
            b[8..16].copy_from_slice(&f.size.to_le_bytes());
            let at = if f.extent_size > 0 {
                blob_offset + f.extent_offset
            } else {
                0
            };
            b[16..24].copy_from_slice(&at.to_le_bytes());
            b[24..32].copy_from_slice(&f.extent_size.to_le_bytes());
            b[32..64].copy_from_slice(&f.sha256);
            b[64] = f.codec.code();
            t.extend_from_slice(&b);
        }
        for c in &children {
            t.extend_from_slice(&c.to_le_bytes());
        }
        t.extend_from_slice(&pool.bytes);
        t
    };
    let toc_len = serialize(0).len() as u64;
    let blob_offset = align16(SUPERBLOCK_SIZE + toc_len);
    let toc = serialize(blob_offset);
    let file_size = blob_offset + blob.len() as u64;
    let mut out = Vec::with_capacity(usize::try_from(file_size).unwrap_or(0));
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&0x80u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&SUPERBLOCK_SIZE.to_le_bytes());
    out.extend_from_slice(&(toc.len() as u64).to_le_bytes());
    out.extend_from_slice(&sha256(&toc));
    out.extend_from_slice(&blob_offset.to_le_bytes());
    out.extend_from_slice(&file_size.to_le_bytes());
    out.extend_from_slice(&u32::try_from(records.len()).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&uuid_of(&records));
    out.resize(0x80, 0);
    out.extend_from_slice(&toc);
    out.resize(usize::try_from(blob_offset).unwrap_or(0), 0);
    out.extend_from_slice(&blob);
    out
}
