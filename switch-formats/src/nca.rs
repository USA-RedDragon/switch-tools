//! NCA content archives: the AES-XTS header, the key area or title key, and
//! the AES-CTR sections.

use std::sync::Arc;

use crate::bytes::{array, hex, u32_at, u64_at};
use crate::crypto::{ctr_apply, ecb_decrypt_block, sha256, xts_decrypt};
use crate::error::{Error, Result, malformed};
use crate::keys::{KeyAreaKind, Keys, TitleKeys};
use crate::storage::{Shared, Storage, SubStorage, check_range, read_vec};

/// The size of the encrypted NCA header.
pub const HEADER_SIZE: usize = 0xC00;
/// The size of one section's FS header.
pub const FS_HEADER_SIZE: usize = 0x200;
/// Section offsets in the header count these units.
pub const MEDIA_UNIT: u64 = 0x200;

/// What an NCA holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentType {
    /// Code (exefs), data (romfs) and logo.
    Program,
    /// The content meta (CNMT).
    Meta,
    /// Icon and NACP.
    Control,
    /// Manual or legal HTML.
    Manual,
    /// Data.
    Data,
    /// Public data.
    PublicData,
}

impl ContentType {
    fn from_byte(b: u8) -> Result<ContentType> {
        Ok(match b {
            0 => ContentType::Program,
            1 => ContentType::Meta,
            2 => ContentType::Control,
            3 => ContentType::Manual,
            4 => ContentType::Data,
            5 => ContentType::PublicData,
            _ => return malformed(format!("NCA: unknown content type {b}")),
        })
    }

    /// A lowercase name.
    pub fn name(self) -> &'static str {
        match self {
            ContentType::Program => "program",
            ContentType::Meta => "meta",
            ContentType::Control => "control",
            ContentType::Manual => "manual",
            ContentType::Data => "data",
            ContentType::PublicData => "public-data",
        }
    }
}

/// How a section's integrity is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashType {
    /// Not hashed.
    None,
    /// Two-level SHA-256 (exefs and other PFS0 sections).
    HierarchicalSha256,
    /// IVFC (romfs).
    Ivfc,
}

/// How a section is encrypted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encryption {
    /// Plain.
    None,
    /// AES-XTS.
    Xts,
    /// AES-CTR.
    Ctr,
    /// AES-CTR with per-region generations (update patches, BKTR).
    CtrEx,
}

/// A section's FS header (decrypted).
#[derive(Clone)]
pub struct FsHeader {
    raw: [u8; FS_HEADER_SIZE],
}

impl FsHeader {
    /// Wrap a raw FS header.
    pub fn from_raw(raw: [u8; FS_HEADER_SIZE]) -> FsHeader {
        FsHeader { raw }
    }

    /// The raw bytes.
    pub fn raw(&self) -> &[u8; FS_HEADER_SIZE] {
        &self.raw
    }

    /// 0 romfs, 1 PFS0.
    pub fn format_type(&self) -> u8 {
        self.raw[2]
    }

    /// The hash type.
    ///
    /// # Errors
    ///
    /// An unknown value.
    pub fn hash_type(&self) -> Result<HashType> {
        match self.raw[3] {
            1 => Ok(HashType::None),
            2 => Ok(HashType::HierarchicalSha256),
            3 => Ok(HashType::Ivfc),
            t => Err(Error::Unsupported(format!("NCA section hash type {t}"))),
        }
    }

    /// The encryption type.
    ///
    /// # Errors
    ///
    /// An unknown value.
    pub fn encryption(&self) -> Result<Encryption> {
        match self.raw[4] {
            1 => Ok(Encryption::None),
            2 => Ok(Encryption::Xts),
            3 => Ok(Encryption::Ctr),
            4 => Ok(Encryption::CtrEx),
            t => Err(Error::Unsupported(format!(
                "NCA section encryption type {t}"
            ))),
        }
    }

    /// The integrity info block (0xF8 bytes at 0x8).
    pub fn integrity_info(&self) -> &[u8] {
        &self.raw[0x8..0x100]
    }

    /// The patch info block (0x40 bytes at 0x100).
    pub fn patch_info(&self) -> &[u8] {
        &self.raw[0x100..0x140]
    }

    /// The upper half of the AES-CTR counter, big-endian as the counter
    /// block holds it.
    pub fn counter_upper(&self) -> [u8; 8] {
        let mut v = [0u8; 8];
        v.copy_from_slice(&self.raw[0x140..0x148]);
        v.reverse();
        v
    }

    /// Whether a sparse layer is present (unsupported here).
    pub fn has_sparse_layer(&self) -> bool {
        self.raw[0x148..0x178].iter().any(|&b| b != 0)
    }

    /// Whether a compression layer is present (unsupported here).
    pub fn has_compression_layer(&self) -> bool {
        self.raw[0x178..0x1A0].iter().any(|&b| b != 0)
    }
}

/// A decrypted NCA header.
#[derive(Clone)]
pub struct NcaHeader {
    raw: Box<[u8; HEADER_SIZE]>,
    stored_plain: bool,
}

impl NcaHeader {
    /// Decrypt and parse the header at the start of `encrypted`. A header
    /// that is already plaintext (some dump tools write NCAs with the
    /// header decrypted and the sections still encrypted) is taken as it
    /// is: its magic is readable at 0x200, which an encrypted header shows
    /// with odds of 2^-32.
    ///
    /// # Errors
    ///
    /// A short input, a wrong `header_key` (no NCA magic after decryption),
    /// NCA0/NCA2, or an FS header whose hash does not match.
    pub fn decrypt(header_key: &[u8; 32], encrypted: &[u8]) -> Result<NcaHeader> {
        let Some(head) = encrypted.get(..HEADER_SIZE) else {
            return malformed("NCA: shorter than its header");
        };
        let mut raw = Box::new([0u8; HEADER_SIZE]);
        raw.copy_from_slice(head);
        let stored_plain = matches!(&raw[0x200..0x204], b"NCA3" | b"NCA2" | b"NCA0");
        if !stored_plain {
            xts_decrypt(header_key, &mut raw[..], 0);
        }
        let magic = &raw[0x200..0x204];
        if magic == b"NCA2" || magic == b"NCA0" {
            return Err(Error::Unsupported(format!(
                "NCA format {}: only NCA3 is supported",
                String::from_utf8_lossy(magic)
            )));
        }
        if magic != b"NCA3" {
            return Err(Error::WrongKey(
                "NCA header did not decrypt (wrong header_key, or not an NCA)".into(),
            ));
        }
        let h = NcaHeader { raw, stored_plain };
        for i in 0..4 {
            if h.section(i).is_some() {
                let want = &h.raw[0x280 + i * 0x20..0x2A0 + i * 0x20];
                if sha256(h.fs_header(i).raw()) != want {
                    return Err(Error::Hash(format!("NCA FS header {i}")));
                }
            }
        }
        ContentType::from_byte(h.raw[0x205])?;
        KeyAreaKind::from_index(h.raw[0x207])?;
        Ok(h)
    }

    /// The decrypted header bytes.
    pub fn raw(&self) -> &[u8; HEADER_SIZE] {
        &self.raw
    }

    /// Whether the header was stored already decrypted.
    pub fn stored_plain(&self) -> bool {
        self.stored_plain
    }

    /// 0 download, 1 game card.
    pub fn distribution(&self) -> u8 {
        self.raw[0x204]
    }

    /// The content type.
    pub fn content_type(&self) -> ContentType {
        ContentType::from_byte(self.raw[0x205]).unwrap_or(ContentType::Data)
    }

    /// The key generation (the larger of the two header fields).
    pub fn key_generation(&self) -> u8 {
        self.raw[0x206].max(self.raw[0x220])
    }

    /// The master key revision the keys of this NCA belong to.
    pub fn master_key_revision(&self) -> u8 {
        self.key_generation().saturating_sub(1)
    }

    /// The key-area key family.
    pub fn key_area_kind(&self) -> KeyAreaKind {
        KeyAreaKind::from_index(self.raw[0x207]).unwrap_or(KeyAreaKind::Application)
    }

    /// The NCA size the header records.
    pub fn nca_size(&self) -> u64 {
        u64::from_le_bytes(array(&self.raw[..], 0x208, "NCA").unwrap_or_default())
    }

    /// The program (title) ID.
    pub fn program_id(&self) -> u64 {
        u64::from_le_bytes(array(&self.raw[..], 0x210, "NCA").unwrap_or_default())
    }

    /// The content index.
    pub fn content_index(&self) -> u32 {
        u32_at(&self.raw[..], 0x218, "NCA").unwrap_or_default()
    }

    /// The SDK version.
    pub fn sdk_version(&self) -> u32 {
        u32_at(&self.raw[..], 0x21C, "NCA").unwrap_or_default()
    }

    /// The rights ID, if the content key is a title key.
    pub fn rights_id(&self) -> Option<[u8; 16]> {
        let r: [u8; 16] = array(&self.raw[..], 0x230, "NCA").unwrap_or_default();
        r.iter().any(|&b| b != 0).then_some(r)
    }

    /// Section `i`'s byte range in the NCA, if present.
    pub fn section(&self, i: usize) -> Option<(u64, u64)> {
        if i >= 4 {
            return None;
        }
        let start = u64::from(u32_at(&self.raw[..], 0x240 + i * 0x10, "NCA").ok()?);
        let end = u64::from(u32_at(&self.raw[..], 0x244 + i * 0x10, "NCA").ok()?);
        (end > start).then_some((start * MEDIA_UNIT, (end - start) * MEDIA_UNIT))
    }

    /// Section `i`'s FS header.
    pub fn fs_header(&self, i: usize) -> FsHeader {
        let mut raw = [0u8; FS_HEADER_SIZE];
        let at = 0x400 + (i % 4) * FS_HEADER_SIZE;
        raw.copy_from_slice(&self.raw[at..at + FS_HEADER_SIZE]);
        FsHeader { raw }
    }

    /// The encrypted key-area entry `i`.
    fn key_area(&self, i: usize) -> [u8; 16] {
        array(&self.raw[..], 0x300 + i * 0x10, "NCA").unwrap_or_default()
    }
}

/// An opened NCA with its content key resolved.
pub struct Nca {
    storage: Shared,
    header: NcaHeader,
    key: Option<[u8; 16]>,
}

impl Nca {
    /// Decrypt the header and resolve the AES-CTR content key: the title key
    /// for the header's rights ID if it has one, else key-area entry 2.
    ///
    /// # Errors
    ///
    /// Header errors, a missing `header_key`, key-area key, titlekek or title
    /// key. A missing content key is only an error when a section needs it,
    /// so headers of any NCA can be shown without title keys.
    pub fn open(storage: Shared, keys: &Keys, title_keys: &TitleKeys) -> Result<Nca> {
        let head = read_vec(
            &*storage,
            0,
            HEADER_SIZE.min(storage.size() as usize) as u64,
        )?;
        let header = NcaHeader::decrypt(&keys.header_key()?, &head)?;
        if header.nca_size() > storage.size() {
            return malformed(format!(
                "NCA: header records {:#x} bytes, file has {:#x}",
                header.nca_size(),
                storage.size()
            ));
        }
        let key = content_key(&header, keys, title_keys).ok();
        Ok(Nca {
            storage,
            header,
            key,
        })
    }

    /// The header.
    pub fn header(&self) -> &NcaHeader {
        &self.header
    }

    /// The content key, or the error saying why it is missing.
    ///
    /// # Errors
    ///
    /// As [`content_key`].
    pub fn key(&self, keys: &Keys, title_keys: &TitleKeys) -> Result<[u8; 16]> {
        match self.key {
            Some(k) => Ok(k),
            None => content_key(&self.header, keys, title_keys),
        }
    }

    /// Section `i` decrypted, hash levels included, before any patch is
    /// applied. For an AES-CTR-EX section this is the patch data region
    /// only (the bucket tables are read with [`Nca::section_table`]).
    ///
    /// # Errors
    ///
    /// No such section, an unsupported layer, or a missing key.
    pub fn section_raw(&self, i: usize, keys: &Keys, title_keys: &TitleKeys) -> Result<Shared> {
        let (offset, size) = self
            .header
            .section(i)
            .ok_or_else(|| Error::Format(format!("NCA has no section {i}")))?;
        let fs = self.header.fs_header(i);
        if fs.has_sparse_layer() {
            return Err(Error::Unsupported(format!(
                "NCA section {i} has a sparse layer"
            )));
        }
        if fs.has_compression_layer() {
            return Err(Error::Unsupported(format!(
                "NCA section {i} has a compression layer"
            )));
        }
        let body = SubStorage::shared(self.storage.clone(), offset, size)?;
        match fs.encryption()? {
            Encryption::None => Ok(body),
            Encryption::Xts => Err(Error::Unsupported(format!(
                "NCA section {i} is AES-XTS encrypted"
            ))),
            Encryption::Ctr if self.header.stored_plain && top_hash_matches(&fs, &*body)? => {
                Ok(body)
            }
            Encryption::Ctr => Ok(Arc::new(CtrStorage {
                base: body,
                key: self.key(keys, title_keys)?,
                upper: fs.counter_upper(),
                stream_offset: offset,
            })),
            Encryption::CtrEx => {
                let patch = crate::bktr::PatchInfo::parse(&fs)?;
                let key = self.key(keys, title_keys)?;
                let tables = Arc::new(CtrStorage {
                    base: body.clone(),
                    key,
                    upper: fs.counter_upper(),
                    stream_offset: offset,
                });
                let entries = crate::bktr::read_ctr_ex_table(&*tables, &patch)?;
                let data = SubStorage::shared(body, 0, patch.relocation_offset)?;
                Ok(Arc::new(crate::bktr::CtrExStorage::new(
                    data,
                    key,
                    fs.counter_upper(),
                    offset,
                    entries,
                )?))
            }
        }
    }

    /// Section `i` decrypted with the plain AES-CTR counter over its whole
    /// range, which is how BKTR bucket tables are stored.
    ///
    /// # Errors
    ///
    /// As [`Nca::section_raw`].
    pub fn section_table(&self, i: usize, keys: &Keys, title_keys: &TitleKeys) -> Result<Shared> {
        let (offset, size) = self
            .header
            .section(i)
            .ok_or_else(|| Error::Format(format!("NCA has no section {i}")))?;
        let fs = self.header.fs_header(i);
        Ok(Arc::new(CtrStorage {
            base: SubStorage::shared(self.storage.clone(), offset, size)?,
            key: self.key(keys, title_keys)?,
            upper: fs.counter_upper(),
            stream_offset: offset,
        }))
    }
}

/// Whether a section's stored bytes already pass its top hash: the first
/// block of the hash table (SHA-256 sections) or of IVFC level 0. A dump
/// tool that wrote an NCA with its header decrypted may have decrypted the
/// sections as well while leaving their encryption type in place.
fn top_hash_matches(fs: &FsHeader, body: &dyn Storage) -> Result<bool> {
    use crate::integrity::{IvfcInfo, Sha256Info};
    match fs.hash_type()? {
        HashType::HierarchicalSha256 => {
            let info = Sha256Info::parse(fs)?;
            if info.table.0 + info.table.1 > body.size() {
                return Ok(false);
            }
            Ok(sha256(&read_vec(body, info.table.0, info.table.1)?) == info.master)
        }
        HashType::Ivfc => {
            let info = IvfcInfo::parse(fs)?;
            let Some(l) = info.levels.first() else {
                return Ok(false);
            };
            if l.block_log2 > 24 || l.offset + l.size > body.size() {
                return Ok(false);
            }
            let block = 1u64 << l.block_log2;
            let mut b = read_vec(body, l.offset, l.size.min(block))?;
            b.resize(usize::try_from(block).unwrap_or(0), 0);
            Ok(info.master.get(..32) == Some(&sha256(&b)[..]))
        }
        HashType::None => Ok(false),
    }
}

/// Resolve the AES-CTR content key of an NCA.
///
/// # Errors
///
/// A missing title key for the rights ID, titlekek or key-area key.
pub fn content_key(header: &NcaHeader, keys: &Keys, title_keys: &TitleKeys) -> Result<[u8; 16]> {
    let rev = header.master_key_revision();
    match header.rights_id() {
        Some(rights) => {
            let enc = title_keys.get(&rights).ok_or_else(|| {
                Error::MissingKey(format!(
                    "no title key for rights ID {} (no matching ticket)",
                    hex(&rights)
                ))
            })?;
            Ok(ecb_decrypt_block(&keys.titlekek(rev)?, &enc))
        }
        None => {
            let kak = keys.key_area_key(header.key_area_kind(), rev)?;
            Ok(ecb_decrypt_block(&kak, &header.key_area(2)))
        }
    }
}

/// AES-CTR over a section: the counter is the FS header's upper half and
/// the byte's absolute NCA offset divided by 16.
pub struct CtrStorage {
    base: Shared,
    key: [u8; 16],
    upper: [u8; 8],
    stream_offset: u64,
}

impl Storage for CtrStorage {
    fn size(&self) -> u64 {
        self.base.size()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.size(), "AES-CTR section")?;
        self.base.read_at(offset, buf)?;
        ctr_apply(&self.key, self.upper, self.stream_offset + offset, buf);
        Ok(())
    }
}

/// The parts of an NCA header a fixture builder sets.
#[derive(Clone, Debug)]
pub struct HeaderSpec {
    /// The content type.
    pub content_type: ContentType,
    /// The key generation byte (master key revision + 1, or 0).
    pub key_generation: u8,
    /// The key-area key family index.
    pub key_area_index: u8,
    /// The program ID.
    pub program_id: u64,
    /// A rights ID; zero for key-area encryption.
    pub rights_id: [u8; 16],
    /// The four key-area entries, plaintext.
    pub key_area: [[u8; 16]; 4],
}

/// Assemble a plaintext NCA3 header for fixtures: `sections` are
/// `(offset, size, fs_header)` with offsets and sizes in bytes (multiples
/// of 0x200). The key area is encrypted with `key_area_key`.
pub fn build_header(
    spec: &HeaderSpec,
    key_area_key: &[u8; 16],
    nca_size: u64,
    sections: &[(u64, u64, FsHeader)],
) -> [u8; HEADER_SIZE] {
    let mut h = [0u8; HEADER_SIZE];
    h[0x200..0x204].copy_from_slice(b"NCA3");
    h[0x205] = match spec.content_type {
        ContentType::Program => 0,
        ContentType::Meta => 1,
        ContentType::Control => 2,
        ContentType::Manual => 3,
        ContentType::Data => 4,
        ContentType::PublicData => 5,
    };
    h[0x206] = spec.key_generation.min(2);
    h[0x207] = spec.key_area_index;
    h[0x208..0x210].copy_from_slice(&nca_size.to_le_bytes());
    h[0x210..0x218].copy_from_slice(&spec.program_id.to_le_bytes());
    h[0x220] = spec.key_generation;
    h[0x230..0x240].copy_from_slice(&spec.rights_id);
    for (i, (off, size, fs)) in sections.iter().enumerate().take(4) {
        let start = u32::try_from(off / MEDIA_UNIT).unwrap_or(0);
        let end = u32::try_from((off + size) / MEDIA_UNIT).unwrap_or(0);
        h[0x240 + i * 0x10..0x244 + i * 0x10].copy_from_slice(&start.to_le_bytes());
        h[0x244 + i * 0x10..0x248 + i * 0x10].copy_from_slice(&end.to_le_bytes());
        h[0x248 + i * 0x10] = 1;
        h[0x280 + i * 0x20..0x2A0 + i * 0x20].copy_from_slice(&sha256(fs.raw()));
        h[0x400 + i * FS_HEADER_SIZE..0x600 + i * FS_HEADER_SIZE].copy_from_slice(fs.raw());
    }
    for (i, k) in spec.key_area.iter().enumerate() {
        let e = crate::crypto::ecb_encrypt_block(key_area_key, k);
        h[0x300 + i * 0x10..0x310 + i * 0x10].copy_from_slice(&e);
    }
    h
}

/// Build an FS header for fixtures.
pub fn build_fs_header(
    format_type: u8,
    hash_type: u8,
    encryption: u8,
    integrity: &[u8],
    patch_info: &[u8],
    counter_upper_le: u64,
) -> FsHeader {
    let mut raw = [0u8; FS_HEADER_SIZE];
    raw[0..2].copy_from_slice(&2u16.to_le_bytes());
    raw[2] = format_type;
    raw[3] = hash_type;
    raw[4] = encryption;
    let n = integrity.len().min(0xF8);
    raw[0x8..0x8 + n].copy_from_slice(&integrity[..n]);
    let n = patch_info.len().min(0x40);
    raw[0x100..0x100 + n].copy_from_slice(&patch_info[..n]);
    raw[0x140..0x148].copy_from_slice(&counter_upper_le.to_le_bytes());
    FsHeader { raw }
}

/// Read `u8`/`u64` helpers re-exported for sibling modules.
pub(crate) fn fs_u64(fs: &FsHeader, at: usize) -> Result<u64> {
    u64_at(fs.raw(), at, "FS header")
}
