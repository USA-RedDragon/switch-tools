//! XCI, the game card image: a card header followed by a root HFS0 whose
//! entries are the partitions (`update`, `normal`, `secure`, `logo`), each
//! an HFS0 of its own. The game NCAs sit in `secure`, encrypted with the
//! key area and no rights ID.
//!
//! Layout read here: an optional 0x200-byte key area prefix some dumps carry
//! (found by `HEAD` at 0x300 instead of 0x100), then the 0x100-byte
//! signature, the `HEAD` header up to 0x200, and the root HFS0 at the offset
//! the header names (0xF000 on cards). Field offsets follow the switchbrew
//! XCI page and LibHac's `XciHeader` (MIT, (c) 2018 Alex Barney). The
//! encrypted card-info block (0x190..0x200) is kept raw; nothing here needs
//! the key that opens it.
//!
//! The root header hash is the plain SHA-256 of the root HFS0 header. Cards
//! whose (encrypted) compatibility type is non-zero salt that hash with one
//! more byte; since the type is only readable with the XCI header key, such
//! an image fails the root hash check with [`Error::Hash`] here.

use std::sync::Arc;

use crate::bytes::{array, u8_at, u32_at, u64_at};
use crate::cnmt::Cnmt;
use crate::crypto::sha256;
use crate::error::{Error, Result, malformed};
use crate::hfs0::{self, Hfs0, Hfs0Entry};
use crate::keys::{Keys, TitleKeys};
use crate::nca::{ContentType, Nca};
use crate::storage::{Shared, SubStorage, read_vec};
use crate::title::open_pfs0_section;

/// The size of the optional key area prefix.
pub const KEY_AREA_SIZE: u64 = 0x200;

/// The size of the card header including its signature.
pub const HEADER_SIZE: u64 = 0x200;

/// Where the root HFS0 sits on cards, and in fixtures.
pub const ROOT_OFFSET: u64 = 0xF000;

/// The card header, every field as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XciHeader {
    /// The RSA-2048 signature over the header bytes 0x100..0x200.
    pub signature: [u8; 0x100],
    /// The first page of the ROM area.
    pub rom_area_start_page: u32,
    /// The first page of the backup area.
    pub backup_area_start_page: u32,
    /// The key index byte (KEK index in the high nibble, title key
    /// decryption index in the low).
    pub key_index: u8,
    /// The ROM size byte (see [`XciHeader::declared_size`]).
    pub rom_size: u8,
    /// The card header version.
    pub header_version: u8,
    /// The card flags.
    pub flags: u8,
    /// The package ID.
    pub package_id: u64,
    /// The last page holding valid data.
    pub valid_data_end_page: u64,
    /// The AES-CBC IV of the encrypted block, as stored (byte-reversed
    /// relative to the IV the cipher takes).
    pub iv: [u8; 0x10],
    /// The offset of the root HFS0 from the `HEAD` file start.
    pub root_offset: u64,
    /// The size of the root HFS0 header.
    pub root_header_size: u64,
    /// SHA-256 of the root HFS0 header.
    pub root_header_hash: [u8; 32],
    /// SHA-256 of the card's initial data.
    pub initial_data_hash: [u8; 32],
    /// The `SelSec` field.
    pub sel_sec: u32,
    /// The `SelT1Key` field.
    pub sel_t1_key: u32,
    /// The `SelKey` field.
    pub sel_key: u32,
    /// The first page of the limited area.
    pub lim_area_page: u32,
    /// The card-info block, still encrypted with the XCI header key.
    pub encrypted_info: [u8; 0x70],
}

impl XciHeader {
    /// Parse the 0x200 bytes of a card header.
    ///
    /// # Errors
    ///
    /// Too short, or no `HEAD` magic.
    pub fn parse(b: &[u8]) -> Result<XciHeader> {
        const W: &str = "XCI header";
        if b.len() < HEADER_SIZE as usize {
            return malformed("XCI header: shorter than 0x200 bytes");
        }
        if &b[0x100..0x104] != b"HEAD" {
            return malformed("XCI header: bad magic (not an XCI)");
        }
        Ok(XciHeader {
            signature: array(b, 0, W)?,
            rom_area_start_page: u32_at(b, 0x104, W)?,
            backup_area_start_page: u32_at(b, 0x108, W)?,
            key_index: u8_at(b, 0x10C, W)?,
            rom_size: u8_at(b, 0x10D, W)?,
            header_version: u8_at(b, 0x10E, W)?,
            flags: u8_at(b, 0x10F, W)?,
            package_id: u64_at(b, 0x110, W)?,
            valid_data_end_page: u64_at(b, 0x118, W)?,
            iv: array(b, 0x120, W)?,
            root_offset: u64_at(b, 0x130, W)?,
            root_header_size: u64_at(b, 0x138, W)?,
            root_header_hash: array(b, 0x140, W)?,
            initial_data_hash: array(b, 0x160, W)?,
            sel_sec: u32_at(b, 0x180, W)?,
            sel_t1_key: u32_at(b, 0x184, W)?,
            sel_key: u32_at(b, 0x188, W)?,
            lim_area_page: u32_at(b, 0x18C, W)?,
            encrypted_info: array(b, 0x190, W)?,
        })
    }

    /// The 0x200 stored bytes (parse's inverse).
    pub fn to_bytes(&self) -> [u8; 0x200] {
        let mut b = [0u8; 0x200];
        b[..0x100].copy_from_slice(&self.signature);
        b[0x100..0x104].copy_from_slice(b"HEAD");
        b[0x104..0x108].copy_from_slice(&self.rom_area_start_page.to_le_bytes());
        b[0x108..0x10C].copy_from_slice(&self.backup_area_start_page.to_le_bytes());
        b[0x10C] = self.key_index;
        b[0x10D] = self.rom_size;
        b[0x10E] = self.header_version;
        b[0x10F] = self.flags;
        b[0x110..0x118].copy_from_slice(&self.package_id.to_le_bytes());
        b[0x118..0x120].copy_from_slice(&self.valid_data_end_page.to_le_bytes());
        b[0x120..0x130].copy_from_slice(&self.iv);
        b[0x130..0x138].copy_from_slice(&self.root_offset.to_le_bytes());
        b[0x138..0x140].copy_from_slice(&self.root_header_size.to_le_bytes());
        b[0x140..0x160].copy_from_slice(&self.root_header_hash);
        b[0x160..0x180].copy_from_slice(&self.initial_data_hash);
        b[0x180..0x184].copy_from_slice(&self.sel_sec.to_le_bytes());
        b[0x184..0x188].copy_from_slice(&self.sel_t1_key.to_le_bytes());
        b[0x188..0x18C].copy_from_slice(&self.sel_key.to_le_bytes());
        b[0x18C..0x190].copy_from_slice(&self.lim_area_page.to_le_bytes());
        b[0x190..].copy_from_slice(&self.encrypted_info);
        b
    }

    /// The card size the ROM size byte declares, if it is a known one.
    pub fn declared_size(&self) -> Option<u64> {
        const GIB: u64 = 1 << 30;
        match self.rom_size {
            0xFA => Some(GIB),
            0xF8 => Some(2 * GIB),
            0xF0 => Some(4 * GIB),
            0xE0 => Some(8 * GIB),
            0xE1 => Some(16 * GIB),
            0xE2 => Some(32 * GIB),
            _ => None,
        }
    }

    /// The ROM size as a name (`1GiB`, ...), if known.
    pub fn declared_size_name(&self) -> Option<&'static str> {
        match self.rom_size {
            0xFA => Some("1GiB"),
            0xF8 => Some("2GiB"),
            0xF0 => Some("4GiB"),
            0xE0 => Some("8GiB"),
            0xE1 => Some("16GiB"),
            0xE2 => Some("32GiB"),
            _ => None,
        }
    }
}

/// An opened XCI.
pub struct Xci {
    header: XciHeader,
    key_area: Option<Vec<u8>>,
    trimmed: bool,
    root: Hfs0,
    title_keys: TitleKeys,
}

impl Xci {
    /// Open an XCI held in `storage`: parse the card header, check the root
    /// HFS0 header hash and every root entry's hash.
    ///
    /// # Errors
    ///
    /// No `HEAD` magic at 0x100 or 0x300, a root HFS0 outside the file, or
    /// [`Error::Hash`] for the root header or a partition's header.
    pub fn open(storage: Shared) -> Result<Xci> {
        let size = storage.size();
        let magic_at = |at: u64| -> Result<bool> {
            if size < at + 4 {
                return Ok(false);
            }
            Ok(&read_vec(&*storage, at, 4)?[..] == b"HEAD")
        };
        let prefix = if magic_at(0x100)? {
            0
        } else if magic_at(KEY_AREA_SIZE + 0x100)? {
            KEY_AREA_SIZE
        } else {
            return malformed("XCI: no HEAD magic at 0x100 or 0x300 (not an XCI)");
        };
        let key_area = if prefix > 0 {
            Some(read_vec(&*storage, 0, prefix)?)
        } else {
            None
        };
        let body: Shared = SubStorage::shared(storage, prefix, size - prefix)?;
        if body.size() < HEADER_SIZE {
            return malformed("XCI: shorter than the card header");
        }
        let header = XciHeader::parse(&read_vec(&*body, 0, HEADER_SIZE)?)?;
        let root_end = header
            .root_offset
            .checked_add(header.root_header_size)
            .filter(|e| *e <= body.size() && header.root_offset >= HEADER_SIZE);
        if root_end.is_none() {
            return malformed("XCI: root HFS0 header runs outside the file");
        }
        let root_header = read_vec(&*body, header.root_offset, header.root_header_size)?;
        if sha256(&root_header) != header.root_header_hash {
            return Err(Error::Hash(
                "XCI: root HFS0 header does not match the card header's hash".into(),
            ));
        }
        let root_storage = SubStorage::shared(
            body.clone(),
            header.root_offset,
            body.size() - header.root_offset,
        )?;
        let root = Hfs0::open(root_storage)?;
        if root.header_size() != header.root_header_size {
            return malformed("XCI: root HFS0 header size differs from the card header's");
        }
        let trimmed = header.declared_size().is_some_and(|d| body.size() < d);
        Ok(Xci {
            header,
            key_area,
            trimmed,
            root,
            title_keys: TitleKeys::default(),
        })
    }

    /// The card header.
    pub fn header(&self) -> &XciHeader {
        &self.header
    }

    /// The 0x200-byte key area prefix, if the dump carries one.
    pub fn key_area(&self) -> Option<&[u8]> {
        self.key_area.as_deref()
    }

    /// Whether the file is shorter than the size its ROM size byte declares.
    pub fn trimmed(&self) -> bool {
        self.trimmed
    }

    /// The root HFS0.
    pub fn root(&self) -> &Hfs0 {
        &self.root
    }

    /// The partitions (root entries), in card order.
    pub fn partitions(&self) -> &[Hfs0Entry] {
        self.root.entries()
    }

    /// Open the partition `name`, every file's hashed region verified.
    ///
    /// # Errors
    ///
    /// No such partition, a malformed HFS0, or [`Error::Hash`] naming the
    /// partition and file.
    pub fn partition(&self, name: &str) -> Result<Hfs0> {
        let Some(e) = self.root.find(name) else {
            return malformed(format!("XCI has no {name} partition"));
        };
        Hfs0::open(self.root.open_entry(e)?).map_err(|err| prefix(name, err))
    }

    /// No tickets live on cards: always empty (the signature matches
    /// [`crate::title::Nsp::title_keys`]).
    pub fn title_keys(&self) -> &TitleKeys {
        &self.title_keys
    }

    /// Open the header of every NCA in the secure partition, including the
    /// `.ncz` entries of an XCZ.
    ///
    /// # Errors
    ///
    /// No secure partition, or a header does not decrypt.
    pub fn ncas(&self, keys: &Keys) -> Result<Vec<(String, Nca)>> {
        let secure = self.partition("secure")?;
        let mut out = Vec::new();
        for e in secure.entries() {
            if e.name.ends_with(".nca") || e.name.ends_with(".ncz") {
                let raw = secure.open_entry(e)?;
                let raw = if e.name.ends_with(".ncz") {
                    crate::ncz::Ncz::open(raw)
                        .map_err(|err| prefix(&e.name, err))?
                        .to_encrypted_storage()
                } else {
                    raw
                };
                let nca =
                    Nca::open(raw, keys, &self.title_keys).map_err(|err| prefix(&e.name, err))?;
                out.push((e.name.clone(), nca));
            }
        }
        Ok(out)
    }

    /// The program NCA.
    ///
    /// # Errors
    ///
    /// None or several, or a header error.
    pub fn program(&self, keys: &Keys) -> Result<Nca> {
        let mut found: Vec<Nca> = self
            .ncas(keys)?
            .into_iter()
            .filter(|(_, n)| n.header().content_type() == ContentType::Program)
            .map(|(_, n)| n)
            .collect();
        if found.len() != 1 {
            return malformed(format!("XCI holds {} program NCAs, want 1", found.len()));
        }
        Ok(found.remove(0))
    }

    /// The content meta, from the meta NCA.
    ///
    /// # Errors
    ///
    /// No meta NCA or no `.cnmt` inside.
    pub fn cnmt(&self, keys: &Keys) -> Result<Cnmt> {
        for (_, nca) in self.ncas(keys)? {
            if nca.header().content_type() == ContentType::Meta {
                let exefs = open_pfs0_section(&nca, 0, keys, &self.title_keys)?;
                for e in exefs.entries() {
                    if e.name.ends_with(".cnmt") {
                        return Cnmt::parse(&exefs.read(e)?);
                    }
                }
            }
        }
        malformed("XCI has no content meta")
    }
}

fn prefix(name: &str, e: Error) -> Error {
    match e {
        Error::Format(m) => Error::Format(format!("{name}: {m}")),
        Error::MissingKey(m) => Error::MissingKey(format!("{name}: {m}")),
        Error::WrongKey(m) => Error::WrongKey(format!("{name}: {m}")),
        Error::Hash(m) => Error::Hash(format!("{name}: {m}")),
        Error::Unsupported(m) => Error::Unsupported(format!("{name}: {m}")),
        other => other,
    }
}

/// The header a fixture XCI carries for a root HFS0 of `root_header` bytes
/// (a 1 GiB card, unsigned, card-info block zero).
fn fixture_header(root_header: &[u8], total: u64) -> XciHeader {
    XciHeader {
        signature: [0x5A; 0x100],
        rom_area_start_page: 0x100,
        backup_area_start_page: 0xFFFF_FFFF,
        key_index: 0x10,
        rom_size: 0xFA,
        header_version: 1,
        flags: 0,
        package_id: 0x0123_4567_89AB_CDEF,
        valid_data_end_page: (total / 0x200).saturating_sub(1),
        iv: [0x11; 0x10],
        root_offset: ROOT_OFFSET,
        root_header_size: root_header.len() as u64,
        root_header_hash: sha256(root_header),
        initial_data_hash: [0x22; 32],
        sel_sec: 1,
        sel_t1_key: 2,
        sel_key: 3,
        lim_area_page: 0x38D,
        encrypted_info: [0x33; 0x70],
    }
}

/// A partition for [`build`]: its name and its files.
pub type PartitionSpec<'a> = (&'a str, Vec<(&'a str, &'a [u8])>);

/// Build an XCI of `partitions` (name and files), with the root HFS0 at
/// 0xF000 and, if `key_area`, a 0x200-byte prefix (for fixtures).
pub fn build(partitions: &[PartitionSpec<'_>], key_area: bool) -> Vec<u8> {
    let children: Vec<Vec<u8>> = partitions.iter().map(|(_, f)| hfs0::build(f)).collect();
    let root_files: Vec<(&str, &[u8], u32)> = partitions
        .iter()
        .zip(&children)
        .map(|((n, _), c)| {
            let hdr = hfs0::header_len(c).unwrap_or(0);
            (*n, c.as_slice(), u32::try_from(hdr).unwrap_or(0))
        })
        .collect();
    let root = hfs0::build_hashed(&root_files);
    let root_header_len = hfs0::header_len(&root).unwrap_or(0);
    let root_header = &root[..usize::try_from(root_header_len).unwrap_or(0)];
    let total = ROOT_OFFSET + root.len() as u64;
    let mut out = Vec::new();
    if key_area {
        out.extend((0..KEY_AREA_SIZE).map(|i| (i as u8).wrapping_mul(7) | 1));
    }
    out.extend_from_slice(&fixture_header(root_header, total).to_bytes());
    out.resize(out.len() + (ROOT_OFFSET - HEADER_SIZE) as usize, 0);
    out.extend_from_slice(&root);
    out
}

impl Xci {
    /// Open an XCI file.
    ///
    /// # Errors
    ///
    /// As [`Xci::open`], or the file cannot be opened.
    pub fn open_path(path: &std::path::Path) -> Result<Xci> {
        Xci::open(Arc::new(crate::storage::FileStorage::open(path)?))
    }
}

impl crate::title::Package for Xci {
    fn program(&self, keys: &Keys) -> Result<Nca> {
        Xci::program(self, keys)
    }

    fn cnmt(&self, keys: &Keys) -> Result<Cnmt> {
        Xci::cnmt(self, keys)
    }

    fn title_keys(&self) -> &TitleKeys {
        Xci::title_keys(self)
    }

    fn ncas(&self, keys: &Keys) -> Result<Vec<(String, Nca)>> {
        Xci::ncas(self, keys)
    }

    fn add_title_keys(&mut self, extra: &TitleKeys) {
        self.title_keys.extend(extra);
    }
}
