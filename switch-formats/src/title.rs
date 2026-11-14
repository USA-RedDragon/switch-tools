//! A title assembled from packages: the base program, an optional update
//! patched over it with BKTR, the verified exefs and romfs.

use std::path::Path;
use std::sync::Arc;

use crate::bktr::{IndirectStorage, PatchInfo};
use crate::bytes::hex;
use crate::cnmt::Cnmt;
use crate::error::{Error, Result, malformed};
use crate::integrity::{IvfcInfo, Sha256Info, open_ivfc, open_sha256};
use crate::keys::{Keys, TitleKeys};
use crate::nca::{ContentType, Encryption, HashType, Nca};
use crate::ncz::Ncz;
use crate::pfs0::Pfs0;
use crate::romfs::Romfs;
use crate::storage::{FileStorage, Shared, ZeroStorage};
use crate::ticket::{Ticket, TitleKeyType};

/// A package a title is read from: an NSP, NSZ, XCI or XCZ.
pub trait Package {
    /// The program NCA.
    ///
    /// # Errors
    ///
    /// None or several, or a header or ticket error.
    fn program(&self, keys: &Keys) -> Result<Nca>;

    /// The content meta.
    ///
    /// # Errors
    ///
    /// No meta NCA, or it does not read.
    fn cnmt(&self, keys: &Keys) -> Result<Cnmt>;

    /// The common title keys the package carries (empty for cards), plus
    /// any added with [`Package::add_title_keys`].
    fn title_keys(&self) -> &TitleKeys;

    /// Every NCA of the package with its header opened, `.ncz` entries
    /// restored.
    ///
    /// # Errors
    ///
    /// A header does not decrypt.
    fn ncas(&self, keys: &Keys) -> Result<Vec<(String, Nca)>>;

    /// Add title keys from outside the package (a `title.keys` file,
    /// `--ticket`, `--titlekey`); the package's own tickets win.
    fn add_title_keys(&mut self, extra: &TitleKeys);

    /// Unwrap the title keys of the package's personalized tickets with the
    /// eTicket RSA key in `keys`, if it has one; packages without
    /// personalized tickets (cards, common-ticket NSPs) do nothing.
    ///
    /// # Errors
    ///
    /// A ticket belongs to another console ([`Error::WrongKey`]). Without
    /// an eTicket key nothing fails here; [`Package::program`] reports the
    /// missing key for a program that needs one.
    fn unlock_personalized(&mut self, keys: &Keys) -> Result<()> {
        let _ = keys;
        Ok(())
    }

    /// Choose the program of a package that holds several (a multi-title
    /// card, or an application with several programs) by its program id;
    /// an update's program `id | 0x800` matches too. `None` accepts only a
    /// package with one program.
    fn select_program(&mut self, id: Option<u64>);

    /// The program id chosen with [`Package::select_program`].
    fn selected_program(&self) -> Option<u64>;
}

/// Pick the program NCA among `ncas`: the one `select` names (or its
/// update program, `| 0x800`), else the only one.
///
/// # Errors
///
/// No program NCA, several without a choice ([`Error::Ambiguous`] listing
/// their program ids), or a choice that matches none.
pub fn pick_program(ncas: Vec<(String, Nca)>, select: Option<u64>, what: &str) -> Result<Nca> {
    let mut found: Vec<Nca> = ncas
        .into_iter()
        .filter(|(_, n)| n.header().content_type() == ContentType::Program)
        .map(|(_, n)| n)
        .collect();
    let ids = |found: &[Nca]| -> String {
        let mut v: Vec<String> = found
            .iter()
            .map(|n| format!("{:016x}", n.header().program_id()))
            .collect();
        v.sort();
        v.dedup();
        v.join(", ")
    };
    match select {
        _ if found.is_empty() => malformed(format!("{what} holds no program NCA")),
        None if found.len() == 1 => Ok(found.remove(0)),
        None => Err(Error::Ambiguous(format!(
            "{what} holds {} program NCAs ({}); choose one with --title-id",
            found.len(),
            ids(&found)
        ))),
        Some(id) => {
            let at = found
                .iter()
                .position(|n| n.header().program_id() == id)
                .or_else(|| {
                    found
                        .iter()
                        .position(|n| n.header().program_id() == id | 0x800)
                });
            match at {
                Some(i) => Ok(found.remove(i)),
                None => malformed(format!(
                    "{what} holds no program {id:016x}; it holds {}",
                    ids(&found)
                )),
            }
        }
    }
}

/// The content meta of `cnmts` that describes `program_id`: the one with
/// that title id, else the only one.
pub(crate) fn meta_for(cnmts: Vec<Cnmt>, program_id: Option<u64>, what: &str) -> Result<Cnmt> {
    let mut cnmts = cnmts;
    if let Some(id) = program_id
        && let Some(i) = cnmts
            .iter()
            .position(|c| c.title_id == id)
            .or_else(|| cnmts.iter().position(|c| c.title_id == id | 0x800))
    {
        return Ok(cnmts.remove(i));
    }
    if cnmts.is_empty() {
        return malformed(format!("{what} has no content meta"));
    }
    Ok(cnmts.remove(0))
}

/// Every content meta of a package: one per meta NCA (a package may hold
/// several titles, such as a bundle of add-ons).
///
/// # Errors
///
/// A meta NCA does not decrypt or holds no `.cnmt`.
pub fn cnmts(package: &dyn Package, keys: &Keys) -> Result<Vec<Cnmt>> {
    let mut out = Vec::new();
    for (name, nca) in package.ncas(keys)? {
        if nca.header().content_type() != ContentType::Meta {
            continue;
        }
        let pfs =
            open_pfs0_section(&nca, 0, keys, package.title_keys()).map_err(|e| prefix(&name, e))?;
        let Some(e) = pfs.entries().iter().find(|e| e.name.ends_with(".cnmt")) else {
            return malformed(format!("{name}: meta NCA holds no .cnmt"));
        };
        out.push(Cnmt::parse(&pfs.read(e)?)?);
    }
    Ok(out)
}

/// Open the first IVFC section of an NCA as a romfs, verified: the data of
/// an add-on (section 0) or of a control NCA. Program NCAs, whose romfs is
/// section 1, go through [`open_romfs`].
///
/// # Errors
///
/// No IVFC section, a wrong key, a hash mismatch or a malformed romfs.
pub fn open_section_romfs(nca: &Nca, keys: &Keys, tk: &TitleKeys) -> Result<Romfs> {
    for i in 0..4 {
        if nca.header().section(i).is_none() {
            continue;
        }
        let fs = nca.header().fs_header(i);
        if fs.hash_type()? == HashType::Ivfc {
            let raw = nca.section_raw(i, keys, tk)?;
            let data: Shared = open_ivfc(raw, &IvfcInfo::parse(&fs)?, "romfs")?;
            return Romfs::open(data);
        }
    }
    malformed("NCA has no romfs (IVFC) section")
}

/// Open a package by its magic: a PFS0 is an NSP (or an NSZ, whose `.ncz`
/// entries are restored on read), a card header is an XCI (or an XCZ).
///
/// # Errors
///
/// An unknown file type, or the container does not open.
pub fn open_package(storage: Shared) -> Result<Box<dyn Package>> {
    let size = storage.size();
    let magic = |at: u64| -> Result<[u8; 4]> {
        let mut m = [0u8; 4];
        if size >= at + 4 {
            storage.read_at(at, &mut m)?;
        }
        Ok(m)
    };
    if &magic(0)? == b"PFS0" {
        return Ok(Box::new(Nsp::from_storage(storage)?));
    }
    if &magic(0x100)? == b"HEAD" || &magic(0x300)? == b"HEAD" {
        return Ok(Box::new(crate::xci::Xci::open(storage)?));
    }
    Err(Error::Unsupported(
        "unknown file type: not an NSP, NSZ, XCI or XCZ".into(),
    ))
}

/// Open a package file, as [`open_package`].
///
/// # Errors
///
/// The file cannot be opened, or as [`open_package`].
pub fn open_package_path(path: &Path) -> Result<Box<dyn Package>> {
    open_package(Arc::new(FileStorage::open(path)?))
        .map_err(|e| prefix(&path.display().to_string(), e))
}

impl Package for Nsp {
    fn program(&self, keys: &Keys) -> Result<Nca> {
        Nsp::program(self, keys)
    }

    fn cnmt(&self, keys: &Keys) -> Result<Cnmt> {
        Nsp::cnmt(self, keys)
    }

    fn title_keys(&self) -> &TitleKeys {
        Nsp::title_keys(self)
    }

    fn ncas(&self, keys: &Keys) -> Result<Vec<(String, Nca)>> {
        Nsp::ncas(self, keys)
    }

    fn add_title_keys(&mut self, extra: &TitleKeys) {
        let mut merged = extra.clone();
        merged.extend(&self.title_keys);
        self.title_keys = merged;
    }

    fn unlock_personalized(&mut self, keys: &Keys) -> Result<()> {
        Nsp::unlock_personalized(self, keys)
    }

    fn select_program(&mut self, id: Option<u64>) {
        self.select = id;
    }

    fn selected_program(&self) -> Option<u64> {
        self.select
    }
}

/// An NSP opened with its tickets read.
pub struct Nsp {
    pfs: Pfs0,
    title_keys: TitleKeys,
    personalized: Vec<Ticket>,
    select: Option<u64>,
}

impl Nsp {
    /// Open an NSP file.
    ///
    /// # Errors
    ///
    /// Not a PFS0, or a ticket does not parse.
    pub fn open(path: &Path) -> Result<Nsp> {
        Nsp::from_storage(Arc::new(FileStorage::open(path)?))
    }

    /// Open an NSP held in `storage`.
    ///
    /// # Errors
    ///
    /// As [`Nsp::open`].
    pub fn from_storage(storage: Shared) -> Result<Nsp> {
        let pfs = Pfs0::open(storage)?;
        let mut title_keys = TitleKeys::default();
        let mut personalized = Vec::new();
        for e in pfs.entries() {
            if e.name.ends_with(".tik") {
                let t = Ticket::parse(&pfs.read(e)?)?;
                match t.key_type {
                    TitleKeyType::Common => title_keys.insert(t.rights_id, t.common_title_key()?),
                    TitleKeyType::Personalized => personalized.push(t),
                }
            }
        }
        Ok(Nsp {
            pfs,
            title_keys,
            personalized,
            select: None,
        })
    }

    /// The archive.
    pub fn pfs0(&self) -> &Pfs0 {
        &self.pfs
    }

    /// The title keys of the tickets inside: the common ones, and the
    /// personalized ones once unlocked.
    pub fn title_keys(&self) -> &TitleKeys {
        &self.title_keys
    }

    /// The rights IDs of personalized tickets not yet unlocked.
    pub fn personalized(&self) -> Vec<[u8; 16]> {
        self.personalized.iter().map(|t| t.rights_id).collect()
    }

    /// Unwrap every personalized ticket with the eTicket RSA key in `keys`
    /// and add its title key; without an eTicket key, do nothing.
    ///
    /// # Errors
    ///
    /// A ticket belongs to another console ([`Error::WrongKey`]).
    pub fn unlock_personalized(&mut self, keys: &Keys) -> Result<()> {
        if keys.eticket_key().is_none() {
            return Ok(());
        }
        for t in std::mem::take(&mut self.personalized) {
            self.title_keys.insert(t.rights_id, t.title_key(keys)?);
        }
        Ok(())
    }

    /// The bytes of an NCA entry. A `.ncz` entry (an NSZ member) is
    /// restored on read, so the result is the NCA either way.
    fn nca_storage(&self, e: &crate::pfs0::Pfs0Entry) -> Result<Shared> {
        let raw = self.pfs.open_entry(e)?;
        if e.name.ends_with(".ncz") {
            return Ok(Ncz::open(raw)
                .map_err(|err| prefix(&e.name, err))?
                .to_encrypted_storage());
        }
        Ok(raw)
    }

    /// Open every NCA's header, including the `.ncz` entries of an NSZ.
    ///
    /// # Errors
    ///
    /// A header does not decrypt.
    pub fn ncas(&self, keys: &Keys) -> Result<Vec<(String, Nca)>> {
        let mut out = Vec::new();
        for e in self.pfs.entries() {
            if e.name.ends_with(".nca") || e.name.ends_with(".ncz") {
                let nca = Nca::open(self.nca_storage(e)?, keys, &self.title_keys)
                    .map_err(|err| prefix(&e.name, err))?;
                out.push((e.name.clone(), nca));
            }
        }
        Ok(out)
    }

    /// The program NCA.
    ///
    /// # Errors
    ///
    /// None, several without a choice ([`Error::Ambiguous`]), a personalized
    /// ticket for it that was not unlocked
    /// (an [`Error::MissingKey`] naming the eTicket settings when `keys` has
    /// no eTicket key), or a header error.
    pub fn program(&self, keys: &Keys) -> Result<Nca> {
        let nca = pick_program(self.ncas(keys)?, self.select, "NSP")?;
        if let Some(r) = nca.header().rights_id()
            && self.title_keys.get(&r).is_none()
            && let Some(t) = self.personalized.iter().find(|t| t.rights_id == r)
        {
            t.title_key(keys)?;
            return Err(Error::MissingKey(format!(
                "the personalized ticket for rights ID {} was not unlocked (call unlock_personalized)",
                hex(&r)
            )));
        }
        Ok(nca)
    }

    /// The content meta, from the meta NCA (the chosen program's when there
    /// are several).
    ///
    /// # Errors
    ///
    /// No meta NCA or no `.cnmt` inside.
    pub fn cnmt(&self, keys: &Keys) -> Result<Cnmt> {
        meta_for(cnmts(self, keys)?, self.select, "NSP")
    }
}

/// Prefix an error message with `name`, keeping its kind.
pub(crate) fn prefix(name: &str, e: Error) -> Error {
    match e {
        Error::Format(m) => Error::Format(format!("{name}: {m}")),
        Error::MissingKey(m) => Error::MissingKey(format!("{name}: {m}")),
        Error::WrongKey(m) => Error::WrongKey(format!("{name}: {m}")),
        Error::Hash(m) => Error::Hash(format!("{name}: {m}")),
        Error::Unsupported(m) => Error::Unsupported(format!("{name}: {m}")),
        Error::Ambiguous(m) => Error::Ambiguous(format!("{name}: {m}")),
        other => other,
    }
}

/// Open a PFS0 section of an NCA through its hierarchical SHA-256, every
/// block verified.
///
/// # Errors
///
/// A wrong key, a hash mismatch or a malformed PFS0.
pub fn open_pfs0_section(nca: &Nca, i: usize, keys: &Keys, tk: &TitleKeys) -> Result<Pfs0> {
    let fs = nca.header().fs_header(i);
    if fs.hash_type()? != HashType::HierarchicalSha256 {
        return Err(Error::Unsupported(format!(
            "section {i}: PFS0 without hierarchical SHA-256"
        )));
    }
    let raw = nca.section_raw(i, keys, tk)?;
    let data = open_sha256(raw, &Sha256Info::parse(&fs)?, &format!("section {i}"))?;
    data.verify_all()?;
    Pfs0::open(Arc::new(data))
}

/// Open the romfs of a program NCA, patched by `update` if given.
///
/// # Errors
///
/// A wrong key, a hash mismatch, a malformed table or romfs.
pub fn open_romfs(
    base: Option<(&Nca, &TitleKeys)>,
    update: Option<(&Nca, &TitleKeys)>,
    keys: &Keys,
) -> Result<Option<Romfs>> {
    match open_romfs_storage(base, update, keys)? {
        Some(data) => Ok(Some(Romfs::open(data)?)),
        None => Ok(None),
    }
}

/// The romfs image of a program NCA, patched by `update` if given: the
/// IVFC data level, every block verified when read.
///
/// # Errors
///
/// A wrong key, a malformed table or an unsupported layer. Hash mismatches
/// show when the blocks are read.
pub fn open_romfs_storage(
    base: Option<(&Nca, &TitleKeys)>,
    update: Option<(&Nca, &TitleKeys)>,
    keys: &Keys,
) -> Result<Option<Shared>> {
    const ROMFS: usize = 1;
    let (top, tk) = match (update, base) {
        (Some(u), _) => u,
        (None, Some(b)) => b,
        (None, None) => return Ok(None),
    };
    if top.header().section(ROMFS).is_none() {
        return Ok(None);
    }
    let fs = top.header().fs_header(ROMFS);
    let raw: Shared = if update.is_some() && fs.encryption()? == Encryption::CtrEx {
        let info = PatchInfo::parse(&fs)?;
        let patch = top.section_raw(ROMFS, keys, tk)?;
        let tables = top.section_table(ROMFS, keys, tk)?;
        let base_raw: Shared = match base {
            Some((b, btk)) if b.header().section(ROMFS).is_some() => {
                b.section_raw(ROMFS, keys, btk)?
            }
            _ => Arc::new(ZeroStorage(0)),
        };
        Arc::new(IndirectStorage::open(&*tables, &info, base_raw, patch)?)
    } else {
        top.section_raw(ROMFS, keys, tk)?
    };
    if fs.hash_type()? != HashType::Ivfc {
        return Err(Error::Unsupported("romfs section without IVFC".into()));
    }
    let data: Shared = open_ivfc(raw, &IvfcInfo::parse(&fs)?, "romfs")?;
    Ok(Some(data))
}

/// The verified parts of a title.
pub struct Title {
    /// The base program ID.
    pub program_id: u64,
    /// The version (the update's if there is one).
    pub version: u32,
    /// The exefs (the update's if there is one): NSOs and `main.npdm`.
    pub exefs: Pfs0,
    /// The romfs, patched if there is an update.
    pub romfs: Option<Romfs>,
}

/// Open a base package and an optional update package as one title.
///
/// # Errors
///
/// Mismatched program IDs, key errors, hash mismatches, malformed data.
pub fn open_title(keys: &Keys, base: &dyn Package, update: Option<&dyn Package>) -> Result<Title> {
    let base_nca = base.program(keys).map_err(|e| prefix("base", e))?;
    let program_id = base_nca.header().program_id();
    let base_meta = base.cnmt(keys).ok();
    let upd = match update {
        Some(u) => {
            let nca = u.program(keys).map_err(|e| prefix("update", e))?;
            if nca.header().program_id() != program_id | 0x800
                && nca.header().program_id() != program_id
            {
                return malformed(format!(
                    "update program {:016x} does not belong to base {program_id:016x}",
                    nca.header().program_id()
                ));
            }
            Some((u, nca))
        }
        None => None,
    };
    let version = match &upd {
        Some((u, _)) => u.cnmt(keys).map(|c| c.version).unwrap_or(0),
        None => base_meta.map_or(0, |c| c.version),
    };
    let (exefs_nca, exefs_tk) = match &upd {
        Some((u, n)) => (n, u.title_keys()),
        None => (&base_nca, base.title_keys()),
    };
    let exefs = open_pfs0_section(exefs_nca, 0, keys, exefs_tk).map_err(|e| prefix("exefs", e))?;
    let romfs = open_romfs(
        Some((&base_nca, base.title_keys())),
        upd.as_ref().map(|(u, n)| (n, u.title_keys())),
        keys,
    )?;
    Ok(Title {
        program_id,
        version,
        exefs,
        romfs,
    })
}
