//! Export: decrypt a title's packages (the base, its updates, its add-ons)
//! into the dump tree the reference NUP packer reads, or straight into a
//! `.nup`.
//!
//! The tree is the input layout of the packer of github.com/a55uka/nup
//! (`README.md`, "Packing a dump", and `tools/nup/nup/discover.py`):
//!
//! ```text
//! <out>/base/exefs/<main, main.npdm, rtld, sdk, subsdk*>
//! <out>/base/romfs/<tree>
//! <out>/updates/<NCM version, decimal>/exefs/...
//! <out>/updates/<NCM version, decimal>/romfs/<full patched tree>
//! <out>/dlc/<add-on title id, 16 lowercase hex>/<index>/romfs/<tree>
//! ```
//!
//! An update's romfs is the whole tree the game sees with that update: the
//! base romfs with the update's BKTR patch applied, not a delta. The packer
//! treats `<index>` as an opaque name; here it numbers the data contents of
//! one add-on from 0 (an add-on has one, so it is `0`). When the same add-on
//! is given twice, only its newest version is kept.
//!
//! [`plan`] opens and verifies the packages and lays out what will be
//! written; nothing is read in bulk until [`Export::write_tree`] or
//! [`Export::write_nup`] streams each file through switch-io, so a 4 GiB
//! romfs never sits in memory. `.listing` files (spec 6.3) are left out.

use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::cnmt::Cnmt;
use crate::error::{Error, Result, malformed};
use crate::keys::Keys;
use crate::nacp::{LANGUAGES, Nacp};
use crate::nca::{ContentType, Nca};
use crate::npdm::Npdm;
use crate::nup::{
    PackageKind, TLV_BUILD_ID, TLV_DISPLAY_VERSION, TLV_LOCALIZED_TITLES, TLV_NACP, TLV_NAME,
    TLV_NPDM, TLV_PUBLISHER,
};
use crate::nup_writer::{self, Content, Summary, WritePackage};
use crate::pfs0::{Pfs0, Pfs0Entry};
use crate::romfs::{Romfs, RomfsFile};
use crate::storage::{Storage, read_vec};
use crate::title::{Package, cnmts, open_pfs0_section, open_romfs, open_section_romfs, prefix};

/// CNMT meta type of an application (a base game).
pub const META_APPLICATION: u8 = 0x80;
/// CNMT meta type of a patch (an update).
pub const META_PATCH: u8 = 0x81;
/// CNMT meta type of add-on content (DLC).
pub const META_ADDON: u8 = 0x82;

/// The file name dump tools leave behind that NUP trees exclude.
pub const LISTING: &str = ".listing";

const CHUNK: u64 = 1 << 20;

/// One package to export.
pub struct ExportPackage {
    /// The kind.
    pub kind: PackageKind,
    /// The title id the NUP record carries: the NPDM program id when the
    /// exefs has one (as the reference packer reads it), else the content
    /// meta's.
    pub title_id: u64,
    /// The NCM version (0 for most bases).
    pub version: u32,
    /// The package directory in the tree, such as `base`,
    /// `updates/65536` or `dlc/0100123456781001/0`.
    pub dir: String,
    /// The meta records (type, payload) of the NUP package.
    pub meta: Vec<(u16, Vec<u8>)>,
    exefs: Option<Pfs0>,
    romfs: Option<Romfs>,
}

/// A planned export: every package opened and verified, nothing written.
pub struct Export {
    /// The application id of the base.
    pub application_id: u64,
    /// The packages: the base, the updates by version, the add-ons in input
    /// order.
    pub packages: Vec<ExportPackage>,
}

/// What [`Export::write_tree`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TreeSummary {
    /// How many files the tree holds.
    pub files: usize,
    /// How many of them were (re)written; the rest were already equal.
    pub written: usize,
    /// How many stale files from an earlier export were removed.
    pub removed: usize,
    /// The total size of every file.
    pub bytes: u64,
}

/// A file of a package, streamed on demand.
pub enum Source<'a> {
    /// An exefs file.
    Exefs(&'a Pfs0, &'a Pfs0Entry),
    /// A romfs file.
    Romfs(&'a Romfs, &'a RomfsFile),
}

impl Content for Source<'_> {
    fn size(&self) -> u64 {
        match self {
            Source::Exefs(_, e) => e.size,
            Source::Romfs(_, f) => f.size,
        }
    }

    fn copy_to(&self, out: &mut dyn Write) -> Result<()> {
        match self {
            Source::Exefs(pfs, e) => copy_storage(&*pfs.open_entry(e)?, out),
            Source::Romfs(r, f) => r.copy_file(f, out),
        }
    }
}

fn copy_storage(s: &dyn Storage, out: &mut dyn Write) -> Result<()> {
    let mut buf = vec![0u8; usize::try_from(CHUNK.min(s.size())).unwrap_or(0)];
    let mut off = 0;
    while off < s.size() {
        let n = CHUNK.min(s.size() - off);
        let b = &mut buf[..usize::try_from(n).unwrap_or(0)];
        s.read_at(off, b)?;
        out.write_all(b)?;
        off += n;
    }
    Ok(())
}

fn is_listing(path: &str) -> bool {
    path.rsplit('/').next() == Some(LISTING)
}

impl ExportPackage {
    /// The files as (path from the package directory, source): exefs in
    /// archive order, then romfs in data order, `.listing` files left out.
    pub fn files(&self) -> Vec<(String, Source<'_>)> {
        let mut out = Vec::new();
        if let Some(pfs) = &self.exefs {
            for e in pfs.entries() {
                if !is_listing(&e.name) {
                    out.push((format!("exefs/{}", e.name), Source::Exefs(pfs, e)));
                }
            }
        }
        if let Some(r) = &self.romfs {
            let mut files: Vec<&RomfsFile> = r.files().iter().collect();
            files.sort_by_key(|f| f.offset);
            for f in files {
                if !is_listing(&f.path) {
                    out.push((format!("romfs/{}", f.path), Source::Romfs(r, f)));
                }
            }
        }
        out
    }

    /// The directories, empty ones included: `exefs`, `romfs` and every
    /// romfs directory.
    pub fn dirs(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.exefs.is_some() {
            out.push("exefs".to_string());
        }
        if let Some(r) = &self.romfs {
            out.push("romfs".to_string());
            out.extend(r.dirs().iter().map(|d| format!("romfs/{d}")));
        }
        out
    }
}

fn check_exefs_names(pfs: &Pfs0, what: &str) -> Result<()> {
    for e in pfs.entries() {
        let n = &e.name;
        if n.is_empty() || n == "." || n == ".." || n.contains(['/', '\\', '\0']) {
            return malformed(format!("{what}: exefs holds an unsafe name {n:?}"));
        }
    }
    Ok(())
}

fn meta_of(cnmts: &[Cnmt], meta_type: u8) -> Vec<&Cnmt> {
    cnmts.iter().filter(|c| c.meta_type == meta_type).collect()
}

/// The verbatim `control.nacp` of a package's control NCA, if it has one.
fn control_nacp(pkg: &dyn Package, keys: &Keys, ncas: &[(String, Nca)]) -> Result<Option<Vec<u8>>> {
    let Some((name, nca)) = ncas
        .iter()
        .find(|(_, n)| n.header().content_type() == ContentType::Control)
    else {
        return Ok(None);
    };
    let r = open_section_romfs(nca, keys, pkg.title_keys()).map_err(|e| prefix(name, e))?;
    let Some(f) = r.files().iter().find(|f| f.path == "control.nacp") else {
        return Ok(None);
    };
    if f.size > 0x10_0000 {
        return malformed(format!("{name}: control.nacp is {:#x} bytes", f.size));
    }
    let mut v = Vec::new();
    r.copy_file(f, &mut v)?;
    Ok(Some(v))
}

/// The meta records of a program package: NPDM, NACP with its display
/// version, names and publisher, and the build id of `main`.
fn program_meta(exefs: &Pfs0, nacp: Option<&[u8]>) -> Result<Vec<(u16, Vec<u8>)>> {
    let mut meta = Vec::new();
    if let Some(e) = exefs.find("main.npdm") {
        meta.push((TLV_NPDM, exefs.read(e)?));
    }
    if let Some(raw) = nacp {
        let n = Nacp::parse(raw)?;
        meta.push((TLV_NACP, raw.to_vec()));
        if !n.display_version.is_empty() {
            meta.push((TLV_DISPLAY_VERSION, n.display_version.clone().into_bytes()));
        }
        if let Some(l) = n.default_language() {
            meta.push((TLV_NAME, n.titles[l].name.clone().into_bytes()));
            if !n.titles[l].publisher.is_empty() {
                meta.push((TLV_PUBLISHER, n.titles[l].publisher.clone().into_bytes()));
            }
        }
        let mut localized = Vec::new();
        for (t, (_, tag)) in n.titles.iter().zip(LANGUAGES) {
            if t.name.is_empty() {
                continue;
            }
            localized.push(u8::try_from(tag.len()).unwrap_or(0));
            localized.extend_from_slice(tag.as_bytes());
            localized.extend_from_slice(&u32::try_from(t.name.len()).unwrap_or(0).to_le_bytes());
            localized.extend_from_slice(t.name.as_bytes());
        }
        if !localized.is_empty() {
            meta.push((TLV_LOCALIZED_TITLES, localized));
        }
    }
    if let Some(e) = exefs.find("main")
        && e.size >= 0x60
    {
        let head = read_vec(&*exefs.open_entry(e)?, 0, 0x60)?;
        if &head[..4] == b"NSO0" || &head[0x10..0x14] == b"NRO0" {
            meta.push((TLV_BUILD_ID, head[0x40..0x60].to_vec()));
        }
    }
    Ok(meta)
}

fn npdm_program_id(exefs: &Pfs0) -> Option<u64> {
    let e = exefs.find("main.npdm")?;
    let n = Npdm::parse(&exefs.read(e).ok()?).ok()?;
    (n.program_id != 0).then_some(n.program_id)
}

/// Open and verify a title's packages and lay out the export. `updates`
/// may come in any order (they are sorted by version); `dlc` packages may
/// each hold several add-ons.
///
/// # Errors
///
/// A missing or wrong key ([`Error::MissingKey`], [`Error::WrongKey`]), a
/// base that is not an application, an update or add-on of another title,
/// two updates of one version, a hash mismatch or a malformed container.
pub fn plan(
    keys: &Keys,
    base: &dyn Package,
    updates: &[&dyn Package],
    dlc: &[&dyn Package],
) -> Result<Export> {
    let base_ncas = base.ncas(keys).map_err(|e| prefix("base", e))?;
    let base_cnmts = cnmts(base, keys).map_err(|e| prefix("base", e))?;
    let Some(app) = meta_of(&base_cnmts, META_APPLICATION).first().copied() else {
        return malformed("base: holds no application content meta (not a base game)");
    };
    let app_id = app.title_id;
    let base_nca = base.program(keys).map_err(|e| prefix("base", e))?;
    if base_nca.header().program_id() != app_id {
        return malformed(format!(
            "base: program {:016x} is not the application {app_id:016x} of its content meta",
            base_nca.header().program_id()
        ));
    }
    let exefs = open_pfs0_section(&base_nca, 0, keys, base.title_keys())
        .map_err(|e| prefix("base exefs", e))?;
    check_exefs_names(&exefs, "base")?;
    let romfs = open_romfs(Some((&base_nca, base.title_keys())), None, keys)
        .map_err(|e| prefix("base romfs", e))?;
    let nacp = control_nacp(base, keys, &base_ncas).map_err(|e| prefix("base", e))?;
    let mut packages = vec![ExportPackage {
        kind: PackageKind::Base,
        title_id: npdm_program_id(&exefs).unwrap_or(app_id),
        version: app.version,
        dir: "base".into(),
        meta: program_meta(&exefs, nacp.as_deref())?,
        exefs: Some(exefs),
        romfs,
    }];
    let base_title_id = packages[0].title_id;

    let mut ups: Vec<ExportPackage> = Vec::new();
    for (i, u) in updates.iter().enumerate() {
        let what = format!("update {}", i + 1);
        let ctx = |e| prefix(&what, e);
        let u_cnmts = cnmts(*u, keys).map_err(ctx)?;
        let Some(patch) = meta_of(&u_cnmts, META_PATCH).first().copied() else {
            return malformed(format!(
                "{what}: holds no patch content meta (not an update)"
            ));
        };
        if patch.title_id != app_id | 0x800 {
            return malformed(format!(
                "{what}: update {:016x} does not belong to base {app_id:016x}",
                patch.title_id
            ));
        }
        let nca = u.program(keys).map_err(ctx)?;
        let pid = nca.header().program_id();
        if pid != app_id | 0x800 && pid != app_id {
            return malformed(format!(
                "{what}: update program {pid:016x} does not belong to base {app_id:016x}"
            ));
        }
        if ups.iter().any(|p| p.version == patch.version) {
            return malformed(format!(
                "{what}: update version {} is given twice",
                patch.version
            ));
        }
        let exefs = open_pfs0_section(&nca, 0, keys, u.title_keys())
            .map_err(|e| prefix(&format!("{what} exefs"), e))?;
        check_exefs_names(&exefs, &what)?;
        let romfs = open_romfs(
            Some((&base_nca, base.title_keys())),
            Some((&nca, u.title_keys())),
            keys,
        )
        .map_err(|e| prefix(&format!("{what} romfs"), e))?;
        let u_ncas = u.ncas(keys).map_err(ctx)?;
        let nacp = control_nacp(*u, keys, &u_ncas).map_err(ctx)?;
        ups.push(ExportPackage {
            kind: PackageKind::Update,
            title_id: npdm_program_id(&exefs).unwrap_or(base_title_id),
            version: patch.version,
            dir: format!("updates/{}", patch.version),
            meta: program_meta(&exefs, nacp.as_deref())?,
            exefs: Some(exefs),
            romfs,
        });
    }
    ups.sort_by_key(|p| p.version);
    packages.extend(ups);

    let mut addons: Vec<(u64, u32, Vec<Romfs>)> = Vec::new();
    let mut at: HashMap<u64, usize> = HashMap::new();
    for (i, d) in dlc.iter().enumerate() {
        let what = format!("dlc {}", i + 1);
        let ctx = |e| prefix(&what, e);
        let d_cnmts = cnmts(*d, keys).map_err(ctx)?;
        let metas = meta_of(&d_cnmts, META_ADDON);
        if metas.is_empty() {
            return malformed(format!("{what}: holds no add-on content meta (not DLC)"));
        }
        let ncas = d.ncas(keys).map_err(ctx)?;
        for m in metas {
            let id = m.title_id;
            if id & !0xFFF != app_id ^ 0x1000 {
                return malformed(format!(
                    "{what}: add-on {id:016x} does not belong to base {app_id:016x}"
                ));
            }
            if at.get(&id).is_some_and(|&k| addons[k].1 >= m.version) {
                continue;
            }
            let mut trees = Vec::new();
            for (name, nca) in &ncas {
                let ty = nca.header().content_type();
                if (ty == ContentType::Data || ty == ContentType::PublicData)
                    && nca.header().program_id() == id
                {
                    trees.push(
                        open_section_romfs(nca, keys, d.title_keys())
                            .map_err(|e| prefix(&format!("{what} {name}"), e))?,
                    );
                }
            }
            if trees.is_empty() {
                return malformed(format!("{what}: add-on {id:016x} has no data NCA"));
            }
            match at.get(&id) {
                Some(&k) => addons[k] = (id, m.version, trees),
                None => {
                    at.insert(id, addons.len());
                    addons.push((id, m.version, trees));
                }
            }
        }
    }
    for (id, version, trees) in addons {
        for (index, romfs) in trees.into_iter().enumerate() {
            packages.push(ExportPackage {
                kind: PackageKind::Addon,
                title_id: id,
                version,
                dir: format!("dlc/{id:016x}/{index}"),
                meta: Vec::new(),
                exefs: None,
                romfs: Some(romfs),
            });
        }
    }
    Ok(Export {
        application_id: app_id,
        packages,
    })
}

/// Every path below `dir`, files and directories, relative and
/// `/`-separated.
fn walk(root: &Path, dir: &Path, files: &mut Vec<PathBuf>, dirs: &mut Vec<PathBuf>) -> Result<()> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    for e in rd {
        let e = e?;
        let p = e.path();
        let rel = p
            .strip_prefix(root)
            .map_or_else(|_| p.clone(), Path::to_path_buf);
        if e.file_type()?.is_dir() {
            walk(root, &p, files, dirs)?;
            dirs.push(rel);
        } else {
            files.push(rel);
        }
    }
    Ok(())
}

impl Export {
    /// Write the tree under `out` through switch-io's streaming
    /// write-if-changed writer: unchanged files keep their mtime, and files
    /// under `base/`, `updates/` and `dlc/` that this export does not hold
    /// (left by an earlier export) are removed, so the packer sees exactly
    /// these packages.
    ///
    /// # Errors
    ///
    /// A read, hash check or write fails. A failed file leaves its old
    /// content in place.
    pub fn write_tree(&self, out: &Path) -> Result<TreeSummary> {
        let mut summary = TreeSummary::default();
        let mut want_files = BTreeSet::new();
        let mut want_dirs = BTreeSet::new();
        for p in &self.packages {
            let mut d = PathBuf::new();
            for part in p.dir.split('/') {
                d.push(part);
                want_dirs.insert(d.clone());
            }
            for dir in p.dirs() {
                let rel = Path::new(&p.dir).join(&dir);
                std::fs::create_dir_all(out.join(&rel))?;
                want_dirs.insert(rel);
            }
            for (path, src) in p.files() {
                let rel = Path::new(&p.dir).join(&path);
                let target = out.join(&rel);
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let mut w = switch_io::StreamWriter::new(&target)?;
                src.copy_to(&mut w)
                    .map_err(|e| prefix(&format!("{}/{path}", p.dir), e))?;
                if w.finish()? {
                    summary.written += 1;
                }
                summary.files += 1;
                summary.bytes += src.size();
                want_files.insert(rel);
            }
        }
        for top in ["base", "updates", "dlc"] {
            let (mut files, mut dirs) = (Vec::new(), Vec::new());
            walk(out, &out.join(top), &mut files, &mut dirs)?;
            for f in files {
                if !want_files.contains(&f) {
                    std::fs::remove_file(out.join(&f))?;
                    summary.removed += 1;
                }
            }
            for d in dirs {
                if !want_dirs.contains(&d) {
                    match std::fs::remove_dir(out.join(&d)) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
                        Err(e) => return Err(Error::Io(e)),
                    }
                }
            }
        }
        Ok(summary)
    }

    /// Write a `.nup` at `path` with the streaming writer: one base
    /// package, one update package per version (its own exefs and full
    /// patched romfs) and one add-on package per add-on data content
    /// (recording the add-on's real NCM version). `level` is the zstd level.
    ///
    /// # Errors
    ///
    /// As [`nup_writer::write`]; `path` is untouched on error.
    pub fn write_nup(&self, path: &Path, level: i32) -> Result<Summary> {
        let sources: Vec<Vec<(String, Source<'_>)>> =
            self.packages.iter().map(ExportPackage::files).collect();
        let packages: Vec<WritePackage<'_>> = self
            .packages
            .iter()
            .zip(&sources)
            .map(|(p, files)| WritePackage {
                title_id: p.title_id,
                version: p.version,
                kind: p.kind,
                standalone: false,
                files: files
                    .iter()
                    .map(|(path, s)| (path.clone(), s as &dyn Content))
                    .collect(),
                dirs: p.dirs(),
                meta: p.meta.clone(),
            })
            .collect();
        nup_writer::write(path, &packages, level)
    }
}
