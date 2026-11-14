//! A streaming NUP writer, from draft 1.0 of the public NUP specification
//! (`SPEC.md` of github.com/a55uka/nup, MIT).
//!
//! The table of contents depends only on the package records, the tree
//! shape and the names, never on where extents land, so its size is known
//! before any content is read. [`write`] therefore lays out the tree,
//! computes `blob_offset`, streams every file's extent into the blob region
//! of a temporary file beside the target, writes the meta blocks after it,
//! and only then seeks back to write the superblock and table at the front
//! and renames the file over the target. No file is ever held in memory:
//! each one is read in chunks through a SHA-256 hasher and a zstd encoder.
//!
//! Writer rules followed (spec sections 3.3, 3.6, 4.1 and 6.2): children
//! sorted bytewise and contiguous per directory, extents 16-byte aligned
//! with zero padding, one zstd frame (level 3 by default, content size in
//! the frame header) only when it is smaller than the file, else raw;
//! equal contents (same SHA-256 and size) share one extent; every reserved
//! field zero; the UUID derived from the package records. Excluding
//! `.listing` artifacts (section 6.3) is the caller's job.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::Path;

use sha2::{Digest, Sha256};
use switch_io::TempFile;

use crate::crypto::sha256;
use crate::error::{Error, Result, malformed};
use crate::nup::{
    Codec, DIR_SIZE, FILE_SIZE, MAGIC, NO_DIR, PACKAGE_SIZE, PackageKind, PackageRecord,
    SUPERBLOCK_SIZE, uuid_of,
};

const TOC_HEADER: usize = 0x30;
const TOC_MAGIC: [u8; 4] = *b"TOC\x01";
const ZEROS: [u8; 16] = [0; 16];

/// The default zstd level (spec section 4.1).
pub const DEFAULT_LEVEL: i32 = 3;

/// A file's content, read on demand and streamed.
pub trait Content {
    /// The size in bytes.
    fn size(&self) -> u64;

    /// Stream the whole content into `out`. Called once or twice per file
    /// (a second time when the compressed frame is not smaller).
    ///
    /// # Errors
    ///
    /// A read, hash check or write fails.
    fn copy_to(&self, out: &mut dyn Write) -> Result<()>;
}

/// Content held in memory (small files and fixtures).
pub struct Bytes(pub Vec<u8>);

impl Content for Bytes {
    fn size(&self) -> u64 {
        self.0.len() as u64
    }

    fn copy_to(&self, out: &mut dyn Write) -> Result<()> {
        out.write_all(&self.0)?;
        Ok(())
    }
}

/// A package to write.
pub struct WritePackage<'a> {
    /// The raw title id.
    pub title_id: u64,
    /// The NCM version.
    pub version: u32,
    /// The kind.
    pub kind: PackageKind,
    /// The `standalone_update` flag.
    pub standalone: bool,
    /// The files as (path from the package root, content), such as
    /// `exefs/main` or `romfs/dir/file.bin`, in the order their extents
    /// are written (data order of the source reads best).
    pub files: Vec<(String, &'a dyn Content)>,
    /// Directories to create even when empty, as paths from the root.
    pub dirs: Vec<String>,
    /// The meta records, (type, payload).
    pub meta: Vec<(u16, Vec<u8>)>,
}

/// What [`write`] produced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    /// The size of the written file.
    pub file_size: u64,
    /// How many file records there are.
    pub files: usize,
    /// How many extents were stored (files minus empty ones and duplicates).
    pub extents: usize,
    /// How many extents are zstd frames.
    pub compressed: usize,
    /// The total uncompressed size of every file.
    pub content_bytes: u64,
}

#[derive(Default)]
struct Node {
    dirs: BTreeMap<String, Node>,
    files: BTreeMap<String, (usize, usize)>,
}

enum Kid {
    Dir(usize),
    File(usize),
}

struct LaidFile {
    name: String,
    package: usize,
    index: usize,
}

struct Layout {
    dirs: Vec<(String, Vec<Kid>)>,
    files: Vec<LaidFile>,
}

fn flatten(node: &Node, name: &str, lay: &mut Layout) -> usize {
    let me = lay.dirs.len();
    lay.dirs.push((name.to_string(), Vec::new()));
    let mut kids: Vec<(&str, Kid)> = Vec::new();
    for (n, d) in &node.dirs {
        kids.push((n, Kid::Dir(flatten(d, n, lay))));
    }
    for (n, (package, index)) in &node.files {
        lay.files.push(LaidFile {
            name: n.clone(),
            package: *package,
            index: *index,
        });
        kids.push((n, Kid::File(lay.files.len() - 1)));
    }
    kids.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    lay.dirs[me].1 = kids.into_iter().map(|(_, k)| k).collect();
    me
}

fn check_name(name: &str, path: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['\\', '\0']) {
        return malformed(format!("NUP writer: unsafe path {path:?}"));
    }
    Ok(())
}

fn tree_of(p: &WritePackage<'_>, pi: usize) -> Result<Node> {
    let mut root = Node::default();
    for (fi, (path, _)) in p.files.iter().enumerate() {
        let parts: Vec<&str> = path.split('/').collect();
        for part in &parts {
            check_name(part, path)?;
        }
        let (leaf, dirs) = parts
            .split_last()
            .ok_or_else(|| Error::Format(format!("NUP writer: empty path {path:?}")))?;
        let mut cur = &mut root;
        for part in dirs {
            if cur.files.contains_key(*part) {
                return malformed(format!("NUP writer: {path:?} is under a file"));
            }
            cur = cur.dirs.entry((*part).to_string()).or_default();
        }
        if cur.dirs.contains_key(*leaf) || cur.files.insert((*leaf).to_string(), (pi, fi)).is_some()
        {
            return malformed(format!("NUP writer: {path:?} is given twice"));
        }
    }
    for path in &p.dirs {
        let mut cur = &mut root;
        for part in path.split('/') {
            check_name(part, path)?;
            if cur.files.contains_key(part) {
                return malformed(format!("NUP writer: directory {path:?} is a file"));
            }
            cur = cur.dirs.entry(part.to_string()).or_default();
        }
    }
    Ok(root)
}

struct Pool {
    bytes: Vec<u8>,
    seen: HashMap<String, (u32, u32)>,
}

impl Pool {
    fn intern(&mut self, s: &str) -> Result<(u32, u32)> {
        if let Some(r) = self.seen.get(s) {
            return Ok(*r);
        }
        let r = (u32_of(self.bytes.len())?, u32_of(s.len())?);
        self.bytes.extend_from_slice(s.as_bytes());
        self.seen.insert(s.to_string(), r);
        Ok(r)
    }
}

fn u32_of(v: usize) -> Result<u32> {
    u32::try_from(v).or_else(|_| malformed("NUP writer: a count or offset passes u32"))
}

fn align16(v: u64) -> u64 {
    v.div_ceil(16) * 16
}

#[derive(Clone, Copy)]
struct Extent {
    offset: u64,
    size: u64,
    codec: Codec,
}

struct FileOut {
    name: (u32, u32),
    size: u64,
    sha256: [u8; 32],
    extent: Extent,
}

/// The blob region's writer: a buffered temporary file and its position.
struct Out {
    buf: BufWriter<TempFile>,
    pos: u64,
}

impl Out {
    fn pad_to(&mut self, to: u64) -> Result<()> {
        while self.pos < to {
            let n = usize::try_from((to - self.pos).min(16)).unwrap_or(16);
            self.buf.write_all(&ZEROS[..n])?;
            self.pos += n as u64;
        }
        Ok(())
    }

    fn truncate(&mut self, to: u64) -> Result<()> {
        self.buf.flush()?;
        self.buf.get_mut().truncate(to)?;
        self.pos = to;
        Ok(())
    }
}

impl Write for Out {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let n = self.buf.write(b)?;
        self.pos += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.buf.flush()
    }
}

/// Hashes every byte and counts them on the way into `inner`.
struct Hashing<'a, W: Write> {
    inner: &'a mut W,
    hasher: Sha256,
    len: u64,
}

impl<W: Write> Write for Hashing<'_, W> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(b)?;
        self.hasher.update(&b[..n]);
        self.len += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// The extents written so far: by (SHA-256, size), and the sizes seen.
#[derive(Default)]
struct Seen {
    extents: HashMap<([u8; 32], u64), Extent>,
    sizes: HashSet<u64>,
}

/// Write one file's extent at the current (aligned) position. Returns the
/// SHA-256 and the extent; a duplicate of an earlier extent shares it.
///
/// A file whose size matches an earlier one is hashed first (one read, no
/// compression), since an update's full romfs repeats most base files;
/// any other file is compressed and hashed in the same pass.
fn put_file(
    out: &mut Out,
    content: &dyn Content,
    level: i32,
    seen: &mut Seen,
    summary: &mut Summary,
) -> Result<([u8; 32], Extent)> {
    let size = content.size();
    summary.content_bytes += size;
    if size == 0 {
        let none = Extent {
            offset: 0,
            size: 0,
            codec: Codec::Raw,
        };
        return Ok((sha256(&[]), none));
    }
    if !seen.sizes.insert(size) {
        let mut null = std::io::sink();
        let mut sink = Hashing {
            inner: &mut null,
            hasher: Sha256::new(),
            len: 0,
        };
        content.copy_to(&mut sink)?;
        let hash: [u8; 32] = sink.hasher.finalize().into();
        if let Some(e) = seen.extents.get(&(hash, size)) {
            return Ok((hash, *e));
        }
    }
    let before = out.pos;
    let start = align16(before);
    out.pad_to(start)?;
    let mut enc = zstd::stream::write::Encoder::new(&mut *out, level)
        .map_err(|e| Error::Format(format!("zstd: {e}")))?;
    enc.set_pledged_src_size(Some(size))
        .and_then(|()| enc.include_contentsize(true))
        .map_err(|e| Error::Format(format!("zstd: {e}")))?;
    let mut sink = Hashing {
        inner: &mut enc,
        hasher: Sha256::new(),
        len: 0,
    };
    content.copy_to(&mut sink)?;
    let (hash, got): ([u8; 32], u64) = (sink.hasher.finalize().into(), sink.len);
    if got != size {
        return malformed(format!(
            "NUP writer: a file gave {got:#x} bytes, expected {size:#x}"
        ));
    }
    enc.finish()
        .map_err(|e| Error::Format(format!("zstd: {e}")))?;
    let packed = out.pos - start;
    if let Some(e) = seen.extents.get(&(hash, size)) {
        out.truncate(before)?;
        return Ok((hash, *e));
    }
    let extent = if packed < size {
        summary.compressed += 1;
        Extent {
            offset: start,
            size: packed,
            codec: Codec::Zstd,
        }
    } else {
        out.truncate(start)?;
        let mut sink = Hashing {
            inner: &mut *out,
            hasher: Sha256::new(),
            len: 0,
        };
        content.copy_to(&mut sink)?;
        let again: [u8; 32] = sink.hasher.finalize().into();
        if again != hash || sink.len != size {
            return malformed("NUP writer: a file read differently the second time");
        }
        Extent {
            offset: start,
            size,
            codec: Codec::Raw,
        }
    };
    summary.extents += 1;
    seen.extents.insert((hash, size), extent);
    Ok((hash, extent))
}

struct Toc<'a> {
    records: &'a [PackageRecord],
    dirs: &'a [((u32, u32), u32, u32)],
    files: &'a [FileOut],
    children: &'a [u32],
    pool: &'a [u8],
}

impl Toc<'_> {
    fn len(&self) -> usize {
        TOC_HEADER
            + self.records.len() * PACKAGE_SIZE
            + self.dirs.len() * DIR_SIZE
            + self.files.len() * FILE_SIZE
            + self.children.len() * 4
            + self.pool.len()
    }

    fn bytes(&self) -> Vec<u8> {
        let mut t = Vec::with_capacity(self.len());
        t.extend_from_slice(&TOC_MAGIC);
        t.extend_from_slice(&(self.records.len() as u32).to_le_bytes());
        t.extend_from_slice(&(self.dirs.len() as u64).to_le_bytes());
        t.extend_from_slice(&(self.files.len() as u64).to_le_bytes());
        let pool_off = self.len() - self.pool.len();
        t.extend_from_slice(&(pool_off as u64).to_le_bytes());
        t.extend_from_slice(&(self.pool.len() as u64).to_le_bytes());
        t.extend_from_slice(&0u64.to_le_bytes());
        for r in self.records {
            let mut b = [0u8; PACKAGE_SIZE];
            b[0..8].copy_from_slice(&r.title_id.to_le_bytes());
            b[8..12].copy_from_slice(&r.root_dir.to_le_bytes());
            b[12..16].copy_from_slice(&r.exefs_dir.to_le_bytes());
            b[16..20].copy_from_slice(&r.romfs_dir.to_le_bytes());
            b[20..24].copy_from_slice(&r.version.to_le_bytes());
            b[24] = r.kind.code();
            b[25] = r.flags;
            b[32..40].copy_from_slice(&r.meta_offset.to_le_bytes());
            b[40..44].copy_from_slice(&r.meta_size.to_le_bytes());
            t.extend_from_slice(&b);
        }
        for ((name_off, name_len), first, count) in self.dirs {
            t.extend_from_slice(&name_off.to_le_bytes());
            t.extend_from_slice(&name_len.to_le_bytes());
            t.extend_from_slice(&first.to_le_bytes());
            t.extend_from_slice(&count.to_le_bytes());
            t.extend_from_slice(&0u64.to_le_bytes());
        }
        for f in self.files {
            let mut b = [0u8; FILE_SIZE];
            b[0..4].copy_from_slice(&f.name.0.to_le_bytes());
            b[4..8].copy_from_slice(&f.name.1.to_le_bytes());
            b[8..16].copy_from_slice(&f.size.to_le_bytes());
            b[16..24].copy_from_slice(&f.extent.offset.to_le_bytes());
            b[24..32].copy_from_slice(&f.extent.size.to_le_bytes());
            b[32..64].copy_from_slice(&f.sha256);
            b[64] = f.extent.codec.code();
            t.extend_from_slice(&b);
        }
        for c in self.children {
            t.extend_from_slice(&c.to_le_bytes());
        }
        t.extend_from_slice(self.pool);
        t
    }
}

fn superblock(toc: &[u8], blob_offset: u64, file_size: u64, records: &[PackageRecord]) -> Vec<u8> {
    let mut sb = Vec::with_capacity(SUPERBLOCK_SIZE as usize);
    sb.extend_from_slice(&MAGIC);
    sb.extend_from_slice(&(SUPERBLOCK_SIZE as u16).to_le_bytes());
    sb.extend_from_slice(&1u16.to_le_bytes());
    sb.extend_from_slice(&SUPERBLOCK_SIZE.to_le_bytes());
    sb.extend_from_slice(&(toc.len() as u64).to_le_bytes());
    sb.extend_from_slice(&sha256(toc));
    sb.extend_from_slice(&blob_offset.to_le_bytes());
    sb.extend_from_slice(&file_size.to_le_bytes());
    sb.extend_from_slice(&(records.len() as u32).to_le_bytes());
    sb.extend_from_slice(&0u32.to_le_bytes());
    sb.extend_from_slice(&uuid_of(records));
    sb.resize(SUPERBLOCK_SIZE as usize, 0);
    sb
}

/// Write `packages` as a `.nup` at `path`, streaming every file, through a
/// temporary file beside `path` that replaces it only when complete.
/// `level` is the zstd level ([`DEFAULT_LEVEL`] per the spec).
///
/// # Errors
///
/// No packages, more than one base, an unsafe or duplicate path, a content
/// read or hash failure, or a write error. On error `path` is untouched.
pub fn write(path: &Path, packages: &[WritePackage<'_>], level: i32) -> Result<Summary> {
    if packages.is_empty() {
        return malformed("NUP writer: no packages");
    }
    if packages
        .iter()
        .filter(|p| p.kind == PackageKind::Base)
        .count()
        > 1
    {
        return malformed("NUP writer: more than one base package");
    }
    let mut lay = Layout {
        dirs: Vec::new(),
        files: Vec::new(),
    };
    let mut records = Vec::new();
    for (pi, p) in packages.iter().enumerate() {
        let root = tree_of(p, pi)?;
        let find = |lay: &Layout, root: usize, name: &str| -> u32 {
            lay.dirs[root]
                .1
                .iter()
                .find_map(|k| match k {
                    Kid::Dir(d) if lay.dirs[*d].0 == name => u32::try_from(*d).ok(),
                    _ => None,
                })
                .unwrap_or(NO_DIR)
        };
        let root_dir = flatten(&root, "", &mut lay);
        records.push(PackageRecord {
            title_id: p.title_id,
            root_dir: u32_of(root_dir)?,
            exefs_dir: find(&lay, root_dir, "exefs"),
            romfs_dir: find(&lay, root_dir, "romfs"),
            version: p.version,
            kind: p.kind,
            flags: u8::from(p.standalone),
            meta_offset: 0,
            meta_size: 0,
        });
    }
    let ndirs = lay.dirs.len();
    let mut pool = Pool {
        bytes: Vec::new(),
        seen: HashMap::new(),
    };
    let mut file_names = Vec::with_capacity(lay.files.len());
    for f in &lay.files {
        file_names.push(pool.intern(&f.name)?);
    }
    let mut dir_recs = Vec::with_capacity(ndirs);
    let mut children = Vec::new();
    for (name, kids) in &lay.dirs {
        let name = pool.intern(name)?;
        dir_recs.push((name, u32_of(children.len())?, u32_of(kids.len())?));
        for k in kids {
            children.push(match k {
                Kid::Dir(d) => u32_of(*d)?,
                Kid::File(f) => u32_of(ndirs + f)?,
            });
        }
    }
    let mut files: Vec<FileOut> = file_names
        .iter()
        .map(|name| FileOut {
            name: *name,
            size: 0,
            sha256: [0; 32],
            extent: Extent {
                offset: 0,
                size: 0,
                codec: Codec::Raw,
            },
        })
        .collect();
    let toc_len = Toc {
        records: &records,
        dirs: &dir_recs,
        files: &files,
        children: &children,
        pool: &pool.bytes,
    }
    .len() as u64;
    let blob_offset = align16(SUPERBLOCK_SIZE + toc_len);

    let mut by_source: HashMap<(usize, usize), usize> = HashMap::new();
    for (i, f) in lay.files.iter().enumerate() {
        by_source.insert((f.package, f.index), i);
    }
    let mut tmp = TempFile::new(path)?;
    tmp.seek(SeekFrom::Start(blob_offset))?;
    let mut out = Out {
        buf: BufWriter::with_capacity(1 << 20, tmp),
        pos: blob_offset,
    };
    let mut seen = Seen::default();
    let mut summary = Summary {
        files: lay.files.len(),
        ..Summary::default()
    };
    for (pi, p) in packages.iter().enumerate() {
        for (fi, (fpath, content)) in p.files.iter().enumerate() {
            let at = by_source
                .get(&(pi, fi))
                .copied()
                .ok_or_else(|| Error::Format(format!("NUP writer: {fpath:?} was not laid out")))?;
            let (hash, extent) = put_file(&mut out, *content, level, &mut seen, &mut summary)
                .map_err(|e| crate::title::prefix(fpath, e))?;
            files[at].size = content.size();
            files[at].sha256 = hash;
            files[at].extent = extent;
        }
    }
    for (r, p) in records.iter_mut().zip(packages) {
        if p.meta.is_empty() {
            continue;
        }
        let start = align16(out.pos);
        out.pad_to(start)?;
        let mut n = 0u64;
        for (ty, payload) in &p.meta {
            out.write_all(&ty.to_le_bytes())?;
            out.write_all(&0u16.to_le_bytes())?;
            out.write_all(&u32_of(payload.len())?.to_le_bytes())?;
            out.write_all(payload)?;
            n += 8 + payload.len() as u64;
        }
        r.meta_offset = start;
        r.meta_size =
            u32::try_from(n).or_else(|_| malformed("NUP writer: meta block passes u32"))?;
    }
    let file_size = out.pos;
    let toc = Toc {
        records: &records,
        dirs: &dir_recs,
        files: &files,
        children: &children,
        pool: &pool.bytes,
    }
    .bytes();
    if toc.len() as u64 != toc_len {
        return malformed("NUP writer: the table changed size while writing");
    }
    out.buf.flush()?;
    let mut tmp = out
        .buf
        .into_inner()
        .map_err(|e| Error::Io(e.into_error()))?;
    tmp.seek(SeekFrom::Start(0))?;
    tmp.write_all(&superblock(&toc, blob_offset, file_size, &records))?;
    tmp.write_all(&toc)?;
    let gap = blob_offset - SUPERBLOCK_SIZE - toc_len;
    tmp.write_all(&ZEROS[..usize::try_from(gap).unwrap_or(0)])?;
    tmp.commit()?;
    summary.file_size = file_size;
    Ok(summary)
}
