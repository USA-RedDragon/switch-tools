//! NCZ: a compressed NCA, the member format of NSZ packages.
//!
//! An NCZ keeps the first [`HEADER_REGION`] bytes of the NCA as they are
//! (encrypted), then `NCZSECTN`, a table of the NCA's sections with their
//! AES-CTR keys and counters, and the rest of the NCA in plaintext,
//! compressed with zstd either as one stream or as independent blocks
//! (`NCZBLOCK`). Restoring the NCA means decompressing and encrypting each
//! section with AES-CTR again; the result is bit-identical to the original
//! NCA, which the content record's SHA-256 confirms.
//!
//! The layout follows the nsz project (<https://github.com/nicoboss/nsz>),
//! whose license is reproduced here as its terms require for the format
//! description and the re-encryption rules ported from its decompressor:
//!
//! ```text
//! MIT License
//!
//! Copyright (c) 2019 Nico Bosshard and Blake Warner
//!
//! Some code inside NSZ originates from NUT. Blake Warner, as the author of
//! NUT, permits to license all NUT code used in NSZ to the following MIT
//! license.
//!
//! Permission is hereby granted, free of charge, to any person obtaining a
//! copy of this software and associated documentation files (the
//! "Software"), to deal in the Software without restriction, including
//! without limitation the rights to use, copy, modify, merge, publish,
//! distribute, sublicense, and/or sell copies of the Software, and to
//! permit persons to whom the Software is furnished to do so, subject to
//! the following conditions:
//!
//! The above copyright notice and this permission notice shall be included
//! in all copies or substantial portions of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
//! OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
//! MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
//! IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
//! CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
//! TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
//! SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//! ```
//!
//! # Design
//!
//! [`Ncz::plain_body`] is a [`Storage`] over the decompressed bytes from
//! [`HEADER_REGION`] on. With the block layout it is random access (one
//! block is cached). With the single-stream layout it keeps one streaming
//! decoder: reads that move forward are cheap, a read before the decoder's
//! position restarts decompression from the beginning, so a solid NCZ is
//! best read in order. [`Ncz::to_encrypted_storage`] is a storage over the
//! restored NCA that encrypts on read, so [`crate::nca::Nca::open`] and
//! everything above it work on an NCZ unchanged, and [`Ncz::to_nca`]
//! streams the restored NCA to a writer while hashing it.
//!
//! # Round trips
//!
//! The section table and the block header are kept as read (padding and
//! reserved fields included), so a future writer can reproduce them. The
//! compressed bytes themselves are not reproducible: zstd output depends on
//! the encoder version and level, so NCZ to NCA to NCZ yields an equivalent,
//! not an identical, file. NCA to NCZ to NCA is exact.

use std::io::{BufReader, Read, Write};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use zstd::stream::read::Decoder;

use crate::bytes::{array, to_usize, u8_at, u32_at, u64_at};
use crate::cnmt::Cnmt;
use crate::crypto::ctr_apply;
use crate::error::{Error, Result, malformed};
use crate::keys::{Keys, TitleKeys};
use crate::nca::Nca;
use crate::storage::{Shared, Storage, check_range, read_vec};

/// The bytes at the start of an NCA that an NCZ stores as they are.
pub const HEADER_REGION: u64 = 0x4000;
/// The magic of the section table.
pub const SECTION_MAGIC: &[u8; 8] = b"NCZSECTN";
/// The magic of the block header.
pub const BLOCK_MAGIC: &[u8; 8] = b"NCZBLOCK";
/// The size of the block header without the block size list.
pub const BLOCK_HEADER_SIZE: u64 = 0x18;
/// The size of one section table entry.
pub const SECTION_ENTRY_SIZE: u64 = 0x40;
/// The most sections a table may declare (an NCA has four).
const MAX_SECTIONS: u64 = 0x1000;
/// Block size exponents nsz accepts.
const BLOCK_EXPONENTS: std::ops::RangeInclusive<u8> = 14..=32;
/// How much one streaming step moves.
const CHUNK: usize = 0x10_0000;

/// One entry of the section table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    /// The section's offset in the NCA.
    pub offset: u64,
    /// The section's size in bytes.
    pub size: u64,
    /// The NCA encryption type of the section: 3 (AES-CTR) and 4 (BKTR,
    /// treated as AES-CTR over the whole section) are encrypted again on
    /// restore, anything else is stored as is.
    pub crypto_type: u64,
    /// The padding field as read.
    pub padding: u64,
    /// The AES-CTR key.
    pub key: [u8; 16],
    /// The AES-CTR counter block as stored; its first 8 bytes are the
    /// upper half, the lower half is replaced by the stream offset / 16.
    pub counter: [u8; 16],
}

impl Section {
    /// Whether the section is encrypted on restore.
    pub fn is_encrypted(&self) -> bool {
        matches!(self.crypto_type, 3 | 4)
    }

    /// The end offset in the NCA.
    pub fn end(&self) -> u64 {
        self.offset.saturating_add(self.size)
    }

    fn upper(&self) -> [u8; 8] {
        let mut u = [0u8; 8];
        u.copy_from_slice(&self.counter[..8]);
        u
    }

    /// The 0x40-byte table entry.
    pub fn to_bytes(&self) -> [u8; 0x40] {
        let mut b = [0u8; 0x40];
        b[..8].copy_from_slice(&self.offset.to_le_bytes());
        b[8..16].copy_from_slice(&self.size.to_le_bytes());
        b[16..24].copy_from_slice(&self.crypto_type.to_le_bytes());
        b[24..32].copy_from_slice(&self.padding.to_le_bytes());
        b[32..48].copy_from_slice(&self.key);
        b[48..64].copy_from_slice(&self.counter);
        b
    }
}

/// The header of the block layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    /// The version byte.
    pub version: u8,
    /// The type byte.
    pub kind: u8,
    /// The unused byte as read.
    pub unused: u8,
    /// log2 of the block size, 14 to 32.
    pub block_size_exponent: u8,
    /// The total decompressed size (the NCA size minus [`HEADER_REGION`]).
    pub decompressed_size: u64,
    /// The stored size of each block. A block whose stored size equals its
    /// decompressed size is raw.
    pub compressed_sizes: Vec<u32>,
}

impl BlockHeader {
    /// The block size in bytes.
    pub fn block_size(&self) -> u64 {
        1u64 << self.block_size_exponent
    }

    /// The decompressed size of block `i`: the block size, or the
    /// remainder for the last block.
    pub fn block_len(&self, i: usize) -> u64 {
        let bs = self.block_size();
        let start = i as u64 * bs;
        self.decompressed_size.saturating_sub(start).min(bs)
    }

    /// The serialized header with the block size list.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(0x18 + self.compressed_sizes.len() * 4);
        b.extend_from_slice(BLOCK_MAGIC);
        b.extend_from_slice(&[
            self.version,
            self.kind,
            self.unused,
            self.block_size_exponent,
        ]);
        b.extend_from_slice(
            &u32::try_from(self.compressed_sizes.len())
                .unwrap_or(0)
                .to_le_bytes(),
        );
        b.extend_from_slice(&self.decompressed_size.to_le_bytes());
        for s in &self.compressed_sizes {
            b.extend_from_slice(&s.to_le_bytes());
        }
        b
    }
}

/// How the body is compressed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Compression {
    /// One zstd stream.
    Solid,
    /// Independently compressed blocks.
    Blocks(BlockHeader),
}

/// One stretch of the NCA from [`HEADER_REGION`] on, as restore sees it.
#[derive(Clone, Copy, Debug)]
struct Span {
    start: u64,
    end: u64,
    key: Option<([u8; 16], [u8; 8])>,
}

/// An opened NCZ.
#[derive(Clone)]
pub struct Ncz {
    header: Arc<Vec<u8>>,
    /// The section table as read.
    pub sections: Vec<Section>,
    /// The compression layout.
    pub compression: Compression,
    /// Where the compressed data starts in the file.
    pub data_offset: u64,
    nca_size: u64,
    spans: Arc<Vec<Span>>,
    body: Shared,
}

impl Ncz {
    /// Parse the section table and compression header of the NCZ in
    /// `storage`. The compressed data is not read.
    ///
    /// # Errors
    ///
    /// A file shorter than its headers, bad magics, a section table that is
    /// not contiguous, block sizes that do not add up, or a block header
    /// that disagrees with the sections.
    pub fn open(storage: Shared) -> Result<Ncz> {
        let fsize = storage.size();
        if fsize < HEADER_REGION + 16 {
            return malformed("NCZ: shorter than the header region and section table");
        }
        let header = read_vec(&*storage, 0, HEADER_REGION)?;
        let mut at = HEADER_REGION;
        let head = read_vec(&*storage, at, 16)?;
        if &head[..8] != SECTION_MAGIC {
            return malformed("NCZ: no NCZSECTN after the header region");
        }
        let count = u64_at(&head, 8, "NCZ")?;
        if count == 0 || count > MAX_SECTIONS {
            return malformed(format!("NCZ: {count} sections"));
        }
        at += 16;
        let table = read_vec(&*storage, at, count * SECTION_ENTRY_SIZE).map_err(|_| {
            Error::Format("NCZ: the section table runs past the end of the file".into())
        })?;
        at += count * SECTION_ENTRY_SIZE;
        let mut sections = Vec::new();
        for i in 0..to_usize(count, "NCZ")? {
            let e = i * 0x40;
            sections.push(Section {
                offset: u64_at(&table, e, "NCZ section")?,
                size: u64_at(&table, e + 8, "NCZ section")?,
                crypto_type: u64_at(&table, e + 16, "NCZ section")?,
                padding: u64_at(&table, e + 24, "NCZ section")?,
                key: array(&table, e + 32, "NCZ section")?,
                counter: array(&table, e + 48, "NCZ section")?,
            });
        }
        let (spans, nca_size) = plan(&sections)?;
        let body_size = nca_size - HEADER_REGION;
        let magic = if fsize >= at + 8 {
            read_vec(&*storage, at, 8)?
        } else {
            Vec::new()
        };
        let (compression, data_offset, body): (Compression, u64, Shared) = if magic == BLOCK_MAGIC {
            let bh = read_vec(&*storage, at, BLOCK_HEADER_SIZE.min(fsize - at))?;
            let exp = u8_at(&bh, 11, "NCZBLOCK")?;
            if !BLOCK_EXPONENTS.contains(&exp) {
                return malformed(format!(
                    "NCZBLOCK: block size exponent {exp} not in 14..=32"
                ));
            }
            let n = u64::from(u32_at(&bh, 12, "NCZBLOCK")?);
            let decompressed_size = u64_at(&bh, 16, "NCZBLOCK")?;
            if n * 4 > fsize - at - BLOCK_HEADER_SIZE {
                return malformed("NCZBLOCK: the block size list runs past the end of the file");
            }
            let list = read_vec(&*storage, at + BLOCK_HEADER_SIZE, n * 4)?;
            let compressed_sizes: Vec<u32> = list
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| u32::from_le_bytes(*c))
                .collect();
            let header = BlockHeader {
                version: u8_at(&bh, 8, "NCZBLOCK")?,
                kind: u8_at(&bh, 9, "NCZBLOCK")?,
                unused: u8_at(&bh, 10, "NCZBLOCK")?,
                block_size_exponent: exp,
                decompressed_size,
                compressed_sizes,
            };
            if decompressed_size != body_size {
                return malformed(format!(
                    "NCZBLOCK: decompressed size {decompressed_size:#x}, the sections say {body_size:#x}"
                ));
            }
            if decompressed_size.div_ceil(header.block_size()) != n {
                return malformed("NCZBLOCK: block count does not match the decompressed size");
            }
            let data_offset = at + BLOCK_HEADER_SIZE + n * 4;
            let mut offsets = Vec::with_capacity(header.compressed_sizes.len());
            let mut pos = data_offset;
            for (i, &c) in header.compressed_sizes.iter().enumerate() {
                if u64::from(c) > header.block_len(i) {
                    return malformed(format!("NCZBLOCK: block {i} is larger than its content"));
                }
                offsets.push(pos);
                pos += u64::from(c);
            }
            if pos > fsize {
                return malformed("NCZBLOCK: the blocks run past the end of the file");
            }
            let body = Arc::new(BlockStorage {
                file: storage,
                header: header.clone(),
                offsets,
                cache: Mutex::new(None),
            });
            (Compression::Blocks(header), data_offset, body)
        } else {
            let body = Arc::new(SolidStorage {
                file: storage,
                data_offset: at,
                size: body_size,
                state: Mutex::new(None),
            });
            (Compression::Solid, at, body)
        };
        Ok(Ncz {
            header: Arc::new(header),
            sections,
            compression,
            data_offset,
            nca_size,
            spans: Arc::new(spans),
            body,
        })
    }

    /// The restored NCA's size.
    pub fn nca_size(&self) -> u64 {
        self.nca_size
    }

    /// The first [`HEADER_REGION`] bytes, as stored (still encrypted).
    pub fn header_region(&self) -> &[u8] {
        &self.header
    }

    /// The decompressed bytes of the NCA from [`HEADER_REGION`] on, with
    /// the sections in plaintext.
    pub fn plain_body(&self) -> Shared {
        self.body.clone()
    }

    /// A storage over the restored NCA that encrypts on read.
    pub fn to_encrypted_storage(&self) -> Shared {
        Arc::new(EncryptedNca {
            header: self.header.clone(),
            spans: self.spans.clone(),
            body: self.body.clone(),
            size: self.nca_size,
        })
    }

    /// Write the restored NCA to `out` and return its SHA-256. With
    /// `expect` the hash is compared at the end (bytes already written stay
    /// written, so a caller writing a file drops the output on error).
    ///
    /// # Errors
    ///
    /// A zstd or block error, a failed write, or [`Error::Hash`] when the
    /// restored NCA's hash differs from `expect`.
    pub fn to_nca(&self, out: &mut dyn Write, expect: Option<&[u8; 32]>) -> Result<[u8; 32]> {
        let storage = self.to_encrypted_storage();
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; CHUNK.min(to_usize(self.nca_size, "NCZ")?)];
        let mut off = 0u64;
        while off < self.nca_size {
            let n = to_usize((buf.len() as u64).min(self.nca_size - off), "NCZ")?;
            storage.read_at(off, &mut buf[..n])?;
            hasher.update(&buf[..n]);
            out.write_all(&buf[..n])?;
            off += n as u64;
        }
        let hash: [u8; 32] = hasher.finalize().into();
        if let Some(want) = expect
            && &hash != want
        {
            return Err(Error::Hash(format!(
                "restored NCA is {}, expected {}",
                crate::hex(&hash),
                crate::hex(want)
            )));
        }
        Ok(hash)
    }

    /// Decompress everything and check the restored NCA's SHA-256 against
    /// `expect`, writing nothing.
    ///
    /// # Errors
    ///
    /// As [`Ncz::to_nca`].
    pub fn verify(&self, expect: &[u8; 32]) -> Result<()> {
        self.to_nca(&mut std::io::sink(), Some(expect)).map(|_| ())
    }
}

/// Lay out the spans after the header region, checking the table is
/// contiguous. Returns the spans and the NCA size.
fn plan(sections: &[Section]) -> Result<(Vec<Span>, u64)> {
    let mut spans = Vec::new();
    let first = &sections[0];
    let mut next = first.offset;
    if first.offset > HEADER_REGION {
        spans.push(Span {
            start: HEADER_REGION,
            end: first.offset,
            key: None,
        });
    }
    for (i, s) in sections.iter().enumerate() {
        if s.offset != next {
            return Err(Error::Unsupported(format!(
                "NCZ section {i} at {:#x} leaves a gap or overlaps (expected {next:#x}); only packed NCAs are supported",
                s.offset
            )));
        }
        let end = s
            .offset
            .checked_add(s.size)
            .ok_or_else(|| Error::Format(format!("NCZ section {i}: size overflows")))?;
        if end < HEADER_REGION {
            return malformed(format!("NCZ section {i} ends inside the header region"));
        }
        spans.push(Span {
            start: s.offset.max(HEADER_REGION),
            end,
            key: s.is_encrypted().then(|| (s.key, s.upper())),
        });
        next = end;
    }
    Ok((spans, next))
}

struct EncryptedNca {
    header: Arc<Vec<u8>>,
    spans: Arc<Vec<Span>>,
    body: Shared,
    size: u64,
}

impl Storage for EncryptedNca {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.size, "NCZ")?;
        let end = offset + buf.len() as u64;
        let head_end = end.min(HEADER_REGION);
        let mut done = 0usize;
        if offset < head_end {
            let n = to_usize(head_end - offset, "NCZ")?;
            let a = to_usize(offset, "NCZ")?;
            buf[..n].copy_from_slice(&self.header[a..a + n]);
            done = n;
        }
        if end <= HEADER_REGION {
            return Ok(());
        }
        let start = offset.max(HEADER_REGION);
        self.body.read_at(start - HEADER_REGION, &mut buf[done..])?;
        for s in self.spans.iter() {
            let (a, b) = (s.start.max(start), s.end.min(end));
            if a >= b {
                continue;
            }
            if let Some((key, upper)) = s.key {
                let lo = done + to_usize(a - start, "NCZ")?;
                let hi = done + to_usize(b - start, "NCZ")?;
                ctr_apply(&key, upper, a, &mut buf[lo..hi]);
            }
        }
        Ok(())
    }
}

fn zstd_err(what: &str, e: impl std::fmt::Display) -> Error {
    Error::Format(format!("NCZ {what}: zstd: {e}"))
}

struct BlockStorage {
    file: Shared,
    header: BlockHeader,
    offsets: Vec<u64>,
    cache: Mutex<Option<(usize, Arc<Vec<u8>>)>>,
}

impl BlockStorage {
    fn block(&self, i: usize) -> Result<Arc<Vec<u8>>> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| Error::Format("NCZ: block cache lock poisoned".into()))?;
        if let Some((n, data)) = cache.as_ref()
            && *n == i
        {
            return Ok(data.clone());
        }
        let raw_len = to_usize(self.header.block_len(i), "NCZ block")?;
        let stored = to_usize(u64::from(self.header.compressed_sizes[i]), "NCZ block")?;
        let bytes = read_vec(&*self.file, self.offsets[i], stored as u64)?;
        let data = if stored < raw_len {
            let out = zstd::bulk::decompress(&bytes, raw_len)
                .map_err(|e| zstd_err(&format!("block {i}"), e))?;
            if out.len() != raw_len {
                return malformed(format!(
                    "NCZ block {i}: decompressed to {:#x} bytes, want {raw_len:#x}",
                    out.len()
                ));
            }
            out
        } else {
            bytes
        };
        let data = Arc::new(data);
        *cache = Some((i, data.clone()));
        Ok(data)
    }
}

impl Storage for BlockStorage {
    fn size(&self) -> u64 {
        self.header.decompressed_size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.size(), "NCZ body")?;
        let bs = self.header.block_size();
        let mut pos = offset;
        let mut done = 0usize;
        while done < buf.len() {
            let i = to_usize(pos / bs, "NCZ")?;
            let within = to_usize(pos % bs, "NCZ")?;
            let block = self.block(i)?;
            let n = (block.len() - within).min(buf.len() - done);
            buf[done..done + n].copy_from_slice(&block[within..within + n]);
            done += n;
            pos += n as u64;
        }
        Ok(())
    }
}

struct StorageReader {
    storage: Shared,
    pos: u64,
}

impl Read for StorageReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.storage.size().saturating_sub(self.pos);
        let n = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        if n == 0 {
            return Ok(0);
        }
        self.storage
            .read_at(self.pos, &mut buf[..n])
            .map_err(std::io::Error::other)?;
        self.pos += n as u64;
        Ok(n)
    }
}

type StreamDecoder = Decoder<'static, BufReader<StorageReader>>;

struct SolidState {
    decoder: StreamDecoder,
    pos: u64,
}

struct SolidStorage {
    file: Shared,
    data_offset: u64,
    size: u64,
    state: Mutex<Option<SolidState>>,
}

impl SolidStorage {
    fn fresh(&self) -> Result<SolidState> {
        let reader = StorageReader {
            storage: self.file.clone(),
            pos: self.data_offset,
        };
        let decoder = Decoder::new(reader).map_err(|e| zstd_err("stream", e))?;
        Ok(SolidState { decoder, pos: 0 })
    }
}

impl Storage for SolidStorage {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.size, "NCZ body")?;
        let mut guard = self
            .state
            .lock()
            .map_err(|_| Error::Format("NCZ: decoder lock poisoned".into()))?;
        let mut state = match guard.take() {
            Some(s) if s.pos <= offset => s,
            _ => self.fresh()?,
        };
        let mut skip = [0u8; 0x1_0000];
        while state.pos < offset {
            let n = skip.len().min(to_usize(offset - state.pos, "NCZ")?);
            state
                .decoder
                .read_exact(&mut skip[..n])
                .map_err(|e| zstd_err("stream", e))?;
            state.pos += n as u64;
        }
        state
            .decoder
            .read_exact(buf)
            .map_err(|e| zstd_err("stream", e))?;
        state.pos += buf.len() as u64;
        *guard = Some(state);
        Ok(())
    }
}

/// Open an NSZ: an NSP whose program NCA entries are `.ncz`. The result
/// reads like [`crate::title::Nsp`]; `.ncz` entries are restored on the
/// fly, so `program`, `cnmt` and [`crate::title::open_title`] work as on an
/// NSP.
///
/// # Errors
///
/// As [`crate::title::Nsp::from_storage`].
pub fn open_nsz(storage: Shared) -> Result<crate::title::Nsp> {
    crate::title::Nsp::from_storage(storage)
}

/// Decompress every `.ncz` entry of `nsp` and compare its SHA-256 with the
/// content record of `cnmt` whose content ID is the entry's file name.
/// Entries with no record are skipped. Returns how many were verified.
///
/// # Errors
///
/// A decompression error or [`Error::Hash`] on the first mismatch.
pub fn verify_nsz(nsp: &crate::title::Nsp, cnmt: &Cnmt) -> Result<usize> {
    let mut n = 0;
    for e in nsp.pfs0().entries() {
        let Some(stem) = e.name.strip_suffix(".ncz") else {
            continue;
        };
        let Some(rec) = cnmt
            .contents
            .iter()
            .find(|r| crate::hex(&r.content_id) == stem.trim_end_matches(".cnmt"))
        else {
            continue;
        };
        Ncz::open(nsp.pfs0().open_entry(e)?)?
            .verify(&rec.hash)
            .map_err(|err| match err {
                Error::Hash(m) => Error::Hash(format!("{}: {m}", e.name)),
                other => other,
            })?;
        n += 1;
    }
    Ok(n)
}

/// How a fixture NCZ is compressed.
#[derive(Clone, Copy, Debug)]
pub enum Layout {
    /// One zstd stream at `level`.
    Solid {
        /// The zstd level.
        level: i32,
    },
    /// Blocks of `1 << exponent` bytes at `level`.
    Blocks {
        /// The block size exponent, 14 to 32.
        exponent: u8,
        /// The zstd level.
        level: i32,
    },
}

/// Build an NCZ from an NCA (fixtures). The sections are decrypted with the
/// NCA's content key, which `keys` and `title_keys` resolve; a section that
/// is not AES-CTR is stored as it is with its crypto type.
///
/// # Errors
///
/// An NCA that does not open, has no section, is not packed, is not larger
/// than [`HEADER_REGION`], or a compression failure.
pub fn build(nca: &[u8], keys: &Keys, title_keys: &TitleKeys, layout: Layout) -> Result<Vec<u8>> {
    if (nca.len() as u64) <= HEADER_REGION {
        return malformed("NCZ: the NCA is not larger than the header region");
    }
    let opened = Nca::open(
        Arc::new(crate::storage::MemStorage(nca.to_vec())),
        keys,
        title_keys,
    )?;
    let mut sections = Vec::new();
    for i in 0..4 {
        let Some((offset, size)) = opened.header().section(i) else {
            continue;
        };
        let fs = opened.header().fs_header(i);
        let encrypted = matches!(
            fs.encryption()?,
            crate::nca::Encryption::Ctr | crate::nca::Encryption::CtrEx
        );
        let mut counter = [0u8; 16];
        counter[..8].copy_from_slice(&fs.counter_upper());
        sections.push(Section {
            offset,
            size,
            crypto_type: match fs.encryption()? {
                crate::nca::Encryption::None => 1,
                crate::nca::Encryption::Xts => 2,
                crate::nca::Encryption::Ctr => 3,
                crate::nca::Encryption::CtrEx => 4,
            },
            padding: 0,
            key: if encrypted {
                opened.key(keys, title_keys)?
            } else {
                [0; 16]
            },
            counter,
        });
    }
    if sections.is_empty() {
        return malformed("NCZ: the NCA has no section");
    }
    let (spans, nca_size) = plan(&sections)?;
    if nca_size != nca.len() as u64 {
        return malformed("NCZ: the sections do not cover the NCA");
    }
    let mut body = nca[HEADER_REGION as usize..].to_vec();
    for s in &spans {
        if let Some((key, upper)) = s.key {
            let lo = (s.start - HEADER_REGION) as usize;
            let hi = (s.end - HEADER_REGION) as usize;
            ctr_apply(&key, upper, s.start, &mut body[lo..hi]);
        }
    }
    let mut out = nca[..HEADER_REGION as usize].to_vec();
    out.extend_from_slice(SECTION_MAGIC);
    out.extend_from_slice(&(sections.len() as u64).to_le_bytes());
    for s in &sections {
        out.extend_from_slice(&s.to_bytes());
    }
    match layout {
        Layout::Solid { level } => {
            let z = zstd::bulk::compress(&body, level).map_err(|e| zstd_err("compress", e))?;
            out.extend_from_slice(&z);
        }
        Layout::Blocks { exponent, level } => {
            let bs = 1usize << exponent;
            let mut stored = Vec::new();
            let mut sizes = Vec::new();
            for chunk in body.chunks(bs) {
                let z = zstd::bulk::compress(chunk, level).map_err(|e| zstd_err("compress", e))?;
                let piece: &[u8] = if z.len() < chunk.len() { &z } else { chunk };
                sizes.push(u32::try_from(piece.len()).unwrap_or(0));
                stored.extend_from_slice(piece);
            }
            let header = BlockHeader {
                version: 2,
                kind: 1,
                unused: 0,
                block_size_exponent: exponent,
                decompressed_size: body.len() as u64,
                compressed_sizes: sizes,
            };
            out.extend_from_slice(&header.to_bytes());
            out.extend_from_slice(&stored);
        }
    }
    Ok(out)
}

/// Build an NSZ from an NSP (fixtures): every NCA larger than
/// [`HEADER_REGION`] whose content type is program becomes an `.ncz`, the
/// rest is copied. Names keep their stem.
///
/// # Errors
///
/// A bad NSP or NCA, or a compression failure.
pub fn build_nsz(nsp: &[u8], keys: &Keys, layout: Layout) -> Result<Vec<u8>> {
    let src = crate::title::Nsp::from_storage(Arc::new(crate::storage::MemStorage(nsp.to_vec())))?;
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    for e in src.pfs0().entries() {
        let data = src.pfs0().read(e)?;
        if e.name.ends_with(".nca") && (data.len() as u64) > HEADER_REGION {
            let n = Nca::open(
                Arc::new(crate::storage::MemStorage(data.clone())),
                keys,
                src.title_keys(),
            )?;
            if n.header().content_type() == crate::nca::ContentType::Program {
                let z = build(&data, keys, src.title_keys(), layout)?;
                files.push((e.name.replace(".nca", ".ncz"), z));
                continue;
            }
        }
        files.push((e.name.clone(), data));
    }
    let list: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    Ok(crate::pfs0::build(&list))
}
