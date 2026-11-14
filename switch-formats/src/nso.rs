//! NSO executables: LZ4-compressed segments, the module path in .rodata,
//! MOD0 and the dynamic symbol table.

use crate::bytes::{array, hex, i32_at, slice, to_usize, u8_at, u16_at, u32_at, u64_at};
use crate::crypto::sha256;
use crate::error::{Error, Result, malformed};

/// The size of an NSO header.
pub const HEADER_SIZE: usize = 0x100;

/// One loaded segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    /// The offset in the module image.
    pub memory_offset: u32,
    /// The decompressed size.
    pub size: u32,
}

/// The MOD0 header, offsets relative to the image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mod0 {
    /// Where MOD0 sits.
    pub offset: u32,
    /// `.dynamic`.
    pub dynamic: u64,
    /// The start of .bss.
    pub bss_start: u64,
    /// The end of .bss.
    pub bss_end: u64,
    /// `.eh_frame_hdr` start.
    pub eh_frame_hdr_start: u64,
    /// `.eh_frame_hdr` end.
    pub eh_frame_hdr_end: u64,
    /// The runtime module object.
    pub module_object: u64,
}

/// One dynamic symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol {
    /// The name.
    pub name: String,
    /// The value (an image offset for defined symbols).
    pub value: u64,
    /// The size.
    pub size: u64,
    /// `st_info`: type in the low nibble, binding in the high.
    pub info: u8,
    /// `st_shndx`; 0 means imported.
    pub section: u16,
}

impl Symbol {
    /// Whether the module defines the symbol (rather than importing it).
    pub fn is_defined(&self) -> bool {
        self.section != 0
    }
}

/// A parsed, decompressed NSO.
#[derive(Clone, Debug)]
pub struct Nso {
    header: [u8; HEADER_SIZE],
    /// text, rodata, data.
    pub segments: [Segment; 3],
    /// The .bss size after data.
    pub bss_size: u32,
    /// The 32-byte module (build) ID.
    pub build_id: [u8; 32],
    /// The module image: the three segments at their offsets, gaps zeroed,
    /// without .bss.
    pub image: Vec<u8>,
}

impl Nso {
    /// Parse and decompress an NSO, checking each segment's SHA-256 when
    /// the header asks for it.
    ///
    /// # Errors
    ///
    /// Bad magic, overlapping or out-of-range segments, an LZ4 error or a
    /// segment hash mismatch.
    pub fn parse(b: &[u8]) -> Result<Nso> {
        if b.get(..4) != Some(b"NSO0") {
            return malformed("NSO: bad magic");
        }
        let header: [u8; HEADER_SIZE] = array(b, 0, "NSO header")?;
        let flags = u32_at(b, 0xC, "NSO")?;
        let mut segments = [Segment {
            memory_offset: 0,
            size: 0,
        }; 3];
        let mut image = Vec::new();
        for (i, seg) in segments.iter_mut().enumerate() {
            let file_off = to_usize(u64::from(u32_at(b, 0x10 + i * 0x10, "NSO")?), "NSO")?;
            let mem = u32_at(b, 0x14 + i * 0x10, "NSO")?;
            let size = u32_at(b, 0x18 + i * 0x10, "NSO")?;
            let file_size = u32_at(b, 0x60 + i * 4, "NSO")? as usize;
            *seg = Segment {
                memory_offset: mem,
                size,
            };
            let name = ["text", "rodata", "data"][i];
            let raw = slice(b, file_off, file_size, name)?;
            let size_us = size as usize;
            let data = if flags & (1 << i) != 0 {
                let mut out = vec![0u8; size_us];
                let n = lz4_flex::block::decompress_into(raw, &mut out)
                    .map_err(|e| Error::Format(format!("NSO {name}: LZ4: {e}")))?;
                if n != size_us {
                    return malformed(format!(
                        "NSO {name}: decompressed to {n:#x} bytes, header says {size:#x}"
                    ));
                }
                out
            } else {
                if file_size != size_us {
                    return malformed(format!("NSO {name}: stored size differs from size"));
                }
                raw.to_vec()
            };
            if flags & (8 << i) != 0 {
                let want: [u8; 32] = array(b, 0xA0 + i * 0x20, "NSO")?;
                if sha256(&data) != want {
                    return Err(Error::Hash(format!("NSO {name} segment")));
                }
            }
            let start = mem as usize;
            if start < image.len() {
                return malformed(format!("NSO {name}: overlaps the previous segment"));
            }
            image.resize(start, 0);
            image.extend_from_slice(&data);
        }
        Ok(Nso {
            header,
            segments,
            bss_size: u32_at(b, 0x3C, "NSO")?,
            build_id: array(b, 0x40, "NSO")?,
            image,
        })
    }

    /// The build ID as lowercase hex (all 32 bytes).
    pub fn build_id_hex(&self) -> String {
        hex(&self.build_id)
    }

    /// The module path recorded at the start of .rodata (`u32 0`, `u32
    /// length`, the path), if present.
    pub fn module_path(&self) -> Option<String> {
        let ro = self.segments[1].memory_offset as usize;
        if u32_at(&self.image, ro, "").ok()? != 0 {
            return None;
        }
        let len = u32_at(&self.image, ro + 4, "").ok()? as usize;
        if len == 0 || len > 0x200 {
            return None;
        }
        let raw = slice(&self.image, ro + 8, len, "").ok()?;
        let raw = &raw[..raw.iter().position(|&c| c == 0).unwrap_or(raw.len())];
        if raw.is_empty() || !raw.iter().all(|c| (0x20..0x7f).contains(c)) {
            return None;
        }
        String::from_utf8(raw.to_vec()).ok()
    }

    /// The module name: the module path's file stem (`nnSdk`, `vulkan`, or
    /// the game's own name for main).
    pub fn module_name(&self) -> Option<String> {
        let path = self.module_path()?;
        let file = path.rsplit(['/', '\\']).next().unwrap_or(&path);
        let stem = match file.rsplit_once('.') {
            Some((s, ext)) if ["nss", "nso", "nrs", "elf"].contains(&ext) && !s.is_empty() => s,
            _ => file,
        };
        Some(stem.to_string())
    }

    /// The MOD0 header, if the image has one.
    ///
    /// # Errors
    ///
    /// A MOD0 offset past the image.
    pub fn mod0(&self) -> Result<Option<Mod0>> {
        parse_mod0(&self.image)
    }

    /// The dynamic symbols, from the .dynsym and .dynstr extents the header
    /// records (relative to .rodata).
    ///
    /// # Errors
    ///
    /// Extents past the image or a name past .dynstr.
    pub fn symbols(&self) -> Result<Vec<Symbol>> {
        let ro = self.segments[1].memory_offset as usize;
        let str_off = u32_at(&self.header, 0x90, "NSO")? as usize;
        let str_size = u32_at(&self.header, 0x94, "NSO")? as usize;
        let sym_off = u32_at(&self.header, 0x98, "NSO")? as usize;
        let sym_size = u32_at(&self.header, 0x9C, "NSO")? as usize;
        let strtab = slice(&self.image, ro + str_off, str_size, ".dynstr")?;
        let symtab = slice(&self.image, ro + sym_off, sym_size, ".dynsym")?;
        read_symbols(strtab, symtab)
    }

    /// The flat module image with .bss zero-filled.
    pub fn flat_image(&self) -> Vec<u8> {
        let mut v = self.image.clone();
        v.resize(v.len() + self.bss_size as usize, 0);
        v
    }

    /// An uncompressed NSO: the original header with the compression flags
    /// cleared, the module-name size zeroed, each segment's file offset at
    /// `0x100 + memory offset` and its file size the decompressed size,
    /// followed by the image. This is the layout of hactool's uncompressed
    /// NSO output; the segment hashes stay valid.
    pub fn to_uncompressed(&self) -> Vec<u8> {
        let mut h = self.header;
        let flags = u32::from_le_bytes([h[0xC], h[0xD], h[0xE], h[0xF]]) & !7;
        h[0xC..0x10].copy_from_slice(&flags.to_le_bytes());
        h[0x2C..0x30].copy_from_slice(&0u32.to_le_bytes());
        for (i, s) in self.segments.iter().enumerate() {
            let off = (HEADER_SIZE as u32).wrapping_add(s.memory_offset);
            h[0x10 + i * 0x10..0x14 + i * 0x10].copy_from_slice(&off.to_le_bytes());
            h[0x60 + i * 4..0x64 + i * 4].copy_from_slice(&s.size.to_le_bytes());
        }
        let mut out = h.to_vec();
        out.extend_from_slice(&self.image);
        out
    }
}

/// Read the MOD0 header the image's second word points at, or `None` if no
/// MOD0 magic is there. Shared with [`crate::nro`], whose images start the
/// same way.
///
/// # Errors
///
/// A MOD0 offset past the image or a negative resolved offset.
pub(crate) fn parse_mod0(image: &[u8]) -> Result<Option<Mod0>> {
    let at = u32_at(image, 4, "image")?;
    let a = at as usize;
    if slice(image, a, 4, "MOD0").ok() != Some(b"MOD0") {
        return Ok(None);
    }
    let rel = |o: usize| -> Result<u64> {
        let v = i64::from(i32_at(image, a + o, "MOD0")?);
        u64::try_from(i64::from(at) + v).or_else(|_| malformed("MOD0: negative offset"))
    };
    Ok(Some(Mod0 {
        offset: at,
        dynamic: rel(4)?,
        bss_start: rel(8)?,
        bss_end: rel(0xC)?,
        eh_frame_hdr_start: rel(0x10)?,
        eh_frame_hdr_end: rel(0x14)?,
        module_object: rel(0x18)?,
    }))
}

/// Read the dynamic symbols (skipping the null entry) from a .dynstr and a
/// .dynsym blob.
///
/// # Errors
///
/// A name offset past the string table.
pub(crate) fn read_symbols(strtab: &[u8], symtab: &[u8]) -> Result<Vec<Symbol>> {
    let mut out = Vec::new();
    for i in 1..symtab.len() / 24 {
        let e = &symtab[i * 24..i * 24 + 24];
        let name_at = u32_at(e, 0, ".dynsym")? as usize;
        let rest = strtab
            .get(name_at..)
            .ok_or_else(|| Error::Format(format!("symbol {i}: name past .dynstr")))?;
        let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
        out.push(Symbol {
            name: String::from_utf8_lossy(&rest[..end]).into_owned(),
            info: u8_at(e, 4, ".dynsym")?,
            section: u16_at(e, 6, ".dynsym")?,
            value: u64_at(e, 8, ".dynsym")?,
            size: u64_at(e, 16, ".dynsym")?,
        });
    }
    Ok(out)
}

/// Inputs of a fixture NSO.
#[derive(Clone, Debug, Default)]
pub struct NsoSpec {
    /// .text bytes.
    pub text: Vec<u8>,
    /// .rodata bytes.
    pub rodata: Vec<u8>,
    /// .data bytes.
    pub data: Vec<u8>,
    /// .bss size.
    pub bss: u32,
    /// The build ID.
    pub build_id: [u8; 32],
    /// (.dynstr, .dynsym) extents relative to .rodata.
    pub dyn_extents: [(u32, u32); 2],
    /// Compress the segments with LZ4.
    pub compress: bool,
}

/// Build an NSO (fixtures): segments page-aligned in memory, compressed
/// with LZ4 if asked, with segment hashes.
pub fn build(spec: &NsoSpec) -> Vec<u8> {
    let page = |n: usize| u32::try_from(n.div_ceil(0x1000) * 0x1000).unwrap_or(0);
    let segs = [&spec.text, &spec.rodata, &spec.data];
    let mems = [
        0,
        page(spec.text.len()),
        page(spec.text.len()) + page(spec.rodata.len()),
    ];
    let mut h = vec![0u8; HEADER_SIZE];
    h[..4].copy_from_slice(b"NSO0");
    let mut flags = 0x38u32;
    if spec.compress {
        flags |= 7;
    }
    h[0xC..0x10].copy_from_slice(&flags.to_le_bytes());
    let mut body = Vec::new();
    for (i, s) in segs.iter().enumerate() {
        let stored = if spec.compress {
            lz4_flex::block::compress(s)
        } else {
            s.to_vec()
        };
        let off = u32::try_from(HEADER_SIZE + body.len()).unwrap_or(0);
        h[0x10 + i * 0x10..0x14 + i * 0x10].copy_from_slice(&off.to_le_bytes());
        h[0x14 + i * 0x10..0x18 + i * 0x10].copy_from_slice(&mems[i].to_le_bytes());
        h[0x18 + i * 0x10..0x1C + i * 0x10]
            .copy_from_slice(&u32::try_from(s.len()).unwrap_or(0).to_le_bytes());
        h[0x60 + i * 4..0x64 + i * 4]
            .copy_from_slice(&u32::try_from(stored.len()).unwrap_or(0).to_le_bytes());
        h[0xA0 + i * 0x20..0xC0 + i * 0x20].copy_from_slice(&sha256(s));
        body.extend_from_slice(&stored);
    }
    h[0x3C..0x40].copy_from_slice(&spec.bss.to_le_bytes());
    h[0x40..0x60].copy_from_slice(&spec.build_id);
    h[0x90..0x94].copy_from_slice(&spec.dyn_extents[0].0.to_le_bytes());
    h[0x94..0x98].copy_from_slice(&spec.dyn_extents[0].1.to_le_bytes());
    h[0x98..0x9C].copy_from_slice(&spec.dyn_extents[1].0.to_le_bytes());
    h[0x9C..0xA0].copy_from_slice(&spec.dyn_extents[1].1.to_le_bytes());
    h.extend_from_slice(&body);
    h
}
