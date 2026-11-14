//! CNMT, the content meta of a title: its ID, version and the hash of each
//! content NCA.

use crate::bytes::{array, u8_at, u16_at, u32_at, u64_at};
use crate::error::Result;

/// One content record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentRecord {
    /// The SHA-256 of the whole NCA.
    pub hash: [u8; 32],
    /// The content ID (the first half of the hash; the NCA file name).
    pub content_id: [u8; 16],
    /// The NCA size.
    pub size: u64,
    /// The content type byte (0 meta, 1 program, 2 data, 3 control, ...).
    pub content_type: u8,
    /// The ID offset byte.
    pub id_offset: u8,
}

/// A parsed CNMT. `raw` keeps the file for bit-exact rewrites.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cnmt {
    /// The title ID.
    pub title_id: u64,
    /// The title version.
    pub version: u32,
    /// The meta type (0x80 application, 0x81 patch, 0x82 add-on content).
    pub meta_type: u8,
    /// The content records.
    pub contents: Vec<ContentRecord>,
    /// The whole file as read.
    pub raw: Vec<u8>,
}

impl Cnmt {
    /// Parse a `.cnmt` file.
    ///
    /// # Errors
    ///
    /// A short file.
    pub fn parse(b: &[u8]) -> Result<Cnmt> {
        let ext = usize::from(u16_at(b, 0xE, "CNMT")?);
        let count = usize::from(u16_at(b, 0x10, "CNMT")?);
        let mut contents = Vec::with_capacity(count);
        for i in 0..count {
            let at = 0x20 + ext + i * 0x38;
            let mut size = [0u8; 8];
            size[..6].copy_from_slice(&array::<6>(b, at + 0x30, "CNMT record")?);
            contents.push(ContentRecord {
                hash: array(b, at, "CNMT record")?,
                content_id: array(b, at + 0x20, "CNMT record")?,
                size: u64::from_le_bytes(size),
                content_type: u8_at(b, at + 0x36, "CNMT record")?,
                id_offset: u8_at(b, at + 0x37, "CNMT record")?,
            });
        }
        Ok(Cnmt {
            title_id: u64_at(b, 0, "CNMT")?,
            version: u32_at(b, 8, "CNMT")?,
            meta_type: u8_at(b, 0xC, "CNMT")?,
            contents,
            raw: b.to_vec(),
        })
    }
}

/// Build a CNMT (fixtures) with no extended header.
pub fn build(title_id: u64, version: u32, meta_type: u8, contents: &[ContentRecord]) -> Vec<u8> {
    let mut b = vec![0u8; 0x20];
    b[0..8].copy_from_slice(&title_id.to_le_bytes());
    b[8..12].copy_from_slice(&version.to_le_bytes());
    b[0xC] = meta_type;
    b[0x10..0x12].copy_from_slice(&u16::try_from(contents.len()).unwrap_or(0).to_le_bytes());
    for c in contents {
        let mut r = vec![0u8; 0x38];
        r[..0x20].copy_from_slice(&c.hash);
        r[0x20..0x30].copy_from_slice(&c.content_id);
        r[0x30..0x36].copy_from_slice(&c.size.to_le_bytes()[..6]);
        r[0x36] = c.content_type;
        r[0x37] = c.id_offset;
        b.extend_from_slice(&r);
    }
    b.extend_from_slice(&[0u8; 0x20]);
    b
}
