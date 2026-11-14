//! Random-access byte sources the readers layer over each other: a file, a
//! buffer, a window into another storage.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::error::{Error, Result};

/// A fixed-size byte source read at offsets.
pub trait Storage: Send + Sync {
    /// The size in bytes.
    fn size(&self) -> u64;

    /// Fill `buf` from `offset`.
    ///
    /// # Errors
    ///
    /// The range runs past [`Storage::size`], or a lower layer fails.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;
}

/// A shared storage, the currency between layers.
pub type Shared = Arc<dyn Storage>;

/// Check that `offset..offset+len` lies in `size`.
pub(crate) fn check_range(offset: u64, len: usize, size: u64, what: &str) -> Result<()> {
    match offset.checked_add(len as u64) {
        Some(end) if end <= size => Ok(()),
        _ => Err(Error::Format(format!(
            "{what}: read of {len:#x} bytes at {offset:#x} past the end ({size:#x})"
        ))),
    }
}

/// Read `len` bytes at `offset` into a new buffer.
///
/// # Errors
///
/// As [`Storage::read_at`].
pub fn read_vec(s: &dyn Storage, offset: u64, len: u64) -> Result<Vec<u8>> {
    let len = usize::try_from(len)
        .map_err(|_| Error::Format(format!("read of {len:#x} bytes does not fit in memory")))?;
    let mut v = vec![0u8; len];
    s.read_at(offset, &mut v)?;
    Ok(v)
}

/// Read a whole storage into memory.
///
/// # Errors
///
/// As [`Storage::read_at`].
pub fn read_all(s: &dyn Storage) -> Result<Vec<u8>> {
    read_vec(s, 0, s.size())
}

/// A file opened for reading.
pub struct FileStorage {
    file: Mutex<File>,
    size: u64,
    name: String,
}

impl FileStorage {
    /// Open `path`.
    ///
    /// # Errors
    ///
    /// The file cannot be opened.
    pub fn open(path: &Path) -> Result<FileStorage> {
        let file = File::open(path).map_err(|e| {
            Error::Io(std::io::Error::new(
                e.kind(),
                format!("{}: {e}", path.display()),
            ))
        })?;
        let size = file.metadata()?.len();
        Ok(FileStorage {
            file: Mutex::new(file),
            size,
            name: path.display().to_string(),
        })
    }
}

impl Storage for FileStorage {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.size, &self.name)?;
        let mut f = self
            .file
            .lock()
            .map_err(|_| Error::Format(format!("{}: reader lock poisoned", self.name)))?;
        f.seek(SeekFrom::Start(offset))?;
        f.read_exact(buf)?;
        Ok(())
    }
}

/// Bytes in memory.
pub struct MemStorage(pub Vec<u8>);

impl Storage for MemStorage {
    fn size(&self) -> u64 {
        self.0.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.size(), "memory")?;
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        buf.copy_from_slice(&self.0[start..start + buf.len()]);
        Ok(())
    }
}

/// `size` zero bytes, standing in for a base section an update patches
/// from nothing.
pub struct ZeroStorage(pub u64);

impl Storage for ZeroStorage {
    fn size(&self) -> u64 {
        self.0
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.0, "zero storage")?;
        buf.fill(0);
        Ok(())
    }
}

/// A window `offset..offset+size` into another storage.
pub struct SubStorage {
    base: Shared,
    offset: u64,
    size: u64,
}

impl SubStorage {
    /// The window, checked against the base's size.
    ///
    /// # Errors
    ///
    /// The window runs past the base.
    pub fn new(base: Shared, offset: u64, size: u64) -> Result<SubStorage> {
        match offset.checked_add(size) {
            Some(end) if end <= base.size() => Ok(SubStorage { base, offset, size }),
            _ => Err(Error::Format(format!(
                "window {offset:#x}+{size:#x} runs past its storage ({:#x})",
                base.size()
            ))),
        }
    }

    /// The window as a [`Shared`].
    ///
    /// # Errors
    ///
    /// As [`SubStorage::new`].
    pub fn shared(base: Shared, offset: u64, size: u64) -> Result<Shared> {
        Ok(Arc::new(SubStorage::new(base, offset, size)?))
    }
}

impl Storage for SubStorage {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.size, "window")?;
        self.base.read_at(self.offset + offset, buf)
    }
}
