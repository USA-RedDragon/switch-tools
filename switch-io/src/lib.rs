//! The one place that writes files and the one place that starts a
//! subprocess.
//!
//! `clippy.toml` disallows `std::fs::write`, `File::create`,
//! `OpenOptions::open`, `fs::copy` and `io::copy` everywhere else, so every
//! file the tools produce goes through [`write_if_changed`], the streaming
//! [`StreamWriter`] beside it, or the random-access [`TempFile`] that is
//! renamed over its target when complete. An unchanged output keeps its
//! mtime. All three open files for writing through one private funnel
//! function. `std::process::Command::new` is disallowed too; [`command`] is
//! its one caller.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A [`Command`] that runs `program`.
#[expect(
    clippy::disallowed_methods,
    reason = "the funnel clippy.toml points every other caller at"
)]
pub fn command(program: impl AsRef<OsStr>) -> Command {
    Command::new(program)
}

/// The temporary path beside `path` that a writer fills before renaming.
fn tmp_beside(path: &Path) -> io::Result<PathBuf> {
    let mut name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?
        .to_os_string();
    name.push(".switch-tools-tmp");
    Ok(path.with_file_name(name))
}

/// A new file written at any offset, beside its target, that replaces the
/// target only on [`TempFile::commit`]. Dropping it uncommitted removes the
/// temporary file and leaves the target as it was.
///
/// Writers that fill a header last (a NUP superblock and table of contents
/// after the blob region) seek back to the front before committing.
pub struct TempFile {
    file: Option<File>,
    path: PathBuf,
    tmp_path: PathBuf,
}

impl TempFile {
    /// Start a temporary file for `path`.
    ///
    /// # Errors
    ///
    /// The path has no file name or the temporary file cannot be created.
    pub fn new(path: &Path) -> io::Result<TempFile> {
        let tmp_path = tmp_beside(path)?;
        let file = create(&tmp_path)?;
        Ok(TempFile {
            file: Some(file),
            path: path.to_path_buf(),
            tmp_path,
        })
    }

    fn file(&mut self) -> io::Result<&mut File> {
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("temporary file already closed"))
    }

    /// Cut the file to `len` bytes and move the write position there, as
    /// when an extent just written turns out to duplicate an earlier one.
    ///
    /// # Errors
    ///
    /// Truncating or seeking fails.
    pub fn truncate(&mut self, len: u64) -> io::Result<()> {
        let f = self.file()?;
        f.set_len(len)?;
        f.seek(SeekFrom::Start(len))?;
        Ok(())
    }

    /// Flush, sync and rename the file over its target.
    ///
    /// # Errors
    ///
    /// Flushing, syncing or renaming fails.
    pub fn commit(mut self) -> io::Result<()> {
        if let Some(mut f) = self.file.take() {
            f.flush()?;
            f.sync_all()?;
        }
        std::fs::rename(&self.tmp_path, &self.path)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if self.file.take().is_some() {
            let _ = std::fs::remove_file(&self.tmp_path);
        }
    }
}

impl Write for TempFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file()?.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file()?.flush()
    }
}

impl Seek for TempFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file()?.seek(pos)
    }
}

/// Open `path` for writing, creating or truncating it. The one function that
/// opts out of the clippy funnel.
#[expect(
    clippy::disallowed_methods,
    reason = "the funnel clippy.toml points every other writer at"
)]
fn create(path: &Path) -> io::Result<File> {
    File::create(path)
}

/// Write `bytes` to `path` unless the file already holds exactly them.
/// Returns whether the file was written.
///
/// # Errors
///
/// Any error reading the old file (other than it not existing) or writing
/// the new one.
pub fn write_if_changed(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    match std::fs::read(path) {
        Ok(old) if old == bytes => return Ok(false),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut file = create(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(true)
}

/// Where a [`StreamWriter`] stands.
enum State {
    /// Every byte so far equals the old file's; nothing is written yet.
    Matching { old: File, matched: u64 },
    /// The output differs (or there was no old file): bytes go to a
    /// temporary file that replaces the target on [`StreamWriter::finish`].
    Writing { tmp: File },
}

/// A write-if-changed writer for outputs too large to hold in memory.
///
/// While the stream equals the existing file it only reads and compares; at
/// the first difference it starts a temporary file beside the target, copies
/// the equal prefix into it and goes on writing. [`StreamWriter::finish`]
/// renames the temporary file over the target, or leaves an unchanged target
/// (and its mtime) alone. Dropping the writer without `finish` leaves the
/// target as it was.
pub struct StreamWriter {
    path: PathBuf,
    tmp_path: PathBuf,
    state: State,
    scratch: Vec<u8>,
}

impl StreamWriter {
    /// Start writing `path`.
    ///
    /// # Errors
    ///
    /// Opening the old file failed for a reason other than it not existing,
    /// or the temporary file could not be created.
    pub fn new(path: &Path) -> io::Result<StreamWriter> {
        let tmp_path = tmp_beside(path)?;
        let state = match File::open(path) {
            Ok(old) if old.metadata()?.is_file() => State::Matching { old, matched: 0 },
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{} is not a file", path.display()),
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => State::Writing {
                tmp: create(&tmp_path)?,
            },
            Err(e) => return Err(e),
        };
        Ok(StreamWriter {
            path: path.to_path_buf(),
            tmp_path,
            state,
            scratch: Vec::new(),
        })
    }

    /// Leave matching mode: copy the matched prefix of the old file into a
    /// new temporary file.
    fn diverge(&mut self) -> io::Result<()> {
        if let State::Matching { old, matched } = &mut self.state {
            let mut tmp = create(&self.tmp_path)?;
            old.seek(SeekFrom::Start(0))?;
            let mut left = *matched;
            let mut buf = vec![0u8; 1 << 20];
            while left > 0 {
                let n = usize::try_from(left.min(buf.len() as u64)).unwrap_or(buf.len());
                old.read_exact(&mut buf[..n])?;
                tmp.write_all(&buf[..n])?;
                left -= n as u64;
            }
            self.state = State::Writing { tmp };
        }
        Ok(())
    }

    /// Finish the stream. Returns whether the target was (re)written.
    ///
    /// # Errors
    ///
    /// Reading the old file, writing or renaming the new one failed.
    pub fn finish(mut self) -> io::Result<bool> {
        if let State::Matching { old, .. } = &mut self.state {
            let mut probe = [0u8; 1];
            if old.read(&mut probe)? == 0 {
                return Ok(false);
            }
            self.diverge()?;
        }
        if let State::Writing { tmp } = &mut self.state {
            tmp.flush()?;
        }
        std::fs::rename(&self.tmp_path, &self.path)?;
        Ok(true)
    }
}

impl Write for StreamWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let State::Matching { old, matched } = &mut self.state {
            self.scratch.resize(buf.len(), 0);
            let mut got = 0;
            while got < buf.len() {
                let n = old.read(&mut self.scratch[got..])?;
                if n == 0 {
                    break;
                }
                got += n;
            }
            if got == buf.len() && self.scratch[..] == buf[..] {
                *matched += buf.len() as u64;
                return Ok(buf.len());
            }
            self.diverge()?;
        }
        match &mut self.state {
            State::Writing { tmp } => tmp.write_all(buf).map(|()| buf.len()),
            State::Matching { .. } => Err(io::Error::other("stream writer did not diverge")),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.state {
            State::Writing { tmp } => tmp.flush(),
            State::Matching { .. } => Ok(()),
        }
    }
}
