//! RomFS: the read-only file tree of a game's data.

use std::io::Write;
use std::path::Path;

use crate::bytes::{slice, u32_at, u64_at};
use crate::error::{Error, Result, malformed};
use crate::storage::{Shared, read_vec};

const NONE: u32 = u32::MAX;

/// One file of a romfs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RomfsFile {
    /// The path from the root, `/`-separated, without a leading slash.
    pub path: String,
    /// The data offset in the romfs storage.
    pub offset: u64,
    /// The size in bytes.
    pub size: u64,
}

/// An opened romfs.
pub struct Romfs {
    storage: Shared,
    files: Vec<RomfsFile>,
    dirs: Vec<String>,
}

fn name_at(table: &[u8], at: usize, len_at: usize, what: &str) -> Result<String> {
    let len = u32_at(table, len_at, what)? as usize;
    let raw = slice(table, at, len, what)?;
    let name = String::from_utf8(raw.to_vec())
        .or_else(|_| malformed(format!("{what}: name is not UTF-8")))?;
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']) {
        return malformed(format!("{what}: unsafe name {name:?}"));
    }
    Ok(name)
}

impl Romfs {
    /// Parse the header and both meta tables of the romfs in `storage`.
    ///
    /// # Errors
    ///
    /// A malformed header or table, a loop, or an unsafe name.
    pub fn open(storage: Shared) -> Result<Romfs> {
        let h = read_vec(&*storage, 0, 0x50.min(storage.size()))?;
        if u64_at(&h, 0, "romfs header")? != 0x50 {
            return malformed("romfs: header size is not 0x50");
        }
        let dir_meta = (u64_at(&h, 0x18, "romfs")?, u64_at(&h, 0x20, "romfs")?);
        let file_meta = (u64_at(&h, 0x38, "romfs")?, u64_at(&h, 0x40, "romfs")?);
        let data = u64_at(&h, 0x48, "romfs")?;
        let dirs_t = read_vec(&*storage, dir_meta.0, dir_meta.1)?;
        let files_t = read_vec(&*storage, file_meta.0, file_meta.1)?;
        let mut files = Vec::new();
        let mut dirs = Vec::new();
        let mut stack = vec![(0u32, String::new())];
        let mut visited = 0usize;
        let limit = dirs_t.len() / 0x18 + 1;
        while let Some((d, prefix)) = stack.pop() {
            visited += 1;
            if visited > limit {
                return malformed("romfs: directory loop");
            }
            let at = d as usize;
            let mut child_file = u32_at(&dirs_t, at + 0xC, "romfs dir")?;
            let mut seen = 0usize;
            while child_file != NONE {
                seen += 1;
                if seen > files_t.len() / 0x20 + 1 {
                    return malformed("romfs: file loop");
                }
                let f = child_file as usize;
                let name = name_at(&files_t, f + 0x20, f + 0x1C, "romfs file")?;
                let offset = u64_at(&files_t, f + 8, "romfs file")?;
                let size = u64_at(&files_t, f + 0x10, "romfs file")?;
                let abs = data
                    .checked_add(offset)
                    .filter(|a| a.checked_add(size).is_some_and(|e| e <= storage.size()))
                    .ok_or_else(|| {
                        Error::Format(format!("romfs file {prefix}{name}: past the end"))
                    })?;
                files.push(RomfsFile {
                    path: format!("{prefix}{name}"),
                    offset: abs,
                    size,
                });
                child_file = u32_at(&files_t, f + 4, "romfs file")?;
            }
            let mut child = u32_at(&dirs_t, at + 8, "romfs dir")?;
            let mut seen = 0usize;
            while child != NONE {
                seen += 1;
                if seen > limit {
                    return malformed("romfs: directory loop");
                }
                let c = child as usize;
                let name = name_at(&dirs_t, c + 0x18, c + 0x14, "romfs dir")?;
                let path = format!("{prefix}{name}");
                dirs.push(path.clone());
                stack.push((child, format!("{path}/")));
                child = u32_at(&dirs_t, c + 4, "romfs dir")?;
            }
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        dirs.sort();
        Ok(Romfs {
            storage,
            files,
            dirs,
        })
    }

    /// Every file, sorted by path.
    pub fn files(&self) -> &[RomfsFile] {
        &self.files
    }

    /// Every directory below the root, sorted.
    pub fn dirs(&self) -> &[String] {
        &self.dirs
    }

    /// Stream one file into `out`.
    ///
    /// # Errors
    ///
    /// A read (or hash check) fails, or writing fails.
    pub fn copy_file(&self, file: &RomfsFile, out: &mut dyn Write) -> Result<()> {
        let mut buf = vec![0u8; 0x10_0000.min(usize::try_from(file.size).unwrap_or(0))];
        let mut off = 0;
        while off < file.size {
            let n = (buf.len() as u64).min(file.size - off);
            let b = &mut buf[..usize::try_from(n).unwrap_or(0)];
            self.storage.read_at(file.offset + off, b)?;
            out.write_all(b)?;
            off += n;
        }
        Ok(())
    }

    /// Extract the tree under `dir` through switch-io's streaming
    /// write-if-changed writer, in data order. Returns how many files were
    /// rewritten.
    ///
    /// # Errors
    ///
    /// A read, hash check or write fails.
    pub fn extract(&self, dir: &Path) -> Result<usize> {
        std::fs::create_dir_all(dir)?;
        for d in &self.dirs {
            std::fs::create_dir_all(dir.join(d))?;
        }
        let mut order: Vec<&RomfsFile> = self.files.iter().collect();
        order.sort_by_key(|f| f.offset);
        let mut written = 0;
        for f in order {
            let mut w = switch_io::StreamWriter::new(&dir.join(&f.path))?;
            self.copy_file(f, &mut w)?;
            if w.finish()? {
                written += 1;
            }
        }
        Ok(written)
    }
}

/// Build a romfs image from `files` (path, data) for fixtures. Paths are
/// `/`-separated without a leading slash.
pub fn build(files: &[(&str, &[u8])]) -> Vec<u8> {
    struct Dir {
        name: String,
        parent: usize,
        dirs: Vec<usize>,
        files: Vec<usize>,
    }
    let mut dirs = vec![Dir {
        name: String::new(),
        parent: 0,
        dirs: vec![],
        files: vec![],
    }];
    let mut sorted: Vec<&(&str, &[u8])> = files.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    for (i, (path, _)) in sorted.iter().enumerate() {
        let parts: Vec<&str> = path.split('/').collect();
        let mut cur = 0;
        for p in &parts[..parts.len() - 1] {
            let found = dirs[cur].dirs.iter().copied().find(|&d| dirs[d].name == *p);
            cur = match found {
                Some(d) => d,
                None => {
                    dirs.push(Dir {
                        name: (*p).to_string(),
                        parent: cur,
                        dirs: vec![],
                        files: vec![],
                    });
                    let id = dirs.len() - 1;
                    dirs[cur].dirs.push(id);
                    id
                }
            };
        }
        dirs[cur].files.push(i);
    }
    let pad4 = |n: usize| n.div_ceil(4) * 4;
    let mut dir_off = vec![0u32; dirs.len()];
    let mut o = 0usize;
    for (i, d) in dirs.iter().enumerate() {
        dir_off[i] = u32::try_from(o).unwrap_or(0);
        o += 0x18 + pad4(d.name.len());
    }
    let dir_table_len = o;
    let names: Vec<String> = sorted
        .iter()
        .map(|(p, _)| p.rsplit('/').next().unwrap_or("").to_string())
        .collect();
    let mut file_off = vec![0u32; sorted.len()];
    let mut o = 0usize;
    let mut file_parent = vec![0usize; sorted.len()];
    for (di, d) in dirs.iter().enumerate() {
        for &f in &d.files {
            file_off[f] = u32::try_from(o).unwrap_or(0);
            file_parent[f] = di;
            o += 0x20 + pad4(names[f].len());
        }
    }
    let file_table_len = o;
    let mut data = Vec::new();
    let mut data_off = vec![0u64; sorted.len()];
    for (i, (_, bytes)) in sorted.iter().enumerate() {
        data_off[i] = data.len() as u64;
        data.extend_from_slice(bytes);
        data.resize(data.len().div_ceil(16) * 16, 0);
    }
    let mut dt = vec![0u8; dir_table_len];
    for (i, d) in dirs.iter().enumerate() {
        let at = dir_off[i] as usize;
        let parent = dir_off[d.parent];
        let sibling = if i == 0 {
            NONE
        } else {
            let sibs = &dirs[d.parent].dirs;
            let pos = sibs.iter().position(|&s| s == i).unwrap_or(0);
            sibs.get(pos + 1).map_or(NONE, |&s| dir_off[s])
        };
        let child = d.dirs.first().map_or(NONE, |&c| dir_off[c]);
        let file = d.files.first().map_or(NONE, |&f| file_off[f]);
        for (k, v) in [parent, sibling, child, file, NONE].iter().enumerate() {
            dt[at + k * 4..at + k * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        dt[at + 0x14..at + 0x18]
            .copy_from_slice(&u32::try_from(d.name.len()).unwrap_or(0).to_le_bytes());
        dt[at + 0x18..at + 0x18 + d.name.len()].copy_from_slice(d.name.as_bytes());
    }
    let mut ft = vec![0u8; file_table_len];
    for (i, name) in names.iter().enumerate() {
        let at = file_off[i] as usize;
        let d = &dirs[file_parent[i]];
        let pos = d.files.iter().position(|&f| f == i).unwrap_or(0);
        let sibling = d.files.get(pos + 1).map_or(NONE, |&f| file_off[f]);
        ft[at..at + 4].copy_from_slice(&dir_off[file_parent[i]].to_le_bytes());
        ft[at + 4..at + 8].copy_from_slice(&sibling.to_le_bytes());
        ft[at + 8..at + 16].copy_from_slice(&data_off[i].to_le_bytes());
        ft[at + 16..at + 24].copy_from_slice(&(sorted[i].1.len() as u64).to_le_bytes());
        ft[at + 24..at + 28].copy_from_slice(&NONE.to_le_bytes());
        ft[at + 28..at + 32].copy_from_slice(&u32::try_from(name.len()).unwrap_or(0).to_le_bytes());
        ft[at + 32..at + 32 + name.len()].copy_from_slice(name.as_bytes());
    }
    let hash = NONE.to_le_bytes().to_vec();
    let mut out = vec![0u8; 0x50];
    let dir_hash = out.len() as u64;
    out.extend_from_slice(&hash);
    let dir_meta = out.len() as u64;
    out.extend_from_slice(&dt);
    let file_hash = out.len() as u64;
    out.extend_from_slice(&hash);
    let file_meta = out.len() as u64;
    out.extend_from_slice(&ft);
    out.resize(out.len().div_ceil(16) * 16, 0);
    let data_at = out.len() as u64;
    out.extend_from_slice(&data);
    let fields = [
        0x50,
        dir_hash,
        4,
        dir_meta,
        dt.len() as u64,
        file_hash,
        4,
        file_meta,
        ft.len() as u64,
        data_at,
    ];
    for (k, v) in fields.iter().enumerate() {
        out[k * 8..k * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    out
}
