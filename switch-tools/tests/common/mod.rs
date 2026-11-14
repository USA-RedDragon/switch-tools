//! Shared fixtures and a runner for the tool CLI tests: the synthetic base
//! and update NSPs and key files are written once per test under the
//! target's temp dir, and each tool runs as a real subprocess.

#![allow(dead_code)]

use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::sync::Arc;

use switch_formats::nca::{ContentType, Nca};
use switch_formats::pfs0::Pfs0;
use switch_formats::romfs::Romfs;
use switch_formats::storage::MemStorage;
use switch_formats::synth::{self, Game};
use switch_formats::title::Nsp;

/// A written fixture set.
pub struct Fixture {
    pub dir: PathBuf,
    pub game: Game,
    pub base: PathBuf,
    pub update: PathBuf,
    pub keys: PathBuf,
    pub wrong_keys: PathBuf,
}

/// Write the fixtures of test `name` into a fresh directory.
pub fn fixture(name: &str) -> Fixture {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir is creatable");
    let game = synth::game();
    let put = |file: &str, bytes: &[u8]| {
        let p = dir.join(file);
        switch_io::write_if_changed(&p, bytes).expect("the fixture is writable");
        p
    };
    let base = put("base.nsp", &game.base);
    let update = put("update.nsp", &game.update);
    let keys = put("prod.keys", game.keys.text.as_bytes());
    let wrong_keys = put("wrong.keys", synth::keys(9).text.as_bytes());
    Fixture {
        dir,
        game,
        base,
        update,
        keys,
        wrong_keys,
    }
}

/// Run a tool binary (`switch-nsp`, ...) with `args`, optional stdin, in
/// the fixture directory, with no inherited settings.
pub fn tool(bin: &str, dir: &Path, args: &[&OsStr], stdin: Option<&[u8]>) -> Output {
    let exe = exe(bin);
    let mut child = switch_io::command(exe)
        .args(args)
        .env_remove("SWITCH_TOOLS_KEYS")
        .env_remove("SWITCH_TOOLS_TITLE_KEYS")
        .current_dir(dir)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the tool starts");
    if let Some(bytes) = stdin {
        let mut pipe = child.stdin.take().expect("stdin is piped");
        let bytes = bytes.to_vec();
        let writer = std::thread::spawn(move || {
            let _ = pipe.write_all(&bytes);
        });
        let out = child.wait_with_output().expect("the tool finishes");
        writer.join().expect("the stdin writer finishes");
        out
    } else {
        child.wait_with_output().expect("the tool finishes")
    }
}

fn exe(bin: &str) -> PathBuf {
    match bin {
        "switch-nsp" => env!("CARGO_BIN_EXE_switch-nsp").into(),
        "switch-nca" => env!("CARGO_BIN_EXE_switch-nca").into(),
        "switch-bktr" => env!("CARGO_BIN_EXE_switch-bktr").into(),
        "switch-xci" => env!("CARGO_BIN_EXE_switch-xci").into(),
        "switch-ncz" => env!("CARGO_BIN_EXE_switch-ncz").into(),
        other => panic!("unknown tool {other}"),
    }
}

/// Shorthand: run with string-like args and no stdin.
pub fn run(bin: &str, dir: &Path, args: &[&str]) -> Output {
    let os: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    tool(bin, dir, &os, None)
}

/// Shorthand: run with string-like args and stdin bytes.
pub fn run_stdin(bin: &str, dir: &Path, args: &[&str], stdin: &[u8]) -> Output {
    let os: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    tool(bin, dir, &os, Some(stdin))
}

pub fn ok(out: &Output) -> &Output {
    assert!(
        out.status.success(),
        "tool failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// Assert exit code 1 with exactly one stderr line containing `needle`.
pub fn fails_with(out: &Output, needle: &str) {
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(1), "stderr: {err}");
    assert_eq!(err.trim_end().lines().count(), 1, "stderr: {err}");
    assert!(err.contains(needle), "want {needle:?} in {err:?}");
}

pub fn path(p: &Path) -> &str {
    p.to_str().expect("fixture paths are UTF-8")
}

pub fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&ok(out).stdout).expect("the tool printed JSON")
}

/// The (name, bytes) files of an NSP.
pub fn nsp_files(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let pfs = Pfs0::open(Arc::new(MemStorage(bytes.to_vec()))).expect("the fixture is a PFS0");
    pfs.entries()
        .iter()
        .map(|e| (e.name.clone(), pfs.read(e).expect("entry reads")))
        .collect()
}

/// The program NCA's file name in an NSP.
pub fn program_nca(g: &Game, nsp: &[u8]) -> String {
    let nsp = Nsp::from_storage(Arc::new(MemStorage(nsp.to_vec()))).expect("nsp opens");
    nsp.ncas(&g.keys.keys)
        .expect("ncas open")
        .into_iter()
        .find(|(_, n): &(String, Nca)| n.header().content_type() == ContentType::Program)
        .expect("a program NCA")
        .0
}

/// The `.tik` file name in an NSP.
pub fn ticket_name(nsp: &[u8]) -> String {
    nsp_files(nsp)
        .into_iter()
        .find(|(n, _)| n.ends_with(".tik"))
        .expect("a ticket")
        .0
}

/// Sorted (path, bytes) of every file under `dir`, `/`-separated.
pub fn tree(dir: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(root: &Path, at: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for e in std::fs::read_dir(at).expect("dir reads") {
            let p = e.expect("entry").path();
            if p.is_dir() {
                walk(root, &p, out);
            } else {
                let rel = p.strip_prefix(root).expect("under root");
                out.push((
                    rel.to_str().expect("UTF-8").replace('\\', "/"),
                    std::fs::read(&p).expect("file reads"),
                ));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// Write `bytes` as `dir/name` and return the path.
pub fn put(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    switch_io::write_if_changed(&p, bytes).expect("the fixture is writable");
    p
}

/// The bytes of the NSP entry `name`.
pub fn entry(nsp: &[u8], name: &str) -> Vec<u8> {
    nsp_files(nsp)
        .into_iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("no entry {name}"))
        .1
}

/// The program NCA and ticket of an NSP written under `dir` as
/// `<tag>.nca` and `<tag>.tik`.
pub fn program_files(g: &Game, nsp: &[u8], dir: &Path, tag: &str) -> (PathBuf, PathBuf) {
    let nca = put(
        dir,
        &format!("{tag}.nca"),
        &entry(nsp, &program_nca(g, nsp)),
    );
    let tik = put(dir, &format!("{tag}.tik"), &entry(nsp, &ticket_name(nsp)));
    (nca, tik)
}

/// Sorted (path, bytes) of every file of a romfs image.
pub fn romfs_tree(image: &[u8]) -> Vec<(String, Vec<u8>)> {
    let r = Romfs::open(Arc::new(MemStorage(image.to_vec()))).expect("the image is a romfs");
    let mut out: Vec<(String, Vec<u8>)> = r
        .files()
        .iter()
        .map(|f| {
            let mut v = Vec::new();
            r.copy_file(f, &mut v).expect("the file reads");
            (f.path.clone(), v)
        })
        .collect();
    out.sort();
    out
}

/// Sorted (path, bytes) of a romfs spec.
pub fn sorted(files: &[(String, Vec<u8>)]) -> Vec<(String, Vec<u8>)> {
    let mut v = files.to_vec();
    v.sort();
    v
}
