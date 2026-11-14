//! The write-if-changed writers.

use std::io::Write;
use std::path::{Path, PathBuf};

use switch_io::{StreamWriter, write_if_changed};

fn dir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("test dir");
    d
}

fn stream(path: &Path, chunks: &[&[u8]]) -> bool {
    let mut w = StreamWriter::new(path).expect("open");
    for c in chunks {
        w.write_all(c).expect("write");
    }
    w.finish().expect("finish")
}

#[test]
fn stream_writes_new_then_skips_equal_then_rewrites_changed() {
    let d = dir("stream");
    let p = d.join("out.bin");
    assert!(stream(&p, &[b"hello ", b"world"]));
    assert_eq!(std::fs::read(&p).expect("read"), b"hello world");
    assert!(!stream(&p, &[b"hello", b" world"]));
    assert!(stream(&p, &[b"hello ", b"there"]));
    assert_eq!(std::fs::read(&p).expect("read"), b"hello there");
    assert!(stream(&p, &[b"hello there", b"!"]));
    assert_eq!(std::fs::read(&p).expect("read"), b"hello there!");
    assert!(stream(&p, &[b"hello"]));
    assert_eq!(std::fs::read(&p).expect("read"), b"hello");
    assert!(!d.join("out.bin.switch-tools-tmp").exists());
}

#[test]
fn a_dropped_stream_leaves_the_target_and_no_temporary_file() {
    let d = dir("dropped");
    let p = d.join("out.bin");
    assert!(stream(&p, &[b"old"]));
    let mut w = switch_io::StreamWriter::new(&p).expect("start");
    w.write_all(b"new and longer").expect("write");
    drop(w);
    assert_eq!(std::fs::read(&p).expect("read"), b"old");
    assert!(!d.join("out.bin.switch-tools-tmp").exists());
}

#[test]
fn write_if_changed_reports_changes() {
    let d = dir("whole");
    let p = d.join("a");
    assert!(write_if_changed(&p, b"x").expect("write"));
    assert!(!write_if_changed(&p, b"x").expect("write"));
    assert!(write_if_changed(&p, b"y").expect("write"));
}
