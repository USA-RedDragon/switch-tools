//! The write funnel writes new or changed content and leaves identical
//! content alone.

use std::path::PathBuf;

use switch_io::write_if_changed;

fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("switch-io-tests");
    std::fs::create_dir_all(&dir).expect("the scratch dir is creatable");
    let path = dir.join(name);
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn writes_new_then_skips_same_then_writes_changed() {
    let path = scratch("funnel.bin");
    assert!(write_if_changed(&path, b"one").expect("first write"));
    assert!(!write_if_changed(&path, b"one").expect("same bytes"));
    assert!(write_if_changed(&path, b"two").expect("changed bytes"));
    assert_eq!(std::fs::read(&path).expect("readable"), b"two");
}
