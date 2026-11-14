//! NUP containers: synthetic ones built per the spec read back bit for bit,
//! pick the right update, list DLC, extract through the streaming writer
//! and fail closed on corruption.

use std::path::PathBuf;
use std::sync::Arc;

use switch_formats::Error;
use switch_formats::npdm;
use switch_formats::nup::{
    self, BuildPackage, Codec, Nup, PackageKind, TLV_DISPLAY_VERSION, TLV_NPDM, UpdateSelect,
};
use switch_formats::storage::MemStorage;

const BASE_ID: u64 = 0x0100_0000_0000_2000;
const DLC_ID: u64 = 0x0100_0000_0000_2001;

fn text(n: usize) -> Vec<u8> {
    b"switch-tools nup fixture line\n".repeat(n)
}

fn noise(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 8) as u8
        })
        .collect()
}

struct Fixture {
    npdm_base: Vec<u8>,
    npdm_upd: Vec<u8>,
    main_base: Vec<u8>,
    main_v1: Vec<u8>,
    main_v2: Vec<u8>,
    big: Vec<u8>,
    raw: Vec<u8>,
    big_v1: Vec<u8>,
    big_v2: Vec<u8>,
    dlc: Vec<u8>,
}

fn fixture() -> Fixture {
    Fixture {
        npdm_base: npdm::build("game", BASE_ID, 0x10000, &[("fs:p", false)]),
        npdm_upd: npdm::build("game", BASE_ID, 0x20000, &[("fs:p", false)]),
        main_base: text(400),
        main_v1: text(500),
        main_v2: text(600),
        big: text(30_000),
        raw: noise(5_000, 7),
        big_v1: text(31_000),
        big_v2: text(32_000),
        dlc: text(900),
    }
}

fn container(f: &Fixture) -> Vec<u8> {
    let base = BuildPackage {
        title_id: BASE_ID,
        version: 0,
        kind: PackageKind::Base,
        standalone: false,
        files: vec![
            ("exefs/main", &f.main_base),
            ("exefs/main.npdm", &f.npdm_base),
            ("romfs/data/big.txt", &f.big),
            ("romfs/data/noise.bin", &f.raw),
            ("romfs/empty.bin", b""),
            ("romfs/same.txt", &f.big),
        ],
        empty_dirs: vec!["romfs/void"],
        meta: vec![
            (TLV_NPDM, f.npdm_base.clone()),
            (TLV_DISPLAY_VERSION, b"1.0.0".to_vec()),
        ],
    };
    let upd1 = BuildPackage {
        title_id: BASE_ID,
        version: 0x10000,
        kind: PackageKind::Update,
        standalone: false,
        files: vec![
            ("exefs/main", &f.main_v1),
            ("exefs/main.npdm", &f.npdm_upd),
            ("romfs/data/big.txt", &f.big_v1),
            ("romfs/data/noise.bin", &f.raw),
        ],
        empty_dirs: vec![],
        meta: vec![(TLV_DISPLAY_VERSION, b"1.1.0".to_vec())],
    };
    let upd2 = BuildPackage {
        title_id: BASE_ID,
        version: 0x20000,
        kind: PackageKind::Update,
        standalone: false,
        files: vec![
            ("exefs/main", &f.main_v2),
            ("exefs/main.npdm", &f.npdm_upd),
            ("romfs/data/big.txt", &f.big_v2),
            ("romfs/data/noise.bin", &f.raw),
            ("romfs/new.txt", b"added in 2"),
        ],
        empty_dirs: vec![],
        meta: vec![(TLV_DISPLAY_VERSION, b"1.2.0".to_vec())],
    };
    let dlc = BuildPackage {
        title_id: DLC_ID,
        version: 0,
        kind: PackageKind::Addon,
        standalone: false,
        files: vec![("romfs/dlc.txt", &f.dlc)],
        empty_dirs: vec![],
        meta: vec![],
    };
    nup::build(&[base, upd1, upd2, dlc])
}

fn open(bytes: Vec<u8>) -> Result<Nup, Error> {
    Nup::open(Arc::new(MemStorage(bytes)))
}

fn read_named(n: &Nup, files: &[(String, nup::NupEntry)], name: &str) -> Vec<u8> {
    let e = &files
        .iter()
        .find(|(p, _)| p == name)
        .expect("file listed")
        .1;
    n.read(e).expect("file reads")
}

#[test]
fn round_trip_lists_every_package() {
    let f = fixture();
    let n = open(container(&f)).expect("opens");
    assert!(n.uuid_matches());
    let kinds: Vec<_> = n
        .packages()
        .iter()
        .map(|p| (p.record.kind, p.record.title_id, p.record.version))
        .collect();
    assert_eq!(
        kinds,
        [
            (PackageKind::Base, BASE_ID, 0),
            (PackageKind::Update, BASE_ID, 0x10000),
            (PackageKind::Update, BASE_ID, 0x20000),
            (PackageKind::Addon, DLC_ID, 0),
        ]
    );
    let base = &n.packages()[0];
    assert_eq!(base.display_version().as_deref(), Some("1.0.0"));
    assert_eq!(base.npdm_program_id(), Some(BASE_ID));
    let exefs = base.exefs();
    assert_eq!(
        exefs.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>(),
        ["main", "main.npdm"]
    );
    assert_eq!(read_named(&n, &exefs, "main"), f.main_base);
    let romfs = base.romfs();
    assert_eq!(read_named(&n, &romfs, "data/big.txt"), f.big);
    assert_eq!(read_named(&n, &romfs, "same.txt"), f.big);
    assert_eq!(read_named(&n, &romfs, "data/noise.bin"), f.raw);
    assert!(read_named(&n, &romfs, "empty.bin").is_empty());
    let codec = |name: &str| romfs.iter().find(|(p, _)| p == name).unwrap().1.codec;
    assert_eq!(codec("data/big.txt"), Codec::Zstd);
    assert_eq!(codec("data/noise.bin"), Codec::Raw);
    let big = romfs.iter().find(|(p, _)| p == "data/big.txt").unwrap();
    let same = romfs.iter().find(|(p, _)| p == "same.txt").unwrap();
    assert_eq!(big.1.extent_offset, same.1.extent_offset, "dedup");
    assert_eq!(base.romfs_dirs(), ["data", "void"]);
}

#[test]
fn newest_update_is_the_default() {
    let f = fixture();
    let n = open(container(&f)).expect("opens");
    let t = n.effective_title(UpdateSelect::Newest).expect("title");
    assert_eq!(t.update, Some(2));
    assert_eq!(t.base, Some(0));
    assert_eq!(t.version, 0x20000);
    assert_eq!(t.display_version.as_deref(), Some("1.2.0"));
    assert_eq!(t.program_id, BASE_ID);
    assert_eq!(read_named(&n, &t.exefs, "main"), f.main_v2);
    assert_eq!(read_named(&n, &t.romfs, "data/big.txt"), f.big_v2);
    assert_eq!(read_named(&n, &t.romfs, "new.txt"), b"added in 2");
    assert!(
        t.romfs.iter().all(|(p, _)| p != "same.txt"),
        "an update's romfs is the full patched tree, not layered over the base"
    );
}

#[test]
fn chosen_update_and_base_alone() {
    let f = fixture();
    let n = open(container(&f)).expect("opens");
    let t = n
        .effective_title(UpdateSelect::Version(0x10000))
        .expect("title");
    assert_eq!(t.update, Some(1));
    assert_eq!(read_named(&n, &t.exefs, "main"), f.main_v1);
    assert_eq!(read_named(&n, &t.romfs, "data/big.txt"), f.big_v1);
    let b = n.effective_title(UpdateSelect::None).expect("title");
    assert_eq!(b.update, None);
    assert_eq!(b.version, 0);
    assert_eq!(read_named(&n, &b.exefs, "main"), f.main_base);
    assert!(b.romfs.iter().any(|(p, _)| p == "same.txt"));
    assert!(matches!(
        n.effective_title(UpdateSelect::Version(0x30000)),
        Err(Error::Format(_))
    ));
}

#[test]
fn dlc_is_listed_and_extractable() {
    let f = fixture();
    let n = open(container(&f)).expect("opens");
    let dlc: Vec<_> = n
        .packages()
        .iter()
        .filter(|p| p.record.kind == PackageKind::Addon)
        .collect();
    assert_eq!(dlc.len(), 1);
    assert_eq!(dlc[0].record.title_id, DLC_ID);
    assert_eq!(read_named(&n, &dlc[0].romfs(), "dlc.txt"), f.dlc);
}

#[test]
fn update_without_trees_inherits_the_base() {
    let f = fixture();
    let base = BuildPackage {
        title_id: BASE_ID,
        version: 0,
        kind: PackageKind::Base,
        standalone: false,
        files: vec![("exefs/main", &f.main_base), ("romfs/a.bin", &f.raw)],
        empty_dirs: vec![],
        meta: vec![],
    };
    let upd = BuildPackage {
        title_id: BASE_ID,
        version: 0x10000,
        kind: PackageKind::Update,
        standalone: false,
        files: vec![("exefs/main", &f.main_v1)],
        empty_dirs: vec![],
        meta: vec![],
    };
    let n = open(nup::build(&[base, upd])).expect("opens");
    let t = n.effective_title(UpdateSelect::Newest).expect("title");
    assert_eq!(read_named(&n, &t.exefs, "main"), f.main_v1);
    assert_eq!(read_named(&n, &t.romfs, "a.bin"), f.raw);
}

#[test]
fn extract_writes_exefs_and_romfs_trees() {
    let f = fixture();
    let n = open(container(&f)).expect("opens");
    let t = n.effective_title(UpdateSelect::Newest).expect("title");
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("nup-extract");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(n.extract_romfs(&t, &dir.join("romfs")).expect("romfs"), 3);
    assert_eq!(n.extract_exefs(&t, &dir.join("exefs")).expect("exefs"), 2);
    assert_eq!(std::fs::read(dir.join("exefs/main")).unwrap(), f.main_v2);
    assert_eq!(
        std::fs::read(dir.join("romfs/data/big.txt")).unwrap(),
        f.big_v2
    );
    assert_eq!(
        std::fs::read(dir.join("romfs/new.txt")).unwrap(),
        b"added in 2"
    );
    assert_eq!(n.extract_romfs(&t, &dir.join("romfs")).expect("again"), 0);
    let all = dir.join("all");
    assert_eq!(n.extract_package(0, &all).expect("package"), 6);
    assert!(all.join("romfs/void").is_dir());
    assert_eq!(std::fs::read(all.join("romfs/same.txt")).unwrap(), f.big);
}

fn find(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len())
        .position(|w| w == needle)
        .expect("needle present")
}

#[test]
fn corrupted_file_content_is_a_hash_error() {
    let f = fixture();
    let good = container(&f);
    let n = open(good.clone()).expect("opens");
    let romfs = n.packages()[0].romfs();
    let raw = &romfs.iter().find(|(p, _)| p == "data/noise.bin").unwrap().1;
    let zst = &romfs.iter().find(|(p, _)| p == "data/big.txt").unwrap().1;
    assert_eq!((raw.codec, zst.codec), (Codec::Raw, Codec::Zstd));
    let mut bad = good.clone();
    bad[raw.extent_offset as usize + 100] ^= 1;
    let n = open(bad).expect("the table is intact");
    let mut sink = Vec::new();
    assert!(matches!(n.copy(raw, &mut sink), Err(Error::Hash(_))));
    assert_eq!(sink.len() as u64, raw.size, "streamed before the end check");

    let mut bad = good;
    bad[zst.extent_offset as usize + zst.extent_size as usize / 2] ^= 0xFF;
    let n = open(bad).expect("the table is intact");
    assert!(n.read(zst).is_err());
}

#[test]
fn failed_extract_leaves_no_finished_file() {
    let f = fixture();
    let mut bytes = container(&f);
    let n = open(bytes.clone()).expect("opens");
    let t = n.effective_title(UpdateSelect::None).expect("title");
    let e = &t.exefs.iter().find(|(p, _)| p == "main").unwrap().1;
    bytes[e.extent_offset as usize + 4] ^= 1;
    let n = open(bytes).expect("opens");
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("nup-bad-extract");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(matches!(
        n.extract_exefs(&t, &dir),
        Err(Error::Hash(_)) | Err(Error::Format(_))
    ));
    assert!(!dir.join("main").exists());
}

#[test]
fn corrupted_toc_is_a_hash_error() {
    let f = fixture();
    let good = container(&f);
    let at = find(&good, b"romfs") + 1;
    let mut bad = good.clone();
    bad[at] ^= 1;
    assert!(matches!(open(bad), Err(Error::Hash(_))));
    let mut bad = good;
    bad[0x90] ^= 1;
    assert!(matches!(open(bad), Err(Error::Hash(_))));
}

#[test]
fn malformed_superblocks_are_rejected() {
    let f = fixture();
    let good = container(&f);
    let patch = |at: usize, v: &[u8]| {
        let mut b = good.clone();
        b[at..at + v.len()].copy_from_slice(v);
        open(b)
    };
    assert!(matches!(patch(0, b"XUP\x01"), Err(Error::Format(_))));
    assert!(matches!(patch(3, &[2]), Err(Error::Unsupported(_))));
    assert!(matches!(patch(0x4C, &[1]), Err(Error::Unsupported(_))));
    assert!(matches!(patch(0x38, &[0x41]), Err(Error::Format(_))));
    assert!(matches!(patch(0x48, &[0, 0, 0, 0]), Err(Error::Format(_))));
    let mut short = good.clone();
    short.pop();
    assert!(matches!(open(short), Err(Error::Format(_))));
    assert!(matches!(open(vec![0; 10]), Err(Error::Format(_))));
}

#[test]
fn a_size_lie_in_a_file_record_is_caught() {
    let f = fixture();
    let n = open(container(&f)).expect("opens");
    let romfs = n.packages()[0].romfs();
    let mut e = romfs
        .iter()
        .find(|(p, _)| p == "data/big.txt")
        .unwrap()
        .1
        .clone();
    e.size -= 1;
    assert!(n.read(&e).is_err());
    e.size += 2;
    assert!(n.read(&e).is_err());
}
