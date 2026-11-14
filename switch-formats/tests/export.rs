//! Export round trips on synthetic dumps: a base, two updates and DLC go to
//! a tree and to a `.nup`; the `.nup` read back with the repo's own reader
//! equals the tree file for file, and each update's romfs is the full
//! patched tree.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use switch_formats::Error;
use switch_formats::export::{self, Export};
use switch_formats::keys::Keys;
use switch_formats::nacp;
use switch_formats::nup::{Nup, PackageKind, TLV_NACP, TLV_NPDM};
use switch_formats::storage::{FileStorage, MemStorage};
use switch_formats::synth::{self, Game};
use switch_formats::title::{Package, open_package};

const ADDON_A: u64 = 0x0100_1234_5678_1001;
const ADDON_B: u64 = 0x0100_1234_5678_1002;

struct Dump {
    game: Game,
    base: Box<dyn Package>,
    updates: Vec<Box<dyn Package>>,
    dlc: Vec<Box<dyn Package>>,
    /// The romfs each update must export (base romfs patched by it).
    want_update_romfs: BTreeMap<u32, Vec<(String, Vec<u8>)>>,
}

fn open(bytes: Vec<u8>) -> Box<dyn Package> {
    open_package(Arc::new(MemStorage(bytes))).expect("the fixture opens")
}

fn sorted(v: &[(String, Vec<u8>)]) -> Vec<(String, Vec<u8>)> {
    let mut v = v.to_vec();
    v.sort();
    v
}

/// A base with a control NCA and a `.listing` artifact in its romfs, the
/// fixture update (1.0.1, version 0x10000) given after a second update
/// (version 0x20000), add-on A twice (versions 0 and 0x10000) and add-on
/// B once.
fn dump() -> Dump {
    let mut game = synth::game();
    let fk = &game.keys;
    let pid = game.base_spec.program_id;
    game.base_spec
        .romfs
        .push(("sub/.listing".into(), b"ftp junk".to_vec()));
    let (base_nca, base_plain) = synth::program_nca(fk, &game.base_spec);
    let base_meta = synth::meta_nca(fk, pid, 0, 0x80, &base_nca);
    let base = synth::nsp(fk, &game.base_spec, &base_nca, &base_meta);
    let nacp_bytes = nacp::build(
        &[(0, "Synth Game", "Synth Co"), (2, "Shinsu", "Synth KK")],
        "1.0.0",
    );
    let base = synth::with_control(fk, &base, pid, &nacp_bytes);
    game.base = base.clone();

    let u1_nca = synth::update_nca(fk, &game.update_spec, &base_plain);
    let u1_meta = synth::meta_nca(fk, pid | 0x800, 0x10000, 0x81, &u1_nca);
    let u1 = synth::nsp(fk, &game.update_spec, &u1_nca, &u1_meta);
    let u1 = synth::with_control(
        fk,
        &u1,
        pid | 0x800,
        &nacp::build(&[(0, "Synth Game", "Synth Co")], "1.0.1"),
    );

    let mut u2_spec = game.update_spec.clone();
    u2_spec.romfs = vec![
        ("data/keep.txt".into(), b"kept".to_vec()),
        ("data/v2.bin".into(), vec![0x22; 0x3000]),
        ("readme.txt".into(), b"version 2".to_vec()),
    ];
    u2_spec.exefs[0].1 = synth::nso("D:\\work\\game\\out\\game-main.nss", 0xC1);
    let u2_nca = synth::update_nca(fk, &u2_spec, &base_plain);
    let u2_meta = synth::meta_nca(fk, pid | 0x800, 0x20000, 0x81, &u2_nca);
    let u2 = synth::nsp(fk, &u2_spec, &u2_nca, &u2_meta);

    let a_old = synth::addon_nsp(fk, ADDON_A, 0, &[("a.bin".into(), b"old a".to_vec())]);
    let a_new = synth::addon_nsp(
        fk,
        ADDON_A,
        0x10000,
        &[
            ("a.bin".into(), b"new a".to_vec()),
            ("deep/er/x.txt".into(), vec![7u8; 0x2345]),
        ],
    );
    let b = synth::addon_nsp(fk, ADDON_B, 0, &[("b.bin".into(), b"b".to_vec())]);

    let want_update_romfs = BTreeMap::from([
        (0x10000, sorted(&game.update_spec.romfs)),
        (0x20000, sorted(&u2_spec.romfs)),
    ]);
    Dump {
        base: open(base),
        updates: vec![open(u2), open(u1)],
        dlc: vec![open(a_new), open(b), open(a_old)],
        want_update_romfs,
        game,
    }
}

fn plan(d: &Dump, keys: &Keys) -> switch_formats::Result<Export> {
    let ups: Vec<&dyn Package> = d.updates.iter().map(AsRef::as_ref).collect();
    let dlc: Vec<&dyn Package> = d.dlc.iter().map(AsRef::as_ref).collect();
    export::plan(keys, d.base.as_ref(), &ups, &dlc)
}

fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir is creatable");
    dir
}

/// Sorted (path, bytes) of every file under `dir`.
fn tree(dir: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(root: &Path, at: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let Ok(rd) = std::fs::read_dir(at) else {
            return;
        };
        for e in rd {
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

fn under(t: &[(String, Vec<u8>)], prefix: &str) -> Vec<(String, Vec<u8>)> {
    t.iter()
        .filter_map(|(p, b)| p.strip_prefix(prefix).map(|r| (r.to_string(), b.clone())))
        .collect()
}

#[test]
fn tree_has_the_packer_layout() {
    let d = dump();
    let dir = scratch("export-tree");
    let e = plan(&d, &d.game.keys.keys).expect("plan");
    let s = e.write_tree(&dir).expect("tree writes");
    assert_eq!(s.written, s.files);
    let t = tree(&dir);
    let names: Vec<&str> = t.iter().map(|(p, _)| p.as_str()).collect();
    for want in [
        "base/exefs/main",
        "base/exefs/main.npdm",
        "base/exefs/sdk",
        "base/romfs/data/big.bin",
        "base/romfs/readme.txt",
        "updates/65536/exefs/main",
        "updates/65536/romfs/data/new/added.bin",
        "updates/131072/romfs/data/v2.bin",
        "dlc/0100123456781001/0/romfs/a.bin",
        "dlc/0100123456781001/0/romfs/deep/er/x.txt",
        "dlc/0100123456781002/0/romfs/b.bin",
    ] {
        assert!(names.contains(&want), "{want} missing from {names:?}");
    }
    assert!(!names.iter().any(|n| n.ends_with(".listing")), "{names:?}");
    assert!(dir.join("base/romfs/sub").is_dir(), "the emptied dir stays");
    assert!(
        names
            .iter()
            .all(|n| n.starts_with("base/") || n.starts_with("updates/") || n.starts_with("dlc/")),
        "{names:?}"
    );

    let mut want_base = d.game.base_spec.romfs.clone();
    want_base.retain(|(p, _)| !p.ends_with(".listing"));
    assert_eq!(under(&t, "base/romfs/"), sorted(&want_base));
    for (v, want) in &d.want_update_romfs {
        assert_eq!(
            &under(&t, &format!("updates/{v}/romfs/")),
            want,
            "update {v}"
        );
    }
    assert_eq!(
        under(&t, "dlc/0100123456781001/0/romfs/")[0],
        ("a.bin".to_string(), b"new a".to_vec()),
        "the newest add-on version wins"
    );
    assert_eq!(
        under(&t, "base/exefs/"),
        sorted(&d.game.base_spec.exefs),
        "exefs is verbatim"
    );
}

#[test]
fn nup_reads_back_equal_to_the_tree() {
    let d = dump();
    let dir = scratch("export-nup");
    let e = plan(&d, &d.game.keys.keys).expect("plan");
    e.write_tree(&dir.join("tree")).expect("tree writes");
    let nup_path = dir.join("game.nup");
    let s = e.write_nup(&nup_path, 3).expect("nup writes");
    assert!(s.extents < s.files, "shared files are deduplicated: {s:?}");
    assert!(
        !dir.join("game.nup.switch-tools-tmp").exists(),
        "the temporary file is renamed"
    );
    let nup = Nup::open(Arc::new(FileStorage::open(&nup_path).expect("opens"))).expect("NUP opens");
    assert!(nup.uuid_matches());
    let t = tree(&dir.join("tree"));
    let kinds: Vec<(PackageKind, u64, u32)> = nup
        .packages()
        .iter()
        .map(|p| (p.record.kind, p.record.title_id, p.record.version))
        .collect();
    let pid = d.game.base_spec.program_id;
    assert_eq!(
        kinds,
        [
            (PackageKind::Base, pid, 0),
            (PackageKind::Update, pid, 0x10000),
            (PackageKind::Update, pid, 0x20000),
            (PackageKind::Addon, ADDON_A, 0x10000),
            (PackageKind::Addon, ADDON_B, 0),
        ]
    );
    let dirs = [
        "base".to_string(),
        "updates/65536".into(),
        "updates/131072".into(),
        "dlc/0100123456781001/0".into(),
        "dlc/0100123456781002/0".into(),
    ];
    for (i, p) in nup.packages().iter().enumerate() {
        let mut got: Vec<(String, Vec<u8>)> = p
            .files
            .iter()
            .map(|(path, entry)| (path.clone(), nup.read(entry).expect("verified read")))
            .collect();
        got.sort();
        assert_eq!(
            got,
            under(&t, &format!("{}/", dirs[i])),
            "package {}",
            dirs[i]
        );
        assert!(p.dirs.iter().any(|d| d == "romfs"), "{:?}", p.dirs);
    }
    let base = &nup.packages()[0];
    assert!(base.tlv(TLV_NPDM).is_some(), "the NPDM TLV is required");
    assert_eq!(base.npdm_program_id(), Some(pid));
    assert!(base.tlv(TLV_NACP).is_some());
    assert_eq!(base.display_version().as_deref(), Some("1.0.0"));
    assert_eq!(base.name().as_deref(), Some("Synth Game"));
    assert_eq!(base.publisher().as_deref(), Some("Synth Co"));
    assert_eq!(base.build_id(), Some([0xA1; 32]));
    assert!(
        base.dirs.iter().any(|d| d == "romfs/sub"),
        "empty dirs survive"
    );
    let u1 = &nup.packages()[1];
    assert_eq!(u1.display_version().as_deref(), Some("1.0.1"));
    assert_eq!(u1.build_id(), Some([0xB1; 32]));
    assert_eq!(nup.packages()[2].display_version(), None);

    let t = nup
        .effective_title(switch_formats::nup::UpdateSelect::Newest)
        .expect("effective title");
    let mut romfs: Vec<(String, Vec<u8>)> = t
        .romfs
        .iter()
        .map(|(p, e)| (p.clone(), nup.read(e).expect("reads")))
        .collect();
    romfs.sort();
    assert_eq!(&romfs, &d.want_update_romfs[&0x20000]);
}

#[test]
fn reexport_rewrites_nothing_and_prunes_stale_files() {
    let d = dump();
    let dir = scratch("export-again");
    let e = plan(&d, &d.game.keys.keys).expect("plan");
    e.write_tree(&dir).expect("first export");
    let stale = dir.join("updates/99/romfs/old.bin");
    std::fs::create_dir_all(stale.parent().expect("parent")).expect("mkdir");
    switch_io::write_if_changed(&stale, b"old").expect("stale file");
    let keep = dir.join("notes.txt");
    switch_io::write_if_changed(&keep, b"mine").expect("user file");
    let s = e.write_tree(&dir).expect("second export");
    assert_eq!(s.written, 0, "{s:?}");
    assert_eq!(s.removed, 1, "{s:?}");
    assert!(
        !dir.join("updates/99").exists(),
        "the stale package dir goes"
    );
    assert!(keep.exists(), "files outside base/, updates/, dlc/ stay");
}

#[test]
fn missing_keys_fail() {
    let d = dump();
    let got = plan(&d, &Keys::default());
    assert!(matches!(got, Err(Error::MissingKey(_))), "{:?}", got.err());
}

#[test]
fn wrong_keys_fail() {
    let d = dump();
    let wrong = synth::keys(9).keys;
    let got = plan(&d, &wrong);
    assert!(matches!(got, Err(Error::WrongKey(_))), "{:?}", got.err());
}

#[test]
fn an_update_of_another_title_fails() {
    let d = dump();
    let fk = &d.game.keys;
    let mut other = d.game.update_spec.clone();
    other.program_id = 0x0100_9999_0000_0800;
    let (_, plain) = synth::program_nca(fk, &d.game.base_spec);
    let nca = synth::update_nca(fk, &other, &plain);
    let meta = synth::meta_nca(fk, 0x0100_9999_0000_0800, 0x10000, 0x81, &nca);
    let u = open(synth::nsp(fk, &other, &nca, &meta));
    let got = export::plan(&fk.keys, d.base.as_ref(), &[u.as_ref()], &[]);
    let msg = got.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(msg.contains("does not belong to base"), "{msg}");
}

#[test]
fn dlc_of_another_title_fails() {
    let d = dump();
    let fk = &d.game.keys;
    let x = open(synth::addon_nsp(
        fk,
        0x0100_9999_0000_1001,
        0,
        &[("x".into(), vec![1])],
    ));
    let got = export::plan(&fk.keys, d.base.as_ref(), &[], &[x.as_ref()]);
    let msg = got.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(msg.contains("does not belong to base"), "{msg}");
}

#[test]
fn wrong_roles_fail() {
    let d = dump();
    let keys = &d.game.keys.keys;
    let as_base = export::plan(keys, d.updates[0].as_ref(), &[], &[]);
    let msg = as_base.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(msg.contains("not a base game"), "{msg}");
    let as_update = export::plan(keys, d.base.as_ref(), &[d.dlc[0].as_ref()], &[]);
    let msg = as_update.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(msg.contains("not an update"), "{msg}");
    let as_dlc = export::plan(keys, d.base.as_ref(), &[], &[d.updates[0].as_ref()]);
    let msg = as_dlc.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(msg.contains("not DLC"), "{msg}");
    let twice = export::plan(
        keys,
        d.base.as_ref(),
        &[d.updates[0].as_ref(), d.updates[0].as_ref()],
        &[],
    );
    let msg = twice.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(msg.contains("given twice"), "{msg}");
}

#[test]
fn unknown_file_types_fail() {
    for bytes in [
        b"not a package at all".to_vec(),
        vec![0u8; 0x1000],
        Vec::new(),
    ] {
        let got = open_package(Arc::new(MemStorage(bytes)));
        assert!(
            matches!(&got, Err(Error::Unsupported(m)) if m.contains("unknown file type")),
            "{:?}",
            got.err()
        );
    }
}
