//! Cross-check against the reference NUP packer (`tools/nup` of
//! github.com/a55uka/nup). Runs only when `NUP_REFERENCE_PACKER` names the
//! packer's `tools/nup` directory and `NUP_REFERENCE_PYTHON` a Python with
//! `zstandard`; CI sets neither, so no downloaded code runs there. The
//! packer runs with `python -I` from the scratch directory, outside its
//! own tree.
//!
//! A synthetic base (with control NCA and icons), update and add-on are
//! exported as a tree; the reference packs that tree (given the same
//! names, publisher, display version and icons the export reads from the
//! NACP) and this crate writes its own `.nup` from the same plan. Every
//! field of both files is compared; the test fails on any difference not
//! in the documented list (`ARCHITECTURE.md`, "The reference packer").
//! Then the plan's meta is changed to what the reference writes (no NACP
//! record, a source name record) and the two files must be byte-identical.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use switch_formats::export;
use switch_formats::nacp;
use switch_formats::nup::{Nup, TLV_NACP, TLV_SOURCE_NAME};
use switch_formats::storage::{FileStorage, MemStorage};
use switch_formats::synth;
use switch_formats::title::{Package, open_package};

const ADDON: u64 = 0x0100_1234_5678_1001;

/// The kinds of field allowed to differ, each explained in
/// `ARCHITECTURE.md` ("The reference packer").
const EXPLAINED: &[&str] = &["file_size", "meta", "meta 0x0002", "meta 0x0008", "toc"];

fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir is creatable");
    dir
}

fn open(bytes: Vec<u8>) -> Box<dyn Package> {
    open_package(Arc::new(MemStorage(bytes))).expect("the fixture opens")
}

fn nup(path: &Path) -> (Nup, Vec<u8>) {
    let n = Nup::open(Arc::new(FileStorage::open(path).expect("opens"))).expect("valid NUP");
    (n, std::fs::read(path).expect("reads"))
}

/// Every observable field of a NUP, keyed by what it is.
fn fields(n: &Nup, raw: &[u8]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let sb = n.superblock();
    out.insert(
        "superblock.package_count".into(),
        sb.package_count.to_string(),
    );
    out.insert("superblock.flags".into(), sb.flags.to_string());
    out.insert("superblock.uuid".into(), switch_formats::hex(&sb.uuid));
    out.insert("superblock.blob_offset".into(), sb.blob_offset.to_string());
    out.insert("superblock.file_size".into(), sb.file_size.to_string());
    out.insert("superblock.toc".into(), switch_formats::hex(&sb.toc_sha256));
    let toc = n.toc();
    let names: Vec<&str> = toc
        .files
        .iter()
        .map(|f| toc.name(f.name_off, f.name_len).expect("name"))
        .collect();
    out.insert("toc.file order".into(), names.join(","));
    let dirs: Vec<&str> = toc
        .dirs
        .iter()
        .map(|d| toc.name(d.name_off, d.name_len).expect("name"))
        .collect();
    out.insert("toc.dir order".into(), dirs.join(","));
    out.insert("toc.children".into(), format!("{:?}", toc.children));
    out.insert(
        "toc.strings".into(),
        String::from_utf8_lossy(&toc.strings).into_owned(),
    );
    for (i, p) in n.packages().iter().enumerate() {
        let r = &p.record;
        let k = |f: &str| format!("package {i}.{f}");
        out.insert(k("title_id"), format!("{:016x}", r.title_id));
        out.insert(k("version"), r.version.to_string());
        out.insert(k("kind"), r.kind.name().to_string());
        out.insert(k("flags"), r.flags.to_string());
        out.insert(k("exefs"), format!("{:?}", p.exefs_path));
        out.insert(k("romfs"), format!("{:?}", p.romfs_path));
        let mut dirs = p.dirs.clone();
        dirs.sort();
        out.insert(k("dirs"), dirs.join(","));
        for (path, e) in &p.files {
            out.insert(
                k(&format!("file {path}")),
                format!(
                    "{} {} {}",
                    e.size,
                    switch_formats::hex(&e.sha256),
                    e.codec.name()
                ),
            );
            let at = usize::try_from(e.extent_offset).expect("fits");
            let len = usize::try_from(e.extent_size).expect("fits");
            assert_eq!(n.read(e).expect("verifies").len() as u64, e.size);
            out.insert(
                k(&format!("extent {path}")),
                switch_formats::hex(&switch_formats::crypto::sha256(&raw[at..at + len])),
            );
            out.insert(k(&format!("offset {path}")), e.extent_offset.to_string());
        }
        for t in &p.meta {
            out.insert(
                k(&format!("meta {:#06x}", t.ty)),
                switch_formats::hex(&switch_formats::crypto::sha256(&t.payload)),
            );
        }
        let order: Vec<String> = p.meta.iter().map(|t| format!("{:#06x}", t.ty)).collect();
        out.insert(k("meta order"), order.join(","));
    }
    out
}

/// The kind of a differing key: `package 2.offset a.bin` is `offset`,
/// `package 0.meta 0x0008` is `meta 0x0008`.
fn kind(key: &str) -> String {
    let rest = key.split_once('.').map_or(key, |(_, r)| r);
    if rest.starts_with("meta 0x") {
        return rest.to_string();
    }
    rest.split(' ').next().unwrap_or(rest).to_string()
}

#[test]
fn matches_the_reference_packer() {
    let (Some(packer), Some(python)) = (
        std::env::var_os("NUP_REFERENCE_PACKER"),
        std::env::var_os("NUP_REFERENCE_PYTHON"),
    ) else {
        eprintln!("NUP_REFERENCE_PACKER or NUP_REFERENCE_PYTHON unset: skipped");
        return;
    };
    let g = synth::game();
    let fk = &g.keys;
    let pid = g.base_spec.program_id;
    let nacp_bytes = nacp::build(
        &[(0, "Synth Game", "Synth Co"), (2, "Shinsu", "Synth Co")],
        "1.0.0",
    );
    let icons = [
        ("AmericanEnglish", synth::icon("en-us")),
        ("Japanese", synth::icon("ja")),
    ];
    let base = synth::with_control_icons(fk, &g.base, pid, &nacp_bytes, &icons);
    let dlc = synth::addon_nsp(fk, ADDON, 0, &[("a.bin".into(), b"addon".to_vec())]);
    let (base, update, dlc) = (open(base), open(g.update.clone()), open(dlc));
    let mut plan =
        export::plan(&fk.keys, base.as_ref(), &[update.as_ref()], &[dlc.as_ref()]).expect("plans");

    let dir = scratch("reference-packer");
    let tree = dir.join("dump");
    plan.write_tree(&tree).expect("tree");
    let ours = dir.join("ours.nup");
    plan.write_nup(&ours, 3).expect("ours");
    let icon_dir = dir.join("icons");
    std::fs::create_dir_all(&icon_dir).expect("mkdir");
    let en = icon_dir.join("en-us.jpg");
    let ja = icon_dir.join("ja.jpg");
    switch_io::write_if_changed(&en, &icons[0].1).expect("icon");
    switch_io::write_if_changed(&ja, &icons[1].1).expect("icon");
    let theirs = dir.join("theirs.nup");
    let s = |p: &Path| p.to_str().expect("UTF-8").to_string();
    let o = switch_io::command(&python)
        .current_dir(&dir)
        .args([
            "-I".into(),
            "-c".into(),
            "import sys; sys.path.insert(0, sys.argv[1]); from nup.cli import main; sys.exit(main(sys.argv[2:]))".into(),
            packer.to_string_lossy().into_owned(),
            "pack".into(),
            "-q".into(),
            "--name".into(),
            "Synth Game".into(),
            "--publisher".into(),
            "Synth Co".into(),
            "--display-version".into(),
            "1.0.0".into(),
            "--lang-name".into(),
            "en-us=Synth Game".into(),
            "--lang-name".into(),
            "ja=Shinsu".into(),
            "--icon".into(),
            s(&en),
            "--lang-icon".into(),
            format!("en-us={}", s(&en)),
            "--lang-icon".into(),
            format!("ja={}", s(&ja)),
            s(&tree),
            s(&theirs),
        ])
        .output()
        .expect("the reference packer runs");
    assert!(
        o.status.success(),
        "reference pack failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );

    let ((a, ra), (b, rb)) = (nup(&ours), nup(&theirs));
    let (fa, fb) = (fields(&a, &ra), fields(&b, &rb));
    if ra == rb {
        return;
    }
    let mut kinds: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for k in fa.keys().chain(fb.keys()) {
        if fa.get(k) != fb.get(k) {
            let line = format!("{k}: ours {:?}, reference {:?}", fa.get(k), fb.get(k));
            let v = kinds.entry(kind(k)).or_default();
            if !v.contains(&line) {
                v.push(line);
            }
        }
    }
    for (k, lines) in &kinds {
        eprintln!("difference {k}: {} fields", lines.len());
        for l in lines {
            eprintln!("    {l}");
        }
    }
    assert!(
        b.packages()
            .iter()
            .all(|p| p.meta.iter().all(|t| t.ty != 0)),
        "the reference wrote TLV type 0, one below SPEC section 5 (its commit 1d904e1 \
         renumbered the types); use the packer from before that commit"
    );
    let unexplained: Vec<&String> = kinds
        .keys()
        .filter(|k| !EXPLAINED.contains(&k.as_str()))
        .collect();
    assert!(
        unexplained.is_empty(),
        "unexplained differences: {unexplained:?}"
    );

    for p in &mut plan.packages {
        p.meta.retain(|(ty, _)| *ty != TLV_NACP);
        p.meta.push((TLV_SOURCE_NAME, b"dump".to_vec()));
        p.meta.sort_by_key(|(ty, _)| *ty);
    }
    let normalized = dir.join("normalized.nup");
    plan.write_nup(&normalized, 3).expect("normalized");
    assert!(
        std::fs::read(&normalized).expect("reads") == rb,
        "without the NACP record and with the reference's source name, the files differ"
    );
}
