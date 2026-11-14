//! `switch-ncz` as a user runs it.

use std::path::PathBuf;
use std::process::Output;
use std::sync::Arc;

use switch_formats::crypto::sha256;
use switch_formats::hex;
use switch_formats::ncz::{self, Layout};
use switch_formats::storage::MemStorage;
use switch_formats::synth;
use switch_formats::title::Nsp;

fn scratch(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("switch-ncz-{name}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch");
    d
}

fn run(args: &[&str]) -> Output {
    switch_io::command(env!("CARGO_BIN_EXE_switch-ncz"))
        .args(args)
        .output()
        .expect("switch-ncz runs")
}

fn fixture(dir: &std::path::Path, layout: Layout) -> (PathBuf, Vec<u8>) {
    let g = synth::game();
    let nsp = Nsp::from_storage(Arc::new(MemStorage(g.base.clone()))).expect("nsp");
    let e = nsp
        .pfs0()
        .entries()
        .iter()
        .find(|e| e.name.ends_with(".nca") && !e.name.ends_with(".cnmt.nca"))
        .expect("program")
        .clone();
    let nca = nsp.pfs0().read(&e).expect("read");
    let z = ncz::build(&nca, &g.keys.keys, nsp.title_keys(), layout).expect("builds");
    let p = dir.join("p.ncz");
    switch_io::write_if_changed(&p, &z).expect("write");
    (p, nca)
}

#[test]
fn show_prints_json_for_both_layouts() {
    let d = scratch("show");
    for (layout, want) in [
        (Layout::Solid { level: 3 }, "solid"),
        (
            Layout::Blocks {
                exponent: 14,
                level: 3,
            },
            "blocks",
        ),
    ] {
        let (p, nca) = fixture(&d, layout);
        let out = run(&["show", "--json", p.to_str().expect("utf8")]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
        assert_eq!(v["compression"]["layout"], want);
        assert_eq!(v["nca_size"], nca.len());
        assert!(!v["sections"].as_array().expect("sections").is_empty());
    }
}

#[test]
fn decompress_restores_the_nca_and_checks_the_hash() {
    let d = scratch("decompress");
    for layout in [
        Layout::Solid { level: 3 },
        Layout::Blocks {
            exponent: 14,
            level: 3,
        },
    ] {
        let (p, nca) = fixture(&d, layout);
        let o = d.join("out.nca");
        let _ = std::fs::remove_file(&o);
        let good = hex(&sha256(&nca));
        let (ps, os) = (p.to_str().expect("utf8"), o.to_str().expect("utf8"));
        let out = run(&["decompress", ps, "-o", os, "--expect-sha256", &good]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(std::fs::read(&o).expect("read"), nca);
        // A wrong hash fails, names the mismatch and leaves no new output.
        let _ = std::fs::remove_file(&o);
        let bad = hex(&sha256(b"x"));
        let out = run(&["decompress", ps, "-o", os, "--expect-sha256", &bad]);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("hash mismatch"));
        assert!(!o.exists());
        // Malformed hex is a usage error.
        let out = run(&["decompress", ps, "-o", os, "--expect-sha256", "zz"]);
        assert!(!out.status.success());
    }
}

#[test]
fn a_non_ncz_input_fails() {
    let d = scratch("bad");
    let p = d.join("junk.ncz");
    switch_io::write_if_changed(&p, &vec![0u8; 0x5000]).expect("write");
    let out = run(&["show", "--json", p.to_str().expect("utf8")]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("switch-ncz:"));
}
