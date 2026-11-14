//! `switch-export` as a subprocess: a synthetic base, update and DLC to a
//! tree and to a `.nup`, settings from flags, env and `switch-tools.toml`,
//! and one-line errors. With `RELIFT_NUP_BIN` set, relift's own NUP reader
//! must extract the same trees from the `.nup`.

mod common;

use std::path::Path;

use common::{fails_with, fixture, ok, path, put, run, tree};
use switch_formats::synth;

const ADDON: u64 = 0x0100_1234_5678_1001;

fn under(t: &[(String, Vec<u8>)], prefix: &str) -> Vec<(String, Vec<u8>)> {
    t.iter()
        .filter_map(|(p, b)| p.strip_prefix(prefix).map(|r| (r.to_string(), b.clone())))
        .collect()
}

#[test]
fn exports_a_tree_and_a_nup() {
    let f = fixture("export-cli");
    let dlc = put(
        &f.dir,
        "dlc.nsp",
        &synth::addon_nsp(
            &f.game.keys,
            ADDON,
            0x10000,
            &[("a.bin".into(), b"a".to_vec())],
        ),
    );
    let out = f.dir.join("tree");
    let nup = f.dir.join("out/game.nup");
    let args = [
        "--keys",
        path(&f.keys),
        path(&f.base),
        "--update",
        path(&f.update),
        "--dlc",
        path(&dlc),
        "--out",
        path(&out),
        "--nup",
        path(&nup),
    ];
    let o = run("switch-export", &f.dir, &args);
    let err = String::from_utf8_lossy(&ok(&o).stderr).into_owned();
    assert!(err.contains("updates/65536"), "{err}");
    let t = tree(&out);
    let mut want = f.game.update_spec.romfs.clone();
    want.sort();
    assert_eq!(under(&t, "updates/65536/romfs/"), want);
    assert_eq!(
        under(&t, "dlc/0100123456781001/0/romfs/"),
        [("a.bin".to_string(), b"a".to_vec())]
    );
    assert!(nup.is_file());

    if let Some(bin) = std::env::var_os("RELIFT_NUP_BIN") {
        for (spec, dir) in [
            ("base", "base"),
            ("update:65536", "updates/65536"),
            ("dlc:0100123456781001:0", "dlc/0100123456781001/0"),
        ] {
            let x = f.dir.join(format!("relift-{}", spec.replace(':', "-")));
            let o = switch_io::command(&bin)
                .args(["extract", path(&nup), "--package", spec, "-o", path(&x)])
                .output()
                .expect("relift-nup runs");
            assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
            assert_eq!(tree(&x), under(&t, &format!("{dir}/")), "{spec}");
        }
    }
}

#[test]
fn settings_come_from_env_and_the_config_file() {
    let f = fixture("export-cli-settings");
    let out = f.dir.join("tree");
    let o = common::tool_env(
        "switch-export",
        &f.dir,
        &[path(&f.base), "-o", path(&out)],
        &[("SWITCH_TOOLS_KEYS", path(&f.keys))],
    );
    ok(&o);
    assert!(out.join("base/exefs/main").is_file());
    put(
        &f.dir,
        "switch-tools.toml",
        format!("keys = {:?}\n", path(&f.keys)).as_bytes(),
    );
    ok(&run(
        "switch-export",
        &f.dir,
        &[path(&f.base), "-o", path(&out)],
    ));
}

#[test]
fn errors_are_one_line() {
    let f = fixture("export-cli-errors");
    let out = f.dir.join("tree");
    let o = run("switch-export", &f.dir, &[path(&f.base), "-o", path(&out)]);
    fails_with(&o, "no key file");
    let o = run(
        "switch-export",
        &f.dir,
        &[
            "--keys",
            path(&f.wrong_keys),
            path(&f.base),
            "-o",
            path(&out),
        ],
    );
    fails_with(&o, "wrong key");
    let junk = put(&f.dir, "junk.bin", b"just some bytes, not a package");
    let o = run(
        "switch-export",
        &f.dir,
        &["--keys", path(&f.keys), path(&junk), "-o", path(&out)],
    );
    fails_with(&o, "unknown file type");
    let o = run(
        "switch-export",
        &f.dir,
        &["--keys", path(&f.keys), path(&f.update), "-o", path(&out)],
    );
    fails_with(&o, "not a base game");
    assert!(!Path::new(&out).join("base").exists());
}

#[test]
fn an_output_is_required() {
    let f = fixture("export-cli-noout");
    let o = run(
        "switch-export",
        &f.dir,
        &["--keys", path(&f.keys), path(&f.base)],
    );
    assert_eq!(
        o.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}

#[test]
fn personalized_tickets_need_the_eticket_key() {
    let f = fixture("export-cli-personalized");
    let pair = synth::eticket_keypair(1);
    let (fk, base, _) = synth::personalized_base(&pair);
    let base = put(&f.dir, "personal.nsp", &base);
    let kek = [0x3c; 16];
    let keys = put(
        &f.dir,
        "eticket.keys",
        format!(
            "{}eticket_rsa_kek = {}\n",
            fk.text,
            switch_formats::hex(&kek)
        )
        .as_bytes(),
    );
    let prodinfo = put(&f.dir, "PRODINFO.bin", &synth::prodinfo(&kek, &pair));
    let keypair = put(&f.dir, "eticket.bin", &pair);
    let other = put(&f.dir, "other.bin", &synth::eticket_keypair(2));
    let out = f.dir.join("tree");
    let o = run(
        "switch-export",
        &f.dir,
        &["--keys", path(&keys), path(&base), "-o", path(&out)],
    );
    fails_with(&o, "eticket-rsa-keypair");
    for extra in [
        ["--prodinfo", path(&prodinfo)],
        ["--eticket-rsa-keypair", path(&keypair)],
    ] {
        let _ = std::fs::remove_dir_all(&out);
        let mut args = vec!["--keys", path(&keys), path(&base), "-o", path(&out)];
        args.extend(extra);
        ok(&run("switch-export", &f.dir, &args));
        assert!(out.join("base/romfs/data/keep.txt").is_file());
    }
    let o = run(
        "switch-export",
        &f.dir,
        &[
            "--keys",
            path(&keys),
            "--eticket-rsa-keypair",
            path(&other),
            path(&base),
            "-o",
            path(&out),
        ],
    );
    fails_with(&o, "another console");
}
