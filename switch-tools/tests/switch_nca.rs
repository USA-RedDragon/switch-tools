//! `switch-nca` against synthetic program NCAs.

mod common;

use common::*;

#[test]
fn show_json_reports_the_header_and_that_the_key_resolves() {
    let f = fixture("nca-show");
    let (nca, tik) = program_files(&f.game, &f.game.base, &f.dir, "base");
    let out = run(
        "switch-nca",
        &f.dir,
        &[
            "show",
            path(&nca),
            "--keys",
            path(&f.keys),
            "--ticket",
            path(&tik),
            "--json",
        ],
    );
    let v = json(&out);
    assert_eq!(v["content_type"], "program");
    assert_eq!(
        v["program_id"],
        format!("{:016x}", f.game.base_spec.program_id)
    );
    assert_eq!(v["content_key_resolves"], true);
    let rights = f.game.base_spec.rights_id.expect("rights id");
    assert_eq!(v["rights_id"], switch_formats::hex(&rights));
    let sections = v["sections"].as_array().expect("sections");
    assert!(sections.len() >= 2);
    assert_eq!(sections[0]["format"], "pfs0");
    assert_eq!(sections[0]["hash"], "sha256");
    assert_eq!(sections[1]["format"], "romfs");
    assert_eq!(sections[1]["hash"], "ivfc");
}

#[test]
fn show_without_a_title_key_says_the_key_does_not_resolve() {
    let f = fixture("nca-show-nokey");
    let (nca, _) = program_files(&f.game, &f.game.base, &f.dir, "base");
    let v = json(&run(
        "switch-nca",
        &f.dir,
        &["show", path(&nca), "--keys", path(&f.keys), "--json"],
    ));
    assert_eq!(v["content_key_resolves"], false);
}

#[test]
fn show_text_reads_an_nca_piped_from_switch_nsp() {
    let f = fixture("nca-pipe");
    let name = program_nca(&f.game, &f.game.base);
    let cat = run("switch-nsp", &f.dir, &["cat", path(&f.base), &name]);
    let out = run_stdin(
        "switch-nca",
        &f.dir,
        &["show", "-", "--keys", path(&f.keys)],
        &ok(&cat).stdout,
    );
    let text = String::from_utf8(ok(&out).stdout.clone()).expect("UTF-8");
    assert!(text.contains("content_type: program"), "{text}");
    assert!(text.contains("section 0:"), "{text}");
}

#[test]
fn extract_exefs_writes_the_files_and_romfs_writes_a_verified_image() {
    let f = fixture("nca-extract");
    let (nca, tik) = program_files(&f.game, &f.game.base, &f.dir, "base");
    let common = ["--keys", path(&f.keys), "--ticket", path(&tik)];
    let exe = f.dir.join("exefs");
    let mut args = vec![
        "extract",
        path(&nca),
        "--section",
        "exefs",
        "-o",
        path(&exe),
    ];
    args.extend(common);
    ok(&run("switch-nca", &f.dir, &args));
    assert_eq!(tree(&exe), sorted(&f.game.base_spec.exefs));

    let img = f.dir.join("romfs.img");
    let mut args = vec![
        "extract",
        path(&nca),
        "--section",
        "romfs",
        "-o",
        path(&img),
    ];
    args.extend(common);
    ok(&run("switch-nca", &f.dir, &args));
    let image = std::fs::read(&img).expect("the image reads");
    assert_eq!(romfs_tree(&image), sorted(&f.game.base_spec.romfs));
}

#[test]
fn extract_by_index_matches_by_name_and_raw_writes_the_whole_section() {
    let f = fixture("nca-raw");
    let (nca, tik) = program_files(&f.game, &f.game.base, &f.dir, "base");
    let common = ["--keys", path(&f.keys), "--ticket", path(&tik)];
    let a = f.dir.join("a");
    let mut args = vec!["extract", path(&nca), "--section", "0", "-o", path(&a)];
    args.extend(common);
    ok(&run("switch-nca", &f.dir, &args));
    assert_eq!(tree(&a), sorted(&f.game.base_spec.exefs));

    let raw = f.dir.join("raw.bin");
    let mut args = vec![
        "extract",
        path(&nca),
        "--section",
        "0",
        "-o",
        path(&raw),
        "--raw",
    ];
    args.extend(common);
    ok(&run("switch-nca", &f.dir, &args));
    let bytes = std::fs::read(&raw).expect("raw reads");
    assert_eq!(bytes.len(), 0x800);
    assert_ne!(bytes, vec![0u8; 0x800]);
}

#[test]
fn titlekey_flag_replaces_the_ticket() {
    let f = fixture("nca-titlekey");
    let (nca, tik) = program_files(&f.game, &f.game.base, &f.dir, "base");
    let t = switch_formats::ticket::Ticket::parse(&std::fs::read(&tik).expect("tik"))
        .expect("ticket parses");
    let pair = format!(
        "{}={}",
        switch_formats::hex(&t.rights_id),
        switch_formats::hex(&t.common_title_key().expect("common"))
    );
    let v = json(&run(
        "switch-nca",
        &f.dir,
        &[
            "show",
            path(&nca),
            "--keys",
            path(&f.keys),
            "--titlekey",
            &pair,
            "--json",
        ],
    ));
    assert_eq!(v["content_key_resolves"], true);
}

#[test]
fn bad_inputs_exit_one_with_one_line() {
    let f = fixture("nca-bad");
    let (nca, tik) = program_files(&f.game, &f.game.base, &f.dir, "base");
    fails_with(
        &run(
            "switch-nca",
            &f.dir,
            &["show", path(&nca), "--keys", path(&f.wrong_keys)],
        ),
        "wrong key",
    );
    fails_with(
        &run(
            "switch-nca",
            &f.dir,
            &["show", "missing.nca", "--keys", path(&f.keys)],
        ),
        "missing.nca",
    );
    fails_with(
        &run(
            "switch-nca",
            &f.dir,
            &[
                "extract",
                path(&nca),
                "--section",
                "romfs",
                "-o",
                "x.img",
                "--keys",
                path(&f.keys),
            ],
        ),
        "key",
    );
    fails_with(
        &run(
            "switch-nca",
            &f.dir,
            &[
                "extract",
                path(&nca),
                "--section",
                "9",
                "-o",
                "x",
                "--keys",
                path(&f.keys),
                "--ticket",
                path(&tik),
            ],
        ),
        "--section",
    );
    fails_with(
        &run(
            "switch-nca",
            &f.dir,
            &[
                "show",
                path(&nca),
                "--keys",
                path(&f.keys),
                "--titlekey",
                "zz",
            ],
        ),
        "RIGHTSID=KEY",
    );
}
