//! `switch-nsp` against synthetic NSPs.

mod common;

use common::*;

#[test]
fn ls_json_lists_every_entry_with_offset_and_size() {
    let f = fixture("nsp-ls");
    let v = json(&run("switch-nsp", &f.dir, &["ls", path(&f.base), "--json"]));
    let want = nsp_files(&f.game.base);
    let got = v.as_array().expect("a JSON array");
    assert_eq!(got.len(), want.len());
    for (g, (name, data)) in got.iter().zip(&want) {
        assert_eq!(g["name"], name.as_str());
        assert_eq!(g["size"], data.len());
        let off = usize::try_from(g["offset"].as_u64().expect("offset")).expect("fits");
        assert_eq!(&f.game.base[off..off + data.len()], data.as_slice());
    }
}

#[test]
fn ls_text_has_one_line_per_entry() {
    let f = fixture("nsp-ls-text");
    let out = run("switch-nsp", &f.dir, &["ls", path(&f.base)]);
    let text = String::from_utf8(ok(&out).stdout.clone()).expect("UTF-8");
    assert_eq!(text.lines().count(), nsp_files(&f.game.base).len());
    assert!(text.lines().all(|l| l.split('\t').count() == 3), "{text}");
}

#[test]
fn extract_writes_every_file_or_only_the_named_ones() {
    let f = fixture("nsp-extract");
    let all = f.dir.join("all");
    ok(&run(
        "switch-nsp",
        &f.dir,
        &["extract", path(&f.base), "-o", path(&all)],
    ));
    let mut want = nsp_files(&f.game.base);
    want.sort();
    assert_eq!(tree(&all), want);

    let nca = program_nca(&f.game, &f.game.base);
    let some = f.dir.join("some");
    ok(&run(
        "switch-nsp",
        &f.dir,
        &["extract", path(&f.base), "-o", path(&some), &nca],
    ));
    let got = tree(&some);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, nca);
}

#[test]
fn cat_streams_one_entry_from_a_file_or_stdin() {
    let f = fixture("nsp-cat");
    let nca = program_nca(&f.game, &f.game.base);
    let want = nsp_files(&f.game.base)
        .into_iter()
        .find(|(n, _)| *n == nca)
        .expect("entry")
        .1;
    let out = run("switch-nsp", &f.dir, &["cat", path(&f.base), &nca]);
    assert_eq!(ok(&out).stdout, want);
    let out = run_stdin("switch-nsp", &f.dir, &["cat", "-", &nca], &f.game.base);
    assert_eq!(ok(&out).stdout, want);
}

#[test]
fn an_extracted_pfs0_lists_like_an_nsp() {
    let f = fixture("nsp-nested");
    let out = run_stdin("switch-nsp", &f.dir, &["ls", "-", "--json"], &f.game.update);
    assert_eq!(
        json(&out).as_array().expect("array").len(),
        nsp_files(&f.game.update).len()
    );
}

#[test]
fn bad_inputs_exit_one_with_one_line() {
    let f = fixture("nsp-bad");
    fails_with(
        &run("switch-nsp", &f.dir, &["ls", "missing.nsp"]),
        "missing.nsp",
    );
    let nca = program_nca(&f.game, &f.game.base);
    fails_with(
        &run("switch-nsp", &f.dir, &["cat", path(&f.base), "nope"]),
        "no such file",
    );
    let out = run(
        "switch-nsp",
        &f.dir,
        &["extract", path(&f.base), "-o", "x", "nope"],
    );
    fails_with(&out, "no such file");
    let out = run_stdin("switch-nsp", &f.dir, &["ls", "-"], b"not a pfs0 at all, no");
    fails_with(&out, "PFS0");
    let _ = nca;
}
