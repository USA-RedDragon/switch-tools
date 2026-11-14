//! `switch-bktr`: the patched image it writes reads as the update's romfs.

mod common;

use common::*;

fn files(f: &Fixture) -> [std::path::PathBuf; 4] {
    let (base, base_tik) = program_files(&f.game, &f.game.base, &f.dir, "base");
    let (upd, upd_tik) = program_files(&f.game, &f.game.update, &f.dir, "update");
    [base, base_tik, upd, upd_tik]
}

#[test]
fn apply_writes_the_patched_image_of_the_update_tree() {
    let f = fixture("bktr-apply");
    let [base, base_tik, upd, upd_tik] = files(&f);
    let img = f.dir.join("romfs.img");
    ok(&run(
        "switch-bktr",
        &f.dir,
        &[
            "apply",
            "--base",
            path(&base),
            "--update",
            path(&upd),
            "--base-ticket",
            path(&base_tik),
            "--update-ticket",
            path(&upd_tik),
            "--keys",
            path(&f.keys),
            "-o",
            path(&img),
        ],
    ));
    let image = std::fs::read(&img).expect("the image reads");
    assert_eq!(romfs_tree(&image), sorted(&f.game.update_spec.romfs));
}

#[test]
fn apply_streams_to_stdout_and_reads_the_update_from_stdin() {
    let f = fixture("bktr-pipe");
    let [base, base_tik, _, upd_tik] = files(&f);
    let upd = entry(&f.game.update, &program_nca(&f.game, &f.game.update));
    let img = run_stdin(
        "switch-bktr",
        &f.dir,
        &[
            "apply",
            "--base",
            path(&base),
            "--update",
            "-",
            "--base-ticket",
            path(&base_tik),
            "--update-ticket",
            path(&upd_tik),
            "--keys",
            path(&f.keys),
            "-o",
            "-",
        ],
        &upd,
    );
    assert_eq!(
        romfs_tree(&ok(&img).stdout),
        sorted(&f.game.update_spec.romfs)
    );
}

#[test]
fn apply_fails_cleanly_on_bad_input() {
    let f = fixture("bktr-bad");
    let [base, base_tik, upd, upd_tik] = files(&f);
    let tickets = [
        "--base-ticket",
        path(&base_tik),
        "--update-ticket",
        path(&upd_tik),
    ];
    let mut args = vec![
        "apply",
        "--base",
        path(&base),
        "--update",
        path(&upd),
        "--keys",
        path(&f.wrong_keys),
        "-o",
        "x.img",
    ];
    args.extend(tickets);
    fails_with(&run("switch-bktr", &f.dir, &args), "wrong key");

    let mut args = vec![
        "apply",
        "--base",
        "missing.nca",
        "--update",
        path(&upd),
        "--keys",
        path(&f.keys),
        "-o",
        "x.img",
    ];
    args.extend(tickets);
    fails_with(&run("switch-bktr", &f.dir, &args), "missing.nca");

    let args = [
        "apply",
        "--base",
        path(&base),
        "--update",
        path(&upd),
        "--keys",
        path(&f.keys),
        "-o",
        "x.img",
    ];
    fails_with(&run("switch-bktr", &f.dir, &args), "key");
    assert!(!f.dir.join("x.img").exists());
}
