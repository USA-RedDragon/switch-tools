//! A reader that closes stdout early (`switch-nsp ls x | head`) is a
//! normal end: the tools exit 0 and print nothing on stderr.

mod common;

use std::path::Path;
use std::process::Stdio;

use common::*;

/// Run `exe` with `args` and stdout a pipe whose read end is closed before
/// the tool writes; return its exit code and stderr.
fn closed_stdout(exe: &str, dir: &Path, args: &[&str]) -> (Option<i32>, String) {
    let mut child = switch_io::command(exe)
        .args(args)
        .env_remove("SWITCH_TOOLS_KEYS")
        .env_remove("SWITCH_TOOLS_TITLE_KEYS")
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the tool starts");
    drop(child.stdout.take());
    let out = child.wait_with_output().expect("the tool finishes");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn closed_stdout_exits_zero_quietly() {
    let f = fixture("epipe");
    let nsp = path(&f.base);
    let keys = path(&f.keys);
    let name = program_nca(&f.game, &f.game.base);
    let nca = put(&f.dir, "base.nca", &entry(&f.game.base, &name));
    let nca = path(&nca);
    let cases: [(&str, &[&str]); 5] = [
        (env!("CARGO_BIN_EXE_switch-nsp"), &["ls", nsp]),
        (env!("CARGO_BIN_EXE_switch-nsp"), &["ls", nsp, "--json"]),
        (env!("CARGO_BIN_EXE_switch-nsp"), &["cat", nsp, &name]),
        (
            env!("CARGO_BIN_EXE_switch-nca"),
            &["show", nca, "--keys", keys],
        ),
        (
            env!("CARGO_BIN_EXE_switch-nca"),
            &["show", nca, "--keys", keys, "--json"],
        ),
    ];
    for (exe, args) in cases {
        let (code, err) = closed_stdout(exe, &f.dir, args);
        assert_eq!(code, Some(0), "{exe} {args:?}: {err}");
        assert_eq!(err, "", "{exe} {args:?}");
    }
}

#[test]
fn other_errors_still_fail() {
    let f = fixture("epipe-missing");
    let (code, err) = closed_stdout(
        env!("CARGO_BIN_EXE_switch-nsp"),
        &f.dir,
        &["ls", "missing.nsp"],
    );
    assert_eq!(code, Some(1), "{err}");
    assert!(err.starts_with("switch-nsp:"), "{err}");
}
