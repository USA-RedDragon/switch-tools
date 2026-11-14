//! The `switch-xci` binary on a synthetic card: show, ls, extract and the
//! one-line failure.

use std::path::PathBuf;
use std::process::Output;

use switch_formats::xci;

fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn card(name: &str) -> PathBuf {
    let bytes = xci::build(
        &[
            ("update", vec![]),
            (
                "secure",
                vec![("a.nca", b"alpha".as_slice()), ("b.tik", &[7u8; 0x300])],
            ),
        ],
        false,
    );
    let path = scratch(name).join("card.xci");
    switch_io::write_if_changed(&path, &bytes).expect("fixture written");
    path
}

fn tool(args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut cmd = switch_io::command(env!("CARGO_BIN_EXE_switch-xci"));
    cmd.args(args).current_dir(env!("CARGO_TARGET_TMPDIR"));
    match stdin {
        None => cmd.output().expect("tool runs"),
        Some(b) => {
            use std::io::Write;
            let mut child = cmd
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("tool spawns");
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(b)
                .expect("stdin writes");
            child.wait_with_output().expect("tool finishes")
        }
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[test]
fn show_prints_the_header() {
    let c = card("show");
    let p = c.to_str().expect("utf-8 path");
    let out = tool(&["show", p], None);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let t = text(&out.stdout);
    assert!(t.contains("trimmed: true"), "{t}");
    assert!(t.contains("partition secure:"), "{t}");
    let out = tool(&["show", "--json", p], None);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["rom_size_name"], "1GiB");
    assert_eq!(v["root_offset"], 0xF000);
    assert_eq!(v["partitions"][1]["name"], "secure");
}

#[test]
fn ls_lists_files_and_reads_stdin() {
    let c = card("ls");
    let out = tool(&["ls", "--json", c.to_str().expect("utf-8 path")], None);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["partitions"][1]["files"][0]["name"], "a.nca");
    assert_eq!(v["partitions"][1]["files"][1]["size"], 0x300);
    let bytes = std::fs::read(&c).expect("fixture reads");
    let out = tool(&["ls", "-"], Some(&bytes));
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("5  a.nca"));
}

#[test]
fn extract_writes_the_files() {
    let c = card("extract");
    let dest = scratch("extract").join("out");
    let out = tool(
        &[
            "extract",
            c.to_str().expect("utf-8 path"),
            "secure",
            "-o",
            dest.to_str().expect("utf-8 path"),
        ],
        None,
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(std::fs::read(dest.join("a.nca")).expect("a"), b"alpha");
    assert_eq!(std::fs::read(dest.join("b.tik")).expect("b"), [7u8; 0x300]);
}

#[test]
fn failures_are_one_line_and_exit_1() {
    let c = card("fail");
    let out = tool(
        &[
            "extract",
            c.to_str().expect("utf-8 path"),
            "nope",
            "-o",
            "x",
        ],
        None,
    );
    assert_eq!(out.status.code(), Some(1));
    let e = text(&out.stderr);
    assert_eq!(e.trim().lines().count(), 1, "{e}");
    assert!(e.starts_with("switch-xci: "), "{e}");
    let out = tool(&["show", "-"], Some(b"not an xci"));
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(text(&out.stderr).trim().lines().count(), 1);
}
