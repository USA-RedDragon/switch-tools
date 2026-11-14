//! The streaming NUP writer: byte-identical to the in-memory fixture
//! builder for the same packages, readable by the repo's reader, raw for
//! incompressible files, deduplicated, and atomic on failure.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use switch_formats::Error;
use switch_formats::nup::{self, BuildPackage, Codec, Nup, PackageKind, TLV_DISPLAY_VERSION};
use switch_formats::nup_writer::{self, Bytes, Content, DEFAULT_LEVEL, WritePackage};
use switch_formats::storage::FileStorage;

const ID: u64 = 0x0100_0000_0000_3000;

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

fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir is creatable");
    dir
}

struct Pkg {
    kind: PackageKind,
    version: u32,
    files: Vec<(&'static str, Vec<u8>)>,
    dirs: Vec<&'static str>,
    meta: Vec<(u16, Vec<u8>)>,
}

fn fixture() -> Vec<Pkg> {
    let text = b"streamed nup line\n".repeat(4000);
    vec![
        Pkg {
            kind: PackageKind::Base,
            version: 0,
            files: vec![
                ("exefs/main", b"main v0".repeat(100)),
                ("romfs/a/big.txt", text.clone()),
                ("romfs/a/noise.bin", noise(3000, 1)),
                ("romfs/empty", Vec::new()),
                ("romfs/z.txt", text.clone()),
            ],
            dirs: vec!["romfs/void"],
            meta: vec![(TLV_DISPLAY_VERSION, b"1.0.0".to_vec())],
        },
        Pkg {
            kind: PackageKind::Update,
            version: 0x10000,
            files: vec![
                ("exefs/main", b"main v1".repeat(100)),
                ("romfs/a/big.txt", text),
                ("romfs/a/noise.bin", noise(3000, 1)),
            ],
            dirs: vec![],
            meta: vec![],
        },
        Pkg {
            kind: PackageKind::Addon,
            version: 7,
            files: vec![("romfs/dlc.bin", noise(100, 2))],
            dirs: vec![],
            meta: vec![],
        },
    ]
}

fn write(path: &std::path::Path, pk: &[Pkg]) -> Result<nup_writer::Summary, Error> {
    let contents: Vec<Vec<Bytes>> = pk
        .iter()
        .map(|p| p.files.iter().map(|(_, b)| Bytes(b.clone())).collect())
        .collect();
    let packages: Vec<WritePackage<'_>> = pk
        .iter()
        .zip(&contents)
        .map(|(p, c)| WritePackage {
            title_id: if p.kind == PackageKind::Addon {
                ID + 0x1001
            } else {
                ID
            },
            version: p.version,
            kind: p.kind,
            standalone: false,
            files: p
                .files
                .iter()
                .zip(c)
                .map(|((n, _), b)| ((*n).to_string(), b as &dyn Content))
                .collect(),
            dirs: p.dirs.iter().map(|d| (*d).to_string()).collect(),
            meta: p.meta.clone(),
        })
        .collect();
    nup_writer::write(path, &packages, DEFAULT_LEVEL)
}

#[test]
fn equals_the_in_memory_builder() {
    let pk = fixture();
    let dir = scratch("nup-writer-equal");
    let path = dir.join("x.nup");
    let s = write(&path, &pk).expect("writes");
    let built = nup::build(
        &pk.iter()
            .map(|p| BuildPackage {
                title_id: if p.kind == PackageKind::Addon {
                    ID + 0x1001
                } else {
                    ID
                },
                version: p.version,
                kind: p.kind,
                standalone: false,
                files: p.files.iter().map(|(n, b)| (*n, b.as_slice())).collect(),
                empty_dirs: p.dirs.clone(),
                meta: p.meta.clone(),
            })
            .collect::<Vec<_>>(),
    );
    let streamed = std::fs::read(&path).expect("reads");
    assert_eq!(streamed.len(), built.len());
    assert!(
        streamed == built,
        "the streamed file differs from nup::build"
    );
    assert_eq!(s.file_size, streamed.len() as u64);
    assert_eq!(s.files, 9);
    assert_eq!(s.extents, 5, "{s:?}");
}

#[test]
fn reads_back_with_raw_and_zstd_extents() {
    let pk = fixture();
    let dir = scratch("nup-writer-read");
    let path = dir.join("x.nup");
    write(&path, &pk).expect("writes");
    let n = Nup::open(Arc::new(FileStorage::open(&path).expect("opens"))).expect("NUP opens");
    assert!(n.uuid_matches());
    for (p, want) in n.packages().iter().zip(&pk) {
        assert_eq!(p.record.version, want.version);
        for (name, bytes) in &want.files {
            let (_, e) = p.files.iter().find(|(f, _)| f == name).expect("listed");
            assert_eq!(&n.read(e).expect("verified"), bytes, "{name}");
            if name.ends_with("noise.bin") {
                assert_eq!(e.codec, Codec::Raw, "noise does not shrink");
            }
            if name.ends_with("big.txt") {
                assert_eq!(e.codec, Codec::Zstd);
                assert_eq!(e.extent_offset % 16, 0);
            }
        }
    }
    let base = &n.packages()[0].files;
    let at = |name: &str| {
        base.iter()
            .find(|(f, _)| f == name)
            .expect("listed")
            .1
            .extent_offset
    };
    assert_eq!(
        at("romfs/a/big.txt"),
        at("romfs/z.txt"),
        "equal files share"
    );
}

struct Failing;

impl Content for Failing {
    fn size(&self) -> u64 {
        10
    }

    fn copy_to(&self, out: &mut dyn Write) -> switch_formats::Result<()> {
        out.write_all(b"12345")?;
        Err(Error::Hash("source".into()))
    }
}

#[test]
fn a_failed_write_leaves_the_target_alone() {
    let dir = scratch("nup-writer-fail");
    let path = dir.join("x.nup");
    switch_io::write_if_changed(&path, b"old").expect("old target");
    let ok = Bytes(b"fine".to_vec());
    let pk = [WritePackage {
        title_id: ID,
        version: 0,
        kind: PackageKind::Base,
        standalone: false,
        files: vec![
            ("romfs/a".into(), &ok as &dyn Content),
            ("romfs/b".into(), &Failing),
        ],
        dirs: vec![],
        meta: vec![],
    }];
    let got = nup_writer::write(&path, &pk, DEFAULT_LEVEL);
    assert!(matches!(got, Err(Error::Hash(_))), "{:?}", got.err());
    assert_eq!(std::fs::read(&path).expect("reads"), b"old");
    assert!(!dir.join("x.nup.switch-tools-tmp").exists());
}

#[test]
fn bad_trees_are_refused() {
    let dir = scratch("nup-writer-bad");
    let b = Bytes(vec![1]);
    for files in [
        vec!["romfs/a", "romfs/a"],
        vec!["romfs/a", "romfs/a/b"],
        vec!["romfs/../x"],
        vec!["romfs//x"],
    ] {
        let pk = [WritePackage {
            title_id: ID,
            version: 0,
            kind: PackageKind::Base,
            standalone: false,
            files: files
                .iter()
                .map(|f| ((*f).to_string(), &b as &dyn Content))
                .collect(),
            dirs: vec![],
            meta: vec![],
        }];
        let got = nup_writer::write(&dir.join("x.nup"), &pk, DEFAULT_LEVEL);
        assert!(matches!(got, Err(Error::Format(_))), "{files:?}");
    }
    assert!(nup_writer::write(&dir.join("x.nup"), &[], DEFAULT_LEVEL).is_err());
}
