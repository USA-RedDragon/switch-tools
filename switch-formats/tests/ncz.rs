//! NCZ and NSZ: both layouts restore the exact NCA, an NSZ reads like its
//! NSP, and corruption or a wrong content hash is an error.

use std::sync::Arc;

use switch_formats::cnmt::{ContentRecord, build as build_cnmt};
use switch_formats::crypto::sha256;
use switch_formats::nca::Nca;
use switch_formats::ncz::{self, Compression, Layout, Ncz};
use switch_formats::romfs::Romfs;
use switch_formats::storage::{MemStorage, Shared};
use switch_formats::synth;
use switch_formats::title::{Nsp, open_title};
use switch_formats::{Error, cnmt::Cnmt};

fn mem(b: Vec<u8>) -> Shared {
    Arc::new(MemStorage(b))
}

fn program_nca(g: &synth::Game) -> (Vec<u8>, Nsp) {
    let nsp = Nsp::from_storage(mem(g.base.clone())).expect("nsp");
    let e = nsp
        .pfs0()
        .entries()
        .iter()
        .find(|e| e.name.ends_with(".nca") && !e.name.ends_with(".cnmt.nca"))
        .expect("program entry")
        .clone();
    (nsp.pfs0().read(&e).expect("read"), nsp)
}

const LAYOUTS: [Layout; 2] = [
    Layout::Solid { level: 3 },
    Layout::Blocks {
        exponent: 14,
        level: 3,
    },
];

fn restore(z: &Ncz) -> Vec<u8> {
    let mut out = Vec::new();
    z.to_nca(&mut out, None).expect("restores");
    out
}

#[test]
fn both_layouts_restore_the_exact_nca() {
    let g = synth::game();
    let (nca, nsp) = program_nca(&g);
    for layout in LAYOUTS {
        let bytes = ncz::build(&nca, &g.keys.keys, nsp.title_keys(), layout).expect("builds");
        assert_ne!(bytes, nca);
        let z = Ncz::open(mem(bytes)).expect("opens");
        assert_eq!(
            matches!(z.compression, Compression::Blocks(_)),
            matches!(layout, Layout::Blocks { .. })
        );
        assert_eq!(z.nca_size(), nca.len() as u64);
        assert_eq!(restore(&z), nca, "{layout:?}");
        let want: [u8; 32] = sha256(&nca);
        z.verify(&want).expect("hash matches");
    }
}

#[test]
fn the_encrypted_storage_opens_as_an_nca_and_reads_in_any_order() {
    let g = synth::game();
    let (nca, nsp) = program_nca(&g);
    for layout in LAYOUTS {
        let z = Ncz::open(mem(ncz::build(
            &nca,
            &g.keys.keys,
            nsp.title_keys(),
            layout,
        )
        .expect("builds")))
        .expect("opens");
        let st = z.to_encrypted_storage();
        Nca::open(st.clone(), &g.keys.keys, nsp.title_keys()).expect("nca opens");
        let mut a = vec![0u8; 0x3000];
        for off in [nca.len() as u64 - 0x3000, 0x3F00, 0x5, 0x4000 - 8] {
            st.read_at(off, &mut a).expect("reads");
            assert_eq!(a, nca[off as usize..off as usize + 0x3000], "{off:#x}");
        }
    }
}

#[test]
fn a_hash_mismatch_is_a_hash_error() {
    let g = synth::game();
    let (nca, nsp) = program_nca(&g);
    for layout in LAYOUTS {
        let z = Ncz::open(mem(ncz::build(
            &nca,
            &g.keys.keys,
            nsp.title_keys(),
            layout,
        )
        .expect("builds")))
        .expect("opens");
        let mut bad = sha256(&nca);
        bad[0] ^= 1;
        assert!(matches!(z.verify(&bad), Err(Error::Hash(_))));
        assert!(matches!(
            z.to_nca(&mut std::io::sink(), Some(&bad)),
            Err(Error::Hash(_))
        ));
    }
}

#[test]
fn a_corrupted_block_is_an_error() {
    let g = synth::game();
    let (nca, nsp) = program_nca(&g);
    let layout = Layout::Blocks {
        exponent: 14,
        level: 3,
    };
    let good = ncz::build(&nca, &g.keys.keys, nsp.title_keys(), layout).expect("builds");
    let z = Ncz::open(mem(good.clone())).expect("opens");
    let Compression::Blocks(h) = &z.compression else {
        panic!("blocks");
    };
    // Corrupt the first compressed (not stored) block's frame magic.
    let i = h
        .compressed_sizes
        .iter()
        .enumerate()
        .position(|(i, &c)| u64::from(c) < h.block_len(i))
        .expect("a compressed block");
    let at = z.data_offset
        + h.compressed_sizes[..i]
            .iter()
            .map(|&c| u64::from(c))
            .sum::<u64>();
    let mut bad = good;
    for k in 0..16 {
        bad[at as usize + k] ^= 0xFF;
    }
    let z = Ncz::open(mem(bad)).expect("header still opens");
    assert!(z.to_nca(&mut std::io::sink(), None).is_err());
}

#[test]
fn a_corrupted_solid_stream_is_an_error() {
    let g = synth::game();
    let (nca, nsp) = program_nca(&g);
    let mut bad = ncz::build(
        &nca,
        &g.keys.keys,
        nsp.title_keys(),
        Layout::Solid { level: 3 },
    )
    .expect("builds");
    let n = bad.len();
    bad.truncate(n - 20);
    let z = Ncz::open(mem(bad)).expect("header opens");
    assert!(z.to_nca(&mut std::io::sink(), None).is_err());
}

#[test]
fn malformed_headers_are_rejected() {
    let g = synth::game();
    let (nca, nsp) = program_nca(&g);
    let good = ncz::build(
        &nca,
        &g.keys.keys,
        nsp.title_keys(),
        Layout::Solid { level: 3 },
    )
    .expect("builds");
    let mut magic = good.clone();
    magic[0x4000] = b'X';
    assert!(matches!(Ncz::open(mem(magic)), Err(Error::Format(_))));
    assert!(matches!(
        Ncz::open(mem(good[..0x4008].to_vec())),
        Err(Error::Format(_))
    ));
    let mut count = good.clone();
    count[0x4008..0x4010].copy_from_slice(&0u64.to_le_bytes());
    assert!(matches!(Ncz::open(mem(count)), Err(Error::Format(_))));
    // A section that leaves a gap is unsupported.
    let mut gap = good;
    let first_off = 0x4010;
    let v = u64::from_le_bytes(gap[first_off..first_off + 8].try_into().expect("8"));
    gap[first_off..first_off + 8].copy_from_slice(&(v + 0x1000).to_le_bytes());
    assert!(Ncz::open(mem(gap)).is_err());
}

fn romfs_files(r: &Romfs) -> Vec<(String, Vec<u8>)> {
    r.files()
        .iter()
        .map(|f| {
            let mut v = Vec::new();
            r.copy_file(f, &mut v).expect("file");
            (f.path.clone(), v)
        })
        .collect()
}

#[test]
fn an_nsz_reads_like_its_nsp() {
    let g = synth::game();
    let nsp = Nsp::from_storage(mem(g.base.clone())).expect("nsp");
    let plain = open_title(&g.keys.keys, &nsp, None).expect("title");
    for layout in LAYOUTS {
        let nsz = ncz::build_nsz(&g.base, &g.keys.keys, layout).expect("nsz");
        assert!(nsz.len() != g.base.len());
        let z = ncz::open_nsz(mem(nsz)).expect("opens");
        assert!(z.pfs0().entries().iter().any(|e| e.name.ends_with(".ncz")));
        assert!(z.program(&g.keys.keys).is_ok());
        assert_eq!(
            z.cnmt(&g.keys.keys).expect("cnmt"),
            nsp.cnmt(&g.keys.keys).expect("cnmt")
        );
        assert_eq!(z.title_keys().len(), nsp.title_keys().len());
        let t = open_title(&g.keys.keys, &z, None).expect("title");
        assert_eq!(t.program_id, plain.program_id);
        let names = |t: &switch_formats::title::Title| {
            t.exefs
                .entries()
                .iter()
                .map(|e| (e.name.clone(), t.exefs.read(e).expect("read")))
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&t), names(&plain));
        assert_eq!(
            romfs_files(&t.romfs.expect("romfs")),
            romfs_files(plain.romfs.as_ref().expect("romfs"))
        );
        let cnmt = z.cnmt(&g.keys.keys).expect("cnmt");
        assert_eq!(ncz::verify_nsz(&z, &cnmt).expect("verifies"), 1);
        // A record with a wrong hash fails.
        let mut recs = cnmt.contents.clone();
        recs[0].hash[3] ^= 1;
        let bad = Cnmt::parse(&build_cnmt(
            cnmt.title_id,
            cnmt.version,
            cnmt.meta_type,
            &recs,
        ))
        .expect("parse");
        assert!(matches!(ncz::verify_nsz(&z, &bad), Err(Error::Hash(_))));
        let _: &ContentRecord = &bad.contents[0];
    }
}
