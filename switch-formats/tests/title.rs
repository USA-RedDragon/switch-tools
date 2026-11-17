//! End-to-end reads of synthetic NSPs: title keys from tickets, exefs
//! through hierarchical SHA-256, a BKTR-patched romfs through IVFC, NSOs.

use std::sync::Arc;

use switch_formats::Error;
use switch_formats::integrity::IvfcInfo;
use switch_formats::keys::TitleKeys;
use switch_formats::nca::{Encryption, Nca};
use switch_formats::npdm::{AddressSpace, Npdm};
use switch_formats::nso::Nso;
use switch_formats::romfs::Romfs;
use switch_formats::storage::MemStorage;
use switch_formats::synth;
use switch_formats::title::{Nsp, open_title};

fn nsp(bytes: &[u8]) -> Nsp {
    Nsp::from_storage(Arc::new(MemStorage(bytes.to_vec()))).expect("nsp opens")
}

fn romfs_contents(r: &Romfs) -> Vec<(String, Vec<u8>)> {
    r.files()
        .iter()
        .map(|f| {
            let mut v = Vec::new();
            r.copy_file(f, &mut v).expect("file reads");
            (f.path.clone(), v)
        })
        .collect()
}

#[test]
fn base_alone_reads_back() {
    let g = synth::game();
    let base = nsp(&g.base);
    let t = open_title(&g.keys.keys, &base, None).expect("title opens");
    assert_eq!(t.program_id, g.base_spec.program_id);
    let names: Vec<_> = t.exefs.entries().iter().map(|e| e.name.clone()).collect();
    assert_eq!(names, ["main", "main.npdm", "sdk"]);
    let romfs = t.romfs.expect("romfs");
    let mut want = g.base_spec.romfs.clone();
    want.sort();
    assert_eq!(romfs_contents(&romfs), want);
}

#[test]
fn update_patches_the_romfs_with_bktr() {
    let g = synth::game();
    let (base, upd) = (nsp(&g.base), nsp(&g.update));
    let t = open_title(&g.keys.keys, &base, Some(&upd)).expect("title opens");
    assert_eq!(t.version, 0x10000);
    let romfs = t.romfs.expect("romfs");
    let mut want = g.update_spec.romfs.clone();
    want.sort();
    assert_eq!(romfs_contents(&romfs), want);
    let main = t.exefs.find("main").expect("main");
    let nso = Nso::parse(&t.exefs.read(main).expect("read")).expect("nso");
    assert_eq!(nso.build_id, [0xB1; 32]);
}

#[test]
fn nso_and_npdm_parse() {
    let g = synth::game();
    let t = open_title(&g.keys.keys, &nsp(&g.base), None).expect("title opens");
    let sdk = Nso::parse(
        &t.exefs
            .read(t.exefs.find("sdk").expect("sdk"))
            .expect("read"),
    )
    .expect("nso");
    assert_eq!(sdk.module_name().as_deref(), Some("nnSdk"));
    let main = Nso::parse(
        &t.exefs
            .read(t.exefs.find("main").expect("main"))
            .expect("read"),
    )
    .expect("nso");
    assert_eq!(main.module_name().as_deref(), Some("game-main"));
    let syms = main.symbols().expect("symbols");
    assert_eq!(syms.len(), 2);
    assert_eq!(syms[0].name, "nnMain");
    assert!(syms[0].is_defined());
    assert!(!syms[1].is_defined());
    let m = main.mod0().expect("mod0").expect("present");
    assert_eq!(m.offset, 0x10);
    let flat = main.to_uncompressed();
    let again = Nso::parse(&flat).expect("uncompressed nso parses");
    assert_eq!(again.image, main.image);
    let npdm = Npdm::parse(
        &t.exefs
            .read(t.exefs.find("main.npdm").expect("npdm"))
            .expect("read"),
    )
    .expect("npdm");
    assert_eq!(npdm.address_space, AddressSpace::As64Bit);
    assert_eq!(npdm.main_thread_stack_size, 0x10_0000);
    let names: Vec<_> = npdm.services.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["fsp-srv", "sm:"]);
}

/// Some dump tools leave the NCA header decrypted and the sections
/// encrypted: such an NSP reads back the same as the original.
#[test]
fn a_plaintext_nca_header_is_read_as_it_is() {
    let g = synth::game();
    let base = nsp(&g.base);
    let mut bytes = g.base.clone();
    for e in base
        .pfs0()
        .entries()
        .iter()
        .filter(|e| e.name.ends_with(".nca"))
    {
        let at = usize::try_from(e.offset).expect("fits");
        let head = &mut bytes[at..at + 0xC00];
        switch_formats::crypto::xts_decrypt(&g.keys.header_key, head, 0);
        assert_eq!(&head[0x200..0x204], b"NCA3");
    }
    let plain = nsp(&bytes);
    let t = open_title(&g.keys.keys, &plain, None).expect("title opens");
    let want = open_title(&g.keys.keys, &base, None).expect("title opens");
    assert_eq!(t.program_id, want.program_id);
    let main = |t: &switch_formats::title::Title| {
        t.exefs
            .read(t.exefs.find("main").expect("main"))
            .expect("read")
    };
    assert_eq!(main(&t), main(&want));
    assert_eq!(
        romfs_contents(&t.romfs.expect("romfs")),
        romfs_contents(&want.romfs.expect("romfs"))
    );
}

/// A fully decrypted NCA (header and sections, the sections still marked
/// AES-CTR) reads back the same: each section's bytes pass its top hash as
/// stored, so they are not decrypted again.
#[test]
fn a_fully_decrypted_nca_is_read_as_it_is() {
    let g = synth::game();
    let base = nsp(&g.base);
    let program = base.program(&g.keys.keys).expect("program");
    let entry = base
        .pfs0()
        .entries()
        .iter()
        .find(|e| e.name.ends_with(".nca") && !e.name.ends_with(".cnmt.nca"))
        .expect("program nca")
        .clone();
    let at = usize::try_from(entry.offset).expect("fits");
    let mut bytes = g.base.clone();
    let mut decrypted = 0;
    for i in 0..4 {
        let Some((off, size)) = program.header().section(i) else {
            continue;
        };
        let fs = program.header().fs_header(i);
        if fs.encryption().expect("type") != Encryption::Ctr {
            continue;
        }
        let (a, n) = (
            usize::try_from(off).expect("fits"),
            usize::try_from(size).expect("fits"),
        );
        switch_formats::crypto::ctr_apply(
            &g.base_spec.content_key,
            fs.counter_upper(),
            off,
            &mut bytes[at + a..at + a + n],
        );
        decrypted += 1;
    }
    assert!(decrypted >= 2, "exefs and romfs are AES-CTR");
    switch_formats::crypto::xts_decrypt(&g.keys.header_key, &mut bytes[at..at + 0xC00], 0);
    let plain = nsp(&bytes);
    let t = open_title(&g.keys.keys, &plain, None).expect("title opens");
    let want = open_title(&g.keys.keys, &base, None).expect("title opens");
    let main = |t: &switch_formats::title::Title| {
        t.exefs
            .read(t.exefs.find("main").expect("main"))
            .expect("read")
    };
    assert_eq!(main(&t), main(&want));
    assert_eq!(
        romfs_contents(&t.romfs.expect("romfs")),
        romfs_contents(&want.romfs.expect("romfs"))
    );
}

#[test]
fn wrong_header_key_is_reported() {
    let g = synth::game();
    let other = synth::keys(9);
    let err = open_title(&other.keys, &nsp(&g.base), None)
        .err()
        .expect("fails");
    assert!(matches!(err, Error::WrongKey(_)), "{err}");
}

#[test]
fn wrong_title_key_is_reported() {
    let g = synth::game();
    let mut keys = g.keys.keys.clone();
    keys.insert("titlekek_00", &[0x33; 16]);
    let err = open_title(&keys, &nsp(&g.base), None).err().expect("fails");
    assert!(matches!(err, Error::WrongKey(_)), "{err}");
}

#[test]
fn missing_ticket_is_reported() {
    let g = synth::game();
    let base = nsp(&g.base);
    let entry = base
        .pfs0()
        .entries()
        .iter()
        .find(|e| e.name.ends_with(".nca") && !e.name.ends_with(".cnmt.nca"))
        .expect("program nca")
        .clone();
    let storage = base.pfs0().open_entry(&entry).expect("entry");
    let nca = Nca::open(storage, &g.keys.keys, &TitleKeys::default()).expect("header opens");
    let err = nca
        .section_raw(0, &g.keys.keys, &TitleKeys::default())
        .err()
        .expect("fails");
    assert!(matches!(err, Error::MissingKey(_)), "{err}");
}

/// Flip one byte of the encrypted romfs data deep inside the NCA: the
/// read of that block fails its IVFC hash.
#[test]
fn flipped_romfs_byte_is_rejected() {
    let g = synth::game();
    let base = nsp(&g.base);
    let nca_entry = base
        .pfs0()
        .entries()
        .iter()
        .find(|e| e.name.ends_with(".nca") && !e.name.ends_with(".cnmt.nca"))
        .expect("program nca")
        .clone();
    let mut bytes = g.base.clone();
    let nca = base.program(&g.keys.keys).expect("program");
    let (sec_off, _) = nca.header().section(1).expect("romfs section");
    let ivfc = IvfcInfo::parse(&nca.header().fs_header(1)).expect("ivfc");
    let data = ivfc.levels.last().expect("data level").offset;
    let at = usize::try_from(nca_entry.offset + sec_off + data + 0x1800).expect("fits");
    bytes[at] ^= 1;
    let bad = nsp(&bytes);
    let t = open_title(&g.keys.keys, &bad, None);
    let err = match t {
        Err(e) => e,
        Ok(t) => {
            let r = t.romfs.expect("romfs");
            let mut err = None;
            for f in r.files() {
                let mut v = Vec::new();
                if let Err(e) = r.copy_file(f, &mut v) {
                    err = Some(e);
                }
            }
            err.expect("some file fails its hash")
        }
    };
    assert!(matches!(err, Error::Hash(_)), "{err}");
}

#[test]
fn flipped_exefs_byte_is_rejected() {
    let g = synth::game();
    let base = nsp(&g.base);
    let entry = base
        .pfs0()
        .entries()
        .iter()
        .find(|e| e.name.ends_with(".nca") && !e.name.ends_with(".cnmt.nca"))
        .expect("program nca")
        .clone();
    let nca = base.program(&g.keys.keys).expect("program");
    let (sec_off, sec_size) = nca.header().section(0).expect("exefs");
    let mut bytes = g.base.clone();
    let at = usize::try_from(entry.offset + sec_off + sec_size / 2).expect("fits");
    bytes[at] ^= 0x80;
    let err = open_title(&g.keys.keys, &nsp(&bytes), None)
        .err()
        .expect("fails");
    assert!(matches!(err, Error::Hash(_)), "{err}");
}

#[test]
fn romfs_storage_is_the_image_the_romfs_reads() {
    let g = synth::game();
    let (base, upd) = (nsp(&g.base), nsp(&g.update));
    let keys = &g.keys.keys;
    let (bn, un) = (
        base.program(keys).expect("base"),
        upd.program(keys).expect("update"),
    );
    let image = switch_formats::title::open_romfs_storage(
        Some((&bn, base.title_keys())),
        Some((&un, upd.title_keys())),
        keys,
    )
    .expect("storage opens")
    .expect("romfs present");
    let romfs = Romfs::open(image).expect("image parses");
    let mut want = g.update_spec.romfs.clone();
    want.sort();
    assert_eq!(romfs_contents(&romfs), want);
}
