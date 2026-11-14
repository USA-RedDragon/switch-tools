//! XCI and HFS0 reads of synthetic cards: the secure partition's key-area
//! NCAs open through the usual section readers, the prefix and trimmed
//! variants read, and flipped bytes fail with a hash error.

use std::sync::Arc;

use switch_formats::Error;
use switch_formats::hfs0::Hfs0;
use switch_formats::nca::ContentType;
use switch_formats::storage::{MemStorage, Shared, Storage};
use switch_formats::synth::{self, FixtureKeys, ProgramSpec};
use switch_formats::title::{open_pfs0_section, open_romfs};
use switch_formats::xci::{self, KEY_AREA_SIZE, ROOT_OFFSET, Xci, XciHeader};

struct Card {
    fk: FixtureKeys,
    spec: ProgramSpec,
    program: Vec<u8>,
    meta: Vec<u8>,
    bytes: Vec<u8>,
}

fn card(key_area: bool) -> Card {
    let g = synth::game();
    let mut spec = g.base_spec.clone();
    spec.rights_id = None;
    let (program, _) = synth::program_nca(&g.keys, &spec);
    let meta = synth::meta_nca(&g.keys, spec.program_id, 0, 0x80, &program);
    let bytes = xci::build(
        &[
            ("update", vec![]),
            ("normal", vec![]),
            (
                "secure",
                vec![
                    ("aaaa.nca", program.as_slice()),
                    ("bbbb.cnmt.nca", meta.as_slice()),
                ],
            ),
            ("logo", vec![("readme", b"hi".as_slice())]),
        ],
        key_area,
    );
    Card {
        fk: g.keys,
        spec,
        program,
        meta,
        bytes,
    }
}

fn open(bytes: Vec<u8>) -> Result<Xci, Error> {
    Xci::open(Arc::new(MemStorage(bytes)))
}

fn check_contents(c: &Card, x: &Xci) {
    let keys = &c.fk.keys;
    assert!(x.title_keys().is_empty());
    let names: Vec<_> = x.partitions().iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["update", "normal", "secure", "logo"]);
    let secure = x.partition("secure").expect("secure opens");
    assert_eq!(secure.entries().len(), 2);
    let e = secure.find("aaaa.nca").expect("program file");
    assert_eq!(secure.read(e).expect("read"), c.program);
    let e = secure.find("bbbb.cnmt.nca").expect("meta file");
    assert_eq!(secure.read(e).expect("read"), c.meta);
    assert_eq!(x.partition("logo").expect("logo").entries().len(), 1);
    assert!(x.partition("nope").is_err());

    let program = x.program(keys).expect("program");
    assert_eq!(program.header().content_type(), ContentType::Program);
    assert_eq!(program.header().program_id(), c.spec.program_id);
    let exefs = open_pfs0_section(&program, 0, keys, x.title_keys()).expect("exefs");
    let got: Vec<_> = exefs.entries().iter().map(|e| e.name.clone()).collect();
    let mut want: Vec<_> = c.spec.exefs.iter().map(|(n, _)| n.clone()).collect();
    want.sort();
    assert_eq!(got, want);
    let romfs = open_romfs(Some((&program, x.title_keys())), None, keys)
        .expect("romfs")
        .expect("has romfs");
    let mut files = Vec::new();
    for f in romfs.files() {
        let mut v = Vec::new();
        romfs.copy_file(f, &mut v).expect("file");
        files.push((f.path.clone(), v));
    }
    let mut want = c.spec.romfs.clone();
    want.sort();
    assert_eq!(files, want);
    let cnmt = x.cnmt(keys).expect("cnmt");
    assert_eq!(cnmt.title_id, c.spec.program_id);
}

#[test]
fn reads_a_card() {
    let c = card(false);
    let x = open(c.bytes.clone()).expect("opens");
    assert!(x.key_area().is_none());
    assert!(x.trimmed());
    let h = x.header();
    assert_eq!(h.root_offset, ROOT_OFFSET);
    assert_eq!(h.rom_size, 0xFA);
    assert_eq!(h.declared_size(), Some(1 << 30));
    assert_eq!(h.package_id, 0x0123_4567_89AB_CDEF);
    assert_eq!(h.lim_area_page, 0x38D);
    assert_eq!(h.encrypted_info, [0x33; 0x70]);
    assert_eq!(
        XciHeader::parse(&c.bytes[..0x200]).expect("parses"),
        h.clone()
    );
    assert_eq!(h.to_bytes()[..], c.bytes[..0x200]);
    check_contents(&c, &x);
}

#[test]
fn reads_with_the_key_area_prefix() {
    let c = card(true);
    let x = open(c.bytes.clone()).expect("opens");
    assert_eq!(x.key_area().expect("prefix").len() as u64, KEY_AREA_SIZE);
    assert_eq!(x.header().root_offset, ROOT_OFFSET);
    check_contents(&c, &x);
}

struct Padded(Vec<u8>, u64);

impl Storage for Padded {
    fn size(&self) -> u64 {
        self.1
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> switch_formats::Result<()> {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = self.0.get(offset as usize + i).copied().unwrap_or(0);
        }
        Ok(())
    }
}

#[test]
fn trimmed_is_false_for_a_full_size_image() {
    let c = card(false);
    let full: Shared = Arc::new(Padded(c.bytes, 1 << 30));
    let x = Xci::open(full).expect("opens");
    assert!(!x.trimmed());
    check_contents(&card(false), &x);
}

#[test]
fn partition_outside_a_cut_file_is_an_error() {
    let c = card(false);
    let cut = c.bytes[..c.bytes.len() - 1].to_vec();
    assert!(matches!(open(cut), Err(Error::Format(_))));
}

#[test]
fn flipped_byte_in_a_hashed_region_is_a_hash_error() {
    let c = card(false);
    let root = Hfs0::open(Arc::new(MemStorage(
        c.bytes[ROOT_OFFSET as usize..].to_vec(),
    )))
    .expect("root");
    let secure = root.find("secure").expect("secure");
    let child = Hfs0::open_unverified(root.open_entry(secure).expect("window")).expect("child");
    let nca = child.find("aaaa.nca").expect("nca");
    let mut bytes = c.bytes.clone();
    bytes[ROOT_OFFSET as usize + secure.offset as usize + nca.offset as usize + 5] ^= 1;
    let x = open(bytes).expect("root level still verifies");
    match x.partition("secure") {
        Err(Error::Hash(m)) => assert!(m.contains("secure") && m.contains("aaaa.nca"), "{m}"),
        other => panic!("want a hash error, got {:?}", other.err()),
    }
}

#[test]
fn bad_root_header_hash_is_a_hash_error() {
    let c = card(false);
    let mut bytes = c.bytes.clone();
    bytes[0x140] ^= 1;
    assert!(matches!(open(bytes), Err(Error::Hash(m)) if m.contains("root")));
    let mut bytes = c.bytes.clone();
    bytes[ROOT_OFFSET as usize + 0x30] ^= 1;
    assert!(matches!(open(bytes), Err(Error::Hash(_))));
}

#[test]
fn flipped_partition_header_is_a_hash_error_naming_the_entry() {
    let c = card(false);
    let mut bytes = c.bytes.clone();
    let root =
        Hfs0::open(Arc::new(MemStorage(bytes[ROOT_OFFSET as usize..].to_vec()))).expect("root");
    let logo = root.find("logo").expect("logo");
    bytes[ROOT_OFFSET as usize + logo.offset as usize + 0x10 + 0x30] ^= 1;
    match open(bytes) {
        Err(Error::Hash(m)) => assert!(m.contains("logo"), "{m}"),
        other => panic!("want a hash error, got {:?}", other.err()),
    }
}

#[test]
fn not_an_xci() {
    assert!(matches!(open(vec![0; 0x1000]), Err(Error::Format(_))));
    assert!(matches!(open(vec![0; 8]), Err(Error::Format(_))));
}
