//! Synthetic fixtures: keys generated from a seed, and complete NSPs (a
//! program NCA with exefs and romfs, a meta NCA, a ticket) plus update NSPs
//! whose romfs is a BKTR patch over the base. Tests across the workspace
//! build every container they read from here; no console data is involved.

use crate::bktr::{
    CTR_EX_ENTRY_SIZE, INDIRECT_ENTRY_SIZE, IndirectEntry, PatchInfo, TreeHeader, build_tree,
};
use crate::cnmt::{self, ContentRecord};
use crate::crypto::{ctr_apply, ecb_encrypt_block, sha256, xts_encrypt};
use crate::integrity::{build_ivfc, build_sha256};
use crate::keys::Keys;
use crate::nca::{ContentType, FsHeader, HeaderSpec, build_fs_header, build_header};
use crate::{pfs0, romfs, ticket};

/// Fixture key material. The values are made up from a seed.
pub struct FixtureKeys {
    /// The parsed key set.
    pub keys: Keys,
    /// The same keys as `prod.keys` text.
    pub text: String,
    /// `header_key`.
    pub header_key: [u8; 32],
    /// `key_area_key_application_00`.
    pub key_area_key: [u8; 16],
    /// `titlekek_00`.
    pub titlekek: [u8; 16],
}

fn seeded<const N: usize>(seed: u8) -> [u8; N] {
    let mut out = [0u8; N];
    let h = sha256(&[seed, 0x5a, 0xa5]);
    for (i, o) in out.iter_mut().enumerate() {
        *o = h[i % 32] ^ (i as u8).wrapping_mul(31);
    }
    out
}

/// Keys derived from `seed`; two seeds give unrelated keys (for wrong-key
/// tests).
pub fn keys(seed: u8) -> FixtureKeys {
    let header_key: [u8; 32] = seeded(seed);
    let key_area_key: [u8; 16] = seeded(seed.wrapping_add(1));
    let titlekek: [u8; 16] = seeded(seed.wrapping_add(2));
    let text = format!(
        "header_key = {}\nkey_area_key_application_00 = {}\ntitlekek_00 = {}\n",
        crate::hex(&header_key),
        crate::hex(&key_area_key),
        crate::hex(&titlekek)
    );
    let keys = Keys::parse(&text).unwrap_or_default();
    FixtureKeys {
        keys,
        text,
        header_key,
        key_area_key,
        titlekek,
    }
}

/// What goes into a program NCA.
#[derive(Clone, Debug)]
pub struct ProgramSpec {
    /// The program ID.
    pub program_id: u64,
    /// Exefs files.
    pub exefs: Vec<(String, Vec<u8>)>,
    /// Romfs files.
    pub romfs: Vec<(String, Vec<u8>)>,
    /// A rights ID: the content key becomes a title key in a ticket.
    pub rights_id: Option<[u8; 16]>,
    /// The content key.
    pub content_key: [u8; 16],
}

/// The IVFC block size of fixtures (log2).
const IVFC_BLOCK_LOG2: u32 = 12;
/// The counter upper half of section `i`, little-endian as stored.
fn counter(i: u64) -> u64 {
    0x0000_0003_0000_0000 | (i + 1)
}

fn pad(v: &mut Vec<u8>, to: usize) {
    v.resize(v.len().div_ceil(to) * to, 0);
}

/// A section ready to place: plaintext and FS header.
struct Section {
    plain: Vec<u8>,
    fs: FsHeader,
    /// For AES-CTR-EX sections: the patch data size and its generations.
    ctr_ex: Option<(u64, Vec<(u64, u32)>)>,
}

fn exefs_section(files: &[(String, Vec<u8>)]) -> Section {
    let list: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    let (plain, info) = build_sha256(&pfs0::build(&list), 0x1000);
    Section {
        plain,
        fs: build_fs_header(1, 2, 3, &info.to_bytes(), &[], counter(0)),
        ctr_ex: None,
    }
}

/// The plaintext romfs section (IVFC levels and data) and its FS header.
fn romfs_section(files: &[(String, Vec<u8>)]) -> (Vec<u8>, FsHeader) {
    let list: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    let (mut plain, info) = build_ivfc(&romfs::build(&list), 3, IVFC_BLOCK_LOG2);
    pad(&mut plain, 0x200);
    (
        plain,
        build_fs_header(0, 3, 3, &info.to_bytes(), &[], counter(1)),
    )
}

fn assemble(
    fk: &FixtureKeys,
    spec: &HeaderSpec,
    content_key: &[u8; 16],
    sections: Vec<Section>,
) -> Vec<u8> {
    // Real NCAs start the first section at 0x4000, after the header and padding.
    let mut out = vec![0u8; 0x4000];
    let mut placed = Vec::new();
    for s in sections {
        let off = out.len() as u64;
        let mut body = s.plain;
        pad(&mut body, 0x200);
        let upper = s.fs.counter_upper();
        match &s.ctr_ex {
            None => ctr_apply(content_key, upper, off, &mut body),
            Some((data_len, gens)) => {
                let data_len = usize::try_from(*data_len).unwrap_or(0);
                for (i, (start, generation)) in gens.iter().enumerate() {
                    let end = gens.get(i + 1).map_or(data_len as u64, |g| g.0);
                    let (a, b) = (
                        usize::try_from(*start).unwrap_or(0),
                        usize::try_from(end).unwrap_or(0),
                    );
                    let mut u = upper;
                    u[4..8].copy_from_slice(&generation.to_be_bytes());
                    ctr_apply(content_key, u, off + *start, &mut body[a..b]);
                }
                ctr_apply(
                    content_key,
                    upper,
                    off + data_len as u64,
                    &mut body[data_len..],
                );
            }
        }
        placed.push((off, body.len() as u64, s.fs));
        out.extend_from_slice(&body);
    }
    let mut spec = spec.clone();
    if spec.rights_id == [0; 16] {
        spec.key_area[2] = *content_key;
    }
    let mut header = build_header(&spec, &fk.key_area_key, out.len() as u64, &placed);
    xts_encrypt(&fk.header_key, &mut header, 0);
    out[..header.len()].copy_from_slice(&header);
    out
}

fn header_spec(content_type: ContentType, program_id: u64, rights: Option<[u8; 16]>) -> HeaderSpec {
    HeaderSpec {
        content_type,
        key_generation: 1,
        key_area_index: 0,
        program_id,
        rights_id: rights.unwrap_or([0; 16]),
        key_area: [[0; 16]; 4],
    }
}

/// Build a base program NCA. Returns the NCA and its plaintext romfs
/// section (which an update patches against).
pub fn program_nca(fk: &FixtureKeys, spec: &ProgramSpec) -> (Vec<u8>, Vec<u8>) {
    let (romfs_plain, romfs_fs) = romfs_section(&spec.romfs);
    let nca = assemble(
        fk,
        &header_spec(ContentType::Program, spec.program_id, spec.rights_id),
        &spec.content_key,
        vec![
            exefs_section(&spec.exefs),
            Section {
                plain: romfs_plain.clone(),
                fs: romfs_fs,
                ctr_ex: None,
            },
        ],
    );
    (nca, romfs_plain)
}

/// Build an update program NCA whose romfs is a BKTR patch over
/// `base_romfs` (the base's plaintext romfs section).
pub fn update_nca(fk: &FixtureKeys, spec: &ProgramSpec, base_romfs: &[u8]) -> Vec<u8> {
    let (new_plain, new_fs) = romfs_section(&spec.romfs);
    let chunk = 0x1000usize;
    let mut entries: Vec<IndirectEntry> = Vec::new();
    let mut patch = Vec::new();
    for (i, c) in new_plain.chunks(chunk).enumerate() {
        let at = i * chunk;
        let same = base_romfs.get(at..at + c.len()) == Some(c);
        let storage = u8::from(!same);
        let phys = if same { at as u64 } else { patch.len() as u64 };
        if !same {
            patch.extend_from_slice(c);
        }
        let merge = entries.last().is_some_and(|e| {
            e.storage == storage
                && (storage == 1 || e.physical_offset + (at as u64 - e.virtual_offset) == at as u64)
        });
        if !merge {
            entries.push(IndirectEntry {
                virtual_offset: at as u64,
                physical_offset: phys,
                storage,
            });
        }
    }
    pad(&mut patch, 0x10);
    let data_len = patch.len() as u64;
    let half = (data_len / 2) & !0xF;
    let gens: Vec<(u64, u32)> = if half > 0 {
        vec![(0, 1), (half, 2)]
    } else {
        vec![(0, 1)]
    };
    let reloc_raw: Vec<Vec<u8>> = entries
        .iter()
        .map(|e| {
            let mut r = Vec::new();
            r.extend_from_slice(&e.virtual_offset.to_le_bytes());
            r.extend_from_slice(&e.physical_offset.to_le_bytes());
            r.extend_from_slice(&u32::from(e.storage).to_le_bytes());
            r
        })
        .collect();
    let reloc = build_tree(&reloc_raw, INDIRECT_ENTRY_SIZE, new_plain.len() as u64);
    let ex_raw: Vec<Vec<u8>> = gens
        .iter()
        .map(|(o, g)| {
            let mut r = Vec::new();
            r.extend_from_slice(&o.to_le_bytes());
            r.extend_from_slice(&0u32.to_le_bytes());
            r.extend_from_slice(&g.to_le_bytes());
            r
        })
        .collect();
    let ex = build_tree(&ex_raw, CTR_EX_ENTRY_SIZE, data_len);
    let info = PatchInfo {
        relocation_offset: data_len,
        relocation_size: reloc.len() as u64,
        relocation_header: TreeHeader {
            entry_count: u32::try_from(reloc_raw.len()).unwrap_or(0),
        },
        encryption_offset: data_len + reloc.len() as u64,
        encryption_size: ex.len() as u64,
        encryption_header: TreeHeader {
            entry_count: u32::try_from(ex_raw.len()).unwrap_or(0),
        },
    };
    let mut plain = patch;
    plain.extend_from_slice(&reloc);
    plain.extend_from_slice(&ex);
    let fs = build_fs_header(
        0,
        3,
        4,
        new_fs.integrity_info(),
        &info.to_bytes(),
        counter(1),
    );
    assemble(
        fk,
        &header_spec(ContentType::Program, spec.program_id, spec.rights_id),
        &spec.content_key,
        vec![
            exefs_section(&spec.exefs),
            Section {
                plain,
                fs,
                ctr_ex: Some((data_len, gens)),
            },
        ],
    )
}

/// Build a meta NCA holding a CNMT for `program` (key-area encrypted).
pub fn meta_nca(
    fk: &FixtureKeys,
    title_id: u64,
    version: u32,
    meta_type: u8,
    program: &[u8],
) -> Vec<u8> {
    meta_nca_for(fk, title_id, version, meta_type, &[(program, 1)])
}

/// Build a meta NCA holding a CNMT that lists `contents` as (NCA bytes,
/// content type byte: 1 program, 2 data, 3 control).
pub fn meta_nca_for(
    fk: &FixtureKeys,
    title_id: u64,
    version: u32,
    meta_type: u8,
    contents: &[(&[u8], u8)],
) -> Vec<u8> {
    let records: Vec<ContentRecord> = contents
        .iter()
        .map(|(nca, content_type)| {
            let hash = sha256(nca);
            let mut id = [0u8; 16];
            id.copy_from_slice(&hash[..16]);
            ContentRecord {
                hash,
                content_id: id,
                size: nca.len() as u64,
                content_type: *content_type,
                id_offset: 0,
            }
        })
        .collect();
    let c = cnmt::build(title_id, version, meta_type, &records);
    let name = format!("Application_{title_id:016x}.cnmt");
    assemble(
        fk,
        &header_spec(ContentType::Meta, title_id, None),
        &seeded(0x77),
        vec![exefs_section(&[(name, c)])],
    )
}

/// A deterministic random source from a seed (SHA-256 of seed and
/// counter), for fixture keys and OAEP padding. Never for real secrets.
pub struct SeededRng {
    seed: [u8; 32],
    counter: u64,
    buf: Vec<u8>,
}

impl SeededRng {
    /// A source from `seed`.
    pub fn new(seed: &[u8]) -> SeededRng {
        SeededRng {
            seed: sha256(seed),
            counter: 0,
            buf: Vec::new(),
        }
    }
}

impl rsa::rand_core::TryRng for SeededRng {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), Self::Error> {
        for d in dst {
            if self.buf.is_empty() {
                let mut block = self.seed.to_vec();
                block.extend_from_slice(&self.counter.to_le_bytes());
                self.counter += 1;
                self.buf = sha256(&block).to_vec();
            }
            *d = self.buf.remove(0);
        }
        Ok(())
    }
}

impl rsa::rand_core::TryCryptoRng for SeededRng {}

/// A test-only eTicket RSA-2048 key pair generated from a seed, as a raw
/// key pair ([`crate::eticket::KEYPAIR_SIZE`] bytes). It belongs to no
/// console. Generation takes a moment, so each seed's pair is made once.
pub fn eticket_keypair(seed: u8) -> Vec<u8> {
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    static CACHE: std::sync::Mutex<Vec<(u8, Vec<u8>)>> = std::sync::Mutex::new(Vec::new());
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((_, v)) = cache.iter().find(|(s, _)| *s == seed) {
        return v.clone();
    }
    let mut rng = SeededRng::new(&[b'e', b't', seed]);
    let Ok(key) = rsa::PrivateKey::new(&mut rng, 2048) else {
        return Vec::new();
    };
    let fixed = |b: Box<[u8]>| -> Vec<u8> {
        let mut v = vec![0u8; 0x100usize.saturating_sub(b.len())];
        v.extend_from_slice(&b);
        v
    };
    let mut out = fixed(key.d().to_be_bytes());
    out.extend(fixed(key.n().to_be_bytes()));
    out.extend_from_slice(&0x10001u32.to_be_bytes());
    out.resize(crate::eticket::KEYPAIR_SIZE, 0);
    cache.push((seed, out.clone()));
    out
}

/// The RSA-OAEP (SHA-256) title key block of a personalized ticket for the
/// key pair `keypair`, wrapping `encrypted_key` (the titlekek-wrapped key).
pub fn personalized_block(keypair: &[u8], encrypted_key: &[u8; 16]) -> [u8; 0x100] {
    let mut out = [0u8; 0x100];
    let n = rsa::BoxedUint::from_be_slice(&keypair[0x100..0x200], 2048);
    let Ok(n) = n else { return out };
    let Ok(public) = rsa::PublicKey::new(n, rsa::BoxedUint::from(0x10001u64)) else {
        return out;
    };
    let mut rng = SeededRng::new(encrypted_key);
    if let Ok(c) = public.oaep_encrypt_with_rng::<sha2::Sha256, _>(&mut rng, encrypted_key)
        && c.len() == 0x100
    {
        out.copy_from_slice(&c);
    }
    out
}

/// A decrypted PRODINFO (`CAL0`) holding `keypair` as its
/// `ExtendedRsa2048ETicketKey`, encrypted with `kek`; every other field is
/// zero. The body hash is valid.
pub fn prodinfo(kek: &[u8; 16], keypair: &[u8]) -> Vec<u8> {
    use crate::eticket::{PRODINFO_KEY_AT, PRODINFO_KEY_SIZE};
    let mut cal = vec![0u8; 0x8000];
    cal[..4].copy_from_slice(b"CAL0");
    let body = u32::try_from(cal.len() - 0x40).unwrap_or(0);
    cal[8..12].copy_from_slice(&body.to_le_bytes());
    let iv: [u8; 16] = seeded(0x90);
    let mut blob = vec![0u8; PRODINFO_KEY_SIZE - 16];
    blob[..keypair.len()].copy_from_slice(keypair);
    crate::crypto::ctr128_apply(kek, iv, &mut blob);
    cal[PRODINFO_KEY_AT..PRODINFO_KEY_AT + 16].copy_from_slice(&iv);
    cal[PRODINFO_KEY_AT + 16..PRODINFO_KEY_AT + PRODINFO_KEY_SIZE].copy_from_slice(&blob);
    let hash = sha256(&cal[0x40..]);
    cal[0x20..0x40].copy_from_slice(&hash);
    cal
}

/// [`game`]'s base as an NSP whose ticket is personalized to `keypair`
/// instead of common.
pub fn personalized_base(keypair: &[u8]) -> (FixtureKeys, Vec<u8>, ProgramSpec) {
    let g = game();
    let fk = g.keys;
    let spec = g.base_spec;
    let (nca, _) = program_nca(&fk, &spec);
    let meta = meta_nca(&fk, spec.program_id, 0, 0x80, &nca);
    let rights = spec.rights_id.unwrap_or([0; 16]);
    let enc = ecb_encrypt_block(&fk.titlekek, &spec.content_key);
    let block = personalized_block(keypair, &enc);
    let mut files: Vec<(String, Vec<u8>)> = vec![
        (format!("{}.nca", crate::hex(&sha256(&nca)[..16])), nca),
        (
            format!("{}.cnmt.nca", crate::hex(&sha256(&meta)[..16])),
            meta,
        ),
        (
            format!("{}.tik", crate::hex(&rights)),
            ticket::build_personalized(rights, &block, 0),
        ),
    ];
    files.push((format!("{}.cert", crate::hex(&rights)), vec![0u8; 0x700]));
    let list: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    let nsp = pfs0::build(&list);
    (fk, nsp, spec)
}

/// Package an NSP: program NCA, meta NCA and, for a rights ID, a common
/// ticket with the content key wrapped by the titlekek.
pub fn nsp(fk: &FixtureKeys, spec: &ProgramSpec, program: &[u8], meta: &[u8]) -> Vec<u8> {
    let tickets: Vec<([u8; 16], [u8; 16])> = spec
        .rights_id
        .map(|r| (r, spec.content_key))
        .into_iter()
        .collect();
    package(fk, &[program], meta, &tickets)
}

/// Package an NSP from content NCAs (named by their hash), a meta NCA
/// (`.cnmt.nca`) and one common ticket per (rights ID, content key).
pub fn package(
    fk: &FixtureKeys,
    contents: &[&[u8]],
    meta: &[u8],
    tickets: &[([u8; 16], [u8; 16])],
) -> Vec<u8> {
    let mut files: Vec<(String, Vec<u8>)> = contents
        .iter()
        .map(|c| (format!("{}.nca", crate::hex(&sha256(c)[..16])), c.to_vec()))
        .collect();
    files.push((
        format!("{}.cnmt.nca", crate::hex(&sha256(meta)[..16])),
        meta.to_vec(),
    ));
    for (r, key) in tickets {
        let enc = ecb_encrypt_block(&fk.titlekek, key);
        files.push((
            format!("{}.tik", crate::hex(r)),
            ticket::build_common(*r, enc, 0),
        ));
        files.push((format!("{}.cert", crate::hex(r)), vec![0u8; 0x700]));
    }
    let list: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    pfs0::build(&list)
}

/// Build a control NCA whose romfs (section 0) holds `control.nacp`.
pub fn control_nca(fk: &FixtureKeys, title_id: u64, nacp: &[u8]) -> Vec<u8> {
    control_nca_with(fk, title_id, nacp, &[])
}

/// Build a control NCA whose romfs holds `control.nacp` and `icons` as
/// (NACP language name, image) pairs, each stored as
/// `icon_<language>.dat`.
pub fn control_nca_with(
    fk: &FixtureKeys,
    title_id: u64,
    nacp: &[u8],
    icons: &[(&str, Vec<u8>)],
) -> Vec<u8> {
    let mut files = vec![("control.nacp".to_string(), nacp.to_vec())];
    files.extend(
        icons
            .iter()
            .map(|(lang, img)| (format!("icon_{lang}.dat"), img.clone())),
    );
    let (plain, fs) = romfs_section(&files);
    assemble(
        fk,
        &header_spec(ContentType::Control, title_id, None),
        &seeded(0x78),
        vec![Section {
            plain,
            fs,
            ctr_ex: None,
        }],
    )
}

/// Build an add-on content (data) NCA whose romfs (section 0) holds
/// `files`, encrypted with `content_key` (a title key when `rights_id` is
/// set).
pub fn addon_nca(
    fk: &FixtureKeys,
    addon_id: u64,
    files: &[(String, Vec<u8>)],
    rights_id: Option<[u8; 16]>,
    content_key: &[u8; 16],
) -> Vec<u8> {
    let (plain, fs) = romfs_section(files);
    assemble(
        fk,
        &header_spec(ContentType::Data, addon_id, rights_id),
        content_key,
        vec![Section {
            plain,
            fs,
            ctr_ex: None,
        }],
    )
}

/// An add-on NSP: one data NCA holding `files`, an add-on content meta
/// (type 0x82) of `version`, and a ticket for its title key.
pub fn addon_nsp(
    fk: &FixtureKeys,
    addon_id: u64,
    version: u32,
    files: &[(String, Vec<u8>)],
) -> Vec<u8> {
    let mut rights = [0u8; 16];
    rights[..8].copy_from_slice(&addon_id.to_be_bytes());
    let key: [u8; 16] = seeded(addon_id.to_le_bytes()[0] ^ (version as u8));
    let data = addon_nca(fk, addon_id, files, Some(rights), &key);
    let meta = meta_nca_for(fk, addon_id, version, 0x82, &[(&data, 2)]);
    package(fk, &[&data], &meta, &[(rights, key)])
}

/// `nsp` with a control NCA holding `nacp` added, as a real dump carries.
pub fn with_control(fk: &FixtureKeys, nsp: &[u8], title_id: u64, nacp: &[u8]) -> Vec<u8> {
    with_control_icons(fk, nsp, title_id, nacp, &[])
}

/// A small stand-in for a console icon: JPEG start and end markers around
/// `tag` (not a decodable image).
pub fn icon(tag: &str) -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0];
    v.extend_from_slice(tag.as_bytes());
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
}

/// [`with_control`] with icons, as (NACP language name, image) pairs.
pub fn with_control_icons(
    fk: &FixtureKeys,
    nsp: &[u8],
    title_id: u64,
    nacp: &[u8],
    icons: &[(&str, Vec<u8>)],
) -> Vec<u8> {
    let Ok(pfs) = pfs0::Pfs0::open(std::sync::Arc::new(crate::storage::MemStorage(
        nsp.to_vec(),
    ))) else {
        return Vec::new();
    };
    let mut files: Vec<(String, Vec<u8>)> = pfs
        .entries()
        .iter()
        .map(|e| (e.name.clone(), pfs.read(e).unwrap_or_default()))
        .collect();
    let control = control_nca_with(fk, title_id, nacp, icons);
    files.insert(
        1,
        (
            format!("{}.nca", crate::hex(&sha256(&control)[..16])),
            control,
        ),
    );
    let list: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    pfs0::build(&list)
}

/// A small NSO with the given module path in .rodata, two dynamic symbols
/// and a MOD0, compressed with LZ4.
pub fn nso(module_path: &str, build_id: u8) -> Vec<u8> {
    let mut text = vec![0u8; 0x200];
    text[4..8].copy_from_slice(&0x10u32.to_le_bytes());
    text[0x10..0x14].copy_from_slice(b"MOD0");
    let mut rodata = Vec::new();
    rodata.extend_from_slice(&0u32.to_le_bytes());
    rodata.extend_from_slice(&u32::try_from(module_path.len()).unwrap_or(0).to_le_bytes());
    rodata.extend_from_slice(module_path.as_bytes());
    pad(&mut rodata, 0x10);
    let dynstr_at = rodata.len();
    let dynstr = b"\0nnMain\0nnImported\0";
    rodata.extend_from_slice(dynstr);
    pad(&mut rodata, 0x10);
    let dynsym_at = rodata.len();
    let mut sym = vec![0u8; 24 * 3];
    sym[24..28].copy_from_slice(&1u32.to_le_bytes());
    sym[28] = 0x12;
    sym[30..32].copy_from_slice(&1u16.to_le_bytes());
    sym[32..40].copy_from_slice(&0x100u64.to_le_bytes());
    sym[40..48].copy_from_slice(&8u64.to_le_bytes());
    sym[48..52].copy_from_slice(&8u32.to_le_bytes());
    sym[52] = 0x12;
    rodata.extend_from_slice(&sym);
    rodata.extend_from_slice(&[0x5a; 0x300]);
    let data = vec![0x11u8; 0x180];
    let text_pages = u32::try_from(text.len().div_ceil(0x1000) * 0x1000).unwrap_or(0);
    let ro_pages = u32::try_from(rodata.len().div_ceil(0x1000) * 0x1000).unwrap_or(0);
    let data_at = i64::from(text_pages + ro_pages);
    let dyn_rel = i32::try_from(data_at - 0x10).unwrap_or(0);
    text[0x14..0x18].copy_from_slice(&dyn_rel.to_le_bytes());
    let bss_rel = i32::try_from(data_at + 0x180 - 0x10).unwrap_or(0);
    text[0x18..0x1C].copy_from_slice(&bss_rel.to_le_bytes());
    text[0x1C..0x20].copy_from_slice(&(bss_rel + 0x40).to_le_bytes());
    crate::nso::build(&crate::nso::NsoSpec {
        text,
        rodata,
        data,
        bss: 0x40,
        build_id: [build_id; 32],
        dyn_extents: [
            (
                u32::try_from(dynstr_at).unwrap_or(0),
                u32::try_from(dynstr.len()).unwrap_or(0),
            ),
            (u32::try_from(dynsym_at).unwrap_or(0), 24 * 3),
        ],
        compress: true,
    })
}

/// A ready-made base plus update pair.
pub struct Game {
    /// The keys.
    pub keys: FixtureKeys,
    /// The base NSP bytes.
    pub base: Vec<u8>,
    /// The update NSP bytes.
    pub update: Vec<u8>,
    /// The base program spec.
    pub base_spec: ProgramSpec,
    /// The update program spec (its romfs is the expected patched tree).
    pub update_spec: ProgramSpec,
}

/// A base game with a title-key-encrypted program, and an update that
/// changes one NSO, edits, adds and keeps romfs files.
pub fn game() -> Game {
    let fk = keys(1);
    let pid = 0x0100_1234_5678_0000u64;
    let big: Vec<u8> = (0..0x5000u32).map(|i| (i * 7 % 251) as u8).collect();
    let base_spec = ProgramSpec {
        program_id: pid,
        exefs: vec![
            (
                "main".into(),
                nso("D:\\work\\game\\out\\game-main.nss", 0xA1),
            ),
            (
                "main.npdm".into(),
                crate::npdm::build(
                    "Application",
                    pid,
                    0x10_0000,
                    &[("fsp-srv", false), ("sm:", false)],
                ),
            ),
            ("sdk".into(), nso("nnSdk", 0xA2)),
        ],
        romfs: vec![
            ("data/big.bin".into(), big.clone()),
            ("data/keep.txt".into(), b"kept".to_vec()),
            ("readme.txt".into(), b"version 0".to_vec()),
        ],
        rights_id: Some([
            0x01, 0x00, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        content_key: seeded(0x42),
    };
    let mut big2 = big;
    big2[0x2100] ^= 0xFF;
    let mut update_spec = base_spec.clone();
    update_spec.program_id = pid | 0x800;
    update_spec.rights_id = Some([
        0x01, 0x00, 0x12, 0x34, 0x56, 0x78, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    update_spec.content_key = seeded(0x43);
    update_spec.exefs[0].1 = nso("D:\\work\\game\\out\\game-main.nss", 0xB1);
    update_spec.romfs = vec![
        ("data/big.bin".into(), big2),
        ("data/keep.txt".into(), b"kept".to_vec()),
        ("data/new/added.bin".into(), vec![9u8; 0x1234]),
        ("readme.txt".into(), b"version 1".to_vec()),
    ];
    let (base_nca, base_romfs) = program_nca(&fk, &base_spec);
    let base_meta = meta_nca(&fk, pid, 0, 0x80, &base_nca);
    let base = nsp(&fk, &base_spec, &base_nca, &base_meta);
    let upd_nca = update_nca(&fk, &update_spec, &base_romfs);
    let upd_meta = meta_nca(&fk, pid | 0x800, 0x10000, 0x81, &upd_nca);
    let update = nsp(&fk, &update_spec, &upd_nca, &upd_meta);
    Game {
        keys: fk,
        base,
        update,
        base_spec,
        update_spec,
    }
}
