//! Personalized tickets: a synthetic NSP whose ticket is RSA-OAEP wrapped
//! to a test-only eTicket key, unwrapped from a raw key pair, from a
//! synthetic PRODINFO with `eticket_rsa_kek`, or from `eticket_rsa_keypair`
//! in the key file; and the errors for a missing or another console's key.

use std::sync::Arc;

use switch_formats::Error;
use switch_formats::eticket::EticketKey;
use switch_formats::keys::Keys;
use switch_formats::storage::MemStorage;
use switch_formats::synth;
use switch_formats::title::{Nsp, open_title};

const KEK: [u8; 16] = [0x3c; 16];

fn nsp(bytes: &[u8]) -> Nsp {
    Nsp::from_storage(Arc::new(MemStorage(bytes.to_vec()))).expect("nsp opens")
}

fn with_key(keys: &Keys, key: EticketKey) -> Keys {
    let mut k = keys.clone();
    k.set_eticket_key(key);
    k
}

fn opens(keys: &Keys, base: &[u8], spec: &synth::ProgramSpec) {
    let mut n = nsp(base);
    assert_eq!(n.personalized().len(), 1);
    n.unlock_personalized(keys).expect("unlocks");
    assert!(n.personalized().is_empty());
    let t = open_title(keys, &n, None).expect("title opens");
    let romfs = t.romfs.expect("romfs");
    let mut got: Vec<(String, Vec<u8>)> = romfs
        .files()
        .iter()
        .map(|f| {
            let mut v = Vec::new();
            romfs.copy_file(f, &mut v).expect("reads");
            (f.path.clone(), v)
        })
        .collect();
    got.sort();
    let mut want = spec.romfs.clone();
    want.sort();
    assert_eq!(got, want);
}

#[test]
fn a_raw_keypair_unwraps_the_ticket() {
    let pair = synth::eticket_keypair(1);
    let (fk, base, spec) = synth::personalized_base(&pair);
    let keys = with_key(&fk.keys, EticketKey::from_keypair(&pair).expect("pair"));
    opens(&keys, &base, &spec);
}

#[test]
fn prodinfo_and_the_kek_give_the_key() {
    let pair = synth::eticket_keypair(1);
    let (fk, base, spec) = synth::personalized_base(&pair);
    let mut keys = fk.keys.clone();
    keys.insert("eticket_rsa_kek", &KEK);
    let key = EticketKey::from_prodinfo(&synth::prodinfo(&KEK, &pair), &keys).expect("derives");
    assert_eq!(key.modulus(), pair[0x100..0x200]);
    opens(&with_key(&keys, key), &base, &spec);
}

#[test]
fn the_personalized_kek_name_is_tried_too() {
    let pair = synth::eticket_keypair(1);
    let mut keys = Keys::default();
    keys.insert("eticket_rsa_kek", &[0x11; 16]);
    keys.insert("eticket_rsa_kek_personalized", &KEK);
    EticketKey::from_prodinfo(&synth::prodinfo(&KEK, &pair), &keys).expect("derives");
}

#[test]
fn the_key_file_can_hold_the_keypair() {
    let pair = synth::eticket_keypair(1);
    let (fk, base, spec) = synth::personalized_base(&pair);
    let text = format!(
        "{}eticket_rsa_keypair = {}\n",
        fk.text,
        switch_formats::hex(&pair)
    );
    let keys = Keys::parse(&text).expect("parses");
    assert!(keys.eticket_key().is_some());
    opens(&keys, &base, &spec);
}

#[test]
fn no_eticket_key_names_the_settings() {
    let pair = synth::eticket_keypair(1);
    let (fk, base, _) = synth::personalized_base(&pair);
    let mut n = nsp(&base);
    n.unlock_personalized(&fk.keys).expect("no key, no work");
    let err = open_title(&fk.keys, &n, None).err().expect("fails");
    assert!(matches!(err, Error::MissingKey(_)), "{err}");
    let msg = err.to_string();
    for needle in [
        "personalized",
        "prodinfo",
        "eticket-rsa-keypair",
        "eticket_rsa_kek",
    ] {
        assert!(msg.contains(needle), "{msg}");
    }
}

#[test]
fn another_consoles_key_is_a_wrong_key() {
    let pair = synth::eticket_keypair(1);
    let other = synth::eticket_keypair(2);
    assert_ne!(pair, other);
    let (fk, base, _) = synth::personalized_base(&pair);
    let keys = with_key(&fk.keys, EticketKey::from_keypair(&other).expect("pair"));
    let err = nsp(&base).unlock_personalized(&keys).expect_err("fails");
    assert!(matches!(err, Error::WrongKey(_)), "{err}");
    assert!(err.to_string().contains("another console"), "{err}");
}

#[test]
fn prodinfo_errors_name_what_is_wrong() {
    let pair = synth::eticket_keypair(1);
    let cal = synth::prodinfo(&KEK, &pair);
    let none = EticketKey::from_prodinfo(&cal, &Keys::default()).expect_err("no kek");
    assert!(matches!(none, Error::MissingKey(_)), "{none}");
    assert!(none.to_string().contains("eticket_rsa_kek"), "{none}");

    let mut wrong = Keys::default();
    wrong.insert("eticket_rsa_kek", &[0x11; 16]);
    let err = EticketKey::from_prodinfo(&cal, &wrong).expect_err("wrong kek");
    assert!(matches!(err, Error::WrongKey(_)), "{err}");

    let mut keys = Keys::default();
    keys.insert("eticket_rsa_kek", &KEK);
    let mut bad = cal.clone();
    bad[0x100] ^= 1;
    let err = EticketKey::from_prodinfo(&bad, &keys).expect_err("hash");
    assert!(matches!(err, Error::Hash(_)), "{err}");
    let err = EticketKey::from_prodinfo(&cal[..0x1000], &keys).expect_err("short");
    assert!(matches!(err, Error::Format(_)), "{err}");
    let mut encrypted = cal;
    encrypted[..4].copy_from_slice(b"XXXX");
    let err = EticketKey::from_prodinfo(&encrypted, &keys).expect_err("magic");
    assert!(err.to_string().contains("decrypted PRODINFO"), "{err}");
}

#[test]
fn a_bad_keypair_is_refused() {
    let mut pair = synth::eticket_keypair(1);
    assert!(EticketKey::from_keypair(&pair[..0x100]).is_err());
    pair[0x203] = 3;
    let err = EticketKey::from_keypair(&pair).expect_err("exponent");
    assert!(matches!(err, Error::WrongKey(_)), "{err}");
}

#[test]
fn debug_never_shows_the_key() {
    let pair = synth::eticket_keypair(1);
    let keys = Keys::parse(&format!(
        "eticket_rsa_keypair = {}\n",
        switch_formats::hex(&pair)
    ))
    .expect("parses");
    let shown = format!("{keys:?} {:?}", keys.eticket_key());
    assert!(!shown.contains(&switch_formats::hex(&pair[..8])), "{shown}");
}
