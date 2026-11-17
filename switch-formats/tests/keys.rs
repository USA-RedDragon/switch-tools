//! Key-area keys and title keks a key file lacks are derived from its
//! master key of that revision and the key sources, as the console derives
//! them; a stored key always wins, and without the inputs the error names
//! the stored key. Every value here is made up at test time.

use switch_formats::Error;
use switch_formats::crypto::ecb_decrypt_block;
use switch_formats::keys::{KeyAreaKind, Keys};

const MASTER: [u8; 16] = [0x11; 16];
const KEK_SEED: [u8; 16] = [0x22; 16];
const KEY_SEED: [u8; 16] = [0x33; 16];
const APP_SOURCE: [u8; 16] = [0x44; 16];
const SYSTEM_SOURCE: [u8; 16] = [0x55; 16];
const TITLEKEK_SOURCE: [u8; 16] = [0x66; 16];

fn keys_with_sources() -> Keys {
    let mut k = Keys::default();
    k.insert("master_key_0e", &MASTER);
    k.insert("aes_kek_generation_source", &KEK_SEED);
    k.insert("aes_key_generation_source", &KEY_SEED);
    k.insert("key_area_key_application_source", &APP_SOURCE);
    k.insert("key_area_key_system_source", &SYSTEM_SOURCE);
    k.insert("titlekek_source", &TITLEKEK_SOURCE);
    k
}

fn expected(source: &[u8; 16]) -> [u8; 16] {
    let kek = ecb_decrypt_block(&MASTER, &KEK_SEED);
    ecb_decrypt_block(&ecb_decrypt_block(&kek, source), &KEY_SEED)
}

#[test]
fn missing_key_area_keys_are_derived_from_the_master_key() {
    let k = keys_with_sources();
    let app = k.key_area_key(KeyAreaKind::Application, 0x0e).unwrap();
    let system = k.key_area_key(KeyAreaKind::System, 0x0e).unwrap();
    assert_eq!(app, expected(&APP_SOURCE));
    assert_eq!(system, expected(&SYSTEM_SOURCE));
    assert_ne!(app, system);
}

#[test]
fn missing_title_keks_are_derived_from_the_master_key() {
    let k = keys_with_sources();
    assert_eq!(
        k.titlekek(0x0e).unwrap(),
        ecb_decrypt_block(&MASTER, &TITLEKEK_SOURCE)
    );
}

#[test]
fn stored_keys_win_over_derivation() {
    let mut k = keys_with_sources();
    k.insert("key_area_key_application_0e", &[0x77; 16]);
    k.insert("titlekek_0e", &[0x88; 16]);
    assert_eq!(
        k.key_area_key(KeyAreaKind::Application, 0x0e).unwrap(),
        [0x77; 16]
    );
    assert_eq!(k.titlekek(0x0e).unwrap(), [0x88; 16]);
}

#[test]
fn without_the_inputs_the_error_names_the_stored_key() {
    let mut k = keys_with_sources();
    let err = k.key_area_key(KeyAreaKind::Ocean, 0x0e).unwrap_err();
    assert!(
        matches!(&err, Error::MissingKey(m) if m.contains("key_area_key_ocean_0e")),
        "{err}"
    );
    let err = k.titlekek(0x0d).unwrap_err();
    assert!(
        matches!(&err, Error::MissingKey(m) if m.contains("titlekek_0d")),
        "{err}"
    );
    k = Keys::default();
    k.insert("master_key_0e", &MASTER);
    assert!(matches!(
        k.key_area_key(KeyAreaKind::Application, 0x0e),
        Err(Error::MissingKey(_))
    ));
}
