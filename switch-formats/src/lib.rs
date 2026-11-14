//! Switch container and executable formats: NSP, NSZ, XCI, NCA, NCZ, BKTR,
//! romfs, NSO, NRO, NPDM, NUP, tickets and keys.
//!
//! Readers layer [`storage::Storage`] values: a file, an NCA section
//! decrypted with AES-CTR, a BKTR patch stitched over its base, and a
//! hash-verified view on top, so a 4 GiB romfs streams without being held in
//! memory. Every format module also has a small builder used by the tests to
//! make synthetic fixtures; no game data is needed to test any of it.

mod bytes;

pub mod bktr;
pub mod cnmt;
pub mod crypto;
pub mod error;
pub mod export;
pub mod hfs0;
pub mod integrity;
pub mod keys;
pub mod nacp;
pub mod nca;
pub mod ncz;
pub mod npdm;
pub mod nso;
pub mod nup;
pub mod nup_writer;
pub mod pfs0;
pub mod romfs;
pub mod storage;
pub mod synth;
pub mod ticket;
pub mod title;
pub mod xci;

pub use bytes::{hex, unhex};
pub use error::{Error, Result};
