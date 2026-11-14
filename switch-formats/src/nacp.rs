//! NACP, the application control property (`control.nacp` in a control
//! NCA's romfs): per-language titles and publishers, and the display
//! version. Only the fields the exporter carries into NUP meta are read.

use crate::error::{Result, malformed};

/// The size of a NACP.
pub const SIZE: usize = 0x4000;

const TITLE_SIZE: usize = 0x300;
const NAME_SIZE: usize = 0x200;
const PUBLISHER_SIZE: usize = 0x100;
const DISPLAY_VERSION_AT: usize = 0x3060;
const DISPLAY_VERSION_SIZE: usize = 0x10;

/// The 16 title languages in NACP order, as (icon file language, BCP-47
/// tag) pairs; the icon of language `l` is `icon_<l>.dat`.
pub const LANGUAGES: [(&str, &str); 16] = [
    ("AmericanEnglish", "en-us"),
    ("BritishEnglish", "en-gb"),
    ("Japanese", "ja"),
    ("French", "fr"),
    ("German", "de"),
    ("LatinAmericanSpanish", "es-419"),
    ("Spanish", "es"),
    ("Italian", "it"),
    ("Dutch", "nl"),
    ("CanadianFrench", "fr-ca"),
    ("Portuguese", "pt"),
    ("Russian", "ru"),
    ("Korean", "ko"),
    ("TraditionalChinese", "zh-hant"),
    ("SimplifiedChinese", "zh-hans"),
    ("BrazilianPortuguese", "pt-br"),
];

/// One language's title entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Title {
    /// The title name; empty when the language is unused.
    pub name: String,
    /// The publisher.
    pub publisher: String,
}

/// The fields of a NACP the exporter uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nacp {
    /// The 16 title entries in [`LANGUAGES`] order.
    pub titles: Vec<Title>,
    /// The display version, such as `1.0.2`.
    pub display_version: String,
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

impl Nacp {
    /// Parse a NACP.
    ///
    /// # Errors
    ///
    /// The file is shorter than the fields read.
    pub fn parse(b: &[u8]) -> Result<Nacp> {
        if b.len() < DISPLAY_VERSION_AT + DISPLAY_VERSION_SIZE {
            return malformed(format!("NACP: {:#x} bytes is too short", b.len()));
        }
        let titles = (0..LANGUAGES.len())
            .map(|i| {
                let t = &b[i * TITLE_SIZE..(i + 1) * TITLE_SIZE];
                Title {
                    name: cstr(&t[..NAME_SIZE]),
                    publisher: cstr(&t[NAME_SIZE..NAME_SIZE + PUBLISHER_SIZE]),
                }
            })
            .collect();
        Ok(Nacp {
            titles,
            display_version: cstr(
                &b[DISPLAY_VERSION_AT..DISPLAY_VERSION_AT + DISPLAY_VERSION_SIZE],
            ),
        })
    }

    /// The index of the default language: the first with a name.
    pub fn default_language(&self) -> Option<usize> {
        self.titles.iter().position(|t| !t.name.is_empty())
    }
}

/// Build a NACP (fixtures): `titles` as (language index, name, publisher).
pub fn build(titles: &[(usize, &str, &str)], display_version: &str) -> Vec<u8> {
    let mut b = vec![0u8; SIZE];
    for (i, name, publisher) in titles {
        let at = i * TITLE_SIZE;
        let n = name.len().min(NAME_SIZE - 1);
        b[at..at + n].copy_from_slice(&name.as_bytes()[..n]);
        let p = publisher.len().min(PUBLISHER_SIZE - 1);
        b[at + NAME_SIZE..at + NAME_SIZE + p].copy_from_slice(&publisher.as_bytes()[..p]);
    }
    let v = display_version.len().min(DISPLAY_VERSION_SIZE - 1);
    b[DISPLAY_VERSION_AT..DISPLAY_VERSION_AT + v].copy_from_slice(&display_version.as_bytes()[..v]);
    b
}
