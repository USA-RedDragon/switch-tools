//! `switch-nca`: show an NCA's header and extract its verified sections.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use serde_json::json;
use switch_formats::hex;
use switch_formats::integrity::{IvfcInfo, open_ivfc};
use switch_formats::nca::{Encryption, HashType, Nca};
use switch_formats::title::open_pfs0_section;
use switch_tools::{BoxError, TitleKeyArgs, ToolSettings, input, print_json, run, write_storage};

/// Show an NCA header and extract its sections, verified. Keys come from
/// --keys (or SWITCH_TOOLS_KEYS, or switch-tools.toml); a title key from --ticket or
/// --titlekey.
#[derive(Parser, Debug)]
#[command(name = "switch-nca", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Debug)]
struct Source {
    /// The NCA, or - for stdin.
    nca: PathBuf,
    #[command(flatten)]
    title_keys: TitleKeyArgs,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print the header: content type, IDs, key generation, sections.
    Show {
        #[command(flatten)]
        source: Source,
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write a section: files into a directory for a PFS0 section, a
    /// verified image file for a romfs section.
    Extract {
        #[command(flatten)]
        source: Source,
        /// The section: 0-3, exefs (0) or romfs (1).
        #[arg(long, value_name = "N|exefs|romfs")]
        section: String,
        /// The output directory (PFS0) or file (romfs, or --raw).
        #[arg(short, long)]
        output: PathBuf,
        /// Write the decrypted raw section, hash levels included, without
        /// verifying it.
        #[arg(long)]
        raw: bool,
    },
}

fn main() -> ExitCode {
    run::<Cli>("switch-nca", |settings, cli| match cli.command {
        Command::Show { source, json } => show(&settings, &source, json),
        Command::Extract {
            source,
            section,
            output,
            raw,
        } => extract(&settings, &source, &section, &output, raw),
    })
}

fn open(
    settings: &ToolSettings,
    source: &Source,
) -> Result<
    (
        Nca,
        switch_formats::keys::Keys,
        switch_formats::keys::TitleKeys,
    ),
    BoxError,
> {
    let keys = settings.load_keys()?;
    let tk = source.title_keys.load(settings)?;
    let nca = Nca::open(input(&source.nca)?, &keys, &tk)?;
    Ok((nca, keys, tk))
}

fn hash_name(h: Result<HashType, switch_formats::Error>) -> &'static str {
    match h {
        Ok(HashType::None) => "none",
        Ok(HashType::HierarchicalSha256) => "sha256",
        Ok(HashType::Ivfc) => "ivfc",
        Err(_) => "unknown",
    }
}

fn enc_name(e: Result<Encryption, switch_formats::Error>) -> &'static str {
    match e {
        Ok(Encryption::None) => "none",
        Ok(Encryption::Xts) => "xts",
        Ok(Encryption::Ctr) => "ctr",
        Ok(Encryption::CtrEx) => "ctr-ex",
        Err(_) => "unknown",
    }
}

fn show(settings: &ToolSettings, source: &Source, as_json: bool) -> Result<(), BoxError> {
    let (nca, keys, tk) = open(settings, source)?;
    let h = nca.header();
    let sections: Vec<_> = (0..4)
        .filter_map(|i| {
            let (offset, size) = h.section(i)?;
            let fs = h.fs_header(i);
            Some(json!({
                "index": i,
                "offset": offset,
                "size": size,
                "format": if fs.format_type() == 0 { "romfs" } else { "pfs0" },
                "hash": hash_name(fs.hash_type()),
                "encryption": enc_name(fs.encryption()),
            }))
        })
        .collect();
    let rights = h.rights_id().map(|r| hex(&r));
    let v = json!({
        "content_type": h.content_type().name(),
        "program_id": format!("{:016x}", h.program_id()),
        "content_index": h.content_index(),
        "size": h.nca_size(),
        "key_generation": h.key_generation(),
        "master_key_revision": h.master_key_revision(),
        "rights_id": rights,
        "sdk_version": format!("{}.{}.{}.{}", h.sdk_version() >> 24, (h.sdk_version() >> 16) & 0xff, (h.sdk_version() >> 8) & 0xff, h.sdk_version() & 0xff),
        "content_key_resolves": nca.key(&keys, &tk).is_ok(),
        "sections": sections,
    });
    if as_json {
        return print_json(&v);
    }
    let mut w = std::io::stdout().lock();
    for k in [
        "content_type",
        "program_id",
        "content_index",
        "size",
        "key_generation",
        "master_key_revision",
        "rights_id",
        "sdk_version",
        "content_key_resolves",
    ] {
        writeln!(
            w,
            "{k}: {}",
            v[k].as_str()
                .map_or_else(|| v[k].to_string(), str::to_string)
        )?;
    }
    for s in &sections {
        writeln!(
            w,
            "section {}: offset {:#x} size {:#x} {} hash={} encryption={}",
            s["index"],
            s["offset"].as_u64().unwrap_or(0),
            s["size"].as_u64().unwrap_or(0),
            s["format"].as_str().unwrap_or(""),
            s["hash"].as_str().unwrap_or(""),
            s["encryption"].as_str().unwrap_or("")
        )?;
    }
    Ok(())
}

fn section_index(s: &str) -> Result<usize, BoxError> {
    match s {
        "exefs" => Ok(0),
        "romfs" => Ok(1),
        n => match n.parse::<usize>() {
            Ok(i) if i < 4 => Ok(i),
            _ => Err(format!("--section {n:?}: want 0-3, exefs or romfs").into()),
        },
    }
}

fn extract(
    settings: &ToolSettings,
    source: &Source,
    section: &str,
    output: &Path,
    raw: bool,
) -> Result<(), BoxError> {
    let i = section_index(section)?;
    let (nca, keys, tk) = open(settings, source)?;
    if nca.header().section(i).is_none() {
        return Err(format!("the NCA has no section {i}").into());
    }
    if raw {
        return write_storage(output, &*nca.section_raw(i, &keys, &tk)?);
    }
    let fs = nca.header().fs_header(i);
    match fs.hash_type()? {
        HashType::HierarchicalSha256 => {
            let pfs = open_pfs0_section(&nca, i, &keys, &tk)?;
            for e in pfs.entries() {
                if e.name.contains(['/', '\\']) || e.name.starts_with('.') {
                    return Err(format!("{:?}: unsafe file name", e.name).into());
                }
                write_storage(&output.join(&e.name), &*pfs.open_entry(e)?)?;
            }
            Ok(())
        }
        HashType::Ivfc => {
            if fs.encryption()? == Encryption::CtrEx {
                return Err(
                    "section is a BKTR patch: apply it over its base with switch-bktr".into(),
                );
            }
            let raw = nca.section_raw(i, &keys, &tk)?;
            let data = open_ivfc(raw, &IvfcInfo::parse(&fs)?, "romfs")?;
            write_storage(output, &*data)
        }
        HashType::None => Err("section is not hashed: use --raw".into()),
    }
}
