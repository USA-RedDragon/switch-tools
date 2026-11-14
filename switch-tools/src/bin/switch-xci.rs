//! `switch-xci`: show, list and extract the contents of an XCI game card
//! image.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde_json::json;
use switch_formats::hex;
use switch_formats::hfs0::Hfs0;
use switch_formats::storage::read_vec;
use switch_formats::xci::Xci;
use switch_tools::{BoxError, input, print_json, run};

/// Inspect an XCI game card image.
#[derive(Parser, Debug)]
#[command(name = "switch-xci", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print the card header and the partitions.
    Show {
        /// The XCI file, or - for stdin.
        input: PathBuf,
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// List the partitions and their files with sizes.
    Ls {
        /// The XCI file, or - for stdin.
        input: PathBuf,
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write each file of one partition into a directory.
    Extract {
        /// The XCI file, or - for stdin.
        input: PathBuf,
        /// The partition: update, normal, secure or logo.
        partition: String,
        /// The directory to write into.
        #[arg(short, long)]
        output: PathBuf,
    },
}

fn main() -> ExitCode {
    run::<Cli>("switch-xci", |_settings, cli| match cli.command {
        Command::Show { input: i, json } => show(&i, json),
        Command::Ls { input: i, json } => ls(&i, json),
        Command::Extract {
            input: i,
            partition,
            output,
        } => extract(&i, &partition, &output),
    })
}

fn open(path: &Path) -> Result<Xci, BoxError> {
    Ok(Xci::open(input(path)?)?)
}

fn show(path: &Path, as_json: bool) -> Result<(), BoxError> {
    let x = open(path)?;
    let h = x.header();
    let parts: Vec<_> = x
        .partitions()
        .iter()
        .map(|p| json!({ "name": p.name, "size": p.size }))
        .collect();
    let value = json!({
        "key_area_prefix": x.key_area().is_some(),
        "trimmed": x.trimmed(),
        "rom_area_start_page": h.rom_area_start_page,
        "backup_area_start_page": h.backup_area_start_page,
        "key_index": h.key_index,
        "rom_size": h.rom_size,
        "rom_size_name": h.declared_size_name(),
        "header_version": h.header_version,
        "flags": h.flags,
        "package_id": format!("{:016x}", h.package_id),
        "valid_data_end_page": h.valid_data_end_page,
        "iv": hex(&h.iv),
        "root_offset": h.root_offset,
        "root_header_size": h.root_header_size,
        "root_header_hash": hex(&h.root_header_hash),
        "initial_data_hash": hex(&h.initial_data_hash),
        "sel_sec": h.sel_sec,
        "sel_t1_key": h.sel_t1_key,
        "sel_key": h.sel_key,
        "lim_area_page": h.lim_area_page,
        "partitions": parts,
    });
    if as_json {
        return print_json(&value);
    }
    let mut out = std::io::stdout().lock();
    if let Some(obj) = value.as_object() {
        for (k, v) in obj.iter().filter(|(k, _)| *k != "partitions") {
            let v = v.as_str().map_or_else(|| v.to_string(), str::to_string);
            writeln!(out, "{k}: {v}")?;
        }
    }
    for p in x.partitions() {
        writeln!(out, "partition {}: {} bytes", p.name, p.size)?;
    }
    Ok(())
}

fn ls(path: &Path, as_json: bool) -> Result<(), BoxError> {
    let x = open(path)?;
    let mut parts = Vec::new();
    for p in x.partitions() {
        let h = x.partition(&p.name)?;
        let files: Vec<_> = h
            .entries()
            .iter()
            .map(|e| json!({ "name": e.name, "size": e.size }))
            .collect();
        parts.push(json!({ "name": p.name, "size": p.size, "files": files }));
    }
    if as_json {
        return print_json(&json!({ "partitions": parts }));
    }
    let mut out = std::io::stdout().lock();
    for p in x.partitions() {
        writeln!(out, "{}/", p.name)?;
        for e in x.partition(&p.name)?.entries() {
            writeln!(out, "  {}  {}", e.size, e.name)?;
        }
    }
    Ok(())
}

fn extract(path: &Path, partition: &str, dir: &Path) -> Result<(), BoxError> {
    let x = open(path)?;
    let h: Hfs0 = x.partition(partition)?;
    std::fs::create_dir_all(dir)?;
    for e in h.entries() {
        if e.name.is_empty() || e.name.contains(['/', '\\']) || e.name.starts_with('.') {
            return Err(format!("refusing the file name {:?}", e.name).into());
        }
        let data = h.open_entry(e)?;
        let mut w = switch_io::StreamWriter::new(&dir.join(&e.name))?;
        let mut at = 0u64;
        while at < data.size() {
            let n = (data.size() - at).min(1 << 20);
            w.write_all(&read_vec(&*data, at, n)?)?;
            at += n;
        }
        w.finish()?;
    }
    Ok(())
}
