//! `switch-nsp`: list, extract and print the files of an NSP (any PFS0).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde_json::json;
use switch_formats::pfs0::Pfs0;
use switch_tools::{BoxError, input, print_json, run, write_storage};

/// Work with the files inside an NSP, or any PFS0 such as an extracted
/// exefs.
#[derive(Parser, Debug)]
#[command(name = "switch-nsp", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// List the files: name, offset, size.
    Ls {
        /// The NSP, or - for stdin.
        nsp: PathBuf,
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write files into a directory.
    Extract {
        /// The NSP, or - for stdin.
        nsp: PathBuf,
        /// The output directory.
        #[arg(short, long)]
        output: PathBuf,
        /// Only these files (default: all).
        names: Vec<String>,
    },
    /// Write one file to stdout.
    Cat {
        /// The NSP, or - for stdin.
        nsp: PathBuf,
        /// The file name.
        name: String,
    },
}

fn main() -> ExitCode {
    run::<Cli>("switch-nsp", |_settings, cli| match cli.command {
        Command::Ls { nsp, json } => ls(&nsp, json),
        Command::Extract { nsp, output, names } => extract(&nsp, &output, &names),
        Command::Cat { nsp, name } => cat(&nsp, &name),
    })
}

fn open(path: &Path) -> Result<Pfs0, BoxError> {
    Ok(Pfs0::open(input(path)?)?)
}

fn ls(path: &Path, as_json: bool) -> Result<(), BoxError> {
    let pfs = open(path)?;
    if as_json {
        let list: Vec<_> = pfs
            .entries()
            .iter()
            .map(|e| json!({ "name": e.name, "offset": e.offset, "size": e.size }))
            .collect();
        return print_json(&json!(list));
    }
    let mut w = std::io::stdout().lock();
    for e in pfs.entries() {
        writeln!(w, "{}\t{:#x}\t{}", e.name, e.offset, e.size)?;
    }
    Ok(())
}

fn extract(path: &Path, dir: &Path, names: &[String]) -> Result<(), BoxError> {
    let pfs = open(path)?;
    for n in names {
        if pfs.find(n).is_none() {
            return Err(format!("{n}: no such file in the archive").into());
        }
    }
    for e in pfs.entries() {
        if names.is_empty() || names.contains(&e.name) {
            if e.name.contains('/') || e.name.contains('\\') || e.name.starts_with('.') {
                return Err(format!("{:?}: unsafe file name", e.name).into());
            }
            write_storage(&dir.join(&e.name), &*pfs.open_entry(e)?)?;
        }
    }
    Ok(())
}

fn cat(path: &Path, name: &str) -> Result<(), BoxError> {
    let pfs = open(path)?;
    let e = pfs
        .find(name)
        .ok_or_else(|| format!("{name}: no such file in the archive"))?;
    let s: switch_formats::storage::Shared = pfs.open_entry(e)?;
    write_storage(Path::new("-"), &*s)
}
