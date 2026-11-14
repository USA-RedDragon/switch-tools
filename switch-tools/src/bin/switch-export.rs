//! `switch-export`: decrypt your own dump (a base NSP, NSZ, XCI or XCZ, its
//! updates and its DLC) with your own keys into a decrypted tree in the NUP
//! packer's layout, or straight into a `.nup`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{ArgGroup, Parser};
use switch_formats::export;
use switch_formats::nup_writer::DEFAULT_LEVEL;
use switch_formats::title::{Package, open_package_path};
use switch_tools::{BoxError, TitleKeyArgs, run};

/// Export a title as a decrypted tree (base/, updates/<version>/,
/// dlc/<id>/<index>/) or as one .nup file.
#[derive(Parser, Debug)]
#[command(name = "switch-export", version)]
#[command(group(ArgGroup::new("output").required(true).multiple(true).args(["out", "nup"])))]
struct Cli {
    /// The base game: an NSP, NSZ, XCI or XCZ.
    base: PathBuf,
    /// An update package; repeatable (each version becomes its own
    /// package).
    #[arg(long = "update", value_name = "FILE")]
    updates: Vec<PathBuf>,
    /// A DLC package; repeatable. Of an add-on given twice only the newest
    /// version is kept.
    #[arg(long = "dlc", value_name = "FILE")]
    dlc: Vec<PathBuf>,
    /// Write the decrypted tree into this directory.
    #[arg(short, long, value_name = "DIR")]
    out: Option<PathBuf>,
    /// Write one .nup file (instead of, or as well as, a tree).
    #[arg(long, value_name = "FILE")]
    nup: Option<PathBuf>,
    /// The program to export from a base (and its updates) that holds
    /// several, such as a multi-title card: its program id, 16 hex digits.
    /// Without it such a base fails with the list of ids.
    #[arg(long = "title-id", value_name = "ID", value_parser = parse_id)]
    title_id: Option<u64>,
    /// The zstd level of the .nup.
    #[arg(long, default_value_t = DEFAULT_LEVEL)]
    level: i32,
    #[command(flatten)]
    title_keys: TitleKeyArgs,
}

fn parse_id(s: &str) -> Result<u64, String> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    if hex.len() != 16 {
        return Err("want 16 hex digits".into());
    }
    u64::from_str_radix(hex, 16).map_err(|_| "want 16 hex digits".to_string())
}

fn open(
    path: &Path,
    select: Option<u64>,
    keys: &switch_formats::keys::Keys,
    extra: &switch_formats::keys::TitleKeys,
) -> Result<Box<dyn Package>, BoxError> {
    let mut p = open_package_path(path)?;
    p.select_program(select);
    p.add_title_keys(extra);
    p.unlock_personalized(keys)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(p)
}

fn main() -> ExitCode {
    run::<Cli>("switch-export", |settings, cli| {
        let keys = settings.load_keys()?;
        let extra = cli.title_keys.load(&settings, &keys)?;
        let base = open(&cli.base, cli.title_id, &keys, &extra)?;
        let updates = cli
            .updates
            .iter()
            .map(|p| open(p, cli.title_id, &keys, &extra))
            .collect::<Result<Vec<_>, _>>()?;
        let dlc = cli
            .dlc
            .iter()
            .map(|p| open(p, None, &keys, &extra))
            .collect::<Result<Vec<_>, _>>()?;
        let updates: Vec<&dyn Package> = updates.iter().map(AsRef::as_ref).collect();
        let dlc: Vec<&dyn Package> = dlc.iter().map(AsRef::as_ref).collect();
        let plan = export::plan(&keys, base.as_ref(), &updates, &dlc)?;
        for p in &plan.packages {
            eprintln!(
                "{}\t{:016x}\tversion {}\t{}",
                p.kind.name(),
                p.title_id,
                p.version,
                p.dir
            );
        }
        if let Some(out) = &cli.out {
            let s = plan.write_tree(out)?;
            eprintln!(
                "{} files ({} bytes), {} written, {} stale removed",
                s.files, s.bytes, s.written, s.removed
            );
        }
        if let Some(nup) = &cli.nup {
            if let Some(dir) = nup.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir)?;
            }
            let s = plan.write_nup(nup, cli.level)?;
            eprintln!(
                "{} bytes, {} files, {} extents ({} zstd), {} content bytes",
                s.file_size, s.files, s.extents, s.compressed, s.content_bytes
            );
        }
        Ok(())
    })
}
