//! `switch-bktr`: apply an update NCA's BKTR patch over its base NCA and
//! write the verified romfs image.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use switch_formats::nca::Nca;
use switch_formats::title::open_romfs_storage;
use switch_tools::{input, run, title_keys, write_storage};

/// Apply a BKTR patch: write the patched, IVFC-verified romfs image. Keys
/// come from --keys (or SWITCH_TOOLS_KEYS, or switch-tools.toml).
#[derive(Parser, Debug)]
#[command(name = "switch-bktr", version)]
enum Cli {
    /// Patch the base romfs with the update's and write the image.
    Apply {
        /// The base program NCA, or - for stdin.
        #[arg(long, value_name = "NCA")]
        base: PathBuf,
        /// The update program NCA, or - for stdin.
        #[arg(long, value_name = "NCA")]
        update: PathBuf,
        /// A common ticket for the base; repeatable.
        #[arg(long, value_name = "FILE")]
        base_ticket: Vec<PathBuf>,
        /// A base title key as RIGHTSID=KEY in hex; repeatable.
        #[arg(long, value_name = "RIGHTSID=KEY")]
        base_titlekey: Vec<String>,
        /// A common ticket for the update; repeatable.
        #[arg(long, value_name = "FILE")]
        update_ticket: Vec<PathBuf>,
        /// An update title key as RIGHTSID=KEY in hex; repeatable.
        #[arg(long, value_name = "RIGHTSID=KEY")]
        update_titlekey: Vec<String>,
        /// The romfs image to write, or - for stdout.
        #[arg(short, long)]
        output: PathBuf,
    },
}

fn main() -> ExitCode {
    run::<Cli>("switch-bktr", |settings, cli| {
        let Cli::Apply {
            base,
            update,
            base_ticket,
            base_titlekey,
            update_ticket,
            update_titlekey,
            output,
        } = cli;
        let keys = settings.load_keys()?;
        let file_tk = settings.load_title_keys()?;
        let mut base_tk = file_tk.clone();
        base_tk.extend(&title_keys(&keys, &base_ticket, &base_titlekey)?);
        let mut update_tk = file_tk;
        update_tk.extend(&title_keys(&keys, &update_ticket, &update_titlekey)?);
        let base_nca =
            Nca::open(input(&base)?, &keys, &base_tk).map_err(|e| format!("base: {e}"))?;
        let update_nca =
            Nca::open(input(&update)?, &keys, &update_tk).map_err(|e| format!("update: {e}"))?;
        let image = open_romfs_storage(
            Some((&base_nca, &base_tk)),
            Some((&update_nca, &update_tk)),
            &keys,
        )?
        .ok_or("the update NCA has no romfs section")?;
        write_storage(&output, &*image)
    })
}
