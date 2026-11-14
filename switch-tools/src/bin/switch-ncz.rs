//! `switch-ncz`: inspect and restore NCZ files (compressed NCAs).

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde_json::json;
use switch_formats::ncz::{Compression, Ncz};
use switch_formats::{hex, unhex};
use switch_io::StreamWriter;
use switch_tools::{BoxError, input, print_json, run};

/// Inspect and restore NCZ files.
#[derive(Parser, Debug)]
#[command(name = "switch-ncz", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Describe an NCZ: its sections and compression layout.
    Show {
        /// The NCZ file, or - for stdin.
        input: PathBuf,
        /// Print JSON (the only format; accepted for scripts).
        #[arg(long)]
        json: bool,
    },
    /// Restore the original NCA.
    Decompress {
        /// The NCZ file, or - for stdin.
        input: PathBuf,
        /// The NCA to write.
        #[arg(short, long)]
        output: PathBuf,
        /// Fail, and leave the output alone, unless the restored NCA has
        /// this SHA-256 (64 hex digits).
        #[arg(long, value_name = "HEX")]
        expect_sha256: Option<String>,
    },
}

fn main() -> ExitCode {
    run::<Cli>("switch-ncz", |_settings, cli| match cli.command {
        Command::Show { input: path, .. } => show(&path),
        Command::Decompress {
            input: path,
            output,
            expect_sha256,
        } => decompress(&path, &output, expect_sha256.as_deref()),
    })
}

fn show(path: &std::path::Path) -> Result<(), BoxError> {
    let z = Ncz::open(input(path)?)?;
    let sections: Vec<_> = z
        .sections
        .iter()
        .map(|s| {
            json!({
                "offset": s.offset,
                "size": s.size,
                "crypto_type": s.crypto_type,
                "encrypted": s.is_encrypted(),
            })
        })
        .collect();
    let compression = match &z.compression {
        Compression::Solid => json!({ "layout": "solid" }),
        Compression::Blocks(h) => json!({
            "layout": "blocks",
            "version": h.version,
            "block_size": h.block_size(),
            "blocks": h.compressed_sizes.len(),
            "decompressed_size": h.decompressed_size,
        }),
    };
    print_json(&json!({
        "nca_size": z.nca_size(),
        "data_offset": z.data_offset,
        "sections": sections,
        "compression": compression,
    }))
}

fn decompress(
    path: &std::path::Path,
    output: &std::path::Path,
    expect: Option<&str>,
) -> Result<(), BoxError> {
    let want: Option<[u8; 32]> = match expect {
        Some(h) => Some(unhex(h).ok_or("--expect-sha256 wants 64 hex digits")?),
        None => None,
    };
    let z = Ncz::open(input(path)?)?;
    if let Some(dir) = output.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let mut w = StreamWriter::new(output)?;
    // An error here drops the writer, which leaves the target untouched.
    let hash = z.to_nca(&mut w as &mut dyn Write, want.as_ref())?;
    w.finish()?;
    eprintln!("{} sha256 {}", output.display(), hex(&hash));
    Ok(())
}
