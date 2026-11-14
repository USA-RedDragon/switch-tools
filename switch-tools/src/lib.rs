//! Shared plumbing of the single-purpose Switch format tools (`switch-nsp`,
//! `switch-nca`, ...): settings, inputs from files or stdin, outputs to
//! files or stdout, JSON and the one-line error exit. All format logic lives
//! in `switch-formats`; every binary here is a thin wrapper.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{ArgMatches, CommandFactory, FromArgMatches};
use configulator::{
    CLIFlagOptions, Config, Configulator, ConfigulatorError, EnvironmentVariableOptions,
    FileOptions, Validate, serde_loader,
};
use switch_formats::keys::{Keys, TitleKeys};
use switch_formats::storage::{FileStorage, MemStorage, Shared, Storage, read_all};
use switch_formats::ticket::Ticket;
use switch_formats::unhex;

/// The environment variable prefix of every setting.
pub const ENV_PREFIX: &str = "SWITCH_TOOLS_";

/// The config file every tool looks for in the working directory.
pub const CONFIG_FILE: &str = "switch-tools.toml";

/// Settings shared by every tool: defaults, `switch-tools.toml`,
/// `SWITCH_TOOLS_*` variables, then flags.
#[derive(Config, Debug)]
pub struct ToolSettings {
    #[configulator(
        name = "keys",
        description = "path to your console key file (prod.keys), needed by every tool that decrypts"
    )]
    pub keys: PathBuf,

    #[configulator(
        name = "title-keys",
        description = "path to a title key file (title.keys) of RIGHTSID=KEY lines, used besides the tickets inside a package and --ticket/--titlekey"
    )]
    pub title_keys: PathBuf,
}

impl Validate for ToolSettings {
    fn validate(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

impl ToolSettings {
    /// Load the key file named by `keys`.
    ///
    /// # Errors
    ///
    /// No key file was given, or it does not load.
    pub fn load_keys(&self) -> Result<Keys, BoxError> {
        if self.keys.as_os_str().is_empty() {
            return Err("no key file: pass --keys or set SWITCH_TOOLS_KEYS".into());
        }
        Ok(Keys::load(&self.keys)?)
    }

    /// Load the title key file named by `title-keys`, or none if unset.
    ///
    /// # Errors
    ///
    /// The file does not load.
    pub fn load_title_keys(&self) -> Result<TitleKeys, BoxError> {
        if self.title_keys.as_os_str().is_empty() {
            return Ok(TitleKeys::default());
        }
        Ok(TitleKeys::load(&self.title_keys)?)
    }
}

/// The error type tool bodies return.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Load settings and arguments for tool `name`, run `body`, and turn an
/// error into one line on stderr and exit code 1.
pub fn run<C: CommandFactory + FromArgMatches>(
    name: &str,
    body: impl FnOnce(ToolSettings, C) -> Result<(), BoxError>,
) -> ExitCode {
    let loaded = Configulator::<ToolSettings>::new()
        .with_cli_command(C::command())
        .with_file(FileOptions {
            paths: vec![CONFIG_FILE.into()],
            ..FileOptions::new(serde_loader(|s| toml::from_str(s)))
        })
        .with_environment_variables(EnvironmentVariableOptions {
            prefix: ENV_PREFIX.into(),
            separator: "_".into(),
        })
        .with_cli_flags(CLIFlagOptions {
            separator: ".".into(),
        })
        .load_with_matches();
    let (settings, matches): (ToolSettings, ArgMatches) = match loaded {
        Ok(l) => l,
        Err(ConfigulatorError::CLIError(e)) => e.exit(),
        Err(e) => {
            eprintln!("{name}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let args = match C::from_arg_matches(&matches) {
        Ok(a) => a,
        Err(e) => e.exit(),
    };
    match body(settings, args) {
        Ok(()) => ExitCode::SUCCESS,
        // A reader that closed stdout early (`| head`) wanted no more: done.
        Err(e) if is_broken_pipe(&*e) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{name}: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Whether `e`, or an error it wraps, is a broken pipe.
pub fn is_broken_pipe(e: &(dyn std::error::Error + 'static)) -> bool {
    let mut at = Some(e);
    while let Some(e) = at {
        if let Some(io) = e.downcast_ref::<std::io::Error>()
            && io.kind() == std::io::ErrorKind::BrokenPipe
        {
            return true;
        }
        if let Some(j) = e.downcast_ref::<serde_json::Error>()
            && j.io_error_kind() == Some(std::io::ErrorKind::BrokenPipe)
        {
            return true;
        }
        at = e.source();
    }
    false
}

/// Open an input: a file, or stdin (read whole) for `-`.
///
/// # Errors
///
/// The file cannot be opened or stdin cannot be read.
pub fn input(path: &Path) -> Result<Shared, BoxError> {
    if path.as_os_str() == "-" {
        let mut v = Vec::new();
        std::io::stdin().read_to_end(&mut v)?;
        return Ok(Arc::new(MemStorage(v)));
    }
    Ok(Arc::new(FileStorage::open(path)?))
}

/// Write `bytes` to a file through switch-io, or to stdout for `-` or
/// no path.
///
/// # Errors
///
/// The write fails.
pub fn output(path: Option<&Path>, bytes: &[u8]) -> Result<(), BoxError> {
    match path {
        Some(p) if p.as_os_str() != "-" => {
            if let Some(dir) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir)?;
            }
            switch_io::write_if_changed(p, bytes)?;
        }
        _ => {
            let mut out = std::io::stdout().lock();
            out.write_all(bytes)?;
            out.flush()?;
        }
    }
    Ok(())
}

/// Print a JSON value, pretty, with a trailing newline.
///
/// # Errors
///
/// Writing stdout fails.
pub fn print_json(v: &serde_json::Value) -> Result<(), BoxError> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, v)?;
    out.write_all(b"\n")?;
    Ok(())
}

/// Where title keys come from, for tools that open an NCA with a rights ID.
#[derive(clap::Args, Debug, Default)]
pub struct TitleKeyArgs {
    /// A common ticket file (.tik), or - for stdin; repeatable.
    #[arg(long = "ticket", value_name = "FILE")]
    pub tickets: Vec<PathBuf>,
    /// An encrypted title key as RIGHTSID=KEY, both 32 hex digits;
    /// repeatable.
    #[arg(long = "titlekey", value_name = "RIGHTSID=KEY")]
    pub title_keys: Vec<String>,
}

impl TitleKeyArgs {
    /// Collect the keys of the `title-keys` file, every ticket and every
    /// `--titlekey`; later sources win for the same rights ID.
    ///
    /// # Errors
    ///
    /// The title key file does not load, a ticket does not read, parse or
    /// is personalized, or a `--titlekey` is not `RIGHTSID=KEY` in hex.
    pub fn load(&self, settings: &ToolSettings) -> Result<TitleKeys, BoxError> {
        let mut out = settings.load_title_keys()?;
        out.extend(&title_keys(&self.tickets, &self.title_keys)?);
        Ok(out)
    }
}

/// Collect title keys from ticket files and `RIGHTSID=KEY` strings.
///
/// # Errors
///
/// A ticket does not read, parse or is personalized, or a `RIGHTSID=KEY`
/// is not hex.
pub fn title_keys(tickets: &[PathBuf], pairs: &[String]) -> Result<TitleKeys, BoxError> {
    let mut out = TitleKeys::default();
    for path in tickets {
        let t = Ticket::parse(&read_all(&*input(path)?)?)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        out.insert(t.rights_id, t.common_title_key()?);
    }
    for s in pairs {
        let bad = || format!("--titlekey {s:?}: want RIGHTSID=KEY, 32 hex digits each");
        let (r, k) = s.split_once('=').ok_or_else(bad)?;
        out.insert(unhex(r).ok_or_else(bad)?, unhex(k).ok_or_else(bad)?);
    }
    Ok(out)
}

/// Stream `storage` in 1 MiB chunks to a file through switch-io's
/// write-if-changed stream writer, or to stdout for `-`.
///
/// # Errors
///
/// A read, hash check or write fails.
pub fn write_storage(path: &Path, storage: &dyn Storage) -> Result<(), BoxError> {
    const CHUNK: u64 = 1 << 20;
    let mut buf = vec![0u8; usize::try_from(CHUNK.min(storage.size()))?];
    let mut stdout = std::io::stdout().lock();
    let mut file = None;
    if path.as_os_str() != "-" {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        file = Some(switch_io::StreamWriter::new(path)?);
    }
    let mut off = 0;
    while off < storage.size() {
        let n = CHUNK.min(storage.size() - off);
        let b = &mut buf[..usize::try_from(n)?];
        storage.read_at(off, b)?;
        match &mut file {
            Some(f) => f.write_all(b)?,
            None => stdout.write_all(b)?,
        }
        off += n;
    }
    match file {
        Some(f) => {
            f.finish()?;
        }
        None => stdout.flush()?,
    }
    Ok(())
}
