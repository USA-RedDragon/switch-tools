//! Measures the NUP writer's cross-update dedup on synthetic data.
//!
//! `nup_dedup_bench gen <dir> [base MiB]` writes a base NSP and three
//! update NSPs whose patched romfs trees repeat most base files (each
//! update edits about 4% of the files in place, resizes 1%, adds 1% and
//! drops 0.5%, on top of the one before). Half the files are noise that
//! does not compress, half are text-like and compress.
//!
//! `nup_dedup_bench run <dir> <prehash|after-compress|off>` exports the
//! four packages to `<dir>/out.nup` with that strategy and prints the wall
//! time of the write, the bytes the process read (`rchar` of
//! `/proc/self/io`, Linux only) and the writer's summary.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use switch_formats::export;
use switch_formats::nup_writer::{DEFAULT_LEVEL, Dedup};
use switch_formats::synth::{self, ProgramSpec};
use switch_formats::title::{Package, open_package_path};

const TITLE: u64 = 0x0100_5555_0000_0000;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

const WORDS: [&str; 16] = [
    "texture", "model", "sound", "event", "script", "table", "level", "actor", "light", "camera",
    "shader", "font", "menu", "voice", "effect", "string",
];

fn content(rng: &mut Rng, size: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(size + 16);
    if rng.below(2) == 0 {
        while v.len() < size {
            v.extend_from_slice(&rng.next().to_le_bytes());
        }
    } else {
        while v.len() < size {
            let w = WORDS[usize::try_from(rng.below(16)).unwrap_or(0)];
            v.extend_from_slice(w.as_bytes());
            v.extend_from_slice(format!(" {} ", rng.below(1000)).as_bytes());
        }
    }
    v.truncate(size);
    v
}

fn size(rng: &mut Rng) -> usize {
    let class = rng.below(10);
    let top = match class {
        0..=5 => 32 << 10,
        6..=8 => 256 << 10,
        _ => 2 << 20,
    };
    usize::try_from(0x200 + rng.below(top)).unwrap_or(0x200)
}

fn spec(program_id: u64, romfs: Vec<(String, Vec<u8>)>, key: u8) -> ProgramSpec {
    ProgramSpec {
        program_id,
        exefs: vec![
            ("main".into(), synth::nso("bench-main", key)),
            (
                "main.npdm".into(),
                switch_formats::npdm::build("Application", TITLE, 0x10_0000, &[("fsp-srv", false)]),
            ),
        ],
        romfs,
        rights_id: None,
        content_key: [key; 16],
    }
}

fn put(path: &Path, bytes: &[u8]) -> Result<(), String> {
    switch_io::write_if_changed(path, bytes)
        .map(|_| ())
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn generate(dir: &Path, base_mib: u64) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let fk = synth::keys(1);
    put(&dir.join("prod.keys"), fk.text.as_bytes())?;
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let mut total = 0u64;
    while total < base_mib << 20 {
        let n = size(&mut rng);
        let name = format!("data/d{:02}/f{:05}.bin", files.len() % 37, files.len());
        files.push((name, content(&mut rng, n)));
        total += n as u64;
    }
    eprintln!("base: {} files, {total} bytes", files.len());
    let base_spec = spec(TITLE, files.clone(), 0x40);
    let (nca, base_romfs) = synth::program_nca(&fk, &base_spec);
    drop(base_spec);
    let meta = synth::meta_nca(&fk, TITLE, 0, 0x80, &nca);
    put(
        &dir.join("base.nsp"),
        &synth::package(&fk, &[&nca], &meta, &[]),
    )?;
    drop((nca, meta));
    let mut next = 100_000usize;
    for u in 1..=3u32 {
        let count = files.len();
        for _ in 0..count * 4 / 100 {
            let i = usize::try_from(rng.below(count as u64)).unwrap_or(0);
            let f = &mut files[i].1;
            let at = usize::try_from(rng.below(f.len() as u64)).unwrap_or(0);
            f[at] ^= 0x5a;
        }
        for _ in 0..count / 100 {
            let i = usize::try_from(rng.below(count as u64)).unwrap_or(0);
            let n = size(&mut rng);
            files[i].1 = content(&mut rng, n);
        }
        for _ in 0..count / 200 {
            let i = usize::try_from(rng.below(files.len() as u64)).unwrap_or(0);
            files.remove(i);
        }
        for _ in 0..count / 100 {
            let n = size(&mut rng);
            files.push((format!("data/new/u{u}/f{next}.bin"), content(&mut rng, n)));
            next += 1;
        }
        let total: u64 = files.iter().map(|f| f.1.len() as u64).sum();
        eprintln!("update {u}: {} files, {total} bytes", files.len());
        let s = spec(
            TITLE | 0x800,
            files.clone(),
            0x40 + u8::try_from(u).unwrap_or(0),
        );
        let nca = synth::update_nca(&fk, &s, &base_romfs);
        drop(s);
        let meta = synth::meta_nca(&fk, TITLE | 0x800, u << 16, 0x81, &nca);
        put(
            &dir.join(format!("update{u}.nsp")),
            &synth::package(&fk, &[&nca], &meta, &[]),
        )?;
    }
    Ok(())
}

fn rchar() -> Option<u64> {
    let io = std::fs::read_to_string("/proc/self/io").ok()?;
    io.lines()
        .find_map(|l| l.strip_prefix("rchar: "))
        .and_then(|v| v.trim().parse().ok())
}

fn run(dir: &Path, mode: &str) -> Result<(), String> {
    let dedup = match mode {
        "prehash" => Dedup::Prehash,
        "after-compress" => Dedup::AfterCompress,
        "off" => Dedup::Off,
        other => return Err(format!("unknown mode {other:?}")),
    };
    let keys =
        switch_formats::keys::Keys::load(&dir.join("prod.keys")).map_err(|e| e.to_string())?;
    let open = |n: &str| -> Result<Box<dyn Package>, String> {
        open_package_path(&dir.join(n)).map_err(|e| e.to_string())
    };
    let base = open("base.nsp")?;
    let updates: Vec<Box<dyn Package>> = (1..=3)
        .map(|u| open(&format!("update{u}.nsp")))
        .collect::<Result<_, _>>()?;
    let ups: Vec<&dyn Package> = updates.iter().map(AsRef::as_ref).collect();
    let plan = export::plan(&keys, base.as_ref(), &ups, &[]).map_err(|e| e.to_string())?;
    let out: PathBuf = dir.join("out.nup");
    let before = rchar();
    let t = Instant::now();
    let s = plan
        .write_nup_with(&out, DEFAULT_LEVEL, dedup)
        .map_err(|e| e.to_string())?;
    let secs = t.elapsed().as_secs_f64();
    let read = match (before, rchar()) {
        (Some(a), Some(b)) => (b - a).to_string(),
        _ => "n/a".into(),
    };
    println!(
        "{mode}\t{secs:.2} s\tread {read}\tnup {} bytes\t{} files\t{} extents ({} zstd)\tcontent {}",
        s.file_size, s.files, s.extents, s.compressed, s.content_bytes
    );
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["gen", dir] => generate(Path::new(dir), 120),
        ["gen", dir, mib] => match mib.parse() {
            Ok(m) => generate(Path::new(dir), m),
            Err(_) => Err(format!("not a size: {mib}")),
        },
        ["run", dir, mode] => run(Path::new(dir), mode),
        _ => Err("usage: nup_dedup_bench gen <dir> [base MiB] | run <dir> <mode>".into()),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("nup_dedup_bench: {e}");
            ExitCode::FAILURE
        }
    }
}
