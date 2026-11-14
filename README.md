# switch-tools

Command-line tools that turn your own Nintendo Switch dumps into decrypted
files. You bring an NSP, NSZ, XCI or XCZ you dumped from your own console
or cartridge, plus the keys dumped from that same console; the tools
decrypt, verify and unpack it into a plain directory tree or a single
[NUP](https://github.com/a55uka/nup) file that emulators, modding tools and
recompilers can read without any keys.

This repository holds no keys, no title keys and no game data, and never
will: every test builds synthetic containers with made-up keys generated at
test time. Without your own `prod.keys` the tools decrypt nothing.

## Tools

| Tool | What it does |
| --- | --- |
| `switch-export` | Decrypt a base game with its updates and DLC into a tree in the NUP packer's layout, or straight into a `.nup` |
| `switch-nsp` | List, extract and print the files of an NSP (or any PFS0, such as an extracted exefs) |
| `switch-nca` | Show an NCA's header and extract its verified sections (exefs files, romfs image) |
| `switch-bktr` | Apply an update NCA's BKTR patch to its base and write the patched romfs |
| `switch-xci` | Show a card image, list and extract its partitions |
| `switch-ncz` | Restore NCZ members (of an NSZ or XCZ) to the exact original NCA |

Every tool prints `--help`. Errors are one line on stderr and exit code 1.

Format conversion between containers (NSP to NSZ and back, XCI to NSP, and
so on) belongs in this repository too, but is not built yet.

## Exporting a title

```sh
switch-export --keys ~/switch/prod.keys game.nsp \
    --update game-v1.nsp --update game-v2.nsp \
    --dlc dlc-pack.nsp \
    --out dump/
switch-export --keys ~/switch/prod.keys game.xci --update game-v2.nsp --nup game.nup
```

`--out` and `--nup` may be given together; at least one is required.
`--update` and `--dlc` repeat. Title keys come from the tickets inside each
package, then from the `title-keys` file and `--ticket`/`--titlekey`
flags. Only common tickets are supported; a personalized (console-bound)
ticket is reported as unsupported.

### The tree

The tree is exactly the input layout of the reference NUP packer
(`nup pack`, see "Packing a dump" in the
[NUP README](https://github.com/a55uka/nup)), so `nup pack dump/ game.nup`
works on it:

```text
dump/base/exefs/main, main.npdm, rtld, sdk, subsdk*
dump/base/romfs/...
dump/updates/<version>/exefs/...
dump/updates/<version>/romfs/...
dump/dlc/<add-on title id>/<index>/romfs/...
```

- `<version>` is the update's NCM version in decimal (`65536` is version
  `0x10000`, usually the first update).
- An update's `romfs/` is the complete tree the game sees with that update
  installed: the base romfs with the update's BKTR patch applied, not a
  delta. Each update is patched against the base on its own.
- `<add-on title id>` is 16 lowercase hex digits. `<index>` numbers the data
  contents of that add-on from `0`. The NUP packer treats this level as an
  opaque name and the NUP spec does not define it; an add-on has one data
  content, so in practice it is always `0`. When the same add-on is given
  twice, only its newest version is exported.
- `.listing` files (dump-tool artifacts, reserved by the NUP spec) are left
  out.

Files are written through a streaming write-if-changed writer, so a romfs
of several GiB never sits in memory, and running the export again leaves
unchanged files (and their modification times) alone. Files under `base/`,
`updates/` and `dlc/` that the new export does not contain are removed;
anything else in the output directory is left as it is.

### The `.nup`

`--nup` writes one base package, one update package per version (each with
its own exefs and full patched romfs) and one add-on package per add-on
(recording the add-on's real NCM version; `nup pack` records 0). Files
shared between packages are stored once. Each program package carries the
NPDM, the NACP with its display version, title names and publisher, and the
build id of `main` in its meta block. The file is written beside the target
and renamed over it only when complete.

## Configuration

Settings come from defaults, then `switch-tools.toml` in the working
directory, then `SWITCH_TOOLS_*` environment variables, then flags.
[`switch-tools.example.toml`](switch-tools.example.toml) lists every
setting.

<!-- configulator:begin -->

| Key          | Type   | Default | Environment               | Flag           | Description                                                                                                                    |
|--------------|--------|---------|---------------------------|----------------|--------------------------------------------------------------------------------------------------------------------------------|
| `keys`       | string |         | `SWITCH_TOOLS_KEYS`       | `--keys`       | path to your console key file (prod.keys), needed by every tool that decrypts                                                  |
| `title-keys` | string |         | `SWITCH_TOOLS_TITLE_KEYS` | `--title-keys` | path to a title key file (title.keys) of RIGHTSID=KEY lines, used besides the tickets inside a package and --ticket/--titlekey |

<!-- configulator:end -->

`prod.keys` holds `name = hex` lines (`header_key`,
`key_area_key_application_XX`, `titlekek_XX`, ...). `title.keys` holds
`RIGHTSID = KEY` lines, both 32 hex digits, with the encrypted title key.
Lines starting with `;` or `#` are comments. Key values never appear in
output or error messages.

## Building

```sh
cargo build --release
cargo test --workspace
```

The toolchain is pinned in `rust-toolchain.toml`.
[ARCHITECTURE.md](ARCHITECTURE.md) describes the crates and the rules the
tests enforce.

## License

MIT, see [LICENSE](LICENSE). Two modules port MIT-licensed code and carry
its notice: `switch-formats/src/bktr.rs` (LibHac, Copyright (c) 2018 Alex
Barney) and `switch-formats/src/ncz.rs` (nsz, Copyright (c) 2019 Nico
Bosshard and Blake Warner).
