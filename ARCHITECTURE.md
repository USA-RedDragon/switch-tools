# Architecture

switch-tools is one flat Cargo workspace of three crates. This file is the
authority on its shape; each structural claim names the file or test that
enforces it. Claims are checked unless marked otherwise.

## Crates, in bands

Read bottom-up; nothing lower depends on anything higher.

| Band | Crate | Holds |
| --- | --- | --- |
| 0 | `switch-io` | The one file writer (write-if-changed, streaming, temp-and-rename) and the one subprocess runner |
| 1 | `switch-formats` | Every container and executable format: keys, tickets and the eTicket RSA key, NCA, PFS0, HFS0, XCI, NCZ, BKTR, IVFC and hierarchical SHA-256, romfs, NSO, NPDM, NACP, CNMT, NUP (reader and streaming writer), the export planner, and `synth`, the synthetic fixture builder |
| 2 | `switch-tools` | Settings, the shared CLI plumbing and the `switch-*` binaries, each a thin wrapper over `switch-formats` |

Enforced by `switch-tools/tests/workspace_charter.rs` (`the_bands_hold`):
`switch-io` reaches no member, `switch-formats` reaches only `switch-io`,
and `switch-formats` has no `clap` in its closure (with presence controls
for each).

No crate of relift (the recompiler this code was split from) may appear in
the graph, in either direction: `no_relift_crate_in_the_graph` in the same
test.

## Rules

- `unsafe_code = "forbid"` in `[workspace.lints.rust]` (`Cargo.toml`), and
  every member has `[lints] workspace = true`:
  `every_member_inherits_the_workspace_lints` in
  `switch-tools/tests/workspace_charter.rs`.
- Every dependency is pinned exactly in `[workspace.dependencies]`
  (`Cargo.toml`); members write `{ workspace = true }`. `deny.toml` allows
  only permissive licenses, crates.io only, no wildcards (`cargo deny
  check` in CI).
- The toolchain is pinned in `rust-toolchain.toml`; the CI gate is
  `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  (`.github/workflows/ci.yaml`, and the pre-push hook in
  `.pre-commit-config.yaml`).

## The funnels

`clippy.toml` `disallowed-methods` bans `std::fs::write`,
`File::create`, `OpenOptions::open`, `fs::copy`, `io::copy` and
`process::Command::new` everywhere. `switch-io/src/lib.rs` is the only
place allowed to call them (each call carries an `#[expect]` with the
reason):

- `write_if_changed` for small outputs, `StreamWriter` for streamed ones:
  an unchanged output keeps its mtime, and a failed or dropped write leaves
  the old file in place (`switch-io/tests/writers.rs`).
- `TempFile` for outputs written out of order (a NUP's superblock and table
  last), renamed over the target on commit
  (`switch-formats/tests/nup_writer.rs`,
  `a_failed_write_leaves_the_target_alone`).
- `command` starts every subprocess.

## Fixtures

No test reads game data or real keys. `switch-formats/src/synth.rs` derives
keys from a seed and builds complete NSPs (program, meta, control and
add-on NCAs, tickets, BKTR updates); every test in the workspace builds its
inputs from it. Error messages never contain key material
(`switch-formats/src/keys.rs`: `Debug` lists key names only).

## Pitfalls

- **An update's romfs is a patch, not a tree.** The update NCA's romfs
  section is AES-CTR-EX patch data plus two bucket trees; the real romfs is
  the base section with the indirect storage stitched over it
  (`switch-formats/src/bktr.rs`, ported from LibHac). Export writes the
  full patched tree per update, each patched against the base alone
  (`switch-formats/tests/export.rs`, `tree_has_the_packer_layout`).
- **NCZ restores sections, not bytes.** An NCZ stores the NCA header
  encrypted and the sections decrypted and compressed; restoring means
  re-encrypting each section with its own key and counter, and only the
  content record's SHA-256 proves the result
  (`switch-formats/tests/ncz.rs`).
- **Personalized tickets need the console's eTicket key.** A console-bound
  ticket's title key block is RSA-2048-OAEP (SHA-256, empty label) to
  that console's eTicket key, and unwraps to the same titlekek-wrapped key
  a common ticket holds (`switch-formats/src/eticket.rs`). The key pair
  comes from the `eticket-rsa-keypair` setting (raw, 0x210 bytes), from
  `eticket_rsa_keypair` in `prod.keys`, or from the `prodinfo` setting: a
  decrypted PRODINFO whose `ExtendedRsa2048ETicketKey` (0x3890) is
  AES-CTR decrypted with `eticket_rsa_kek` (then
  `eticket_rsa_kek_personalized`). Packages unwrap their tickets in
  `Package::unlock_personalized`; without a key, `Nsp::program` fails with
  `missing key` naming both settings, and another console's key is `wrong
  key` (`switch-formats/tests/eticket.rs`). The RSA crate is RustCrypto
  `rsa` 0.10, the first release patched for RUSTSEC-2023-0071.
- **Several programs in one package.** A multi-title card or an
  application with several programs holds more than one program NCA.
  `title::pick_program` takes the one chosen with
  `Package::select_program` (an update's `id | 0x800` matches too), and
  without a choice fails as `ambiguous` listing every program id; the plan
  then uses that title's content meta and control NCA
  (`switch-formats/tests/xci.rs`,
  `a_multi_title_card_exports_each_chosen_title`).
- **Key generations.** Each NCA names a key generation; the key-area key and
  titlekek of that generation must be in `prod.keys`. A missing one is
  `missing key: <name>`, a wrong one shows as `wrong key` when the header
  or first hashed block fails to verify (`switch-formats/tests/export.rs`,
  `missing_keys_fail`, `wrong_keys_fail`).
- **Streaming.** A romfs can exceed 4 GiB. Every read goes through layered
  `Storage` values (file, AES-CTR, BKTR, IVFC-verified) in 1 MiB chunks,
  and every write through `switch-io`; nothing holds a whole romfs or large
  file in memory. The NUP writer knows its table size from names and counts
  alone, so it streams extents first and writes the header last
  (`switch-formats/src/nup_writer.rs`; byte-identical to the in-memory
  fixture builder: `equals_the_in_memory_builder`).
- **Dedup across updates.** A full patched romfs repeats most base files.
  The NUP writer hashes a file before compressing it only when an earlier
  file had the same size, so a repeated file costs one read and no
  compression (`switch-formats/src/nup_writer.rs`, `put_file`). Measured
  faster on commit 063e229 with `switch-formats/examples/nup_dedup_bench.rs`
  (`gen <dir>`, then `run <dir> <mode>`; release build, five runs of each
  mode, warm page cache, AMD Ryzen 9 7950X). The data: a 121 MiB base
  romfs of 795 files and three updates, each editing 4% of the files in
  place, resizing 1%, adding 1% and dropping 0.5%, half noise and half
  text; 510 MB of content in 3212 files. Size-matched prehash (the
  default): 0.93 to 0.99 s, 608 MB read (`rchar`), a 93 MB `.nup`.
  Compressing every file and dropping duplicate frames after: 1.53 to
  1.63 s, 597 MB read, the same bytes. No sharing: 1.79 to 2.14 s, 787 MB
  read, a 330 MB `.nup`. The prehash reads 11 MB more (a same-size file
  that changed is read twice) and saves about 40% of the time. Cold-cache
  reads were not measured. All three strategies read back the same files
  (`switch-formats/tests/nup_writer.rs`,
  `every_dedup_strategy_reads_back_the_same_files`). Rerun on 9117d98,
  after the extent order changed to the reference packer's: three runs
  each, within 0.05 s of the ranges above, the same bytes read.

## The reference packer

`switch-formats/tests/reference_packer.rs` packs the exported tree of a
synthetic base (with icons), update and add-on with the reference Python
packer (`tools/nup` of github.com/a55uka/nup) and compares every field
with this crate's `.nup` of the same plan. It runs only when
`NUP_REFERENCE_PACKER` (the packer's `tools/nup` directory) and
`NUP_REFERENCE_PYTHON` (a Python with `zstandard`) are set, never in CI,
and runs the packer with `python -I` from the scratch directory.

Checked against the packer at a34925a (zstandard 0.25.0, zstd 1.5.7):
the trees, file records, extents, offsets, string pool, children and
UUID are identical, because both lay out directories in pre-order, number
a directory's own files before its subdirectories', pool directory names
before file names, write extents in file order and write meta blocks
back to back without alignment (`switch-formats/src/nup_writer.rs`,
`switch-formats/src/nup.rs` `build`). Two meta records differ, both valid
per SPEC section 5, and with them the meta offsets, the TOC hash and the
file size:

- NACP (0x0002): written here from the control NCA; the reference packs a
  tree, which has no NACP, and leaves the optional record out.
- Source dump name (0x0008): the reference writes its input directory's
  name; this crate reads packages, not a dump directory, and leaves the
  optional provenance record out.

With the plan's meta changed to match (no NACP, source name `dump`), the
two files are byte-identical; the test asserts that.

The packer's main branch at a4840f0 writes every meta type one lower than
SPEC section 5 (NPDM as 0x0000): its commit 1d904e1 replaced the
constants with an `IntEnum` starting at 0. The test fails with that
message against it; use a34925a, the commit before.
