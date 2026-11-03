# CLAUDE.md — sast3uh

## Project overview

sast3uh is a Rust CLI: a hardened wrapper that runs several analysers
(Semgrep, Bearer, Trivy, Luacheck today) over a directory, parses what each one says,
removes the duplicates and writes one report — text, JSON, YAML, XML or HTML —
with one exit code. Before scanning it checks each scanner against the newest
version mise knows and offers (asks) to install or update it through mise —
sast3uh never downloads anything itself. It runs other people's binaries
on other people's code, so **a bug here is a security bug by default**.
Security and the absence of regressions come first; features come second.

The engineering baseline (commit gate, CI fleet, pinning, testing) is lifted
from `../superapp` and from the ciso-assistant repository; every rule below
exists because something slipped through somewhere once.

## Stack

- **Language**: Rust, edition 2024, toolchain pinned in `rust-toolchain.toml`
- **CLI**: clap (derive) · **errors**: anyhow at the edge, thiserror inside
- **Serialisation**: serde / serde_json / serde-saphyr (YAML, safe Rust);
  XML and HTML are hand-written writers with escaping
- **Tool management**: mise (`which` / `latest` / `use -g`), driven as a
  child process like any scanner — no HTTP client in the binary
- **Tests**: `cargo test` — unit tests in each module, pipeline tests on a
  fake runner, end-to-end tests in `tests/` with assert_cmd + shell stubs
  that replay recorded fixtures (`tests/fixtures/<tool>/`)
- **Gates**: pre-commit, Bearer, Grype, cargo-deny, Semgrep, Plumber, zizmor,
  CodeQL, Dependency Review, OpenSSF Scorecard

## Architecture

```text
sast3uh/
├── src/
│   ├── main.rs          # thin: argv → sast3uh::run → exit code
│   ├── lib.rs           # run / run_with (injectable Deps), exit codes, --fail-on gate
│   ├── cli.rs           # clap definition only — no behaviour
│   ├── pipeline.rs      # locate (mise which → PATH) → version → install/update (ask) →
│   │                    # run → parse → dedup → Report
│   ├── scanners/        # Scanner trait + registry; semgrep.rs, bearer.rs, trivy.rs, luacheck.rs
│   │                    # (args, env, output → findings, mise id) — pure glue
│   ├── detect.rs        # languages + markers of the target from file names (no reads)
│   ├── packs.rs         # measured Semgrep pack catalogue, selection by language/profile
│   ├── exec.rs          # THE process boundary: argv list, scrubbed env, cwd, timeout, cap
│   ├── update.rs        # mise front-end: which / latest / ls --json / use -g, UpdatePlan
│   ├── dedup.rs         # exact + cross-tool (path, line, CWE) merge, sort worst first
│   ├── model.rs         # Severity, Finding, ToolRun, Summary, Report, path normalisation
│   ├── output/          # text, json, yaml, xml, html renderers + atomic file write
│   ├── version.rs       # loose semver parse/compare
│   ├── prompt.rs        # yes/no on a terminal; always "no" when not interactive
│   ├── tools.rs         # find_in_path — the only way a binary is resolved
│   └── timefmt.rs       # RFC 3339 without a date crate
├── tests/cli.rs         # process boundary: exit codes, stdout vs stderr, files
├── tests/fixtures/      # recorded scanner output (report + version banner per tool)
├── Cargo.toml           # hardened lints + release profile (fat LTO, overflow checks)
├── clippy.toml          # thresholds + disallowed methods (Command::new, set_var…)
├── deny.toml            # advisories, license allow-list, bans, crates.io only
├── .pre-commit-config.yaml
├── .mise.toml           # gate tools pinned (Plumber), run with `mise exec`
├── .plumber.yaml        # CI/CD trust policy (every control listed explicitly)
├── bearer.yml, .grype.yaml
└── .github/workflows/   # CI, cargo-deny, Bearer, Grype, Semgrep, CodeQL,
                         # CI hardening (zizmor + Plumber), Scorecard,
                         # Dependency Review, pre-commit
```

Exit codes are fixed: `0` clean, `1` findings at or above `--fail-on`, `2`
usage (clap), `3` could not run or a scanner failed (report still written).
They are documented in `src/lib.rs` and asserted in `tests/cli.rs`.

### Adding a scanner

1. `src/scanners/<tool>.rs`: a unit struct implementing `Scanner` — name,
   binary, mise id (check `mise registry`; else `aqua:owner/repo` or
   `ubi:owner/repo`), version args, scan args (the target is the cwd, pass
   `.`), `interpret` (exit code + stdout → `Outcome`).
2. A pure `parse(bytes)` function tested on **recorded output** copied into
   `tests/fixtures/<tool>/report.*` and `version.txt` (run the real tool on
   a sample project once; never call it from a test), that keeps every
   field — see "Parsing rules" — with a completeness test and a
   tolerance test.
3. Register it in `scanners::registry()`; `names()`/`by_name` follow.
4. Add the stub to `tests/cli.rs` (`Stubs::new`) and extend the end-to-end
   assertions; `sast3uh tools` picks it up by itself.

## Dev commands

```bash
pre-commit install                                   # once per clone
cargo test --all-features --locked                   # all tests
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo fmt --all
cargo deny check                                     # advisories, licenses, bans, sources
cargo build --release --locked
```

## MANDATORY — Pre-commit checklist (BLOCKING)

**This section is the single most important rule in this file.**
Run ALL of it before EVERY `git commit`. No exceptions.

```bash
# 0. Stage EVERYTHING first — `pre-commit run --all-files` only looks at
#    files git knows about; an untracked new file is silently skipped and
#    fails in CI instead.
git add -A

# 1. Pre-commit (hygiene, secrets, typos, yaml/md/actions lint, zizmor,
#    cargo fmt / clippy / doc / test, cargo-deny, Bearer, Grype, Plumber —
#    Plumber runs on EVERY commit, through the version pinned in .mise.toml)
pre-commit run --all-files
# If a hook "modified files", stage its fixes and run it again until it passes.

# 2. The pre-push hooks, by hand (Semgrep with real Rust rules, release build)
pre-commit run --all-files --hook-stage pre-push
```

**If ANY check fails, DO NOT commit. Fix the issue first, then re-run.**

- Clippy: every lint in `Cargo.toml` is an error in CI (`-D warnings`);
  fix the code, never `#[allow]` without a comment saying why
- cargo-deny: an advisory ⇒ bump the dependency; a license ⇒ review it and
  add it to `deny.toml` on purpose, or drop the crate
- Grype High/Critical ⇒ update the dependency; an ignore in `.grype.yaml`
  needs the advisory id, a reason and a removal condition
- Bearer Critical/High ⇒ fix the flagged pattern
- Plumber: any finding fails (`--min-points 100`); a new third-party action
  must be SHA-pinned AND allow-listed in `.plumber.yaml`
- Keep the `bearer`, `grype`, `semgrep` binaries current — CI runs the
  latest release, and an older local copy has fewer rules: it waves through
  what CI then blocks. Plumber is the exception: `.mise.toml` pins the exact
  version the CI action uses, and the hook runs it with `mise exec` so the
  `/usr/bin/plumber` of the machine is never what gates a commit. Bump both
  together (the action SHA and the pin).
- **Reproduce a CI failure before fixing it**: a fresh clone with an empty
  `HOME` (`HOME=$(mktemp -d)`) reproduces what the runner sees — Bearer 2.1.3
  without cached rules writes "The security report is not yet available…"
  instead of SARIF and exits 1, which a warm local cache never shows.
- Medium/Low from Grype or Bearer are acceptable; everything from
  cargo-deny, clippy, zizmor and Plumber is blocking

The git hooks make the gate automatic; `pre-commit install` once per clone.
A `--no-verify` commit is never acceptable.

## Testing (MANDATORY)

A regression is the one failure that must never reach users, so every change
ships with its tests in the same commit — a feature without tests is not
finished. CI enforces **80 % line coverage** (`cargo llvm-cov
--fail-under-lines 80`).

- **Unit tests** for every new function, type and parser, in a `#[cfg(test)]
  mod tests` next to the code.
- **End-to-end tests** in `tests/cli.rs` for every subcommand and every exit
  code: happy path, usage error, missing target, scanner failure.
- **A regression test for every bug fix**, written to fail before the fix.
- **Scanner adapters are tested against recorded output** (fixtures in
  `tests/fixtures/<tool>/`), never against the live binary: tests must not
  depend on what is installed on the machine, and must not touch the network.
  The pipeline is tested with `FakeRunner`/`FakeHttp`/`FixedAnswer`; the
  binary with shell stubs on a private `PATH` that replay the fixtures.
- **Malformed input is a test case**: every parser of scanner output gets a
  truncated, an empty, an oversized and a wrong-shape fixture.
- File fixtures go through `tempfile`; never write into the repo or `/tmp`
  by hand.
- Tests may `unwrap`/`expect`/`panic`/index (`clippy.toml` allows it in
  `#[test]` bodies; an integration test crate adds the `#![allow]` at its
  top with the comment that is in `tests/cli.rs`).

## Parsing rules (the heart of the project)

The tool is worth exactly what its parsers keep. Every adapter follows these:

- **Keep everything the scanner says.** What has a cross-tool meaning gets a
  typed field of `Finding` (severity, confidence, CWE, OWASP, categories, tags,
  location with end line/column, snippet, fix, references, data flow,
  fingerprint, suppression); what is tool-specific goes verbatim into
  `extra` under the scanner's own field name (unknown fields included, via
  `#[serde(flatten)]`); what the tool says about its run — files scanned or
  skipped, rules that errored — goes into `ToolRun` (`scanned_files`,
  `skipped_paths`, `diagnostics`). Dropping a field is a bug.
- **One bad entry never sinks the report.** Each result is deserialised on
  its own; an unreadable one becomes a `warnings` entry that says which and
  why. `null` where a list, string or flag is expected reads as empty
  (`null_default`); a value that may be a string or a list reads through
  `Strings`.
- **Completeness is tested, not assumed.** Every fixture test checks that the
  number of findings (plus warnings) equals the number of raw entries and
  that every raw id is present; every tolerant path has a test with nulls,
  wrong types and escaping paths.
- **Fixtures are recorded output**, copied from a real run on a sample
  project, never hand-written — with anything that looks like a live secret
  redacted (`sk_live_<redacted-in-fixture>`): GitHub push protection blocks a
  push that carries a key-shaped string, fake or not.
- **Suppressed findings** (`nosemgrep`…) stay in the report flagged
  `suppressed`, out of the counts and of the exit code.
- **Deduplication merges, it never discards**: the merged finding keeps the
  union of every list, fills what it lacked, and files the other tool's own
  fields under `tool:field` in `extra`.

## Rule packs (what the scanners are given)

- `src/packs.rs` is the Semgrep catalogue: every official registry pack that
  is not empty for the OSS engine, not meta/test, not a strict subset of a
  listed pack, not style-only — each with the languages or markers
  (`src/detect.rs`) that call for it, a profile tier and the rule count
  measured on 2026-11-02. The pipeline detects the target's languages once
  and selects the packs; `sast3uh packs DIR` shows the selection.
- **Re-measure before editing the catalogue**: the listing is
  `https://semgrep.dev/api/registry/rulesets` (305 rulesets, with author,
  languages and tags) and a pack's rules are
  `https://semgrep.dev/c/p/<name>`; count rules per language anonymously
  (what the OSS engine downloads), drop packs with 0 rules. Semgrep
  deduplicates identical rule ids across `--config`s (measured: 3
  overlapping packs, 0 duplicate findings), so overlap costs download time
  only — selecting by language is what keeps a scan fast.
- Bearer runs `--scanner sast,secrets`; Trivy runs `fs --scanners
  vuln,misconfig,secret,license --include-dev-deps` (plus
  `--detection-priority comprehensive --license-full` in the exhaustive
  profile, and `--skip-db-update --skip-java-db-update --skip-check-update
  --offline-scan` under `--offline`); Luacheck runs with the default
  `std = max` and the project's `.luacheckrc`. A new scanner's adapter
  documents its own "most exhaustive" invocation in its `scan_args`.
- Trivy masks the secrets it reports (`***`); the masked `Match` is the
  finding's message and the masked code lines its snippet — nothing else of
  a secret is ever kept.

## Secure coding rules (the point of the project)

- **No `unsafe`** — forbidden at the crate level. If a dependency needs it,
  that is a reason to look for another dependency.
- **No panic paths in library code**: `unwrap`, `expect`, `panic!`,
  `todo!`, `unimplemented!`, `unreachable!`, `[i]` indexing and string
  slicing are clippy *errors*. Return a `Result`; `main` prints and exits.
- **Spawning a scanner** goes through `crate::exec::run` (the only call site
  of `std::process::Command::new`, with `#[allow(clippy::disallowed_methods)]`
  and a comment); the pipeline receives it as a `Runner` so tests inject a
  fake:
  - argv as a list — never a shell, never a formatted command string;
  - an explicit, minimal environment (`env_clear()` then only what the tool
    needs: `PATH`, `HOME`, locale) — the user's tokens never reach a scanner
    that does not need them;
  - the target as the working directory, the binary resolved with
    `tools::find_in_path` (a name with a path separator is never run);
  - a timeout, and a cap on captured stdout/stderr (a scanner that prints
    forever must not OOM the wrapper);
  - the exit status interpreted per tool (most return 1 on findings — that
    is a result, not an error).
- **Scanner output is untrusted input**: parse with serde into typed structs,
  bounded sizes, lossy UTF-8; a malformed report is an error for that tool,
  never a panic, never silently empty.
- **Paths**: the target is canonicalised once (`scan::resolve_target`);
  findings are reported relative to it; a finding pointing outside the
  target is dropped with a warning (symlink escape).
- **Never mutate the process environment** (`set_var`/`remove_var` are
  disallowed) — pass an environment to the child.
- **Never log or print a secret**: no environment dump, no raw scanner
  stderr in the JSON report, redact anything that looks like a token.
- **Written files** (reports, downloaded binaries) are staged next to their
  destination and renamed over it (`output::write_atomically`,
  `update::place_binary`): a symlink at the destination is replaced, never
  followed. Never write to a path the scanned project controls.
- **Installs and updates go through mise and ask first**: the prompt only
  appears on a terminal, a non-interactive run never changes the machine (it
  prints the `mise use -g` line instead), `--update always` is the explicit
  opt-in. sast3uh has no HTTP client; mise is the only child that receives
  `MISE_*` and `GITHUB_TOKEN`, and a scanner never does.
- **Reports are output encoding**: XML and HTML escape every value, HTML
  ships a CSP with no script, and only `http(s)` URLs become links.
- **Dependencies**: crates.io only, no git deps, license allow-list, no
  native TLS (`deny.toml`); prefer the standard library over a small crate.
- **Integer overflow** is checked in release too (`overflow-checks = true`).

## Commits & versioning

Conventional commits, enforced by the `commit-msg` hook: `feat:`, `fix:`,
`chore:`, `docs:`, `refactor:`, `test:`, `ci:`, `build:`, `perf:`,
`revert:`, with an optional scope (`fix(ci):`, `feat(semgrep):`).

Versions are `vX.Y.Z`, and the commit types in a release decide which number
moves:

- **X — major**: only the user decides to bump it. Never propose or tag a
  major version on your own, whatever the size of the change.
- **Y — feature**: the release contains at least one `feat:`. Resets Z to 0.
- **Z — bug fix**: the release contains only `fix:` (and chores/docs).

### Release flow — strict order, verify between every step

```bash
git commit …          # the gate runs; if it fails, THE COMMIT DOES NOT EXIST
git log -1            # VERIFY the commit is there before tagging
git tag vX.Y.Z
git log -1 vX.Y.Z     # VERIFY the tag points at the right commit
git push origin main vX.Y.Z
```

Never script `commit && tag && push` without each step aborting on the
previous one's failure. A release workflow (signed artifacts + build
provenance attestations, as Plumber CTRL-712 requires) is written the day
there is a first release; until then there is nothing to publish.

## CI fleet (what each workflow owns — nothing is run twice)

| Workflow                | Owns                                                                                 |
| ----------------------- | ------------------------------------------------------------------------------------ |
| `ci.yml`                | fmt, clippy, rustdoc, tests (Linux + macOS), coverage ≥ 80 %, release build          |
| `cargo-deny.yml`        | RustSec advisories, licenses, bans, sources (+ weekly)                               |
| `security-scan.yml`     | Grype SCA on `Cargo.lock` (+ weekly)                                                 |
| `bearer.yml`            | Bearer SAST — no Rust rules, covers helper scripts the day there are some (+ weekly) |
| `semgrep.yml`           | Semgrep `p/rust` + `p/secrets` (+ weekly)                                            |
| `codeql.yml`            | CodeQL Rust, security-and-quality (+ weekly)                                         |
| `ci-hardening.yml`      | zizmor on the workflows                                                              |
| `plumber.yml`           | Plumber: CI/CD trust policy on the workflows and repo settings, 100 points or fail   |
| `scorecard.yml`         | OpenSSF Scorecard                                                                    |
| `dependency-review.yml` | PR gate on new vulnerable / copyleft dependencies                                    |
| `pre-commit.yml`        | the hygiene hooks only (the rest is SKIPped — see above)                             |

Every action is pinned by full commit SHA with a `# vX.Y.Z` comment that
matches the SHA (Plumber checks both); Dependabot bumps them weekly after a
7-day cooldown. Every `actions/checkout` sets `persist-credentials: false`.
Permissions are declared per job, `contents: read` by default. A new
third-party action is added to `trustedGithubActions` in `.plumber.yaml`
with a comment saying what it is for.
