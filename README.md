# sast3uh

One SAST to run them all. A hardened Rust CLI that drives several static
analysers (SAST, SCA, IaC, secrets, licenses) over a directory, parses what each one says, removes the
duplicates and writes a single report — text, JSON, YAML, XML or HTML —
with a single exit code. Before scanning it checks each scanner against its
latest GitHub release and offers to update it.

## Scanners

| Tool     | Covers                                                                      | mise id                     |
| -------- | --------------------------------------------------------------------------- | --------------------------- |
| semgrep  | SAST, 30+ languages, rule packs (`p/default` by default)                    | `semgrep`                   |
| bearer   | SAST + sensitive data: JS/TS, Python, Go, Java, Ruby, PHP                   | `aqua:Bearer/bearer`        |
| trivy    | SCA (CVEs in lockfiles), IaC misconfigurations, secrets, licenses           | `trivy`                     |
| codeql   | GitHub's semantic analysis: JS/TS, Python, Ruby, Java/Kotlin, C#, C/C++,    | `codeql`                    |
|          | Rust, Go, Swift and GitHub Actions workflows, `security-extended` suites    |                             |
| plumber  | CI/CD trust policy: GitHub Actions / GitLab CI attack paths, pinning,       | `github:getplumber/plumber` |
|          | permissions, injections, images                                             |                             |
| luacheck | Lua linter: globals, unused, syntax                                         | `ubi:lunarmodules/luacheck` |

Scanners are installed and updated through [mise](https://mise.jdx.dev):
sast3uh resolves each binary with `mise which` (falling back to `PATH`),
asks `mise latest` for the newest version and runs `mise use -g <id>@<v>`
when you say yes. It never downloads anything itself. A scanner that is
missing is offered for install; one that is behind is offered for update;
one that fails marks the report incomplete (exit 3). The same problem
reported by two scanners on the same line with a CWE in common is one
finding, at the worst severity, with both tools listed.

## Installation

sast3uh is a single binary with no runtime dependency beyond the system C
library. Pick one of the three ways below, then install the scanners (next
section) — or let sast3uh offer to install them the first time you run a
scan.

### 1. Through mise (recommended)

[mise](https://mise.jdx.dev) installs the right archive for your platform
straight from the GitHub release and keeps it updated:

```bash
mise use -g github:Claquetteuuuh/sast3uh@0.1.0   # a pinned version
mise use -g github:Claquetteuuuh/sast3uh         # the newest release that is 24 h old
sast3uh --version
```

`sast3uh` is on your `PATH` only when mise is activated in your shell —
`mise doctor` must say `activated: yes` (or `shims_on_path: yes`). If it
does not, add mise's hook to your shell once and open a new terminal:

```bash
echo 'eval "$(mise activate zsh)"' >> ~/.zshrc     # bash: mise activate bash >> ~/.bashrc
```

Until then, `mise exec -- sast3uh --version` runs the installed binary.

mise hides a release younger than its `minimum_release_age` (24 h by
default) from `@latest`: the day a version comes out, `mise use` without a
version answers "no versions found … eligible tomorrow". That is the same
cooldown this project's Dependabot applies to its own dependencies — keep
it, and pin the version instead. sast3uh itself always installs scanners
with an explicit version (`mise use -g <tool>@<version>`), so it is never
held back by it.

### 2. Prebuilt binary from a release

Every release ships, for `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu` and `aarch64-apple-darwin`, the bare executable
`sast3uh-<version>-<target>` (download, `chmod +x`, run) and an archive
`sast3uh-<version>-<target>.tar.gz` with README and SECURITY.md — each with
a `.sha256`, all listed in `checksums.txt`, and each carrying a
build-provenance attestation signed by the release workflow. (v0.1.0 shipped
the archives only.)

```bash
V=0.1.0; T=x86_64-unknown-linux-gnu   # pick your target
gh release download "v$V" --repo Claquetteuuuh/sast3uh \
  --pattern "sast3uh-$V-$T.tar.gz" --pattern checksums.txt
sha256sum --ignore-missing -c checksums.txt                 # integrity
gh attestation verify "sast3uh-$V-$T.tar.gz" --repo Claquetteuuuh/sast3uh  # provenance
tar -xzf "sast3uh-$V-$T.tar.gz"
install -m 0755 "sast3uh-$V-$T/sast3uh" ~/.local/bin/   # anywhere on your PATH
```

Or the bare executable, same checks:

```bash
gh release download "v$V" --repo Claquetteuuuh/sast3uh --pattern "sast3uh-$V-$T" --pattern checksums.txt
sha256sum --ignore-missing -c checksums.txt
gh attestation verify "sast3uh-$V-$T" --repo Claquetteuuuh/sast3uh
install -m 0755 "sast3uh-$V-$T" ~/.local/bin/sast3uh
```

Without the `gh` CLI, the same files are on the
[releases page](https://github.com/Claquetteuuuh/sast3uh/releases).

### 3. From source

Needs Rust 1.98 or newer (`rust-toolchain.toml` pins the exact version when
you build inside the clone). The crate is not on crates.io on purpose.

```bash
# straight from the tag, into ~/.cargo/bin
cargo install --locked --git https://github.com/Claquetteuuuh/sast3uh --tag v0.1.0

# or from a clone
git clone https://github.com/Claquetteuuuh/sast3uh && cd sast3uh
cargo build --release --locked        # → target/release/sast3uh
cargo test --all-features --locked    # 175 tests, no scanner needed
```

The release profile uses fat LTO, keeps integer overflow checks on and
strips symbols; `--locked` makes sure the audited `Cargo.lock` is what gets
built.

### Installing the scanners

sast3uh drives the scanners it finds; it never bundles them. With mise on
your `PATH`, a scan offers to install a missing one and to update an
outdated one (`--update ask`, the default; `--update always` to say yes to
everything, `--offline` for no lookup at all). To install them yourself:

```bash
mise use -g semgrep aqua:Bearer/bearer trivy codeql github:getplumber/plumber ubi:lunarmodules/luacheck
sast3uh tools      # installed path, version and latest release of each
```

Each scanner is resolved with `mise which` first, then on `PATH`, so a
mise-managed version always wins over a stray system one.

#### CodeQL, kept light

CodeQL is the heaviest of the scanners and sast3uh keeps it as simple as a
`mise use -g codeql`: the bare CLI (about 750 MB installed, with its own
Java runtime — no bundle, no system Java), no database to manage and no
query to compile.

- For each language found in the target, sast3uh extracts a CodeQL database
  into a private scratch directory (`~/.cache/sast3uh/sast3uh-scan-*`, never
  inside the project), runs the language's `security-extended` suite on it
  and deletes the database as soon as it is analysed.
- The query packs (`codeql/<language>-queries`, precompiled, a few tens of
  MB each) are downloaded by CodeQL itself the first time a language is
  analysed, into `~/.codeql/packages`; later scans reuse them. Under
  `--offline` nothing is downloaded: a missing pack is reported for that
  language and the others still run.
- Interpreted languages (JavaScript/TypeScript, Python, Ruby) and GitHub
  Actions workflows need nothing else. Java/Kotlin, C#, C/C++ and Rust are
  extracted without building (`--build-mode=none`). Go and Swift need their
  toolchain on `PATH` (`autobuild`). A language that cannot be extracted is
  a diagnostic in the report, not a failed scan.
- Each `codeql` step gets the full `--timeout`; a large project can take
  several minutes per language, and the live progress (below) shows what
  CodeQL is doing.

The CodeQL CLI is free for open-source projects and academic research; using
it on other code needs a GitHub Advanced Security licence — see
[GitHub's terms](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md).
CodeQL has no Linux ARM build at the time of writing (x86-64 Linux, macOS
and Windows only).

#### Plumber, on the clone's pipeline

Plumber runs when the target has `.github/workflows` or a `.gitlab-ci.yml`,
and needs a git clone whose `origin` remote names GitHub or GitLab;
otherwise it is skipped (not failed). It analyses the workflows locally:
every issue (unpinned action, excessive permissions, template injection,
`pull_request_target` checkouts, unverified scripts, mutable images…) and
every attack path it builds becomes a finding, with the Plumber Score as a
diagnostic. Repository settings (branch protection) need a provider token:
with `GH_TOKEN` / `GITHUB_TOKEN` / `GH_ENTERPRISE_TOKEN` / `GITLAB_TOKEN` in
the environment that control runs too — those four variables are the only
thing of your environment Plumber sees, and no other scanner ever sees them.
Without a token the control is skipped on purpose, otherwise Plumber withholds
its score and every severity.

## Rule packs: exhaustive by default

Semgrep is only as good as the rules it is given. sast3uh looks at what the
target holds (languages from file names, notable files such as workflows,
lockfiles, compose or Kubernetes manifests) and passes Semgrep every official
registry pack that applies, from a catalogue measured against the registry:
the curated multi-language sets (`p/default`, `p/security-audit`,
`p/owasp-top-ten`, `p/cwe-top-25`, `p/gitlab`, `p/trailofbits`, `p/ci`…), the
secrets packs (`p/secrets`, `p/gitleaks`), the injection packs (SQL, XSS,
command injection, JWT, insecure transport), supply-chain and AI packs, and
the language and framework packs of every language found (Python/Django/
Flask, JavaScript/Node/Express/React, Java/FindSecBugs/Spring, Go, Ruby/
Rails, PHP, C#, C/C++/Flawfinder, Rust, Terraform, Docker, Kubernetes,
GitHub Actions…). Packs that are empty without a Pro login, meta or test
packs, strict subsets and style-only packs are left out. Semgrep
deduplicates a rule shared by several packs, so overlap never doubles a
finding.

- `--semgrep-profile exhaustive` (default): every non-style pack, including
  the audit-oriented, community and correctness ones.
- `--semgrep-profile security`: the security packs only — fewer findings.
- `--semgrep-config <CONFIG>` (repeatable): your own list, no selection.
- `sast3uh packs [DIR]`: what the selection would be, and why.

Bearer runs both of its engines (`--scanner sast,secrets`); Trivy runs all
four of its scanners (`vuln,misconfig,secret,license`), dev dependencies
included, with comprehensive detection and license reading from file headers
in the exhaustive profile, and cached databases only under `--offline`;
Luacheck runs with `std = max` and honours the project's `.luacheckrc`.
CodeQL runs `database create` (no build where CodeQL allows it) then
`database analyze` with `codeql/<language>-queries:codeql-suites/<language>-security-extended.qls`
per language; Plumber runs `analyze --min-points 0` with every control.

## Comment markers and suppression comments

Two passes of sast3uh's own run after the scanners, on request. Both are
plain whole-word, case-insensitive searches over every text file of the
target (the same directories as the detector are skipped: `.git`,
`node_modules`, `target`, `vendor`, `dist`…; binaries and files over 4 MiB
too), and each hit says the file, the line and the column.

- `--comments` reports the markers developers leave behind — `TODO`, `to do`,
  `FIXME`, `fix me`, `to fix`, `HACK`, `XXX`, `bypass`, `kludge`,
  `workaround` (hyphen and underscore spellings included) — as `comments`
  findings at severity *info*, one per line, with the line as snippet.
- `--suppressions report` reports every inline comment that silences a
  scanner as a `suppressions` finding at severity *low*, with the rule it
  names in `extra.argument`; `--suppressions ignore` does that and disables
  the suppressions where the scanner allows it, so that the silenced
  findings come back in the report:

| Scanner  | Comment                                      | Placement                   | `ignore` mode                             |
| -------- | -------------------------------------------- | --------------------------- | ----------------------------------------- |
| semgrep  | `nosemgrep` / `nosem`, `: rule-id`           | same line or the line above | `--disable-nosem`: the findings come back |
| bearer   | `bearer:disable rule_id`                     | the line above              | no switch: the comment is reported        |
| trivy    | `trivy:ignore:AVD-…`, `tfsec:ignore:…`       | the line above              | no switch: the comment is reported        |
| luacheck | `-- luacheck: ignore`, `no unused`, `push`…  | same line or the closure    | no switch: the comment is reported        |
| codeql   | `lgtm[query-id]`, `lgtm`, `codeql[query-id]` | the alert's line            | the suppression queries are not run       |
| plumber  | none (exceptions live in `.plumber.yaml`)    |                             |                                           |
| others   | `nosec`, `NOSONAR`, `noqa`, `nolint`…        | see below                   | reported under `other`                    |

The "others" row covers the suppression comments of tools sast3uh does not
drive but that are common in code bases: `nosec` (Bandit, gosec),
`NOSONAR`, `noqa`, `nolint`, `gitleaks:allow`, `checkov:skip`, `pragma:
allowlist secret`, `trufflehog:ignore`.

By default (`honour`) each scanner applies its own comments; a finding it
still reports stays flagged `suppressed`, out of the counts and of the exit
code. For CodeQL that means running the pack's `AlertSuppression` queries
next to the suite (checked with `codeql resolve queries` first), as GitHub
code scanning does — without them a `lgtm[…]` comment would be silently
ignored.

## What a finding carries

Everything the scanner said: severity and confidence, rule id, title and
message, file with line and column ranges, CWE and OWASP, categories and
tags (PII groups, data types, technologies), the code snippet, a suggested
fix, references and the rule link, the data flow from source to sink, the
scanner's fingerprint, whether the code suppresses it (`nosemgrep`), and
every other field under `extra` keyed by the scanner's own name. Each tool
run also records the files it scanned or skipped and the diagnostics it
raised (rules that errored). A finding two scanners agree on is one entry
that keeps both tools' details.

## Usage

```text
sast3uh scan [DIR] [options]      # run every available scanner
sast3uh tools [--offline]         # installed / latest version of each scanner
sast3uh packs [DIR]               # languages found and Semgrep packs selected

  -f, --format <text|json|yaml|xml|html>   guessed from --output's extension
  -o, --output <FILE>                      atomic write; stdout otherwise
  -t, --tools <semgrep,bearer,trivy,codeql,plumber,luacheck>  subset, registry order
      --semgrep-config <CONFIG>            repeatable (p/rust, rules.yml…); replaces the selection
      --semgrep-profile <exhaustive|security>  how many packs the selection takes (default: exhaustive)
      --fail-on <severity>                 exit 1 at or above (default: info)
      --timeout <seconds>                  per scanner (default: 600)
      --update <ask|always|never>          when a scanner is behind (default: ask)
      --offline                            no GitHub lookup at all
            --no-dedup                           keep every finding
      --comments                           also report TODO / FIXME / HACK / XXX / bypass… comments
      --suppressions <honour|report|ignore>  what to do with nosemgrep, bearer:disable… comments (default: honour)
```

Exit codes: `0` clean · `1` findings at or above `--fail-on` · `2` usage
error · `3` could not run or a scanner failed (the report is still written).

On a terminal the scanners show their own progress: their standard error is
echoed as it comes (Bearer's progress bar, Semgrep's status, CodeQL's query
counter…) and a `<tool>: still running (1m02s)` line appears after 15
seconds of silence, so a long scan is never a blank screen. Through a pipe
or in CI the scanners run quiet and only sast3uh's own lines are printed.

The install/update prompt only appears on a terminal; a non-interactive run
(CI, a pipe) never changes the machine and prints the `mise use` command to
run instead. `--update always` is the explicit opt-in; `--update never`
only reports. Without mise on `PATH` there is no version check at all.

## How it stays safe

- Every scanner is spawned with an argument list (never a shell), an
  environment reduced to `PATH`/`HOME`/locale, the target as working
  directory, a timeout and a cap on captured output. Intermediate files
  (CodeQL databases, Plumber's report) live in a private scratch directory
  deleted after the run, never in the scanned project.
- Scanner output is untrusted: parsed into typed structs, paths that could
  escape the target are dropped, a malformed report fails that tool only.
- XML and HTML reports escape every value; the HTML page carries a
  Content-Security-Policy that forbids scripts and links only to
  `http(s)` URLs.
- No network code: version lookups and installs are mise's job (its aqua
  backend verifies checksums), and mise is the only child that sees the
  `MISE_*` / `GITHUB_TOKEN` variables — Plumber excepted, which receives
  the provider token it is documented to read, and nothing else.

## Development

```bash
pre-commit install              # once per clone — the commit gate (needs mise: the
                                # Plumber hook runs the version pinned in .mise.toml)
cargo test --all-features       # unit + end-to-end tests (stub scanners, recorded fixtures)
cargo clippy --all-targets --all-features -- -D warnings
```

The full gate (what runs on every commit, and what CI adds) is in
[CLAUDE.md](CLAUDE.md). Security reports: see [SECURITY.md](SECURITY.md).
