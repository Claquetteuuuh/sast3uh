# sasteuuuh

One SAST to run them all. A hardened Rust CLI that drives several static
analysers (SAST, SCA, IaC, secrets, licenses) over a directory, parses what each one says, removes the
duplicates and writes a single report — text, JSON, YAML, XML or HTML —
with a single exit code. Before scanning it checks each scanner against its
latest GitHub release and offers to update it.

## Scanners

| Tool     | Covers                                                            | mise id                     |
| -------- | ----------------------------------------------------------------- | --------------------------- |
| semgrep  | SAST, 30+ languages, rule packs (`p/default` by default)          | `semgrep`                   |
| bearer   | SAST + sensitive data: JS/TS, Python, Go, Java, Ruby, PHP         | `aqua:Bearer/bearer`        |
| trivy    | SCA (CVEs in lockfiles), IaC misconfigurations, secrets, licenses | `trivy`                     |
| luacheck | Lua linter: globals, unused, syntax                               | `ubi:lunarmodules/luacheck` |

Scanners are installed and updated through [mise](https://mise.jdx.dev):
sasteuuuh resolves each binary with `mise which` (falling back to `PATH`),
asks `mise latest` for the newest version and runs `mise use -g <id>@<v>`
when you say yes. It never downloads anything itself. A scanner that is
missing is offered for install; one that is behind is offered for update;
one that fails marks the report incomplete (exit 3). The same problem
reported by two scanners on the same line with a CWE in common is one
finding, at the worst severity, with both tools listed.

## Rule packs: exhaustive by default

Semgrep is only as good as the rules it is given. sasteuuuh looks at what the
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
- `sasteuuuh packs [DIR]`: what the selection would be, and why.

Bearer runs both of its engines (`--scanner sast,secrets`); Trivy runs all
four of its scanners (`vuln,misconfig,secret,license`), dev dependencies
included, with comprehensive detection and license reading from file headers
in the exhaustive profile, and cached databases only under `--offline`;
Luacheck runs with `std = max` and honours the project's `.luacheckrc`.

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
sasteuuuh scan [DIR] [options]      # run every available scanner
sasteuuuh tools [--offline]         # installed / latest version of each scanner
sasteuuuh packs [DIR]               # languages found and Semgrep packs selected

  -f, --format <text|json|yaml|xml|html>   guessed from --output's extension
  -o, --output <FILE>                      atomic write; stdout otherwise
  -t, --tools <semgrep,bearer,luacheck>    subset, registry order
      --semgrep-config <CONFIG>            repeatable (p/rust, rules.yml…); replaces the selection
      --semgrep-profile <exhaustive|security>  how many packs the selection takes (default: exhaustive)
      --fail-on <severity>                 exit 1 at or above (default: info)
      --timeout <seconds>                  per scanner (default: 600)
      --update <ask|always|never>          when a scanner is behind (default: ask)
      --offline                            no GitHub lookup at all
      --no-dedup                           keep every finding
```

Exit codes: `0` clean · `1` findings at or above `--fail-on` · `2` usage
error · `3` could not run or a scanner failed (the report is still written).

The install/update prompt only appears on a terminal; a non-interactive run
(CI, a pipe) never changes the machine and prints the `mise use` command to
run instead. `--update always` is the explicit opt-in; `--update never`
only reports. Without mise on `PATH` there is no version check at all.

## How it stays safe

- Every scanner is spawned with an argument list (never a shell), an
  environment reduced to `PATH`/`HOME`/locale, the target as working
  directory, a timeout and a cap on captured output.
- Scanner output is untrusted: parsed into typed structs, paths that could
  escape the target are dropped, a malformed report fails that tool only.
- XML and HTML reports escape every value; the HTML page carries a
  Content-Security-Policy that forbids scripts and links only to
  `http(s)` URLs.
- No network code: version lookups and installs are mise's job (its aqua
  backend verifies checksums), and mise is the only child that sees the
  `MISE_*` / `GITHUB_TOKEN` variables.

## Development

```bash
pre-commit install              # once per clone — the commit gate (needs mise: the
                                # Plumber hook runs the version pinned in .mise.toml)
cargo test --all-features       # unit + end-to-end tests (stub scanners, recorded fixtures)
cargo clippy --all-targets --all-features -- -D warnings
```

The full gate (what runs on every commit, and what CI adds) is in
[CLAUDE.md](CLAUDE.md). Security reports: see [SECURITY.md](SECURITY.md).
