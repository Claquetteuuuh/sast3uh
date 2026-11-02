# sasteuuuh

One SAST to run them all. A hardened Rust CLI that drives several static
analysers over a directory, parses what each one says, removes the
duplicates and writes a single report — text, JSON, YAML, XML or HTML —
with a single exit code. Before scanning it checks each scanner against its
latest GitHub release and offers to update it.

## Scanners

| Tool     | Covers                                                    | mise id                     |
| -------- | --------------------------------------------------------- | --------------------------- |
| semgrep  | SAST, 30+ languages, rule packs (`p/default` by default)  | `semgrep`                   |
| bearer   | SAST + sensitive data: JS/TS, Python, Go, Java, Ruby, PHP | `aqua:Bearer/bearer`        |
| luacheck | Lua linter: globals, unused, syntax                       | `ubi:lunarmodules/luacheck` |

Scanners are installed and updated through [mise](https://mise.jdx.dev):
sasteuuuh resolves each binary with `mise which` (falling back to `PATH`),
asks `mise latest` for the newest version and runs `mise use -g <id>@<v>`
when you say yes. It never downloads anything itself. A scanner that is
missing is offered for install; one that is behind is offered for update;
one that fails marks the report incomplete (exit 3). The same problem
reported by two scanners on the same line with a CWE in common is one
finding, at the worst severity, with both tools listed.

## Usage

```text
sasteuuuh scan [DIR] [options]      # run every available scanner
sasteuuuh tools [--offline]         # installed / latest version of each scanner

  -f, --format <text|json|yaml|xml|html>   guessed from --output's extension
  -o, --output <FILE>                      atomic write; stdout otherwise
  -t, --tools <semgrep,bearer,luacheck>    subset, registry order
      --semgrep-config <CONFIG>            repeatable (p/rust, rules.yml…)
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
pre-commit install              # once per clone — the commit gate
cargo test --all-features       # unit + end-to-end tests (stub scanners, recorded fixtures)
cargo clippy --all-targets --all-features -- -D warnings
```

The full gate (what runs on every commit, and what CI adds) is in
[CLAUDE.md](CLAUDE.md). Security reports: see [SECURITY.md](SECURITY.md).
