//! End-to-end tests of the built binary: the process boundary (exit codes, stdout vs stderr,
//! files written) that the in-process tests cannot see. The scanners are shell stubs that
//! replay the recorded fixtures, so nothing here depends on what is installed.

// `allow-*-in-tests` in clippy.toml covers `#[test]` bodies only; the helpers of an
// integration test crate need it spelled out.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;

fn bin() -> Command {
    Command::cargo_bin("sast3uh").expect("binary built by cargo")
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

/// Stub scanners on a private `PATH` (plus the system directories the stubs' `cat` needs).
#[cfg(unix)]
struct Stubs {
    dir: tempfile::TempDir,
    path: std::ffi::OsString,
}

#[cfg(unix)]
impl Stubs {
    fn new(tools: &[&str]) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let fx = fixtures();
        for tool in tools {
            let script = match *tool {
                "semgrep" => format!(
                    "#!/bin/sh\ncase \"$1\" in --version) echo 1.163.0;; *) cat '{}';; esac\n",
                    fx.join("semgrep/report.json").display()
                ),
                "bearer" => format!(
                    "#!/bin/sh\ncase \"$1\" in version) echo 'bearer version 2.1.1, build x';; *) cat '{}';; esac\n",
                    fx.join("bearer/report.json").display()
                ),
                // The same replay for the one on PATH and the one only mise knows about (its
                // file name keeps it off PATH): the install path end to end.
                "luacheck" | "luacheck-via-mise" => format!(
                    "#!/bin/sh\ncase \"$1\" in --version) cat '{}';; *) cat '{}'; exit 1;; esac\n",
                    fx.join("luacheck/version.txt").display(),
                    fx.join("luacheck/report.txt").display()
                ),
                "luacheck-broken" => "#!/bin/sh\ncase \"$1\" in --version) echo 'Luacheck: 1.2.0';; *) echo 'Critical error: boom'; exit 4;; esac\n".to_owned(),
                "trivy" => format!(
                    "#!/bin/sh\ncase \"$1\" in --version) cat '{}';; *) cat '{}';; esac\n",
                    fx.join("trivy/version.txt").display(),
                    fx.join("trivy/report.json").display()
                ),
                // A luacheck that is not on PATH (its file name differs) and that `mise which`
                // only reveals once `mise use` ran: the install path end to end.
                // mise: `which` knows luacheck-via-mise after a `use`, `latest` answers for the
                // three tools, `ls --json` says semgrep is managed as pipx:semgrep, `use`
                // records what it was asked.
                "mise" => format!(
                    "#!/bin/sh\ncase \"$1\" in\n  which) if [ \"$2\" = luacheck ] && [ -f '{d}/mise-use.log' ]; then echo '{d}/luacheck-via-mise'; else echo \"mise ERROR $2 is not a mise bin\" >&2; exit 1; fi;;\n  latest) case \"$2\" in *semgrep*) echo 1.183.0;; *bearer*) echo 2.1.3;; *luacheck*) echo 1.2.0;; *) exit 1;; esac;;\n  ls) echo '{{\"pipx:semgrep\":[{{\"version\":\"1.163.0\",\"installed\":true}}]}}';;\n  use) echo \"$3\" >> '{d}/mise-use.log'; echo \"mise ~/.config/mise/config.toml tools: $3\";;\n  *) exit 2;;\nesac\n",
                    d = dir.path().display()
                ),
                other => panic!("no stub for {other}"),
            };
            let name = tool.trim_end_matches("-broken");
            let path = dir.path().join(name);
            std::fs::write(&path, script).expect("stub");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        let path = std::env::join_paths([dir.path(), Path::new("/usr/bin"), Path::new("/bin")])
            .expect("path");
        Stubs { dir, path }
    }
}

#[test]
fn help_lists_the_subcommands() {
    bin()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("scan").and(predicate::str::contains("tools")));
}

#[test]
fn version_prints_the_crate_version() {
    bin()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn no_subcommand_is_a_usage_error() {
    bin()
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn unknown_subcommand_is_a_usage_error() {
    bin()
        .arg("frobnicate")
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty());
}

#[test]
fn scan_of_a_missing_directory_exits_3_with_a_message_on_stderr() {
    let dir = tempfile::tempdir().expect("tempdir");
    bin()
        .args(["scan", "--offline"])
        .arg(dir.path().join("missing"))
        .assert()
        .code(3)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("does not exist"));
}

#[test]
fn scan_of_a_file_exits_3() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("f");
    std::fs::write(&file, b"x").expect("write");
    bin()
        .args(["scan", "--offline"])
        .arg(&file)
        .assert()
        .code(3)
        .stderr(predicate::str::contains("not a directory"));
}

#[test]
fn scan_with_an_empty_path_skips_everything_and_exits_clean() {
    let dir = tempfile::tempdir().expect("tempdir");
    bin()
        .args(["scan", "--offline"])
        .arg(dir.path())
        .env("PATH", "")
        .assert()
        .code(0)
        .stdout(
            predicate::str::contains("not installed")
                .and(predicate::str::contains("Findings (0 unique")),
        )
        .stderr(predicate::str::contains("semgrep: not installed"));
}

#[test]
fn unknown_tool_exits_3() {
    let dir = tempfile::tempdir().expect("tempdir");
    bin()
        .args(["scan", "--offline", "--tools", "codeql"])
        .arg(dir.path())
        .assert()
        .code(3)
        .stderr(predicate::str::contains("unknown tool `codeql`"));
}

#[test]
fn packs_shows_the_target_languages_and_the_selected_packs() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join(".github/workflows")).expect("mkdir");
    std::fs::write(dir.path().join(".github/workflows/ci.yml"), b"on: push").expect("write");
    std::fs::write(dir.path().join("app.py"), b"print(1)").expect("write");
    std::fs::write(dir.path().join("index.ts"), b"export {}").expect("write");
    bin()
        .arg("packs")
        .arg(dir.path())
        .env("PATH", "")
        .assert()
        .code(0)
        .stdout(
            predicate::str::contains("python (1)")
                .and(predicate::str::contains("typescript (1)"))
                .and(predicate::str::contains("github-actions"))
                .and(predicate::str::contains("p/default"))
                .and(predicate::str::contains("p/python"))
                .and(predicate::str::contains("p/javascript"))
                .and(predicate::str::contains("p/github-actions"))
                .and(predicate::str::contains("p/gitleaks"))
                .and(predicate::str::contains("Exhaustive profile")),
        );
    bin()
        .args(["packs", "--semgrep-profile", "security"])
        .arg(dir.path())
        .env("PATH", "")
        .assert()
        .code(0)
        .stdout(
            predicate::str::contains("Security profile")
                .and(predicate::str::contains("p/replit-community").not()),
        );
    bin()
        .arg("packs")
        .arg(dir.path().join("missing"))
        .assert()
        .code(3)
        .stderr(predicate::str::contains("does not exist"));
}

#[test]
fn tools_lists_every_known_scanner_even_with_an_empty_path() {
    bin()
        .args(["tools", "--offline"])
        .env("PATH", "")
        .assert()
        .code(0)
        .stdout(
            predicate::str::contains("semgrep")
                .and(predicate::str::contains("bearer"))
                .and(predicate::str::contains("luacheck"))
                .and(predicate::str::contains("trivy"))
                .and(predicate::str::contains("missing")),
        );
}

#[cfg(unix)]
#[test]
fn scan_runs_the_stubs_merges_and_exits_1_on_findings() {
    let stubs = Stubs::new(&["semgrep", "bearer", "luacheck", "trivy"]);
    let dir = tempfile::tempdir().expect("tempdir");
    let output = bin()
        .args(["scan", "--offline", "--format", "json"])
        .arg(dir.path())
        .env("PATH", &stubs.path)
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains("semgrep 1.163.0")
                .and(predicate::str::contains("bearer 2.1.1")),
        )
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).expect("json report");
    assert_eq!(json["schema_version"], 2);
    assert_eq!(json["tools"].as_array().unwrap().len(), 4);
    assert!(
        json["tools"]
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t["status"]["state"] == "completed"),
        "{json}"
    );
    // 9 + 7 + 6 findings; Bearer and Semgrep agree on four lines (stripe key, eval,
    // subprocess shell=True, pickle), each merged into one finding at the worst severity.
    assert_eq!(json["summary"]["duplicates_removed"], 4, "{json}");
    assert_eq!(
        json["summary"]["total"],
        18 + 24,
        "trivy adds 24 findings on files nobody else scans: {json}"
    );
    assert_eq!(json["summary"]["critical"], 5 + 1, "{json}");
    assert_eq!(json["summary"]["high"], 1 + 12, "{json}");
    let merged: Vec<_> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["also_reported_by"].is_array())
        .collect();
    assert_eq!(merged.len(), 4, "{json}");
    assert!(
        merged
            .iter()
            .all(|f| f["also_reported_by"][0] == "bearer" && f["tool"] == "semgrep"),
        "{json}"
    );
}

#[cfg(unix)]
#[test]
fn scan_writes_the_report_file_in_the_format_of_its_extension() {
    let stubs = Stubs::new(&["luacheck"]);
    let dir = tempfile::tempdir().expect("tempdir");
    let report = dir.path().join("report.html");
    bin()
        .args(["scan", "--offline", "--tools", "luacheck", "--output"])
        .arg(&report)
        .arg(dir.path())
        .env("PATH", &stubs.path)
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("report written to"));
    let html = std::fs::read_to_string(&report).expect("report file");
    assert!(html.starts_with("<!doctype html>"), "{html}");
    assert!(html.contains("Content-Security-Policy"));
    assert!(html.contains("W211"));
}

#[cfg(unix)]
#[test]
fn fail_on_raises_the_gate() {
    let stubs = Stubs::new(&["luacheck"]);
    let dir = tempfile::tempdir().expect("tempdir");
    bin()
        .args([
            "scan",
            "--offline",
            "--tools",
            "luacheck",
            "--fail-on",
            "medium",
        ])
        .arg(dir.path())
        .env("PATH", &stubs.path)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("6 unique"));
}

#[cfg(unix)]
#[test]
fn every_format_is_produced() {
    let stubs = Stubs::new(&["luacheck"]);
    let dir = tempfile::tempdir().expect("tempdir");
    for (format, marker) in [
        ("text", "Summary:"),
        ("json", "\"schema_version\": 2"),
        ("yaml", "schema_version: 2"),
        ("xml", "<?xml"),
        ("html", "<!doctype html>"),
    ] {
        bin()
            .args([
                "scan",
                "--offline",
                "--tools",
                "luacheck",
                "--format",
                format,
            ])
            .arg(dir.path())
            .env("PATH", &stubs.path)
            .assert()
            .code(1)
            .stdout(predicate::str::contains(marker));
    }
}

#[cfg(unix)]
#[test]
fn a_broken_scanner_exits_3_and_is_marked_failed() {
    let stubs = Stubs::new(&["luacheck-broken"]);
    let dir = tempfile::tempdir().expect("tempdir");
    bin()
        .args([
            "scan",
            "--offline",
            "--tools",
            "luacheck",
            "--format",
            "xml",
        ])
        .arg(dir.path())
        .env("PATH", &stubs.path)
        .assert()
        .code(3)
        .stdout(predicate::str::contains(r#"state="failed""#).and(predicate::str::contains("boom")))
        .stderr(predicate::str::contains("incomplete"));
}

#[cfg(unix)]
#[test]
fn no_dedup_keeps_every_finding() {
    let stubs = Stubs::new(&["semgrep", "bearer"]);
    let dir = tempfile::tempdir().expect("tempdir");
    let output = bin()
        .args(["scan", "--offline", "--no-dedup", "--format", "json"])
        .arg(dir.path())
        .env("PATH", &stubs.path)
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).expect("json report");
    assert_eq!(json["summary"]["duplicates_removed"], 0);
    assert_eq!(json["summary"]["total"], 16);
}

#[cfg(unix)]
#[test]
fn an_outdated_scanner_is_updated_through_mise_with_update_always() {
    let stubs = Stubs::new(&["semgrep", "mise"]);
    let dir = tempfile::tempdir().expect("tempdir");
    bin()
        .args([
            "scan", "--tools", "semgrep", "--update", "always", "--format", "json",
        ])
        .arg(dir.path())
        .env("PATH", &stubs.path)
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains("semgrep: 1.163.0 installed, 1.183.0 available")
                .and(predicate::str::contains("tools: pipx:semgrep@1.183.0")),
        );
    let log = std::fs::read_to_string(stubs.dir.path().join("mise-use.log")).expect("mise use ran");
    assert_eq!(
        log.trim(),
        "pipx:semgrep@1.183.0",
        "the id mise already manages, pinned to the latest"
    );
}

#[cfg(unix)]
#[test]
fn a_missing_scanner_is_installed_through_mise_then_run() {
    let stubs = Stubs::new(&["luacheck-via-mise", "mise"]);
    let dir = tempfile::tempdir().expect("tempdir");
    let output = bin()
        .args([
            "scan", "--tools", "luacheck", "--update", "always", "--format", "json",
        ])
        .arg(dir.path())
        .env("PATH", &stubs.path)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("luacheck: installed at"))
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).expect("json report");
    assert_eq!(json["tools"][0]["status"]["state"], "completed", "{json}");
    assert_eq!(json["tools"][0]["findings"], 6);
    let log = std::fs::read_to_string(stubs.dir.path().join("mise-use.log")).expect("mise use ran");
    assert_eq!(log.trim(), "ubi:lunarmodules/luacheck@1.2.0");
}

#[cfg(unix)]
#[test]
fn a_non_interactive_run_never_installs_or_updates() {
    let stubs = Stubs::new(&["semgrep", "mise"]);
    let dir = tempfile::tempdir().expect("tempdir");
    bin()
        .args(["scan", "--tools", "semgrep,luacheck", "--format", "json"])
        .arg(dir.path())
        .env("PATH", &stubs.path)
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains(
                "semgrep: skipped; to do it later: mise use -g pipx:semgrep@1.183.0",
            )
            .and(predicate::str::contains(
                "luacheck: skipped; to do it later: mise use -g ubi:lunarmodules/luacheck@1.2.0",
            )),
        );
    assert!(
        !stubs.dir.path().join("mise-use.log").exists(),
        "stdin is not a terminal: no prompt, no change"
    );
}

#[cfg(unix)]
#[test]
fn tools_shows_installed_versions() {
    let stubs = Stubs::new(&["semgrep", "luacheck"]);
    bin()
        .args(["tools", "--offline"])
        .env("PATH", &stubs.path)
        .assert()
        .code(0)
        // Bearer is not stubbed: whatever the machine has (or not) is reported, so only the
        // stubbed lines are asserted.
        .stdout(predicate::str::contains("semgrep    1.163.0").and(predicate::str::contains("luacheck   1.2.0")).and(predicate::str::contains("\nbearer     ")));
}

#[cfg(unix)]
#[test]
fn tools_online_shows_latest_and_mise_ids() {
    let stubs = Stubs::new(&["semgrep", "mise"]);
    bin()
        .arg("tools")
        .env("PATH", &stubs.path)
        .assert()
        .code(0)
        .stdout(
            predicate::str::contains("semgrep    1.163.0    1.183.0    outdated")
                .and(predicate::str::contains("mise: pipx:semgrep"))
                .and(predicate::str::contains(
                    "luacheck   -          1.2.0      missing",
                ))
                .and(predicate::str::contains("mise: ubi:lunarmodules/luacheck")),
        );
}
