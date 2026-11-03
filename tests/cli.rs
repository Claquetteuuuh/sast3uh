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
                // Plumber writes its report where `--output` says; CodeQL creates a database
                // (nothing to replay) then analyses it into the `--output` SARIF.
                "plumber" => format!(
                    "#!/bin/sh\ncase \"$1\" in version) cat '{}';; analyze) while [ $# -gt 0 ]; do if [ \"$1\" = --output ]; then cp '{}' \"$2\"; fi; shift; done; exit 0;; *) exit 2;; esac\n",
                    fx.join("plumber/version.txt").display(),
                    fx.join("plumber/report.json").display()
                ),
                "codeql" => format!(
                    "#!/bin/sh\ncase \"$1\" in version) cat '{}';; database) if [ \"$2\" = create ]; then exit 0; fi; while [ $# -gt 0 ]; do if [ \"$1\" = --output ]; then cp '{}' \"$2\"; fi; shift; done; exit 0;; *) exit 2;; esac\n",
                    fx.join("codeql/version.txt").display(),
                    fx.join("codeql/report.sarif").display()
                ),
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
        .args(["scan", "--offline", "--tools", "gosec"])
        .arg(dir.path())
        .assert()
        .code(3)
        .stderr(predicate::str::contains("unknown tool `gosec`"));
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
                .and(predicate::str::contains("Security profile")),
        );
    bin()
        .args(["packs", "--semgrep-profile", "exhaustive"])
        .arg(dir.path())
        .env("PATH", "")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Exhaustive profile"));
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
                .and(predicate::str::contains("codeql"))
                .and(predicate::str::contains("plumber"))
                .and(predicate::str::contains("missing")),
        );
}

#[cfg(unix)]
#[test]
fn codeql_and_plumber_run_on_a_project_with_code_and_workflows() {
    let stubs = Stubs::new(&["codeql", "plumber"]);
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join(".github/workflows")).expect("mkdir");
    std::fs::write(dir.path().join(".github/workflows/ci.yml"), "on: push\n").expect("write");
    std::fs::write(dir.path().join("app.js"), "console.log(1)\n").expect("write");
    let output = bin()
        .args([
            "scan",
            "--offline",
            "--format",
            "json",
            "--tools",
            "codeql",
            "--tools",
            "plumber",
        ])
        .arg(dir.path())
        .env("PATH", &stubs.path)
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains("codeql 2.27.3")
                .and(predicate::str::contains("plumber 0.7.17"))
                .and(predicate::str::contains(
                    "codeql: security-extended suite for javascript, actions",
                ))
                .and(predicate::str::contains(
                    "codeql: javascript: extracting the database",
                ))
                .and(predicate::str::contains(
                    "codeql: actions: running the security-extended suite",
                ))
                .and(predicate::str::contains("plumber: CI/CD trust policy")),
        )
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).expect("json report");
    let tools = json["tools"].as_array().expect("tools");
    assert_eq!(tools.len(), 2, "{json}");
    assert!(
        tools.iter().all(|t| t["status"]["state"] == "completed"),
        "{json}"
    );
    assert_eq!(tools[0]["tool"], "codeql");
    assert_eq!(
        tools[0]["findings"], 10,
        "5 per language, two languages: {json}"
    );
    assert_eq!(tools[1]["tool"], "plumber");
    assert_eq!(
        tools[1]["findings"], 22,
        "17 issues and 5 attack paths: {json}"
    );
    // The stub replays the same SARIF for both languages: the five exact duplicates merge.
    assert_eq!(json["summary"]["duplicates_removed"], 5, "{json}");
    assert_eq!(json["summary"]["total"], 27, "{json}");
    assert!(
        json["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["tool"] == "plumber"
                && f["rule_id"] == "attack-path"
                && f["flow"].is_array()),
        "{json}"
    );
    assert!(
        json["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["tool"] == "codeql"
                && f["rule_id"] == "js/reflected-xss"
                && f["cwes"][0] == 79),
        "{json}"
    );
}

#[cfg(unix)]
#[test]
fn comment_markers_and_suppression_comments_are_swept_on_request() {
    let stubs = Stubs::new(&["luacheck"]);
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("a.lua"),
        "-- TODO: later\nlocal x = 1 -- luacheck: ignore\n",
    )
    .expect("write");
    std::fs::write(dir.path().join("b.py"), "eval(x)  # nosemgrep: rule-id\n").expect("write");
    let output = bin()
        .args([
            "scan",
            "--offline",
            "--format",
            "json",
            "--tools",
            "luacheck",
            "--comments",
            "--suppressions",
            "report",
        ])
        .arg(dir.path())
        .env("PATH", &stubs.path)
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains("comments: 1 finding(s) in 2 file(s)").and(
                predicate::str::contains("suppressions: 2 finding(s) in 2 file(s)"),
            ),
        )
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).expect("json report");
    let names: Vec<&str> = json["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["tool"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec!["luacheck", "comments", "suppressions"],
        "{json}"
    );
    let findings = json["findings"].as_array().unwrap();
    assert!(
        findings.iter().any(|f| f["tool"] == "comments"
            && f["rule_id"] == "todo"
            && f["path"] == "a.lua"
            && f["line"] == 1
            && f["severity"] == "info"),
        "{json}"
    );
    assert!(
        findings.iter().any(|f| f["tool"] == "suppressions"
            && f["rule_id"] == "semgrep"
            && f["path"] == "b.py"
            && f["line"] == 1
            && f["extra"]["argument"] == "rule-id"),
        "{json}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f["tool"] == "suppressions" && f["rule_id"] == "luacheck" && f["line"] == 2),
        "{json}"
    );

    let output = bin()
        .args([
            "scan",
            "--offline",
            "--format",
            "json",
            "--tools",
            "luacheck",
        ])
        .arg(dir.path())
        .env("PATH", &stubs.path)
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).expect("json report");
    assert_eq!(
        json["tools"].as_array().unwrap().len(),
        1,
        "no sweep by default: {json}"
    );
}

#[cfg(unix)]
#[test]
fn codeql_and_plumber_are_skipped_on_a_project_without_code_or_workflows() {
    let stubs = Stubs::new(&["codeql", "plumber"]);
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("notes.txt"), "nothing to scan\n").expect("write");
    bin()
        .args([
            "scan",
            "--offline",
            "--tools",
            "codeql",
            "--tools",
            "plumber",
        ])
        .arg(dir.path())
        .env("PATH", &stubs.path)
        .assert()
        .code(0)
        .stderr(
            predicate::str::contains("codeql: skipped: no language CodeQL supports").and(
                predicate::str::contains("plumber: skipped: no CI/CD configuration"),
            ),
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
    assert_eq!(json["schema_version"], 3);
    let tools = json["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 6);
    assert!(
        tools
            .iter()
            .filter(|t| t["tool"] != "codeql" && t["tool"] != "plumber")
            .all(|t| t["status"]["state"] == "completed"),
        "{json}"
    );
    assert!(
        tools
            .iter()
            .filter(|t| t["tool"] == "codeql" || t["tool"] == "plumber")
            .all(|t| t["status"]["state"] == "skipped"),
        "not stubbed, so not installed: {json}"
    );
    // 9 + 7 + 6 findings; Bearer and Semgrep agree on four lines (stripe key, eval,
    // subprocess shell=True, pickle), each merged into one finding at the worst severity.
    assert_eq!(json["summary"]["duplicates_removed"], 4, "{json}");
    assert_eq!(
        json["summary"]["total"],
        18 + 24 - 1,
        "trivy adds 24 findings on files nobody else scans; one low-confidence Semgrep \
         finding nobody corroborates is set aside: {json}"
    );
    assert_eq!(json["summary"]["filtered"], 1, "{json}");
    assert_eq!(
        json["findings"].as_array().unwrap().len(),
        42,
        "set aside, not dropped"
    );
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
        ("json", "\"schema_version\": 3"),
        ("yaml", "schema_version: 3"),
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
    assert_eq!(json["summary"]["total"], 12);
    assert_eq!(
        json["summary"]["filtered"], 4,
        "low-confidence, uncorroborated: {json}"
    );
    assert_eq!(
        json["findings"].as_array().unwrap().len(),
        16,
        "set aside, not dropped"
    );
}

#[cfg(unix)]
fn triage_run(stubs: &Stubs, dir: &Path, extra: &[&str], code: i32) -> serde_json::Value {
    let output = bin()
        .args([
            "scan",
            "--offline",
            "--format",
            "json",
            "--tools",
            "semgrep",
            "--tools",
            "bearer",
        ])
        .args(extra)
        .arg(dir)
        .env("PATH", &stubs.path)
        .assert()
        .code(code)
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).expect("json report")
}

#[cfg(unix)]
#[test]
fn triage_flags_set_findings_aside_with_a_reason_and_low_confidence_brings_them_back() {
    let stubs = Stubs::new(&["semgrep", "bearer"]);
    let dir = tempfile::tempdir().expect("tempdir");
    let default = triage_run(&stubs, dir.path(), &[], 1);
    let everything = triage_run(&stubs, dir.path(), &["--min-confidence", "low"], 1);
    assert_eq!(everything["summary"]["filtered"], 0, "{everything}");
    assert!(
        default["summary"]["total"].as_u64() < everything["summary"]["total"].as_u64(),
        "{default}"
    );
    let aside: Vec<_> = default["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["filtered"].is_string())
        .collect();
    assert!(!aside.is_empty());
    assert!(
        aside
            .iter()
            .all(|f| f["filtered"] == "confidence low below medium" && f["tool"] == "semgrep"),
        "{default}"
    );
    let corroborated = triage_run(&stubs, dir.path(), &["--corroborated"], 1);
    assert_eq!(
        corroborated["summary"]["total"], 4,
        "the four Semgrep+Bearer merges: {corroborated}"
    );
    assert!(
        corroborated["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["filtered"] == "reported by one tool only"),
        "{corroborated}"
    );
    let flowing = triage_run(&stubs, dir.path(), &["--with-flow"], 1);
    assert!(
        flowing["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["filtered"] == "no data flow"),
        "{flowing}"
    );
}

#[cfg(unix)]
#[test]
fn a_baseline_and_an_ignore_file_hide_what_is_known() {
    let stubs = Stubs::new(&["semgrep", "bearer"]);
    let dir = tempfile::tempdir().expect("tempdir");
    let scratch = tempfile::tempdir().expect("tempdir");
    let everything = triage_run(&stubs, dir.path(), &["--min-confidence", "low"], 1);
    let baseline = scratch.path().join("baseline.json");
    std::fs::write(&baseline, everything.to_string()).expect("baseline");
    let news = triage_run(
        &stubs,
        dir.path(),
        &["--baseline", baseline.to_str().unwrap()],
        0,
    );
    assert_eq!(
        news["summary"]["total"], 0,
        "nothing new since the baseline: {news}"
    );
    assert!(
        news["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["filtered"] == "already in the baseline"),
        "the baseline wins over the confidence floor: {news}"
    );

    let first = &everything["findings"][0];
    let identity = first["fingerprint"].as_str().map_or_else(
        || {
            format!(
                "{}:{}:{}:{}",
                first["tool"].as_str().unwrap(),
                first["rule_id"].as_str().unwrap(),
                first["path"].as_str().unwrap(),
                first["line"]
            )
        },
        str::to_owned,
    );
    let ignore = scratch.path().join(".sast3uh-ignore");
    bin()
        .args(["ignore", "--file"])
        .arg(&ignore)
        .args(["--reason", "reviewed, false positive"])
        .arg(&identity)
        .assert()
        .code(0)
        .stderr(predicate::str::contains("1 identity added to"));
    let text = std::fs::read_to_string(&ignore).expect("ignore file");
    assert!(
        text.contains(&identity) && text.contains("# reviewed, false positive"),
        "{text}"
    );
    let ignored = triage_run(
        &stubs,
        dir.path(),
        &[
            "--ignore-file",
            ignore.to_str().unwrap(),
            "--min-confidence",
            "low",
        ],
        1,
    );
    assert_eq!(ignored["summary"]["filtered"], 1, "{ignored}");
    assert_eq!(
        ignored["summary"]["total"],
        everything["summary"]["total"].as_u64().unwrap() - 1
    );
    bin()
        .args(["scan", "--offline", "--ignore-file", "/nonexistent/ignore"])
        .arg(dir.path())
        .env("PATH", &stubs.path)
        .assert()
        .code(3)
        .stderr(predicate::str::contains("reading the ignore file"));
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
