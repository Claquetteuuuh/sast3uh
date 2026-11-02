//! Bearer: SAST plus sensitive-data flows (`--format json` output, one list per severity).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use serde::Deserialize;

use super::{
    Outcome, ParseError, Parsed, ScanOptions, Scanner, cwe_number, cwes, failure_reason,
    first_json, os_args,
};
use crate::exec::Output;
use crate::model::{Finding, Severity, normalize_reported_path};
use crate::update::{UpdateContext, UpdatePlan, UpdateStep};
use crate::version::Version;

/// The Bearer adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct Bearer;

/// What Bearer prints when the tree holds no file in a language it has rules for.
const NO_RULES: &str = "0 rules found";

impl Scanner for Bearer {
    fn name(&self) -> &'static str {
        "bearer"
    }

    fn binary(&self) -> &'static str {
        "bearer"
    }

    fn purpose(&self) -> &'static str {
        "SAST + sensitive data (JS/TS, Python, Go, Java, Ruby, PHP)"
    }

    fn github_repo(&self) -> &'static str {
        "Bearer/bearer"
    }

    fn version_args(&self) -> Vec<OsString> {
        os_args(&["version", "--disable-version-check"])
    }

    fn parse_version(&self, output: &Output) -> Option<Version> {
        // The banner may be preceded by an "outdated version, vX is available" nag whose
        // version must not be mistaken for the installed one.
        let text = format!("{}\n{}", output.stdout_text(), output.stderr_text());
        text.lines()
            .find(|line| line.trim_start().starts_with("bearer version"))
            .and_then(Version::parse)
            .or_else(|| Version::parse(&text))
    }

    fn scan_args(&self, _options: &ScanOptions) -> Vec<OsString> {
        os_args(&[
            "scan",
            ".",
            "--format",
            "json",
            "--quiet",
            "--exit-code",
            "0",
            "--hide-progress-bar",
            "--disable-version-check",
        ])
    }

    fn env(&self) -> Vec<(OsString, OsString)> {
        vec![("NO_COLOR".into(), "1".into())]
    }

    fn interpret(&self, output: &Output) -> Outcome {
        if output.timed_out {
            return Outcome::Failed(failure_reason(output));
        }
        if output.stderr_text().contains(NO_RULES) {
            return Outcome::Skipped("no file in a language Bearer has rules for".to_owned());
        }
        if output.stdout_truncated {
            return Outcome::Failed("output exceeded the capture limit".to_owned());
        }
        match parse(&output.stdout) {
            Ok(parsed) => Outcome::Completed {
                findings: parsed.findings,
                warnings: parsed.warnings,
            },
            Err(err) => Outcome::Failed(format!("{}; {err}", failure_reason(output))),
        }
    }

    fn update_plan(&self, ctx: &UpdateContext<'_>) -> UpdatePlan {
        if ctx.find("brew").is_some() && ctx.installed_path.to_string_lossy().contains("/Cellar/") {
            return UpdatePlan::command(
                format!("upgrade bearer to {} with Homebrew", ctx.latest),
                "brew",
                &["upgrade", "bearer"],
            );
        }
        match release_asset(std::env::consts::OS, std::env::consts::ARCH, &ctx.latest) {
            Some(asset) => UpdatePlan {
                summary: format!(
                    "download bearer {} from GitHub releases, verify its SHA-256 against checksums.txt, replace {}",
                    ctx.latest,
                    ctx.installed_path.display()
                ),
                steps: vec![UpdateStep::ReleaseBinary {
                    repo: self.github_repo().to_owned(),
                    tag: format!("v{}", ctx.latest),
                    asset,
                    checksums_asset: "checksums.txt".to_owned(),
                    member: Some(
                        if std::env::consts::OS == "windows" {
                            "bearer.exe"
                        } else {
                            "bearer"
                        }
                        .to_owned(),
                    ),
                    destination: ctx.installed_path.to_path_buf(),
                }],
            },
            None => UpdatePlan::manual(format!(
                "no prebuilt bearer {} for {}/{}: see https://docs.bearer.com/reference/installation/",
                ctx.latest,
                std::env::consts::OS,
                std::env::consts::ARCH
            )),
        }
    }
}

/// The release archive for this platform, following Bearer's naming
/// (`bearer_2.1.3_linux_amd64.tar.gz`).
pub fn release_asset(os: &str, arch: &str, version: &Version) -> Option<String> {
    let os = match os {
        "linux" => "linux",
        "macos" => "darwin",
        "windows" => "windows",
        _ => return None,
    };
    let arch = match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => return None,
    };
    Some(format!("bearer_{version}_{os}_{arch}.tar.gz"))
}

#[derive(Deserialize)]
struct RawItem {
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    documentation_url: Option<String>,
    #[serde(default)]
    line_number: Option<u32>,
    #[serde(default)]
    filename: String,
    #[serde(default)]
    full_filename: Option<String>,
    #[serde(default)]
    cwe_ids: Vec<String>,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default)]
    source: Option<RawRange>,
}

#[derive(Deserialize, Default)]
struct RawRange {
    #[serde(default)]
    start: Option<u32>,
    #[serde(default)]
    end: Option<u32>,
    #[serde(default)]
    column: Option<RawColumn>,
}

#[derive(Deserialize, Default)]
struct RawColumn {
    #[serde(default)]
    start: Option<u32>,
}

/// Parse `bearer scan --format json` output (a banner before the JSON is tolerated).
///
/// # Errors
///
/// [`ParseError`] when there is no JSON object in the output.
pub fn parse(bytes: &[u8]) -> Result<Parsed, ParseError> {
    let json = first_json(bytes);
    if json.is_empty() {
        return Err(ParseError::Empty);
    }
    let buckets: BTreeMap<String, Vec<RawItem>> = serde_json::from_slice(json)?;
    let mut parsed = Parsed::default();
    for (bucket, items) in buckets {
        let severity = bucket_severity(&bucket);
        for raw in items {
            let reported = raw
                .full_filename
                .clone()
                .unwrap_or_else(|| raw.filename.clone());
            match normalize_reported_path(&reported) {
                Some(path) => parsed.findings.push(to_finding(raw, severity, path)),
                None => parsed.warnings.push(format!(
                    "dropped {}: path `{reported}` is outside the target",
                    raw.id
                )),
            }
        }
    }
    parsed.findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.line.cmp(&b.line))
    });
    Ok(parsed)
}

fn bucket_severity(bucket: &str) -> Severity {
    match bucket.trim().to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn to_finding(raw: RawItem, severity: Severity, path: PathBuf) -> Finding {
    let source = raw.source.unwrap_or_default();
    let line = raw.line_number.or(source.start).filter(|l| *l > 0);
    let message = first_paragraph(&raw.description).unwrap_or_else(|| raw.title.clone());
    Finding {
        tool: "bearer".to_owned(),
        also_reported_by: Vec::new(),
        rule_id: raw.id,
        severity,
        title: raw.title,
        message,
        path,
        line,
        end_line: source.end.filter(|l| *l > 0),
        column: source.column.and_then(|c| c.start).filter(|c| *c > 0),
        cwes: cwes(raw.cwe_ids.iter().map(|c| cwe_number(c))),
        url: raw.documentation_url.filter(|u| !u.is_empty()),
        fingerprint: raw.fingerprint.filter(|f| !f.is_empty()),
    }
}

/// The first prose line of a Markdown description (headings and blank lines skipped), cut at
/// 300 characters.
fn first_paragraph(markdown: &str) -> Option<String> {
    let line = markdown
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("```"))?;
    let mut text: String = line.chars().take(300).collect();
    if text.len() < line.len() {
        text.push('…');
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::tests::output;

    const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/bearer/report.json");
    const VERSION: &str = include_str!("../../tests/fixtures/bearer/version.txt");

    #[test]
    fn parses_the_recorded_report() {
        let parsed = parse(FIXTURE).unwrap();
        assert_eq!(parsed.findings.len(), 7);
        assert!(parsed.warnings.is_empty());
        let eval = parsed
            .findings
            .iter()
            .find(|f| f.rule_id == "javascript_lang_eval_user_input")
            .unwrap();
        assert_eq!(eval.tool, "bearer");
        assert_eq!(eval.severity, Severity::Critical);
        assert_eq!(eval.title, "Unsanitized user input in 'eval' type function");
        assert!(
            eval.message.starts_with("Allowing user input"),
            "{}",
            eval.message
        );
        assert_eq!(eval.path, PathBuf::from("src/app.js"));
        assert_eq!(eval.line, Some(7));
        assert_eq!(eval.end_line, Some(7));
        assert_eq!(eval.column, Some(3));
        assert_eq!(eval.cwes, vec![95]);
        assert_eq!(
            eval.url.as_deref(),
            Some("https://docs.bearer.com/reference/rules/javascript_lang_eval_user_input")
        );
        assert_eq!(
            eval.fingerprint.as_deref(),
            Some("efad3d49fc4e4382288911a8b41b6ea9_0")
        );
        assert_eq!(
            parsed
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Medium)
                .count(),
            3
        );
        assert_eq!(
            parsed.findings.first().map(|f| f.severity),
            Some(Severity::Critical)
        );
    }

    #[test]
    fn tolerates_a_banner_and_unknown_buckets() {
        let json = br#"Analyzing codebase
{"warning":[{"id":"x","title":"T","filename":"a.rb","line_number":3}],"weird":[{"id":"y","filename":"b.rb"}]}"#;
        let parsed = parse(json).unwrap();
        assert_eq!(parsed.findings.len(), 2);
        assert!(parsed.findings.iter().all(|f| f.severity == Severity::Info));
        let x = parsed.findings.iter().find(|f| f.rule_id == "x").unwrap();
        assert_eq!(
            x.message, "T",
            "falls back to the title without a description"
        );
        assert_eq!(x.line, Some(3));
        let y = parsed.findings.iter().find(|f| f.rule_id == "y").unwrap();
        assert_eq!(y.line, None);
    }

    #[test]
    fn drops_findings_whose_path_escapes_the_target() {
        let json = br#"{"high":[{"id":"x","title":"T","filename":"/etc/passwd"}]}"#;
        let parsed = parse(json).unwrap();
        assert!(parsed.findings.is_empty());
        assert_eq!(parsed.warnings.len(), 1);
    }

    #[test]
    fn malformed_output_is_a_parse_error_not_a_panic() {
        assert!(matches!(parse(b""), Err(ParseError::Empty)));
        assert!(matches!(
            parse(b"Analyzing codebase\n"),
            Err(ParseError::Empty)
        ));
        assert!(matches!(
            parse(b"{\"critical\": [{"),
            Err(ParseError::Json(_))
        ));
        assert!(matches!(
            parse(b"{\"critical\": 3}"),
            Err(ParseError::Json(_))
        ));
        let truncated = &FIXTURE[..FIXTURE.len() / 3];
        assert!(matches!(parse(truncated), Err(ParseError::Json(_))));
        assert!(parse(b"{}").unwrap().findings.is_empty());
    }

    #[test]
    fn first_paragraph_skips_headings_and_caps_length() {
        assert_eq!(
            first_paragraph("## Description\n\nHello world.\n\nMore"),
            Some("Hello world.".into())
        );
        assert_eq!(first_paragraph("# only a heading"), None);
        let long = "x".repeat(400);
        let got = first_paragraph(&long).unwrap();
        assert_eq!(got.chars().count(), 301);
        assert!(got.ends_with('…'));
    }

    #[test]
    fn interpret_skips_when_bearer_has_no_rules_for_the_tree() {
        let stderr = "Error: report error: 0 rules found for supported language, default rules could not be downloaded";
        match Bearer.interpret(&output(Some(1), b"Analyzing codebase\n{}\n", stderr)) {
            Outcome::Skipped(reason) => assert!(reason.contains("no file"), "{reason}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn interpret_completes_fails_and_times_out() {
        match Bearer.interpret(&output(Some(0), FIXTURE, "")) {
            Outcome::Completed { findings, .. } => assert_eq!(findings.len(), 7),
            other => panic!("{other:?}"),
        }
        assert!(
            matches!(Bearer.interpret(&output(Some(1), b"", "panic: boom")), Outcome::Failed(r) if r.contains("boom"))
        );
        let mut timed = output(None, b"", "");
        timed.timed_out = true;
        assert!(matches!(Bearer.interpret(&timed), Outcome::Failed(_)));
    }

    #[test]
    fn version_ignores_the_update_nag() {
        let v = Bearer
            .parse_version(&output(Some(0), VERSION.as_bytes(), ""))
            .unwrap();
        assert_eq!(v, Version::new(2, 1, 1));
        let v = Bearer
            .parse_version(&output(Some(0), b"", "bearer version 2.1.3, build abc"))
            .unwrap();
        assert_eq!(v, Version::new(2, 1, 3));
    }

    #[test]
    fn release_assets_follow_bearers_naming() {
        let v = Version::new(2, 1, 3);
        assert_eq!(
            release_asset("linux", "x86_64", &v).as_deref(),
            Some("bearer_2.1.3_linux_amd64.tar.gz")
        );
        assert_eq!(
            release_asset("macos", "aarch64", &v).as_deref(),
            Some("bearer_2.1.3_darwin_arm64.tar.gz")
        );
        assert_eq!(
            release_asset("windows", "x86_64", &v).as_deref(),
            Some("bearer_2.1.3_windows_amd64.tar.gz")
        );
        assert_eq!(release_asset("freebsd", "x86_64", &v), None);
        assert_eq!(release_asset("linux", "riscv64", &v), None);
    }

    #[test]
    fn scan_args_force_json_quiet_and_a_fixed_exit_code() {
        let args: Vec<String> = Bearer
            .scan_args(&ScanOptions::default())
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args[..2], ["scan", "."]);
        assert!(args.windows(2).any(|w| w == ["--format", "json"]));
        assert!(args.windows(2).any(|w| w == ["--exit-code", "0"]));
        assert!(args.contains(&"--disable-version-check".to_owned()));
    }
}
