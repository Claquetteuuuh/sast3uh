//! Semgrep: multi-language SAST driven by rule packs (`--json` output).

use std::ffi::OsString;

use serde::Deserialize;

use super::{
    Outcome, ParseError, Parsed, ScanOptions, Scanner, cwe_number, cwes, failure_reason, os_args,
    tail,
};
use crate::exec::Output;
use crate::model::{Finding, Severity, normalize_reported_path};
use crate::update::{UpdateContext, UpdatePlan};

/// The Semgrep adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct Semgrep;

impl Scanner for Semgrep {
    fn name(&self) -> &'static str {
        "semgrep"
    }

    fn binary(&self) -> &'static str {
        "semgrep"
    }

    fn purpose(&self) -> &'static str {
        "SAST, 30+ languages (rule packs)"
    }

    fn github_repo(&self) -> &'static str {
        "semgrep/semgrep"
    }

    fn version_args(&self) -> Vec<OsString> {
        os_args(&["--version"])
    }

    fn scan_args(&self, options: &ScanOptions) -> Vec<OsString> {
        let mut args = os_args(&[
            "scan",
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
        ]);
        for config in &options.semgrep_configs {
            args.push("--config".into());
            args.push(config.into());
        }
        args.push(".".into());
        args
    }

    fn env(&self) -> Vec<(OsString, OsString)> {
        vec![
            ("SEMGREP_SEND_METRICS".into(), "off".into()),
            ("NO_COLOR".into(), "1".into()),
        ]
    }

    fn interpret(&self, output: &Output) -> Outcome {
        if output.timed_out {
            return Outcome::Failed(failure_reason(output));
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
        if ctx.find("pipx").is_some() {
            return UpdatePlan::command(
                format!("upgrade semgrep to {} with pipx", ctx.latest),
                "pipx",
                &["upgrade", "semgrep"],
            );
        }
        if ctx.find("python3").is_some() {
            let pin = format!("semgrep=={}", ctx.latest);
            return UpdatePlan::command(
                format!("upgrade semgrep to {} with pip", ctx.latest),
                "python3",
                &["-m", "pip", "install", "--user", "--upgrade", &pin],
            );
        }
        UpdatePlan::manual(format!(
            "install pipx, then `pipx install semgrep=={}` (https://semgrep.dev/docs/getting-started/quickstart)",
            ctx.latest
        ))
    }
}

#[derive(Deserialize)]
struct Root {
    // Required on purpose: it is what makes `[]` or `{}` fail instead of reading as "clean".
    results: Vec<RawResult>,
    #[serde(default)]
    errors: Vec<RawError>,
}

#[derive(Deserialize)]
struct RawResult {
    check_id: String,
    path: String,
    #[serde(default)]
    start: Position,
    #[serde(default)]
    end: Option<Position>,
    #[serde(default)]
    extra: Extra,
}

#[derive(Deserialize, Default)]
struct Position {
    #[serde(default)]
    line: u32,
    #[serde(default)]
    col: u32,
}

#[derive(Deserialize, Default)]
struct Extra {
    #[serde(default)]
    message: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    metadata: Metadata,
    #[serde(default)]
    fingerprint: Option<String>,
}

#[derive(Deserialize, Default)]
struct Metadata {
    #[serde(default)]
    cwe: Option<OneOrMany>,
    #[serde(default)]
    source: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct RawError {
    #[serde(default)]
    level: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    rule_id: Option<String>,
}

/// Parse `semgrep --json` output.
///
/// # Errors
///
/// [`ParseError`] when the output is empty or not Semgrep's JSON.
pub fn parse(bytes: &[u8]) -> Result<Parsed, ParseError> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(ParseError::Empty);
    }
    let root: Root = serde_json::from_slice(bytes)?;
    let mut parsed = Parsed::default();
    for raw in root.results {
        match normalize_reported_path(&raw.path) {
            Some(path) => parsed.findings.push(to_finding(raw, path)),
            None => parsed.warnings.push(format!(
                "dropped {}: path `{}` is outside the target",
                raw.check_id, raw.path
            )),
        }
    }
    for err in root.errors {
        let first_line = err.message.lines().next().unwrap_or_default().trim();
        let rule = err.rule_id.map_or_else(String::new, |r| format!(" [{r}]"));
        parsed.warnings.push(format!(
            "{}{rule}: {}",
            err.level.trim(),
            tail(first_line, 200)
        ));
    }
    Ok(parsed)
}

fn to_finding(raw: RawResult, path: std::path::PathBuf) -> Finding {
    let cwe_list = match raw.extra.metadata.cwe {
        None => Vec::new(),
        Some(OneOrMany::One(s)) => vec![s],
        Some(OneOrMany::Many(v)) => v,
    };
    let title = raw
        .check_id
        .rsplit('.')
        .next()
        .unwrap_or(&raw.check_id)
        .to_owned();
    Finding {
        tool: "semgrep".to_owned(),
        also_reported_by: Vec::new(),
        rule_id: raw.check_id,
        severity: severity(&raw.extra.severity),
        title,
        message: raw.extra.message.trim().to_owned(),
        path,
        line: (raw.start.line > 0).then_some(raw.start.line),
        end_line: raw.end.map(|e| e.line).filter(|l| *l > 0),
        column: (raw.start.col > 0).then_some(raw.start.col),
        cwes: cwes(cwe_list.iter().map(|c| cwe_number(c))),
        url: raw.extra.metadata.source.filter(|s| !s.is_empty()),
        fingerprint: raw.extra.fingerprint.filter(|s| !s.is_empty()),
    }
}

fn severity(raw: &str) -> Severity {
    match raw.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "ERROR" | "HIGH" => Severity::High,
        "WARNING" | "MEDIUM" => Severity::Medium,
        "INFO" | "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::tests::output;
    use std::path::PathBuf;

    const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/semgrep/report.json");

    #[test]
    fn parses_the_recorded_report() {
        let parsed = parse(FIXTURE).unwrap();
        assert_eq!(parsed.findings.len(), 9);
        let eval = parsed
            .findings
            .iter()
            .find(|f| f.rule_id == "javascript.express.code.eval-express.eval-express")
            .unwrap();
        assert_eq!(eval.tool, "semgrep");
        assert_eq!(eval.severity, Severity::Critical);
        assert_eq!(eval.title, "eval-express");
        assert_eq!(eval.path, PathBuf::from("src/app.js"));
        assert_eq!(eval.line, Some(7));
        assert_eq!(eval.column, Some(8));
        assert_eq!(eval.end_line, Some(7));
        assert_eq!(eval.cwes, vec![94]);
        assert!(
            eval.url
                .as_deref()
                .unwrap()
                .starts_with("https://semgrep.dev/r/")
        );
        assert!(eval.fingerprint.is_some());
        assert!(!eval.message.is_empty());
        // The three internal matching errors are surfaced as warnings, not failures.
        assert_eq!(parsed.warnings.len(), 3, "{:?}", parsed.warnings);
        assert!(
            parsed.warnings.iter().all(|w| w.starts_with("warn [")),
            "{:?}",
            parsed.warnings
        );
    }

    #[test]
    fn maps_every_severity_level() {
        assert_eq!(severity("CRITICAL"), Severity::Critical);
        assert_eq!(severity("ERROR"), Severity::High);
        assert_eq!(severity("high"), Severity::High);
        assert_eq!(severity("WARNING"), Severity::Medium);
        assert_eq!(severity("INFO"), Severity::Low);
        assert_eq!(severity("LOW"), Severity::Low);
        assert_eq!(severity(""), Severity::Info);
    }

    #[test]
    fn cwe_may_be_a_string_or_a_list_and_paths_are_validated() {
        let json = br#"{"results":[
          {"check_id":"a.b","path":"x.py","start":{"line":1,"col":1},"extra":{"severity":"ERROR","metadata":{"cwe":"CWE-78: x"}}},
          {"check_id":"c.d","path":"../evil.py","start":{"line":1,"col":1},"extra":{"severity":"ERROR"}},
          {"check_id":"e","path":"y.py","start":{"line":0,"col":0},"extra":{}}
        ]}"#;
        let parsed = parse(json).unwrap();
        assert_eq!(parsed.findings.len(), 2);
        assert_eq!(parsed.findings[0].cwes, vec![78]);
        assert_eq!(parsed.findings[1].line, None);
        assert_eq!(parsed.findings[1].column, None);
        assert_eq!(parsed.findings[1].title, "e");
        assert_eq!(parsed.warnings.len(), 1);
        assert!(parsed.warnings[0].contains("../evil.py"));
    }

    #[test]
    fn empty_results_are_a_clean_completion() {
        let parsed = parse(br#"{"results":[],"errors":[]}"#).unwrap();
        assert!(parsed.findings.is_empty());
        assert!(parsed.warnings.is_empty());
    }

    #[test]
    fn malformed_output_is_a_parse_error_not_a_panic() {
        assert!(matches!(parse(b""), Err(ParseError::Empty)));
        assert!(matches!(parse(b"   \n"), Err(ParseError::Empty)));
        assert!(matches!(
            parse(b"{\"results\": [{"),
            Err(ParseError::Json(_))
        ));
        assert!(matches!(parse(b"not json"), Err(ParseError::Json(_))));
        assert!(matches!(parse(b"[]"), Err(ParseError::Json(_))));
        assert!(
            matches!(parse(b"{}"), Err(ParseError::Json(_))),
            "no `results` is not a clean run"
        );
        let truncated = &FIXTURE[..FIXTURE.len() / 2];
        assert!(matches!(parse(truncated), Err(ParseError::Json(_))));
    }

    #[test]
    fn interpret_distinguishes_completion_timeout_and_garbage() {
        let scanner = Semgrep;
        match scanner.interpret(&output(Some(0), FIXTURE, "")) {
            Outcome::Completed { findings, .. } => assert_eq!(findings.len(), 9),
            other => panic!("{other:?}"),
        }
        let mut timed = output(None, b"", "");
        timed.timed_out = true;
        assert!(matches!(scanner.interpret(&timed), Outcome::Failed(r) if r.contains("timed out")));
        match scanner.interpret(&output(Some(2), b"", "Fatal: no config")) {
            Outcome::Failed(reason) => {
                assert!(reason.contains("exit code 2"), "{reason}");
                assert!(reason.contains("no config"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
        let mut truncated = output(Some(0), FIXTURE, "");
        truncated.stdout_truncated = true;
        assert!(matches!(scanner.interpret(&truncated), Outcome::Failed(_)));
    }

    #[test]
    fn scan_args_carry_every_config_and_end_with_the_target() {
        let options = ScanOptions {
            semgrep_configs: vec!["p/rust".into(), "rules.yml".into()],
        };
        let args: Vec<String> = Semgrep
            .scan_args(&options)
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args.first().map(String::as_str), Some("scan"));
        assert!(args.contains(&"--json".to_owned()));
        assert!(args.contains(&"--metrics=off".to_owned()));
        assert_eq!(args.iter().filter(|a| *a == "--config").count(), 2);
        assert_eq!(args.last().map(String::as_str), Some("."));
        assert_eq!(
            ScanOptions::default().semgrep_configs,
            vec!["p/default".to_owned()]
        );
    }

    #[test]
    fn version_is_read_from_the_banner() {
        let v = Semgrep
            .parse_version(&output(Some(0), b"1.163.0\n", ""))
            .unwrap();
        assert_eq!(v, crate::version::Version::new(1, 163, 0));
    }
}
