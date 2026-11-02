//! Semgrep: multi-language SAST driven by rule packs (`--json` output).
//!
//! Everything a result carries is kept: message, severity, confidence, the rule's metadata
//! (CWE, OWASP, categories, technologies, references, links), the matched lines, a fix, the
//! taint trace (source → intermediate → sink) and the `nosemgrep` flag; the run's `errors`
//! become diagnostics and `paths` become the scanned/skipped lists.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::Value;

use super::{
    Outcome, ParseError, Parsed, ScanOptions, Scanner, Strings, TEXT_CAP, cap, cwe_number, cwes,
    failure_reason, null_default, os_args, push_unique, tail, value_text,
};
use crate::exec::Output;
use crate::model::{
    Confidence, Diagnostic, Finding, FlowKind, FlowStep, Severity, SkippedPath,
    normalize_reported_path,
};

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

    fn mise_id(&self) -> &'static str {
        "semgrep"
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
            Ok(parsed) => Outcome::Completed(parsed),
            Err(err) => Outcome::Failed(format!("{}; {err}", failure_reason(output))),
        }
    }
}

#[derive(Deserialize)]
struct Root {
    // Required on purpose: it is what makes `[]` or `{}` fail instead of reading as "clean".
    results: Vec<Value>,
    #[serde(default, deserialize_with = "null_default")]
    errors: Vec<Value>,
    #[serde(default)]
    paths: Option<Paths>,
}

#[derive(Deserialize, Default)]
struct Paths {
    #[serde(default, deserialize_with = "null_default")]
    scanned: Vec<String>,
    #[serde(default, deserialize_with = "null_default")]
    skipped: Vec<Value>,
}

#[derive(Deserialize)]
struct RawResult {
    check_id: String,
    path: String,
    #[serde(default, deserialize_with = "null_default")]
    start: Position,
    #[serde(default)]
    end: Option<Position>,
    #[serde(default, deserialize_with = "null_default")]
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
    #[serde(default, deserialize_with = "null_default")]
    message: String,
    #[serde(default, deserialize_with = "null_default")]
    severity: String,
    #[serde(default, deserialize_with = "null_default")]
    metadata: Metadata,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default)]
    lines: Option<String>,
    #[serde(default)]
    fix: Option<String>,
    #[serde(default, deserialize_with = "null_default")]
    is_ignored: bool,
    #[serde(default)]
    dataflow_trace: Option<Value>,
    /// Positions of the rule's metavariables: noise for a report, left out on purpose.
    #[serde(default)]
    #[allow(dead_code)]
    metavars: Option<Value>,
    /// Whatever else Semgrep adds (`engine_kind`, `validation_state`…) goes to `extra` verbatim.
    #[serde(flatten)]
    rest: BTreeMap<String, Value>,
}

#[derive(Deserialize, Default)]
struct Metadata {
    #[serde(default)]
    cwe: Strings,
    #[serde(default)]
    owasp: Strings,
    #[serde(default)]
    category: Strings,
    #[serde(default)]
    subcategory: Strings,
    #[serde(default)]
    vulnerability_class: Strings,
    #[serde(default)]
    technology: Strings,
    #[serde(default)]
    references: Strings,
    #[serde(default, rename = "source-rule-url")]
    source_rule_url: Strings,
    #[serde(default)]
    confidence: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default, rename = "display-name")]
    display_name: Option<String>,
    /// likelihood, impact, shortlink, license, cwe2022-top25… verbatim into `extra`.
    #[serde(flatten)]
    rest: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
struct RawError {
    #[serde(default, deserialize_with = "null_default")]
    level: String,
    #[serde(default, rename = "type", deserialize_with = "null_default")]
    kind: String,
    #[serde(default, deserialize_with = "null_default")]
    message: String,
    #[serde(default)]
    rule_id: Option<String>,
    #[serde(default)]
    path: Option<String>,
}

/// Parse `semgrep --json` output.
///
/// One unreadable result does not fail the report: it is dropped with a warning that says so.
///
/// # Errors
///
/// [`ParseError`] when the output is empty or not Semgrep's JSON at all.
pub fn parse(bytes: &[u8]) -> Result<Parsed, ParseError> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(ParseError::Empty);
    }
    let root: Root = serde_json::from_slice(bytes)?;
    let mut parsed = Parsed::default();
    for (index, value) in root.results.into_iter().enumerate() {
        let raw: RawResult = match serde_json::from_value(value) {
            Ok(raw) => raw,
            Err(err) => {
                parsed
                    .warnings
                    .push(format!("dropped result #{index}: {err}"));
                continue;
            }
        };
        match normalize_reported_path(&raw.path) {
            Some(path) => parsed.findings.push(to_finding(raw, path)),
            None => parsed.warnings.push(format!(
                "dropped {}: path `{}` is outside the target",
                raw.check_id, raw.path
            )),
        }
    }
    for value in root.errors {
        match serde_json::from_value::<RawError>(value) {
            Ok(err) => parsed.diagnostics.push(to_diagnostic(err)),
            Err(err) => parsed
                .warnings
                .push(format!("unreadable error entry: {err}")),
        }
    }
    if let Some(paths) = root.paths {
        parsed.scanned_files = Some(paths.scanned.len());
        parsed.skipped_paths = paths.skipped.iter().filter_map(skipped_path).collect();
    }
    Ok(parsed)
}

fn to_finding(raw: RawResult, path: PathBuf) -> Finding {
    let meta = raw.extra.metadata;
    let title = meta
        .display_name
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| {
            raw.check_id
                .rsplit('.')
                .next()
                .unwrap_or(&raw.check_id)
                .to_owned()
        });
    let mut f = Finding::new(
        "semgrep",
        raw.check_id,
        severity(&raw.extra.severity),
        title,
        raw.extra.message.trim(),
        path,
    );
    f.confidence = meta.confidence.as_deref().and_then(Confidence::parse);
    f.suppressed = raw.extra.is_ignored;
    f.line = (raw.start.line > 0).then_some(raw.start.line);
    f.column = (raw.start.col > 0).then_some(raw.start.col);
    f.end_line = raw.end.as_ref().map(|e| e.line).filter(|l| *l > 0);
    f.end_column = raw.end.as_ref().map(|e| e.col).filter(|c| *c > 0);
    f.cwes = cwes(meta.cwe.0.iter().map(|c| cwe_number(c)));
    for item in meta.owasp.0 {
        push_unique(&mut f.owasp, item);
    }
    for item in meta
        .category
        .0
        .into_iter()
        .chain(meta.subcategory.0)
        .chain(meta.vulnerability_class.0)
    {
        push_unique(&mut f.categories, item);
    }
    for item in meta.technology.0 {
        push_unique(&mut f.tags, item);
    }
    for item in meta.references.0.into_iter().chain(meta.source_rule_url.0) {
        push_unique(&mut f.references, item);
    }
    f.snippet = raw
        .extra
        .lines
        .filter(|l| !l.trim().is_empty())
        .map(|l| cap(&l, TEXT_CAP));
    f.fix = raw
        .extra
        .fix
        .filter(|l| !l.trim().is_empty())
        .map(|l| cap(&l, TEXT_CAP));
    f.url = meta.source.filter(|s| !s.is_empty());
    f.fingerprint = raw.extra.fingerprint.filter(|s| !s.is_empty());
    f.flow = raw
        .extra
        .dataflow_trace
        .as_ref()
        .map(flow_from_trace)
        .unwrap_or_default();
    if let Some(confidence) = meta
        .confidence
        .filter(|c| f.confidence.is_none() && !c.trim().is_empty())
    {
        f.extra.insert("confidence".to_owned(), confidence);
    }
    for (key, value) in meta.rest.into_iter().chain(raw.extra.rest) {
        if !value.is_null() {
            f.extra.insert(key, value_text(&value));
        }
    }
    f
}

fn to_diagnostic(err: RawError) -> Diagnostic {
    let first_line = err.message.lines().next().unwrap_or_default().trim();
    let message = if err.kind.trim().is_empty() {
        tail(first_line, 300)
    } else {
        format!("{}: {}", err.kind.trim(), tail(first_line, 300))
    };
    Diagnostic {
        level: if err.level.trim().is_empty() {
            "warn".to_owned()
        } else {
            err.level.trim().to_owned()
        },
        rule_id: err.rule_id.filter(|r| !r.is_empty()),
        path: err.path.filter(|p| !p.is_empty()),
        message,
    }
}

/// A `paths.skipped` entry: `{"path": …, "reason": …, "details": …}` or a bare path.
fn skipped_path(value: &Value) -> Option<SkippedPath> {
    match value {
        Value::String(path) => Some(SkippedPath {
            path: path.clone(),
            reason: "skipped".to_owned(),
        }),
        Value::Object(map) => {
            let path = map.get("path").and_then(Value::as_str)?.to_owned();
            let reason = map
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("skipped");
            let details = map
                .get("details")
                .and_then(Value::as_str)
                .filter(|d| !d.is_empty());
            let reason = match details {
                Some(details) => format!("{reason}: {}", cap(details, 300)),
                None => reason.to_owned(),
            };
            Some(SkippedPath { path, reason })
        }
        _ => None,
    }
}

/// The taint trace: `{"taint_source": ["CliLoc", [loc, content]], "intermediate_vars":
/// [{"location": loc, "content": …}], "taint_sink": ["CliLoc", [loc, content]]}` — read
/// loosely, since the call variants nest the same shapes deeper.
fn flow_from_trace(trace: &Value) -> Vec<FlowStep> {
    let mut steps = Vec::new();
    if let Some(step) = trace
        .get("taint_source")
        .and_then(|v| step_in(v, FlowKind::Source))
    {
        steps.push(step);
    }
    if let Some(Value::Array(vars)) = trace.get("intermediate_vars") {
        for var in vars {
            let content = var.get("content").and_then(Value::as_str);
            if let Some(step) = var
                .get("location")
                .and_then(|loc| step_from(loc, content, FlowKind::Intermediate))
            {
                steps.push(step);
            }
        }
    }
    if let Some(step) = trace
        .get("taint_sink")
        .and_then(|v| step_in(v, FlowKind::Sink))
    {
        steps.push(step);
    }
    steps
}

/// The first location object inside `value` (depth first), with the string next to it.
fn step_in(value: &Value, kind: FlowKind) -> Option<FlowStep> {
    match value {
        Value::Object(_) if value.get("path").is_some() => step_from(value, None, kind),
        Value::Array(items) => {
            if let Some(pos) = items
                .iter()
                .position(|i| i.is_object() && i.get("path").is_some())
            {
                let content = items.iter().skip(pos + 1).find_map(Value::as_str);
                return items.get(pos).and_then(|loc| step_from(loc, content, kind));
            }
            items.iter().find_map(|item| step_in(item, kind))
        }
        _ => None,
    }
}

fn step_from(loc: &Value, content: Option<&str>, kind: FlowKind) -> Option<FlowStep> {
    let path = normalize_reported_path(loc.get("path")?.as_str()?)?;
    let number = |key: &str, field: &str| {
        loc.get(key)
            .and_then(|p| p.get(field))
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n > 0)
    };
    Some(FlowStep {
        kind,
        path,
        line: number("start", "line"),
        column: number("start", "col"),
        end_line: number("end", "line"),
        end_column: number("end", "col"),
        content: content
            .filter(|c| !c.trim().is_empty())
            .map(|c| cap(c, 500)),
    })
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

    const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/semgrep/report.json");

    #[test]
    fn parses_the_recorded_report_completely() {
        let parsed = parse(FIXTURE).unwrap();
        let raw: Value = serde_json::from_slice(FIXTURE).unwrap();
        let raw_results = raw["results"].as_array().unwrap();
        assert_eq!(
            parsed.findings.len(),
            raw_results.len(),
            "every result is a finding"
        );
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        let mut ids: Vec<&str> = raw_results
            .iter()
            .map(|r| r["check_id"].as_str().unwrap())
            .collect();
        ids.sort_unstable();
        let mut got: Vec<&str> = parsed.findings.iter().map(|f| f.rule_id.as_str()).collect();
        got.sort_unstable();
        assert_eq!(got, ids);
        assert!(
            parsed.findings.iter().all(|f| f.snippet.is_some()),
            "every result carries its lines"
        );
        assert!(
            parsed.findings.iter().all(|f| f.confidence.is_some()),
            "every rule states its confidence"
        );
        assert!(
            parsed.findings.iter().all(|f| !f.owasp.is_empty()
                && !f.categories.is_empty()
                && !f.references.is_empty())
        );
        assert!(parsed.findings.iter().all(|f| !f.suppressed));
        assert_eq!(parsed.scanned_files, Some(3));
        assert!(parsed.skipped_paths.is_empty());
        assert_eq!(
            parsed.diagnostics.len(),
            raw["errors"].as_array().unwrap().len()
        );
    }

    #[test]
    fn keeps_every_field_of_a_result() {
        let parsed = parse(FIXTURE).unwrap();
        let key = parsed
            .findings
            .iter()
            .find(|f| f.rule_id.ends_with("detected-stripe-api-key"))
            .unwrap();
        assert_eq!(key.tool, "semgrep");
        assert_eq!(key.severity, Severity::High, "ERROR maps to high");
        assert_eq!(key.confidence, Some(Confidence::Low));
        assert_eq!(key.title, "detected-stripe-api-key");
        assert_eq!(key.message, "Stripe API Key detected");
        assert_eq!(key.path, PathBuf::from("src/app.js"));
        assert_eq!(
            (key.line, key.column, key.end_line, key.end_column),
            (Some(3), Some(18), Some(3), Some(50))
        );
        assert_eq!(key.cwes, vec![798]);
        assert_eq!(
            key.owasp,
            vec![
                "A07:2021 - Identification and Authentication Failures",
                "A07:2025 - Authentication Failures"
            ]
        );
        assert_eq!(
            key.categories,
            vec!["security", "audit", "Hard-coded Secrets"]
        );
        assert_eq!(key.tags, vec!["secrets", "stripe"]);
        // The recorded key is redacted in the fixture (GitHub push protection would block it).
        assert_eq!(
            key.snippet.as_deref(),
            Some("const API_KEY = \"sk_live_<redacted-in-fixture>\";")
        );
        assert!(
            key.references
                .iter()
                .any(|r| r.contains("truffleHogRegexes")),
            "{:?}",
            key.references
        );
        assert!(
            key.url
                .as_deref()
                .unwrap()
                .starts_with("https://semgrep.dev/r/")
        );
        assert!(key.fingerprint.is_some());
        assert_eq!(key.extra["likelihood"], "LOW");
        assert_eq!(key.extra["impact"], "MEDIUM");
        assert_eq!(key.extra["shortlink"], "https://sg.run/dKd5");
        assert_eq!(key.extra["engine_kind"], "OSS");
        assert_eq!(key.extra["validation_state"], "NO_VALIDATOR");
        assert_eq!(key.extra["cwe2022-top25"], "true");
        assert!(
            key.extra.contains_key("semgrep.dev"),
            "{:?}",
            key.extra.keys()
        );
        assert!(!key.extra.contains_key("metavars"), "metavars are noise");
        assert!(!key.extra.contains_key("fix"));
        assert!(key.flow.is_empty());
    }

    #[test]
    fn keeps_the_taint_trace_as_a_flow() {
        let parsed = parse(FIXTURE).unwrap();
        let log = parsed
            .findings
            .iter()
            .find(|f| f.rule_id.ends_with("console-log-express"))
            .unwrap();
        assert_eq!(log.flow.len(), 3, "{:?}", log.flow);
        assert_eq!(log.flow[0].kind, FlowKind::Source);
        assert_eq!(
            (log.flow[0].line, log.flow[0].column, log.flow[0].end_column),
            (Some(5), Some(25), Some(28))
        );
        assert_eq!(log.flow[0].content.as_deref(), Some("req"));
        assert_eq!(log.flow[1].kind, FlowKind::Intermediate);
        assert_eq!(log.flow[1].content.as_deref(), Some("user"));
        assert_eq!(log.flow[2].kind, FlowKind::Sink);
        assert_eq!(log.flow[2].line, Some(6));
        assert_eq!(
            log.flow[2].content.as_deref(),
            Some("console.log(\"user\", user)")
        );
        assert_eq!(log.flow[2].path, PathBuf::from("src/app.js"));
        let fixed = parsed.findings.iter().find(|f| f.fix.is_some()).unwrap();
        assert_eq!(fixed.fix.as_deref(), Some("False"));
    }

    #[test]
    fn rule_errors_become_diagnostics() {
        let parsed = parse(FIXTURE).unwrap();
        assert_eq!(parsed.diagnostics.len(), 3);
        let d = &parsed.diagnostics[0];
        assert_eq!(d.level, "warn");
        assert_eq!(
            d.rule_id.as_deref(),
            Some("javascript.crypto-js.cryptojs-weak-algorithm.cryptojs-weak-algorithm")
        );
        assert_eq!(d.path.as_deref(), Some("src/app.js"));
        assert!(
            d.message
                .starts_with("Internal matching error: Internal matching error when running"),
            "{}",
            d.message
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
    fn tolerates_odd_shapes_and_reports_what_it_drops() {
        let json = br#"{"results":[
          {"check_id":"a.b","path":"x.py","start":{"line":1,"col":1},"extra":{"severity":"ERROR","is_ignored":true,"lines":null,"metadata":{"cwe":"CWE-78: x","owasp":null,"category":"security","technology":7,"confidence":"certain","display-name":"Shell injection"}}},
          {"check_id":"c.d","path":"../evil.py","start":{"line":1,"col":1},"extra":{"severity":"ERROR"}},
          {"check_id":"e","path":"y.py","start":{"line":0,"col":0},"extra":null},
          {"check_id":"broken","path":"z.py","start":{"line":"one"}}
        ],"errors":[{"level":"error","message":"boom\nmore"},{"level":null,"message":null},"garbage"],
          "paths":{"scanned":["x.py","y.py"],"skipped":[{"path":"big.min.js","reason":"too large","details":"5 MB"},"plain.js",{"nopath":1}]}}"#;
        let parsed = parse(json).unwrap();
        assert_eq!(parsed.findings.len(), 2, "{:?}", parsed.warnings);
        let a = &parsed.findings[0];
        assert_eq!(a.cwes, vec![78]);
        assert!(a.suppressed);
        assert_eq!(
            a.title, "Shell injection",
            "display-name wins over the id tail"
        );
        assert_eq!(a.categories, vec!["security"]);
        assert_eq!(a.tags, vec!["7"]);
        assert_eq!(a.confidence, None);
        assert_eq!(
            a.extra["confidence"], "certain",
            "an unknown level is kept verbatim"
        );
        assert!(a.snippet.is_none());
        let e = &parsed.findings[1];
        assert_eq!((e.line, e.column, e.end_line), (None, None, None));
        assert_eq!(e.title, "e");
        assert_eq!(e.severity, Severity::Info);
        assert_eq!(parsed.warnings.len(), 3, "{:?}", parsed.warnings);
        assert!(parsed.warnings.iter().any(|w| w.contains("../evil.py")));
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| w.contains("dropped result #3"))
        );
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| w.contains("unreadable error entry"))
        );
        assert_eq!(parsed.diagnostics.len(), 2);
        assert_eq!(parsed.diagnostics[0].message, "boom");
        assert_eq!(parsed.diagnostics[1].level, "warn");
        assert_eq!(parsed.scanned_files, Some(2));
        assert_eq!(parsed.skipped_paths.len(), 2);
        assert_eq!(parsed.skipped_paths[0].reason, "too large: 5 MB");
        assert_eq!(parsed.skipped_paths[1].path, "plain.js");
    }

    #[test]
    fn empty_results_are_a_clean_completion() {
        let parsed = parse(br#"{"results":[],"errors":[]}"#).unwrap();
        assert!(parsed.findings.is_empty());
        assert!(parsed.warnings.is_empty());
        assert_eq!(parsed.scanned_files, None);
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
            Outcome::Completed(parsed) => assert_eq!(parsed.findings.len(), 9),
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
