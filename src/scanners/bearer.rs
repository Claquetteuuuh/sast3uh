//! Bearer: SAST plus sensitive-data flows (`--format json` output, one list per severity).
//!
//! Everything an item carries is kept: title, the full description (remediation included),
//! CWEs, the PII category groups and the data type, the code extract, the source → sink
//! locations as a flow, fingerprints and the documentation link.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;

use super::{
    Outcome, ParseError, Parsed, ScanOptions, Scanner, Strings, TEXT_CAP, cap, cwe_number, cwes,
    failure_reason, first_json, null_default, os_args, push_unique, value_text,
};
use crate::exec::Output;
use crate::model::{Finding, FlowKind, FlowStep, Severity, normalize_reported_path};
use crate::version::Version;

/// The Bearer adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct Bearer;

/// What Bearer says when the tree holds no file in a language it has rules for: on stderr
/// ("0 rules found for supported language") or, with a report format, in the report itself
/// ("Zero rules found. A security report requires rules to function").
fn says_no_rules(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("0 rules found")
        || lower.contains("zero rules found")
        || lower.contains("requires rules")
}

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

    fn mise_id(&self) -> &'static str {
        "aqua:Bearer/bearer"
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
            // The SAST rules plus the secrets scanner: both of Bearer\'s engines.
            "--scanner",
            "sast,secrets",
        ])
    }

    fn env(&self) -> Vec<(OsString, OsString)> {
        vec![("NO_COLOR".into(), "1".into())]
    }

    fn interpret(&self, output: &Output) -> Outcome {
        if output.timed_out {
            return Outcome::Failed(failure_reason(output));
        }
        if says_no_rules(&output.stderr_text()) || says_no_rules(&output.stdout_text()) {
            return Outcome::Skipped("no file in a language Bearer has rules for".to_owned());
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
struct RawItem {
    id: String,
    #[serde(default, deserialize_with = "null_default")]
    title: String,
    #[serde(default, deserialize_with = "null_default")]
    description: String,
    #[serde(default)]
    documentation_url: Option<String>,
    #[serde(default)]
    line_number: Option<u32>,
    #[serde(default, deserialize_with = "null_default")]
    filename: String,
    #[serde(default)]
    full_filename: Option<String>,
    #[serde(default)]
    cwe_ids: Strings,
    #[serde(default)]
    category_groups: Strings,
    #[serde(default)]
    data_type: Option<DataType>,
    #[serde(default)]
    code_extract: Option<String>,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default)]
    old_fingerprint: Option<String>,
    #[serde(default)]
    parent_line_number: Option<u32>,
    #[serde(default)]
    source: Option<RawRange>,
    #[serde(default)]
    sink: Option<RawRange>,
    /// Whatever else Bearer adds goes to `extra` verbatim.
    #[serde(flatten)]
    rest: BTreeMap<String, Value>,
}

#[derive(Deserialize, Default)]
struct DataType {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    category_uuid: Option<String>,
}

#[derive(Deserialize, Default)]
struct RawRange {
    #[serde(default)]
    start: Option<u32>,
    #[serde(default)]
    end: Option<u32>,
    #[serde(default)]
    column: Option<RawColumn>,
    #[serde(default)]
    content: Option<String>,
}

#[derive(Deserialize, Default)]
struct RawColumn {
    #[serde(default)]
    start: Option<u32>,
    #[serde(default)]
    end: Option<u32>,
}

/// Parse `bearer scan --format json` output (a banner before the JSON is tolerated).
///
/// One unreadable item does not fail the report: it is dropped with a warning that says so.
///
/// # Errors
///
/// [`ParseError`] when there is no JSON object in the output.
pub fn parse(bytes: &[u8]) -> Result<Parsed, ParseError> {
    let json = first_json(bytes);
    if json.is_empty() {
        return Err(ParseError::Empty);
    }
    let buckets: BTreeMap<String, Vec<Value>> = serde_json::from_slice(json)?;
    let mut parsed = Parsed::default();
    for (bucket, items) in buckets {
        let severity = bucket_severity(&bucket);
        for (index, value) in items.into_iter().enumerate() {
            let raw: RawItem = match serde_json::from_value(value) {
                Ok(raw) => raw,
                Err(err) => {
                    parsed
                        .warnings
                        .push(format!("dropped {bucket} item #{index}: {err}"));
                    continue;
                }
            };
            let reported = raw
                .full_filename
                .clone()
                .filter(|f| !f.is_empty())
                .unwrap_or_else(|| raw.filename.clone());
            match normalize_reported_path(&reported) {
                Some(path) => parsed.findings.push(to_finding(raw, severity, &path)),
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

fn to_finding(raw: RawItem, severity: Severity, path: &Path) -> Finding {
    let source = raw.source.unwrap_or_default();
    let sink = raw.sink.unwrap_or_default();
    let message = first_paragraph(&raw.description).unwrap_or_else(|| raw.title.clone());
    let mut f = Finding::new(
        "bearer",
        raw.id,
        severity,
        raw.title,
        message,
        path.to_path_buf(),
    );
    f.line = raw
        .line_number
        .or(sink.start)
        .or(source.start)
        .filter(|l| *l > 0);
    f.end_line = sink.end.or(source.end).filter(|l| *l > 0);
    let column = sink.column.as_ref().or(source.column.as_ref());
    f.column = column.and_then(|c| c.start).filter(|c| *c > 0);
    f.end_column = column.and_then(|c| c.end).filter(|c| *c > 0);
    f.cwes = cwes(raw.cwe_ids.0.iter().map(|c| cwe_number(c)));
    for group in raw.category_groups.0 {
        push_unique(&mut f.categories, group);
    }
    if let Some(data_type) = raw.data_type {
        if let Some(name) = data_type.name {
            push_unique(&mut f.tags, name);
        }
        if let Some(uuid) = data_type.category_uuid.filter(|u| !u.is_empty()) {
            f.extra.insert("data_type.category_uuid".to_owned(), uuid);
        }
    }
    f.snippet = raw
        .code_extract
        .filter(|c| !c.trim().is_empty())
        .map(|c| cap(&c, TEXT_CAP));
    f.url = raw.documentation_url.filter(|u| !u.is_empty());
    f.fingerprint = raw.fingerprint.filter(|s| !s.is_empty());
    if let Some(step) = range_step(&source, path, FlowKind::Source) {
        f.flow.push(step);
    }
    if let Some(step) = range_step(&sink, path, FlowKind::Sink) {
        f.flow.push(step);
    }
    if !raw.description.trim().is_empty() {
        f.extra.insert(
            "description".to_owned(),
            cap(raw.description.trim(), TEXT_CAP),
        );
    }
    if let Some(parent) = raw.parent_line_number {
        f.extra
            .insert("parent_line_number".to_owned(), parent.to_string());
    }
    if let Some(old) = raw
        .old_fingerprint
        .filter(|o| !o.is_empty() && Some(o.as_str()) != f.fingerprint.as_deref())
    {
        f.extra.insert("old_fingerprint".to_owned(), old);
    }
    for (key, value) in raw.rest {
        if !value.is_null() {
            f.extra.insert(key, value_text(&value));
        }
    }
    f
}

fn range_step(range: &RawRange, path: &Path, kind: FlowKind) -> Option<FlowStep> {
    let line = range.start.filter(|l| *l > 0)?;
    Some(FlowStep {
        kind,
        path: path.to_path_buf(),
        line: Some(line),
        column: range
            .column
            .as_ref()
            .and_then(|c| c.start)
            .filter(|c| *c > 0),
        end_line: range.end.filter(|l| *l > 0),
        end_column: range.column.as_ref().and_then(|c| c.end).filter(|c| *c > 0),
        content: range
            .content
            .as_deref()
            .filter(|c| !c.trim().is_empty())
            .map(|c| cap(c, 500)),
    })
}

/// The first prose line of a Markdown description (headings and blank lines skipped), cut at
/// 300 characters.
fn first_paragraph(markdown: &str) -> Option<String> {
    let line = markdown
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("```"))?;
    Some(cap(line, 300))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::tests::output;
    use std::path::PathBuf;

    const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/bearer/report.json");
    const VERSION: &str = include_str!("../../tests/fixtures/bearer/version.txt");

    #[test]
    fn parses_the_recorded_report_completely() {
        let parsed = parse(FIXTURE).unwrap();
        let raw: BTreeMap<String, Vec<Value>> = serde_json::from_slice(FIXTURE).unwrap();
        let raw_count: usize = raw.values().map(Vec::len).sum();
        assert_eq!(parsed.findings.len(), raw_count, "every item is a finding");
        assert!(parsed.warnings.is_empty());
        let mut ids: Vec<&str> = raw
            .values()
            .flatten()
            .map(|i| i["id"].as_str().unwrap())
            .collect();
        ids.sort_unstable();
        let mut got: Vec<&str> = parsed.findings.iter().map(|f| f.rule_id.as_str()).collect();
        got.sort_unstable();
        assert_eq!(got, ids);
        assert!(
            parsed.findings.iter().all(|f| f.snippet.is_some()),
            "every item carries its code extract"
        );
        assert!(
            parsed
                .findings
                .iter()
                .all(|f| !f.categories.is_empty() && f.extra.contains_key("description"))
        );
        assert!(
            parsed.findings.iter().all(|f| f.flow.len() == 2),
            "source and sink for every item"
        );
        assert_eq!(
            parsed
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Critical)
                .count(),
            4
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
    fn keeps_every_field_of_an_item() {
        let parsed = parse(FIXTURE).unwrap();
        let logger = parsed
            .findings
            .iter()
            .find(|f| f.rule_id == "javascript_lang_logger")
            .unwrap();
        assert_eq!(logger.tool, "bearer");
        assert_eq!(logger.severity, Severity::Medium);
        assert_eq!(
            logger.title,
            "Leakage of sensitive information in logger message"
        );
        assert!(
            logger.message.starts_with("Sensitive information leakage"),
            "{}",
            logger.message
        );
        assert_eq!(logger.path, PathBuf::from("src/app.js"));
        assert_eq!(
            (
                logger.line,
                logger.end_line,
                logger.column,
                logger.end_column
            ),
            (Some(6), Some(6), Some(3), Some(28))
        );
        assert_eq!(logger.cwes, vec![532]);
        assert_eq!(logger.categories, vec!["PII", "Personal Data"]);
        assert_eq!(logger.tags, vec!["ID Number"]);
        assert_eq!(
            logger.snippet.as_deref(),
            Some("  console.log(\"user\", user);")
        );
        assert_eq!(
            logger.url.as_deref(),
            Some("https://docs.bearer.com/reference/rules/javascript_lang_logger")
        );
        assert_eq!(
            logger.fingerprint.as_deref(),
            Some("cb1b0668f3819101bcc39c1d5b930c3e_0")
        );
        assert_eq!(logger.flow[0].kind, FlowKind::Source);
        assert_eq!(
            (
                logger.flow[0].line,
                logger.flow[0].column,
                logger.flow[0].end_column
            ),
            (Some(5), Some(18), Some(40))
        );
        assert_eq!(logger.flow[1].kind, FlowKind::Sink);
        assert_eq!(logger.flow[1].line, Some(6));
        assert!(
            logger.extra["description"].starts_with("## Description"),
            "the full remediation text is kept"
        );
        assert_eq!(logger.extra["parent_line_number"], "6");
        assert_eq!(
            logger.extra["data_type.category_uuid"],
            "14124881-6b92-4fc5-8005-ea7c1c09592e"
        );
        assert!(
            !logger.extra.contains_key("old_fingerprint"),
            "identical to the fingerprint: not repeated"
        );

        let eval = parsed
            .findings
            .iter()
            .find(|f| f.rule_id == "javascript_lang_eval_user_input")
            .unwrap();
        assert_eq!(eval.severity, Severity::Critical);
        assert_eq!(eval.cwes, vec![95]);
        assert_eq!(eval.line, Some(7));
        assert!(eval.tags.is_empty());
    }

    #[test]
    fn tolerates_a_banner_unknown_buckets_and_odd_values() {
        let json = br#"Analyzing codebase
{"warning":[{"id":"x","title":"T","filename":"a.rb","line_number":3,"cwe_ids":null,"category_groups":null,"old_fingerprint":"old","fingerprint":"new","custom_field":{"a":1}}],
 "weird":[{"id":"y","filename":"b.rb","source":{"start":2,"end":4,"column":{"start":1,"end":9},"content":"x"}},{"id":7,"filename":"c.rb"}]}"#;
        let parsed = parse(json).unwrap();
        assert_eq!(parsed.findings.len(), 2, "{:?}", parsed.warnings);
        assert!(parsed.findings.iter().all(|f| f.severity == Severity::Info));
        let x = parsed.findings.iter().find(|f| f.rule_id == "x").unwrap();
        assert_eq!(
            x.message, "T",
            "falls back to the title without a description"
        );
        assert_eq!(x.line, Some(3));
        assert!(x.cwes.is_empty());
        assert_eq!(x.extra["old_fingerprint"], "old");
        assert_eq!(
            x.extra["custom_field"], r#"{"a":1}"#,
            "an unknown field is kept verbatim"
        );
        let y = parsed.findings.iter().find(|f| f.rule_id == "y").unwrap();
        assert_eq!(
            (y.line, y.end_line, y.column, y.end_column),
            (Some(2), Some(4), Some(1), Some(9)),
            "the source range locates it"
        );
        assert_eq!(y.flow.len(), 1);
        assert_eq!(y.flow[0].content.as_deref(), Some("x"));
        assert_eq!(parsed.warnings.len(), 1, "{:?}", parsed.warnings);
        assert!(parsed.warnings[0].contains("dropped weird item #1"));
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
    fn interpret_skips_when_the_report_itself_says_zero_rules() {
        // Bearer 2.1.3 with a report format: nothing on stderr, the text in the report.
        let report = b"\nSecurity Report\n\n=====================================\n\nZero rules found. A security report requires rules to function. Please check configuration.\n";
        match Bearer.interpret(&output(Some(1), report, "")) {
            Outcome::Skipped(reason) => assert!(reason.contains("no file"), "{reason}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn interpret_completes_fails_and_times_out() {
        match Bearer.interpret(&output(Some(0), FIXTURE, "")) {
            Outcome::Completed(parsed) => assert_eq!(parsed.findings.len(), 7),
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
        assert!(args.windows(2).any(|w| w == ["--scanner", "sast,secrets"]));
    }
}
