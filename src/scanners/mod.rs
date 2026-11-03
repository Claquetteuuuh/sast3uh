//! Scanner adapters: how to run each tool, how to read what it says.
//!
//! An adapter is pure glue. It never spawns anything itself (the pipeline does, through
//! [`crate::exec`]); it only builds argument lists and turns captured output into findings. That
//! keeps every parser testable against recorded output in `tests/fixtures/<tool>/`.

pub mod bearer;
pub mod luacheck;
pub mod semgrep;
pub mod trivy;

use std::ffi::OsString;

use serde::{Deserialize, Deserializer};

use crate::exec::Output;
use crate::model::{Diagnostic, Finding, SkippedPath};
use crate::version::Version;

/// Per-scan knobs the adapters read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOptions {
    /// Explicit Semgrep rule sources (`p/rust`, a rules file…). `None` selects packs from
    /// [`ScanOptions::detected`] with [`crate::packs`].
    pub semgrep_configs: Option<Vec<String>>,
    /// How much noise the pack selection accepts.
    pub semgrep_profile: crate::packs::Profile,
    /// What the target holds, filled by the pipeline before the scanners run.
    pub detected: crate::detect::Detected,
    /// No network at all: scanners that fetch databases use what they have cached.
    pub offline: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            semgrep_configs: None,
            semgrep_profile: crate::packs::Profile::Exhaustive,
            detected: crate::detect::Detected::default(),
            offline: false,
        }
    }
}

impl ScanOptions {
    /// The Semgrep `--config` values: the explicit list, else the packs the target calls for.
    pub fn semgrep_configs(&self) -> Vec<String> {
        match &self.semgrep_configs {
            Some(configs) => configs.clone(),
            None => crate::packs::configs(&self.detected, self.semgrep_profile),
        }
    }
}

/// What a scanner's output meant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The scan ran and its output was parsed.
    Completed(Parsed),
    /// The scan did not apply (nothing to scan).
    Skipped(String),
    /// The output is unusable.
    Failed(String),
}

/// Why a scanner's output could not be parsed.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// Not the JSON the tool documents.
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Nothing at all on standard output.
    #[error("empty output")]
    Empty,
}

/// Parsed output of one scanner: the findings, and everything the tool said about the run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    /// The findings.
    pub findings: Vec<Finding>,
    /// Notes from the parser itself: an entry it could not read, a finding dropped for an
    /// invalid path. Each one is a result that did not make it into `findings`.
    pub warnings: Vec<String>,
    /// How many files the tool scanned, when it says.
    pub scanned_files: Option<usize>,
    /// Files the tool chose not to scan, when it says.
    pub skipped_paths: Vec<SkippedPath>,
    /// What the tool reported about its own run (rules that errored…).
    pub diagnostics: Vec<Diagnostic>,
}

/// Cap on a code snippet or a verbatim text kept in a finding, in characters.
pub(crate) const TEXT_CAP: usize = 4000;

/// A `null` where a list, a string or a flag is expected reads as empty rather than as an
/// error: one odd field must not sink a whole report.
pub(crate) fn null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// Strings out of whatever JSON the tool put there: a string, a number, a list of them, or
/// nothing. Objects are ignored.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Strings(pub(crate) Vec<String>);

impl<'de> Deserialize<'de> for Strings {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        Ok(Strings(strings_of(&value)))
    }
}

fn strings_of(value: &serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Number(n) => vec![n.to_string()],
        serde_json::Value::Bool(b) => vec![b.to_string()],
        serde_json::Value::Array(items) => items.iter().flat_map(strings_of).collect(),
        serde_json::Value::Null | serde_json::Value::Object(_) => Vec::new(),
    }
}

/// The first `max_chars` characters of `text`, with an ellipsis when cut.
pub(crate) fn cap(text: &str, max_chars: usize) -> String {
    let mut out: String = text.chars().take(max_chars).collect();
    if out.len() < text.len() {
        out.push('…');
    }
    out
}

/// Add `value` to `list` unless empty or already there.
pub(crate) fn push_unique(list: &mut Vec<String>, value: impl Into<String>) {
    let value = value.into();
    let trimmed = value.trim();
    if !trimmed.is_empty() && !list.iter().any(|v| v == trimmed) {
        list.push(trimmed.to_owned());
    }
}

/// A JSON value as compact text, for [`Finding::extra`](crate::model::Finding::extra).
pub(crate) fn value_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => cap(s, 1000),
        other => cap(&other.to_string(), 1000),
    }
}

/// A scanner sast3uh can drive.
pub trait Scanner: Send + Sync {
    /// Display name (also the `tool` field of its findings).
    fn name(&self) -> &'static str;
    /// Executable looked up on `PATH`.
    fn binary(&self) -> &'static str;
    /// What it covers, for `sast3uh tools`.
    fn purpose(&self) -> &'static str;
    /// The mise tool id that installs it (`semgrep`, `aqua:Bearer/bearer`…), used when mise
    /// does not already manage the binary under another id.
    fn mise_id(&self) -> &'static str;
    /// Arguments that print the version.
    fn version_args(&self) -> Vec<OsString>;
    /// Read the installed version from the output of [`Scanner::version_args`].
    fn parse_version(&self, output: &Output) -> Option<Version> {
        Version::parse(&output.stdout_text()).or_else(|| Version::parse(&output.stderr_text()))
    }
    /// Arguments that scan the current directory (the pipeline sets it to the target).
    fn scan_args(&self, options: &ScanOptions) -> Vec<OsString>;
    /// One line on what the scan will use (rule packs…), for the log.
    fn plan(&self, _options: &ScanOptions) -> Option<String> {
        None
    }
    /// Extra environment for the scan (on top of the allow-list in [`crate::exec`]).
    fn env(&self) -> Vec<(OsString, OsString)> {
        Vec::new()
    }
    /// Turn the captured output of a scan into findings.
    fn interpret(&self, output: &Output) -> Outcome;
}

/// Every scanner, in display order.
pub fn registry() -> Vec<Box<dyn Scanner>> {
    vec![
        Box::new(semgrep::Semgrep),
        Box::new(bearer::Bearer),
        Box::new(trivy::Trivy),
        Box::new(luacheck::Luacheck),
    ]
}

/// The scanner names, in display order.
pub fn names() -> Vec<&'static str> {
    registry().iter().map(|s| s.name()).collect()
}

/// The scanner called `name`, if any.
pub fn by_name(name: &str) -> Option<Box<dyn Scanner>> {
    registry()
        .into_iter()
        .find(|s| s.name().eq_ignore_ascii_case(name.trim()))
}

/// `&[&str]` to the `OsString`s the trait wants.
pub(crate) fn os_args(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

/// The last `max_chars` characters of `text`, whitespace trimmed.
pub(crate) fn tail(text: &str, max_chars: usize) -> String {
    let trimmed = text.trim();
    let count = trimmed.chars().count();
    if count <= max_chars {
        return trimmed.to_owned();
    }
    let skipped = count.saturating_sub(max_chars);
    format!("…{}", trimmed.chars().skip(skipped).collect::<String>())
}

/// A one-line reason for a failed run: the exit code (or the timeout) and the end of stderr.
pub(crate) fn failure_reason(output: &Output) -> String {
    let stderr = tail(&output.stderr_text(), 400);
    let what = if output.timed_out {
        format!("timed out after {}s", output.duration.as_secs())
    } else {
        match output.code {
            Some(code) => format!("exit code {code}"),
            None => "killed by a signal".to_owned(),
        }
    };
    if stderr.is_empty() {
        what
    } else {
        format!("{what}: {stderr}")
    }
}

/// [`failure_reason`] for sibling modules.
pub(crate) fn failure_reason_pub(output: &Output) -> String {
    failure_reason(output)
}

/// [`tail`] for sibling modules.
pub(crate) fn tail_pub(text: &str, max_chars: usize) -> String {
    tail(text, max_chars)
}

/// The output from its first `{` or `[` on: tools that print a banner before their JSON.
pub(crate) fn first_json(bytes: &[u8]) -> &[u8] {
    bytes
        .iter()
        .position(|b| *b == b'{' || *b == b'[')
        .and_then(|start| bytes.get(start..))
        .unwrap_or(&[])
}

/// `CWE-95: Eval Injection` or `95` → `95`.
pub(crate) fn cwe_number(text: &str) -> Option<u32> {
    let digits: String = text
        .trim()
        .trim_start_matches(|c: char| !c.is_ascii_digit())
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// Sort and deduplicate a CWE list.
pub(crate) fn cwes(raw: impl IntoIterator<Item = Option<u32>>) -> Vec<u32> {
    let mut out: Vec<u32> = raw.into_iter().flatten().collect();
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    pub(crate) use crate::exec::test_support::output;

    #[test]
    fn registry_names_are_unique_and_lookup_is_case_insensitive() {
        let names = names();
        assert_eq!(names, vec!["semgrep", "bearer", "trivy", "luacheck"]);
        assert!(by_name("Semgrep").is_some());
        assert!(by_name(" luacheck ").is_some());
        assert!(by_name("codeql").is_none());
        let mut bins: Vec<_> = registry().iter().map(|s| s.binary()).collect();
        bins.sort_unstable();
        bins.dedup();
        assert_eq!(bins.len(), names.len());
        for scanner in registry() {
            assert_eq!(
                crate::update::short_name(scanner.mise_id()),
                scanner.binary(),
                "{}",
                scanner.name()
            );
        }
    }

    #[test]
    fn tail_keeps_the_end_and_respects_char_boundaries() {
        assert_eq!(tail("  abc  ", 10), "abc");
        assert_eq!(tail("abcdef", 3), "…def");
        assert_eq!(tail("ééééé", 2), "…éé");
    }

    #[test]
    fn failure_reason_describes_exit_timeout_and_signal() {
        assert_eq!(
            failure_reason(&output(Some(2), b"", "boom\n")),
            "exit code 2: boom"
        );
        assert_eq!(failure_reason(&output(None, b"", "")), "killed by a signal");
        let mut timed = output(None, b"", "");
        timed.timed_out = true;
        timed.duration = Duration::from_secs(600);
        assert_eq!(failure_reason(&timed), "timed out after 600s");
    }

    #[test]
    fn first_json_skips_banners() {
        assert_eq!(
            first_json(b"Analyzing codebase\n{\"a\":1}\n"),
            b"{\"a\":1}\n"
        );
        assert_eq!(first_json(b"[1]"), b"[1]");
        assert_eq!(first_json(b"nothing"), b"");
    }

    #[test]
    fn tolerant_helpers() {
        #[derive(Deserialize)]
        struct T {
            #[serde(default, deserialize_with = "null_default")]
            list: Vec<String>,
            #[serde(default, deserialize_with = "null_default")]
            flag: bool,
            #[serde(default)]
            strings: Strings,
        }
        let t: T = serde_json::from_str(
            r#"{"list": null, "flag": null, "strings": ["a", 7, true, null, {"x":1}, ["b"]]}"#,
        )
        .unwrap();
        assert!(t.list.is_empty());
        assert!(!t.flag);
        assert_eq!(t.strings.0, vec!["a", "7", "true", "b"]);
        let t: T = serde_json::from_str(r#"{"strings": "single"}"#).unwrap();
        assert_eq!(t.strings.0, vec!["single"]);
        assert_eq!(cap("abc", 5), "abc");
        assert_eq!(cap("abcdef", 3), "abc…");
        let mut list = vec!["a".to_owned()];
        push_unique(&mut list, " a ");
        push_unique(&mut list, "");
        push_unique(&mut list, "b");
        assert_eq!(list, vec!["a", "b"]);
        assert_eq!(value_text(&serde_json::json!("s")), "s");
        assert_eq!(
            value_text(&serde_json::json!({"k": [1, 2]})),
            r#"{"k":[1,2]}"#
        );
    }

    #[test]
    fn cwe_numbers_are_extracted() {
        assert_eq!(
            cwe_number("CWE-352: Cross-Site Request Forgery (CSRF)"),
            Some(352)
        );
        assert_eq!(cwe_number("95"), Some(95));
        assert_eq!(cwe_number(" cwe-79 "), Some(79));
        assert_eq!(cwe_number("none"), None);
        assert_eq!(cwes([Some(95), None, Some(94), Some(95)]), vec![94, 95]);
    }
}
