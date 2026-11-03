//! The report data model shared by every scanner adapter and every output format.
//!
//! The rule of the model: **a parser keeps everything a scanner says**. What has a meaning
//! across tools gets a typed field (severity, confidence, CWE, OWASP, location, snippet, data
//! flow…); what is specific to one tool goes verbatim into [`Finding::extra`]; what the tool
//! says about the run itself — files it skipped, rules that errored — goes into [`ToolRun`].

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// How bad a finding is, in ascending order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational.
    Info,
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
    /// Critical.
    Critical,
}

impl Severity {
    /// Every severity, worst first.
    pub const DESCENDING: [Severity; 5] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    /// The lowercase name used in every output format.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `pad` honours width and alignment (`{:<8}`); `write_str` would not.
        f.pad(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            other => Err(format!(
                "unknown severity `{other}` (info, low, medium, high, critical)"
            )),
        }
    }
}

/// How sure the scanner is.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
}

impl Confidence {
    /// `LOW` / `medium` / `High` → the level; anything else → `None`.
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "low" => Some(Confidence::Low),
            "medium" => Some(Confidence::Medium),
            "high" => Some(Confidence::High),
            _ => None,
        }
    }

    /// The lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

/// The role of a step in a data flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowKind {
    /// Where the tainted data enters.
    Source,
    /// A variable or call it goes through.
    Intermediate,
    /// Where it does damage.
    Sink,
}

impl FlowKind {
    /// The lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            FlowKind::Source => "source",
            FlowKind::Intermediate => "intermediate",
            FlowKind::Sink => "sink",
        }
    }
}

/// One step of a data flow (taint source → sink).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowStep {
    /// Role.
    pub kind: FlowKind,
    /// File, relative to the scanned directory.
    pub path: PathBuf,
    /// 1-based first line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// 1-based column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    /// 1-based last line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    /// 1-based last column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u32>,
    /// The code at that step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

/// One finding, normalised across scanners.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// The scanner that reported it first.
    pub tool: String,
    /// Other scanners that reported the same thing (filled by deduplication).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also_reported_by: Vec<String>,
    /// The scanner's rule identifier.
    pub rule_id: String,
    /// Normalised severity.
    pub severity: Severity,
    /// How sure the scanner is, when it says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
    /// Suppressed in the code (a `nosemgrep` comment…): kept in the report, left out of the
    /// counts and of the exit code.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub suppressed: bool,
    /// Why sast3uh set the finding aside (confidence below the floor, in the baseline, in
    /// the ignore file…): still in the report, out of the counts and of the exit code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filtered: Option<String>,
    /// A short title.
    pub title: String,
    /// The scanner's message.
    pub message: String,
    /// File the finding points at, relative to the scanned directory.
    pub path: PathBuf,
    /// 1-based first line, when the scanner gives one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// 1-based last line, when the scanner gives one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    /// 1-based column, when the scanner gives one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    /// 1-based last column, when the scanner gives one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u32>,
    /// CWE identifiers (numbers only), sorted and unique.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwes: Vec<u32>,
    /// OWASP categories, as the scanner names them (`A01:2021 - Broken Access Control`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owasp: Vec<String>,
    /// What kind of problem it is (`security`, `audit`, `PII`, `Hard-coded Secrets`…).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    /// Technologies or data types involved (`express`, `stripe`, `ID Number`…).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// The offending code, as the scanner extracted it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    /// A fix the scanner suggests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    /// Links to read more.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    /// The rule's own documentation link, when the scanner gives one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// The scanner's own fingerprint, when it gives one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// The data flow that leads to the finding, when the scanner traced one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flow: Vec<FlowStep>,
    /// Everything else the scanner said, verbatim, keyed by the scanner's own field name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, String>,
}

impl Finding {
    /// `true` when the finding counts: neither suppressed by its tool nor set aside by
    /// sast3uh's triage.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.suppressed && self.filtered.is_none()
    }

    /// A finding with only the required fields; set the rest as the scanner provides them.
    pub fn new(
        tool: impl Into<String>,
        rule_id: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
        message: impl Into<String>,
        path: PathBuf,
    ) -> Self {
        Finding {
            tool: tool.into(),
            also_reported_by: Vec::new(),
            rule_id: rule_id.into(),
            severity,
            confidence: None,
            suppressed: false,
            filtered: None,
            title: title.into(),
            message: message.into(),
            path,
            line: None,
            end_line: None,
            column: None,
            end_column: None,
            cwes: Vec::new(),
            owasp: Vec::new(),
            categories: Vec::new(),
            tags: Vec::new(),
            snippet: None,
            fix: None,
            references: Vec::new(),
            url: None,
            fingerprint: None,
            flow: Vec::new(),
            extra: BTreeMap::new(),
        }
    }
}

/// Normalise a path reported by a scanner: relative, forward slashes, no `.` or `..`.
///
/// Returns `None` for anything that could point outside the scanned directory: an absolute
/// path, a drive prefix, a `..` component, or an empty path.
pub fn normalize_reported_path(raw: &str) -> Option<PathBuf> {
    let trimmed = raw.trim().replace('\\', "/");
    if trimmed.is_empty() || trimmed.starts_with('/') {
        return None;
    }
    // A drive letter (`C:`) is a prefix on Windows and an odd file name elsewhere: refuse both.
    if trimmed
        .split('/')
        .next()
        .is_some_and(|first| first.contains(':'))
    {
        return None;
    }
    let mut out = PathBuf::new();
    for component in Path::new(&trimmed).components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

/// A file the scanner chose not to scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedPath {
    /// The path as the scanner printed it.
    pub path: String,
    /// Why.
    pub reason: String,
}

/// Something the scanner reported about its own run (a rule that errored, a parse failure…).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// `warn`, `error`, … as the scanner says it.
    pub level: String,
    /// The rule concerned, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// The file concerned, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The message.
    pub message: String,
}

/// What happened to one scanner during a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum ToolStatus {
    /// It ran and its output was parsed.
    Completed,
    /// It did not run, on purpose (not installed, nothing for it to scan, excluded).
    Skipped {
        /// Why.
        reason: String,
    },
    /// It ran (or tried to) and the result is unusable.
    Failed {
        /// Why.
        reason: String,
    },
}

/// One scanner's run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolRun {
    /// Scanner name.
    pub tool: String,
    /// Installed version, when it could be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Outcome.
    pub status: ToolStatus,
    /// Findings it contributed before deduplication.
    pub findings: usize,
    /// Wall-clock time of the scan, in milliseconds.
    pub duration_ms: u64,
    /// How many files it scanned, when it says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanned_files: Option<usize>,
    /// Files it chose not to scan, when it says.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped_paths: Vec<SkippedPath>,
    /// What it reported about its own run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
}

impl ToolRun {
    /// A run with no scan details yet.
    pub fn new(tool: impl Into<String>, version: Option<String>, status: ToolStatus) -> Self {
        ToolRun {
            tool: tool.into(),
            version,
            status,
            findings: 0,
            duration_ms: 0,
            scanned_files: None,
            skipped_paths: Vec::new(),
            diagnostics: Vec::new(),
        }
    }
}

/// Finding counts. Suppressed findings are counted apart and nowhere else.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    /// Active findings after deduplication.
    pub total: usize,
    /// Critical findings.
    pub critical: usize,
    /// High findings.
    pub high: usize,
    /// Medium findings.
    pub medium: usize,
    /// Low findings.
    pub low: usize,
    /// Informational findings.
    pub info: usize,
    /// Findings suppressed in the code.
    pub suppressed: usize,
    /// Findings set aside by sast3uh's triage (see `Finding::filtered`), counted apart.
    #[serde(default)]
    pub filtered: usize,
    /// Findings dropped or merged by deduplication.
    pub duplicates_removed: usize,
}

impl Summary {
    /// Count `findings` by severity.
    pub fn of(findings: &[Finding], duplicates_removed: usize) -> Self {
        let mut summary = Summary {
            duplicates_removed,
            ..Summary::default()
        };
        for finding in findings {
            if finding.suppressed {
                summary.suppressed += 1;
                continue;
            }
            if finding.filtered.is_some() {
                summary.filtered += 1;
                continue;
            }
            summary.total += 1;
            match finding.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
                Severity::Info => summary.info += 1,
            }
        }
        summary
    }

    /// The count for one severity.
    pub fn count(&self, severity: Severity) -> usize {
        match severity {
            Severity::Critical => self.critical,
            Severity::High => self.high,
            Severity::Medium => self.medium,
            Severity::Low => self.low,
            Severity::Info => self.info,
        }
    }
}

/// The merged result of a scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// Format version of this report.
    pub schema_version: u32,
    /// When the report was produced (RFC 3339, UTC).
    pub generated_at: String,
    /// The scanned directory, canonicalised.
    pub target: PathBuf,
    /// One entry per scanner that was considered.
    pub tools: Vec<ToolRun>,
    /// Counts.
    pub summary: Summary,
    /// Every finding, worst first.
    pub findings: Vec<Finding>,
}

impl Report {
    /// The current schema version.
    pub const SCHEMA_VERSION: u32 = 3;

    /// Assemble a report; `findings` must already be deduplicated and sorted.
    pub fn new(
        target: PathBuf,
        generated_at: String,
        tools: Vec<ToolRun>,
        findings: Vec<Finding>,
        duplicates_removed: usize,
    ) -> Self {
        let summary = Summary::of(&findings, duplicates_removed);
        Report {
            schema_version: Self::SCHEMA_VERSION,
            generated_at,
            target,
            tools,
            summary,
            findings,
        }
    }

    /// The findings that count: neither suppressed nor set aside.
    pub fn active(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| f.is_active())
    }

    /// `true` when there is no active finding.
    pub fn is_clean(&self) -> bool {
        self.active().next().is_none()
    }

    /// The worst active severity, if any.
    pub fn max_severity(&self) -> Option<Severity> {
        self.active().map(|f| f.severity).max()
    }

    /// `true` when at least one active finding is at or above `threshold`.
    pub fn has_findings_at_or_above(&self, threshold: Severity) -> bool {
        self.max_severity().is_some_and(|worst| worst >= threshold)
    }

    /// `true` when at least one scanner failed.
    pub fn has_failures(&self) -> bool {
        self.tools
            .iter()
            .any(|t| matches!(t.status, ToolStatus::Failed { .. }))
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// A finding with sensible defaults for tests.
    pub(crate) fn finding(
        tool: &str,
        rule: &str,
        severity: Severity,
        path: &str,
        line: u32,
    ) -> Finding {
        let mut f = Finding::new(
            tool,
            rule,
            severity,
            rule,
            format!("{rule} at {path}:{line}"),
            PathBuf::from(path),
        );
        f.line = Some(line);
        f
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::finding;
    use super::*;

    #[test]
    fn severities_order_from_info_to_critical() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
        assert_eq!(Severity::DESCENDING.first(), Some(&Severity::Critical));
    }

    #[test]
    fn severity_parses_case_insensitively_and_rejects_junk() {
        assert_eq!("HIGH".parse::<Severity>(), Ok(Severity::High));
        assert_eq!(" info ".parse::<Severity>(), Ok(Severity::Info));
        assert!("urgent".parse::<Severity>().unwrap_err().contains("urgent"));
        assert_eq!(Severity::Medium.to_string(), "medium");
        assert_eq!(format!("{:<8}|", Severity::Low), "low     |");
    }

    #[test]
    fn severity_and_confidence_serialise_in_lowercase() {
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            "\"critical\""
        );
        assert_eq!(
            serde_json::from_str::<Severity>("\"low\"").unwrap(),
            Severity::Low
        );
        assert_eq!(
            serde_json::to_string(&Confidence::High).unwrap(),
            "\"high\""
        );
        assert_eq!(Confidence::parse("MEDIUM"), Some(Confidence::Medium));
        assert_eq!(Confidence::parse(""), None);
        assert_eq!(Confidence::parse("certain"), None);
        assert_eq!(Confidence::Low.to_string(), "low");
        assert_eq!(FlowKind::Sink.as_str(), "sink");
    }

    #[test]
    fn reported_paths_are_normalised() {
        assert_eq!(
            normalize_reported_path("./src/app.js"),
            Some(PathBuf::from("src/app.js"))
        );
        assert_eq!(
            normalize_reported_path("src\\app.js"),
            Some(PathBuf::from("src/app.js"))
        );
        assert_eq!(normalize_reported_path("a/./b"), Some(PathBuf::from("a/b")));
        assert_eq!(
            normalize_reported_path("  x.lua \n"),
            Some(PathBuf::from("x.lua"))
        );
    }

    #[test]
    fn reported_paths_that_could_escape_the_target_are_rejected() {
        assert_eq!(normalize_reported_path("/etc/passwd"), None);
        assert_eq!(normalize_reported_path("../secret"), None);
        assert_eq!(normalize_reported_path("src/../../x"), None);
        assert_eq!(normalize_reported_path(""), None);
        assert_eq!(normalize_reported_path("."), None);
        assert_eq!(normalize_reported_path("C:\\x"), None);
    }

    #[test]
    fn summary_counts_each_severity_and_sets_suppressed_apart() {
        let mut suppressed = finding("a", "r5", Severity::Critical, "x", 5);
        suppressed.suppressed = true;
        let findings = vec![
            finding("a", "r1", Severity::Critical, "x", 1),
            finding("a", "r2", Severity::High, "x", 2),
            finding("a", "r3", Severity::High, "x", 3),
            finding("a", "r4", Severity::Info, "x", 4),
            suppressed,
        ];
        let summary = Summary::of(&findings, 2);
        assert_eq!(summary.total, 4);
        assert_eq!(
            summary.critical, 1,
            "the suppressed critical does not count"
        );
        assert_eq!(summary.high, 2);
        assert_eq!(summary.medium, 0);
        assert_eq!(summary.low, 0);
        assert_eq!(summary.info, 1);
        assert_eq!(summary.suppressed, 1);
        assert_eq!(summary.duplicates_removed, 2);
        assert_eq!(summary.count(Severity::High), 2);
    }

    #[test]
    fn report_gate_ignores_suppressed_findings() {
        let tools = vec![ToolRun::new(
            "a",
            None,
            ToolStatus::Failed {
                reason: "boom".into(),
            },
        )];
        let mut suppressed = finding("a", "r2", Severity::Critical, "x", 2);
        suppressed.suppressed = true;
        let findings = vec![finding("a", "r", Severity::Medium, "x", 1), suppressed];
        let report = Report::new(PathBuf::from("/t"), "now".into(), tools, findings, 0);
        assert!(!report.is_clean());
        assert_eq!(
            report.max_severity(),
            Some(Severity::Medium),
            "critical is suppressed"
        );
        assert!(report.has_findings_at_or_above(Severity::Low));
        assert!(report.has_findings_at_or_above(Severity::Medium));
        assert!(!report.has_findings_at_or_above(Severity::High));
        assert!(report.has_failures());
        assert_eq!(report.schema_version, Report::SCHEMA_VERSION);
        assert_eq!(report.active().count(), 1);

        let only_suppressed = Report::new(
            PathBuf::from("/t"),
            "now".into(),
            vec![],
            vec![report.findings[1].clone()],
            0,
        );
        assert!(only_suppressed.is_clean());
        assert_eq!(only_suppressed.summary.suppressed, 1);
        assert!(!only_suppressed.has_findings_at_or_above(Severity::Info));
        assert!(!only_suppressed.has_failures());
    }

    #[test]
    fn finding_json_omits_empty_optionals_and_round_trips() {
        let f = finding("a", "r", Severity::Low, "x", 1);
        let json = serde_json::to_value(&f).unwrap();
        for absent in [
            "also_reported_by",
            "column",
            "cwes",
            "owasp",
            "categories",
            "tags",
            "snippet",
            "fix",
            "references",
            "flow",
            "extra",
            "confidence",
            "suppressed",
        ] {
            assert!(
                json.get(absent).is_none(),
                "{absent} should be omitted: {json}"
            );
        }
        assert_eq!(json["line"], 1);
        let back: Finding = serde_json::from_value(json).unwrap();
        assert_eq!(back, f);

        let mut full = f.clone();
        full.confidence = Some(Confidence::High);
        full.suppressed = true;
        full.end_column = Some(9);
        full.flow.push(FlowStep {
            kind: FlowKind::Source,
            path: PathBuf::from("x"),
            line: Some(1),
            column: Some(2),
            end_line: None,
            end_column: None,
            content: Some("req".into()),
        });
        full.extra.insert("likelihood".into(), "LOW".into());
        let json = serde_json::to_value(&full).unwrap();
        assert_eq!(json["suppressed"], true);
        assert_eq!(json["flow"][0]["kind"], "source");
        assert_eq!(json["extra"]["likelihood"], "LOW");
        let back: Finding = serde_json::from_value(json).unwrap();
        assert_eq!(back, full);
    }

    #[test]
    fn tool_run_json_carries_the_scan_details_only_when_present() {
        let mut run = ToolRun::new("semgrep", Some("1.0.0".into()), ToolStatus::Completed);
        let json = serde_json::to_value(&run).unwrap();
        assert!(json.get("skipped_paths").is_none());
        assert!(json.get("diagnostics").is_none());
        assert!(json.get("scanned_files").is_none());
        run.scanned_files = Some(3);
        run.skipped_paths.push(SkippedPath {
            path: "big.min.js".into(),
            reason: "too large".into(),
        });
        run.diagnostics.push(Diagnostic {
            level: "warn".into(),
            rule_id: Some("r".into()),
            path: None,
            message: "m".into(),
        });
        let json = serde_json::to_value(&run).unwrap();
        assert_eq!(json["scanned_files"], 3);
        assert_eq!(json["skipped_paths"][0]["reason"], "too large");
        assert_eq!(json["diagnostics"][0]["rule_id"], "r");
        assert!(json["diagnostics"][0].get("path").is_none());
        let back: ToolRun = serde_json::from_value(json).unwrap();
        assert_eq!(back, run);
    }

    #[test]
    fn tool_status_is_tagged() {
        let json = serde_json::to_value(ToolStatus::Skipped { reason: "x".into() }).unwrap();
        assert_eq!(json["state"], "skipped");
        assert_eq!(json["reason"], "x");
        assert_eq!(
            serde_json::to_value(ToolStatus::Completed).unwrap()["state"],
            "completed"
        );
    }
}
