//! The report data model shared by every scanner adapter and every output format.

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
    /// CWE identifiers (numbers only), sorted and unique.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwes: Vec<u32>,
    /// Documentation link, when the scanner gives one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// The scanner's own fingerprint, when it gives one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
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
}

/// Finding counts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    /// Findings after deduplication.
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
    /// Findings dropped or merged by deduplication.
    pub duplicates_removed: usize,
}

impl Summary {
    /// Count `findings` by severity.
    pub fn of(findings: &[Finding], duplicates_removed: usize) -> Self {
        let mut summary = Summary {
            total: findings.len(),
            duplicates_removed,
            ..Summary::default()
        };
        for finding in findings {
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
    pub const SCHEMA_VERSION: u32 = 1;

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

    /// `true` when there is nothing to report.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// The worst severity found, if any.
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// `true` when at least one finding is at or above `threshold`.
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
        Finding {
            tool: tool.to_owned(),
            also_reported_by: Vec::new(),
            rule_id: rule.to_owned(),
            severity,
            title: rule.to_owned(),
            message: format!("{rule} at {path}:{line}"),
            path: PathBuf::from(path),
            line: Some(line),
            end_line: None,
            column: None,
            cwes: Vec::new(),
            url: None,
            fingerprint: None,
        }
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
    fn severity_serialises_in_lowercase() {
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            "\"critical\""
        );
        assert_eq!(
            serde_json::from_str::<Severity>("\"low\"").unwrap(),
            Severity::Low
        );
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
    fn summary_counts_each_severity() {
        let findings = vec![
            finding("a", "r1", Severity::Critical, "x", 1),
            finding("a", "r2", Severity::High, "x", 2),
            finding("a", "r3", Severity::High, "x", 3),
            finding("a", "r4", Severity::Info, "x", 4),
        ];
        let summary = Summary::of(&findings, 2);
        assert_eq!(summary.total, 4);
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.high, 2);
        assert_eq!(summary.medium, 0);
        assert_eq!(summary.low, 0);
        assert_eq!(summary.info, 1);
        assert_eq!(summary.duplicates_removed, 2);
        assert_eq!(summary.count(Severity::High), 2);
    }

    #[test]
    fn report_gate_and_failure_helpers() {
        let tools = vec![ToolRun {
            tool: "a".into(),
            version: None,
            status: ToolStatus::Failed {
                reason: "boom".into(),
            },
            findings: 0,
            duration_ms: 1,
        }];
        let findings = vec![finding("a", "r", Severity::Medium, "x", 1)];
        let report = Report::new(PathBuf::from("/t"), "now".into(), tools, findings, 0);
        assert!(!report.is_clean());
        assert_eq!(report.max_severity(), Some(Severity::Medium));
        assert!(report.has_findings_at_or_above(Severity::Low));
        assert!(report.has_findings_at_or_above(Severity::Medium));
        assert!(!report.has_findings_at_or_above(Severity::High));
        assert!(report.has_failures());
        assert_eq!(report.schema_version, Report::SCHEMA_VERSION);

        let empty = Report::new(PathBuf::from("/t"), "now".into(), vec![], vec![], 0);
        assert!(empty.is_clean());
        assert!(!empty.has_findings_at_or_above(Severity::Info));
        assert!(!empty.has_failures());
    }

    #[test]
    fn finding_json_omits_empty_optionals() {
        let f = finding("a", "r", Severity::Low, "x", 1);
        let json = serde_json::to_value(&f).unwrap();
        assert!(json.get("also_reported_by").is_none());
        assert!(json.get("column").is_none());
        assert!(json.get("cwes").is_none());
        assert_eq!(json["line"], 1);
        let back: Finding = serde_json::from_value(json).unwrap();
        assert_eq!(back, f);
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
