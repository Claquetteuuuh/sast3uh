//! Deduplication: the same problem reported twice is one finding.
//!
//! Two rules, applied in order:
//!
//! 1. **Exact duplicates** — same tool, rule, file, line and column — are dropped. A scanner
//!    run twice over an overlapping path does this.
//! 2. **Cross-tool duplicates** — two *different* tools flagging the same file and line with a
//!    CWE in common — are merged into the first one seen: it keeps the worst severity and
//!    confidence, the union of the CWEs, OWASP entries, categories, tags and references, fills
//!    in what it lacked (snippet, fix, flow, link), keeps the other tool's own fields under a
//!    `tool:field` key in `extra`, and lists that tool in `also_reported_by`. Nothing is lost.
//!
//! Two rules of the same tool on the same line are kept apart: they say different things.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::model::Finding;

/// The result of [`dedup`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deduplicated {
    /// Unique findings, worst first.
    pub findings: Vec<Finding>,
    /// How many input findings were dropped or merged.
    pub removed: usize,
}

#[derive(Hash, PartialEq, Eq)]
struct ExactKey {
    tool: String,
    rule_id: String,
    path: PathBuf,
    line: Option<u32>,
    column: Option<u32>,
}

#[derive(Hash, PartialEq, Eq, Clone)]
struct CweKey {
    path: PathBuf,
    line: Option<u32>,
    cwe: u32,
}

/// Deduplicate and sort `input` (see the module documentation).
pub fn dedup(input: Vec<Finding>) -> Deduplicated {
    let mut findings: Vec<Finding> = Vec::with_capacity(input.len());
    let mut exact: HashSet<ExactKey> = HashSet::new();
    let mut by_cwe: HashMap<CweKey, usize> = HashMap::new();
    let mut removed = 0;

    for finding in input {
        let key = ExactKey {
            tool: finding.tool.clone(),
            rule_id: finding.rule_id.clone(),
            path: finding.path.clone(),
            line: finding.line,
            column: finding.column,
        };
        if !exact.insert(key) {
            removed += 1;
            continue;
        }

        let mut merge_target = None;
        for cwe in &finding.cwes {
            let key = CweKey {
                path: finding.path.clone(),
                line: finding.line,
                cwe: *cwe,
            };
            if let Some(&index) = by_cwe.get(&key) {
                let same_tool = findings.get(index).is_some_and(|existing| {
                    existing.tool == finding.tool
                        || existing.also_reported_by.contains(&finding.tool)
                });
                if !same_tool {
                    merge_target = Some(index);
                    break;
                }
            }
        }

        if let Some(existing) = merge_target.and_then(|index| findings.get_mut(index)) {
            merge_into(existing, finding);
            removed += 1;
        } else {
            let index = findings.len();
            for cwe in &finding.cwes {
                by_cwe
                    .entry(CweKey {
                        path: finding.path.clone(),
                        line: finding.line,
                        cwe: *cwe,
                    })
                    .or_insert(index);
            }
            findings.push(finding);
        }
    }

    sort(&mut findings);
    Deduplicated { findings, removed }
}

fn merge_into(existing: &mut Finding, other: Finding) {
    if other.severity > existing.severity {
        existing.severity = other.severity;
    }
    if other.confidence > existing.confidence {
        existing.confidence = other.confidence;
    }
    // Suppressed only when every tool that saw it agrees it is.
    existing.suppressed = existing.suppressed && other.suppressed;
    if !existing.also_reported_by.contains(&other.tool) {
        existing.also_reported_by.push(other.tool.clone());
    }
    existing.cwes.extend(other.cwes);
    existing.cwes.sort_unstable();
    existing.cwes.dedup();
    for (mine, theirs) in [
        (&mut existing.owasp, other.owasp),
        (&mut existing.categories, other.categories),
        (&mut existing.tags, other.tags),
        (&mut existing.references, other.references),
    ] {
        for item in theirs {
            if !mine.contains(&item) {
                mine.push(item);
            }
        }
    }
    for (slot, value) in [
        (&mut existing.url, other.url),
        (&mut existing.snippet, other.snippet),
        (&mut existing.fix, other.fix),
        (&mut existing.fingerprint, other.fingerprint),
    ] {
        if slot.is_none() {
            *slot = value;
        }
    }
    for (slot, value) in [
        (&mut existing.end_line, other.end_line),
        (&mut existing.column, other.column),
        (&mut existing.end_column, other.end_column),
    ] {
        if slot.is_none() {
            *slot = value;
        }
    }
    if existing.flow.is_empty() {
        existing.flow = other.flow;
    }
    existing
        .extra
        .insert(format!("{}:rule_id", other.tool), other.rule_id);
    existing
        .extra
        .insert(format!("{}:title", other.tool), other.title);
    existing
        .extra
        .insert(format!("{}:message", other.tool), other.message);
    for (key, value) in other.extra {
        existing
            .extra
            .insert(format!("{}:{key}", other.tool), value);
    }
}

/// Worst first, then by file, line, column, tool and rule.
pub fn sort(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.column.cmp(&b.column))
            .then_with(|| a.tool.cmp(&b.tool))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;
    use crate::model::test_support::finding;

    fn with_cwes(mut f: Finding, cwes: &[u32]) -> Finding {
        f.cwes = cwes.to_vec();
        f
    }

    #[test]
    fn exact_duplicates_are_dropped() {
        let a = finding("semgrep", "r1", Severity::High, "src/a.js", 7);
        let result = dedup(vec![a.clone(), a.clone(), a.clone()]);
        assert_eq!(result.findings, vec![a]);
        assert_eq!(result.removed, 2);
    }

    #[test]
    fn same_rule_on_different_columns_is_kept() {
        let mut a = finding("semgrep", "r1", Severity::High, "src/a.js", 7);
        a.column = Some(3);
        let mut b = a.clone();
        b.column = Some(20);
        let result = dedup(vec![a, b]);
        assert_eq!(result.findings.len(), 2);
        assert_eq!(result.removed, 0);
    }

    #[test]
    fn different_tools_sharing_a_cwe_on_a_line_are_merged_without_loss() {
        let mut bearer = with_cwes(
            finding("bearer", "js_eval", Severity::Critical, "src/a.js", 7),
            &[95],
        );
        bearer.categories = vec!["PII".into()];
        bearer.snippet = Some("eval(x)".into());
        bearer.confidence = Some(crate::model::Confidence::High);
        bearer
            .extra
            .insert("description".into(), "## Description".into());
        bearer.suppressed = true;
        let mut semgrep = with_cwes(
            finding("semgrep", "eval-detected", Severity::Medium, "src/a.js", 7),
            &[95, 94],
        );
        semgrep.url = Some("https://semgrep.dev/r/x".into());
        semgrep.categories = vec!["security".into()];
        semgrep.confidence = Some(crate::model::Confidence::Low);
        let result = dedup(vec![semgrep, bearer]);
        assert_eq!(result.removed, 1);
        assert_eq!(result.findings.len(), 1);
        let merged = &result.findings[0];
        assert_eq!(merged.tool, "semgrep", "the first one seen is kept");
        assert_eq!(merged.also_reported_by, vec!["bearer".to_owned()]);
        assert_eq!(merged.severity, Severity::Critical, "worst severity wins");
        assert_eq!(
            merged.confidence,
            Some(crate::model::Confidence::High),
            "best confidence wins"
        );
        assert!(!merged.suppressed, "active for semgrep: active");
        assert_eq!(merged.cwes, vec![94, 95]);
        assert_eq!(merged.categories, vec!["security", "PII"]);
        assert_eq!(
            merged.snippet.as_deref(),
            Some("eval(x)"),
            "filled from the other tool"
        );
        assert_eq!(merged.url.as_deref(), Some("https://semgrep.dev/r/x"));
        assert_eq!(merged.extra["bearer:rule_id"], "js_eval");
        assert_eq!(merged.extra["bearer:description"], "## Description");
        assert!(merged.extra.contains_key("bearer:message"));
    }

    #[test]
    fn the_same_tool_reporting_two_rules_on_a_line_is_not_merged() {
        let a = with_cwes(
            finding("semgrep", "eval-detected", Severity::Medium, "src/a.js", 7),
            &[95],
        );
        let b = with_cwes(
            finding(
                "semgrep",
                "code-string-concat",
                Severity::High,
                "src/a.js",
                7,
            ),
            &[95],
        );
        let result = dedup(vec![a, b]);
        assert_eq!(result.findings.len(), 2);
        assert_eq!(result.removed, 0);
    }

    #[test]
    fn a_third_tool_joins_an_existing_merge_once() {
        let a = with_cwes(finding("semgrep", "r", Severity::Low, "x", 1), &[79]);
        let b = with_cwes(finding("bearer", "r", Severity::Low, "x", 1), &[79]);
        let c = with_cwes(finding("codeql", "r", Severity::High, "x", 1), &[79]);
        let c2 = with_cwes(finding("codeql", "r2", Severity::High, "x", 1), &[79]);
        let result = dedup(vec![a, b, c, c2]);
        assert_eq!(
            result.findings.len(),
            2,
            "codeql's second rule stays separate"
        );
        assert_eq!(result.removed, 2);
        let merged = result
            .findings
            .iter()
            .find(|f| f.tool == "semgrep")
            .unwrap();
        assert_eq!(
            merged.also_reported_by,
            vec!["bearer".to_owned(), "codeql".to_owned()]
        );
        assert_eq!(merged.severity, Severity::High);
    }

    #[test]
    fn different_lines_or_files_never_merge() {
        let a = with_cwes(finding("semgrep", "r", Severity::Low, "x", 1), &[79]);
        let b = with_cwes(finding("bearer", "r", Severity::Low, "x", 2), &[79]);
        let c = with_cwes(finding("bearer", "r", Severity::Low, "y", 1), &[79]);
        let result = dedup(vec![a, b, c]);
        assert_eq!(result.findings.len(), 3);
    }

    #[test]
    fn findings_without_cwes_only_dedupe_exactly() {
        let a = finding("semgrep", "r", Severity::Low, "x", 1);
        let b = finding("bearer", "r", Severity::Low, "x", 1);
        let result = dedup(vec![a, b]);
        assert_eq!(result.findings.len(), 2);
    }

    #[test]
    fn output_is_sorted_worst_first_then_by_location() {
        let input = vec![
            finding("b", "r", Severity::Low, "z.rs", 9),
            finding("a", "r", Severity::Critical, "b.rs", 2),
            finding("a", "r", Severity::Critical, "a.rs", 5),
            finding("a", "r", Severity::Critical, "a.rs", 1),
            finding("a", "r2", Severity::High, "a.rs", 1),
        ];
        let result = dedup(input);
        let order: Vec<_> = result
            .findings
            .iter()
            .map(|f| (f.severity, f.path.to_str().unwrap(), f.line))
            .collect();
        assert_eq!(
            order,
            vec![
                (Severity::Critical, "a.rs", Some(1)),
                (Severity::Critical, "a.rs", Some(5)),
                (Severity::Critical, "b.rs", Some(2)),
                (Severity::High, "a.rs", Some(1)),
                (Severity::Low, "z.rs", Some(9)),
            ]
        );
    }

    #[test]
    fn empty_input_is_empty_output() {
        let result = dedup(Vec::new());
        assert!(result.findings.is_empty());
        assert_eq!(result.removed, 0);
    }
}
