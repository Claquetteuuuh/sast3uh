//! What keeps a report readable: findings set aside — never dropped — for a reason that is
//! written on them (`filtered`), and an order that puts the strongest signal first.
//!
//! A finding below the confidence floor, not corroborated when corroboration is required,
//! without a data flow when one is required, present in a baseline report or listed in an
//! ignore file stays in the report with its reason, out of the counts and of the exit code,
//! like a suppressed one. Nothing a scanner said is lost; the default view is just what is
//! worth reading first.

use std::collections::BTreeSet;
use std::path::Path;

use crate::model::{Confidence, Finding};

/// How findings are set aside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Triage {
    /// Findings whose scanner states a confidence below this are set aside, unless another
    /// tool corroborates them. A finding without a stated confidence is kept.
    pub min_confidence: Confidence,
    /// Keep only the findings reported by at least two tools.
    pub corroborated_only: bool,
    /// Keep only the findings that carry a data flow (source → sink).
    pub with_flow_only: bool,
    /// Identities of the findings of a previous report: those are not news.
    pub baseline: BTreeSet<String>,
    /// Identities listed in the ignore file.
    pub ignored: BTreeSet<String>,
    /// Tools whose rules normally state a confidence: one of their findings without a
    /// stated confidence is treated as low.
    pub states_confidence: BTreeSet<String>,
}

impl Default for Triage {
    fn default() -> Self {
        Triage {
            min_confidence: Confidence::Medium,
            corroborated_only: false,
            with_flow_only: false,
            baseline: BTreeSet::new(),
            ignored: BTreeSet::new(),
            states_confidence: BTreeSet::new(),
        }
    }
}

/// The stable identity of a finding: the scanner's fingerprint when it gave one, else
/// `tool:rule:path:line`. What an ignore file or a baseline matches on.
#[must_use]
pub fn identity(f: &Finding) -> String {
    f.fingerprint.clone().unwrap_or_else(|| key(f))
}

/// The positional key of a finding, `tool:rule:path:line` (`-` without a line); accepted in
/// an ignore file next to fingerprints, and what a baseline matches when a tool gives no
/// fingerprint.
#[must_use]
pub fn key(f: &Finding) -> String {
    format!(
        "{}:{}:{}:{}",
        f.tool,
        f.rule_id,
        f.path.display(),
        f.line.map_or_else(|| "-".to_owned(), |l| l.to_string())
    )
}

/// Both identities a listed entry may name.
fn identities(f: &Finding) -> [String; 2] {
    [identity(f), key(f)]
}

/// Set aside, with its reason, every finding `triage` says to; the others keep `filtered`
/// empty. Suppressed findings are left alone.
pub fn apply(findings: &mut [Finding], triage: &Triage) {
    for f in findings.iter_mut() {
        if f.suppressed {
            continue;
        }
        f.filtered = reason(f, triage);
    }
}

fn reason(f: &Finding, triage: &Triage) -> Option<String> {
    let ids = identities(f);
    if ids.iter().any(|id| triage.ignored.contains(id)) {
        return Some("ignored by the ignore file".to_owned());
    }
    if ids.iter().any(|id| triage.baseline.contains(id)) {
        return Some("already in the baseline".to_owned());
    }
    let corroborated = !f.also_reported_by.is_empty();
    if triage.corroborated_only && !corroborated {
        return Some("reported by one tool only".to_owned());
    }
    if triage.with_flow_only && f.flow.is_empty() {
        return Some("no data flow".to_owned());
    }
    if corroborated {
        return None;
    }
    match f.confidence {
        Some(confidence) if confidence < triage.min_confidence => Some(format!(
            "confidence {confidence} below {}",
            triage.min_confidence
        )),
        None if triage.min_confidence > Confidence::Low
            && triage.states_confidence.contains(&f.tool) =>
        {
            Some("rule states no confidence (treated as low)".to_owned())
        }
        _ => None,
    }
}

/// The identities of every finding of a JSON report written by sast3uh (any version: only
/// `findings[].{fingerprint,tool,rule_id,path,line}` are read).
///
/// # Errors
///
/// When the file cannot be read or is not a sast3uh JSON report.
pub fn load_baseline(path: &Path) -> Result<BTreeSet<String>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let root: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("{}: not a JSON report: {e}", path.display()))?;
    let findings = root
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("{}: no `findings` list", path.display()))?;
    let mut ids = BTreeSet::new();
    for f in findings {
        let text = |k: &str| f.get(k).and_then(serde_json::Value::as_str).unwrap_or("");
        if let Some(fp) = f.get("fingerprint").and_then(serde_json::Value::as_str) {
            ids.insert(fp.to_owned());
        }
        let line = f
            .get("line")
            .and_then(serde_json::Value::as_u64)
            .map_or_else(|| "-".to_owned(), |l| l.to_string());
        ids.insert(format!(
            "{}:{}:{}:{line}",
            text("tool"),
            text("rule_id"),
            text("path")
        ));
    }
    Ok(ids)
}

/// The identities listed in an ignore file: one per line, `#` starts a comment, blank lines
/// and surrounding whitespace ignored.
///
/// # Errors
///
/// When the file cannot be read.
pub fn load_ignore_file(path: &Path) -> Result<BTreeSet<String>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(parse_ignore_list(&text))
}

/// See [`load_ignore_file`].
#[must_use]
pub fn parse_ignore_list(text: &str) -> BTreeSet<String> {
    text.lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Append `ids` to the ignore file at `path` (created when missing), each with `reason` as a
/// comment, skipping those already listed; returns how many were added.
///
/// # Errors
///
/// When the file cannot be read or written.
pub fn add_to_ignore_file(
    path: &Path,
    ids: &[String],
    reason: Option<&str>,
) -> Result<usize, String> {
    let existing = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let listed = parse_ignore_list(&existing);
    let mut text = existing;
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    let mut added = 0;
    for id in ids {
        let id = id.trim();
        if id.is_empty() || listed.contains(id) || id.contains('\n') {
            continue;
        }
        text.push_str(id);
        if let Some(reason) = reason.map(str::trim).filter(|r| !r.is_empty()) {
            text.push_str("  # ");
            text.push_str(&reason.replace(['\n', '\r'], " "));
        }
        text.push('\n');
        added += 1;
    }
    crate::output::write_atomically(path, text.as_bytes())
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(added)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::test_support::finding;
    use crate::model::{FlowKind, FlowStep, Severity};

    fn with(confidence: Option<Confidence>, also: &[&str], flow: bool) -> Finding {
        let mut f = finding("semgrep", "r", Severity::High, "a.js", 3);
        f.confidence = confidence;
        f.also_reported_by = also.iter().map(|s| (*s).to_owned()).collect();
        if flow {
            f.flow.push(FlowStep {
                kind: FlowKind::Source,
                path: "a.js".into(),
                line: Some(1),
                column: None,
                end_line: None,
                end_column: None,
                content: None,
            });
        }
        f
    }

    #[test]
    fn confidence_below_the_floor_is_set_aside_unless_corroborated_or_unknown() {
        let mut findings = vec![
            with(Some(Confidence::Low), &[], false),
            with(Some(Confidence::Medium), &[], false),
            with(Some(Confidence::High), &[], false),
            with(None, &[], false),
            with(Some(Confidence::Low), &["bearer"], false),
        ];
        apply(&mut findings, &Triage::default());
        let reasons: Vec<Option<&str>> = findings.iter().map(|f| f.filtered.as_deref()).collect();
        assert_eq!(
            reasons,
            vec![Some("confidence low below medium"), None, None, None, None]
        );
        let strict = Triage {
            min_confidence: Confidence::High,
            ..Triage::default()
        };
        apply(&mut findings, &strict);
        assert!(findings[1].filtered.is_some());
        assert!(findings[2].filtered.is_none());
        let lax = Triage {
            min_confidence: Confidence::Low,
            ..Triage::default()
        };
        apply(&mut findings, &lax);
        assert!(findings.iter().all(|f| f.filtered.is_none()));

        // A Semgrep rule without confidence metadata is treated as low; Bearer never states
        // one and is left alone.
        let states = Triage {
            states_confidence: ["semgrep".to_owned()].into_iter().collect(),
            ..Triage::default()
        };
        let mut bearer = with(None, &[], true);
        bearer.tool = "bearer".to_owned();
        let mut findings = vec![
            with(None, &[], false),
            bearer,
            with(None, &["bearer"], false),
        ];
        apply(&mut findings, &states);
        assert_eq!(
            findings[0].filtered.as_deref(),
            Some("rule states no confidence (treated as low)")
        );
        assert_eq!(findings[1].filtered, None);
        assert_eq!(findings[2].filtered, None, "corroboration wins");
        apply(
            &mut findings,
            &Triage {
                min_confidence: Confidence::Low,
                ..states
            },
        );
        assert!(findings.iter().all(|f| f.filtered.is_none()));
    }

    #[test]
    fn corroboration_and_flow_filters_and_suppressed_findings_are_left_alone() {
        let mut findings = vec![
            with(Some(Confidence::High), &[], true),
            with(Some(Confidence::High), &["codeql"], false),
        ];
        let mut suppressed = with(Some(Confidence::Low), &[], false);
        suppressed.suppressed = true;
        findings.push(suppressed);
        apply(
            &mut findings,
            &Triage {
                corroborated_only: true,
                ..Triage::default()
            },
        );
        assert_eq!(
            findings[0].filtered.as_deref(),
            Some("reported by one tool only")
        );
        assert_eq!(findings[1].filtered, None);
        assert_eq!(
            findings[2].filtered, None,
            "suppressed stays suppressed, not filtered"
        );
        apply(
            &mut findings,
            &Triage {
                with_flow_only: true,
                ..Triage::default()
            },
        );
        assert_eq!(findings[0].filtered, None);
        assert_eq!(findings[1].filtered.as_deref(), Some("no data flow"));
    }

    #[test]
    fn ignore_list_and_baseline_match_fingerprints_or_keys() {
        let mut a = with(Some(Confidence::High), &[], false);
        a.fingerprint = Some("abc123".to_owned());
        let b = with(Some(Confidence::High), &[], false);
        assert_eq!(identity(&a), "abc123");
        assert_eq!(identity(&b), "semgrep:r:a.js:3");
        assert_eq!(key(&a), "semgrep:r:a.js:3");
        let triage = Triage {
            ignored: parse_ignore_list(
                "# reviewed\nabc123  # false positive\n\n  semgrep:r:a.js:3\n",
            ),
            ..Triage::default()
        };
        let mut findings = vec![a.clone(), b.clone()];
        apply(&mut findings, &triage);
        assert!(
            findings
                .iter()
                .all(|f| f.filtered.as_deref() == Some("ignored by the ignore file"))
        );
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("old.json");
        std::fs::write(
            &report,
            serde_json::json!({"findings": [
                {"tool": "semgrep", "rule_id": "r", "path": "a.js", "line": 3, "fingerprint": "abc123"},
                {"tool": "trivy", "rule_id": "CVE-1", "path": "lock", "line": null}
            ]})
            .to_string(),
        )
        .unwrap();
        let baseline = load_baseline(&report).unwrap();
        assert!(
            baseline.contains("abc123")
                && baseline.contains("semgrep:r:a.js:3")
                && baseline.contains("trivy:CVE-1:lock:-")
        );
        let mut findings = vec![a, b];
        apply(
            &mut findings,
            &Triage {
                baseline,
                ..Triage::default()
            },
        );
        assert!(
            findings
                .iter()
                .all(|f| f.filtered.as_deref() == Some("already in the baseline"))
        );
        assert!(load_baseline(&dir.path().join("missing.json")).is_err());
        std::fs::write(dir.path().join("bad.json"), b"[]").unwrap();
        assert!(
            load_baseline(&dir.path().join("bad.json"))
                .unwrap_err()
                .contains("findings")
        );
    }

    #[test]
    fn the_ignore_file_grows_without_duplicates_and_keeps_reasons() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".sast3uh-ignore");
        let added = add_to_ignore_file(
            &file,
            &["abc".to_owned(), "semgrep:r:a.js:3".to_owned()],
            Some("reviewed\nby me"),
        )
        .unwrap();
        assert_eq!(added, 2);
        let added = add_to_ignore_file(
            &file,
            &["abc".to_owned(), " ".to_owned(), "new".to_owned()],
            None,
        )
        .unwrap();
        assert_eq!(added, 1);
        let text = std::fs::read_to_string(&file).unwrap();
        assert_eq!(
            text,
            "abc  # reviewed by me\nsemgrep:r:a.js:3  # reviewed by me\nnew\n"
        );
        assert_eq!(load_ignore_file(&file).unwrap().len(), 3);
        assert!(load_ignore_file(&dir.path().join("nope")).is_err());
    }
}
