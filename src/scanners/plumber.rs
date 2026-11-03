//! Plumber (<https://getplumber.io>): the CI/CD trust policy of the scanned repository —
//! GitHub Actions and GitLab CI workflows, attack paths, action pinning, permissions,
//! injections, container images.
//!
//! Plumber works on a git clone whose `origin` remote names the provider; on anything else it
//! stops with "could not determine the provider", which sast3uh reports as *skipped*. The
//! repository settings (branch protection) need a provider token: without one in the
//! environment that control is skipped on purpose, otherwise Plumber withholds its score and
//! every severity ("degraded" data collection).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;

use super::{
    Context, Outcome, Parsed, ScanOptions, Scanner, TEXT_CAP, cap, failure_reason, null_default,
    os_args, push_unique, read_report, value_text,
};
use crate::detect::Marker;
use crate::exec::Output;
use crate::model::{Diagnostic, Finding, FlowKind, FlowStep, Severity};

/// Plumber, through `plumber analyze`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Plumber;

/// Variables Plumber reads for the provider API; nothing else of the environment reaches it.
pub const TOKENS: &[&str] = &[
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "GITLAB_TOKEN",
];
/// Name of the JSON report in the scratch directory.
const REPORT: &str = "plumber.json";
/// What Plumber says outside a clone with a usable remote.
const NO_PROVIDER: &str = "could not determine the provider";
/// The control that needs the provider API.
const BRANCH_CONTROL: &str = "branchMustBeProtected";
/// Rule id of an attack path (a `pathBlocks` entry), which has no issue code of its own.
pub const ATTACK_PATH: &str = "attack-path";
/// Where an issue code is documented.
const DOCS: &str = "https://getplumber.io/docs/cli/issues/";

impl Plumber {
    /// Arguments of `plumber analyze` writing its JSON report to `report`. Every control is
    /// evaluated (`--min-points 0` so the exit code never says "gate"); without a provider
    /// token the branch-protection control is skipped (see the module documentation).
    #[must_use]
    pub fn analyze_args(report: &Path, has_token: bool) -> Vec<OsString> {
        let mut args = os_args(&["analyze", "--min-points", "0", "--print=false"]);
        if !has_token {
            args.extend(os_args(&["--skip-controls", BRANCH_CONTROL]));
        }
        args.push("--output".into());
        args.push(report.into());
        args
    }

    fn applies(options: &ScanOptions) -> bool {
        let markers = &options.detected.markers;
        markers.contains(&Marker::GithubActions) || markers.contains(&Marker::GitlabCi)
    }
}

impl Scanner for Plumber {
    fn name(&self) -> &'static str {
        "plumber"
    }

    fn binary(&self) -> &'static str {
        "plumber"
    }

    fn purpose(&self) -> &'static str {
        "CI/CD pipeline hardening: GitHub Actions and GitLab CI workflows, attack paths, \
         pinning, permissions, injections, images"
    }

    fn mise_id(&self) -> &'static str {
        "github:getplumber/plumber"
    }

    fn version_args(&self) -> Vec<OsString> {
        os_args(&["version"])
    }

    fn inherit_env(&self) -> &'static [&'static str] {
        TOKENS
    }

    fn env(&self) -> Vec<(OsString, OsString)> {
        vec![("NO_COLOR".into(), "1".into())]
    }

    fn plan(&self, options: &ScanOptions) -> Option<String> {
        Self::applies(options)
            .then(|| "CI/CD trust policy on the clone's workflows (every control)".to_owned())
    }

    fn interpret(&self, output: &Output) -> Outcome {
        if output.timed_out {
            return Outcome::Failed(failure_reason(output));
        }
        if output.code == Some(2) {
            let stderr = output.stderr_text();
            if stderr.contains(NO_PROVIDER) {
                return Outcome::Skipped(
                    "not a git clone with a GitHub or GitLab remote (Plumber needs one)".to_owned(),
                );
            }
            return Outcome::Failed(failure_reason(output));
        }
        // 0: passed, 1: gate (never, with --min-points 0), 3: degraded data collection — the
        // report is written in every case.
        if !matches!(output.code, Some(0 | 1 | 3)) {
            return Outcome::Failed(failure_reason(output));
        }
        match parse(&output.stdout) {
            Ok(parsed) => Outcome::Completed(parsed),
            Err(err) => Outcome::Failed(format!("{}; {err}", failure_reason(output))),
        }
    }

    fn execute(&self, ctx: &mut Context<'_>) -> Outcome {
        if !Self::applies(ctx.options) {
            return Outcome::Skipped(
                "no CI/CD configuration (.github/workflows, .gitlab-ci.yml)".to_owned(),
            );
        }
        let report = match ctx.scratch() {
            Ok(dir) => dir.join(REPORT),
            Err(err) => return Outcome::Failed(err),
        };
        let has_token = ctx
            .inherited
            .iter()
            .any(|(key, _)| TOKENS.iter().any(|token| key == token));
        let inv = ctx.invocation(Self::analyze_args(&report, has_token), &self.env());
        let mut output = match ctx.run(&inv) {
            Ok(output) => output,
            Err(err) => return Outcome::Failed(err.to_string()),
        };
        match read_report(&report, ctx.max_output) {
            Ok(bytes) => output.stdout = bytes,
            // A missing report with exit code 2 is explained by standard error.
            Err(_) if output.code == Some(2) || output.timed_out => {}
            Err(err) => {
                return Outcome::Failed(format!("{}; no report: {err}", failure_reason(&output)));
            }
        }
        self.interpret(&output)
    }
}

/// One control's block (`<name>Result`).
#[derive(Deserialize)]
struct Control {
    #[serde(default, deserialize_with = "null_default")]
    name: String,
    #[serde(default, rename = "controlName", deserialize_with = "null_default")]
    key: String,
    #[serde(default, deserialize_with = "null_default")]
    category: String,
    #[serde(default, deserialize_with = "null_default")]
    status: String,
    #[serde(default, deserialize_with = "null_default")]
    issues: Vec<Value>,
}

#[derive(Deserialize)]
struct Issue {
    code: String,
    #[serde(default, deserialize_with = "null_default")]
    title: String,
    #[serde(default)]
    explanation: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default, rename = "baseSeverity")]
    base_severity: Option<String>,
    #[serde(default, rename = "occurrenceSeverity")]
    occurrence_severity: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default, rename = "docUrl")]
    doc_url: Option<String>,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default)]
    identity: Option<Identity>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default, rename = "pathIds", deserialize_with = "null_default")]
    path_ids: Vec<String>,
    #[serde(flatten)]
    rest: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
struct Identity {
    #[serde(default, deserialize_with = "null_default")]
    fields: Vec<IdentityField>,
}

#[derive(Deserialize)]
struct IdentityField {
    key: String,
    #[serde(default)]
    value: Value,
}

#[derive(Deserialize)]
struct PathBlock {
    #[serde(default, deserialize_with = "null_default")]
    id: String,
    #[serde(default, deserialize_with = "null_default")]
    tier: String,
    #[serde(default, deserialize_with = "null_default")]
    entry: String,
    #[serde(default, deserialize_with = "null_default")]
    so: String,
    #[serde(default, deserialize_with = "null_default")]
    fix: String,
    #[serde(default, deserialize_with = "null_default")]
    findings: Vec<PathFinding>,
    #[serde(flatten)]
    rest: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
struct PathFinding {
    #[serde(default, deserialize_with = "null_default")]
    code: String,
    #[serde(default, deserialize_with = "null_default")]
    title: String,
    #[serde(default)]
    location: Option<String>,
    #[serde(default, deserialize_with = "null_default")]
    details: Vec<Value>,
}

#[derive(Deserialize)]
struct Score {
    #[serde(default, rename = "finalPoints")]
    final_points: Option<Value>,
    #[serde(default, rename = "score", deserialize_with = "null_default")]
    letter: String,
    #[serde(default, deserialize_with = "null_default")]
    situation: String,
}

#[derive(Deserialize)]
struct Workflow {
    #[serde(default, deserialize_with = "null_default")]
    path: String,
}

#[derive(Deserialize)]
struct CiConfig {
    #[serde(default, deserialize_with = "null_default")]
    workflows: Vec<Workflow>,
}

#[derive(Deserialize)]
struct Root {
    #[serde(default, rename = "pathBlocks", deserialize_with = "null_default")]
    path_blocks: Vec<Value>,
    #[serde(default, rename = "plumberScore")]
    plumber_score: Option<Score>,
    #[serde(default, rename = "dataCollectionDegraded")]
    degraded: bool,
    #[serde(default, rename = "degradedReasons", deserialize_with = "null_default")]
    degraded_reasons: Vec<String>,
    #[serde(default, deserialize_with = "null_default")]
    warnings: Vec<Value>,
    #[serde(default, rename = "ciValid")]
    ci_valid: Option<bool>,
    #[serde(default, rename = "ciMissing")]
    ci_missing: Option<bool>,
    #[serde(default, rename = "analyzedCiConfig")]
    ci_config: Option<CiConfig>,
    #[serde(flatten)]
    rest: BTreeMap<String, Value>,
}

/// Read a Plumber JSON report. Every issue of every control and every attack path becomes a
/// finding; what Plumber says about its run becomes diagnostics.
///
/// # Errors
///
/// When the bytes are not a Plumber report at all.
pub fn parse(bytes: &[u8]) -> Result<Parsed, String> {
    let root: Root =
        serde_json::from_slice(bytes).map_err(|e| format!("not a Plumber JSON report: {e}"))?;
    let mut controls: Vec<(String, Control)> = Vec::new();
    for (key, value) in &root.rest {
        if !key.ends_with("Result") || !value.is_object() {
            continue;
        }
        match serde_json::from_value::<Control>(value.clone()) {
            Ok(control) => controls.push((key.clone(), control)),
            Err(e) => return Err(format!("control {key} is unreadable: {e}")),
        }
    }
    if controls.is_empty() && root.plumber_score.is_none() && root.ci_config.is_none() {
        return Err("no control result in the report".to_owned());
    }
    let mut parsed = Parsed::default();
    let mut unscored = false;
    for (key, control) in &controls {
        if control.status == "error" {
            parsed.diagnostics.push(Diagnostic {
                level: "error".to_owned(),
                rule_id: Some(control.key.clone()),
                path: None,
                message: format!("control could not be evaluated: {}", control.name),
            });
        }
        for (index, raw) in control.issues.iter().enumerate() {
            match serde_json::from_value::<Issue>(raw.clone()) {
                Ok(issue) => {
                    let (finding, scored) = issue_finding(&issue, control);
                    unscored |= !scored;
                    parsed.findings.push(finding);
                }
                Err(e) => parsed
                    .warnings
                    .push(format!("unreadable issue {index} of {key}: {e}")),
            }
        }
    }
    for (index, raw) in root.path_blocks.iter().enumerate() {
        match serde_json::from_value::<PathBlock>(raw.clone()) {
            Ok(block) => parsed.findings.push(path_finding(&block)),
            Err(e) => parsed
                .warnings
                .push(format!("unreadable attack path {index}: {e}")),
        }
    }
    run_diagnostics(&root, unscored, &mut parsed);
    Ok(parsed)
}

/// What Plumber says about its run, as diagnostics.
fn run_diagnostics(root: &Root, unscored: bool, parsed: &mut Parsed) {
    if unscored {
        parsed.diagnostics.push(Diagnostic {
            level: "warning".to_owned(),
            rule_id: None,
            path: None,
            message: "Plumber withheld the severities (degraded data collection); such \
                      findings are reported as medium"
                .to_owned(),
        });
    }
    for reason in &root.degraded_reasons {
        parsed.diagnostics.push(Diagnostic {
            level: "warning".to_owned(),
            rule_id: None,
            path: None,
            message: format!("degraded data collection: {reason}"),
        });
    }
    if root.degraded && root.degraded_reasons.is_empty() {
        parsed.diagnostics.push(Diagnostic {
            level: "warning".to_owned(),
            rule_id: None,
            path: None,
            message: "degraded data collection: the score is withheld".to_owned(),
        });
    }
    for warning in &root.warnings {
        parsed.diagnostics.push(Diagnostic {
            level: "warning".to_owned(),
            rule_id: None,
            path: None,
            message: cap(&value_text(warning), TEXT_CAP),
        });
    }
    if root.ci_valid == Some(false) {
        parsed.diagnostics.push(Diagnostic {
            level: "error".to_owned(),
            rule_id: None,
            path: None,
            message: "the CI configuration is not valid".to_owned(),
        });
    }
    if root.ci_missing == Some(true) {
        parsed.diagnostics.push(Diagnostic {
            level: "warning".to_owned(),
            rule_id: None,
            path: None,
            message: "no CI configuration found".to_owned(),
        });
    }
    if let Some(score) = &root.plumber_score {
        let points = score
            .final_points
            .as_ref()
            .map(value_text)
            .unwrap_or_default();
        parsed.diagnostics.push(Diagnostic {
            level: "info".to_owned(),
            rule_id: None,
            path: None,
            message: format!(
                "Plumber Score {points}/100 ({}) — {}",
                score.letter,
                cap(&score.situation, TEXT_CAP)
            ),
        });
    }
    if let Some(config) = &root.ci_config {
        let paths: Vec<&str> = config
            .workflows
            .iter()
            .map(|w| w.path.as_str())
            .filter(|p| !p.is_empty())
            .collect();
        parsed.scanned_files = Some(paths.len());
        if !paths.is_empty() {
            parsed.diagnostics.push(Diagnostic {
                level: "info".to_owned(),
                rule_id: None,
                path: None,
                message: format!("workflows analysed: {}", paths.join(", ")),
            });
        }
    }
}

/// `file:line` or `file:line (note)` → (file, line); a `:suffix` that is not a number
/// stays in the file.
fn split_location(text: &str) -> (String, Option<u32>) {
    let head = match text.split_once(" (") {
        Some((head, note)) if note.ends_with(')') => head,
        _ => text,
    };
    if let Some((file, line)) = head.rsplit_once(':')
        && let Ok(line) = line.parse::<u32>()
    {
        return (file.to_owned(), Some(line));
    }
    (text.to_owned(), None)
}

/// The path of a workflow as Plumber names it: relative when it is in the identity or the
/// location, else the absolute `url` cut at the workflow directory it contains.
fn relative_path(file: &str) -> PathBuf {
    for marker in [".github/workflows/", ".gitlab-ci.yml", ".gitlab/"] {
        if let Some(at) = file.find(marker)
            && Path::new(file).is_absolute()
        {
            return PathBuf::from(file.get(at..).unwrap_or(file));
        }
    }
    PathBuf::from(file)
}

fn severity(text: &str) -> Option<Severity> {
    match text.to_ascii_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "info" | "informational" | "none" => Some(Severity::Info),
        _ => None,
    }
}

/// An issue as a finding; the flag says whether Plumber gave it a severity.
fn issue_finding(issue: &Issue, control: &Control) -> (Finding, bool) {
    let identity: BTreeMap<&str, String> = issue
        .identity
        .as_ref()
        .map(|id| {
            id.fields
                .iter()
                .map(|f| (f.key.as_str(), value_text(&f.value)))
                .collect()
        })
        .unwrap_or_default();
    let (url_file, url_line) = issue.url.as_deref().map(split_location).unwrap_or_default();
    let (loc_file, loc_line) = issue
        .location
        .as_deref()
        .map(split_location)
        .unwrap_or_default();
    let file = identity
        .get("file")
        .filter(|f| !f.is_empty())
        .cloned()
        .or_else(|| (!loc_file.is_empty()).then(|| loc_file.clone()))
        .unwrap_or_else(|| url_file.clone());
    let stated = [
        &issue.severity,
        &issue.base_severity,
        &issue.occurrence_severity,
    ]
    .into_iter()
    .flatten()
    .find_map(|s| severity(s));
    let message = issue
        .explanation
        .clone()
        .filter(|e| !e.is_empty())
        .unwrap_or_else(|| issue.title.clone());
    let mut finding = Finding::new(
        "plumber",
        issue.code.clone(),
        stated.unwrap_or(Severity::Medium),
        cap(&issue.title, TEXT_CAP),
        cap(&message, TEXT_CAP),
        relative_path(&file),
    );
    finding.line = url_line.or(loc_line);
    if !control.category.is_empty() {
        finding.categories.push(control.category.clone());
    }
    if !control.key.is_empty() {
        finding.tags.push(control.key.clone());
    }
    let doc = issue
        .doc_url
        .clone()
        .unwrap_or_else(|| format!("{DOCS}{}", issue.code));
    finding.references.push(doc.clone());
    finding.url = Some(doc);
    finding.fingerprint.clone_from(&issue.fingerprint);
    let extra = &mut finding.extra;
    extra.insert("control".to_owned(), control.name.clone());
    extra.insert("control_status".to_owned(), control.status.clone());
    for (key, value) in [
        ("severity", &issue.severity),
        ("baseSeverity", &issue.base_severity),
        ("occurrenceSeverity", &issue.occurrence_severity),
        ("url", &issue.url),
        ("location", &issue.location),
    ] {
        if let Some(value) = value {
            extra.insert(key.to_owned(), cap(value, TEXT_CAP));
        }
    }
    if !issue.path_ids.is_empty() {
        extra.insert("pathIds".to_owned(), issue.path_ids.join(", "));
    }
    for (key, value) in &identity {
        extra.insert(format!("identity.{key}"), cap(value, TEXT_CAP));
    }
    for (key, value) in &issue.rest {
        extra.insert(key.clone(), cap(&value_text(value), TEXT_CAP));
    }
    (finding, stated.is_some())
}

fn path_finding(block: &PathBlock) -> Finding {
    let locations: Vec<(String, Option<u32>)> = block
        .findings
        .iter()
        .filter_map(|f| f.location.as_deref().map(split_location))
        .collect();
    let (file, line) = locations.first().cloned().unwrap_or_default();
    let message = if block.fix.is_empty() {
        block.so.clone()
    } else {
        format!("{}. Fix: {}", block.so, block.fix)
    };
    let mut finding = Finding::new(
        "plumber",
        ATTACK_PATH,
        severity(&block.tier).unwrap_or(Severity::High),
        cap(&format!("Attack path: {}", block.entry), TEXT_CAP),
        cap(&message, TEXT_CAP),
        relative_path(&file),
    );
    finding.line = line;
    finding.fingerprint = (!block.id.is_empty()).then(|| block.id.clone());
    finding.categories.push("Attack path".to_owned());
    let last = locations.len().saturating_sub(1);
    for (index, (file, line)) in locations.iter().enumerate() {
        let kind = if index == 0 {
            FlowKind::Source
        } else if index == last {
            FlowKind::Sink
        } else {
            FlowKind::Intermediate
        };
        finding.flow.push(FlowStep {
            kind,
            path: relative_path(file),
            line: *line,
            column: None,
            end_line: None,
            end_column: None,
            content: None,
        });
    }
    let extra = &mut finding.extra;
    extra.insert("id".to_owned(), block.id.clone());
    extra.insert("tier".to_owned(), block.tier.clone());
    extra.insert("entry".to_owned(), cap(&block.entry, TEXT_CAP));
    extra.insert("so".to_owned(), cap(&block.so, TEXT_CAP));
    extra.insert("fix".to_owned(), cap(&block.fix, TEXT_CAP));
    for (index, f) in block.findings.iter().enumerate() {
        push_unique(&mut finding.tags, f.code.clone());
        finding.references.push(format!("{DOCS}{}", f.code));
        extra.insert(
            format!("finding.{index}"),
            cap(
                &format!(
                    "{} — {}{}",
                    f.code,
                    f.title,
                    f.location
                        .as_deref()
                        .map(|l| format!(" ({l})"))
                        .unwrap_or_default()
                ),
                TEXT_CAP,
            ),
        );
        let details: Vec<String> = f.details.iter().map(value_text).collect();
        if !details.is_empty() {
            extra.insert(
                format!("finding.{index}.details"),
                cap(&details.join("\n"), TEXT_CAP),
            );
        }
    }
    for (key, value) in &block.rest {
        extra.insert(key.clone(), cap(&value_text(value), TEXT_CAP));
    }
    finding
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::test_support::output;
    use crate::scanners::Parsed;

    const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/plumber/report.json");
    const DEGRADED: &[u8] = include_bytes!("../../tests/fixtures/plumber/report-degraded.json");
    const VERSION: &str = include_str!("../../tests/fixtures/plumber/version.txt");

    fn raw_counts(bytes: &[u8]) -> (usize, usize, Vec<String>) {
        let root: Value = serde_json::from_slice(bytes).unwrap();
        let mut issues = 0;
        let mut codes = Vec::new();
        for (key, value) in root.as_object().unwrap() {
            if key.ends_with("Result") {
                for issue in value["issues"].as_array().into_iter().flatten() {
                    issues += 1;
                    codes.push(issue["code"].as_str().unwrap().to_owned());
                }
            }
        }
        let paths = root["pathBlocks"].as_array().map_or(0, Vec::len);
        (issues, paths, codes)
    }

    fn fixture() -> Parsed {
        parse(FIXTURE).unwrap()
    }

    #[test]
    fn every_issue_and_attack_path_of_the_recorded_report_is_a_finding() {
        let (issues, paths, codes) = raw_counts(FIXTURE);
        let parsed = fixture();
        assert_eq!(
            parsed.findings.len() + parsed.warnings.len(),
            issues + paths
        );
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        assert_eq!(issues, 17);
        assert_eq!(paths, 5);
        for code in codes {
            assert!(
                parsed.findings.iter().any(|f| f.rule_id == code),
                "{code} missing"
            );
        }
        assert_eq!(
            parsed
                .findings
                .iter()
                .filter(|f| f.rule_id == ATTACK_PATH)
                .count(),
            5
        );
    }

    #[test]
    fn an_issue_keeps_what_plumber_says() {
        let parsed = fixture();
        let f = parsed
            .findings
            .iter()
            .find(|f| f.rule_id == "ISSUE-411")
            .unwrap();
        assert_eq!(f.tool, "plumber");
        assert_eq!(f.title, "Unverified script execution");
        assert_eq!(f.path, PathBuf::from(".github/workflows/ci.yml"));
        assert_eq!(f.line, Some(23));
        assert_eq!(f.categories, vec!["Pipeline Composition".to_owned()]);
        assert!(
            f.tags
                .iter()
                .any(|t| t == "pipelineMustNotExecuteUnverifiedScripts"),
            "{:?}",
            f.tags
        );
        assert_eq!(
            f.url.as_deref(),
            Some("https://getplumber.io/docs/cli/issues/ISSUE-411")
        );
        assert!(f.fingerprint.is_some());
        assert_eq!(
            f.extra.get("scriptLine").map(String::as_str),
            Some("curl -sSL https://example.com/install.sh | bash")
        );
        assert_eq!(f.extra.get("job").map(String::as_str), Some("ci/build"));
        assert_eq!(
            f.extra.get("identity.file").map(String::as_str),
            Some(".github/workflows/ci.yml")
        );
        assert!(f.extra.get("url").unwrap().ends_with("ci.yml:23"));
        assert!(!f.message.is_empty());
        let critical = parsed
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical && f.rule_id != ATTACK_PATH)
            .count();
        assert_eq!(critical, 6, "severity is the effective one");
    }

    #[test]
    fn an_attack_path_becomes_a_finding_with_a_flow() {
        let parsed = fixture();
        let path = parsed
            .findings
            .iter()
            .find(|f| f.rule_id == ATTACK_PATH)
            .unwrap();
        assert_eq!(path.severity, Severity::Critical);
        assert!(path.title.starts_with("Attack path: "));
        assert!(path.message.contains("Fix: "), "{}", path.message);
        assert_eq!(path.path, PathBuf::from(".github/workflows/ci.yml"));
        assert!(path.line.is_some());
        assert!(path.flow.len() >= 2, "{:?}", path.flow);
        assert_eq!(path.flow.first().unwrap().kind, FlowKind::Source);
        assert_eq!(path.flow.last().unwrap().kind, FlowKind::Sink);
        assert!(path.tags.iter().any(|t| t.starts_with("ISSUE-")));
        assert!(path.extra.contains_key("branches"));
        assert!(path.extra.contains_key("reachesShort"));
        assert!(path.extra.contains_key("finding.0.details"));
        assert!(path.fingerprint.is_some());
    }

    #[test]
    fn the_run_is_described_in_diagnostics_and_scanned_files() {
        let parsed = fixture();
        assert!(
            parsed
                .diagnostics
                .iter()
                .any(|d| d.level == "info" && d.message.starts_with("Plumber Score 9/100 (E)")),
            "{:?}",
            parsed.diagnostics
        );
        assert!(
            !parsed.diagnostics.iter().any(|d| d.level == "error"),
            "{:?}",
            parsed.diagnostics
        );
        assert_eq!(parsed.scanned_files, Some(2));
        assert!(parsed.diagnostics.iter().any(|d| d.message
            == "workflows analysed: .github/workflows/ci.yml, .github/workflows/reusable.yml"));
    }

    #[test]
    fn a_degraded_report_is_read_with_medium_severities_and_a_warning() {
        let (issues, paths, _) = raw_counts(DEGRADED);
        let parsed = parse(DEGRADED).unwrap();
        assert_eq!(parsed.findings.len(), issues + paths);
        let medium = parsed
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        assert_eq!(medium, 16, "every issue without a stated severity");
        let stated = parsed
            .findings
            .iter()
            .find(|f| f.rule_id == "ISSUE-713")
            .unwrap();
        assert_eq!(
            stated.severity,
            Severity::High,
            "occurrenceSeverity is kept"
        );
        assert!(
            parsed.diagnostics.iter().any(
                |d| d.level == "error" && d.rule_id.as_deref() == Some("branchMustBeProtected")
            )
        );
        assert!(
            parsed
                .diagnostics
                .iter()
                .any(|d| d.message.contains("withheld the severities"))
        );
        assert!(parsed.diagnostics.iter().any(|d| {
            d.message
                .contains("degraded data collection: branch protection")
        }));
        assert!(
            !parsed
                .diagnostics
                .iter()
                .any(|d| d.message.starts_with("Plumber Score"))
        );
    }

    #[test]
    fn one_bad_issue_or_path_becomes_a_warning_not_a_failure() {
        let mut root: Value = serde_json::from_slice(FIXTURE).unwrap();
        root["actionPinningResult"]["issues"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"title": "no code"}));
        root["pathBlocks"].as_array_mut().unwrap().push(Value::Null);
        root["excessivePermissionsResult"]["issues"][0]["severity"] = Value::Null;
        root["excessivePermissionsResult"]["issues"][0]["identity"] = Value::Null;
        root["excessivePermissionsResult"]["issues"][0]["pathIds"] = Value::Null;
        let parsed = parse(&serde_json::to_vec(&root).unwrap()).unwrap();
        assert_eq!(parsed.warnings.len(), 2, "{:?}", parsed.warnings);
        assert_eq!(parsed.findings.len(), 22);
        let injected = parsed
            .findings
            .iter()
            .find(|f| f.rule_id == "ISSUE-803")
            .unwrap();
        assert_eq!(
            injected.path,
            PathBuf::from(".github/workflows/ci.yml"),
            "falls back to the url"
        );
        assert_eq!(injected.line, Some(12));
        assert_eq!(
            injected.severity,
            Severity::High,
            "then the base severity (effective was critical)"
        );
    }

    #[test]
    fn garbage_empty_and_wrong_shapes_are_errors() {
        assert!(parse(b"").is_err());
        assert!(parse(b"{").is_err());
        assert!(parse(b"[]").is_err());
        assert!(parse(b"{}").is_err());
        assert!(parse(b"{\"fooResult\": \"text\"}").is_err());
        assert!(parse(br#"{"fooResult": {"issues": "nope"}}"#).is_err());
        let big = format!(
            "{{\"fooResult\": {{\"issues\": [{}]}}}}",
            "{\"code\":\"X\"},".repeat(5000).trim_end_matches(',')
        );
        assert_eq!(parse(big.as_bytes()).unwrap().findings.len(), 5000);
    }

    #[test]
    fn locations_and_paths_are_split_and_made_relative() {
        assert_eq!(
            split_location("a/b.yml:12"),
            ("a/b.yml".to_owned(), Some(12))
        );
        assert_eq!(split_location("a/b.yml"), ("a/b.yml".to_owned(), None));
        assert_eq!(split_location("C:no"), ("C:no".to_owned(), None));
        assert_eq!(
            split_location(
                ".github/workflows/x.yml:133 (docker/build-push-action@v7 via org/repo/.github/workflows/g.yml@main)"
            ),
            (".github/workflows/x.yml".to_owned(), Some(133))
        );
        assert_eq!(
            split_location("a.yml (note)"),
            ("a.yml (note)".to_owned(), None)
        );
        assert_eq!(
            relative_path("/home/x/repo/.github/workflows/ci.yml"),
            PathBuf::from(".github/workflows/ci.yml")
        );
        assert_eq!(
            relative_path(".gitlab-ci.yml"),
            PathBuf::from(".gitlab-ci.yml")
        );
        assert_eq!(
            relative_path("/abs/.gitlab-ci.yml"),
            PathBuf::from(".gitlab-ci.yml")
        );
        assert_eq!(
            relative_path("other/file.yml"),
            PathBuf::from("other/file.yml")
        );
    }

    #[test]
    fn args_skip_the_api_control_without_a_token() {
        let report = Path::new("/scratch/plumber.json");
        let without = Plumber::analyze_args(report, false);
        assert!(without.iter().any(|a| a == "--skip-controls"));
        assert!(without.iter().any(|a| a == BRANCH_CONTROL));
        assert!(without.iter().any(|a| a == "--print=false"));
        assert_eq!(without.last().unwrap(), report.as_os_str());
        let with = Plumber::analyze_args(report, true);
        assert!(!with.iter().any(|a| a == "--skip-controls"));
        assert_eq!(Plumber.inherit_env(), TOKENS);
        assert_eq!(Plumber.mise_id(), "github:getplumber/plumber");
        assert!(Plumber.scan_args(&ScanOptions::default()).is_empty());
    }

    #[test]
    fn version_is_read_from_the_banner() {
        let v = Plumber
            .parse_version(&output(Some(0), VERSION.as_bytes(), ""))
            .unwrap();
        assert_eq!(v.to_string(), "0.7.17");
    }

    #[test]
    fn interpret_maps_exit_codes() {
        assert!(matches!(
            Plumber.interpret(&output(Some(0), FIXTURE, "")),
            Outcome::Completed(_)
        ));
        assert!(matches!(
            Plumber.interpret(&output(Some(3), DEGRADED, "")),
            Outcome::Completed(_)
        ));
        match Plumber.interpret(&output(
            Some(2),
            b"",
            "Error: could not determine the provider: not in a git repository",
        )) {
            Outcome::Skipped(reason) => assert!(reason.contains("remote")),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            Plumber.interpret(&output(Some(2), b"", "Error: token")),
            Outcome::Failed(_)
        ));
        assert!(matches!(
            Plumber.interpret(&output(Some(0), b"garbage", "")),
            Outcome::Failed(_)
        ));
        assert!(matches!(
            Plumber.interpret(&output(Some(9), FIXTURE, "")),
            Outcome::Failed(_)
        ));
        let mut timed = output(None, b"", "");
        timed.timed_out = true;
        assert!(matches!(Plumber.interpret(&timed), Outcome::Failed(_)));
    }

    #[test]
    fn plan_and_applicability_follow_the_ci_markers() {
        let mut options = ScanOptions::default();
        assert!(Plumber.plan(&options).is_none());
        options.detected.markers.insert(Marker::GitlabCi);
        assert!(Plumber.plan(&options).is_some());
    }
}
