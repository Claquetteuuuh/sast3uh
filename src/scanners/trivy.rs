//! Trivy: known vulnerabilities in dependencies (SCA), infrastructure-as-code misconfigurations,
//! secrets and licenses (`trivy fs --format json`).
//!
//! One result per scanned target (a lockfile, a Dockerfile, a Terraform file…) carries up to
//! four lists; every entry of every list becomes a finding, with the target as its path. The
//! check summaries (`MisconfSummary`) become diagnostics so the report says what was checked,
//! not only what failed. Trivy masks the secrets it reports; the masked text is kept as is.

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
use crate::model::{Diagnostic, Finding, Severity, normalize_reported_path};
use crate::packs::Profile;

/// The Trivy adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct Trivy;

impl Scanner for Trivy {
    fn name(&self) -> &'static str {
        "trivy"
    }

    fn binary(&self) -> &'static str {
        "trivy"
    }

    fn purpose(&self) -> &'static str {
        "SCA (CVEs in dependencies), IaC misconfigurations, secrets, licenses"
    }

    fn mise_id(&self) -> &'static str {
        "trivy"
    }

    fn version_args(&self) -> Vec<OsString> {
        os_args(&["--version"])
    }

    fn scan_args(&self, options: &ScanOptions) -> Vec<OsString> {
        let mut args = os_args(&[
            "fs",
            // Every engine Trivy has.
            "--scanners",
            "vuln,misconfig,secret,license",
            "--include-dev-deps",
            "--format",
            "json",
            "--quiet",
            "--no-progress",
            "--skip-version-check",
            // Findings are a result, not an error: the exit code must say "ran".
            "--exit-code",
            "0",
        ]);
        if options.semgrep_profile == Profile::Exhaustive {
            // More detections at the cost of precision, and licenses read from file
            // headers, not only from package metadata.
            args.extend(os_args(&[
                "--detection-priority",
                "comprehensive",
                "--license-full",
            ]));
        }
        if options.offline {
            args.extend(os_args(&[
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-check-update",
                "--offline-scan",
            ]));
        }
        args.push(".".into());
        args
    }

    fn env(&self) -> Vec<(OsString, OsString)> {
        vec![
            ("TRIVY_DISABLE_VEX_NOTICE".into(), "true".into()),
            ("NO_COLOR".into(), "1".into()),
        ]
    }

    fn plan(&self, options: &ScanOptions) -> Option<String> {
        let mut parts = vec!["vuln, misconfig, secret and license scanners".to_owned()];
        if options.semgrep_profile == Profile::Exhaustive {
            parts.push("comprehensive detection, licenses from file headers".to_owned());
        }
        if options.offline {
            parts.push("offline: cached databases only".to_owned());
        }
        Some(parts.join(" · "))
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
    // Required on purpose: `{}` or `[]` is not a Trivy report.
    #[serde(rename = "SchemaVersion")]
    schema_version: u32,
    #[serde(rename = "Results", default, deserialize_with = "null_default")]
    results: Vec<Value>,
}

#[derive(Deserialize)]
struct RawResult {
    #[serde(rename = "Target", default, deserialize_with = "null_default")]
    target: String,
    #[serde(rename = "Class", default, deserialize_with = "null_default")]
    class: String,
    #[serde(rename = "Type", default, deserialize_with = "null_default")]
    kind: String,
    #[serde(rename = "Vulnerabilities", default, deserialize_with = "null_default")]
    vulnerabilities: Vec<Value>,
    #[serde(
        rename = "Misconfigurations",
        default,
        deserialize_with = "null_default"
    )]
    misconfigurations: Vec<Value>,
    #[serde(rename = "Secrets", default, deserialize_with = "null_default")]
    secrets: Vec<Value>,
    #[serde(rename = "Licenses", default, deserialize_with = "null_default")]
    licenses: Vec<Value>,
    #[serde(rename = "MisconfSummary", default)]
    misconf_summary: Option<MisconfSummary>,
}

#[derive(Deserialize, Default)]
struct MisconfSummary {
    #[serde(rename = "Successes", default)]
    successes: u64,
    #[serde(rename = "Failures", default)]
    failures: u64,
    #[serde(rename = "Exceptions", default)]
    exceptions: u64,
}

#[derive(Deserialize)]
struct RawVulnerability {
    #[serde(rename = "VulnerabilityID")]
    id: String,
    #[serde(rename = "PkgName", default, deserialize_with = "null_default")]
    pkg_name: String,
    #[serde(rename = "PkgID", default)]
    pkg_id: Option<String>,
    #[serde(rename = "PkgIdentifier", default)]
    pkg_identifier: Option<Value>,
    #[serde(
        rename = "InstalledVersion",
        default,
        deserialize_with = "null_default"
    )]
    installed_version: String,
    #[serde(rename = "FixedVersion", default)]
    fixed_version: Option<String>,
    #[serde(rename = "Status", default)]
    status: Option<String>,
    #[serde(rename = "Severity", default, deserialize_with = "null_default")]
    severity: String,
    #[serde(rename = "Title", default)]
    title: Option<String>,
    #[serde(rename = "Description", default, deserialize_with = "null_default")]
    description: String,
    #[serde(rename = "PrimaryURL", default)]
    primary_url: Option<String>,
    #[serde(rename = "References", default)]
    references: Strings,
    #[serde(rename = "CweIDs", default)]
    cwe_ids: Strings,
    #[serde(rename = "VendorIDs", default)]
    vendor_ids: Strings,
    #[serde(rename = "Fingerprint", default)]
    fingerprint: Option<String>,
    #[serde(flatten)]
    rest: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
struct RawMisconfiguration {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "AVDID", default)]
    avd_id: Option<String>,
    #[serde(rename = "Type", default, deserialize_with = "null_default")]
    kind: String,
    #[serde(rename = "Title", default, deserialize_with = "null_default")]
    title: String,
    #[serde(rename = "Description", default, deserialize_with = "null_default")]
    description: String,
    #[serde(rename = "Message", default, deserialize_with = "null_default")]
    message: String,
    #[serde(rename = "Resolution", default)]
    resolution: Option<String>,
    #[serde(rename = "Severity", default, deserialize_with = "null_default")]
    severity: String,
    #[serde(rename = "PrimaryURL", default)]
    primary_url: Option<String>,
    #[serde(rename = "References", default)]
    references: Strings,
    #[serde(rename = "Status", default)]
    status: Option<String>,
    #[serde(rename = "CauseMetadata", default)]
    cause: Option<Cause>,
    #[serde(flatten)]
    rest: BTreeMap<String, Value>,
}

#[derive(Deserialize, Default)]
struct Cause {
    #[serde(rename = "Provider", default)]
    provider: Option<String>,
    #[serde(rename = "Service", default)]
    service: Option<String>,
    #[serde(rename = "Resource", default)]
    resource: Option<String>,
    #[serde(rename = "StartLine", default)]
    start_line: Option<u32>,
    #[serde(rename = "EndLine", default)]
    end_line: Option<u32>,
    #[serde(rename = "Code", default)]
    code: Option<Code>,
}

#[derive(Deserialize, Default)]
struct Code {
    #[serde(rename = "Lines", default, deserialize_with = "null_default")]
    lines: Vec<CodeLine>,
}

#[derive(Deserialize, Default)]
struct CodeLine {
    #[serde(rename = "Content", default, deserialize_with = "null_default")]
    content: String,
}

#[derive(Deserialize)]
struct RawSecret {
    #[serde(rename = "RuleID")]
    rule_id: String,
    #[serde(rename = "Category", default)]
    category: Option<String>,
    #[serde(rename = "Severity", default, deserialize_with = "null_default")]
    severity: String,
    #[serde(rename = "Title", default, deserialize_with = "null_default")]
    title: String,
    #[serde(rename = "StartLine", default)]
    start_line: Option<u32>,
    #[serde(rename = "EndLine", default)]
    end_line: Option<u32>,
    #[serde(rename = "Match", default, deserialize_with = "null_default")]
    matched: String,
    #[serde(rename = "Code", default)]
    code: Option<Code>,
    #[serde(flatten)]
    rest: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
struct RawLicense {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Category", default)]
    category: Option<String>,
    #[serde(rename = "Severity", default, deserialize_with = "null_default")]
    severity: String,
    #[serde(rename = "PkgName", default)]
    pkg_name: Option<String>,
    #[serde(rename = "FilePath", default)]
    file_path: Option<String>,
    #[serde(rename = "Confidence", default)]
    confidence: Option<f64>,
    #[serde(rename = "Link", default)]
    link: Option<String>,
    #[serde(flatten)]
    rest: BTreeMap<String, Value>,
}

/// Parse `trivy fs --format json` output.
///
/// One unreadable entry does not fail the report: it is dropped with a warning that says so.
///
/// # Errors
///
/// [`ParseError`] when the output is empty or not a Trivy report.
pub fn parse(bytes: &[u8]) -> Result<Parsed, ParseError> {
    let json = first_json(bytes);
    if json.is_empty() {
        return Err(ParseError::Empty);
    }
    let root: Root = serde_json::from_slice(json)?;
    let mut parsed = Parsed::default();
    if root.schema_version != 2 {
        parsed.warnings.push(format!(
            "report schema version {} (2 expected): read on a best-effort basis",
            root.schema_version
        ));
    }
    for (index, value) in root.results.into_iter().enumerate() {
        let result: RawResult = match serde_json::from_value(value) {
            Ok(result) => result,
            Err(err) => {
                parsed
                    .warnings
                    .push(format!("dropped result #{index}: {err}"));
                continue;
            }
        };
        let Some(path) = normalize_reported_path(&result.target) else {
            parsed.warnings.push(format!(
                "dropped result #{index}: target `{}` is outside the target",
                result.target
            ));
            continue;
        };
        if let Some(summary) = &result.misconf_summary {
            parsed.diagnostics.push(Diagnostic {
                level: "info".to_owned(),
                rule_id: None,
                path: Some(result.target.clone()),
                message: format!(
                    "{} check(s) passed, {} failed, {} excepted ({})",
                    summary.successes, summary.failures, summary.exceptions, result.kind
                ),
            });
        }
        let target = path.as_path();
        let kinds = [
            ("vulnerability", &result.vulnerabilities),
            ("misconfiguration", &result.misconfigurations),
            ("secret", &result.secrets),
            ("license", &result.licenses),
        ];
        for (what, entries) in kinds {
            for (n, entry) in entries.iter().enumerate() {
                let converted = match what {
                    "vulnerability" => serde_json::from_value::<RawVulnerability>(entry.clone())
                        .map(|raw| vulnerability(raw, &result, target)),
                    "misconfiguration" => {
                        serde_json::from_value::<RawMisconfiguration>(entry.clone())
                            .map(|raw| misconfiguration(raw, &result, target))
                    }
                    "secret" => serde_json::from_value::<RawSecret>(entry.clone())
                        .map(|raw| secret(raw, &result, target)),
                    _ => serde_json::from_value::<RawLicense>(entry.clone())
                        .map(|raw| license(raw, &result, target)),
                };
                match converted {
                    Ok(finding) => parsed.findings.push(finding),
                    Err(err) => parsed
                        .warnings
                        .push(format!("dropped {what} #{n} of {}: {err}", result.target)),
                }
            }
        }
    }
    Ok(parsed)
}

fn severity(raw: &str) -> Severity {
    match raw.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

fn first_paragraph(text: &str) -> Option<String> {
    let line = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    Some(cap(line, 300))
}

fn keep_rest(f: &mut Finding, rest: BTreeMap<String, Value>) {
    for (key, value) in rest {
        if !value.is_null() {
            f.extra.insert(key, value_text(&value));
        }
    }
}

fn vulnerability(raw: RawVulnerability, result: &RawResult, path: &Path) -> Finding {
    let title = raw
        .title
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| format!("{} {}: {}", raw.pkg_name, raw.installed_version, raw.id));
    let message = first_paragraph(&raw.description).unwrap_or_else(|| {
        format!(
            "{} {} is affected by {}",
            raw.pkg_name, raw.installed_version, raw.id
        )
    });
    let mut f = Finding::new(
        "trivy",
        raw.id,
        severity(&raw.severity),
        title,
        message,
        path.to_path_buf(),
    );
    f.cwes = cwes(raw.cwe_ids.0.iter().map(|c| cwe_number(c)));
    for c in ["vulnerability", result.class.as_str(), result.kind.as_str()] {
        push_unique(&mut f.categories, c);
    }
    push_unique(&mut f.tags, raw.pkg_name.clone());
    if let Some(purl) = raw
        .pkg_identifier
        .as_ref()
        .and_then(|p| p.get("PURL"))
        .and_then(Value::as_str)
    {
        push_unique(&mut f.tags, purl);
        f.extra.insert("purl".to_owned(), purl.to_owned());
    }
    for r in raw.references.0 {
        push_unique(&mut f.references, r);
    }
    f.url = raw.primary_url.filter(|u| !u.is_empty());
    f.fingerprint = raw.fingerprint.filter(|s| !s.is_empty());
    f.extra.insert("pkg_name".to_owned(), raw.pkg_name);
    f.extra
        .insert("installed_version".to_owned(), raw.installed_version);
    if let Some(fixed) = raw.fixed_version.filter(|v| !v.is_empty()) {
        f.extra.insert("fixed_version".to_owned(), fixed);
    }
    if let Some(status) = raw.status.filter(|v| !v.is_empty()) {
        f.extra.insert("status".to_owned(), status);
    }
    if let Some(pkg_id) = raw.pkg_id.filter(|v| !v.is_empty()) {
        f.extra.insert("pkg_id".to_owned(), pkg_id);
    }
    if !raw.vendor_ids.0.is_empty() {
        f.extra
            .insert("vendor_ids".to_owned(), raw.vendor_ids.0.join(", "));
    }
    if !raw.description.trim().is_empty() {
        f.extra.insert(
            "description".to_owned(),
            cap(raw.description.trim(), TEXT_CAP),
        );
    }
    keep_rest(&mut f, raw.rest);
    f
}

fn misconfiguration(raw: RawMisconfiguration, result: &RawResult, path: &Path) -> Finding {
    let cause = raw.cause.unwrap_or_default();
    let rule_id = raw
        .avd_id
        .clone()
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| raw.id.clone());
    let message = if raw.message.trim().is_empty() {
        raw.description.clone()
    } else {
        raw.message.clone()
    };
    let mut f = Finding::new(
        "trivy",
        rule_id,
        severity(&raw.severity),
        raw.title,
        cap(message.trim(), 300),
        path.to_path_buf(),
    );
    f.line = cause.start_line.filter(|l| *l > 0);
    f.end_line = cause.end_line.filter(|l| *l > 0);
    for c in [
        Some("misconfiguration"),
        Some(raw.kind.as_str()),
        Some(result.class.as_str()),
        Some(result.kind.as_str()),
        cause.provider.as_deref(),
        cause.service.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        push_unique(&mut f.categories, c);
    }
    if let Some(resource) = cause.resource.as_deref() {
        push_unique(&mut f.tags, resource);
        f.extra.insert("resource".to_owned(), resource.to_owned());
    }
    f.snippet = cause
        .code
        .map(|code| {
            code.lines
                .iter()
                .map(|l| l.content.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .filter(|s| !s.trim().is_empty())
        .map(|s| cap(&s, TEXT_CAP));
    for r in raw.references.0 {
        push_unique(&mut f.references, r);
    }
    f.url = raw.primary_url.filter(|u| !u.is_empty());
    f.fix = raw
        .resolution
        .filter(|r| !r.trim().is_empty())
        .map(|r| cap(&r, TEXT_CAP));
    if raw.avd_id.is_some_and(|a| a != raw.id) {
        f.extra.insert("id".to_owned(), raw.id);
    }
    if let Some(status) = raw.status.filter(|v| !v.is_empty()) {
        f.extra.insert("status".to_owned(), status);
    }
    if !raw.description.trim().is_empty() {
        f.extra.insert(
            "description".to_owned(),
            cap(raw.description.trim(), TEXT_CAP),
        );
    }
    keep_rest(&mut f, raw.rest);
    f
}

fn secret(raw: RawSecret, result: &RawResult, path: &Path) -> Finding {
    let title = if raw.title.trim().is_empty() {
        raw.rule_id.clone()
    } else {
        raw.title.clone()
    };
    // Trivy masks the matched secret itself; what it prints is what is kept.
    let message = if raw.matched.trim().is_empty() {
        title.clone()
    } else {
        cap(raw.matched.trim(), 300)
    };
    let mut f = Finding::new(
        "trivy",
        raw.rule_id,
        severity(&raw.severity),
        title,
        message,
        path.to_path_buf(),
    );
    f.line = raw.start_line.filter(|l| *l > 0);
    f.end_line = raw.end_line.filter(|l| *l > 0);
    for c in [
        Some("secret"),
        raw.category.as_deref(),
        Some(result.class.as_str()),
    ]
    .into_iter()
    .flatten()
    {
        push_unique(&mut f.categories, c);
    }
    f.snippet = raw
        .code
        .map(|code| {
            code.lines
                .iter()
                .map(|l| l.content.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .filter(|s| !s.trim().is_empty())
        .map(|s| cap(&s, TEXT_CAP));
    keep_rest(&mut f, raw.rest);
    f
}

fn license(raw: RawLicense, result: &RawResult, path: &Path) -> Finding {
    let category = raw
        .category
        .clone()
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    let subject = raw
        .pkg_name
        .clone()
        .filter(|p| !p.is_empty())
        .or_else(|| raw.file_path.clone().filter(|p| !p.is_empty()))
        .unwrap_or_else(|| result.target.clone());
    let title = format!("{} license ({category})", raw.name);
    let message = format!("{subject} is under the {} license", raw.name);
    let location = raw
        .file_path
        .as_deref()
        .and_then(normalize_reported_path)
        .unwrap_or_else(|| path.to_path_buf());
    let mut f = Finding::new(
        "trivy",
        raw.name,
        severity(&raw.severity),
        title,
        message,
        location,
    );
    for c in ["license", category.as_str(), result.class.as_str()] {
        push_unique(&mut f.categories, c);
    }
    if let Some(pkg) = raw.pkg_name.filter(|p| !p.is_empty()) {
        push_unique(&mut f.tags, pkg.clone());
        f.extra.insert("pkg_name".to_owned(), pkg);
    }
    if let Some(confidence) = raw.confidence {
        f.extra
            .insert("confidence".to_owned(), confidence.to_string());
    }
    f.url = raw.link.filter(|l| !l.is_empty());
    keep_rest(&mut f, raw.rest);
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::tests::output;
    use std::path::PathBuf;

    const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/trivy/report.json");
    const VERSION: &str = include_str!("../../tests/fixtures/trivy/version.txt");

    fn raw_counts() -> (usize, usize, usize, usize) {
        let raw: Value = serde_json::from_slice(FIXTURE).unwrap();
        let count = |key: &str| {
            raw["Results"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r[key].as_array().map_or(0, Vec::len))
                .sum::<usize>()
        };
        (
            count("Vulnerabilities"),
            count("Misconfigurations"),
            count("Secrets"),
            count("Licenses"),
        )
    }

    #[test]
    fn parses_the_recorded_report_completely() {
        let parsed = parse(FIXTURE).unwrap();
        let (vulns, misconfigs, secrets, licenses) = raw_counts();
        assert_eq!(
            parsed.findings.len(),
            vulns + misconfigs + secrets + licenses,
            "every entry of every list is a finding"
        );
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        assert_eq!(
            parsed
                .findings
                .iter()
                .filter(|f| f.categories.contains(&"vulnerability".to_owned()))
                .count(),
            vulns
        );
        assert_eq!(
            parsed
                .findings
                .iter()
                .filter(|f| f.categories.contains(&"misconfiguration".to_owned()))
                .count(),
            misconfigs
        );
        assert_eq!(
            parsed
                .findings
                .iter()
                .filter(|f| f.categories.contains(&"secret".to_owned()))
                .count(),
            secrets
        );
        assert_eq!(
            parsed.diagnostics.len(),
            3,
            "one check summary per config target: {:?}",
            parsed.diagnostics
        );
        assert!(parsed.diagnostics.iter().all(|d| d.level == "info"));
        assert!(parsed.findings.iter().all(|f| f.tool == "trivy"));
    }

    #[test]
    fn keeps_every_field_of_a_vulnerability() {
        let parsed = parse(FIXTURE).unwrap();
        let v = parsed
            .findings
            .iter()
            .find(|f| f.rule_id == "CVE-2020-8203")
            .unwrap();
        assert_eq!(v.severity, Severity::High);
        assert_eq!(
            v.title,
            "nodejs-lodash: prototype pollution in zipObjectDeep function"
        );
        assert!(!v.message.is_empty());
        assert_eq!(v.path, PathBuf::from("package-lock.json"));
        assert_eq!(v.line, None, "a lockfile finding has no line");
        assert_eq!(v.cwes, vec![770, 1321]);
        assert_eq!(v.categories, vec!["vulnerability", "lang-pkgs", "npm"]);
        assert_eq!(v.tags, vec!["lodash", "pkg:npm/lodash@4.17.15"]);
        assert_eq!(
            v.url.as_deref(),
            Some("https://avd.aquasec.com/nvd/cve-2020-8203")
        );
        assert!(v.references.len() > 3);
        assert!(v.fingerprint.as_deref().unwrap().starts_with("sha256:"));
        assert_eq!(v.extra["installed_version"], "4.17.15");
        assert_eq!(v.extra["fixed_version"], "4.17.19");
        assert_eq!(v.extra["status"], "fixed");
        assert_eq!(v.extra["pkg_id"], "lodash@4.17.15");
        assert_eq!(v.extra["vendor_ids"], "GHSA-p6mc-m468-83gw");
        assert!(v.extra.contains_key("CVSS"), "{:?}", v.extra.keys());
        assert!(v.extra.contains_key("DataSource"));
        assert!(v.extra.contains_key("PublishedDate"));
        assert!(v.extra["description"].len() > 20);
    }

    #[test]
    fn keeps_every_field_of_a_misconfiguration_and_a_secret() {
        let parsed = parse(FIXTURE).unwrap();
        let m = parsed
            .findings
            .iter()
            .find(|f| f.rule_id == "DS-0001")
            .unwrap();
        assert_eq!(m.severity, Severity::Medium);
        assert_eq!(m.title, "':latest' tag used");
        assert_eq!(
            m.message,
            "Specify a tag in the 'FROM' statement for image 'node'"
        );
        assert_eq!(m.path, PathBuf::from("Dockerfile"));
        assert_eq!((m.line, m.end_line), (Some(1), Some(1)));
        assert_eq!(m.snippet.as_deref(), Some("FROM node:latest"));
        assert_eq!(
            m.fix.as_deref(),
            Some("Add a tag to the image in the 'FROM' statement")
        );
        assert!(
            m.categories
                .iter()
                .any(|c| c == "Dockerfile Security Check"),
            "{:?}",
            m.categories
        );
        assert!(
            m.categories.iter().any(|c| c == "Dockerfile"),
            "{:?}",
            m.categories
        );
        assert_eq!(
            m.url.as_deref(),
            Some("https://avd.aquasec.com/misconfig/ds-0001")
        );
        assert_eq!(m.extra["status"], "FAIL");
        assert_eq!(m.extra["Namespace"], "builtin.dockerfile.DS001");
        let tf = parsed
            .findings
            .iter()
            .find(|f| {
                f.path == Path::new("infra/main.tf")
                    && f.tags.iter().any(|t| t == "aws_s3_bucket.logs")
            })
            .unwrap();
        assert!(
            tf.categories.iter().any(|c| c == "AWS"),
            "{:?}",
            tf.categories
        );
        assert_eq!(tf.extra["resource"], "aws_s3_bucket.logs");

        let s = parsed
            .findings
            .iter()
            .find(|f| f.rule_id == "jwt-token")
            .unwrap();
        assert_eq!(s.severity, Severity::Medium);
        assert_eq!(s.title, "JWT token");
        assert_eq!(s.path, PathBuf::from("settings.py"));
        assert_eq!((s.line, s.end_line), (Some(1), Some(1)));
        assert!(
            s.message.starts_with("API_TOKEN = \"***"),
            "the masked match is the message: {}",
            s.message
        );
        assert_eq!(s.categories, vec!["secret", "JWT"]);
        assert!(s.snippet.as_deref().unwrap().contains("***"));
    }

    #[test]
    fn licenses_and_odd_shapes_are_read_and_drops_are_reported() {
        let json = br#"{"SchemaVersion": 3, "Results": [
          {"Target": "go.mod", "Class": "lang-pkgs", "Type": "gomod", "Vulnerabilities": null,
           "Licenses": [{"Severity": "LOW", "Category": "notice", "PkgName": "golang.org/x/net", "Name": "BSD-3-Clause", "Confidence": 1, "Link": "https://spdx.org/licenses/BSD-3-Clause.html"},
                        {"Severity": "HIGH", "Category": "forbidden", "FilePath": "vendor/LICENSE", "Name": "GPL-3.0", "Confidence": 0.8, "Link": ""}]},
          {"Target": "../escape", "Class": "config", "Misconfigurations": [{"ID": "X"}]},
          {"Target": "k8s/app.yaml", "Class": "config", "Type": "kubernetes", "Misconfigurations": [{"ID": "KSV-0001", "AVDID": "AVD-KSV-0001", "Title": "t", "Severity": "WEIRD", "CauseMetadata": null}, {"NoID": true}], "Secrets": null, "MisconfSummary": {"Successes": 5, "Failures": 1}},
          "garbage"
        ]}"#;
        let parsed = parse(json).unwrap();
        assert_eq!(parsed.findings.len(), 3, "{:?}", parsed.warnings);
        let bsd = parsed
            .findings
            .iter()
            .find(|f| f.rule_id == "BSD-3-Clause")
            .unwrap();
        assert_eq!(bsd.severity, Severity::Low);
        assert_eq!(bsd.title, "BSD-3-Clause license (notice)");
        assert_eq!(
            bsd.message,
            "golang.org/x/net is under the BSD-3-Clause license"
        );
        assert_eq!(bsd.path, PathBuf::from("go.mod"));
        assert_eq!(bsd.categories, vec!["license", "notice", "lang-pkgs"]);
        assert_eq!(bsd.tags, vec!["golang.org/x/net"]);
        assert_eq!(
            bsd.url.as_deref(),
            Some("https://spdx.org/licenses/BSD-3-Clause.html")
        );
        assert_eq!(bsd.extra["confidence"], "1");
        let gpl = parsed
            .findings
            .iter()
            .find(|f| f.rule_id == "GPL-3.0")
            .unwrap();
        assert_eq!(
            gpl.path,
            PathBuf::from("vendor/LICENSE"),
            "a file path locates the license"
        );
        assert_eq!(gpl.url, None);
        let ksv = parsed
            .findings
            .iter()
            .find(|f| f.rule_id == "AVD-KSV-0001")
            .unwrap();
        assert_eq!(
            ksv.severity,
            Severity::Info,
            "an unknown severity reads as info"
        );
        assert_eq!(ksv.extra["id"], "KSV-0001");
        assert_eq!(ksv.line, None);
        assert_eq!(parsed.warnings.len(), 4, "{:?}", parsed.warnings);
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| w.contains("schema version 3"))
        );
        assert!(parsed.warnings.iter().any(|w| w.contains("../escape")));
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| w.contains("dropped misconfiguration #1 of k8s/app.yaml"))
        );
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| w.contains("dropped result #3"))
        );
        assert_eq!(parsed.diagnostics.len(), 1);
        assert_eq!(
            parsed.diagnostics[0].message,
            "5 check(s) passed, 1 failed, 0 excepted (kubernetes)"
        );
    }

    #[test]
    fn empty_results_are_a_clean_completion() {
        let parsed =
            parse(br#"{"SchemaVersion": 2, "ArtifactName": ".", "Results": null}"#).unwrap();
        assert!(parsed.findings.is_empty());
        assert!(parsed.warnings.is_empty());
        let parsed = parse(br#"{"SchemaVersion": 2}"#).unwrap();
        assert!(parsed.findings.is_empty());
    }

    #[test]
    fn malformed_output_is_a_parse_error_not_a_panic() {
        assert!(matches!(parse(b""), Err(ParseError::Empty)));
        assert!(matches!(
            parse(b"2026-11-03 INFO no json here"),
            Err(ParseError::Empty)
        ));
        assert!(
            matches!(parse(b"{}"), Err(ParseError::Json(_))),
            "no SchemaVersion is not a report"
        );
        assert!(matches!(parse(b"[]"), Err(ParseError::Json(_))));
        assert!(matches!(
            parse(b"{\"SchemaVersion\": 2, \"Results\": [{"),
            Err(ParseError::Json(_))
        ));
        let truncated = &FIXTURE[..FIXTURE.len() / 2];
        assert!(matches!(parse(truncated), Err(ParseError::Json(_))));
    }

    #[test]
    fn interpret_completes_fails_and_times_out() {
        match Trivy.interpret(&output(
            Some(0),
            FIXTURE,
            "2026-11-03T10:00:00Z INFO Vulnerability scanning is enabled\n",
        )) {
            Outcome::Completed(parsed) => assert_eq!(
                parsed.findings.len(),
                raw_counts().0 + raw_counts().1 + raw_counts().2 + raw_counts().3
            ),
            other => panic!("{other:?}"),
        }
        assert!(
            matches!(Trivy.interpret(&output(Some(1), b"", "FATAL failed to download vulnerability DB")), Outcome::Failed(r) if r.contains("vulnerability DB"))
        );
        let mut timed = output(None, b"", "");
        timed.timed_out = true;
        assert!(matches!(Trivy.interpret(&timed), Outcome::Failed(_)));
    }

    #[test]
    fn scan_args_follow_the_profile_and_the_offline_flag() {
        let exhaustive = ScanOptions::default();
        let args: Vec<String> = Trivy
            .scan_args(&exhaustive)
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args[0], "fs");
        assert!(
            args.windows(2)
                .any(|w| w == ["--scanners", "vuln,misconfig,secret,license"])
        );
        assert!(args.windows(2).any(|w| w == ["--exit-code", "0"]));
        assert!(
            args.windows(2)
                .any(|w| w == ["--detection-priority", "comprehensive"])
        );
        assert!(args.contains(&"--license-full".to_owned()));
        assert!(!args.contains(&"--skip-db-update".to_owned()));
        assert_eq!(args.last().map(String::as_str), Some("."));
        assert!(Trivy.plan(&exhaustive).unwrap().contains("comprehensive"));

        let security_offline = ScanOptions {
            semgrep_profile: Profile::Security,
            offline: true,
            ..ScanOptions::default()
        };
        let args: Vec<String> = Trivy
            .scan_args(&security_offline)
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(!args.contains(&"--license-full".to_owned()));
        assert!(!args.contains(&"--detection-priority".to_owned()));
        for flag in [
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-check-update",
            "--offline-scan",
        ] {
            assert!(args.contains(&flag.to_owned()), "{flag}");
        }
        assert!(Trivy.plan(&security_offline).unwrap().contains("offline"));
    }

    #[test]
    fn version_is_the_binary_version_not_the_db_version() {
        let v = Trivy
            .parse_version(&output(Some(0), VERSION.as_bytes(), ""))
            .unwrap();
        assert_eq!(v, crate::version::Version::new(0, 76, 1));
    }
}
