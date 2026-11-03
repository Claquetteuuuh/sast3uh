//! `CodeQL` (<https://codeql.github.com>): GitHub's semantic analysis, driven per language with
//! the `security-extended` query suite.
//!
//! Kept light on purpose: the bare CLI from mise (`codeql`, no bundle), the query packs
//! downloaded by `CodeQL` itself the first time a language is analysed (precompiled, so no
//! query compilation on the user's machine; nothing downloaded when offline), one database
//! extracted per language into the scratch directory — never into the target — and deleted
//! as soon as it has been analysed. Compiled languages are extracted without a build where
//! `CodeQL` supports it (`--build-mode=none`: Java/Kotlin, C#, C/C++, Rust); Go and Swift
//! need their toolchain (`--build-mode=autobuild`) and a language that cannot be extracted
//! is a diagnostic, not a failed scan.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;

use super::{
    Context, Outcome, Parsed, Scanner, TEXT_CAP, cap, cwe_number, cwes, failure_reason,
    null_default, os_args, push_unique, read_report, value_text,
};
use crate::detect::{Detected, Language, Marker};
use crate::exec::Output;
use crate::model::{Confidence, Diagnostic, Finding, FlowKind, FlowStep, Severity};

/// `CodeQL`, through `codeql database create` then `codeql database analyze`.
#[derive(Debug, Clone, Copy, Default)]
pub struct CodeQl;

/// A `CodeQL` language and how its database is extracted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    /// The `--language` value.
    pub language: &'static str,
    /// The `--build-mode` value, for a compiled language.
    pub build_mode: Option<&'static str>,
}

/// Exit code of `database create` when no file of the language was found.
const NO_CODE: i32 = 32;
/// What `database create` says then.
const NO_CODE_TEXT: &str = "but not any written in";
/// Where a query's help lives.
const HELP: &str = "https://codeql.github.com/codeql-query-help/";

/// The `CodeQL` languages the target calls for, most files first — one per `CodeQL`
/// language (JavaScript and TypeScript share one, Java and Kotlin another), the GitHub
/// Actions workflows included.
#[must_use]
pub fn targets(detected: &Detected) -> Vec<Target> {
    let mut out: Vec<Target> = Vec::new();
    let mut add = |language: &'static str, build_mode: Option<&'static str>| {
        if !out.iter().any(|t| t.language == language) {
            out.push(Target {
                language,
                build_mode,
            });
        }
    };
    for lang in detected.languages_by_weight() {
        match lang {
            Language::JavaScript | Language::TypeScript => add("javascript", None),
            Language::Python => add("python", None),
            Language::Ruby => add("ruby", None),
            Language::Java | Language::Kotlin => add("java", Some("none")),
            Language::CSharp => add("csharp", Some("none")),
            Language::Cpp => add("cpp", Some("none")),
            Language::Rust => add("rust", Some("none")),
            Language::Go => add("go", Some("autobuild")),
            Language::Swift => add("swift", Some("autobuild")),
            _ => {}
        }
    }
    if detected.markers.contains(&Marker::GithubActions) {
        add("actions", None);
    }
    out
}

impl CodeQl {
    /// `codeql database create` for one language, the current directory as source root.
    #[must_use]
    pub fn create_args(db: &Path, target: Target) -> Vec<OsString> {
        let mut args = os_args(&["database", "create"]);
        args.push(db.into());
        args.push(format!("--language={}", target.language).into());
        args.extend(os_args(&["--source-root=.", "--threads=0", "--overwrite"]));
        if let Some(mode) = target.build_mode {
            args.push(format!("--build-mode={mode}").into());
        }
        args
    }

    /// `codeql database analyze` with the language's `security-extended` suite, SARIF to
    /// `sarif`; the query pack is downloaded when missing unless offline.
    #[must_use]
    pub fn analyze_args(db: &Path, language: &str, sarif: &Path, offline: bool) -> Vec<OsString> {
        let mut args = os_args(&["database", "analyze"]);
        args.push(db.into());
        args.push(
            format!("codeql/{language}-queries:codeql-suites/{language}-security-extended.qls")
                .into(),
        );
        args.extend(os_args(&[
            "--format=sarif-latest",
            "--threads=0",
            "--output",
        ]));
        args.push(sarif.into());
        if !offline {
            args.push("--download".into());
        }
        args
    }

    fn run_target(
        self,
        ctx: &mut Context<'_>,
        scratch: &Path,
        target: Target,
        parsed: &mut Parsed,
    ) -> Result<(), String> {
        let language = target.language;
        let db = scratch.join(format!("db-{language}"));
        let sarif = scratch.join(format!("{language}.sarif"));
        ctx.log(format!("{language}: extracting the database…"));
        let inv = ctx.invocation(Self::create_args(&db, target), &self.env());
        let created = ctx.run(&inv).map_err(|e| format!("{language}: {e}"))?;
        if !created.success() {
            let text = created.stderr_text();
            if created.code == Some(NO_CODE) || text.contains(NO_CODE_TEXT) {
                let said = text
                    .lines()
                    .find(|l| l.contains(NO_CODE_TEXT))
                    .unwrap_or("no source file of that language")
                    .trim_start_matches("ERROR: ");
                parsed.diagnostics.push(Diagnostic {
                    level: "warning".to_owned(),
                    rule_id: None,
                    path: None,
                    message: format!("{language}: nothing extracted: {}", cap(said, TEXT_CAP)),
                });
                return Ok(());
            }
            return Err(format!(
                "{language}: database creation failed: {}",
                failure_reason(&created)
            ));
        }
        ctx.log(format!("{language}: running the security-extended suite…"));
        let inv = ctx.invocation(
            Self::analyze_args(&db, language, &sarif, ctx.options.offline),
            &self.env(),
        );
        let analysed = ctx.run(&inv).map_err(|e| format!("{language}: {e}"))?;
        // The database can be large; free it before the next language.
        let _ = std::fs::remove_dir_all(&db);
        if !analysed.success() {
            return Err(format!(
                "{language}: analysis failed: {}",
                failure_reason(&analysed)
            ));
        }
        let part = read_report(&sarif, ctx.max_output)
            .and_then(|bytes| parse(&bytes))
            .map_err(|e| format!("{language}: {e}"))?;
        merge(parsed, part, language);
        Ok(())
    }
}

/// Add one language's results to the whole.
fn merge(whole: &mut Parsed, part: Parsed, language: &str) {
    for mut finding in part.findings {
        finding
            .extra
            .insert("language".to_owned(), language.to_owned());
        whole.findings.push(finding);
    }
    whole.warnings.extend(
        part.warnings
            .into_iter()
            .map(|w| format!("{language}: {w}")),
    );
    whole.diagnostics.extend(part.diagnostics);
    whole.skipped_paths.extend(part.skipped_paths);
    if let Some(n) = part.scanned_files {
        whole.scanned_files = Some(whole.scanned_files.unwrap_or(0).saturating_add(n));
    }
}

impl Scanner for CodeQl {
    fn name(&self) -> &'static str {
        "codeql"
    }

    fn binary(&self) -> &'static str {
        "codeql"
    }

    fn purpose(&self) -> &'static str {
        "GitHub's semantic analysis (security-extended suite per language; ~1 GB installed, \
         query packs fetched on first use)"
    }

    fn mise_id(&self) -> &'static str {
        "codeql"
    }

    fn version_args(&self) -> Vec<OsString> {
        os_args(&["version", "--format=terse"])
    }

    fn env(&self) -> Vec<(OsString, OsString)> {
        vec![("NO_COLOR".into(), "1".into())]
    }

    fn plan(&self, options: &super::ScanOptions) -> Option<String> {
        let targets = targets(&options.detected);
        (!targets.is_empty()).then(|| {
            format!(
                "security-extended suite for {}",
                targets
                    .iter()
                    .map(|t| t.language)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
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

    fn execute(&self, ctx: &mut Context<'_>) -> Outcome {
        let targets = targets(&ctx.options.detected);
        if targets.is_empty() {
            return Outcome::Skipped("no language CodeQL supports in the target".to_owned());
        }
        let scratch = match ctx.scratch() {
            Ok(dir) => dir,
            Err(err) => return Outcome::Failed(err),
        };
        let mut parsed = Parsed::default();
        let mut failures = Vec::new();
        let mut analysed = 0usize;
        for target in targets {
            match Self.run_target(ctx, &scratch, target, &mut parsed) {
                Ok(()) => analysed += 1,
                Err(reason) => failures.push(reason),
            }
        }
        for reason in &failures {
            parsed.warnings.push(reason.clone());
            parsed.diagnostics.push(Diagnostic {
                level: "error".to_owned(),
                rule_id: None,
                path: None,
                message: reason.clone(),
            });
        }
        if analysed == 0 && !failures.is_empty() {
            return Outcome::Failed(failures.join("; "));
        }
        Outcome::Completed(parsed)
    }
}

#[derive(Deserialize)]
struct Sarif {
    // Required on purpose: `{}` is not a SARIF log.
    runs: Vec<Value>,
}

#[derive(Deserialize, Default)]
struct Run {
    #[serde(default)]
    tool: Tool,
    #[serde(default, deserialize_with = "null_default")]
    results: Vec<Value>,
    #[serde(default, deserialize_with = "null_default")]
    invocations: Vec<Invocation>,
    #[serde(default, deserialize_with = "null_default")]
    artifacts: Vec<Value>,
}

#[derive(Deserialize, Default)]
struct Tool {
    #[serde(default)]
    driver: Component,
    #[serde(default, deserialize_with = "null_default")]
    extensions: Vec<Component>,
}

#[derive(Deserialize, Default)]
struct Component {
    #[serde(default, deserialize_with = "null_default")]
    rules: Vec<Value>,
}

#[derive(Deserialize, Default)]
struct Rule {
    #[serde(default, deserialize_with = "null_default")]
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "shortDescription")]
    short: Option<Text>,
    #[serde(default, rename = "fullDescription")]
    full: Option<Text>,
    #[serde(default)]
    help: Option<Text>,
    #[serde(default, rename = "helpUri")]
    help_uri: Option<String>,
    #[serde(default, rename = "defaultConfiguration")]
    default_configuration: Option<Value>,
    #[serde(default, deserialize_with = "null_default")]
    properties: BTreeMap<String, Value>,
}

#[derive(Deserialize, Default)]
struct Text {
    #[serde(default, deserialize_with = "null_default")]
    text: String,
    #[serde(default)]
    markdown: Option<String>,
}

#[derive(Deserialize)]
struct SarifResult {
    #[serde(default, rename = "ruleId")]
    rule_id: Option<String>,
    #[serde(default, rename = "ruleIndex")]
    rule_index: Option<usize>,
    #[serde(default)]
    rule: Option<RuleRef>,
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    message: Option<Text>,
    #[serde(default, deserialize_with = "null_default")]
    locations: Vec<Location>,
    #[serde(default, rename = "codeFlows", deserialize_with = "null_default")]
    code_flows: Vec<CodeFlow>,
    #[serde(
        default,
        rename = "partialFingerprints",
        deserialize_with = "null_default"
    )]
    partial_fingerprints: BTreeMap<String, Value>,
    #[serde(default, deserialize_with = "null_default")]
    suppressions: Vec<Value>,
    #[serde(flatten)]
    rest: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
struct RuleRef {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    index: Option<usize>,
    #[serde(default, rename = "toolComponent")]
    tool_component: Option<ComponentRef>,
}

#[derive(Deserialize)]
struct ComponentRef {
    #[serde(default)]
    index: Option<usize>,
}

#[derive(Deserialize, Default)]
struct Location {
    #[serde(default, rename = "physicalLocation")]
    physical: Option<Physical>,
    #[serde(default)]
    message: Option<Text>,
}

#[derive(Deserialize, Default)]
struct Physical {
    #[serde(default, rename = "artifactLocation")]
    artifact: Option<Artifact>,
    #[serde(default)]
    region: Option<Region>,
}

#[derive(Deserialize, Default)]
struct Artifact {
    #[serde(default)]
    uri: Option<String>,
}

#[derive(Deserialize, Default)]
struct Region {
    #[serde(default, rename = "startLine")]
    start_line: Option<u32>,
    #[serde(default, rename = "startColumn")]
    start_column: Option<u32>,
    #[serde(default, rename = "endLine")]
    end_line: Option<u32>,
    #[serde(default, rename = "endColumn")]
    end_column: Option<u32>,
    #[serde(default)]
    snippet: Option<Text>,
}

#[derive(Deserialize, Default)]
struct CodeFlow {
    #[serde(default, rename = "threadFlows", deserialize_with = "null_default")]
    thread_flows: Vec<ThreadFlow>,
}

#[derive(Deserialize, Default)]
struct ThreadFlow {
    #[serde(default, deserialize_with = "null_default")]
    locations: Vec<ThreadLocation>,
}

#[derive(Deserialize, Default)]
struct ThreadLocation {
    #[serde(default)]
    location: Option<Location>,
}

#[derive(Deserialize, Default)]
struct Invocation {
    #[serde(
        default,
        rename = "toolExecutionNotifications",
        deserialize_with = "null_default"
    )]
    execution: Vec<Notification>,
    #[serde(
        default,
        rename = "toolConfigurationNotifications",
        deserialize_with = "null_default"
    )]
    configuration: Vec<Notification>,
}

#[derive(Deserialize, Default)]
struct Notification {
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    message: Option<Text>,
    #[serde(default)]
    descriptor: Option<Descriptor>,
    #[serde(default, deserialize_with = "null_default")]
    locations: Vec<Location>,
}

#[derive(Deserialize, Default)]
struct Descriptor {
    #[serde(default)]
    id: Option<String>,
}

/// The rules of a run: the driver's, then each extension's, in SARIF component order.
struct Rules {
    components: Vec<Vec<Rule>>,
}

impl Rules {
    fn of(tool: &Tool) -> Self {
        let read = |component: &Component| {
            component
                .rules
                .iter()
                .map(|raw| serde_json::from_value::<Rule>(raw.clone()).unwrap_or_default())
                .collect::<Vec<Rule>>()
        };
        let mut components = vec![read(&tool.driver)];
        components.extend(tool.extensions.iter().map(read));
        Rules { components }
    }

    /// The rule a result refers to: by component and index first, then by index in the
    /// driver, then by id anywhere.
    fn for_result(&self, result: &SarifResult) -> Option<&Rule> {
        let id = result
            .rule_id
            .as_deref()
            .or(result.rule.as_ref().and_then(|r| r.id.as_deref()));
        let by_index = |component: usize, index: usize| {
            self.components
                .get(component)
                .and_then(|rules| rules.get(index))
                .filter(|rule| id.is_none_or(|id| rule.id == id))
        };
        if let Some(reference) = &result.rule
            && let Some(index) = reference.index
        {
            let component = reference
                .tool_component
                .as_ref()
                .and_then(|c| c.index)
                .map_or(0, |i| i.saturating_add(1));
            if let Some(rule) = by_index(component, index) {
                return Some(rule);
            }
        }
        if let Some(index) = result.rule_index
            && let Some(rule) = by_index(0, index)
        {
            return Some(rule);
        }
        let id = id?;
        self.components.iter().flatten().find(|rule| rule.id == id)
    }
}

/// Read a SARIF log written by `codeql database analyze`. Every result of every run becomes a
/// finding; the tool's notifications become diagnostics.
///
/// # Errors
///
/// When the bytes are not a SARIF log.
pub fn parse(bytes: &[u8]) -> Result<Parsed, String> {
    let sarif: Sarif =
        serde_json::from_slice(bytes).map_err(|e| format!("not a SARIF log: {e}"))?;
    let mut parsed = Parsed::default();
    for (run_index, raw) in sarif.runs.iter().enumerate() {
        let run: Run = serde_json::from_value(raw.clone())
            .map_err(|e| format!("run {run_index} is unreadable: {e}"))?;
        let rules = Rules::of(&run.tool);
        for (index, raw) in run.results.iter().enumerate() {
            match serde_json::from_value::<SarifResult>(raw.clone()) {
                Ok(result) => parsed
                    .findings
                    .push(finding(&result, rules.for_result(&result))),
                Err(e) => parsed
                    .warnings
                    .push(format!("unreadable result {index}: {e}")),
            }
        }
        let mut extracted = 0usize;
        for invocation in &run.invocations {
            for notification in invocation.execution.iter().chain(&invocation.configuration) {
                let id = notification.descriptor.as_ref().and_then(|d| d.id.clone());
                let level = notification.level.as_deref().unwrap_or("warning");
                if level == "none" {
                    if id
                        .as_deref()
                        .is_some_and(|id| id.ends_with("successfully-extracted-files"))
                    {
                        extracted = extracted.saturating_add(1);
                    }
                    continue;
                }
                parsed.diagnostics.push(Diagnostic {
                    level: level.to_owned(),
                    rule_id: id,
                    path: notification.locations.first().and_then(uri_of),
                    message: cap(
                        &notification
                            .message
                            .as_ref()
                            .map(|m| m.text.clone())
                            .unwrap_or_default(),
                        TEXT_CAP,
                    ),
                });
            }
        }
        let files = extracted.max(run.artifacts.len());
        if files > 0 {
            parsed.scanned_files = Some(parsed.scanned_files.unwrap_or(0).saturating_add(files));
        }
    }
    Ok(parsed)
}

fn uri_of(location: &Location) -> Option<String> {
    location.physical.as_ref()?.artifact.as_ref()?.uri.clone()
}

/// The severity `CodeQL` gives a query: its CVSS-like `security-severity` first, then its
/// `problem.severity`, then the SARIF level.
fn severity(rule: Option<&Rule>, level: Option<&str>) -> Severity {
    if let Some(rule) = rule {
        let score = rule
            .properties
            .get("security-severity")
            .and_then(|v| v.as_f64().or_else(|| v.as_str()?.trim().parse().ok()));
        if let Some(score) = score {
            return if score >= 9.0 {
                Severity::Critical
            } else if score >= 7.0 {
                Severity::High
            } else if score >= 4.0 {
                Severity::Medium
            } else if score > 0.0 {
                Severity::Low
            } else {
                Severity::Info
            };
        }
        match rule
            .properties
            .get("problem.severity")
            .and_then(Value::as_str)
        {
            Some("error") => return Severity::High,
            Some("warning") => return Severity::Medium,
            Some("recommendation") => return Severity::Low,
            _ => {}
        }
    }
    let level = level.map(str::to_owned).or_else(|| {
        rule?
            .default_configuration
            .as_ref()?
            .get("level")?
            .as_str()
            .map(str::to_owned)
    });
    match level.as_deref() {
        Some("error") => Severity::High,
        Some("warning") => Severity::Medium,
        Some("note") => Severity::Low,
        _ => Severity::Info,
    }
}

fn confidence(rule: Option<&Rule>) -> Option<Confidence> {
    match rule?.properties.get("precision")?.as_str()? {
        "very-high" | "high" => Some(Confidence::High),
        "medium" => Some(Confidence::Medium),
        "low" => Some(Confidence::Low),
        _ => None,
    }
}

/// The query help page, from the id's language prefix (`js/reflected-xss` → javascript).
fn help_url(rule_id: &str) -> Option<String> {
    let (prefix, _) = rule_id.split_once('/')?;
    let language = match prefix {
        "js" => "javascript",
        "py" => "python",
        "rb" => "ruby",
        "java" => "java",
        "cpp" => "cpp",
        "cs" => "csharp",
        "go" => "go",
        "swift" => "swift",
        "rust" => "rust",
        "actions" => "actions",
        _ => return None,
    };
    Some(format!("{HELP}{language}/{}/", rule_id.replace('/', "-")))
}

fn step(location: &Location, kind: FlowKind) -> Option<FlowStep> {
    let physical = location.physical.as_ref()?;
    let region = physical.region.as_ref();
    Some(FlowStep {
        kind,
        path: physical.artifact.as_ref()?.uri.clone()?.into(),
        line: region.and_then(|r| r.start_line),
        column: region.and_then(|r| r.start_column),
        end_line: region.and_then(|r| r.end_line),
        end_column: region.and_then(|r| r.end_column),
        content: location
            .message
            .as_ref()
            .map(|m| cap(&m.text, TEXT_CAP))
            .filter(|m| !m.is_empty()),
    })
}

fn finding(result: &SarifResult, rule: Option<&Rule>) -> Finding {
    let rule_id = result
        .rule_id
        .clone()
        .or_else(|| result.rule.as_ref()?.id.clone())
        .or_else(|| rule.map(|r| r.id.clone()))
        .unwrap_or_else(|| "unknown".to_owned());
    let title = rule
        .and_then(|r| {
            r.short
                .as_ref()
                .map(|t| t.text.clone())
                .filter(|t| !t.is_empty())
        })
        .or_else(|| rule?.name.clone())
        .unwrap_or_else(|| rule_id.clone());
    let message = result
        .message
        .as_ref()
        .map(|m| m.text.clone())
        .unwrap_or_default();
    let primary = result.locations.first();
    let physical = primary.and_then(|l| l.physical.as_ref());
    let region = physical.and_then(|p| p.region.as_ref());
    let path = physical
        .and_then(|p| p.artifact.as_ref()?.uri.clone())
        .unwrap_or_default();
    let mut f = Finding::new(
        "codeql",
        rule_id.clone(),
        severity(rule, result.level.as_deref()),
        cap(&title, TEXT_CAP),
        cap(&message, TEXT_CAP),
        path.into(),
    );
    f.confidence = confidence(rule);
    f.suppressed = !result.suppressions.is_empty();
    f.line = region.and_then(|r| r.start_line);
    f.end_line = region.and_then(|r| r.end_line);
    f.column = region.and_then(|r| r.start_column);
    f.end_column = region.and_then(|r| r.end_column);
    f.snippet = region
        .and_then(|r| r.snippet.as_ref())
        .map(|s| cap(&s.text, TEXT_CAP));
    apply_rule(&mut f, rule);
    if let Some(url) = help_url(&rule_id) {
        push_unique(&mut f.references, url.clone());
        f.url = Some(url);
    }
    f.fingerprint = result
        .partial_fingerprints
        .get("primaryLocationLineHash")
        .map(value_text);
    apply_flow(&mut f, result);
    f
}

/// What the rule says about every result it produces.
fn apply_rule(f: &mut Finding, rule: Option<&Rule>) {
    if let Some(rule) = rule {
        let tags: Vec<String> = rule
            .properties
            .get("tags")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(value_text)
            .collect();
        f.cwes = cwes(
            tags.iter()
                .filter(|t| t.to_ascii_lowercase().contains("cwe-"))
                .map(|t| cwe_number(t)),
        );
        for tag in &tags {
            if !tag.contains('/') {
                push_unique(&mut f.categories, tag.clone());
            }
        }
        f.tags = tags;
        if let Some(kind) = rule.properties.get("kind").and_then(Value::as_str) {
            push_unique(&mut f.categories, kind);
        }
        if let Some(uri) = &rule.help_uri {
            f.references.push(uri.clone());
        }
        if let Some(full) = &rule.full {
            f.extra
                .insert("rule.description".to_owned(), cap(&full.text, TEXT_CAP));
        }
        if let Some(help) = &rule.help {
            let text = help.markdown.as_deref().unwrap_or(&help.text);
            f.extra.insert("rule.help".to_owned(), cap(text, TEXT_CAP));
        }
        for (key, value) in &rule.properties {
            if key != "tags" {
                f.extra
                    .insert(format!("rule.{key}"), cap(&value_text(value), TEXT_CAP));
            }
        }
    }
}

/// The first code flow as the finding's data flow, and the rest of the result as extras.
fn apply_flow(f: &mut Finding, result: &SarifResult) {
    if let Some(flow) = result
        .code_flows
        .first()
        .and_then(|c| c.thread_flows.first())
    {
        let last = flow.locations.len().saturating_sub(1);
        for (index, location) in flow.locations.iter().enumerate() {
            let kind = if index == 0 {
                FlowKind::Source
            } else if index == last {
                FlowKind::Sink
            } else {
                FlowKind::Intermediate
            };
            if let Some(step) = location.location.as_ref().and_then(|l| step(l, kind)) {
                f.flow.push(step);
            }
        }
    }
    if result.code_flows.len() > 1 {
        f.extra
            .insert("codeFlows".to_owned(), result.code_flows.len().to_string());
    }
    if let Some(level) = &result.level {
        f.extra.insert("level".to_owned(), level.clone());
    }
    for (key, value) in &result.partial_fingerprints {
        f.extra
            .insert(format!("partialFingerprints.{key}"), value_text(value));
    }
    for (key, value) in &result.rest {
        f.extra
            .insert(key.clone(), cap(&value_text(value), TEXT_CAP));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::test_support::{FakeRunner, output};
    use crate::scanners::ScanOptions;
    use std::path::PathBuf;

    const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/codeql/report.sarif");
    const PYTHON: &[u8] = include_bytes!("../../tests/fixtures/codeql/report-python.sarif");
    const VERSION: &str = include_str!("../../tests/fixtures/codeql/version.txt");
    const NO_CODE_STDERR: &str = include_str!("../../tests/fixtures/codeql/create-no-code.txt");

    fn raw_results(bytes: &[u8]) -> Vec<String> {
        let root: Value = serde_json::from_slice(bytes).unwrap();
        root["runs"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|run| run["results"].as_array().unwrap().iter())
            .map(|r| r["ruleId"].as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn every_result_of_the_recorded_logs_is_a_finding() {
        for bytes in [FIXTURE, PYTHON] {
            let ids = raw_results(bytes);
            let parsed = parse(bytes).unwrap();
            assert_eq!(parsed.findings.len() + parsed.warnings.len(), ids.len());
            assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
            for id in ids {
                assert!(parsed.findings.iter().any(|f| f.rule_id == id), "{id}");
            }
            assert!(parsed.scanned_files.unwrap() >= 1);
        }
        assert_eq!(parse(FIXTURE).unwrap().findings.len(), 5);
        assert_eq!(parse(PYTHON).unwrap().findings.len(), 3);
    }

    #[test]
    fn a_finding_keeps_what_codeql_says() {
        let parsed = parse(PYTHON).unwrap();
        let f = parsed
            .findings
            .iter()
            .find(|f| f.rule_id == "py/command-line-injection")
            .unwrap();
        assert_eq!(f.tool, "codeql");
        assert_eq!(f.severity, Severity::Critical, "security-severity 9.8");
        assert_eq!(f.confidence, Some(Confidence::High));
        assert_eq!(f.title, "Uncontrolled command line");
        assert!(f.message.contains("user-provided value"));
        assert_eq!(f.path, PathBuf::from("app.py"));
        assert_eq!(
            (f.line, f.column, f.end_column),
            (Some(11), Some(36), Some(55))
        );
        assert_eq!(f.cwes, vec![78, 88]);
        assert!(f.categories.contains(&"security".to_owned()));
        assert!(f.categories.contains(&"path-problem".to_owned()));
        assert!(f.tags.contains(&"external/cwe/cwe-078".to_owned()));
        assert_eq!(
            f.url.as_deref(),
            Some("https://codeql.github.com/codeql-query-help/python/py-command-line-injection/")
        );
        assert!(f.fingerprint.as_deref().unwrap().contains(':'));
        assert!(f.flow.len() >= 2, "{:?}", f.flow);
        assert_eq!(f.flow.first().unwrap().kind, FlowKind::Source);
        assert_eq!(f.flow.last().unwrap().kind, FlowKind::Sink);
        assert_eq!(f.flow.first().unwrap().path, PathBuf::from("app.py"));
        assert!(f.flow.first().unwrap().content.is_some());
        assert_eq!(
            f.extra.get("rule.precision").map(String::as_str),
            Some("high")
        );
        assert_eq!(
            f.extra.get("rule.security-severity").map(String::as_str),
            Some("9.8")
        );
        assert!(f.extra.contains_key("rule.description"));
        assert!(f.extra.contains_key("relatedLocations"));
        assert!(!f.suppressed);
        let medium = parse(FIXTURE)
            .unwrap()
            .findings
            .into_iter()
            .find(|f| f.rule_id == "js/missing-rate-limiting")
            .unwrap();
        assert_eq!(medium.severity, Severity::High, "7.5");
        assert!(medium.flow.is_empty());
    }

    #[test]
    fn severity_follows_security_severity_then_problem_severity_then_level() {
        let rule = |props: Value, level: Option<&str>| Rule {
            properties: props
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            default_configuration: level.map(|l| serde_json::json!({ "level": l })),
            ..Rule::default()
        };
        assert_eq!(
            severity(
                Some(&rule(serde_json::json!({"security-severity": "9.0"}), None)),
                None
            ),
            Severity::Critical
        );
        assert_eq!(
            severity(
                Some(&rule(serde_json::json!({"security-severity": 7.0}), None)),
                None
            ),
            Severity::High
        );
        assert_eq!(
            severity(
                Some(&rule(serde_json::json!({"security-severity": "4"}), None)),
                None
            ),
            Severity::Medium
        );
        assert_eq!(
            severity(
                Some(&rule(serde_json::json!({"security-severity": "0.5"}), None)),
                None
            ),
            Severity::Low
        );
        assert_eq!(
            severity(
                Some(&rule(serde_json::json!({"security-severity": "0"}), None)),
                None
            ),
            Severity::Info
        );
        assert_eq!(
            severity(
                Some(&rule(
                    serde_json::json!({"problem.severity": "error"}),
                    None
                )),
                None
            ),
            Severity::High
        );
        assert_eq!(
            severity(
                Some(&rule(
                    serde_json::json!({"problem.severity": "recommendation"}),
                    None
                )),
                Some("error")
            ),
            Severity::Low
        );
        assert_eq!(
            severity(Some(&rule(serde_json::json!({}), Some("warning"))), None),
            Severity::Medium
        );
        assert_eq!(severity(None, Some("note")), Severity::Low);
        assert_eq!(severity(None, None), Severity::Info);
        assert_eq!(
            confidence(Some(&rule(
                serde_json::json!({"precision": "very-high"}),
                None
            ))),
            Some(Confidence::High)
        );
        assert_eq!(confidence(None), None);
        assert_eq!(
            help_url("js/x"),
            Some("https://codeql.github.com/codeql-query-help/javascript/js-x/".to_owned())
        );
        assert_eq!(help_url("weird"), None);
        assert_eq!(help_url("zz/x"), None);
    }

    #[test]
    fn rules_are_found_in_extensions_by_index_or_anywhere_by_id() {
        let log = serde_json::json!({"runs": [{
            "tool": {"driver": {"rules": [{"id": "a/one", "shortDescription": {"text": "One"}}]},
                     "extensions": [{"name": "pack", "rules": [{"id": "a/two", "properties": {"problem.severity": "warning"}}]}]},
            "results": [
                {"ruleId": "a/two", "rule": {"index": 0, "toolComponent": {"index": 0}}, "message": {"text": "m"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "x.js"}, "region": {"startLine": 3}}}]},
                {"ruleId": "a/one", "ruleIndex": 0, "message": {"text": "m"}, "locations": []},
                {"ruleId": "a/two", "message": {"text": "by id"}, "suppressions": [{"kind": "inSource"}]},
                {"ruleId": "a/none", "rule": {"index": 7}, "message": null, "locations": null, "codeFlows": null, "partialFingerprints": null},
                "not an object"
            ]
        }]});
        let parsed = parse(&serde_json::to_vec(&log).unwrap()).unwrap();
        assert_eq!(parsed.findings.len(), 4);
        assert_eq!(parsed.warnings.len(), 1, "{:?}", parsed.warnings);
        assert_eq!(parsed.findings[0].severity, Severity::Medium);
        assert_eq!(parsed.findings[0].line, Some(3));
        assert_eq!(parsed.findings[1].title, "One");
        assert_eq!(parsed.findings[2].severity, Severity::Medium, "found by id");
        assert!(parsed.findings[2].suppressed);
        assert_eq!(parsed.findings[3].title, "a/none");
        assert_eq!(parsed.findings[3].severity, Severity::Info);
        assert_eq!(parsed.findings[3].path, PathBuf::new());
    }

    #[test]
    fn notifications_become_diagnostics() {
        let log = serde_json::json!({"runs": [{"tool": {"driver": {}}, "results": [],
            "invocations": [{"toolExecutionNotifications": [
                {"level": "none", "descriptor": {"id": "js/diagnostics/successfully-extracted-files"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.js"}}}]},
                {"level": "error", "descriptor": {"id": "js/diagnostics/extraction-errors"}, "message": {"text": "boom"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "b.js"}}}]}
            ], "toolConfigurationNotifications": [{"message": {"text": "config"}}]}]}]});
        let parsed = parse(&serde_json::to_vec(&log).unwrap()).unwrap();
        assert_eq!(parsed.scanned_files, Some(1));
        assert_eq!(parsed.diagnostics.len(), 2);
        assert_eq!(parsed.diagnostics[0].level, "error");
        assert_eq!(parsed.diagnostics[0].path.as_deref(), Some("b.js"));
        assert_eq!(parsed.diagnostics[1].level, "warning");
    }

    #[test]
    fn garbage_empty_and_wrong_shapes_are_errors() {
        assert!(parse(b"").is_err());
        assert!(parse(b"{").is_err());
        assert!(parse(b"[]").is_err());
        assert!(parse(b"{}").is_err());
        assert!(parse(br#"{"runs": "nope"}"#).is_err());
        assert!(parse(br#"{"runs": ["nope"]}"#).is_err());
        assert!(parse(&FIXTURE[..FIXTURE.len() / 2]).is_err());
        let results = "{\"ruleId\":\"x/y\",\"message\":{\"text\":\"m\"}},".repeat(3000);
        let big = format!(
            "{{\"runs\":[{{\"tool\":{{\"driver\":{{}}}},\"results\":[{}]}}]}}",
            results.trim_end_matches(',')
        );
        assert_eq!(parse(big.as_bytes()).unwrap().findings.len(), 3000);
        assert_eq!(parse(br#"{"runs": []}"#).unwrap().findings.len(), 0);
    }

    #[test]
    fn targets_map_the_detected_languages_once_each() {
        let mut detected = Detected::default();
        assert!(targets(&detected).is_empty());
        detected.languages.insert(Language::TypeScript, 10);
        detected.languages.insert(Language::JavaScript, 2);
        detected.languages.insert(Language::Kotlin, 1);
        detected.languages.insert(Language::Lua, 50);
        detected.languages.insert(Language::Go, 3);
        detected.markers.insert(Marker::GithubActions);
        let found = targets(&detected);
        let names: Vec<&str> = found.iter().map(|t| t.language).collect();
        assert_eq!(names, vec!["javascript", "go", "java", "actions"]);
        assert_eq!(found[1].build_mode, Some("autobuild"));
        assert_eq!(found[2].build_mode, Some("none"));
        assert_eq!(found[3].build_mode, None);
    }

    #[test]
    fn args_name_the_language_the_suite_and_the_files() {
        let db = Path::new("/scratch/db-java");
        let create = CodeQl::create_args(
            db,
            Target {
                language: "java",
                build_mode: Some("none"),
            },
        );
        assert_eq!(create[0], "database");
        assert_eq!(create[1], "create");
        assert_eq!(create[2], db.as_os_str());
        assert!(create.iter().any(|a| a == "--language=java"));
        assert!(create.iter().any(|a| a == "--build-mode=none"));
        assert!(create.iter().any(|a| a == "--source-root=."));
        let plain = CodeQl::create_args(
            db,
            Target {
                language: "python",
                build_mode: None,
            },
        );
        assert!(
            !plain
                .iter()
                .any(|a| a.to_string_lossy().starts_with("--build-mode"))
        );
        let sarif = Path::new("/scratch/java.sarif");
        let analyze = CodeQl::analyze_args(db, "java", sarif, false);
        assert!(
            analyze
                .iter()
                .any(|a| a == "codeql/java-queries:codeql-suites/java-security-extended.qls")
        );
        assert!(analyze.iter().any(|a| a == "--format=sarif-latest"));
        assert!(analyze.iter().any(|a| a == "--download"));
        let at = analyze.iter().position(|a| a == "--output").unwrap();
        assert_eq!(analyze[at + 1], sarif.as_os_str());
        assert!(
            !CodeQl::analyze_args(db, "java", sarif, true)
                .iter()
                .any(|a| a == "--download")
        );
        assert_eq!(CodeQl.mise_id(), "codeql");
        assert!(CodeQl.scan_args(&ScanOptions::default()).is_empty());
        let mut options = ScanOptions::default();
        assert!(CodeQl.plan(&options).is_none());
        options.detected.languages.insert(Language::Python, 1);
        assert_eq!(
            CodeQl.plan(&options).unwrap(),
            "security-extended suite for python"
        );
    }

    #[test]
    fn version_is_read_from_the_terse_output() {
        let v = CodeQl
            .parse_version(&output(Some(0), VERSION.as_bytes(), ""))
            .unwrap();
        assert_eq!(v.to_string(), "2.27.3");
    }

    #[test]
    fn interpret_reads_a_sarif_log_or_fails() {
        assert!(matches!(
            CodeQl.interpret(&output(Some(0), FIXTURE, "")),
            Outcome::Completed(_)
        ));
        assert!(matches!(
            CodeQl.interpret(&output(Some(0), b"nope", "")),
            Outcome::Failed(_)
        ));
        let mut timed = output(None, b"", "");
        timed.timed_out = true;
        assert!(matches!(CodeQl.interpret(&timed), Outcome::Failed(_)));
        let mut big = output(Some(0), FIXTURE, "");
        big.stdout_truncated = true;
        assert!(matches!(CodeQl.interpret(&big), Outcome::Failed(_)));
    }

    fn options_for(languages: &[Language]) -> ScanOptions {
        let mut options = ScanOptions::default();
        for (i, lang) in languages.iter().enumerate() {
            options.detected.languages.insert(*lang, 10 - i);
        }
        options
    }

    /// Answers `database create` and `database analyze` like `CodeQL` would, writing `sarif`
    /// where `--output` says; `create_code` is the exit code of every creation.
    fn runner(
        sarif: &'static [u8],
        create_code: i32,
        create_stderr: &'static str,
    ) -> FakeRunner<impl Fn(&crate::exec::Invocation) -> Result<Output, crate::exec::ExecError>>
    {
        FakeRunner::new(move |inv: &crate::exec::Invocation| {
            let args: Vec<String> = inv
                .args
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            if args.get(1).map(String::as_str) == Some("create") {
                return Ok(output(Some(create_code), b"", create_stderr));
            }
            let at = args.iter().position(|a| a == "--output").unwrap();
            std::fs::write(&args[at + 1], sarif).unwrap();
            Ok(output(Some(0), b"", ""))
        })
    }

    #[test]
    fn execute_runs_create_then_analyze_per_language_and_merges() {
        let runner = runner(FIXTURE, 0, "");
        let options = options_for(&[Language::JavaScript, Language::Python]);
        let mut log = Vec::new();
        let dir = tempfile::tempdir().unwrap();
        let outcome = {
            let mut ctx = Context::new(
                "codeql",
                PathBuf::from("/bin/codeql"),
                dir.path(),
                &options,
                &runner,
                &mut log,
            );
            ctx.scratch_root = Some(dir.path().join("cache"));
            CodeQl.execute(&mut ctx)
        };
        let Outcome::Completed(parsed) = outcome else {
            panic!("{outcome:?}")
        };
        assert_eq!(parsed.findings.len(), 10, "5 per language");
        assert_eq!(
            parsed.findings[0].extra.get("language").map(String::as_str),
            Some("javascript")
        );
        assert_eq!(
            parsed.findings[9].extra.get("language").map(String::as_str),
            Some("python")
        );
        let calls = runner.calls();
        assert_eq!(calls.len(), 4);
        assert!(calls.iter().all(|c| c.cwd.as_deref() == Some(dir.path())));
        assert!(calls[0].args.iter().any(|a| a == "--language=javascript"));
        assert!(calls[2].args.iter().any(|a| a == "--language=python"));
        let db = calls[0].args[2].to_string_lossy().into_owned();
        assert!(
            db.starts_with(&dir.path().join("cache").to_string_lossy().into_owned()),
            "{db}"
        );
        assert!(
            !std::fs::exists(dir.path().join("cache")).unwrap()
                || std::fs::read_dir(dir.path().join("cache"))
                    .unwrap()
                    .next()
                    .is_none(),
            "scratch deleted"
        );
        let text = String::from_utf8(log).unwrap();
        assert!(
            text.contains("codeql: javascript: extracting the database…"),
            "{text}"
        );
    }

    #[test]
    fn a_language_without_code_is_a_diagnostic_and_the_rest_runs() {
        let runner = runner(PYTHON, NO_CODE, NO_CODE_STDERR);
        let options = options_for(&[Language::Ruby]);
        let mut log = Vec::new();
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = Context::new(
            "codeql",
            PathBuf::from("/bin/codeql"),
            dir.path(),
            &options,
            &runner,
            &mut log,
        );
        let Outcome::Completed(parsed) = CodeQl.execute(&mut ctx) else {
            panic!()
        };
        assert!(parsed.findings.is_empty());
        assert_eq!(parsed.diagnostics.len(), 1);
        assert!(parsed.diagnostics[0].message.contains("ruby: nothing extracted: CodeQL detected code written in JavaScript/TypeScript, but not any written in Ruby"), "{}", parsed.diagnostics[0].message);
        assert_eq!(runner.calls().len(), 1, "no analysis without a database");
    }

    #[test]
    fn a_failed_extraction_fails_the_scan_when_nothing_else_ran() {
        let runner = runner(PYTHON, 1, "ERROR: the extractor crashed");
        let options = options_for(&[Language::Python]);
        let mut log = Vec::new();
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = Context::new(
            "codeql",
            PathBuf::from("/bin/codeql"),
            dir.path(),
            &options,
            &runner,
            &mut log,
        );
        match CodeQl.execute(&mut ctx) {
            Outcome::Failed(reason) => assert!(
                reason.contains("python: database creation failed") && reason.contains("crashed"),
                "{reason}"
            ),
            other => panic!("{other:?}"),
        }
        let none = ScanOptions::default();
        let mut ctx = Context::new(
            "codeql",
            PathBuf::from("/bin/codeql"),
            dir.path(),
            &none,
            &runner,
            &mut log,
        );
        assert!(matches!(CodeQl.execute(&mut ctx), Outcome::Skipped(_)));
    }
}
