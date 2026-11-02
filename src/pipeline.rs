//! The scan pipeline: locate each scanner, check its version, offer the update, run it, parse
//! its output, merge everything into one report.
//!
//! Every side effect goes through [`Deps`] — the process runner, the HTTP client, the prompt,
//! `PATH`, the log — so the whole flow is tested in-process with fakes.

use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::dedup;
use crate::exec::{DEFAULT_MAX_OUTPUT, DEFAULT_TIMEOUT, Invocation, Runner};
use crate::model::{Finding, Report, ToolRun, ToolStatus};
use crate::prompt::Prompter;
use crate::scanners::{self, Outcome, ScanOptions, Scanner};
use crate::tools::find_in_path;
use crate::update::{self, Http, StepResult, UpdateContext};
use crate::version::Version;

/// What to do with an outdated scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum UpdatePolicy {
    /// Ask on the terminal (no in a non-interactive run).
    Ask,
    /// Update without asking.
    Always,
    /// Never update; only say that a newer version exists.
    Never,
}

/// Pipeline settings.
#[derive(Debug, Clone)]
pub struct Options {
    /// Scanners to run; every known one when empty.
    pub tools: Vec<String>,
    /// Per-scanner knobs.
    pub scan: ScanOptions,
    /// Per-scanner time limit.
    pub timeout: Duration,
    /// Per-stream capture cap.
    pub max_output: usize,
    /// Update policy.
    pub update: UpdatePolicy,
    /// Deduplicate (see [`crate::dedup`]).
    pub dedup: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            tools: Vec::new(),
            scan: ScanOptions::default(),
            timeout: DEFAULT_TIMEOUT,
            max_output: DEFAULT_MAX_OUTPUT,
            update: UpdatePolicy::Ask,
            dedup: true,
        }
    }
}

/// The outside world, injectable.
pub struct Deps<'a> {
    /// Runs processes.
    pub runner: &'a dyn Runner,
    /// Talks to GitHub; `None` means offline (no version check, no update).
    pub http: Option<&'a dyn Http>,
    /// Asks the user.
    pub prompter: &'a mut dyn Prompter,
    /// `PATH`.
    pub path_var: Option<&'a OsStr>,
    /// Progress and warnings (standard error in the CLI).
    pub log: &'a mut dyn Write,
}

impl std::fmt::Debug for Deps<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Deps")
            .field("online", &self.http.is_some())
            .finish_non_exhaustive()
    }
}

impl Deps<'_> {
    fn log(&mut self, line: impl std::fmt::Display) {
        // The log is best effort: a closed stderr must not stop a scan.
        let _ = writeln!(self.log, "{line}");
    }
}

/// Why the pipeline could not start.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    /// The target path does not exist.
    #[error("target does not exist: {0}")]
    Missing(PathBuf),
    /// The target exists but is not a directory.
    #[error("target is not a directory: {0}")]
    NotADirectory(PathBuf),
    /// The target could not be inspected or resolved.
    #[error("cannot resolve target {path}")]
    Resolve {
        /// The path as given.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A name in `--tools` is not a known scanner.
    #[error("unknown tool `{name}` (known: {known})")]
    UnknownTool {
        /// The name.
        name: String,
        /// The known names.
        known: String,
    },
}

/// Check that `path` is an existing directory and return its canonical form.
///
/// # Errors
///
/// [`PipelineError::Missing`], [`PipelineError::NotADirectory`] or [`PipelineError::Resolve`].
pub fn resolve_target(path: &Path) -> Result<PathBuf, PipelineError> {
    let metadata = std::fs::metadata(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            PipelineError::Missing(path.to_path_buf())
        } else {
            PipelineError::Resolve {
                path: path.to_path_buf(),
                source,
            }
        }
    })?;
    if !metadata.is_dir() {
        return Err(PipelineError::NotADirectory(path.to_path_buf()));
    }
    std::fs::canonicalize(path).map_err(|source| PipelineError::Resolve {
        path: path.to_path_buf(),
        source,
    })
}

/// The scanners named in `names`, in registry order; every scanner when `names` is empty.
///
/// # Errors
///
/// [`PipelineError::UnknownTool`] for a name that is not a scanner.
pub fn select(names: &[String]) -> Result<Vec<Box<dyn Scanner>>, PipelineError> {
    if names.is_empty() {
        return Ok(scanners::registry());
    }
    let known = scanners::names().join(", ");
    for name in names {
        if scanners::by_name(name).is_none() {
            return Err(PipelineError::UnknownTool {
                name: name.clone(),
                known: known.clone(),
            });
        }
    }
    Ok(scanners::registry()
        .into_iter()
        .filter(|s| {
            names
                .iter()
                .any(|n| n.trim().eq_ignore_ascii_case(s.name()))
        })
        .collect())
}

/// Scan `target` with the selected scanners and merge their findings.
///
/// # Errors
///
/// [`PipelineError`] when the target or the tool selection is invalid. A scanner that fails
/// does not stop the run: it is reported as [`ToolStatus::Failed`] in the report.
pub fn scan(
    target: &Path,
    options: &Options,
    deps: &mut Deps<'_>,
) -> Result<Report, PipelineError> {
    let target = resolve_target(target)?;
    let scanners = select(&options.tools)?;
    let mut runs = Vec::with_capacity(scanners.len());
    let mut findings = Vec::new();
    for scanner in &scanners {
        let (run, found) = run_one(scanner.as_ref(), &target, options, deps);
        runs.push(run);
        findings.extend(found);
    }
    let (findings, removed) = if options.dedup {
        let result = dedup::dedup(findings);
        (result.findings, result.removed)
    } else {
        let mut findings = findings;
        dedup::sort(&mut findings);
        (findings, 0)
    };
    Ok(Report::new(
        target,
        crate::timefmt::now_rfc3339(),
        runs,
        findings,
        removed,
    ))
}

fn run_one(
    scanner: &dyn Scanner,
    target: &Path,
    options: &Options,
    deps: &mut Deps<'_>,
) -> (ToolRun, Vec<Finding>) {
    let name = scanner.name();
    let Some(path) = find_in_path(scanner.binary(), deps.path_var) else {
        deps.log(format!("{name}: not installed, skipped"));
        return (skipped(name, None, "not installed"), Vec::new());
    };
    let mut installed = installed_version(scanner, &path, deps.runner);
    match installed {
        Some(v) => deps.log(format!("{name} {v} ({})", path.display())),
        None => deps.log(format!(
            "{name}: cannot read its version ({})",
            path.display()
        )),
    }
    // Online, the latest release is always looked up — `--update never` only decides what
    // happens when the tool is behind.
    if let (Some(http), Some(current)) = (deps.http, installed)
        && let Some(updated) = check_and_update(scanner, &path, current, http, options, deps)
    {
        installed = Some(updated);
    }

    let mut inv = Invocation::new(&path)
        .args(scanner.scan_args(&options.scan))
        .cwd(target)
        .timeout(options.timeout)
        .max_output(options.max_output);
    for (key, value) in scanner.env() {
        inv = inv.env(key, value);
    }
    deps.log(format!("{name}: scanning…"));
    let version = installed.map(|v| v.to_string());
    let output = match deps.runner.run(&inv) {
        Ok(output) => output,
        Err(err) => {
            deps.log(format!("{name}: FAILED: {err:#}"));
            return (failed(name, version, err.to_string(), 0), Vec::new());
        }
    };
    let duration_ms = u64::try_from(output.duration.as_millis()).unwrap_or(u64::MAX);
    match scanner.interpret(&output) {
        Outcome::Completed { findings, warnings } => {
            for warning in warnings {
                deps.log(format!("{name}: {warning}"));
            }
            deps.log(format!(
                "{name}: {} finding(s) in {duration_ms} ms",
                findings.len()
            ));
            let run = ToolRun {
                tool: name.to_owned(),
                version,
                status: ToolStatus::Completed,
                findings: findings.len(),
                duration_ms,
            };
            (run, findings)
        }
        Outcome::Skipped(reason) => {
            deps.log(format!("{name}: skipped: {reason}"));
            (
                ToolRun {
                    duration_ms,
                    ..skipped(name, version, &reason)
                },
                Vec::new(),
            )
        }
        Outcome::Failed(reason) => {
            deps.log(format!("{name}: FAILED: {reason}"));
            (failed(name, version, reason, duration_ms), Vec::new())
        }
    }
}

fn skipped(name: &str, version: Option<String>, reason: &str) -> ToolRun {
    ToolRun {
        tool: name.to_owned(),
        version,
        status: ToolStatus::Skipped {
            reason: reason.to_owned(),
        },
        findings: 0,
        duration_ms: 0,
    }
}

fn failed(name: &str, version: Option<String>, reason: String, duration_ms: u64) -> ToolRun {
    ToolRun {
        tool: name.to_owned(),
        version,
        status: ToolStatus::Failed { reason },
        findings: 0,
        duration_ms,
    }
}

fn installed_version(scanner: &dyn Scanner, path: &Path, runner: &dyn Runner) -> Option<Version> {
    let inv = Invocation::new(path)
        .args(scanner.version_args())
        .timeout(Duration::from_secs(30))
        .max_output(64 * 1024);
    runner
        .run(&inv)
        .ok()
        .and_then(|output| scanner.parse_version(&output))
}

/// Look the latest release up and, policy permitting, update. Returns the version installed
/// after a successful update.
fn check_and_update(
    scanner: &dyn Scanner,
    path: &Path,
    installed: Version,
    http: &dyn Http,
    options: &Options,
    deps: &mut Deps<'_>,
) -> Option<Version> {
    let name = scanner.name();
    let latest = match update::latest_release(http, scanner.github_repo()) {
        Ok(latest) => latest,
        Err(err) => {
            deps.log(format!("{name}: cannot check for updates ({err})"));
            return None;
        }
    };
    if latest <= installed {
        deps.log(format!("{name}: up to date"));
        return None;
    }
    deps.log(format!("{name}: {installed} installed, {latest} available"));
    let ctx = UpdateContext {
        tool: name,
        installed_path: path,
        installed,
        latest,
        path_var: deps.path_var,
    };
    let plan = scanner.update_plan(&ctx);
    if !plan.is_automatic() {
        deps.log(format!("{name}: update by hand: {}", plan.describe()));
        return None;
    }
    let go = match options.update {
        UpdatePolicy::Always => true,
        UpdatePolicy::Never => {
            deps.log(format!(
                "{name}: not updated (--update never); to update: {}",
                plan.describe()
            ));
            return None;
        }
        UpdatePolicy::Ask => deps.prompter.confirm(&format!(
            "Update {name} {installed} → {latest}? ({})",
            plan.describe()
        )),
    };
    if !go {
        deps.log(format!("{name}: update skipped, scanning with {installed}"));
        return None;
    }
    for step in &plan.steps {
        match update::execute(step, http, deps.runner, deps.path_var) {
            Ok(StepResult::Done(detail)) => deps.log(format!("{name}: {detail}")),
            Ok(StepResult::Manual(text)) => {
                deps.log(format!("{name}: {text}"));
                return None;
            }
            Err(err) => {
                deps.log(format!(
                    "{name}: update failed: {err}; scanning with {installed}"
                ));
                return None;
            }
        }
    }
    let now = installed_version(scanner, path, deps.runner);
    match now {
        Some(v) => deps.log(format!("{name}: now {v}")),
        None => deps.log(format!("{name}: updated, version unreadable")),
    }
    now
}

/// One line of `sasteuuuh tools`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolInfo {
    /// Scanner name.
    pub name: &'static str,
    /// What it covers.
    pub purpose: &'static str,
    /// Where it is, when installed.
    pub path: Option<PathBuf>,
    /// Installed version, when readable.
    pub installed: Option<Version>,
    /// Latest release, when looked up.
    pub latest: Option<Version>,
    /// Why `latest` is missing, when it is.
    pub note: Option<String>,
}

/// What is installed and what upstream has, for every scanner.
pub fn inventory(deps: &mut Deps<'_>) -> Vec<ToolInfo> {
    scanners::registry()
        .iter()
        .map(|scanner| {
            let path = find_in_path(scanner.binary(), deps.path_var);
            let installed = path
                .as_deref()
                .and_then(|p| installed_version(scanner.as_ref(), p, deps.runner));
            let (latest, note) = match deps.http {
                None => (None, Some("offline".to_owned())),
                Some(http) => match update::latest_release(http, scanner.github_repo()) {
                    Ok(v) => (Some(v), None),
                    Err(err) => (None, Some(err.to_string())),
                },
            };
            ToolInfo {
                name: scanner.name(),
                purpose: scanner.purpose(),
                path,
                installed,
                latest,
                note,
            }
        })
        .collect()
}

/// Print the inventory, one line per scanner.
///
/// # Errors
///
/// The I/O error of `out`.
pub fn write_inventory(infos: &[ToolInfo], out: &mut impl Write) -> std::io::Result<()> {
    writeln!(
        out,
        "{:<10} {:<10} {:<10} {:<12} PATH / NOTE",
        "TOOL", "INSTALLED", "LATEST", "STATUS"
    )?;
    for info in infos {
        let installed = info
            .installed
            .map_or_else(|| "-".to_owned(), |v| v.to_string());
        let latest = info
            .latest
            .map_or_else(|| "-".to_owned(), |v| v.to_string());
        let status = match (info.path.as_ref(), info.installed, info.latest) {
            (None, _, _) => "missing",
            (Some(_), Some(i), Some(l)) if l > i => "outdated",
            (Some(_), Some(_), Some(_)) => "up to date",
            (Some(_), _, _) => "installed",
        };
        let detail = match (&info.path, &info.note) {
            (Some(path), Some(note)) => format!("{} ({note})", path.display()),
            (Some(path), None) => path.display().to_string(),
            (None, Some(note)) => note.clone(),
            (None, None) => String::new(),
        };
        writeln!(
            out,
            "{:<10} {installed:<10} {latest:<10} {status:<12} {detail}",
            info.name
        )?;
        writeln!(out, "{:<10} {}", "", info.purpose)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::test_support::{FakeRunner, output};
    use crate::exec::{ExecError, Output};
    use crate::prompt::FixedAnswer;
    use crate::update::test_support::FakeHttp;
    use std::ffi::OsString;

    const SEMGREP: &[u8] = include_bytes!("../tests/fixtures/semgrep/report.json");
    const BEARER: &[u8] = include_bytes!("../tests/fixtures/bearer/report.json");
    const LUACHECK: &[u8] = include_bytes!("../tests/fixtures/luacheck/report.txt");

    /// A fake `PATH` holding the named stub binaries.
    fn stub_path(names: &[&str]) -> (tempfile::TempDir, OsString) {
        let dir = tempfile::tempdir().unwrap();
        for name in names {
            std::fs::write(dir.path().join(name), b"stub").unwrap();
        }
        let path_var = std::env::join_paths([dir.path()]).unwrap();
        (dir, path_var)
    }

    fn tool_of(inv: &Invocation) -> String {
        inv.program
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    fn is_version_call(inv: &Invocation) -> bool {
        inv.args
            .first()
            .is_some_and(|a| a == "--version" || a == "version")
    }

    /// Answers version calls and scans with the recorded fixtures.
    // The signature is the runner's: a `Result`, even though this script never fails.
    #[allow(clippy::unnecessary_wraps)]
    fn scripted(inv: &Invocation) -> Result<Output, ExecError> {
        let tool = tool_of(inv);
        if is_version_call(inv) {
            return Ok(match tool.as_str() {
                "semgrep" => output(Some(0), b"1.163.0\n", ""),
                "bearer" => output(Some(0), b"bearer version 2.1.1, build abc\n", ""),
                "luacheck" => output(Some(0), b"Luacheck: 1.2.0\nLua: 5.4\n", ""),
                _ => output(Some(0), b"pipx 1.0.0\n", ""),
            });
        }
        Ok(match tool.as_str() {
            "semgrep" => output(Some(0), SEMGREP, ""),
            "bearer" => output(Some(0), BEARER, ""),
            "luacheck" => output(Some(1), LUACHECK, ""),
            _ => output(Some(0), b"ok\n", ""),
        })
    }

    fn latest_bodies() -> FakeHttp {
        FakeHttp::default()
            .with(
                "https://api.github.com/repos/semgrep/semgrep/releases/latest",
                br#"{"tag_name":"v1.183.0"}"#,
            )
            .with(
                "https://api.github.com/repos/Bearer/bearer/releases/latest",
                br#"{"tag_name":"v2.1.1"}"#,
            )
            .with(
                "https://api.github.com/repos/lunarmodules/luacheck/releases/latest",
                br#"{"tag_name":"v1.2.0"}"#,
            )
    }

    #[test]
    fn scans_every_installed_tool_offline_and_merges_the_findings() {
        let (_dir, path_var) = stub_path(&["semgrep", "bearer", "luacheck"]);
        let target = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new(scripted);
        let mut prompter = FixedAnswer(false);
        let mut log = Vec::new();
        let mut deps = Deps {
            runner: &runner,
            http: None,
            prompter: &mut prompter,
            path_var: Some(&path_var),
            log: &mut log,
        };

        let report = scan(target.path(), &Options::default(), &mut deps).unwrap();

        assert_eq!(report.tools.len(), 3);
        assert!(
            report
                .tools
                .iter()
                .all(|t| t.status == ToolStatus::Completed),
            "{:?}",
            report.tools
        );
        assert_eq!(
            report.tools.iter().map(|t| t.findings).sum::<usize>(),
            9 + 7 + 6
        );
        assert_eq!(report.tools[0].version.as_deref(), Some("1.163.0"));
        assert!(
            report.summary.duplicates_removed >= 1,
            "bearer and semgrep both flag eval on line 7"
        );
        assert_eq!(report.summary.total + report.summary.duplicates_removed, 22);
        assert!(
            report
                .findings
                .iter()
                .any(|f| !f.also_reported_by.is_empty())
        );
        assert_eq!(report.target, target.path().canonicalize().unwrap());

        // Every scan ran in the target with the scanner's own environment, after a version call.
        let calls = runner.calls();
        assert_eq!(calls.len(), 6);
        let scans: Vec<_> = calls.iter().filter(|c| !is_version_call(c)).collect();
        assert!(
            scans
                .iter()
                .all(|c| c.cwd.as_deref() == Some(target.path()))
        );
        assert!(
            scans
                .iter()
                .find(|c| tool_of(c) == "semgrep")
                .unwrap()
                .env
                .iter()
                .any(|(k, _)| k == "SEMGREP_SEND_METRICS")
        );
        let text = String::from_utf8(log).unwrap();
        assert!(text.contains("semgrep 1.163.0"), "{text}");
        assert!(
            !text.contains("available"),
            "offline: no update talk: {text}"
        );
    }

    #[test]
    fn a_missing_tool_is_skipped_and_the_rest_still_runs() {
        let (_dir, path_var) = stub_path(&["luacheck"]);
        let target = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new(scripted);
        let mut prompter = FixedAnswer(false);
        let mut log = Vec::new();
        let mut deps = Deps {
            runner: &runner,
            http: None,
            prompter: &mut prompter,
            path_var: Some(&path_var),
            log: &mut log,
        };
        let report = scan(target.path(), &Options::default(), &mut deps).unwrap();
        assert_eq!(
            report.tools[0].status,
            ToolStatus::Skipped {
                reason: "not installed".into()
            }
        );
        assert_eq!(report.tools[2].status, ToolStatus::Completed);
        assert_eq!(report.summary.total, 6);
    }

    #[test]
    fn tool_selection_filters_and_rejects_unknown_names() {
        let (_dir, path_var) = stub_path(&["semgrep", "bearer", "luacheck"]);
        let target = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new(scripted);
        let mut prompter = FixedAnswer(false);
        let mut log = Vec::new();
        let mut deps = Deps {
            runner: &runner,
            http: None,
            prompter: &mut prompter,
            path_var: Some(&path_var),
            log: &mut log,
        };
        let options = Options {
            tools: vec!["Luacheck".into(), "semgrep".into()],
            ..Options::default()
        };
        let report = scan(target.path(), &options, &mut deps).unwrap();
        let names: Vec<_> = report.tools.iter().map(|t| t.tool.as_str()).collect();
        assert_eq!(
            names,
            vec!["semgrep", "luacheck"],
            "registry order, not request order"
        );

        let options = Options {
            tools: vec!["codeql".into()],
            ..Options::default()
        };
        let err = scan(target.path(), &options, &mut deps).unwrap_err();
        assert!(
            matches!(err, PipelineError::UnknownTool { ref name, .. } if name == "codeql"),
            "{err}"
        );
        assert!(err.to_string().contains("semgrep, bearer, luacheck"));
    }

    #[test]
    fn a_failing_scanner_is_reported_not_fatal() {
        let (_dir, path_var) = stub_path(&["semgrep", "luacheck"]);
        let target = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new(|inv| {
            if tool_of(inv) == "luacheck" && !is_version_call(inv) {
                return Ok(output(Some(4), b"Critical error: bad --formatter", ""));
            }
            if tool_of(inv) == "semgrep" && !is_version_call(inv) {
                return Err(ExecError::Pipe(inv.program.clone()));
            }
            scripted(inv)
        });
        let mut prompter = FixedAnswer(false);
        let mut log = Vec::new();
        let mut deps = Deps {
            runner: &runner,
            http: None,
            prompter: &mut prompter,
            path_var: Some(&path_var),
            log: &mut log,
        };
        let report = scan(target.path(), &Options::default(), &mut deps).unwrap();
        assert!(
            matches!(&report.tools[0].status, ToolStatus::Failed { reason } if reason.contains("capture")),
            "{:?}",
            report.tools[0]
        );
        assert!(
            matches!(&report.tools[2].status, ToolStatus::Failed { reason } if reason.contains("bad --formatter")),
            "{:?}",
            report.tools[2]
        );
        assert!(report.has_failures());
        assert!(report.is_clean());
    }

    #[test]
    fn bearer_without_supported_files_is_skipped() {
        let (_dir, path_var) = stub_path(&["bearer"]);
        let target = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new(|inv| {
            if is_version_call(inv) {
                return scripted(inv);
            }
            Ok(output(
                Some(1),
                b"{}\n",
                "Error: report error: 0 rules found for supported language",
            ))
        });
        let mut prompter = FixedAnswer(false);
        let mut log = Vec::new();
        let mut deps = Deps {
            runner: &runner,
            http: None,
            prompter: &mut prompter,
            path_var: Some(&path_var),
            log: &mut log,
        };
        let report = scan(target.path(), &Options::default(), &mut deps).unwrap();
        assert!(
            matches!(&report.tools[1].status, ToolStatus::Skipped { reason } if reason.contains("no file"))
        );
        assert!(!report.has_failures());
    }

    #[test]
    fn no_dedup_keeps_everything() {
        let (_dir, path_var) = stub_path(&["semgrep", "bearer"]);
        let target = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new(scripted);
        let mut prompter = FixedAnswer(false);
        let mut log = Vec::new();
        let mut deps = Deps {
            runner: &runner,
            http: None,
            prompter: &mut prompter,
            path_var: Some(&path_var),
            log: &mut log,
        };
        let report = scan(
            target.path(),
            &Options {
                dedup: false,
                ..Options::default()
            },
            &mut deps,
        )
        .unwrap();
        assert_eq!(report.summary.duplicates_removed, 0);
        assert_eq!(report.summary.total, 16);
    }

    #[test]
    fn an_outdated_tool_is_updated_only_when_allowed() {
        let (dir, path_var) = stub_path(&["semgrep", "pipx"]);
        let target = tempfile::tempdir().unwrap();
        let http = latest_bodies();

        let run_with = |policy: UpdatePolicy, answer: bool| {
            let runner = FakeRunner::new(scripted);
            let mut prompter = FixedAnswer(answer);
            let mut log = Vec::new();
            let mut deps = Deps {
                runner: &runner,
                http: Some(&http),
                prompter: &mut prompter,
                path_var: Some(&path_var),
                log: &mut log,
            };
            let options = Options {
                tools: vec!["semgrep".into()],
                update: policy,
                ..Options::default()
            };
            scan(target.path(), &options, &mut deps).unwrap();
            let updated = runner
                .calls()
                .iter()
                .any(|c| tool_of(c) == "pipx" && c.args == vec!["upgrade", "semgrep"]);
            (updated, String::from_utf8(log).unwrap())
        };

        let (updated, log) = run_with(UpdatePolicy::Ask, true);
        assert!(updated, "{log}");
        assert!(
            log.contains("1.163.0 installed, 1.183.0 available"),
            "{log}"
        );

        let (updated, log) = run_with(UpdatePolicy::Ask, false);
        assert!(!updated, "{log}");
        assert!(log.contains("update skipped"), "{log}");

        let (updated, _) = run_with(UpdatePolicy::Always, false);
        assert!(updated);

        let (updated, log) = run_with(UpdatePolicy::Never, true);
        assert!(!updated);
        assert!(
            log.contains("1.183.0 available"),
            "never still tells: {log}"
        );
        assert!(log.contains("--update never"), "{log}");
        drop(dir);
    }

    #[test]
    fn an_up_to_date_tool_or_a_failed_lookup_is_only_logged() {
        let (_dir, path_var) = stub_path(&["bearer", "luacheck"]);
        let target = tempfile::tempdir().unwrap();
        let http = FakeHttp::default().with(
            "https://api.github.com/repos/Bearer/bearer/releases/latest",
            br#"{"tag_name":"v2.1.1"}"#,
        );
        let runner = FakeRunner::new(scripted);
        let mut prompter = FixedAnswer(true);
        let mut log = Vec::new();
        let mut deps = Deps {
            runner: &runner,
            http: Some(&http),
            prompter: &mut prompter,
            path_var: Some(&path_var),
            log: &mut log,
        };
        let report = scan(target.path(), &Options::default(), &mut deps).unwrap();
        let text = String::from_utf8(log).unwrap();
        assert!(text.contains("bearer: up to date"), "{text}");
        assert!(
            text.contains("luacheck: cannot check for updates"),
            "{text}"
        );
        assert_eq!(
            report
                .tools
                .iter()
                .filter(|t| t.status == ToolStatus::Completed)
                .count(),
            2
        );
    }

    #[test]
    fn a_failed_update_falls_back_to_the_installed_version() {
        let (_dir, path_var) = stub_path(&["semgrep", "pipx"]);
        let target = tempfile::tempdir().unwrap();
        let http = latest_bodies();
        let runner = FakeRunner::new(|inv| {
            if tool_of(inv) == "pipx" {
                return Ok(output(Some(1), b"", "No module named pipx"));
            }
            scripted(inv)
        });
        let mut prompter = FixedAnswer(true);
        let mut log = Vec::new();
        let mut deps = Deps {
            runner: &runner,
            http: Some(&http),
            prompter: &mut prompter,
            path_var: Some(&path_var),
            log: &mut log,
        };
        let options = Options {
            tools: vec!["semgrep".into()],
            ..Options::default()
        };
        let report = scan(target.path(), &options, &mut deps).unwrap();
        let text = String::from_utf8(log).unwrap();
        assert!(text.contains("update failed"), "{text}");
        assert_eq!(
            report.tools[0].status,
            ToolStatus::Completed,
            "the scan still ran"
        );
        assert_eq!(report.tools[0].version.as_deref(), Some("1.163.0"));
    }

    #[test]
    fn a_manual_only_update_is_printed_not_prompted() {
        let (_dir, path_var) = stub_path(&["luacheck"]);
        let target = tempfile::tempdir().unwrap();
        let http = FakeHttp::default().with(
            "https://api.github.com/repos/lunarmodules/luacheck/releases/latest",
            br#"{"tag_name":"v9.0.0"}"#,
        );
        let runner = FakeRunner::new(scripted);
        let mut prompter = FixedAnswer(true);
        let mut log = Vec::new();
        let mut deps = Deps {
            runner: &runner,
            http: Some(&http),
            prompter: &mut prompter,
            path_var: Some(&path_var),
            log: &mut log,
        };
        scan(target.path(), &Options::default(), &mut deps).unwrap();
        let text = String::from_utf8(log).unwrap();
        assert!(text.contains("update by hand"), "{text}");
        assert!(text.contains("releases/tag/v9.0.0"), "{text}");
        assert_eq!(runner.calls().len(), 2, "version + scan, no update command");
    }

    #[test]
    fn target_errors_are_reported_before_anything_runs() {
        let runner = FakeRunner::new(|_| panic!("nothing must run"));
        let mut prompter = FixedAnswer(false);
        let mut log = Vec::new();
        let mut deps = Deps {
            runner: &runner,
            http: None,
            prompter: &mut prompter,
            path_var: None,
            log: &mut log,
        };
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        assert!(
            matches!(scan(&missing, &Options::default(), &mut deps), Err(PipelineError::Missing(p)) if p == missing)
        );
        let file = dir.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        assert!(matches!(
            scan(&file, &Options::default(), &mut deps),
            Err(PipelineError::NotADirectory(_))
        ));
    }

    #[test]
    fn inventory_reports_installed_latest_and_notes() {
        let (dir, path_var) = stub_path(&["semgrep", "bearer"]);
        let http = latest_bodies();
        let runner = FakeRunner::new(scripted);
        let mut prompter = FixedAnswer(false);
        let mut log = Vec::new();
        let mut deps = Deps {
            runner: &runner,
            http: Some(&http),
            prompter: &mut prompter,
            path_var: Some(&path_var),
            log: &mut log,
        };
        let infos = inventory(&mut deps);
        assert_eq!(infos.len(), 3);
        assert_eq!(
            infos[0].path.as_deref(),
            Some(dir.path().join("semgrep").as_path())
        );
        assert_eq!(infos[0].installed, Some(Version::new(1, 163, 0)));
        assert_eq!(infos[0].latest, Some(Version::new(1, 183, 0)));
        assert_eq!(infos[2].path, None);
        assert_eq!(infos[2].installed, None);
        let mut out = Vec::new();
        write_inventory(&infos, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("semgrep    1.163.0    1.183.0    outdated"),
            "{text}"
        );
        assert!(
            text.contains("bearer     2.1.1      2.1.1      up to date"),
            "{text}"
        );
        assert!(
            text.contains("luacheck   -          1.2.0      missing"),
            "{text}"
        );

        let mut deps = Deps {
            runner: &runner,
            http: None,
            prompter: &mut prompter,
            path_var: Some(&path_var),
            log: &mut log,
        };
        let offline = inventory(&mut deps);
        assert_eq!(offline[0].latest, None);
        assert_eq!(offline[0].note.as_deref(), Some("offline"));
        let mut out = Vec::new();
        write_inventory(&offline, &mut out).unwrap();
        assert!(String::from_utf8(out).unwrap().contains("installed"));
    }
}
