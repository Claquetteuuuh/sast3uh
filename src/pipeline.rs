//! The scan pipeline: locate each scanner, check its version, offer to install or update it
//! through mise, run it, parse its output, merge everything into one report.
//!
//! Every side effect goes through [`Deps`] — the process runner, mise, the prompt, `PATH`,
//! the log — so the whole flow is tested in-process with fakes.

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
use crate::update::{Mise, UpdatePlan};
use crate::version::Version;

/// What to do with a scanner that is missing or behind its latest version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum UpdatePolicy {
    /// Ask on the terminal (no in a non-interactive run).
    Ask,
    /// Install or update without asking.
    Always,
    /// Never touch the machine; only print the mise command that would.
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
    /// Install / update policy.
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
    /// mise, when installed; without it there is no version check, install or update.
    pub mise: Option<Mise>,
    /// `false` means offline: `mise latest` is never run, so nothing is installed or updated.
    pub online: bool,
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
            .field("mise", &self.mise)
            .field("online", &self.online)
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

/// Where a scanner's binary is: the one mise manages first, then `PATH`.
fn locate(scanner: &dyn Scanner, deps: &Deps<'_>) -> Option<PathBuf> {
    deps.mise
        .as_ref()
        .and_then(|mise| mise.which(deps.runner, scanner.binary()))
        .or_else(|| find_in_path(scanner.binary(), deps.path_var))
}

fn run_one(
    scanner: &dyn Scanner,
    target: &Path,
    options: &Options,
    deps: &mut Deps<'_>,
) -> (ToolRun, Vec<Finding>) {
    let name = scanner.name();
    let Some(path) = locate(scanner, deps).or_else(|| offer_install(scanner, options, deps)) else {
        deps.log(format!("{name}: not installed, skipped"));
        return (skipped(name, None, "not installed"), Vec::new());
    };
    let (path, installed) = refresh(scanner, path, options, deps);
    let version = installed.map(|v| v.to_string());

    let mut inv = Invocation::new(&path)
        .args(scanner.scan_args(&options.scan))
        .cwd(target)
        .timeout(options.timeout)
        .max_output(options.max_output);
    for (key, value) in scanner.env() {
        inv = inv.env(key, value);
    }
    deps.log(format!("{name}: scanning…"));
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

/// Read the installed version and, when mise knows a newer one, offer the update. Returns the
/// binary to run and its version afterwards.
fn refresh(
    scanner: &dyn Scanner,
    path: PathBuf,
    options: &Options,
    deps: &mut Deps<'_>,
) -> (PathBuf, Option<Version>) {
    let name = scanner.name();
    let installed = installed_version(scanner, &path, deps.runner);
    match installed {
        Some(v) => deps.log(format!("{name} {v} ({})", path.display())),
        None => deps.log(format!(
            "{name}: cannot read its version ({})",
            path.display()
        )),
    }
    let Some(current) = installed else {
        return (path, None);
    };
    if !offer_update(scanner, current, options, deps) {
        return (path, installed);
    }
    // mise may have switched the global version to a new install directory.
    let path = locate(scanner, deps).unwrap_or(path);
    let now = installed_version(scanner, &path, deps.runner);
    match now {
        Some(v) => deps.log(format!("{name}: now {v} ({})", path.display())),
        None => deps.log(format!("{name}: updated, version unreadable")),
    }
    (path, now.or(installed))
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

/// The mise id to install `scanner` with: what mise already manages, else the adapter's default.
fn mise_id(scanner: &dyn Scanner, mise: &Mise, runner: &dyn Runner) -> String {
    mise.managed_id(runner, scanner.binary())
        .unwrap_or_else(|| scanner.mise_id().to_owned())
}

/// A missing scanner: look its latest version up and, policy permitting, install it. Returns
/// where it ended up.
fn offer_install(scanner: &dyn Scanner, options: &Options, deps: &mut Deps<'_>) -> Option<PathBuf> {
    let name = scanner.name();
    let Some(mise) = deps.mise.clone() else {
        deps.log(format!(
            "{name}: not installed (install mise to let sasteuuuh install it: https://mise.jdx.dev)"
        ));
        return None;
    };
    if !deps.online {
        deps.log(format!("{name}: not installed (offline: not installing)"));
        return None;
    }
    let id = mise_id(scanner, &mise, deps.runner);
    let latest = match mise.latest(deps.runner, &id) {
        Ok(latest) => latest,
        Err(err) => {
            deps.log(format!(
                "{name}: not installed, and mise cannot tell the latest version ({err})"
            ));
            return None;
        }
    };
    let plan = UpdatePlan {
        id,
        version: latest,
    };
    let question = format!(
        "{name} is not installed. Install {latest} with mise? ({})",
        plan.command_line()
    );
    if !decide(options.update, &question, &plan, name, deps) {
        return None;
    }
    match mise.use_global(deps.runner, &plan) {
        Ok(detail) => deps.log(format!("{name}: {detail}")),
        Err(err) => {
            deps.log(format!("{name}: install failed: {err}"));
            return None;
        }
    }
    let located = locate(scanner, deps);
    match &located {
        Some(path) => deps.log(format!("{name}: installed at {}", path.display())),
        None => deps.log(format!(
            "{name}: installed, but not found afterwards (is mise activated in this shell?)"
        )),
    }
    located
}

/// An installed scanner: look its latest version up and, policy permitting, update it. Returns
/// `true` when an update ran.
fn offer_update(
    scanner: &dyn Scanner,
    installed: Version,
    options: &Options,
    deps: &mut Deps<'_>,
) -> bool {
    let name = scanner.name();
    let Some(mise) = deps.mise.clone() else {
        return false;
    };
    if !deps.online {
        return false;
    }
    let id = mise_id(scanner, &mise, deps.runner);
    let latest = match mise.latest(deps.runner, &id) {
        Ok(latest) => latest,
        Err(err) => {
            deps.log(format!("{name}: cannot check for updates ({err})"));
            return false;
        }
    };
    if latest <= installed {
        deps.log(format!("{name}: up to date"));
        return false;
    }
    deps.log(format!("{name}: {installed} installed, {latest} available"));
    let plan = UpdatePlan {
        id,
        version: latest,
    };
    let question = format!(
        "Update {name} {installed} → {latest} with mise? ({})",
        plan.command_line()
    );
    if !decide(options.update, &question, &plan, name, deps) {
        return false;
    }
    match mise.use_global(deps.runner, &plan) {
        Ok(detail) => {
            deps.log(format!("{name}: {detail}"));
            true
        }
        Err(err) => {
            deps.log(format!(
                "{name}: update failed: {err}; scanning with {installed}"
            ));
            false
        }
    }
}

/// Apply the policy to a plan: `true` means run it.
fn decide(
    policy: UpdatePolicy,
    question: &str,
    plan: &UpdatePlan,
    name: &str,
    deps: &mut Deps<'_>,
) -> bool {
    match policy {
        UpdatePolicy::Always => true,
        UpdatePolicy::Never => {
            deps.log(format!(
                "{name}: not touched (--update never); to do it: {}",
                plan.command_line()
            ));
            false
        }
        UpdatePolicy::Ask => {
            if deps.prompter.confirm(question) {
                true
            } else {
                deps.log(format!(
                    "{name}: skipped; to do it later: {}",
                    plan.command_line()
                ));
                false
            }
        }
    }
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
    /// The mise id that installs or updates it.
    pub mise_id: String,
    /// Latest version mise can install, when looked up.
    pub latest: Option<Version>,
    /// Why `latest` is missing, when it is.
    pub note: Option<String>,
}

/// What is installed and what mise has, for every scanner.
pub fn inventory(deps: &mut Deps<'_>) -> Vec<ToolInfo> {
    scanners::registry()
        .iter()
        .map(|scanner| {
            let path = locate(scanner.as_ref(), deps);
            let installed = path
                .as_deref()
                .and_then(|p| installed_version(scanner.as_ref(), p, deps.runner));
            let (mise_id, latest, note) = match (&deps.mise, deps.online) {
                (None, _) => (
                    scanner.mise_id().to_owned(),
                    None,
                    Some("mise not installed".to_owned()),
                ),
                (Some(mise), online) => {
                    let id = mise_id(scanner.as_ref(), mise, deps.runner);
                    if online {
                        match mise.latest(deps.runner, &id) {
                            Ok(v) => (id, Some(v), None),
                            Err(err) => (id, None, Some(err.to_string())),
                        }
                    } else {
                        (id, None, Some("offline".to_owned()))
                    }
                }
            };
            ToolInfo {
                name: scanner.name(),
                purpose: scanner.purpose(),
                path,
                installed,
                mise_id,
                latest,
                note,
            }
        })
        .collect()
}

/// Print the inventory, two lines per scanner.
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
        writeln!(out, "{:<10} {} · mise: {}", "", info.purpose, info.mise_id)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::test_support::{FakeRunner, output};
    use crate::exec::{ExecError, Output};
    use crate::prompt::FixedAnswer;
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

    fn arg(inv: &Invocation, i: usize) -> String {
        inv.args
            .get(i)
            .map(|a| a.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// Scripted mise: nothing managed, latest known for the three tools, `use` succeeds.
    fn mise_script(inv: &Invocation) -> Output {
        match arg(inv, 0).as_str() {
            "which" => output(Some(1), b"", "mise ERROR not a mise bin"),
            "ls" => output(Some(0), b"{}", ""),
            "latest" => {
                let id = arg(inv, 1);
                let version: &[u8] = if id.contains("semgrep") {
                    b"1.183.0\n"
                } else if id.contains("bearer") {
                    b"2.1.1\n"
                } else if id.contains("luacheck") {
                    b"1.2.0\n"
                } else {
                    return output(Some(1), b"", "mise ERROR unknown");
                };
                output(Some(0), version, "")
            }
            "use" => output(
                Some(0),
                format!("mise ~/.config/mise/config.toml tools: {}\n", arg(inv, 2)).as_bytes(),
                "",
            ),
            _ => output(Some(2), b"", "unexpected mise call"),
        }
    }

    /// Answers mise, version calls and scans with the recorded fixtures.
    // The signature is the runner's: a `Result`, even though this script never fails.
    #[allow(clippy::unnecessary_wraps)]
    fn scripted(inv: &Invocation) -> Result<Output, ExecError> {
        let tool = tool_of(inv);
        if tool == "mise" {
            return Ok(mise_script(inv));
        }
        if is_version_call(inv) {
            return Ok(match tool.as_str() {
                "semgrep" => output(Some(0), b"1.163.0\n", ""),
                "bearer" => output(Some(0), b"bearer version 2.1.1, build abc\n", ""),
                "luacheck" => output(Some(0), b"Luacheck: 1.2.0\nLua: 5.4\n", ""),
                _ => output(Some(0), b"0.0.0\n", ""),
            });
        }
        Ok(match tool.as_str() {
            "semgrep" => output(Some(0), SEMGREP, ""),
            "bearer" => output(Some(0), BEARER, ""),
            "luacheck" => output(Some(1), LUACHECK, ""),
            _ => output(Some(0), b"ok\n", ""),
        })
    }

    // `Deps::mise` is an `Option`: the helper hands back exactly what the field takes.
    #[allow(clippy::unnecessary_wraps)]
    fn mise() -> Option<Mise> {
        Some(Mise::at("/fake/mise"))
    }

    fn mise_calls(
        runner: &FakeRunner<impl Fn(&Invocation) -> Result<Output, ExecError>>,
    ) -> Vec<Vec<String>> {
        runner
            .calls()
            .iter()
            .filter(|c| tool_of(c) == "mise")
            .map(|c| {
                c.args
                    .iter()
                    .map(|a| a.to_string_lossy().into_owned())
                    .collect()
            })
            .collect()
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
            mise: None,
            online: false,
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
        assert_eq!(
            report.summary.duplicates_removed, 4,
            "bearer and semgrep agree on four lines"
        );
        assert_eq!(report.summary.total, 18);
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
    fn a_missing_tool_is_skipped_without_mise_and_the_rest_still_runs() {
        let (_dir, path_var) = stub_path(&["luacheck"]);
        let target = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new(scripted);
        let mut prompter = FixedAnswer(true);
        let mut log = Vec::new();
        let mut deps = Deps {
            runner: &runner,
            mise: None,
            online: true,
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
        let text = String::from_utf8(log).unwrap();
        assert!(text.contains("install mise"), "{text}");
    }

    #[test]
    fn mise_managed_binaries_win_over_path() {
        let (dir, path_var) = stub_path(&["semgrep", "managed-semgrep"]);
        let target = tempfile::tempdir().unwrap();
        let managed = dir.path().join("managed-semgrep");
        let managed_text = managed.display().to_string();
        let runner = FakeRunner::new(move |inv| {
            if tool_of(inv) == "mise" && arg(inv, 0) == "which" && arg(inv, 1) == "semgrep" {
                return Ok(output(Some(0), format!("{managed_text}\n").as_bytes(), ""));
            }
            if tool_of(inv) == "managed-semgrep" {
                return Ok(if is_version_call(inv) {
                    output(Some(0), b"1.183.0\n", "")
                } else {
                    output(Some(0), SEMGREP, "")
                });
            }
            scripted(inv)
        });
        let mut prompter = FixedAnswer(false);
        let mut log = Vec::new();
        let mut deps = Deps {
            runner: &runner,
            mise: mise(),
            online: true,
            prompter: &mut prompter,
            path_var: Some(&path_var),
            log: &mut log,
        };
        let options = Options {
            tools: vec!["semgrep".into()],
            ..Options::default()
        };
        let report = scan(target.path(), &options, &mut deps).unwrap();
        assert_eq!(
            report.tools[0].version.as_deref(),
            Some("1.183.0"),
            "the mise one, not PATH's 1.163.0"
        );
        assert!(
            runner
                .calls()
                .iter()
                .any(|c| tool_of(c) == "managed-semgrep" && !is_version_call(c))
        );
        assert!(
            String::from_utf8(log)
                .unwrap()
                .contains("semgrep: up to date")
        );
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
            mise: None,
            online: false,
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
            mise: None,
            online: false,
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
            if is_version_call(inv) || tool_of(inv) == "mise" {
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
            mise: None,
            online: false,
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
            mise: None,
            online: false,
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
    fn an_outdated_tool_is_updated_through_mise_only_when_allowed() {
        let (_dir, path_var) = stub_path(&["semgrep"]);
        let target = tempfile::tempdir().unwrap();

        let run_with = |policy: UpdatePolicy, answer: bool| {
            let runner = FakeRunner::new(scripted);
            let mut prompter = FixedAnswer(answer);
            let mut log = Vec::new();
            let mut deps = Deps {
                runner: &runner,
                mise: mise(),
                online: true,
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
            let used = mise_calls(&runner)
                .into_iter()
                .any(|c| c == ["use", "-g", "semgrep@1.183.0"]);
            (used, String::from_utf8(log).unwrap())
        };

        let (updated, log) = run_with(UpdatePolicy::Ask, true);
        assert!(updated, "{log}");
        assert!(
            log.contains("1.163.0 installed, 1.183.0 available"),
            "{log}"
        );
        assert!(log.contains("tools: semgrep@1.183.0"), "{log}");

        let (updated, log) = run_with(UpdatePolicy::Ask, false);
        assert!(!updated, "{log}");
        assert!(
            log.contains("skipped; to do it later: mise use -g semgrep@1.183.0"),
            "{log}"
        );

        let (updated, _) = run_with(UpdatePolicy::Always, false);
        assert!(updated);

        let (updated, log) = run_with(UpdatePolicy::Never, true);
        assert!(!updated);
        assert!(
            log.contains("1.183.0 available"),
            "never still tells: {log}"
        );
        assert!(log.contains("--update never"), "{log}");
    }

    #[test]
    fn an_update_uses_the_id_mise_already_manages() {
        let (_dir, path_var) = stub_path(&["semgrep"]);
        let target = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new(|inv| {
            if tool_of(inv) == "mise" && arg(inv, 0) == "ls" {
                return Ok(output(
                    Some(0),
                    br#"{"pipx:semgrep":[{"version":"1.163.0","installed":true}]}"#,
                    "",
                ));
            }
            scripted(inv)
        });
        let mut prompter = FixedAnswer(true);
        let mut log = Vec::new();
        let mut deps = Deps {
            runner: &runner,
            mise: mise(),
            online: true,
            prompter: &mut prompter,
            path_var: Some(&path_var),
            log: &mut log,
        };
        let options = Options {
            tools: vec!["semgrep".into()],
            ..Options::default()
        };
        scan(target.path(), &options, &mut deps).unwrap();
        let calls = mise_calls(&runner);
        assert!(
            calls.contains(&vec!["latest".to_owned(), "pipx:semgrep".to_owned()]),
            "{calls:?}"
        );
        assert!(
            calls.contains(&vec![
                "use".to_owned(),
                "-g".to_owned(),
                "pipx:semgrep@1.183.0".to_owned()
            ]),
            "{calls:?}"
        );
    }

    #[test]
    fn a_missing_tool_is_installed_through_mise_then_scanned() {
        let (dir, path_var) = stub_path(&["luacheck-from-mise"]);
        let target = tempfile::tempdir().unwrap();
        let installed = dir.path().join("luacheck-from-mise");
        let installed_text = installed.display().to_string();
        let used = std::cell::Cell::new(false);
        let runner = FakeRunner::new(|inv| {
            if tool_of(inv) == "mise" && arg(inv, 0) == "which" && arg(inv, 1) == "luacheck" {
                // Only resolvable once `mise use` ran.
                return Ok(if used.get() {
                    output(Some(0), format!("{installed_text}\n").as_bytes(), "")
                } else {
                    output(Some(1), b"", "mise ERROR luacheck is not a mise bin")
                });
            }
            if tool_of(inv) == "mise" && arg(inv, 0) == "use" {
                used.set(true);
            }
            if tool_of(inv) == "luacheck-from-mise" {
                return Ok(if is_version_call(inv) {
                    output(Some(0), b"Luacheck: 1.2.0\n", "")
                } else {
                    output(Some(1), LUACHECK, "")
                });
            }
            scripted(inv)
        });
        let mut prompter = FixedAnswer(true);
        let mut log = Vec::new();
        let mut deps = Deps {
            runner: &runner,
            mise: mise(),
            online: true,
            prompter: &mut prompter,
            path_var: Some(&path_var),
            log: &mut log,
        };
        let options = Options {
            tools: vec!["luacheck".into()],
            ..Options::default()
        };
        let report = scan(target.path(), &options, &mut deps).unwrap();
        assert_eq!(
            report.tools[0].status,
            ToolStatus::Completed,
            "{:?}",
            report.tools[0]
        );
        assert_eq!(report.tools[0].findings, 6);
        let calls = mise_calls(&runner);
        assert!(
            calls.contains(&vec![
                "use".to_owned(),
                "-g".to_owned(),
                "ubi:lunarmodules/luacheck@1.2.0".to_owned()
            ]),
            "{calls:?}"
        );
        let text = String::from_utf8(log).unwrap();
        assert!(text.contains("luacheck: installed at"), "{text}");
    }

    #[test]
    fn a_missing_tool_is_only_announced_when_declined_offline_or_never() {
        let (_dir, path_var) = stub_path(&[]);
        let target = tempfile::tempdir().unwrap();
        for (online, policy, answer, expect) in [
            (
                true,
                UpdatePolicy::Ask,
                false,
                "skipped; to do it later: mise use -g aqua:Bearer/bearer@2.1.1",
            ),
            (
                true,
                UpdatePolicy::Never,
                true,
                "not touched (--update never)",
            ),
            (false, UpdatePolicy::Always, true, "offline: not installing"),
        ] {
            let runner = FakeRunner::new(scripted);
            let mut prompter = FixedAnswer(answer);
            let mut log = Vec::new();
            let mut deps = Deps {
                runner: &runner,
                mise: mise(),
                online,
                prompter: &mut prompter,
                path_var: Some(&path_var),
                log: &mut log,
            };
            let options = Options {
                tools: vec!["bearer".into()],
                update: policy,
                ..Options::default()
            };
            let report = scan(target.path(), &options, &mut deps).unwrap();
            assert_eq!(
                report.tools[0].status,
                ToolStatus::Skipped {
                    reason: "not installed".into()
                }
            );
            assert!(
                mise_calls(&runner).iter().all(|c| c[0] != "use"),
                "{policy:?}: nothing installed"
            );
            let text = String::from_utf8(log).unwrap();
            assert!(text.contains(expect), "{policy:?} online={online}: {text}");
        }
    }

    #[test]
    fn a_failed_update_or_install_falls_back_gracefully() {
        let (_dir, path_var) = stub_path(&["semgrep"]);
        let target = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new(|inv| {
            if tool_of(inv) == "mise" && arg(inv, 0) == "use" {
                return Ok(output(Some(1), b"", "mise ERROR failed to install"));
            }
            scripted(inv)
        });
        let mut prompter = FixedAnswer(true);
        let mut log = Vec::new();
        let mut deps = Deps {
            runner: &runner,
            mise: mise(),
            online: true,
            prompter: &mut prompter,
            path_var: Some(&path_var),
            log: &mut log,
        };
        let options = Options {
            tools: vec!["semgrep".into(), "bearer".into()],
            update: UpdatePolicy::Always,
            ..Options::default()
        };
        let report = scan(target.path(), &options, &mut deps).unwrap();
        let text = String::from_utf8(log).unwrap();
        assert!(text.contains("semgrep: update failed"), "{text}");
        assert!(text.contains("bearer: install failed"), "{text}");
        assert_eq!(
            report.tools[0].status,
            ToolStatus::Completed,
            "the scan still ran"
        );
        assert_eq!(report.tools[0].version.as_deref(), Some("1.163.0"));
        assert_eq!(
            report.tools[1].status,
            ToolStatus::Skipped {
                reason: "not installed".into()
            }
        );
    }

    #[test]
    fn a_failed_latest_lookup_is_only_logged() {
        let (_dir, path_var) = stub_path(&["luacheck"]);
        let target = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new(|inv| {
            if tool_of(inv) == "mise" && arg(inv, 0) == "latest" {
                return Ok(output(Some(1), b"", "mise ERROR network down"));
            }
            scripted(inv)
        });
        let mut prompter = FixedAnswer(true);
        let mut log = Vec::new();
        let mut deps = Deps {
            runner: &runner,
            mise: mise(),
            online: true,
            prompter: &mut prompter,
            path_var: Some(&path_var),
            log: &mut log,
        };
        let options = Options {
            tools: vec!["luacheck".into(), "bearer".into()],
            ..Options::default()
        };
        let report = scan(target.path(), &options, &mut deps).unwrap();
        let text = String::from_utf8(log).unwrap();
        assert!(
            text.contains("luacheck: cannot check for updates"),
            "{text}"
        );
        assert!(
            text.contains("bearer: not installed, and mise cannot tell"),
            "{text}"
        );
        assert_eq!(report.tools[1].status, ToolStatus::Completed);
    }

    #[test]
    fn target_errors_are_reported_before_anything_runs() {
        let runner = FakeRunner::new(|_| panic!("nothing must run"));
        let mut prompter = FixedAnswer(false);
        let mut log = Vec::new();
        let mut deps = Deps {
            runner: &runner,
            mise: None,
            online: false,
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
    fn inventory_reports_installed_latest_ids_and_notes() {
        let (dir, path_var) = stub_path(&["semgrep", "bearer"]);
        let runner = FakeRunner::new(scripted);
        let mut prompter = FixedAnswer(false);
        let mut log = Vec::new();
        let mut deps = Deps {
            runner: &runner,
            mise: mise(),
            online: true,
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
        assert_eq!(infos[0].mise_id, "semgrep");
        assert_eq!(infos[2].path, None);
        assert_eq!(infos[2].installed, None);
        assert_eq!(infos[2].mise_id, "ubi:lunarmodules/luacheck");
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
        assert!(text.contains("mise: aqua:Bearer/bearer"), "{text}");

        let mut deps = Deps {
            runner: &runner,
            mise: mise(),
            online: false,
            prompter: &mut prompter,
            path_var: Some(&path_var),
            log: &mut log,
        };
        let offline = inventory(&mut deps);
        assert_eq!(offline[0].latest, None);
        assert_eq!(offline[0].note.as_deref(), Some("offline"));

        let mut deps = Deps {
            runner: &runner,
            mise: None,
            online: true,
            prompter: &mut prompter,
            path_var: Some(&path_var),
            log: &mut log,
        };
        let no_mise = inventory(&mut deps);
        assert_eq!(no_mise[0].note.as_deref(), Some("mise not installed"));
        let mut out = Vec::new();
        write_inventory(&no_mise, &mut out).unwrap();
        assert!(String::from_utf8(out).unwrap().contains("installed    "));
    }
}
