//! The scan pipeline: locate each scanner, check its version, offer to install or update it
//! through mise, run it, parse its output, merge everything into one report.
//!
//! Every side effect goes through [`Deps`] — the process runner, mise, the prompt, `PATH`,
//! the log — so the whole flow is tested in-process with fakes.

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::dedup;
use crate::exec::{DEFAULT_MAX_OUTPUT, DEFAULT_TIMEOUT, Invocation, Runner};
use crate::model::{Finding, Report, ToolRun, ToolStatus};
use crate::prompt::Prompter;
use crate::scanners::Context;
use crate::scanners::{self, Outcome, ScanOptions, Scanner};
use crate::sweep::{self, Suppressions};
use crate::tools::find_in_path;
use crate::triage::{self, Triage};
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
    /// Echo each scanner's standard error to this process's as it runs, with a heartbeat
    /// when the tool is silent; for a terminal. The scanners then show their own progress.
    pub live: bool,
    /// Sweep the target for comment markers (TODO, FIXME…) after the scanners.
    pub comments: bool,
    /// What to do with the inline comments that silence a scanner.
    pub suppressions: Suppressions,
    /// What is set aside (confidence floor, corroboration, baseline, ignore file).
    pub triage: Triage,
}

/// Silence after which a live run prints a `still running` line.
pub const HEARTBEAT: Duration = Duration::from_secs(15);

impl Default for Options {
    fn default() -> Self {
        Options {
            tools: Vec::new(),
            scan: ScanOptions::default(),
            timeout: DEFAULT_TIMEOUT,
            max_output: DEFAULT_MAX_OUTPUT,
            update: UpdatePolicy::Ask,
            dedup: true,
            live: false,
            comments: false,
            suppressions: Suppressions::Honour,
            triage: Triage::default(),
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
    let mut options = options.clone();
    options.scan.detected = crate::detect::detect(&target, crate::detect::DEFAULT_MAX_FILES);
    options.scan.offline = !deps.online;
    options.scan.live = options.live;
    options.scan.suppressions = options.suppressions;

    deps.log(format!(
        "target: {} — {}",
        target.display(),
        options.scan.detected.summary()
    ));
    let mut runs = Vec::with_capacity(scanners.len());
    let mut findings = Vec::new();
    for scanner in &scanners {
        let (run, found) = run_one(scanner.as_ref(), &target, &options, deps);
        runs.push(run);
        findings.extend(found);
    }
    let report_suppressions = options.suppressions != Suppressions::Honour;
    if options.comments || report_suppressions {
        for (run, found) in sweep_runs(&target, options.comments, report_suppressions, deps) {
            runs.push(run);
            findings.extend(found);
        }
    }

    let (mut findings, removed) = if options.dedup {
        let result = dedup::dedup(findings);
        (result.findings, result.removed)
    } else {
        let mut findings = findings;
        dedup::sort(&mut findings);
        (findings, 0)
    };
    let mut triage = options.triage.clone();
    triage.states_confidence = scanners
        .iter()
        .filter(|s| s.states_confidence())
        .map(|s| s.name().to_owned())
        .collect();
    triage::apply(&mut findings, &triage);
    let filtered = findings.iter().filter(|f| f.filtered.is_some()).count();
    if filtered > 0 {
        deps.log(format!(
            "{filtered} finding(s) set aside by the triage (still in the report, out of the counts)"
        ));
    }
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

    if let Some(plan) = scanner.plan(&options.scan) {
        deps.log(format!("{name}: {plan}"));
    }
    deps.log(format!("{name}: scanning…"));
    let inherited = inherited(scanner.inherit_env());
    let (outcome, elapsed) = {
        let mut ctx = Context::new(
            name,
            path,
            target,
            &options.scan,
            deps.runner,
            &mut *deps.log,
        );
        ctx.timeout = options.timeout;
        ctx.max_output = options.max_output;
        ctx.path = Some(child_path(&ctx.program, deps.path_var));
        ctx.inherited = inherited;
        ctx.scratch_root = scratch_root();
        if options.live {
            ctx.live = Some(Arc::new(Mutex::new(std::io::stderr())));
            ctx.heartbeat = Some(HEARTBEAT);
        }
        let outcome = scanner.execute(&mut ctx);
        (outcome, ctx.elapsed)
    };
    let duration_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    match outcome {
        Outcome::Completed(parsed) => {
            for warning in &parsed.warnings {
                deps.log(format!("{name}: {warning}"));
            }
            if !parsed.diagnostics.is_empty() {
                deps.log(format!(
                    "{name}: {} diagnostic(s) reported by the tool",
                    parsed.diagnostics.len()
                ));
            }
            if !parsed.skipped_paths.is_empty() {
                deps.log(format!(
                    "{name}: {} path(s) skipped by the tool",
                    parsed.skipped_paths.len()
                ));
            }
            deps.log(format!(
                "{name}: {} finding(s) in {duration_ms} ms",
                parsed.findings.len()
            ));
            let mut run = ToolRun::new(name, version, ToolStatus::Completed);
            run.findings = parsed.findings.len();
            run.duration_ms = duration_ms;
            run.scanned_files = parsed.scanned_files;
            run.skipped_paths = parsed.skipped_paths;
            run.diagnostics = parsed.diagnostics;
            (run, parsed.findings)
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
    let installed = installed_version(scanner, &path, deps.runner, deps.path_var);
    match &installed {
        Ok(v) => deps.log(format!("{name} {v} ({})", path.display())),
        Err(reason) => deps.log(format!(
            "{name}: cannot read its version ({}): {reason}",
            path.display()
        )),
    }
    let Ok(current) = installed else {
        return (path, None);
    };
    if !offer_update(scanner, current, options, deps) {
        return (path, Some(current));
    }
    // mise may have switched the global version to a new install directory.
    let path = locate(scanner, deps).unwrap_or(path);
    let now = installed_version(scanner, &path, deps.runner, deps.path_var).ok();
    match now {
        Some(v) => deps.log(format!("{name}: now {v} ({})", path.display())),
        None => deps.log(format!("{name}: updated, version unreadable")),
    }
    (path, now.or(Some(current)))
}

/// sast3uh's own passes over the target (one walk for both), reported like scanners.
fn sweep_runs(
    target: &Path,
    comments: bool,
    suppressions: bool,
    deps: &mut Deps<'_>,
) -> Vec<(ToolRun, Vec<Finding>)> {
    let wanted: Vec<&str> = [
        comments.then_some(sweep::COMMENTS),
        suppressions.then_some(sweep::SUPPRESSIONS),
    ]
    .into_iter()
    .flatten()
    .collect();
    deps.log(format!("{}: sweeping…", wanted.join(" + ")));
    let started = std::time::Instant::now();
    let (found_comments, found_suppressions) = sweep::run(
        target,
        crate::detect::DEFAULT_MAX_FILES,
        comments,
        suppressions,
    );
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mut out = Vec::new();
    for (name, swept, wanted) in [
        (sweep::COMMENTS, found_comments, comments),
        (sweep::SUPPRESSIONS, found_suppressions, suppressions),
    ] {
        if !wanted {
            continue;
        }
        if swept.truncated {
            deps.log(format!("{name}: stopped at the file cap"));
        }
        deps.log(format!(
            "{name}: {} finding(s) in {} file(s), {duration_ms} ms",
            swept.findings.len(),
            swept.scanned_files
        ));
        let mut run = ToolRun::new(
            name,
            Some(env!("CARGO_PKG_VERSION").to_owned()),
            ToolStatus::Completed,
        );
        run.findings = swept.findings.len();
        run.duration_ms = duration_ms;
        run.scanned_files = Some(swept.scanned_files);
        run.skipped_paths = swept.skipped_paths;
        if swept.truncated {
            run.diagnostics.push(crate::model::Diagnostic {
                level: "warning".to_owned(),
                rule_id: None,
                path: None,
                message: "the walk stopped at the file cap".to_owned(),
            });
        }
        out.push((run, swept.findings));
    }
    out
}

/// The parent-environment variables a scanner asked for, those that are set.
fn inherited(names: &[&str]) -> Vec<(OsString, OsString)> {
    names
        .iter()
        .filter_map(|name| std::env::var_os(name).map(|value| (OsString::from(name), value)))
        .collect()
}

/// Where scanners keep intermediate files: the user's cache directory (`$XDG_CACHE_HOME` or
/// `~/.cache`, under `sast3uh`), a real disk where `/tmp` may be memory; `None` (the system
/// temporary directory) when neither is known.
fn scratch_root() -> Option<PathBuf> {
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    Some(cache.join("sast3uh"))
}

fn skipped(name: &str, version: Option<String>, reason: &str) -> ToolRun {
    ToolRun::new(
        name,
        version,
        ToolStatus::Skipped {
            reason: reason.to_owned(),
        },
    )
}

fn failed(name: &str, version: Option<String>, reason: String, duration_ms: u64) -> ToolRun {
    ToolRun {
        duration_ms,
        ..ToolRun::new(name, version, ToolStatus::Failed { reason })
    }
}

/// The version the binary at `path` reports, read only from a successful version command:
/// a failing one (a broken install printing mise's own error, say) must not pass for a
/// version. `path_var` is the `PATH` the scanner gets (see [`child_path`]).
fn installed_version(
    scanner: &dyn Scanner,
    path: &Path,
    runner: &dyn Runner,
    path_var: Option<&OsStr>,
) -> Result<Version, String> {
    let inv = Invocation::new(path)
        .args(scanner.version_args())
        .env("PATH", child_path(path, path_var))
        .timeout(Duration::from_secs(30))
        .max_output(64 * 1024);
    let output = runner.run(&inv).map_err(|e| e.to_string())?;
    if !output.success() {
        return Err(scanners::failure_reason_pub(&output));
    }
    scanner
        .parse_version(&output)
        .ok_or_else(|| "no version in its output".to_owned())
}

/// The `PATH` a scanner runs with: its own directory first, then the user's. A tool that
/// execs a sibling binary (Semgrep's `osemgrep`) then finds the real file, not a mise shim
/// that may not resolve outside the user's shell.
fn child_path(program: &Path, path_var: Option<&OsStr>) -> OsString {
    let own = program.parent().map(Path::to_path_buf);
    let rest = path_var.map(std::env::split_paths).into_iter().flatten();
    let all: Vec<PathBuf> = own.into_iter().chain(rest).fold(Vec::new(), |mut acc, p| {
        if !acc.contains(&p) {
            acc.push(p);
        }
        acc
    });
    std::env::join_paths(all)
        .unwrap_or_else(|_| path_var.map(OsStr::to_os_string).unwrap_or_default())
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
            "{name}: not installed (install mise to let sast3uh install it: https://mise.jdx.dev)"
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

/// One line of `sast3uh tools`.
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
            let installed = path.as_deref().and_then(|p| {
                installed_version(scanner.as_ref(), p, deps.runner, deps.path_var).ok()
            });
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
    const TRIVY: &[u8] = include_bytes!("../tests/fixtures/trivy/report.json");
    const PLUMBER: &[u8] = include_bytes!("../tests/fixtures/plumber/report.json");

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
                } else if id.contains("trivy") {
                    b"0.76.1\n"
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
                "trivy" => output(
                    Some(0),
                    b"Version: 0.76.1\nVulnerability DB:\n  Version: 2\n",
                    "",
                ),
                _ => output(Some(0), b"0.0.0\n", ""),
            });
        }
        Ok(match tool.as_str() {
            "semgrep" => output(Some(0), SEMGREP, ""),
            "bearer" => output(Some(0), BEARER, ""),
            "luacheck" => output(Some(1), LUACHECK, ""),
            "trivy" => output(Some(0), TRIVY, ""),
            _ => output(Some(0), b"ok\n", ""),
        })
    }

    #[test]
    fn live_mode_hands_every_scan_a_stderr_echo_and_a_heartbeat_and_drops_quiet_flags() {
        let (_dir, path_var) = stub_path(&["semgrep", "bearer", "trivy"]);
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
            live: true,
            ..Options::default()
        };
        scan(target.path(), &options, &mut deps).unwrap();
        let scans: Vec<Invocation> = runner
            .calls()
            .into_iter()
            .filter(|inv| !is_version_call(inv))
            .collect();
        assert_eq!(scans.len(), 3);
        for inv in &scans {
            assert!(inv.live.is_some(), "{inv:?}");
            assert_eq!(inv.heartbeat, Some(HEARTBEAT));
            assert_eq!(inv.label, tool_of(inv));
            assert!(
                !inv.args
                    .iter()
                    .any(|a| a == "--quiet" || a == "--hide-progress-bar" || a == "--no-progress"),
                "{inv:?}"
            );
        }
        let versions: Vec<Invocation> =
            runner.calls().into_iter().filter(is_version_call).collect();
        assert!(
            versions.iter().all(|inv| inv.live.is_none()),
            "only scans echo"
        );

        let runner = FakeRunner::new(scripted);
        let mut deps = Deps {
            runner: &runner,
            mise: None,
            online: false,
            prompter: &mut prompter,
            path_var: Some(&path_var),
            log: &mut log,
        };
        scan(target.path(), &Options::default(), &mut deps).unwrap();
        for inv in runner.calls().iter().filter(|inv| !is_version_call(inv)) {
            assert!(inv.live.is_none());
            assert!(inv.args.iter().any(|a| a == "--quiet"), "{inv:?}");
        }
    }

    #[test]
    fn only_plumber_may_inherit_provider_tokens_and_nothing_else_of_the_environment() {
        let (_dir, path_var) = stub_path(&["semgrep", "plumber"]);
        let target = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(target.path().join(".github/workflows")).unwrap();
        std::fs::write(
            target.path().join(".github/workflows/ci.yml"),
            "on: push
",
        )
        .unwrap();
        let runner = FakeRunner::new(|inv: &Invocation| {
            if tool_of(inv) == "plumber" && !is_version_call(inv) {
                let at = inv.args.iter().position(|a| a == "--output").unwrap();
                std::fs::write(&inv.args[at + 1], PLUMBER).unwrap();
                return Ok(output(Some(0), b"", ""));
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
        let plumber = report.tools.iter().find(|t| t.tool == "plumber").unwrap();
        assert_eq!(plumber.status, ToolStatus::Completed, "{plumber:?}");
        assert_eq!(plumber.findings, 22);
        let tokens = scanners::plumber::TOKENS;
        for inv in runner.calls() {
            let keys: Vec<String> = inv
                .env
                .iter()
                .map(|(k, _)| k.to_string_lossy().into_owned())
                .filter(|k| k != "PATH")
                .collect();
            if tool_of(&inv) == "plumber" {
                assert!(
                    keys.iter()
                        .all(|k| k == "NO_COLOR" || tokens.contains(&k.as_str())),
                    "{keys:?}"
                );
            } else {
                assert!(
                    !keys.iter().any(|k| tokens.contains(&k.as_str())),
                    "{keys:?}"
                );
            }
        }
        let scan_inv = runner
            .calls()
            .into_iter()
            .find(|inv| tool_of(inv) == "plumber" && !is_version_call(inv))
            .unwrap();
        let has_token = tokens.iter().any(|t| std::env::var_os(t).is_some());
        assert_eq!(
            !scan_inv.args.iter().any(|a| a == "--skip-controls"),
            has_token,
            "the branch-protection control runs only with a token: {scan_inv:?}"
        );
        let out: String = scan_inv
            .args
            .iter()
            .skip_while(|a| *a != "--output")
            .nth(1)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(
            !out.starts_with(&target.path().to_string_lossy().into_owned()),
            "report never in the target: {out}"
        );
        assert!(!Path::new(&out).exists(), "scratch deleted after the run");
    }

    #[test]
    fn sweeps_run_after_the_scanners_only_when_asked() {
        let (_dir, path_var) = stub_path(&["luacheck"]);
        let target = tempfile::tempdir().unwrap();
        std::fs::write(
            target.path().join("a.lua"),
            "local x = 1 -- luacheck: ignore 211\n-- TODO: tidy\n",
        )
        .unwrap();
        std::fs::write(target.path().join("b.py"), "eval(x)  # nosemgrep\n").unwrap();
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
            tools: vec!["luacheck".into()],
            comments: true,
            suppressions: Suppressions::Report,
            ..Options::default()
        };
        let report = scan(target.path(), &options, &mut deps).unwrap();
        let names: Vec<&str> = report.tools.iter().map(|t| t.tool.as_str()).collect();
        assert_eq!(names, vec!["luacheck", "comments", "suppressions"]);
        assert_eq!(report.tools[1].findings, 1);
        assert_eq!(report.tools[1].scanned_files, Some(2));
        assert_eq!(
            report.tools[1].version.as_deref(),
            Some(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(report.tools[1].status, ToolStatus::Completed);
        assert_eq!(report.tools[2].findings, 2);
        assert!(report.findings.iter().any(|f| f.tool == "comments"
            && f.rule_id == "todo"
            && f.path == Path::new("a.lua")
            && f.line == Some(2)));
        assert!(report.findings.iter().any(|f| f.tool == "suppressions"
            && f.rule_id == "semgrep"
            && f.path == Path::new("b.py")));
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.tool == "suppressions" && f.rule_id == "luacheck")
        );

        let plain = Options {
            tools: vec!["luacheck".into()],
            ..Options::default()
        };
        let report = scan(target.path(), &plain, &mut deps).unwrap();
        assert_eq!(report.tools.len(), 1, "no sweep by default");

        let ignoring = Options {
            tools: vec!["luacheck".into()],
            suppressions: Suppressions::Ignore,
            ..Options::default()
        };
        let report = scan(target.path(), &ignoring, &mut deps).unwrap();
        let names: Vec<&str> = report.tools.iter().map(|t| t.tool.as_str()).collect();
        assert_eq!(
            names,
            vec!["luacheck", "suppressions"],
            "ignore reports the comments too"
        );
    }

    #[test]
    fn a_scanner_runs_with_its_own_directory_first_on_path() {
        let joined =
            std::env::join_paths([Path::new("/usr/bin"), Path::new("/opt/tool/bin")]).unwrap();
        let path = child_path(Path::new("/opt/tool/bin/tool"), Some(&joined));
        let parts: Vec<PathBuf> = std::env::split_paths(&path).collect();
        assert_eq!(
            parts,
            vec![PathBuf::from("/opt/tool/bin"), PathBuf::from("/usr/bin")],
            "own directory first, once"
        );
        let alone = child_path(Path::new("/opt/tool/bin/tool"), None);
        assert_eq!(
            std::env::split_paths(&alone).collect::<Vec<_>>(),
            vec![PathBuf::from("/opt/tool/bin")]
        );

        let (dir, path_var) = stub_path(&["semgrep"]);
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
        scan(target.path(), &Options::default(), &mut deps).unwrap();
        for inv in runner.calls() {
            let path = inv
                .env
                .iter()
                .find(|(k, _)| k == "PATH")
                .map(|(_, v)| v.clone())
                .expect("every invocation sets PATH");
            let first = std::env::split_paths(&path).next().unwrap();
            assert_eq!(first, dir.path(), "{inv:?}");
        }
    }

    #[test]
    fn a_failing_version_command_is_not_a_version() {
        let (_dir, path_var) = stub_path(&["semgrep", "luacheck"]);
        let target = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new(|inv: &Invocation| {
            if tool_of(inv) == "semgrep" && is_version_call(inv) {
                // A dangling mise shim: the error carries mise's own version string.
                return Ok(output(
                    Some(1),
                    b"",
                    "mise ERROR osemgrep is not a valid shim. This likely means you uninstalled a tool\nmise ERROR Version: 2026.10.25 linux-x64 (2026-10-31)\n",
                ));
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
        let semgrep = report.tools.iter().find(|t| t.tool == "semgrep").unwrap();
        assert_eq!(semgrep.version, None, "2026.10.25 is mise's, not Semgrep's");
        assert_eq!(
            semgrep.status,
            ToolStatus::Completed,
            "the scan itself still runs"
        );
        let text = String::from_utf8(log).unwrap();
        assert!(
            text.contains("semgrep: cannot read its version") && text.contains("not a valid shim"),
            "{text}"
        );
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
        let (_dir, path_var) = stub_path(&["semgrep", "bearer", "luacheck", "trivy"]);
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

        assert_eq!(report.tools.len(), 6);
        assert!(
            report
                .tools
                .iter()
                .filter(|t| !matches!(t.tool.as_str(), "codeql" | "plumber"))
                .all(|t| t.status == ToolStatus::Completed),
            "{:?}",
            report.tools
        );
        assert!(
            report
                .tools
                .iter()
                .filter(|t| matches!(t.tool.as_str(), "codeql" | "plumber"))
                .all(|t| matches!(&t.status, ToolStatus::Skipped { reason } if reason == "not installed")),
            "{:?}",
            report.tools
        );
        assert_eq!(
            report.tools.iter().map(|t| t.findings).sum::<usize>(),
            9 + 7 + 6 + 24,
            "trivy: 9 vulnerabilities, 14 misconfigurations, 1 secret"
        );
        assert_eq!(report.tools[0].version.as_deref(), Some("1.163.0"));
        assert_eq!(
            report.summary.duplicates_removed, 4,
            "bearer and semgrep agree on four lines"
        );
        assert_eq!(
            report.summary.total,
            18 + 24 - 1,
            "trivy's files overlap with nobody's; one low-confidence Semgrep finding that no \
             other tool corroborates is set aside"
        );
        assert_eq!(report.summary.filtered, 1);
        assert_eq!(report.findings.len(), 42, "set aside, not dropped");
        let aside = report
            .findings
            .iter()
            .find(|f| f.filtered.is_some())
            .unwrap();
        assert_eq!(aside.tool, "semgrep");
        assert_eq!(
            aside.filtered.as_deref(),
            Some("confidence low below medium")
        );
        assert!(aside.also_reported_by.is_empty());
        assert!(
            report
                .findings
                .iter()
                .filter(|f| !f.also_reported_by.is_empty())
                .all(|f| f.filtered.is_none()),
            "a corroborated finding is never set aside"
        );
        assert_eq!(
            report.tools[0].scanned_files,
            Some(3),
            "semgrep's paths.scanned"
        );
        assert_eq!(
            report.tools[0].diagnostics.len(),
            3,
            "semgrep's rule errors travel into the report"
        );
        assert_eq!(report.tools[1].scanned_files, None);
        assert_eq!(report.tools[2].tool, "trivy");
        assert_eq!(
            report.tools[2].diagnostics.len(),
            3,
            "trivy's check summaries"
        );
        assert_eq!(report.target, target.path().canonicalize().unwrap());

        // Every scan ran in the target with the scanner's own environment, after a version call.
        let calls = runner.calls();
        assert_eq!(calls.len(), 8);
        let scans: Vec<_> = calls.iter().filter(|c| !is_version_call(c)).collect();
        // The target is canonicalised first: on a runner where /tmp is a symlink the two differ.
        let canonical = target.path().canonicalize().unwrap();
        assert!(
            scans
                .iter()
                .all(|c| c.cwd.as_deref() == Some(canonical.as_path())),
            "{scans:?}"
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
    fn semgrep_gets_the_packs_the_target_calls_for() {
        let (_dir, path_var) = stub_path(&["semgrep"]);
        let target = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(target.path().join(".github/workflows")).unwrap();
        std::fs::write(target.path().join(".github/workflows/ci.yml"), b"on: push").unwrap();
        std::fs::write(target.path().join("app.py"), b"print(1)").unwrap();
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
            tools: vec!["semgrep".into()],
            ..Options::default()
        };
        scan(target.path(), &options, &mut deps).unwrap();
        let scan_call = runner
            .calls()
            .into_iter()
            .find(|c| tool_of(c) == "semgrep" && !is_version_call(c))
            .unwrap();
        let args: Vec<String> = scan_call
            .args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for pack in [
            "p/default",
            "p/python",
            "p/django",
            "p/github-actions",
            "p/gitleaks",
        ] {
            assert!(args.contains(&pack.to_owned()), "{pack} missing: {args:?}");
        }
        assert!(!args.contains(&"p/golang".to_owned()));
        let text = String::from_utf8(log).unwrap();
        assert!(
            text.contains("target: ")
                && text.contains("python (1)")
                && text.contains("github-actions"),
            "{text}"
        );
        assert!(
            text.contains("semgrep: ") && text.contains("rule source(s), Exhaustive profile"),
            "{text}"
        );

        // An explicit list wins, whatever the target holds.
        let runner = FakeRunner::new(scripted);
        let mut log = Vec::new();
        let mut deps = Deps {
            runner: &runner,
            mise: None,
            online: false,
            prompter: &mut prompter,
            path_var: Some(&path_var),
            log: &mut log,
        };
        let explicit = Options {
            tools: vec!["semgrep".into()],
            scan: ScanOptions {
                semgrep_configs: Some(vec!["rules.yml".into()]),
                ..ScanOptions::default()
            },
            ..Options::default()
        };
        scan(target.path(), &explicit, &mut deps).unwrap();
        let scan_call = runner
            .calls()
            .into_iter()
            .find(|c| tool_of(c) == "semgrep" && !is_version_call(c))
            .unwrap();
        let args: Vec<String> = scan_call
            .args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args.iter().filter(|a| *a == "--config").count(), 1);
        assert!(args.contains(&"rules.yml".to_owned()));
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
        assert_eq!(
            report.tools[2].status,
            ToolStatus::Skipped {
                reason: "not installed".into()
            },
            "trivy"
        );
        assert_eq!(report.tools[5].status, ToolStatus::Completed, "luacheck");
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
            tools: vec!["gosec".into()],
            ..Options::default()
        };
        let err = scan(target.path(), &options, &mut deps).unwrap_err();
        assert!(
            matches!(err, PipelineError::UnknownTool { ref name, .. } if name == "gosec"),
            "{err}"
        );
        assert!(
            err.to_string()
                .contains("semgrep, bearer, trivy, codeql, plumber, luacheck")
        );
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
            matches!(&report.tools[5].status, ToolStatus::Failed { reason } if reason.contains("bad --formatter")),
            "{:?}",
            report.tools[5]
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
        assert_eq!(report.summary.total, 12);
        assert_eq!(
            report.summary.filtered, 4,
            "the four low-confidence Semgrep findings are set aside, not dropped"
        );
        assert_eq!(report.findings.len(), 16);
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
        assert_eq!(infos.len(), 6);
        assert_eq!(
            infos[0].path.as_deref(),
            Some(dir.path().join("semgrep").as_path())
        );
        assert_eq!(infos[0].installed, Some(Version::new(1, 163, 0)));
        assert_eq!(infos[0].latest, Some(Version::new(1, 183, 0)));
        assert_eq!(infos[0].mise_id, "semgrep");
        assert_eq!(infos[2].mise_id, "trivy");
        assert_eq!(infos[2].latest, Some(Version::new(0, 76, 1)));
        assert_eq!(infos[5].path, None);
        assert_eq!(infos[5].installed, None);
        assert_eq!(infos[5].mise_id, "ubi:lunarmodules/luacheck");
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
