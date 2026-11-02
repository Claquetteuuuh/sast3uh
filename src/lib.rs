//! sasteuuuh — one SAST to run them all.
//!
//! A hardened wrapper that drives several static analysers (Semgrep, Bearer, Luacheck, more
//! to come) over a directory, parses what each one says, removes the duplicates and writes a
//! single report — text, JSON, YAML, XML or HTML — with a single exit code. Before scanning it
//! checks each scanner against its latest release and offers to update it.
//!
//! The crate is a library first: the binary in `main.rs` only calls [`run`], so every behaviour
//! — argument parsing, scanning, rendering, exit codes — is covered by tests that never spawn
//! a real scanner.
//!
//! # Exit codes
//!
//! | code | meaning |
//! |------|---------|
//! | 0    | every scanner ran (or was skipped) and nothing is at or above `--fail-on` |
//! | 1    | at least one finding at or above `--fail-on` |
//! | 2    | the command line could not be parsed (clap's convention) |
//! | 3    | the scan could not run or is incomplete (bad target, a scanner failed, …) |

pub mod cli;
pub mod dedup;
pub mod exec;
pub mod model;
pub mod output;
pub mod pipeline;
pub mod prompt;
pub mod scanners;
pub mod timefmt;
pub mod tools;
pub mod update;
pub mod version;

use std::ffi::OsString;
use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;

use crate::cli::{Cli, Command, ScanArgs};
use crate::exec::RealRunner;
use crate::output::Format;
use crate::pipeline::{Deps, UpdatePolicy};
use crate::prompt::TerminalPrompter;
use crate::scanners::ScanOptions;
use crate::update::{Http, UreqHttp};

/// Nothing at or above the gate.
pub const EXIT_CLEAN: u8 = 0;
/// At least one finding at or above the gate.
pub const EXIT_FINDINGS: u8 = 1;
/// The command line could not be parsed.
pub const EXIT_USAGE: u8 = 2;
/// The scan could not run, or a scanner failed (the report is incomplete).
pub const EXIT_ERROR: u8 = 3;

/// Parse `args` (the full argv, program name included) and run the matching command with the
/// real process runner, HTTP client, terminal prompt and standard streams.
///
/// `--help` and `--version` are handled here: clap reports them as errors that print to
/// stdout and exit 0.
///
/// # Errors
///
/// Returns an error when the command could not run (for example a missing target
/// directory); the caller prints it and exits with [`EXIT_ERROR`].
pub fn run<I, T>(args: I) -> anyhow::Result<ExitCode>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) => {
            err.print().context("writing the usage message")?;
            let code = u8::try_from(err.exit_code()).unwrap_or(EXIT_USAGE);
            return Ok(ExitCode::from(code));
        }
    };
    let offline = match &cli.command {
        Command::Scan(args) => args.offline,
        Command::Tools(args) => args.offline,
    };
    let http = (!offline).then(UreqHttp::new);
    let runner = RealRunner;
    let mut prompter = TerminalPrompter;
    let path_var = std::env::var_os("PATH");
    let mut log = std::io::stderr().lock();
    let mut deps = Deps {
        runner: &runner,
        http: http.as_ref().map(|h| -> &dyn Http { h }),
        prompter: &mut prompter,
        path_var: path_var.as_deref(),
        log: &mut log,
    };
    let mut stdout = std::io::stdout().lock();
    run_with(cli, &mut stdout, &mut deps)
}

/// Run an already-parsed command, writing the report to `out` and talking to the world
/// through `deps`.
///
/// # Errors
///
/// Returns an error when the command could not run or when `out` cannot be written.
pub fn run_with(cli: Cli, out: &mut impl Write, deps: &mut Deps<'_>) -> anyhow::Result<ExitCode> {
    match cli.command {
        Command::Scan(args) => scan(&args, out, deps),
        Command::Tools(_) => {
            let infos = pipeline::inventory(deps);
            pipeline::write_inventory(&infos, out).context("writing the tool inventory")?;
            Ok(ExitCode::from(EXIT_CLEAN))
        }
    }
}

fn scan(args: &ScanArgs, out: &mut impl Write, deps: &mut Deps<'_>) -> anyhow::Result<ExitCode> {
    let format = args
        .format
        .or_else(|| args.output.as_deref().and_then(Format::from_path))
        .unwrap_or(Format::Text);
    let mut scan_options = ScanOptions::default();
    if !args.semgrep_configs.is_empty() {
        scan_options
            .semgrep_configs
            .clone_from(&args.semgrep_configs);
    }
    let options = pipeline::Options {
        tools: args.tools.clone(),
        scan: scan_options,
        timeout: Duration::from_secs(args.timeout.max(1)),
        max_output: exec::DEFAULT_MAX_OUTPUT,
        update: if args.offline {
            UpdatePolicy::Never
        } else {
            args.update
        },
        dedup: !args.no_dedup,
    };

    let report = pipeline::scan(&args.path, &options, deps)
        .with_context(|| format!("scanning {}", args.path.display()))?;
    let bytes = output::render(&report, format).context("rendering the report")?;
    match &args.output {
        Some(path) => {
            output::write_atomically(path, &bytes)
                .with_context(|| format!("writing the report to {}", path.display()))?;
            let _ = writeln!(deps.log, "report written to {}", path.display());
        }
        None => out.write_all(&bytes).context("writing the report")?,
    }

    let code = if report.has_failures() {
        let _ = writeln!(
            deps.log,
            "at least one scanner failed: the report is incomplete"
        );
        EXIT_ERROR
    } else if report.has_findings_at_or_above(args.fail_on) {
        EXIT_FINDINGS
    } else {
        EXIT_CLEAN
    };
    Ok(ExitCode::from(code))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::test_support::{FakeRunner, output};
    use crate::exec::{ExecError, Invocation, Output};
    use crate::prompt::FixedAnswer;

    const LUACHECK: &[u8] = include_bytes!("../tests/fixtures/luacheck/report.txt");

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("valid command line")
    }

    // The signature is the runner's: a `Result`, even though this script never fails.
    #[allow(clippy::unnecessary_wraps)]
    fn luacheck_runner(inv: &Invocation) -> Result<Output, ExecError> {
        if inv.args.first().is_some_and(|a| a == "--version") {
            return Ok(output(Some(0), b"Luacheck: 1.2.0\n", ""));
        }
        Ok(output(Some(1), LUACHECK, ""))
    }

    /// Runs `cli` with a fake `PATH` holding `tools`, offline, answering `no` to prompts.
    fn drive(cli: Cli, tools: &[&str], runner: &dyn exec::Runner) -> (ExitCode, Vec<u8>, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        for tool in tools {
            std::fs::write(dir.path().join(tool), b"stub").expect("stub");
        }
        let path_var = std::env::join_paths([dir.path()]).expect("path");
        let mut prompter = FixedAnswer(false);
        let mut log = Vec::new();
        let mut deps = Deps {
            runner,
            http: None,
            prompter: &mut prompter,
            path_var: Some(&path_var),
            log: &mut log,
        };
        let mut out = Vec::new();
        let code = run_with(cli, &mut out, &mut deps).expect("command runs");
        (code, out, String::from_utf8(log).expect("utf-8 log"))
    }

    #[test]
    fn scan_with_no_installed_tool_is_clean_and_says_so() {
        let target = tempfile::tempdir().expect("tempdir");
        let cli = parse(&[
            "sasteuuuh",
            "scan",
            target.path().to_str().expect("utf-8"),
            "--offline",
        ]);
        let runner = FakeRunner::new(|_| panic!("nothing must run"));
        let (code, out, log) = drive(cli, &[], &runner);
        assert_eq!(code, ExitCode::from(EXIT_CLEAN));
        let text = String::from_utf8(out).expect("utf-8");
        assert!(text.contains("not installed"), "{text}");
        assert!(text.contains("Findings (0 unique"), "{text}");
        assert!(log.contains("semgrep: not installed"), "{log}");
    }

    #[test]
    fn findings_exit_1_unless_the_gate_is_above_them() {
        let target = tempfile::tempdir().expect("tempdir");
        let path = target.path().to_str().expect("utf-8");
        let runner = FakeRunner::new(luacheck_runner);
        let cli = parse(&[
            "sasteuuuh",
            "scan",
            path,
            "--offline",
            "--tools",
            "luacheck",
        ]);
        let (code, _, _) = drive(cli, &["luacheck"], &runner);
        assert_eq!(code, ExitCode::from(EXIT_FINDINGS));
        let cli = parse(&[
            "sasteuuuh",
            "scan",
            path,
            "--offline",
            "--tools",
            "luacheck",
            "--fail-on",
            "medium",
        ]);
        let (code, _, _) = drive(cli, &["luacheck"], &runner);
        assert_eq!(code, ExitCode::from(EXIT_CLEAN), "luacheck's worst is low");
    }

    #[test]
    fn a_failed_scanner_exits_3_with_the_report_still_written() {
        let target = tempfile::tempdir().expect("tempdir");
        let runner = FakeRunner::new(|inv| {
            if inv.args.first().is_some_and(|a| a == "--version") {
                return Ok(output(Some(0), b"Luacheck: 1.2.0\n", ""));
            }
            Ok(output(Some(3), b"", "cannot read src"))
        });
        let cli = parse(&[
            "sasteuuuh",
            "scan",
            target.path().to_str().expect("utf-8"),
            "--offline",
            "-t",
            "luacheck",
            "-f",
            "json",
        ]);
        let (code, out, log) = drive(cli, &["luacheck"], &runner);
        assert_eq!(code, ExitCode::from(EXIT_ERROR));
        let json: serde_json::Value = serde_json::from_slice(&out).expect("json");
        assert_eq!(json["tools"][0]["status"]["state"], "failed");
        assert!(log.contains("incomplete"), "{log}");
    }

    #[test]
    fn the_format_follows_the_flag_then_the_output_extension() {
        let target = tempfile::tempdir().expect("tempdir");
        let path = target.path().to_str().expect("utf-8");
        let runner = FakeRunner::new(luacheck_runner);
        let report_path = target.path().join("report.yml");
        let cli = parse(&[
            "sasteuuuh",
            "scan",
            path,
            "--offline",
            "-t",
            "luacheck",
            "-o",
            report_path.to_str().expect("utf-8"),
        ]);
        let (_, out, log) = drive(cli, &["luacheck"], &runner);
        assert!(out.is_empty(), "nothing on stdout when --output is given");
        assert!(log.contains("report written to"), "{log}");
        let yaml = std::fs::read_to_string(&report_path).expect("report file");
        assert!(yaml.contains("schema_version: 1"), "{yaml}");

        let cli = parse(&[
            "sasteuuuh",
            "scan",
            path,
            "--offline",
            "-t",
            "luacheck",
            "-f",
            "xml",
            "-o",
            report_path.to_str().expect("utf-8"),
        ]);
        drive(cli, &["luacheck"], &runner);
        assert!(
            std::fs::read_to_string(&report_path)
                .expect("report file")
                .starts_with("<?xml"),
            "the flag wins"
        );
    }

    #[test]
    fn scan_of_a_missing_directory_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("nope");
        let cli = parse(&[
            "sasteuuuh",
            "scan",
            missing.to_str().expect("utf-8"),
            "--offline",
        ]);
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
        let mut out = Vec::new();
        let err = run_with(cli, &mut out, &mut deps).expect_err("missing target must fail");
        assert!(format!("{err:#}").contains("does not exist"), "{err:#}");
        assert!(out.is_empty());
    }

    #[test]
    fn an_unknown_tool_is_an_error() {
        let target = tempfile::tempdir().expect("tempdir");
        let cli = parse(&[
            "sasteuuuh",
            "scan",
            target.path().to_str().expect("utf-8"),
            "--offline",
            "-t",
            "codeql",
        ]);
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
        let err = run_with(cli, &mut Vec::new(), &mut deps).expect_err("unknown tool");
        assert!(
            format!("{err:#}").contains("unknown tool `codeql`"),
            "{err:#}"
        );
    }

    #[test]
    fn tools_lists_every_scanner() {
        let cli = parse(&["sasteuuuh", "tools", "--offline"]);
        let runner = FakeRunner::new(luacheck_runner);
        let (code, out, _) = drive(cli, &["luacheck"], &runner);
        assert_eq!(code, ExitCode::from(EXIT_CLEAN));
        let text = String::from_utf8(out).expect("utf-8");
        for name in scanners::names() {
            assert!(
                text.contains(name),
                "{name} missing from inventory:\n{text}"
            );
        }
        assert!(text.contains("luacheck   1.2.0"), "{text}");
        assert!(text.contains("missing"), "{text}");
    }

    #[test]
    fn help_is_not_an_error_and_a_bad_flag_is_a_usage_error() {
        assert_eq!(
            run(["sasteuuuh", "--help"]).expect("help prints"),
            ExitCode::from(EXIT_CLEAN)
        );
        assert_eq!(
            run(["sasteuuuh", "--definitely-not-a-flag"]).expect("usage error"),
            ExitCode::from(EXIT_USAGE)
        );
    }
}
