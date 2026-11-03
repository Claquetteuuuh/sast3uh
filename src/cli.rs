//! Command-line definition (clap derive).
//!
//! Only the shape of the command line lives here; the behaviour is in the crate root so it
//! can be driven without a process.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::model::Severity;
use crate::output::Format;
use crate::packs::Profile;
use crate::pipeline::UpdatePolicy;

/// One SAST to run them all.
#[derive(Debug, Parser)]
#[command(name = "sast3uh", version, about, propagate_version = true)]
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// The subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run every available scanner on a directory and merge the findings.
    Scan(ScanArgs),
    /// List the scanners sast3uh knows about: installed path, version, latest release.
    Tools(ToolsArgs),
    /// Show what a directory holds and which Semgrep rule packs a scan of it would run.
    Packs(PacksArgs),
}

/// Arguments of `scan`.
#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Directory to scan.
    #[arg(default_value = ".", value_name = "DIR")]
    pub path: PathBuf,

    /// Report format (guessed from the --output extension when omitted; text otherwise).
    #[arg(short, long, value_enum)]
    pub format: Option<Format>,

    /// Write the report to this file instead of standard output.
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Run only these scanners (comma-separated: semgrep, bearer, luacheck).
    #[arg(short, long, value_delimiter = ',', value_name = "NAME")]
    pub tools: Vec<String>,

    /// Semgrep rule source, repeatable (a registry pack such as p/rust, or a rules file).
    #[arg(long = "semgrep-config", value_name = "CONFIG")]
    pub semgrep_configs: Vec<String>,

    /// How many Semgrep packs the automatic selection takes: every non-style pack, or the
    /// security ones only.
    #[arg(long, value_enum, default_value_t = Profile::Exhaustive)]
    pub semgrep_profile: Profile,

    /// Exit 1 when a finding is at or above this severity.
    #[arg(long, default_value = "info", value_name = "SEVERITY")]
    pub fail_on: Severity,

    /// Time limit per scanner, in seconds.
    #[arg(long, default_value_t = 600, value_name = "SECONDS")]
    pub timeout: u64,

    /// What to do when a scanner is behind its latest release.
    #[arg(long, value_enum, default_value_t = UpdatePolicy::Ask)]
    pub update: UpdatePolicy,

    /// Do not look releases up on GitHub (implies --update never).
    #[arg(long)]
    pub offline: bool,

    /// Keep every finding, even the ones reported twice.
    #[arg(long)]
    pub no_dedup: bool,
}

/// Arguments of `packs`.
#[derive(Debug, Args)]
pub struct PacksArgs {
    /// Directory to inspect.
    #[arg(default_value = ".", value_name = "DIR")]
    pub path: PathBuf,

    /// Profile to select with.
    #[arg(long, value_enum, default_value_t = Profile::Exhaustive)]
    pub semgrep_profile: Profile,
}

/// Arguments of `tools`.
#[derive(Debug, Args)]
pub struct ToolsArgs {
    /// Do not look releases up on GitHub.
    #[arg(long)]
    pub offline: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(args: &[&str]) -> ScanArgs {
        let mut full = vec!["sast3uh", "scan"];
        full.extend_from_slice(args);
        match Cli::try_parse_from(full).unwrap().command {
            Command::Scan(args) => args,
            other => panic!("expected scan: {other:?}"),
        }
    }

    #[test]
    fn scan_defaults() {
        let args = scan(&[]);
        assert_eq!(args.path, PathBuf::from("."));
        assert_eq!(args.format, None);
        assert_eq!(args.output, None);
        assert!(args.tools.is_empty());
        assert!(args.semgrep_configs.is_empty());
        assert_eq!(args.fail_on, Severity::Info);
        assert_eq!(args.timeout, 600);
        assert_eq!(args.update, UpdatePolicy::Ask);
        assert_eq!(args.semgrep_profile, Profile::Exhaustive);
        assert!(!args.offline);
        assert!(!args.no_dedup);
    }

    #[test]
    fn scan_accepts_every_option() {
        let args = scan(&[
            "/tmp/x",
            "-f",
            "html",
            "-o",
            "out.html",
            "-t",
            "semgrep,luacheck",
            "--semgrep-config",
            "p/rust",
            "--semgrep-config",
            "rules.yml",
            "--fail-on",
            "HIGH",
            "--timeout",
            "30",
            "--update",
            "never",
            "--offline",
            "--no-dedup",
        ]);
        assert_eq!(args.path, PathBuf::from("/tmp/x"));
        assert_eq!(args.format, Some(Format::Html));
        assert_eq!(args.output, Some(PathBuf::from("out.html")));
        assert_eq!(args.tools, vec!["semgrep", "luacheck"]);
        assert_eq!(args.semgrep_configs, vec!["p/rust", "rules.yml"]);
        assert_eq!(args.fail_on, Severity::High);
        assert_eq!(args.timeout, 30);
        assert_eq!(args.update, UpdatePolicy::Never);
        assert!(args.offline);
        assert!(args.no_dedup);
    }

    #[test]
    fn bad_values_are_rejected() {
        for argv in [
            vec!["sast3uh", "scan", "--format", "pdf"],
            vec!["sast3uh", "scan", "--fail-on", "urgent"],
            vec!["sast3uh", "scan", "--update", "maybe"],
            vec!["sast3uh", "scan", "--timeout", "soon"],
        ] {
            let err = Cli::try_parse_from(&argv).unwrap_err();
            // An enum rejects with InvalidValue, a FromStr type with ValueValidation.
            assert!(
                matches!(
                    err.kind(),
                    clap::error::ErrorKind::InvalidValue | clap::error::ErrorKind::ValueValidation
                ),
                "{argv:?}: {:?}",
                err.kind()
            );
        }
    }

    #[test]
    fn packs_takes_a_directory_and_a_profile() {
        match Cli::try_parse_from([
            "sast3uh",
            "packs",
            "/tmp/x",
            "--semgrep-profile",
            "security",
        ])
        .unwrap()
        .command
        {
            Command::Packs(args) => {
                assert_eq!(args.path, PathBuf::from("/tmp/x"));
                assert_eq!(args.semgrep_profile, Profile::Security);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn tools_has_an_offline_flag() {
        match Cli::try_parse_from(["sast3uh", "tools", "--offline"])
            .unwrap()
            .command
        {
            Command::Tools(args) => assert!(args.offline),
            other => panic!("expected tools: {other:?}"),
        }
    }

    #[test]
    fn a_subcommand_is_required() {
        let err = Cli::try_parse_from(["sast3uh"]).unwrap_err();
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }

    #[test]
    fn the_command_line_is_self_consistent() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
