//! Installing and updating scanners through [mise](https://mise.jdx.dev).
//!
//! sasteuuuh never downloads anything itself: mise is the one tool manager, it resolves a
//! scanner's binary (`mise which`), knows the newest version (`mise latest`) and installs or
//! updates it (`mise use -g`). Every call goes through [`crate::exec`] like a scanner would,
//! so the whole flow is tested with a scripted runner.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::exec::{ExecError, Invocation, Output, Runner, env_with_prefix};
use crate::tools::find_in_path;
use crate::version::Version;

/// Time allowed for a query (`which`, `latest`, `ls`).
const QUERY_TIMEOUT: Duration = Duration::from_secs(90);
/// Time allowed for an install.
const INSTALL_TIMEOUT: Duration = Duration::from_mins(15);

/// The mise binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mise {
    program: PathBuf,
}

/// Why a mise call did not give an answer.
#[derive(Debug, thiserror::Error)]
pub enum MiseError {
    /// mise exited with an error.
    #[error("`{command}` failed: {reason}")]
    Failed {
        /// The command.
        command: String,
        /// Exit code and the end of stderr.
        reason: String,
    },
    /// mise answered, but not with a version.
    #[error("`{command}` printed no version: {output}")]
    NoVersion {
        /// The command.
        command: String,
        /// What it printed.
        output: String,
    },
    /// mise could not be run at all.
    #[error(transparent)]
    Exec(#[from] ExecError),
}

/// What an install or update will run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePlan {
    /// The mise tool id (`semgrep`, `pipx:semgrep`, `aqua:Bearer/bearer`…).
    pub id: String,
    /// The version to install.
    pub version: Version,
}

impl UpdatePlan {
    /// The command as it would be typed.
    pub fn command_line(&self) -> String {
        format!("mise use -g {}@{}", self.id, self.version)
    }
}

impl Mise {
    /// mise, if it is on `path_var`.
    pub fn detect(path_var: Option<&OsStr>) -> Option<Self> {
        find_in_path("mise", path_var).map(|program| Mise { program })
    }

    /// A mise at an explicit path (tests, or a configured location).
    pub fn at(program: impl Into<PathBuf>) -> Self {
        Mise {
            program: program.into(),
        }
    }

    /// Where the binary is.
    pub fn program(&self) -> &Path {
        &self.program
    }

    fn invocation(&self, args: &[&str], timeout: Duration) -> Invocation {
        let mut inv = Invocation::new(&self.program)
            .args(args.iter().copied())
            .timeout(timeout)
            .max_output(4 * 1024 * 1024)
            .env("MISE_YES", "1")
            .env("NO_COLOR", "1");
        // mise's own settings, and the token it uses for GitHub API rate limits — this is the
        // one child that may see them.
        for (key, value) in env_with_prefix("MISE_") {
            inv = inv.env(key, value);
        }
        for name in ["GITHUB_TOKEN", "GH_TOKEN"] {
            if let Some(value) = std::env::var_os(name) {
                inv = inv.env(name, value);
            }
        }
        inv
    }

    /// `mise which <binary>`: the binary mise would run, when mise manages it.
    pub fn which(&self, runner: &dyn Runner, binary: &str) -> Option<PathBuf> {
        let inv = self.invocation(&["which", binary], QUERY_TIMEOUT);
        let output = runner.run(&inv).ok()?;
        if !output.success() {
            return None;
        }
        let path = PathBuf::from(output.stdout_text().trim());
        (path.is_absolute() && path.is_file()).then_some(path)
    }

    /// `mise latest <id>`: the newest version mise can install.
    ///
    /// # Errors
    ///
    /// [`MiseError`] when mise fails (unknown tool, no network…) or prints no version.
    pub fn latest(&self, runner: &dyn Runner, id: &str) -> Result<Version, MiseError> {
        let inv = self.invocation(&["latest", id], QUERY_TIMEOUT);
        let output = runner.run(&inv)?;
        if !output.success() {
            return Err(MiseError::Failed {
                command: inv.display(),
                reason: failure(&output),
            });
        }
        parse_latest(&output.stdout_text()).ok_or_else(|| MiseError::NoVersion {
            command: inv.display(),
            output: crate::scanners::tail_pub(&output.stdout_text(), 200),
        })
    }

    /// The id under which mise already manages `binary` (`pipx:semgrep` for `semgrep`), if any.
    pub fn managed_id(&self, runner: &dyn Runner, binary: &str) -> Option<String> {
        let inv = self.invocation(&["ls", "--json"], QUERY_TIMEOUT);
        let output = runner.run(&inv).ok()?;
        if !output.success() {
            return None;
        }
        parse_managed_id(&output.stdout, binary)
    }

    /// `mise use -g <id>@<version>`: install and make it the global version.
    ///
    /// # Errors
    ///
    /// [`MiseError`] when mise fails.
    pub fn use_global(&self, runner: &dyn Runner, plan: &UpdatePlan) -> Result<String, MiseError> {
        let spec = format!("{}@{}", plan.id, plan.version);
        let inv = self.invocation(&["use", "-g", &spec], INSTALL_TIMEOUT);
        let output = runner.run(&inv)?;
        if !output.success() {
            return Err(MiseError::Failed {
                command: inv.display(),
                reason: failure(&output),
            });
        }
        Ok(last_lines(&output, 3))
    }
}

fn failure(output: &Output) -> String {
    crate::scanners::failure_reason_pub(output)
}

fn last_lines(output: &Output, n: usize) -> String {
    let text = format!("{}\n{}", output.stdout_text(), output.stderr_text());
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let skip = lines.len().saturating_sub(n);
    lines
        .iter()
        .skip(skip)
        .copied()
        .collect::<Vec<_>>()
        .join(" | ")
}

/// The version on the last non-empty line of `mise latest` output.
pub fn parse_latest(stdout: &str) -> Option<Version> {
    stdout
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .and_then(Version::parse)
}

#[derive(Deserialize)]
struct Install {
    #[serde(default)]
    installed: bool,
}

/// The key of `mise ls --json` whose tool is `binary`.
pub fn parse_managed_id(json: &[u8], binary: &str) -> Option<String> {
    let tools: std::collections::BTreeMap<String, Vec<Install>> =
        serde_json::from_slice(json).ok()?;
    tools
        .into_iter()
        .filter(|(id, installs)| {
            short_name(id).eq_ignore_ascii_case(binary) && installs.iter().any(|i| i.installed)
        })
        .map(|(id, _)| id)
        .next()
}

/// The tool name inside a mise id: `pipx:semgrep` → `semgrep`, `aqua:Bearer/bearer` → `bearer`,
/// `asdf:mise-plugins/mise-semgrep` → `semgrep`.
pub fn short_name(id: &str) -> &str {
    let after_slash = id.rsplit('/').next().unwrap_or(id);
    let after_colon = after_slash.rsplit(':').next().unwrap_or(after_slash);
    after_colon.strip_prefix("mise-").unwrap_or(after_colon)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::test_support::{FakeRunner, output};

    fn mise() -> Mise {
        Mise::at("/fake/mise")
    }

    #[test]
    fn detect_finds_mise_on_path_only() {
        let dir = tempfile::tempdir().unwrap();
        let path_var = std::env::join_paths([dir.path()]).unwrap();
        assert_eq!(Mise::detect(Some(&path_var)), None);
        std::fs::write(dir.path().join("mise"), b"").unwrap();
        assert_eq!(
            Mise::detect(Some(&path_var)).unwrap().program(),
            dir.path().join("mise")
        );
        assert_eq!(Mise::detect(None), None);
    }

    #[test]
    fn parses_latest_and_short_names() {
        assert_eq!(parse_latest("1.183.0\n"), Some(Version::new(1, 183, 0)));
        assert_eq!(
            parse_latest("mise WARN something\n2.1.3\n\n"),
            Some(Version::new(2, 1, 3))
        );
        assert_eq!(parse_latest(""), None);
        assert_eq!(parse_latest("mise ERROR no such tool"), None);
        assert_eq!(short_name("semgrep"), "semgrep");
        assert_eq!(short_name("pipx:semgrep"), "semgrep");
        assert_eq!(short_name("aqua:Bearer/bearer"), "bearer");
        assert_eq!(short_name("ubi:lunarmodules/luacheck"), "luacheck");
        assert_eq!(short_name("asdf:mise-plugins/mise-semgrep"), "semgrep");
    }

    #[test]
    fn managed_id_comes_from_ls_json() {
        let json = br#"{"pipx:semgrep":[{"version":"1.183.0","installed":true,"active":true}],
                        "node":[{"version":"22.0.0","installed":true}],
                        "aqua:Bearer/bearer":[{"version":"2.1.3","installed":false}]}"#;
        assert_eq!(
            parse_managed_id(json, "semgrep").as_deref(),
            Some("pipx:semgrep")
        );
        assert_eq!(
            parse_managed_id(json, "SEMGREP").as_deref(),
            Some("pipx:semgrep")
        );
        assert_eq!(
            parse_managed_id(json, "bearer"),
            None,
            "listed but not installed"
        );
        assert_eq!(parse_managed_id(json, "luacheck"), None);
        assert_eq!(parse_managed_id(b"{}", "semgrep"), None);
        assert_eq!(parse_managed_id(b"not json", "semgrep"), None);
    }

    #[test]
    fn plans_print_the_mise_command() {
        let plan = UpdatePlan {
            id: "aqua:Bearer/bearer".into(),
            version: Version::new(2, 1, 3),
        };
        assert_eq!(plan.command_line(), "mise use -g aqua:Bearer/bearer@2.1.3");
    }

    #[test]
    fn which_requires_success_and_an_existing_absolute_file() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("semgrep");
        std::fs::write(&real, b"").unwrap();
        let real_text = real.display().to_string();
        let runner = FakeRunner::new(move |inv| {
            assert_eq!(inv.program, PathBuf::from("/fake/mise"));
            assert_eq!(inv.args[0], "which");
            Ok(match inv.args[1].to_str().unwrap() {
                "semgrep" => output(Some(0), format!("{real_text}\n").as_bytes(), ""),
                "bearer" => output(Some(1), b"", "mise ERROR bearer is not a mise bin"),
                "ghost" => output(Some(0), b"/does/not/exist\n", ""),
                _ => output(Some(0), b"relative/path\n", ""),
            })
        });
        assert_eq!(mise().which(&runner, "semgrep"), Some(real));
        assert_eq!(mise().which(&runner, "bearer"), None);
        assert_eq!(mise().which(&runner, "ghost"), None);
        assert_eq!(mise().which(&runner, "other"), None);
        let inv = &runner.calls()[0];
        assert!(inv.env.iter().any(|(k, v)| k == "MISE_YES" && v == "1"));
    }

    #[test]
    fn latest_reports_failures_and_missing_versions() {
        let runner = FakeRunner::new(|inv| {
            assert_eq!(inv.args[0], "latest");
            Ok(match inv.args[1].to_str().unwrap() {
                "semgrep" => output(Some(0), b"1.183.0\n", ""),
                "aqua:Nope/nope" => output(Some(1), b"", "mise ERROR no aqua-registry found"),
                _ => output(Some(0), b"\n", "mise WARN nothing"),
            })
        });
        assert_eq!(
            mise().latest(&runner, "semgrep").unwrap(),
            Version::new(1, 183, 0)
        );
        let err = mise().latest(&runner, "aqua:Nope/nope").unwrap_err();
        assert!(matches!(err, MiseError::Failed { .. }), "{err}");
        assert!(err.to_string().contains("no aqua-registry"), "{err}");
        assert!(matches!(
            mise().latest(&runner, "empty"),
            Err(MiseError::NoVersion { .. })
        ));
    }

    #[test]
    fn use_global_runs_the_pinned_spec_and_reports_the_outcome() {
        let runner = FakeRunner::new(|inv| {
            assert_eq!(inv.args[..2], ["use", "-g"]);
            if inv.args[2] == "semgrep@1.183.0" {
                Ok(output(
                    Some(0),
                    b"mise ~/.config/mise/config.toml tools: semgrep@1.183.0\n",
                    "",
                ))
            } else {
                Ok(output(Some(1), b"", "mise ERROR failed to install"))
            }
        });
        let ok = UpdatePlan {
            id: "semgrep".into(),
            version: Version::new(1, 183, 0),
        };
        let detail = mise().use_global(&runner, &ok).unwrap();
        assert!(detail.contains("tools: semgrep@1.183.0"), "{detail}");
        let ko = UpdatePlan {
            id: "ubi:x/y".into(),
            version: Version::new(1, 0, 0),
        };
        let err = mise().use_global(&runner, &ko).unwrap_err();
        assert!(err.to_string().contains("failed to install"), "{err}");
        let inv = &runner.calls()[1];
        assert_eq!(inv.args[2], "ubi:x/y@1.0.0");
        assert_eq!(inv.timeout, INSTALL_TIMEOUT);
    }

    #[test]
    fn a_runner_error_is_wrapped() {
        let runner = FakeRunner::new(|inv| Err(ExecError::Pipe(inv.program.clone())));
        assert!(matches!(
            mise().latest(&runner, "semgrep"),
            Err(MiseError::Exec(_))
        ));
        assert_eq!(mise().which(&runner, "semgrep"), None);
        assert_eq!(mise().managed_id(&runner, "semgrep"), None);
    }
}
