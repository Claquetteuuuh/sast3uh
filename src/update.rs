//! Keeping the scanners current: what is installed, what upstream released, how to move.
//!
//! The network part is tiny on purpose — one GET on the GitHub releases API per tool, and the
//! download of a release asset when an adapter can verify it — and sits behind [`Http`] so the
//! rest is testable without a socket.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::exec::{Invocation, Output, Runner};
use crate::tools::find_in_path;
use crate::version::Version;

/// Largest response accepted from the GitHub API.
pub const API_BODY_CAP: usize = 1024 * 1024;
/// Largest release asset accepted.
pub const ASSET_CAP: usize = 256 * 1024 * 1024;
/// Time allowed for one HTTP request.
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// What an adapter knows when it decides how to update.
#[derive(Debug, Clone)]
pub struct UpdateContext<'a> {
    /// The scanner.
    pub tool: &'a str,
    /// Where the installed binary is.
    pub installed_path: &'a Path,
    /// What is installed.
    pub installed: Version,
    /// What upstream released.
    pub latest: Version,
    /// `PATH`, to look for package managers.
    pub path_var: Option<&'a OsStr>,
}

impl UpdateContext<'_> {
    /// Where `binary` is on `PATH`, if anywhere.
    pub fn find(&self, binary: &str) -> Option<PathBuf> {
        find_in_path(binary, self.path_var)
    }
}

/// One step of an update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateStep {
    /// Run a package manager (resolved on `PATH` at execution time).
    Command {
        /// Program name.
        program: String,
        /// Arguments.
        args: Vec<String>,
    },
    /// Download a GitHub release asset, verify its SHA-256 against the release's checksums
    /// file, and put the binary at `destination`.
    ReleaseBinary {
        /// `owner/repo`.
        repo: String,
        /// Release tag (`v2.1.3`).
        tag: String,
        /// Asset file name.
        asset: String,
        /// Checksums file name in the same release.
        checksums_asset: String,
        /// Path of the binary inside the archive, when the asset is a `.tar.gz`.
        member: Option<String>,
        /// Where the binary goes.
        destination: PathBuf,
    },
    /// Nothing automatic: tell the user what to do.
    Manual(String),
}

/// How to bring a scanner up to date.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePlan {
    /// One line for the prompt.
    pub summary: String,
    /// The steps, in order.
    pub steps: Vec<UpdateStep>,
}

impl UpdatePlan {
    /// A single command.
    pub fn command(summary: impl Into<String>, program: &str, args: &[&str]) -> Self {
        UpdatePlan {
            summary: summary.into(),
            steps: vec![UpdateStep::Command {
                program: program.to_owned(),
                args: args.iter().map(|a| (*a).to_owned()).collect(),
            }],
        }
    }

    /// Instructions only.
    pub fn manual(text: impl Into<String>) -> Self {
        let text = text.into();
        UpdatePlan {
            summary: text.clone(),
            steps: vec![UpdateStep::Manual(text)],
        }
    }

    /// `true` when every step can run without the user.
    pub fn is_automatic(&self) -> bool {
        self.steps
            .iter()
            .all(|s| !matches!(s, UpdateStep::Manual(_)))
    }

    /// The commands as they would be typed, one per line.
    pub fn describe(&self) -> String {
        self.steps
            .iter()
            .map(|step| match step {
                UpdateStep::Command { program, args } => format!("{program} {}", args.join(" ")),
                UpdateStep::ReleaseBinary { repo, tag, asset, destination, .. } => format!(
                    "download {asset} from github.com/{repo} release {tag}, verify SHA-256, install to {}",
                    destination.display()
                ),
                UpdateStep::Manual(text) => text.clone(),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Why an update could not be checked or applied.
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    /// The network request failed.
    #[error("{0}")]
    Http(String),
    /// The API answered something unexpected.
    #[error("unexpected answer from GitHub: {0}")]
    Api(String),
    /// The asset's digest does not match the checksums file.
    #[error(
        "checksum mismatch for {asset}: the download does not match the release's checksums file"
    )]
    Checksum {
        /// The asset.
        asset: String,
    },
    /// The checksums file has no entry for the asset.
    #[error("no checksum for {asset} in {checksums}")]
    MissingChecksum {
        /// The asset.
        asset: String,
        /// The checksums file.
        checksums: String,
    },
    /// A command of the plan failed.
    #[error("`{command}` failed: {reason}")]
    Command {
        /// The command.
        command: String,
        /// Why.
        reason: String,
    },
    /// A program of the plan is not on `PATH`.
    #[error("`{0}` is not on PATH")]
    MissingProgram(String),
    /// A local file operation failed.
    #[error("{context}")]
    Io {
        /// What was being done.
        context: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
}

/// A minimal HTTP GET.
pub trait Http {
    /// Fetch `url`, refusing bodies larger than `cap`.
    ///
    /// # Errors
    ///
    /// [`UpdateError::Http`] on any transport or status error.
    fn get(&self, url: &str, cap: usize) -> Result<Vec<u8>, UpdateError>;
}

/// The real client: TLS through rustls, a global timeout, the GitHub headers, and the
/// `GITHUB_TOKEN` / `GH_TOKEN` of the environment sent to api.github.com only.
#[derive(Debug)]
pub struct UreqHttp {
    agent: ureq::Agent,
    token: Option<String>,
}

impl UreqHttp {
    /// A client with the default timeout.
    pub fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(HTTP_TIMEOUT))
            .user_agent(concat!("sasteuuuh/", env!("CARGO_PKG_VERSION")))
            .build();
        let token = ["GITHUB_TOKEN", "GH_TOKEN"]
            .iter()
            .find_map(|name| std::env::var(name).ok())
            .map(|t| t.trim().to_owned())
            .filter(|t| !t.is_empty());
        UreqHttp {
            agent: ureq::Agent::new_with_config(config),
            token,
        }
    }
}

impl Default for UreqHttp {
    fn default() -> Self {
        Self::new()
    }
}

impl Http for UreqHttp {
    fn get(&self, url: &str, cap: usize) -> Result<Vec<u8>, UpdateError> {
        let mut request = self
            .agent
            .get(url)
            .header("Accept", "application/vnd.github+json");
        if let Some(token) = self
            .token
            .as_deref()
            .filter(|_| url.starts_with("https://api.github.com/"))
        {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }
        let mut response = request
            .call()
            .map_err(|e| UpdateError::Http(format!("GET {url}: {e}")))?;
        let cap_u64 = u64::try_from(cap).unwrap_or(u64::MAX);
        response
            .body_mut()
            .with_config()
            .limit(cap_u64)
            .read_to_vec()
            .map_err(|e| UpdateError::Http(format!("GET {url}: reading the body: {e}")))
    }
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
}

/// The newest release of `repo` (`owner/repo`).
///
/// # Errors
///
/// [`UpdateError`] when the request fails or the answer carries no version.
pub fn latest_release(http: &dyn Http, repo: &str) -> Result<Version, UpdateError> {
    let body = http.get(
        &format!("https://api.github.com/repos/{repo}/releases/latest"),
        API_BODY_CAP,
    )?;
    parse_latest_release(&body)
}

/// Read the version out of a `releases/latest` answer.
///
/// # Errors
///
/// [`UpdateError::Api`] when the body is not the documented JSON or its tag is not a version.
pub fn parse_latest_release(body: &[u8]) -> Result<Version, UpdateError> {
    let release: Release =
        serde_json::from_slice(body).map_err(|e| UpdateError::Api(e.to_string()))?;
    Version::parse(&release.tag_name)
        .ok_or_else(|| UpdateError::Api(format!("tag `{}` is not a version", release.tag_name)))
}

/// The SHA-256 listed for `asset` in a `sha256sum`-style checksums file (`<hex>  <name>`).
pub fn expected_sha256(checksums: &str, asset: &str) -> Option<String> {
    checksums.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let hex = parts.next()?;
        let name = parts.next()?.trim_start_matches('*');
        (name == asset && hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()))
            .then(|| hex.to_ascii_lowercase())
    })
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            // Writing to a String cannot fail.
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// Verify `bytes` against the checksums file.
///
/// # Errors
///
/// [`UpdateError::MissingChecksum`] or [`UpdateError::Checksum`].
pub fn verify_sha256(
    bytes: &[u8],
    checksums: &str,
    asset: &str,
    checksums_name: &str,
) -> Result<(), UpdateError> {
    let expected =
        expected_sha256(checksums, asset).ok_or_else(|| UpdateError::MissingChecksum {
            asset: asset.to_owned(),
            checksums: checksums_name.to_owned(),
        })?;
    if sha256_hex(bytes) == expected {
        Ok(())
    } else {
        Err(UpdateError::Checksum {
            asset: asset.to_owned(),
        })
    }
}

/// What happened when a step ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepResult {
    /// The step ran; here is the last of its output.
    Done(String),
    /// The step could not be automated; here is what to do by hand.
    Manual(String),
}

/// Run one step.
///
/// # Errors
///
/// [`UpdateError`] when the step fails; the machine is left as it was.
pub fn execute(
    step: &UpdateStep,
    http: &dyn Http,
    runner: &dyn Runner,
    path_var: Option<&OsStr>,
) -> Result<StepResult, UpdateError> {
    execute_in(step, http, runner, path_var, &default_cache_base()?)
}

/// [`execute`] with an explicit directory for downloads that cannot be installed.
///
/// # Errors
///
/// See [`execute`].
pub fn execute_in(
    step: &UpdateStep,
    http: &dyn Http,
    runner: &dyn Runner,
    path_var: Option<&OsStr>,
    cache_base: &Path,
) -> Result<StepResult, UpdateError> {
    match step {
        UpdateStep::Manual(text) => Ok(StepResult::Manual(text.clone())),
        UpdateStep::Command { program, args } => {
            let resolved = find_in_path(program, path_var)
                .ok_or_else(|| UpdateError::MissingProgram(program.clone()))?;
            let inv = Invocation::new(resolved)
                .args(args.iter().map(String::as_str))
                .timeout(Duration::from_mins(15));
            let output = runner.run(&inv).map_err(|e| UpdateError::Command {
                command: inv.display(),
                reason: e.to_string(),
            })?;
            if output.success() {
                Ok(StepResult::Done(last_lines(&output, 5)))
            } else {
                Err(UpdateError::Command {
                    command: inv.display(),
                    reason: crate::scanners::failure_reason_pub(&output),
                })
            }
        }
        UpdateStep::ReleaseBinary {
            repo,
            tag,
            asset,
            checksums_asset,
            member,
            destination,
        } => install_release_binary(
            http,
            runner,
            path_var,
            repo,
            tag,
            asset,
            checksums_asset,
            member.as_deref(),
            destination,
            cache_base,
        ),
    }
}

fn last_lines(output: &Output, n: usize) -> String {
    let text = format!("{}\n{}", output.stdout_text(), output.stderr_text());
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let skip = lines.len().saturating_sub(n);
    lines
        .iter()
        .skip(skip)
        .copied()
        .collect::<Vec<_>>()
        .join("\n")
}

#[allow(clippy::too_many_arguments)]
fn install_release_binary(
    http: &dyn Http,
    runner: &dyn Runner,
    path_var: Option<&OsStr>,
    repo: &str,
    tag: &str,
    asset: &str,
    checksums_asset: &str,
    member: Option<&str>,
    destination: &Path,
    cache_base: &Path,
) -> Result<StepResult, UpdateError> {
    let base = format!("https://github.com/{repo}/releases/download/{tag}");
    let checksums = http.get(&format!("{base}/{checksums_asset}"), API_BODY_CAP)?;
    let archive = http.get(&format!("{base}/{asset}"), ASSET_CAP)?;
    verify_sha256(
        &archive,
        &String::from_utf8_lossy(&checksums),
        asset,
        checksums_asset,
    )?;

    let work = tempfile::tempdir().map_err(|source| UpdateError::Io {
        context: "creating a temporary directory".into(),
        source,
    })?;
    let downloaded = work.path().join(asset);
    std::fs::write(&downloaded, &archive).map_err(|source| UpdateError::Io {
        context: format!("writing {}", downloaded.display()),
        source,
    })?;

    let binary = match member {
        Some(member) if is_tarball(asset) => {
            extract_member(runner, path_var, &downloaded, work.path(), member)?
        }
        _ => downloaded,
    };
    place_binary(&binary, destination, cache_base)
}

fn is_tarball(asset: &str) -> bool {
    asset.to_ascii_lowercase().ends_with(".tar.gz")
}

fn extract_member(
    runner: &dyn Runner,
    path_var: Option<&OsStr>,
    archive: &Path,
    into: &Path,
    member: &str,
) -> Result<PathBuf, UpdateError> {
    let tar =
        find_in_path("tar", path_var).ok_or_else(|| UpdateError::MissingProgram("tar".into()))?;
    let inv = Invocation::new(tar)
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(into)
        .arg(member)
        .timeout(Duration::from_secs(120));
    let output = runner.run(&inv).map_err(|e| UpdateError::Command {
        command: inv.display(),
        reason: e.to_string(),
    })?;
    if !output.success() {
        return Err(UpdateError::Command {
            command: inv.display(),
            reason: crate::scanners::failure_reason_pub(&output),
        });
    }
    let extracted = into.join(member);
    if !extracted.is_file() {
        return Err(UpdateError::Command {
            command: inv.display(),
            reason: format!("{member} not found in the archive"),
        });
    }
    Ok(extracted)
}

/// Move the verified binary over `destination` atomically when its directory is writable;
/// otherwise keep it in the user's cache and say what to run.
fn place_binary(
    binary: &Path,
    destination: &Path,
    cache_base: &Path,
) -> Result<StepResult, UpdateError> {
    set_executable(binary)?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if let Ok(staged) = tempfile::NamedTempFile::new_in(parent) {
        let staged_path = staged.path().to_path_buf();
        std::fs::copy(binary, &staged_path).map_err(|source| UpdateError::Io {
            context: format!("staging {}", staged_path.display()),
            source,
        })?;
        set_executable(&staged_path)?;
        staged.persist(destination).map_err(|e| UpdateError::Io {
            context: format!("replacing {}", destination.display()),
            source: e.error,
        })?;
        return Ok(StepResult::Done(format!(
            "installed {}",
            destination.display()
        )));
    }
    let cache = cache_base.join("sasteuuuh");
    std::fs::create_dir_all(&cache).map_err(|source| UpdateError::Io {
        context: format!("creating {}", cache.display()),
        source,
    })?;
    let kept = cache.join(binary.file_name().unwrap_or_else(|| OsStr::new("binary")));
    std::fs::copy(binary, &kept).map_err(|source| UpdateError::Io {
        context: format!("saving {}", kept.display()),
        source,
    })?;
    set_executable(&kept)?;
    Ok(StepResult::Manual(format!(
        "{} is not writable; the verified binary is at {}. Install it with:\n  sudo install -m 0755 {} {}",
        parent.display(),
        kept.display(),
        kept.display(),
        destination.display()
    )))
}

/// `$XDG_CACHE_HOME`, else `~/.cache`.
fn default_cache_base() -> Result<PathBuf, UpdateError> {
    std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .ok_or_else(|| UpdateError::Io {
            context: "no HOME to keep the download in".into(),
            source: std::io::Error::other("HOME is not set"),
        })
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<(), UpdateError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).map_err(|source| {
        UpdateError::Io {
            context: format!("making {} executable", path.display()),
            source,
        }
    })
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<(), UpdateError> {
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::collections::HashMap;

    /// Serves canned bodies by URL; records what was asked.
    #[derive(Default)]
    pub(crate) struct FakeHttp {
        pub(crate) bodies: HashMap<String, Vec<u8>>,
        pub(crate) requests: std::cell::RefCell<Vec<String>>,
    }

    impl FakeHttp {
        pub(crate) fn with(mut self, url: &str, body: &[u8]) -> Self {
            self.bodies.insert(url.to_owned(), body.to_vec());
            self
        }
    }

    impl Http for FakeHttp {
        fn get(&self, url: &str, cap: usize) -> Result<Vec<u8>, UpdateError> {
            self.requests.borrow_mut().push(url.to_owned());
            let body = self
                .bodies
                .get(url)
                .ok_or_else(|| UpdateError::Http(format!("GET {url}: 404")))?;
            if body.len() > cap {
                return Err(UpdateError::Http(format!(
                    "GET {url}: body over {cap} bytes"
                )));
            }
            Ok(body.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::FakeHttp;
    use super::*;
    use crate::exec::test_support::FakeRunner;

    #[test]
    fn parses_the_releases_api_answer() {
        let body = br#"{"url":"x","tag_name":"v1.183.0","name":"Release 1.183.0"}"#;
        assert_eq!(parse_latest_release(body).unwrap(), Version::new(1, 183, 0));
        assert!(matches!(
            parse_latest_release(b"{\"tag_name\":\"nightly\"}"),
            Err(UpdateError::Api(_))
        ));
        assert!(matches!(
            parse_latest_release(b"not json"),
            Err(UpdateError::Api(_))
        ));
        assert!(matches!(
            parse_latest_release(b"{}"),
            Err(UpdateError::Api(_))
        ));
    }

    #[test]
    fn latest_release_hits_the_documented_endpoint() {
        let http = FakeHttp::default().with(
            "https://api.github.com/repos/Bearer/bearer/releases/latest",
            br#"{"tag_name":"v2.1.3"}"#,
        );
        assert_eq!(
            latest_release(&http, "Bearer/bearer").unwrap(),
            Version::new(2, 1, 3)
        );
        assert!(matches!(
            latest_release(&http, "nope/nope"),
            Err(UpdateError::Http(_))
        ));
    }

    #[test]
    fn checksum_files_are_read_and_verified() {
        let data = b"hello\n";
        let hex = sha256_hex(data);
        assert_eq!(
            hex,
            "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
        );
        let checksums = format!(
            "deadbeef  other.tar.gz\n{hex}  bearer_2.1.3_linux_amd64.tar.gz\n{hex} *starred\n"
        );
        assert_eq!(
            expected_sha256(&checksums, "bearer_2.1.3_linux_amd64.tar.gz").as_deref(),
            Some(hex.as_str())
        );
        assert_eq!(
            expected_sha256(&checksums, "starred").as_deref(),
            Some(hex.as_str())
        );
        assert_eq!(
            expected_sha256(&checksums, "other.tar.gz"),
            None,
            "a malformed digest is no digest"
        );
        assert_eq!(expected_sha256(&checksums, "missing"), None);
        assert!(verify_sha256(data, &checksums, "starred", "checksums.txt").is_ok());
        assert!(matches!(
            verify_sha256(b"tampered", &checksums, "starred", "checksums.txt"),
            Err(UpdateError::Checksum { .. })
        ));
        assert!(matches!(
            verify_sha256(data, &checksums, "missing", "checksums.txt"),
            Err(UpdateError::MissingChecksum { .. })
        ));
    }

    #[test]
    fn plans_describe_themselves() {
        let plan = UpdatePlan::command("up", "pipx", &["upgrade", "semgrep"]);
        assert!(plan.is_automatic());
        assert_eq!(plan.describe(), "pipx upgrade semgrep");
        let manual = UpdatePlan::manual("do it by hand");
        assert!(!manual.is_automatic());
        assert_eq!(manual.describe(), "do it by hand");
        assert_eq!(manual.summary, "do it by hand");
    }

    #[test]
    fn a_command_step_runs_through_the_runner_and_reports_failure() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pipx"), b"").unwrap();
        let path_var = std::env::join_paths([dir.path()]).unwrap();
        let step = UpdateStep::Command {
            program: "pipx".into(),
            args: vec!["upgrade".into(), "semgrep".into()],
        };

        let ok = FakeRunner::new(|_| {
            Ok(crate::exec::test_support::output(
                Some(0),
                b"upgraded semgrep 1.1 -> 1.2\n",
                "",
            ))
        });
        let result = execute(&step, &FakeHttp::default(), &ok, Some(&path_var)).unwrap();
        assert_eq!(
            result,
            StepResult::Done("upgraded semgrep 1.1 -> 1.2".into())
        );
        assert_eq!(ok.calls()[0].args, vec!["upgrade", "semgrep"]);
        assert_eq!(ok.calls()[0].program, dir.path().join("pipx"));

        let ko = FakeRunner::new(|_| {
            Ok(crate::exec::test_support::output(
                Some(1),
                b"",
                "network down",
            ))
        });
        let err = execute(&step, &FakeHttp::default(), &ko, Some(&path_var)).unwrap_err();
        assert!(matches!(err, UpdateError::Command { .. }), "{err}");
        assert!(err.to_string().contains("network down"), "{err}");

        let missing = execute(&step, &FakeHttp::default(), &ok, None).unwrap_err();
        assert!(matches!(missing, UpdateError::MissingProgram(p) if p == "pipx"));
    }

    #[test]
    fn a_manual_step_is_returned_verbatim() {
        let step = UpdateStep::Manual("read the docs".into());
        let runner = FakeRunner::new(|_| panic!("must not run"));
        assert_eq!(
            execute(&step, &FakeHttp::default(), &runner, None).unwrap(),
            StepResult::Manual("read the docs".into())
        );
    }

    #[test]
    fn a_release_binary_is_verified_before_it_is_installed() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("bin").join("tool");
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::write(&destination, b"old").unwrap();
        let payload = b"#!/bin/sh\necho new\n";
        let checksums = format!("{}  tool-linux\n", sha256_hex(payload));
        let base = "https://github.com/o/r/releases/download/v9.9.9";
        let http = FakeHttp::default()
            .with(&format!("{base}/checksums.txt"), checksums.as_bytes())
            .with(&format!("{base}/tool-linux"), payload);
        let step = UpdateStep::ReleaseBinary {
            repo: "o/r".into(),
            tag: "v9.9.9".into(),
            asset: "tool-linux".into(),
            checksums_asset: "checksums.txt".into(),
            member: None,
            destination: destination.clone(),
        };
        let runner = FakeRunner::new(|_| panic!("a raw binary needs no tar"));
        let result = execute(&step, &http, &runner, None).unwrap();
        assert!(
            matches!(result, StepResult::Done(ref s) if s.contains("installed")),
            "{result:?}"
        );
        assert_eq!(std::fs::read(&destination).unwrap(), payload);

        // Tampered download: nothing is touched.
        std::fs::write(&destination, b"old").unwrap();
        let bad = FakeHttp::default()
            .with(&format!("{base}/checksums.txt"), checksums.as_bytes())
            .with(&format!("{base}/tool-linux"), b"evil");
        let err = execute(&step, &bad, &runner, None).unwrap_err();
        assert!(matches!(err, UpdateError::Checksum { .. }), "{err}");
        assert_eq!(std::fs::read(&destination).unwrap(), b"old");
    }

    #[cfg(unix)]
    #[test]
    fn a_tarball_asset_is_extracted_with_the_system_tar() {
        use crate::exec::{Invocation, RealRunner};
        use std::os::unix::fs::PermissionsExt;
        let path_var = std::env::var_os("PATH");
        let tar = find_in_path("tar", path_var.as_deref()).expect("tar on PATH");
        let work = tempfile::tempdir().unwrap();
        let payload = b"#!/bin/sh\necho from tarball\n";
        std::fs::write(work.path().join("bearer"), payload).unwrap();
        let archive = work.path().join("bearer_9.9.9_linux_amd64.tar.gz");
        let packed = crate::exec::run(
            &Invocation::new(tar)
                .arg("-czf")
                .arg(&archive)
                .arg("-C")
                .arg(work.path())
                .arg("bearer"),
        )
        .unwrap();
        assert!(packed.success(), "{}", packed.stderr_text());
        let bytes = std::fs::read(&archive).unwrap();

        let base = "https://github.com/Bearer/bearer/releases/download/v9.9.9";
        let checksums = format!("{}  bearer_9.9.9_linux_amd64.tar.gz\n", sha256_hex(&bytes));
        let http = FakeHttp::default()
            .with(&format!("{base}/checksums.txt"), checksums.as_bytes())
            .with(&format!("{base}/bearer_9.9.9_linux_amd64.tar.gz"), &bytes);
        let destination = work.path().join("bin").join("bearer");
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        let step = UpdateStep::ReleaseBinary {
            repo: "Bearer/bearer".into(),
            tag: "v9.9.9".into(),
            asset: "bearer_9.9.9_linux_amd64.tar.gz".into(),
            checksums_asset: "checksums.txt".into(),
            member: Some("bearer".into()),
            destination: destination.clone(),
        };
        let result = execute(&step, &http, &RealRunner, path_var.as_deref()).unwrap();
        assert!(matches!(result, StepResult::Done(_)), "{result:?}");
        assert_eq!(std::fs::read(&destination).unwrap(), payload);
        assert_eq!(
            std::fs::metadata(&destination)
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0o111
        );

        // A member that is not in the archive is an error, not a silent no-op.
        let step = UpdateStep::ReleaseBinary {
            repo: "Bearer/bearer".into(),
            tag: "v9.9.9".into(),
            asset: "bearer_9.9.9_linux_amd64.tar.gz".into(),
            checksums_asset: "checksums.txt".into(),
            member: Some("nope".into()),
            destination,
        };
        let err = execute(&step, &http, &RealRunner, path_var.as_deref()).unwrap_err();
        assert!(matches!(err, UpdateError::Command { .. }), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn an_unwritable_destination_keeps_the_verified_binary_aside() {
        use std::os::unix::fs::PermissionsExt;
        let work = tempfile::tempdir().unwrap();
        let locked = work.path().join("usr-bin");
        std::fs::create_dir(&locked).unwrap();
        let destination = locked.join("tool");
        std::fs::write(&destination, b"old").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();
        if std::fs::write(locked.join("probe"), b"").is_ok() {
            // root (CI containers sometimes are): the directory is writable after all.
            return;
        }
        let payload = b"new";
        let checksums = format!("{}  tool-linux\n", sha256_hex(payload));
        let base = "https://github.com/o/r/releases/download/v1.0.0";
        let http = FakeHttp::default()
            .with(&format!("{base}/checksums.txt"), checksums.as_bytes())
            .with(&format!("{base}/tool-linux"), payload);
        let step = UpdateStep::ReleaseBinary {
            repo: "o/r".into(),
            tag: "v1.0.0".into(),
            asset: "tool-linux".into(),
            checksums_asset: "checksums.txt".into(),
            member: None,
            destination: destination.clone(),
        };
        let cache = work.path().join("cache");
        let runner = FakeRunner::new(|_| panic!("no tar needed"));
        let result = execute_in(&step, &http, &runner, None, &cache).unwrap();
        let StepResult::Manual(text) = result else {
            panic!("{result:?}")
        };
        assert!(text.contains("sudo install -m 0755"), "{text}");
        assert!(text.contains(&destination.display().to_string()), "{text}");
        let kept = cache.join("sasteuuuh").join("tool-linux");
        assert_eq!(std::fs::read(&kept).unwrap(), payload);
        assert_eq!(
            std::fs::read(&destination).unwrap(),
            b"old",
            "nothing touched"
        );
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn http_errors_and_oversized_bodies_propagate() {
        let http = FakeHttp::default().with("u", &[0u8; 10]);
        assert!(http.get("u", 5).is_err());
        assert!(http.get("u", 10).is_ok());
        assert!(http.get("missing", 10).is_err());
    }
}
