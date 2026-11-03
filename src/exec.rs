//! The only place a child process is spawned.
//!
//! Every scanner runs through [`run`]: an absolute program path (never a bare name resolved by
//! a shell), arguments as a list, an environment reduced to what a command-line tool needs, an
//! explicit working directory, a wall-clock timeout and a cap on captured output. A tool that
//! misbehaves — hangs, prints forever, inherits a token it should not see — is a bug in this
//! module, not somewhere else. On Unix the child starts its own process group and the timeout
//! kills the whole group: a scanner's own subprocesses cannot outlive it holding the pipes.

use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Default wall-clock limit for one scanner.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);
/// Default cap on each captured stream, in bytes.
pub const DEFAULT_MAX_OUTPUT: usize = 64 * 1024 * 1024;

/// Environment variables a child may inherit. Everything else — tokens, credentials, proxies
/// with embedded passwords — stays here.
const INHERITED_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SYSTEMROOT",
    "USERPROFILE",
    "LOCALAPPDATA",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
];

/// Where a child's standard error is echoed live, on top of being captured.
pub type LiveSink = Arc<Mutex<dyn Write + Send>>;

/// A command to run.
#[derive(Clone)]
pub struct Invocation {
    /// Absolute path of the executable.
    pub program: PathBuf,
    /// Arguments, program name excluded.
    pub args: Vec<OsString>,
    /// Working directory; the parent's when `None`.
    pub cwd: Option<PathBuf>,
    /// Extra environment variables, on top of the inherited allow-list.
    pub env: Vec<(OsString, OsString)>,
    /// Wall-clock limit; the child is killed past it.
    pub timeout: Duration,
    /// Cap on each captured stream, in bytes; the rest is read and discarded.
    pub max_output: usize,
    /// Echo the child's standard error here as it arrives (progress bars included).
    pub live: Option<LiveSink>,
    /// With `live`: after this long without a byte from the child, write a
    /// `<label>: still running (<elapsed>)` line to the sink, and again at each interval.
    pub heartbeat: Option<Duration>,
    /// Name used in heartbeat lines.
    pub label: String,
}

impl std::fmt::Debug for Invocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invocation")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("cwd", &self.cwd)
            .field("env", &self.env)
            .field("timeout", &self.timeout)
            .field("max_output", &self.max_output)
            .field("live", &self.live.is_some())
            .field("heartbeat", &self.heartbeat)
            .field("label", &self.label)
            .finish()
    }
}

impl Invocation {
    /// A command with default timeout and output cap.
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Invocation {
            program: program.into(),
            args: Vec::new(),
            cwd: None,
            env: Vec::new(),
            timeout: DEFAULT_TIMEOUT,
            max_output: DEFAULT_MAX_OUTPUT,
            live: None,
            heartbeat: None,
            label: String::new(),
        }
    }

    /// Echo standard error live to `sink`; with `heartbeat`, add a `<label>: still running`
    /// line after that long without output.
    #[must_use]
    pub fn live(
        mut self,
        sink: LiveSink,
        heartbeat: Option<Duration>,
        label: impl Into<String>,
    ) -> Self {
        self.live = Some(sink);
        self.heartbeat = heartbeat;
        self.label = label.into();
        self
    }

    /// Add one argument.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Add arguments.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set the working directory.
    #[must_use]
    pub fn cwd(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cwd = Some(dir.into());
        self
    }

    /// Add an environment variable.
    #[must_use]
    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Set the timeout.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the output cap.
    #[must_use]
    pub fn max_output(mut self, max_output: usize) -> Self {
        self.max_output = max_output;
        self
    }

    /// The command as it would be typed, for messages.
    pub fn display(&self) -> String {
        std::iter::once(self.program.as_os_str())
            .chain(self.args.iter().map(OsString::as_os_str))
            .map(|s| s.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// What a child produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// Exit code; `None` when killed by a signal (or by the timeout).
    pub code: Option<i32>,
    /// Captured standard output, at most `max_output` bytes.
    pub stdout: Vec<u8>,
    /// Captured standard error, at most `max_output` bytes.
    pub stderr: Vec<u8>,
    /// `true` when stdout exceeded the cap.
    pub stdout_truncated: bool,
    /// `true` when stderr exceeded the cap.
    pub stderr_truncated: bool,
    /// `true` when the child was killed because of the timeout.
    pub timed_out: bool,
    /// Wall-clock time.
    pub duration: Duration,
}

impl Output {
    /// `true` when the child exited with code 0 in time.
    pub fn success(&self) -> bool {
        self.code == Some(0) && !self.timed_out
    }

    /// Standard output as text (lossy).
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// Standard error as text (lossy).
    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

/// Why a child could not be run.
#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    /// The program path is not absolute: resolve it first (`tools::find_in_path`).
    #[error("refusing to run `{0}`: not an absolute path")]
    RelativeProgram(PathBuf),
    /// `spawn` failed (missing binary, permissions, …).
    #[error("cannot start `{program}`")]
    Spawn {
        /// The program.
        program: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// Waiting on the child failed.
    #[error("cannot wait for `{program}`")]
    Wait {
        /// The program.
        program: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The output pipes could not be set up.
    #[error("cannot capture the output of `{0}`")]
    Pipe(PathBuf),
}

/// Run `inv` to completion (or to its timeout) and capture what it produced.
///
/// # Errors
///
/// [`ExecError`] when the program path is relative, cannot be started, or cannot be waited
/// for. A non-zero exit code, a timeout or truncated output are *not* errors: they are
/// reported in [`Output`] for the caller to interpret.
// The one sanctioned call site of `Command::new` (see clippy.toml).
#[allow(clippy::disallowed_methods)]
pub fn run(inv: &Invocation) -> Result<Output, ExecError> {
    if !inv.program.is_absolute() {
        return Err(ExecError::RelativeProgram(inv.program.clone()));
    }
    let mut command = Command::new(&inv.program);
    command
        .args(&inv.args)
        .env_clear()
        .envs(inherited_env())
        .envs(inv.env.iter().map(|(k, v)| (k.as_os_str(), v.as_os_str())))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = &inv.cwd {
        command.current_dir(cwd);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // A new group whose id is the child's pid, so the timeout can kill it as a whole.
        command.process_group(0);
    }

    let start = Instant::now();
    let mut child = command.spawn().map_err(|source| ExecError::Spawn {
        program: inv.program.clone(),
        source,
    })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ExecError::Pipe(inv.program.clone()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ExecError::Pipe(inv.program.clone()))?;
    let cap = inv.max_output;

    let last_output = AtomicU64::new(0);
    let (out, err, waited) = std::thread::scope(|scope| {
        let out = scope.spawn(move || drain(stdout, cap, None));
        let live = inv.live.as_ref().map(|sink| (sink, &last_output, start));
        let err = scope.spawn(move || drain(stderr, cap, live));
        let waited = wait_with_timeout(&mut child, inv, start, &last_output);
        (out.join(), err.join(), waited)
    });
    let (code, timed_out) = waited?;
    let (stdout, stdout_truncated) = out.unwrap_or((Vec::new(), true));
    let (stderr, stderr_truncated) = err.unwrap_or((Vec::new(), true));

    Ok(Output {
        code,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        timed_out,
        duration: start.elapsed(),
    })
}

/// The variables of this process whose name starts with `prefix`, for a child that owns that
/// namespace (`MISE_*` for mise). Everything else stays behind the allow-list.
pub fn env_with_prefix(prefix: &str) -> Vec<(OsString, OsString)> {
    std::env::vars_os()
        .filter(|(name, _)| name.to_string_lossy().starts_with(prefix))
        .collect()
}

fn inherited_env() -> impl Iterator<Item = (&'static OsStr, OsString)> {
    INHERITED_ENV
        .iter()
        .filter_map(|name| std::env::var_os(name).map(|value| (OsStr::new(name), value)))
}

/// Read a stream to its end, keeping at most `cap` bytes. With `live`, every chunk is also
/// echoed to the sink as it arrives and the time of the last byte is noted (milliseconds
/// since `start`) for the heartbeat.
fn drain(
    mut reader: impl Read,
    cap: usize,
    live: Option<(&LiveSink, &AtomicU64, Instant)>,
) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut truncated = false;
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let room = cap.saturating_sub(kept.len());
                let take = n.min(room);
                let received = chunk.get(..n).unwrap_or_default();
                kept.extend_from_slice(chunk.get(..take).unwrap_or_default());
                if take < n {
                    truncated = true;
                }
                if let Some((sink, seen, start)) = live {
                    seen.store(millis_since(start), Ordering::Relaxed);
                    // Best effort: a closed terminal must not stop the capture.
                    if let Ok(mut sink) = sink.lock() {
                        let _ = sink.write_all(received);
                        let _ = sink.flush();
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    (kept, truncated)
}

fn millis_since(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// `1m02s`-style elapsed time for heartbeat and summary lines.
#[must_use]
pub fn human_elapsed(elapsed: Duration) -> String {
    let secs = elapsed.as_secs();
    if secs >= 60 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

/// Write a heartbeat line when the child has been silent for `every`, measured from the
/// later of the last byte received and the last heartbeat.
fn heartbeat(inv: &Invocation, start: Instant, last_output: &AtomicU64, last_beat: &mut u64) {
    let (Some(sink), Some(every)) = (&inv.live, inv.heartbeat) else {
        return;
    };
    let now = millis_since(start);
    let quiet_since = last_output.load(Ordering::Relaxed).max(*last_beat);
    let every_ms = u64::try_from(every.as_millis()).unwrap_or(u64::MAX);
    if now.saturating_sub(quiet_since) < every_ms {
        return;
    }
    if let Ok(mut sink) = sink.lock() {
        let _ = writeln!(
            sink,
            "{}: still running ({})",
            inv.label,
            human_elapsed(start.elapsed())
        );
        let _ = sink.flush();
    }
    *last_beat = now;
}

fn wait_with_timeout(
    child: &mut Child,
    inv: &Invocation,
    start: Instant,
    last_output: &AtomicU64,
) -> Result<(Option<i32>, bool), ExecError> {
    let program = &inv.program;
    let deadline = start + inv.timeout;
    let mut last_beat = 0u64;
    loop {
        let waited = child.try_wait().map_err(|source| ExecError::Wait {
            program: program.clone(),
            source,
        })?;
        if let Some(status) = waited {
            return Ok((status.code(), false));
        }
        heartbeat(inv, start, last_output, &mut last_beat);
        if Instant::now() >= deadline {
            // Best effort: the child may already be gone, and a kill that fails leaves
            // nothing better to do than report the timeout.
            kill_tree(child);
            let status = child.wait().map_err(|source| ExecError::Wait {
                program: program.clone(),
                source,
            })?;
            return Ok((status.code(), true));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Something that runs an [`Invocation`]: the real thing, or a fake in tests.
pub trait Runner {
    /// Run `inv`.
    ///
    /// # Errors
    ///
    /// See [`run`].
    fn run(&self, inv: &Invocation) -> Result<Output, ExecError>;
}

/// Spawns real processes through [`run`].
#[derive(Debug, Clone, Copy, Default)]
pub struct RealRunner;

impl Runner for RealRunner {
    fn run(&self, inv: &Invocation) -> Result<Output, ExecError> {
        run(inv)
    }
}

/// Kill the child and, on Unix, every process in its group (its own subprocesses).
#[cfg(unix)]
fn kill_tree(child: &mut Child) {
    let pid = rustix::process::Pid::from_child(child);
    let _group = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    let _direct = child.kill();
}

#[cfg(not(unix))]
fn kill_tree(child: &mut Child) {
    let _direct = child.kill();
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::cell::RefCell;

    /// An [`Output`] with sensible defaults.
    pub(crate) fn output(code: Option<i32>, stdout: &[u8], stderr: &str) -> Output {
        Output {
            code,
            stdout: stdout.to_vec(),
            stderr: stderr.as_bytes().to_vec(),
            stdout_truncated: false,
            stderr_truncated: false,
            timed_out: false,
            duration: Duration::from_millis(5),
        }
    }

    /// A scripted runner: answers with the closure, remembers every invocation.
    pub(crate) struct FakeRunner<F: Fn(&Invocation) -> Result<Output, ExecError>> {
        script: F,
        calls: RefCell<Vec<Invocation>>,
    }

    impl<F: Fn(&Invocation) -> Result<Output, ExecError>> FakeRunner<F> {
        pub(crate) fn new(script: F) -> Self {
            FakeRunner {
                script,
                calls: RefCell::new(Vec::new()),
            }
        }

        pub(crate) fn calls(&self) -> Vec<Invocation> {
            self.calls.borrow().clone()
        }
    }

    impl<F: Fn(&Invocation) -> Result<Output, ExecError>> Runner for FakeRunner<F> {
        fn run(&self, inv: &Invocation) -> Result<Output, ExecError> {
            self.calls.borrow_mut().push(inv.clone());
            (self.script)(inv)
        }
    }
}

#[cfg(all(test, unix))]
// The `sh()` helper is not a `#[test]` body, where clippy.toml already allows `expect`.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn sh() -> PathBuf {
        crate::tools::find_in_path("sh", std::env::var_os("PATH").as_deref()).expect("sh on PATH")
    }

    /// A sink the test reads back once the run is over.
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| std::io::Error::other("poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capture() -> (LiveSink, Arc<Mutex<Vec<u8>>>) {
        let buf = Arc::new(Mutex::new(Vec::new()));
        (Arc::new(Mutex::new(Capture(Arc::clone(&buf)))), buf)
    }

    #[test]
    fn captures_both_streams_and_the_exit_code() {
        let out =
            run(&Invocation::new(sh()).args(["-c", "echo out; echo err >&2; exit 3"])).unwrap();
        assert_eq!(out.code, Some(3));
        assert_eq!(out.stdout_text(), "out\n");
        assert_eq!(out.stderr_text(), "err\n");
        assert!(!out.success());
        assert!(!out.timed_out);
        assert!(!out.stdout_truncated);
    }

    #[test]
    fn success_means_zero_in_time() {
        let out = run(&Invocation::new(sh()).args(["-c", "true"])).unwrap();
        assert!(out.success());
        assert_eq!(out.code, Some(0));
    }

    #[test]
    fn refuses_a_relative_program() {
        let err = run(&Invocation::new("sh").arg("-c").arg("true")).unwrap_err();
        assert!(matches!(err, ExecError::RelativeProgram(_)), "{err}");
    }

    #[test]
    fn a_missing_program_is_a_spawn_error() {
        let err = run(&Invocation::new("/definitely/not/here")).unwrap_err();
        assert!(matches!(err, ExecError::Spawn { .. }), "{err}");
    }

    #[test]
    fn kills_the_child_and_its_subprocesses_past_the_timeout() {
        // `sleep` is not the last command, so `sh` forks it: a grandchild that holds the
        // pipes open. Only a process-group kill ends the run in time.
        let started = Instant::now();
        let out = run(&Invocation::new(sh())
            .args(["-c", "sleep 30; echo done"])
            .timeout(Duration::from_millis(200)))
        .unwrap();
        assert!(out.timed_out);
        assert!(!out.success());
        assert!(
            out.stdout.is_empty(),
            "nothing after the kill: {}",
            out.stdout_text()
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the child tree was not killed"
        );
    }

    #[test]
    fn caps_the_captured_output_without_blocking_the_child() {
        let out = run(&Invocation::new(sh())
            .args([
                "-c",
                "head -c 300000 /dev/zero | tr '\\0' 'x'; echo done >&2",
            ])
            .max_output(1024))
        .unwrap();
        assert!(
            out.success(),
            "the child must run to completion: {}",
            out.stderr_text()
        );
        assert_eq!(out.stdout.len(), 1024);
        assert!(out.stdout_truncated);
        assert_eq!(out.stderr_text(), "done\n");
        assert!(!out.stderr_truncated);
    }

    #[test]
    fn the_child_only_inherits_the_allow_listed_environment() {
        // cargo sets CARGO_MANIFEST_DIR for the test process; the child must not see it.
        assert!(std::env::var_os("CARGO_MANIFEST_DIR").is_some());
        let out = run(&Invocation::new(sh())
            .args(["-c", "printf '%s|%s' \"$CARGO_MANIFEST_DIR\" \"$EXTRA\""])
            .env("EXTRA", "given"))
        .unwrap();
        assert_eq!(out.stdout_text(), "|given");
    }

    #[test]
    fn runs_in_the_requested_directory() {
        let dir = tempfile::tempdir().unwrap();
        let out = run(&Invocation::new(sh()).args(["-c", "pwd"]).cwd(dir.path())).unwrap();
        assert_eq!(
            PathBuf::from(out.stdout_text().trim())
                .canonicalize()
                .unwrap(),
            dir.path().canonicalize().unwrap()
        );
    }

    #[test]
    fn stdin_is_closed() {
        let out = run(&Invocation::new(sh()).args(["-c", "cat"])).unwrap();
        assert!(out.success());
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn env_with_prefix_only_returns_that_namespace() {
        // cargo sets CARGO_* for the test process.
        let cargo: Vec<_> = env_with_prefix("CARGO_");
        assert!(!cargo.is_empty());
        assert!(
            cargo
                .iter()
                .all(|(k, _)| k.to_string_lossy().starts_with("CARGO_"))
        );
        assert!(env_with_prefix("DEFINITELY_NOT_SET_PREFIX_").is_empty());
    }

    #[test]
    fn live_stderr_is_echoed_as_it_arrives_and_still_captured() {
        let (sink, buf) = capture();
        let out = run(&Invocation::new(sh())
            .args(["-c", "printf 'a\\rb\\n' >&2; echo out; printf 'c' >&2"])
            .live(sink, None, "demo"))
        .unwrap();
        assert_eq!(out.stdout_text(), "out\n", "stdout is never echoed");
        assert_eq!(out.stderr_text(), "a\rb\nc");
        let echoed = buf.lock().unwrap().clone();
        assert_eq!(
            echoed, b"a\rb\nc",
            "carriage returns and all, byte for byte"
        );
    }

    #[test]
    fn a_heartbeat_line_appears_when_the_child_is_silent() {
        let (sink, buf) = capture();
        let out = run(&Invocation::new(sh())
            .args(["-c", "sleep 1; echo done >&2"])
            .live(sink, Some(Duration::from_millis(300)), "slow"))
        .unwrap();
        assert!(out.success());
        let echoed = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(echoed.contains("slow: still running ("), "{echoed}");
        assert!(echoed.ends_with("done\n"), "{echoed}");
        assert_eq!(
            out.stderr_text(),
            "done\n",
            "heartbeats are never captured as tool output"
        );
    }

    #[test]
    fn no_heartbeat_without_an_interval_or_while_the_child_talks() {
        let (sink, buf) = capture();
        run(&Invocation::new(sh())
            .args(["-c", "sleep 0.5; echo done >&2"])
            .live(sink, None, "quiet"))
        .unwrap();
        assert_eq!(buf.lock().unwrap().as_slice(), b"done\n");

        let (sink, buf) = capture();
        run(&Invocation::new(sh())
            .args([
                "-c",
                "for i in 1 2 3 4 5 6; do echo tick >&2; sleep 0.1; done",
            ])
            .live(
                Arc::clone(&sink),
                Some(Duration::from_millis(400)),
                "chatty",
            ))
        .unwrap();
        let echoed = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(!echoed.contains("still running"), "{echoed}");
    }

    #[test]
    fn elapsed_times_read_well() {
        assert_eq!(human_elapsed(Duration::from_secs(7)), "7s");
        assert_eq!(human_elapsed(Duration::from_secs(62)), "1m02s");
        assert_eq!(human_elapsed(Duration::from_secs(3600)), "60m00s");
    }

    #[test]
    fn display_joins_program_and_args() {
        let inv = Invocation::new("/usr/bin/tool").args(["scan", "."]);
        assert_eq!(inv.display(), "/usr/bin/tool scan .");
    }
}
