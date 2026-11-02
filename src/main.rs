//! Binary entry point.
//!
//! Deliberately tiny: everything happens in [`sasteuuuh::run`], which is unit-tested with an
//! in-memory writer. This file only turns the outcome into a process exit code.

use std::process::ExitCode;

fn main() -> ExitCode {
    // argv[0] is never trusted: `cli.rs` fixes the program name, so clap only ever reads the
    // arguments after it. The Semgrep rule warns about relying on argv[0] for security.
    // nosemgrep: rust.lang.security.args-os.args-os
    match sasteuuuh::run(std::env::args_os()) {
        Ok(code) => code,
        // `sasteuuuh … | head`: the reader went away; that is not an error worth a line.
        Err(err) if sasteuuuh::is_broken_pipe(&err) => ExitCode::from(sasteuuuh::EXIT_CLEAN),
        Err(err) => {
            eprintln!("sasteuuuh: {err:#}");
            ExitCode::from(sasteuuuh::EXIT_ERROR)
        }
    }
}
