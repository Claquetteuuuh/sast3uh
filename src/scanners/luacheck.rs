//! Luacheck: the Lua linter (`--formatter plain --codes --ranges` output).

use std::ffi::OsString;

use super::{Outcome, Parsed, ScanOptions, Scanner, failure_reason, os_args, tail};
use crate::exec::Output;
use crate::model::{Finding, Severity, normalize_reported_path};

/// The Luacheck adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct Luacheck;

const WARNINGS_URL: &str = "https://luacheck.readthedocs.io/en/stable/warnings.html";

impl Scanner for Luacheck {
    fn name(&self) -> &'static str {
        "luacheck"
    }

    fn binary(&self) -> &'static str {
        "luacheck"
    }

    fn purpose(&self) -> &'static str {
        "Lua linter (globals, unused, syntax)"
    }

    fn mise_id(&self) -> &'static str {
        "ubi:lunarmodules/luacheck"
    }

    fn version_args(&self) -> Vec<OsString> {
        os_args(&["--version"])
    }

    fn scan_args(&self, _options: &ScanOptions) -> Vec<OsString> {
        os_args(&[
            ".",
            "--formatter",
            "plain",
            "--codes",
            "--ranges",
            "--no-color",
        ])
    }

    fn interpret(&self, output: &Output) -> Outcome {
        if output.timed_out {
            return Outcome::Failed(failure_reason(output));
        }
        if output.stdout_truncated {
            return Outcome::Failed("output exceeded the capture limit".to_owned());
        }
        match output.code {
            // 0: clean, 1: warnings, 2: errors (syntax) — all three carry a report.
            Some(0..=2) => {
                let parsed = parse(&output.stdout_text());
                Outcome::Completed {
                    findings: parsed.findings,
                    warnings: parsed.warnings,
                }
            }
            Some(3) => Outcome::Failed(format!("I/O error: {}", tail(&output.stderr_text(), 400))),
            Some(4) => Outcome::Failed(format!(
                "invalid options or configuration: {}",
                tail(
                    &format!("{}\n{}", output.stdout_text(), output.stderr_text()),
                    400
                )
            )),
            _ => Outcome::Failed(failure_reason(output)),
        }
    }
}

/// Parse `luacheck --formatter plain --codes --ranges` output.
///
/// Lines that are not `path:line:col[-col]: (Wnnn) message` are kept as warnings.
pub fn parse(text: &str) -> Parsed {
    let mut parsed = Parsed::default();
    for line in text
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.trim().is_empty())
    {
        match parse_line(line) {
            Some(finding) => parsed.findings.push(finding),
            None => parsed
                .warnings
                .push(format!("unparsed line: {}", tail(line, 200))),
        }
    }
    parsed
}

fn parse_line(line: &str) -> Option<Finding> {
    let (location, rest) = line.split_once(": (")?;
    let (code, message) = rest.split_once(") ")?;
    let mut parts = location.rsplitn(3, ':');
    let columns = parts.next()?;
    let line_no: u32 = parts.next()?.parse().ok()?;
    let path = normalize_reported_path(parts.next()?)?;
    let column: u32 = columns.split('-').next()?.parse().ok()?;
    let code = code.trim();
    let severity = match code.chars().next()? {
        'E' => Severity::Medium,
        'W' => Severity::Low,
        _ => Severity::Info,
    };
    Some(Finding {
        tool: "luacheck".to_owned(),
        also_reported_by: Vec::new(),
        rule_id: code.to_owned(),
        severity,
        title: code.to_owned(),
        message: message.trim().to_owned(),
        path,
        line: Some(line_no),
        end_line: Some(line_no),
        column: Some(column),
        cwes: Vec::new(),
        url: Some(WARNINGS_URL.to_owned()),
        fingerprint: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::tests::output;
    use std::path::PathBuf;

    const FIXTURE: &str = include_str!("../../tests/fixtures/luacheck/report.txt");
    const WITH_ERROR: &str = include_str!("../../tests/fixtures/luacheck/report-with-error.txt");
    const VERSION: &str = include_str!("../../tests/fixtures/luacheck/version.txt");

    #[test]
    fn parses_the_recorded_report() {
        let parsed = parse(FIXTURE);
        assert_eq!(parsed.findings.len(), 6);
        assert!(parsed.warnings.is_empty());
        let first = &parsed.findings[0];
        assert_eq!(first.tool, "luacheck");
        assert_eq!(first.rule_id, "W211");
        assert_eq!(first.title, "W211");
        assert_eq!(first.severity, Severity::Low);
        assert_eq!(first.message, "unused variable 'unused'");
        assert_eq!(first.path, PathBuf::from("src/main.lua"));
        assert_eq!(first.line, Some(1));
        assert_eq!(first.column, Some(7));
        assert_eq!(first.url.as_deref(), Some(WARNINGS_URL));
    }

    #[test]
    fn syntax_errors_are_medium() {
        let parsed = parse(WITH_ERROR);
        assert_eq!(parsed.findings.len(), 7);
        let error = parsed
            .findings
            .iter()
            .find(|f| f.rule_id == "E011")
            .unwrap();
        assert_eq!(error.severity, Severity::Medium);
        assert_eq!(error.path, PathBuf::from("src/broken.lua"));
        assert_eq!(error.message, "expected '(' near 'broken'");
    }

    #[test]
    fn unparsable_lines_become_warnings_and_bad_paths_are_dropped() {
        let parsed = parse(
            "Checking src/x.lua  OK\n\n../x.lua:1:1: (W111) bad\nsrc/y.lua:abc:1: (W111) bad\n",
        );
        assert!(parsed.findings.is_empty());
        assert_eq!(parsed.warnings.len(), 3, "{:?}", parsed.warnings);
    }

    #[test]
    fn empty_output_is_clean() {
        let parsed = parse("");
        assert!(parsed.findings.is_empty());
        assert!(parsed.warnings.is_empty());
    }

    #[test]
    fn interpret_follows_luachecks_exit_codes() {
        for code in [0, 1, 2] {
            match Luacheck.interpret(&output(Some(code), FIXTURE.as_bytes(), "")) {
                Outcome::Completed { findings, .. } => assert_eq!(findings.len(), 6, "exit {code}"),
                other => panic!("exit {code}: {other:?}"),
            }
        }
        assert!(
            matches!(Luacheck.interpret(&output(Some(3), b"", "cannot read")), Outcome::Failed(r) if r.contains("I/O"))
        );
        assert!(
            matches!(Luacheck.interpret(&output(Some(4), b"Critical error: bad option", "")), Outcome::Failed(r) if r.contains("bad option"))
        );
        assert!(matches!(
            Luacheck.interpret(&output(None, b"", "")),
            Outcome::Failed(_)
        ));
        let mut timed = output(Some(0), b"", "");
        timed.timed_out = true;
        assert!(matches!(Luacheck.interpret(&timed), Outcome::Failed(_)));
    }

    #[test]
    fn version_is_the_luacheck_line_not_the_lua_one() {
        let v = Luacheck
            .parse_version(&output(Some(0), VERSION.as_bytes(), ""))
            .unwrap();
        assert_eq!(v, crate::version::Version::new(1, 2, 0));
    }
}
