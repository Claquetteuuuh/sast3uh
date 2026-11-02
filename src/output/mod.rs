//! Report renderers: one function per format, all fed the same [`Report`].
//!
//! Everything a scanner said is untrusted text. The XML and HTML writers escape every value
//! and never emit a link whose scheme is not `http` or `https`; the HTML page carries a
//! Content-Security-Policy that forbids scripts, so a finding cannot run code in the browser
//! that opens the report.

pub mod html;
pub mod json;
pub mod text;
pub mod xml;
pub mod yaml;

use std::io::Write;
use std::path::Path;

use crate::model::Report;

/// A report format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// Human-readable summary.
    Text,
    /// JSON.
    Json,
    /// YAML.
    Yaml,
    /// XML.
    Xml,
    /// A self-contained HTML page.
    Html,
}

impl Format {
    /// Every format, for messages.
    pub const ALL: [Format; 5] = [
        Format::Text,
        Format::Json,
        Format::Yaml,
        Format::Xml,
        Format::Html,
    ];

    /// The usual file extension.
    pub fn extension(self) -> &'static str {
        match self {
            Format::Text => "txt",
            Format::Json => "json",
            Format::Yaml => "yaml",
            Format::Xml => "xml",
            Format::Html => "html",
        }
    }

    /// Guess the format from a file name, when it has a known extension.
    pub fn from_path(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        match ext.as_str() {
            "txt" => Some(Format::Text),
            "json" => Some(Format::Json),
            "yaml" | "yml" => Some(Format::Yaml),
            "xml" => Some(Format::Xml),
            "html" | "htm" => Some(Format::Html),
            _ => None,
        }
    }
}

/// Why a report could not be rendered.
#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    /// JSON serialisation failed.
    #[error("rendering JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// YAML serialisation failed.
    #[error("rendering YAML: {0}")]
    Yaml(String),
    /// Writing to the buffer failed.
    #[error("rendering: {0}")]
    Io(#[from] std::io::Error),
}

/// Render `report` in `format`.
///
/// # Errors
///
/// [`RenderError`] when serialisation fails (it should not: the model is plain data).
pub fn render(report: &Report, format: Format) -> Result<Vec<u8>, RenderError> {
    let mut out = Vec::new();
    match format {
        Format::Text => text::render(report, &mut out)?,
        Format::Json => json::render(report, &mut out)?,
        Format::Yaml => yaml::render(report, &mut out)?,
        Format::Xml => xml::render(report, &mut out)?,
        Format::Html => html::render(report, &mut out)?,
    }
    Ok(out)
}

/// Write `bytes` to `path` atomically: staged next to it, then renamed over it. A symlink
/// at `path` is replaced, never followed.
///
/// # Errors
///
/// The I/O error of staging, writing or renaming.
pub fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if path.is_dir() {
        return Err(std::io::Error::other(format!(
            "{} is a directory",
            path.display()
        )));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged.write_all(bytes)?;
    staged.flush()?;
    staged.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// Escape text for an XML or HTML text node or attribute. Characters XML 1.0 forbids
/// (controls other than tab, newline and carriage return) become U+FFFD.
pub(crate) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if c.is_control() => out.push('\u{FFFD}'),
            c => out.push(c),
        }
    }
    out
}

/// A link target safe to emit: `http` or `https` only, no control characters.
pub(crate) fn safe_href(url: &str) -> Option<&str> {
    let trimmed = url.trim();
    let lower = trimmed.to_ascii_lowercase();
    ((lower.starts_with("https://") || lower.starts_with("http://"))
        && !trimmed.chars().any(|c| c.is_control() || c.is_whitespace()))
    .then_some(trimmed)
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::model::{
        Confidence, Diagnostic, Finding, FlowKind, FlowStep, Report, Severity, SkippedPath,
        ToolRun, ToolStatus,
    };
    use std::path::PathBuf;

    /// A report with one finding per severity, hostile strings included, a suppressed one,
    /// and three tools with run details.
    pub(crate) fn sample_report() -> Report {
        let finding = |tool: &str, rule: &str, severity: Severity, path: &str, line: u32| {
            let mut f = Finding::new(
                tool,
                rule,
                severity,
                format!("{rule} title"),
                format!("{rule} <message> & \"quotes\" 'single'"),
                PathBuf::from(path),
            );
            f.line = Some(line);
            f.end_line = Some(line);
            f.column = Some(3);
            f.end_column = Some(9);
            f.cwes = vec![79, 95];
            f.url = Some("https://example.com/rule".into());
            f.fingerprint = Some("fp".into());
            f
        };
        let mut merged = finding("semgrep", "eval", Severity::Critical, "src/app.js", 7);
        merged.also_reported_by = vec!["bearer".into()];
        merged.confidence = Some(Confidence::High);
        merged.owasp = vec!["A03:2021 - Injection".into()];
        merged.categories = vec!["security".into(), "PII".into()];
        merged.tags = vec!["express".into()];
        merged.snippet = Some("eval(req.query.code); // <script>".into());
        merged.fix = Some("safeEval(code)".into());
        merged.references = vec!["https://owasp.org/x".into(), "javascript:alert(2)".into()];
        merged.flow = vec![
            FlowStep {
                kind: FlowKind::Source,
                path: PathBuf::from("src/app.js"),
                line: Some(5),
                column: Some(25),
                end_line: None,
                end_column: Some(28),
                content: Some("req".into()),
            },
            FlowStep {
                kind: FlowKind::Sink,
                path: PathBuf::from("src/app.js"),
                line: Some(7),
                column: Some(3),
                end_line: Some(7),
                end_column: None,
                content: Some("eval(code) & co".into()),
            },
        ];
        merged.extra.insert("likelihood".into(), "LOW".into());
        merged
            .extra
            .insert("bearer:description".into(), "## Description <b>".into());
        let mut hostile = finding("bearer", "xss", Severity::High, "src/<b>.js", 2);
        hostile.url = Some("javascript:alert(1)".into());
        hostile.message = "\u{0}control\u{7}".into();
        let mut no_location = finding("luacheck", "W111", Severity::Low, "main.lua", 1);
        no_location.line = None;
        no_location.end_line = None;
        no_location.column = None;
        no_location.end_column = None;
        no_location.cwes = Vec::new();
        no_location.url = None;
        no_location.fingerprint = None;
        let mut suppressed = finding(
            "semgrep",
            "nosemgrep-ed",
            Severity::Critical,
            "src/app.js",
            9,
        );
        suppressed.suppressed = true;
        let findings = vec![
            merged,
            hostile,
            finding("semgrep", "csrf", Severity::Medium, "src/app.js", 2),
            no_location,
            finding("semgrep", "log", Severity::Info, "src/app.js", 6),
            suppressed,
        ];
        let mut semgrep = ToolRun::new("semgrep", Some("1.163.0".into()), ToolStatus::Completed);
        semgrep.findings = 9;
        semgrep.duration_ms = 1234;
        semgrep.scanned_files = Some(3);
        semgrep.skipped_paths = vec![SkippedPath {
            path: "vendor/big.min.js".into(),
            reason: "too large <1MB>".into(),
        }];
        semgrep.diagnostics = vec![Diagnostic {
            level: "warn".into(),
            rule_id: Some("rule.x".into()),
            path: Some("src/app.js".into()),
            message: "Internal matching error & more".into(),
        }];
        let mut bearer = ToolRun::new(
            "bearer",
            Some("2.1.1".into()),
            ToolStatus::Skipped {
                reason: "no <supported> files".into(),
            },
        );
        bearer.duration_ms = 10;
        let luacheck = ToolRun::new(
            "luacheck",
            None,
            ToolStatus::Failed {
                reason: "exit code 4".into(),
            },
        );
        Report::new(
            PathBuf::from("/work/project"),
            "2026-11-02T12:00:00Z".into(),
            vec![semgrep, bearer, luacheck],
            findings,
            3,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::sample_report;
    use super::*;

    #[test]
    fn escape_neutralises_markup_and_controls() {
        assert_eq!(
            escape(r#"<a href="x">&'</a>"#),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;"
        );
        assert_eq!(escape("tab\tnl\ncr\r"), "tab\tnl\ncr\r");
        assert_eq!(escape("a\u{0}b\u{7}c"), "a\u{FFFD}b\u{FFFD}c");
        assert_eq!(escape("plain"), "plain");
    }

    #[test]
    fn only_web_links_are_safe() {
        assert_eq!(safe_href("https://x.y/z"), Some("https://x.y/z"));
        assert_eq!(safe_href(" HTTP://x "), Some("HTTP://x"));
        assert_eq!(safe_href("javascript:alert(1)"), None);
        assert_eq!(safe_href("data:text/html,x"), None);
        assert_eq!(safe_href("https://x.y/a b"), None);
        assert_eq!(safe_href("https://x.y/\u{0}"), None);
        assert_eq!(safe_href("ftp://x"), None);
    }

    #[test]
    fn every_format_renders_the_sample_without_error() {
        let report = sample_report();
        for format in Format::ALL {
            let bytes = render(&report, format).unwrap();
            assert!(!bytes.is_empty(), "{format:?}");
            assert!(bytes.ends_with(b"\n"), "{format:?} must end with a newline");
        }
    }

    #[test]
    fn formats_have_extensions_and_are_guessed_from_paths() {
        assert_eq!(Format::Html.extension(), "html");
        assert_eq!(Format::from_path(Path::new("out.JSON")), Some(Format::Json));
        assert_eq!(Format::from_path(Path::new("out.yml")), Some(Format::Yaml));
        assert_eq!(Format::from_path(Path::new("out.htm")), Some(Format::Html));
        assert_eq!(Format::from_path(Path::new("out")), None);
        assert_eq!(Format::from_path(Path::new("out.sarif")), None);
    }

    #[test]
    fn atomic_write_creates_replaces_and_refuses_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        write_atomically(&path, b"one").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"one");
        write_atomically(&path, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert!(write_atomically(dir.path(), b"x").is_err());
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no temp file left behind"
        );
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_replaces_a_symlink_instead_of_following_it() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        let link = dir.path().join("report.json");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        write_atomically(&link, b"report").unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert!(!link.is_symlink());
        assert_eq!(std::fs::read(&link).unwrap(), b"report");
    }
}
