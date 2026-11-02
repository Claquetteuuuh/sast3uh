//! HTML: one self-contained page, no script, a CSP that forbids one, every value escaped.

use std::io::Write;

use crate::model::{Report, Severity, ToolStatus};
use crate::output::{escape, safe_href};

const STYLE: &str = r"
:root { color-scheme: light dark; --bg: #fff; --fg: #1b1f24; --muted: #57606a; --line: #d0d7de; --critical: #a40e26; --high: #cf222e; --medium: #bf8700; --low: #0969da; --info: #57606a; }
@media (prefers-color-scheme: dark) { :root { --bg: #0d1117; --fg: #e6edf3; --muted: #8d96a0; --line: #30363d; --critical: #ff7b72; --high: #f85149; --medium: #d29922; --low: #58a6ff; --info: #8d96a0; } }
body { margin: 0; padding: 24px 16px; background: var(--bg); color: var(--fg); font: 14px/1.5 system-ui, sans-serif; }
main { max-width: 1200px; margin: 0 auto; }
h1 { font-size: 20px; margin: 0 0 4px; }
.meta { color: var(--muted); margin: 0 0 20px; word-break: break-all; }
.counts { display: flex; flex-wrap: wrap; gap: 8px; margin: 0 0 20px; padding: 0; list-style: none; }
.counts li { border: 1px solid var(--line); border-radius: 6px; padding: 6px 12px; }
.counts b { font-size: 18px; margin-right: 6px; }
table { border-collapse: collapse; width: 100%; margin-bottom: 24px; }
th, td { text-align: left; vertical-align: top; padding: 6px 8px; border-bottom: 1px solid var(--line); }
th { color: var(--muted); font-weight: 600; }
td.sev { font-weight: 700; text-transform: uppercase; white-space: nowrap; }
.critical { color: var(--critical); } .high { color: var(--high); } .medium { color: var(--medium); } .low { color: var(--low); } .info { color: var(--info); }
code { font: 12px/1.4 ui-monospace, monospace; word-break: break-all; }
.msg { color: var(--muted); }
.failed { color: var(--high); font-weight: 600; }
@media (max-width: 700px) { th.opt, td.opt { display: none; } }
";

/// Write the HTML report.
///
/// # Errors
///
/// The I/O error of `out`.
pub fn render(report: &Report, out: &mut impl Write) -> std::io::Result<()> {
    writeln!(out, "<!doctype html>")?;
    writeln!(out, r#"<html lang="en">"#)?;
    writeln!(out, "<head>")?;
    writeln!(out, r#"<meta charset="utf-8">"#)?;
    writeln!(
        out,
        r#"<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">"#
    )?;
    writeln!(
        out,
        r#"<meta name="viewport" content="width=device-width, initial-scale=1">"#
    )?;
    writeln!(out, "<title>sasteuuuh report</title>")?;
    writeln!(out, "<style>{STYLE}</style>")?;
    writeln!(out, "</head>")?;
    writeln!(out, "<body><main>")?;
    writeln!(out, "<h1>sasteuuuh report</h1>")?;
    writeln!(
        out,
        r#"<p class="meta"><code>{}</code> · {}</p>"#,
        escape(&report.target.to_string_lossy()),
        escape(&report.generated_at)
    )?;

    writeln!(out, r#"<ul class="counts">"#)?;
    for severity in Severity::DESCENDING {
        writeln!(
            out,
            r#"<li class="{severity}"><b>{}</b>{severity}</li>"#,
            report.summary.count(severity)
        )?;
    }
    writeln!(
        out,
        "<li><b>{}</b>duplicates removed</li>",
        report.summary.duplicates_removed
    )?;
    writeln!(out, "</ul>")?;

    writeln!(out, "<h2>Tools</h2>")?;
    writeln!(
        out,
        "<table><thead><tr><th>Tool</th><th>Version</th><th>Status</th><th>Findings</th><th class=\"opt\">Duration</th></tr></thead><tbody>"
    )?;
    for run in &report.tools {
        let status = match &run.status {
            ToolStatus::Completed => "completed".to_owned(),
            ToolStatus::Skipped { reason } => format!("skipped — {}", escape(reason)),
            ToolStatus::Failed { reason } => {
                format!(r#"<span class="failed">failed</span> — {}"#, escape(reason))
            }
        };
        writeln!(
            out,
            r#"<tr><td>{}</td><td>{}</td><td>{status}</td><td>{}</td><td class="opt">{} ms</td></tr>"#,
            escape(&run.tool),
            escape(run.version.as_deref().unwrap_or("-")),
            run.findings,
            run.duration_ms
        )?;
    }
    writeln!(out, "</tbody></table>")?;

    writeln!(out, "<h2>Findings ({})</h2>", report.summary.total)?;
    writeln!(
        out,
        "<table><thead><tr><th>Severity</th><th>Location</th><th>Tool</th><th>Rule</th><th class=\"opt\">CWE</th></tr></thead><tbody>"
    )?;
    for f in &report.findings {
        let location = match (f.line, f.column) {
            (Some(line), Some(column)) => format!("{}:{line}:{column}", f.path.display()),
            (Some(line), None) => format!("{}:{line}", f.path.display()),
            _ => f.path.display().to_string(),
        };
        let tools = if f.also_reported_by.is_empty() {
            escape(&f.tool)
        } else {
            format!(
                "{} <span class=\"msg\">(+{})</span>",
                escape(&f.tool),
                escape(&f.also_reported_by.join(", "))
            )
        };
        let rule = match f.url.as_deref().and_then(safe_href) {
            Some(href) => format!(
                r#"<a href="{}" rel="noopener noreferrer">{}</a>"#,
                escape(href),
                escape(&f.rule_id)
            ),
            None => escape(&f.rule_id),
        };
        let cwes: Vec<String> = f.cwes.iter().map(|c| format!("CWE-{c}")).collect();
        writeln!(
            out,
            r#"<tr><td class="sev {sev}">{sev}</td><td><code>{location}</code></td><td>{tools}</td><td>{rule}<br><b>{title}</b><br><span class="msg">{message}</span></td><td class="opt">{cwes}</td></tr>"#,
            sev = f.severity,
            location = escape(&location),
            title = escape(&f.title),
            message = escape(&f.message),
            cwes = cwes.join(", ")
        )?;
    }
    writeln!(out, "</tbody></table>")?;
    writeln!(out, "</main></body></html>")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::test_support::sample_report;

    #[test]
    fn is_self_contained_script_free_and_escaped() {
        let mut out = Vec::new();
        render(&sample_report(), &mut out).unwrap();
        let html = String::from_utf8(out).unwrap();
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("Content-Security-Policy"));
        assert!(html.contains("default-src 'none'"));
        assert!(!html.contains("<script"), "no script, ever");
        assert!(!html.contains("src=\"http"), "no external resource");
        assert!(html.contains("<code>src/&lt;b&gt;.js:2:3</code>"), "{html}");
        assert!(
            html.contains("eval &lt;message&gt; &amp; &quot;quotes&quot; &#39;single&#39;"),
            "{html}"
        );
        assert!(
            html.contains("skipped — no &lt;supported&gt; files"),
            "{html}"
        );
        assert!(html.contains("(+bearer)"), "{html}");
        assert!(html.contains("CWE-79, CWE-95"), "{html}");
        assert!(
            html.contains(r#"<td class="sev critical">critical</td>"#),
            "{html}"
        );
        assert!(html.ends_with("</html>\n"));
    }

    #[test]
    fn links_only_to_web_urls() {
        let mut out = Vec::new();
        render(&sample_report(), &mut out).unwrap();
        let html = String::from_utf8(out).unwrap();
        assert!(
            html.contains(
                r#"<a href="https://example.com/rule" rel="noopener noreferrer">eval</a>"#
            ),
            "{html}"
        );
        assert!(
            !html.contains("javascript:"),
            "a javascript: url must not be linked: {html}"
        );
        assert!(
            html.contains("xss<br>"),
            "the unlinked rule id is still shown: {html}"
        );
    }
}
