//! HTML: one self-contained page, no script, a CSP that forbids one, every value escaped.

use std::fmt::Write as _;
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
.chip { display: inline-block; border: 1px solid var(--line); border-radius: 10px; padding: 0 8px; margin: 2px 4px 2px 0; font-size: 12px; color: var(--muted); }
pre { margin: 6px 0 0; padding: 6px 8px; border: 1px solid var(--line); border-radius: 4px; overflow-x: auto; font: 12px/1.4 ui-monospace, monospace; white-space: pre-wrap; word-break: break-all; }
ol.flow { margin: 6px 0 0; padding-left: 20px; }
tr.suppressed td { opacity: 0.55; }
details { margin: 4px 0; } summary { cursor: pointer; color: var(--muted); }
.refs a { margin-right: 8px; }
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
        "<li><b>{}</b>suppressed</li>",
        report.summary.suppressed
    )?;
    writeln!(
        out,
        "<li><b>{}</b>duplicates removed</li>",
        report.summary.duplicates_removed
    )?;
    writeln!(out, "</ul>")?;

    write_tools(report, out)?;
    write_findings(report, out)?;
    writeln!(out, "</main></body></html>")
}

fn write_tools(report: &Report, out: &mut impl Write) -> std::io::Result<()> {
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
        let mut notes = String::new();
        if let Some(n) = run.scanned_files {
            let _ = write!(notes, " · {n} files scanned");
        }
        if !run.skipped_paths.is_empty() || !run.diagnostics.is_empty() {
            let _ = write!(
                notes,
                "<details><summary>{} skipped · {} diagnostics</summary><ul>",
                run.skipped_paths.len(),
                run.diagnostics.len()
            );
            for skipped in &run.skipped_paths {
                let _ = write!(
                    notes,
                    "<li>skipped <code>{}</code>: {}</li>",
                    escape(&skipped.path),
                    escape(&skipped.reason)
                );
            }
            for d in &run.diagnostics {
                let rule = d
                    .rule_id
                    .as_deref()
                    .map_or_else(String::new, |r| format!(" <code>{}</code>", escape(r)));
                let path = d
                    .path
                    .as_deref()
                    .map_or_else(String::new, |p| format!(" <code>{}</code>", escape(p)));
                let _ = write!(
                    notes,
                    "<li>{}{rule}{path}: {}</li>",
                    escape(&d.level),
                    escape(&d.message)
                );
            }
            notes.push_str("</ul></details>");
        }
        writeln!(
            out,
            r#"<tr><td>{}</td><td>{}</td><td>{status}{notes}</td><td>{}</td><td class="opt">{} ms</td></tr>"#,
            escape(&run.tool),
            escape(run.version.as_deref().unwrap_or("-")),
            run.findings,
            run.duration_ms
        )?;
    }
    writeln!(out, "</tbody></table>")
}

fn location_of(path: &std::path::Path, line: Option<u32>, column: Option<u32>) -> String {
    match (line, column) {
        (Some(line), Some(column)) => format!("{}:{line}:{column}", path.display()),
        (Some(line), None) => format!("{}:{line}", path.display()),
        _ => path.display().to_string(),
    }
}

fn write_findings(report: &Report, out: &mut impl Write) -> std::io::Result<()> {
    writeln!(out, "<h2>Findings ({})</h2>", report.summary.total)?;
    writeln!(
        out,
        "<table><thead><tr><th>Severity</th><th>Location</th><th>Tool</th><th>Rule</th><th class=\"opt\">CWE</th></tr></thead><tbody>"
    )?;
    for f in &report.findings {
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
        let mut body = format!(
            "{rule}<br><b>{}</b><br><span class=\"msg\">{}</span>",
            escape(&f.title),
            escape(&f.message)
        );
        let chips: Vec<String> = f
            .confidence
            .iter()
            .map(|c| format!("confidence {c}"))
            .chain(f.owasp.iter().cloned())
            .chain(f.categories.iter().cloned())
            .chain(f.tags.iter().cloned())
            .map(|c| format!(r#"<span class="chip">{}</span>"#, escape(&c)))
            .collect();
        if !chips.is_empty() {
            body.push_str("<br>");
            body.push_str(&chips.concat());
        }
        if let Some(snippet) = &f.snippet {
            let _ = write!(body, "<pre>{}</pre>", escape(snippet));
        }
        if !f.flow.is_empty() {
            body.push_str(r#"<ol class="flow">"#);
            for step in &f.flow {
                let content = step
                    .content
                    .as_deref()
                    .map_or_else(String::new, |c| format!(" <code>{}</code>", escape(c)));
                let _ = write!(
                    body,
                    "<li>{} <code>{}</code>{content}</li>",
                    step.kind.as_str(),
                    escape(&location_of(&step.path, step.line, step.column))
                );
            }
            body.push_str("</ol>");
        }
        if let Some(fix) = &f.fix {
            let _ = write!(
                body,
                "<details><summary>suggested fix</summary><pre>{}</pre></details>",
                escape(fix)
            );
        }
        let refs: Vec<String> = f
            .references
            .iter()
            .filter_map(|r| safe_href(r))
            .map(|href| {
                format!(
                    r#"<a href="{0}" rel="noopener noreferrer">{0}</a>"#,
                    escape(href)
                )
            })
            .collect();
        if !refs.is_empty() {
            let _ = write!(
                body,
                r#"<details class="refs"><summary>{} reference(s)</summary>{}</details>"#,
                refs.len(),
                refs.join(" ")
            );
        }
        if !f.extra.is_empty() {
            body.push_str("<details><summary>more from the scanner</summary><ul>");
            for (key, value) in &f.extra {
                let _ = write!(body, "<li><b>{}</b>: {}</li>", escape(key), escape(value));
            }
            body.push_str("</ul></details>");
        }
        let cwes: Vec<String> = f.cwes.iter().map(|c| format!("CWE-{c}")).collect();
        let row_class = if f.suppressed {
            " class=\"suppressed\""
        } else {
            ""
        };
        let sev_label = if f.suppressed {
            format!("{} (suppressed)", f.severity)
        } else {
            f.severity.to_string()
        };
        writeln!(
            out,
            r#"<tr{row_class}><td class="sev {sev}">{sev_label}</td><td><code>{location}</code></td><td>{tools}</td><td>{body}</td><td class="opt">{cwes}</td></tr>"#,
            sev = f.severity,
            location = escape(&location_of(&f.path, f.line, f.column)),
            cwes = cwes.join(", ")
        )?;
    }
    writeln!(out, "</tbody></table>")
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
        assert!(
            html.contains(
                r#"<tr class="suppressed"><td class="sev critical">critical (suppressed)</td>"#
            ),
            "{html}"
        );
        assert!(
            html.contains(r#"<span class="chip">confidence high</span>"#),
            "{html}"
        );
        assert!(
            html.contains(r#"<span class="chip">A03:2021 - Injection</span>"#),
            "{html}"
        );
        assert!(
            html.contains("<pre>eval(req.query.code); // &lt;script&gt;</pre>"),
            "{html}"
        );
        assert!(
            html.contains("<li>source <code>src/app.js:5:25</code> <code>req</code></li>"),
            "{html}"
        );
        assert!(
            html.contains(
                "<li>sink <code>src/app.js:7:3</code> <code>eval(code) &amp; co</code></li>"
            ),
            "{html}"
        );
        assert!(
            html.contains("<summary>suggested fix</summary><pre>safeEval(code)</pre>"),
            "{html}"
        );
        assert!(
            html.contains("<li><b>bearer:description</b>: ## Description &lt;b&gt;</li>"),
            "{html}"
        );
        assert!(
            html.contains("<li>skipped <code>vendor/big.min.js</code>: too large &lt;1MB&gt;</li>"),
            "{html}"
        );
        assert!(html.contains("<li>warn <code>rule.x</code> <code>src/app.js</code>: Internal matching error &amp; more</li>"), "{html}");
        assert!(html.contains("<li><b>1</b>suppressed</li>"), "{html}");
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
            "a javascript: url must not be linked, in references either: {html}"
        );
        assert!(
            html.contains(
                r#"<a href="https://owasp.org/x" rel="noopener noreferrer">https://owasp.org/x</a>"#
            ),
            "{html}"
        );
        assert!(
            html.contains("xss<br>"),
            "the unlinked rule id is still shown: {html}"
        );
    }
}
