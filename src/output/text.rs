//! The human-readable report.

use std::io::Write;

use crate::model::{Report, Severity, ToolStatus};

/// Write the text report.
///
/// # Errors
///
/// The I/O error of `out`.
pub fn render(report: &Report, out: &mut impl Write) -> std::io::Result<()> {
    writeln!(
        out,
        "sast3uh report — {} ({})",
        report.target.display(),
        report.generated_at
    )?;
    writeln!(out)?;
    writeln!(out, "Tools")?;
    for run in &report.tools {
        let version = run.version.as_deref().unwrap_or("-");
        let (state, detail) = match &run.status {
            ToolStatus::Completed => (
                "completed",
                format!("{} finding{}", run.findings, plural(run.findings)),
            ),
            ToolStatus::Skipped { reason } => ("skipped", reason.clone()),
            ToolStatus::Failed { reason } => ("FAILED", reason.clone()),
        };
        let mut details = Vec::new();
        if let Some(n) = run.scanned_files {
            details.push(format!("{n} file{} scanned", plural(n)));
        }
        if !run.skipped_paths.is_empty() {
            details.push(format!("{} skipped by the tool", run.skipped_paths.len()));
        }
        if !run.diagnostics.is_empty() {
            details.push(format!(
                "{} diagnostic{}",
                run.diagnostics.len(),
                plural(run.diagnostics.len())
            ));
        }
        let details = if details.is_empty() {
            String::new()
        } else {
            format!(" · {}", details.join(" · "))
        };
        writeln!(
            out,
            "  {:<10} {:<10} {:<10} {detail}{details}  [{}]",
            run.tool,
            version,
            state,
            duration(run.duration_ms)
        )?;
        for d in &run.diagnostics {
            let rule = d
                .rule_id
                .as_deref()
                .map_or_else(String::new, |r| format!(" [{r}]"));
            let path = d
                .path
                .as_deref()
                .map_or_else(String::new, |p| format!(" {p}:"));
            writeln!(out, "             {}{rule}{path} {}", d.level, d.message)?;
        }
        for skipped in &run.skipped_paths {
            writeln!(
                out,
                "             skipped {} ({})",
                skipped.path, skipped.reason
            )?;
        }
    }
    writeln!(out)?;
    writeln!(
        out,
        "Findings ({} unique, {} duplicate{} removed)",
        report.summary.total,
        report.summary.duplicates_removed,
        plural(report.summary.duplicates_removed)
    )?;
    for f in &report.findings {
        let line = f.line.map_or_else(String::new, |l| format!(":{l}"));
        let column = f.column.map_or_else(String::new, |c| format!(":{c}"));
        let also = if f.also_reported_by.is_empty() {
            String::new()
        } else {
            format!(" (+{})", f.also_reported_by.join(", +"))
        };
        let suppressed = if f.suppressed { " (suppressed)" } else { "" };
        writeln!(
            out,
            "  {:<8} {}{line}{column}  {}{also}  [{}] {}{suppressed}",
            f.severity,
            f.path.display(),
            f.tool,
            f.rule_id,
            f.title
        )?;
    }
    writeln!(out)?;
    let counts: Vec<String> = Severity::DESCENDING
        .iter()
        .map(|s| format!("{} {s}", report.summary.count(*s)))
        .collect();
    writeln!(
        out,
        "Summary: {} · {} suppressed",
        counts.join(" · "),
        report.summary.suppressed
    )
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

fn duration(ms: u64) -> String {
    if ms >= 1000 {
        format!("{}.{}s", ms / 1000, (ms % 1000) / 100)
    } else {
        format!("{ms}ms")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::test_support::sample_report;

    #[test]
    fn lists_tools_findings_and_counts() {
        let mut out = Vec::new();
        render(&sample_report(), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("semgrep    1.163.0    completed  9 findings · 3 files scanned · 1 skipped by the tool · 1 diagnostic  [1.2s]"),
            "{text}"
        );
        assert!(
            text.contains("warn [rule.x] src/app.js: Internal matching error & more"),
            "{text}"
        );
        assert!(
            text.contains("skipped vendor/big.min.js (too large <1MB>)"),
            "{text}"
        );
        assert!(
            text.contains("bearer     2.1.1      skipped    no <supported> files"),
            "{text}"
        );
        assert!(
            text.contains("luacheck   -          FAILED     exit code 4"),
            "{text}"
        );
        assert!(
            text.contains("Findings (5 unique, 3 duplicates removed)"),
            "{text}"
        );
        assert!(
            text.contains("critical src/app.js:7:3  semgrep (+bearer)  [eval] eval title"),
            "{text}"
        );
        assert!(
            text.contains("low      main.lua  luacheck  [W111]"),
            "{text}"
        );
        assert!(
            text.contains("[nosemgrep-ed] nosemgrep-ed title (suppressed)"),
            "{text}"
        );
        assert!(
            text.ends_with(
                "Summary: 1 critical · 1 high · 1 medium · 1 low · 1 info · 1 suppressed\n"
            ),
            "{text}"
        );
    }

    #[test]
    fn durations_and_plurals() {
        assert_eq!(duration(5), "5ms");
        assert_eq!(duration(1234), "1.2s");
        assert_eq!(plural(1), "");
        assert_eq!(plural(0), "s");
    }
}
