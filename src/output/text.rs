//! The human-readable report.

use std::io::Write;

use crate::model::{Finding, Report, Severity, ToolStatus};

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
    write_tools(report, out)?;
    write_findings(report, out)
}

/// The tools section.
fn write_tools(report: &Report, out: &mut impl Write) -> std::io::Result<()> {
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
    Ok(())
}

/// The findings, grouped by rule, then what was set aside and the summary line.
fn write_findings(report: &Report, out: &mut impl Write) -> std::io::Result<()> {
    writeln!(out)?;
    let set_aside = if report.summary.filtered > 0 {
        format!(", {} set aside", report.summary.filtered)
    } else {
        String::new()
    };
    writeln!(
        out,
        "Findings ({} unique, {} duplicate{} removed{set_aside})",
        report.summary.total,
        report.summary.duplicates_removed,
        plural(report.summary.duplicates_removed)
    )?;
    let active: Vec<&Finding> = report.findings.iter().filter(|f| f.is_active()).collect();
    for group in groups(&active) {
        if group.len() < GROUP_MIN {
            for f in group {
                write_line(f, out)?;
            }
            continue;
        }
        let Some(first) = group.first() else {
            continue;
        };
        writeln!(
            out,
            "  {:<8} {} [{}] {} — {} findings",
            first.severity,
            first.tool,
            first.rule_id,
            first.title,
            group.len()
        )?;
        let mut locations: Vec<String> = group
            .iter()
            .take(GROUP_SHOWN)
            .map(|f| location(f))
            .collect();
        if group.len() > GROUP_SHOWN {
            locations.push(format!(
                "… and {} more (see the JSON report)",
                group.len() - GROUP_SHOWN
            ));
        }
        for chunk in wrap(&locations, 100) {
            writeln!(out, "           {chunk}")?;
        }
    }
    let suppressed: Vec<&Finding> = report.findings.iter().filter(|f| f.suppressed).collect();
    for f in suppressed {
        write_line(f, out)?;
    }
    let mut reasons: Vec<(String, usize)> = Vec::new();
    for f in report.findings.iter().filter(|f| !f.suppressed) {
        if let Some(reason) = &f.filtered {
            match reasons.iter_mut().find(|(r, _)| r == reason) {
                Some((_, n)) => *n += 1,
                None => reasons.push((reason.clone(), 1)),
            }
        }
    }
    if !reasons.is_empty() {
        writeln!(out)?;
        writeln!(
            out,
            "Set aside ({}, in the JSON report, not counted):",
            report.summary.filtered
        )?;
        for (reason, n) in reasons {
            writeln!(out, "  {n:>6}  {reason}")?;
        }
    }
    writeln!(out)?;
    let counts: Vec<String> = Severity::DESCENDING
        .iter()
        .map(|s| format!("{} {s}", report.summary.count(*s)))
        .collect();
    writeln!(
        out,
        "Summary: {} · {} suppressed · {} set aside",
        counts.join(" · "),
        report.summary.suppressed,
        report.summary.filtered
    )
}

/// A rule with at least this many findings of one severity is listed once, with its
/// locations.
const GROUP_MIN: usize = 4;
/// Locations shown for a grouped rule.
const GROUP_SHOWN: usize = 60;

/// `path:line:column`.
fn location(f: &Finding) -> String {
    let line = f.line.map_or_else(String::new, |l| format!(":{l}"));
    let column = f.column.map_or_else(String::new, |c| format!(":{c}"));
    format!("{}{line}{column}", f.path.display())
}

/// One finding on one line.
fn write_line(f: &Finding, out: &mut impl Write) -> std::io::Result<()> {
    let also = if f.also_reported_by.is_empty() {
        String::new()
    } else {
        format!(" (+{})", f.also_reported_by.join(", +"))
    };
    let flow = if f.flow.is_empty() { "" } else { " ~flow" };
    let suppressed = if f.suppressed { " (suppressed)" } else { "" };
    writeln!(
        out,
        "  {:<8} {}  {}{also}{flow}  [{}] {}{suppressed}",
        f.severity,
        location(f),
        f.tool,
        f.rule_id,
        f.title
    )
}

/// Consecutive runs of findings of one severity, tool and rule, in report order (a rule's
/// findings are gathered under its first appearance).
pub(crate) fn groups<'a>(findings: &[&'a Finding]) -> Vec<Vec<&'a Finding>> {
    let mut out: Vec<Vec<&'a Finding>> = Vec::new();
    let mut index: Vec<((Severity, &str, &str), usize)> = Vec::new();
    for f in findings {
        let key = (f.severity, f.tool.as_str(), f.rule_id.as_str());
        if let Some((_, at)) = index.iter().find(|(k, _)| *k == key) {
            if let Some(group) = out.get_mut(*at) {
                group.push(f);
            }
        } else {
            index.push((key, out.len()));
            out.push(vec![f]);
        }
    }
    out
}

/// Comma-separated items wrapped at about `width` characters per line.
fn wrap(items: &[String], width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for item in items {
        if !current.is_empty() && current.len() + item.len() + 2 > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push_str(", ");
        }
        current.push_str(item);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
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
            text.contains("critical src/app.js:7:3  semgrep (+bearer)")
                && text.contains("[eval] eval title"),
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
                "Summary: 1 critical · 1 high · 1 medium · 1 low · 1 info · 1 suppressed · 0 set aside\n"
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

    #[test]
    fn a_frequent_rule_is_grouped_and_set_aside_findings_are_summarised() {
        use crate::model::test_support::finding;
        let mut findings: Vec<Finding> = (1..=5)
            .map(|i| {
                finding(
                    "semgrep",
                    "jquery.insecure-selector",
                    Severity::Medium,
                    &format!("js/f{i}.js"),
                    i,
                )
            })
            .collect();
        findings.push(finding("bearer", "sqli", Severity::High, "src/db.php", 9));
        let mut aside = finding("semgrep", "weak", Severity::Low, "src/x.php", 2);
        aside.filtered = Some("confidence low below medium".to_owned());
        findings.push(aside.clone());
        findings.push(aside);
        let report = Report::new(
            "/work".into(),
            "2026-11-03T00:00:00Z".to_owned(),
            Vec::new(),
            findings,
            0,
        );
        let mut out = Vec::new();
        render(&report, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("Findings (6 unique, 0 duplicates removed, 2 set aside)"),
            "{text}"
        );
        assert!(
            text.contains(
                "medium   semgrep [jquery.insecure-selector] jquery.insecure-selector — 5 findings"
            ),
            "{text}"
        );
        assert!(
            text.contains("js/f1.js:1, js/f2.js:2, js/f3.js:3, js/f4.js:4, js/f5.js:5"),
            "{text}"
        );
        assert!(
            text.contains("high     src/db.php:9  bearer  [sqli]"),
            "{text}"
        );
        assert!(
            text.contains("Set aside (2, in the JSON report, not counted):"),
            "{text}"
        );
        assert!(
            text.contains("     2  confidence low below medium"),
            "{text}"
        );
        assert!(
            !text.contains("src/x.php"),
            "set-aside findings are summarised, not listed: {text}"
        );
        assert!(text.ends_with("· 0 suppressed · 2 set aside\n"), "{text}");
        let many: Vec<String> = (0..70).map(|i| format!("f{i}")).collect();
        let lines = wrap(&many, 40);
        assert!(
            lines.len() > 3 && lines.iter().all(|l| l.len() <= 42),
            "{lines:?}"
        );
    }
}
