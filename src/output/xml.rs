//! XML: a fixed, flat schema; every value escaped.

use std::io::Write;

use crate::model::{Finding, Report, ToolStatus};
use crate::output::escape;

/// Write the XML report.
///
/// # Errors
///
/// The I/O error of `out`.
pub fn render(report: &Report, out: &mut impl Write) -> std::io::Result<()> {
    writeln!(out, r#"<?xml version="1.0" encoding="UTF-8"?>"#)?;
    writeln!(
        out,
        r#"<sasteuuuh-report schema-version="{}" generated-at="{}" target="{}">"#,
        report.schema_version,
        escape(&report.generated_at),
        escape(&report.target.to_string_lossy())
    )?;
    writeln!(out, "  <tools>")?;
    for run in &report.tools {
        let (state, reason) = match &run.status {
            ToolStatus::Completed => ("completed", None),
            ToolStatus::Skipped { reason } => ("skipped", Some(reason)),
            ToolStatus::Failed { reason } => ("failed", Some(reason)),
        };
        write!(
            out,
            r#"    <tool name="{}" version="{}" state="{state}" findings="{}" duration-ms="{}""#,
            escape(&run.tool),
            escape(run.version.as_deref().unwrap_or("")),
            run.findings,
            run.duration_ms
        )?;
        match reason {
            Some(reason) => writeln!(out, r#" reason="{}"/>"#, escape(reason))?,
            None => writeln!(out, "/>")?,
        }
    }
    writeln!(out, "  </tools>")?;
    let s = &report.summary;
    writeln!(
        out,
        r#"  <summary total="{}" critical="{}" high="{}" medium="{}" low="{}" info="{}" duplicates-removed="{}"/>"#,
        s.total, s.critical, s.high, s.medium, s.low, s.info, s.duplicates_removed
    )?;
    writeln!(out, "  <findings>")?;
    for f in &report.findings {
        write_finding(f, out)?;
    }
    writeln!(out, "  </findings>")?;
    writeln!(out, "</sasteuuuh-report>")
}

fn write_finding(f: &Finding, out: &mut impl Write) -> std::io::Result<()> {
    write!(
        out,
        r#"    <finding tool="{}" rule-id="{}" severity="{}""#,
        escape(&f.tool),
        escape(&f.rule_id),
        f.severity
    )?;
    if let Some(line) = f.line {
        write!(out, r#" line="{line}""#)?;
    }
    if let Some(end) = f.end_line {
        write!(out, r#" end-line="{end}""#)?;
    }
    if let Some(column) = f.column {
        write!(out, r#" column="{column}""#)?;
    }
    writeln!(out, ">")?;
    writeln!(
        out,
        "      <path>{}</path>",
        escape(&f.path.to_string_lossy())
    )?;
    writeln!(out, "      <title>{}</title>", escape(&f.title))?;
    writeln!(out, "      <message>{}</message>", escape(&f.message))?;
    if !f.cwes.is_empty() {
        write!(out, "      <cwes>")?;
        for cwe in &f.cwes {
            write!(out, "<cwe>{cwe}</cwe>")?;
        }
        writeln!(out, "</cwes>")?;
    }
    if !f.also_reported_by.is_empty() {
        write!(out, "      <also-reported-by>")?;
        for tool in &f.also_reported_by {
            write!(out, "<tool>{}</tool>", escape(tool))?;
        }
        writeln!(out, "</also-reported-by>")?;
    }
    if let Some(url) = &f.url {
        writeln!(out, "      <url>{}</url>", escape(url))?;
    }
    if let Some(fp) = &f.fingerprint {
        writeln!(out, "      <fingerprint>{}</fingerprint>", escape(fp))?;
    }
    writeln!(out, "    </finding>")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::test_support::sample_report;

    #[test]
    fn writes_the_structure_with_every_value_escaped() {
        let mut out = Vec::new();
        render(&sample_report(), &mut out).unwrap();
        let xml = String::from_utf8(out).unwrap();
        assert!(xml.starts_with("<?xml version=\"1.0\""));
        assert!(xml.contains(r#"<sasteuuuh-report schema-version="1" generated-at="2026-11-02T12:00:00Z" target="/work/project">"#));
        assert!(xml.contains(r#"<tool name="bearer" version="2.1.1" state="skipped" findings="0" duration-ms="10" reason="no &lt;supported&gt; files"/>"#), "{xml}");
        assert!(xml.contains(r#"<summary total="5" critical="1" high="1" medium="1" low="1" info="1" duplicates-removed="3"/>"#));
        assert!(xml.contains(r#"<finding tool="semgrep" rule-id="eval" severity="critical" line="7" end-line="7" column="3">"#));
        assert!(xml.contains("<path>src/&lt;b&gt;.js</path>"), "{xml}");
        assert!(
            xml.contains(
                "<message>eval &lt;message&gt; &amp; &quot;quotes&quot; &#39;single&#39;</message>"
            ),
            "{xml}"
        );
        assert!(xml.contains("<cwes><cwe>79</cwe><cwe>95</cwe></cwes>"));
        assert!(xml.contains("<also-reported-by><tool>bearer</tool></also-reported-by>"));
        assert!(
            xml.contains("<message>\u{FFFD}control\u{FFFD}</message>"),
            "control characters are replaced"
        );
        assert!(xml.ends_with("</sasteuuuh-report>\n"));
        // No raw markup from the hostile strings survives.
        assert!(!xml.contains("<b>.js"));
        assert!(!xml.contains("<message> &"));
    }

    #[test]
    fn omits_absent_optionals() {
        let mut out = Vec::new();
        render(&sample_report(), &mut out).unwrap();
        let xml = String::from_utf8(out).unwrap();
        let luacheck = xml
            .lines()
            .find(|l| l.contains(r#"tool="luacheck" rule-id="W111""#))
            .unwrap();
        assert!(!luacheck.contains("line="), "{luacheck}");
        assert!(!luacheck.contains("column="), "{luacheck}");
    }
}
