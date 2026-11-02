//! XML: a fixed, flat schema; every value escaped; nothing the model holds is left out.

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
        if let Some(reason) = reason {
            write!(out, r#" reason="{}""#, escape(reason))?;
        }
        if let Some(n) = run.scanned_files {
            write!(out, r#" scanned-files="{n}""#)?;
        }
        if run.skipped_paths.is_empty() && run.diagnostics.is_empty() {
            writeln!(out, "/>")?;
            continue;
        }
        writeln!(out, ">")?;
        for skipped in &run.skipped_paths {
            writeln!(
                out,
                r#"      <skipped-path reason="{}">{}</skipped-path>"#,
                escape(&skipped.reason),
                escape(&skipped.path)
            )?;
        }
        for d in &run.diagnostics {
            write!(out, r#"      <diagnostic level="{}""#, escape(&d.level))?;
            if let Some(rule) = &d.rule_id {
                write!(out, r#" rule-id="{}""#, escape(rule))?;
            }
            if let Some(path) = &d.path {
                write!(out, r#" path="{}""#, escape(path))?;
            }
            writeln!(out, ">{}</diagnostic>", escape(&d.message))?;
        }
        writeln!(out, "    </tool>")?;
    }
    writeln!(out, "  </tools>")?;
    let s = &report.summary;
    writeln!(
        out,
        r#"  <summary total="{}" critical="{}" high="{}" medium="{}" low="{}" info="{}" suppressed="{}" duplicates-removed="{}"/>"#,
        s.total, s.critical, s.high, s.medium, s.low, s.info, s.suppressed, s.duplicates_removed
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
    if let Some(confidence) = f.confidence {
        write!(out, r#" confidence="{confidence}""#)?;
    }
    if f.suppressed {
        write!(out, r#" suppressed="true""#)?;
    }
    for (name, value) in [
        ("line", f.line),
        ("end-line", f.end_line),
        ("column", f.column),
        ("end-column", f.end_column),
    ] {
        if let Some(value) = value {
            write!(out, r#" {name}="{value}""#)?;
        }
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
    for (element, item, list) in [
        ("owasp", "item", &f.owasp),
        ("categories", "category", &f.categories),
        ("tags", "tag", &f.tags),
        ("references", "reference", &f.references),
        ("also-reported-by", "tool", &f.also_reported_by),
    ] {
        if !list.is_empty() {
            write!(out, "      <{element}>")?;
            for value in list {
                write!(out, "<{item}>{}</{item}>", escape(value))?;
            }
            writeln!(out, "</{element}>")?;
        }
    }
    for (element, value) in [
        ("snippet", &f.snippet),
        ("fix", &f.fix),
        ("url", &f.url),
        ("fingerprint", &f.fingerprint),
    ] {
        if let Some(value) = value {
            writeln!(out, "      <{element}>{}</{element}>", escape(value))?;
        }
    }
    if !f.flow.is_empty() {
        writeln!(out, "      <flow>")?;
        for step in &f.flow {
            write!(
                out,
                r#"        <step kind="{}" path="{}""#,
                step.kind.as_str(),
                escape(&step.path.to_string_lossy())
            )?;
            for (name, value) in [
                ("line", step.line),
                ("end-line", step.end_line),
                ("column", step.column),
                ("end-column", step.end_column),
            ] {
                if let Some(value) = value {
                    write!(out, r#" {name}="{value}""#)?;
                }
            }
            match &step.content {
                Some(content) => writeln!(out, ">{}</step>", escape(content))?,
                None => writeln!(out, "/>")?,
            }
        }
        writeln!(out, "      </flow>")?;
    }
    if !f.extra.is_empty() {
        writeln!(out, "      <extra>")?;
        for (key, value) in &f.extra {
            writeln!(
                out,
                r#"        <field name="{}">{}</field>"#,
                escape(key),
                escape(value)
            )?;
        }
        writeln!(out, "      </extra>")?;
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
        assert!(xml.contains(r#"<sasteuuuh-report schema-version="2" generated-at="2026-11-02T12:00:00Z" target="/work/project">"#), "{xml}");
        assert!(xml.contains(r#"<tool name="bearer" version="2.1.1" state="skipped" findings="0" duration-ms="10" reason="no &lt;supported&gt; files"/>"#), "{xml}");
        assert!(xml.contains(r#"<tool name="semgrep" version="1.163.0" state="completed" findings="9" duration-ms="1234" scanned-files="3">"#), "{xml}");
        assert!(
            xml.contains(
                r#"<skipped-path reason="too large &lt;1MB&gt;">vendor/big.min.js</skipped-path>"#
            ),
            "{xml}"
        );
        assert!(xml.contains(r#"<diagnostic level="warn" rule-id="rule.x" path="src/app.js">Internal matching error &amp; more</diagnostic>"#), "{xml}");
        assert!(xml.contains(r#"<summary total="5" critical="1" high="1" medium="1" low="1" info="1" suppressed="1" duplicates-removed="3"/>"#), "{xml}");
        assert!(xml.contains(r#"<finding tool="semgrep" rule-id="eval" severity="critical" confidence="high" line="7" end-line="7" column="3" end-column="9">"#), "{xml}");
        assert!(xml.contains(r#"<finding tool="semgrep" rule-id="nosemgrep-ed" severity="critical" suppressed="true""#), "{xml}");
        assert!(xml.contains("<path>src/&lt;b&gt;.js</path>"), "{xml}");
        assert!(
            xml.contains(
                "<message>eval &lt;message&gt; &amp; &quot;quotes&quot; &#39;single&#39;</message>"
            ),
            "{xml}"
        );
        assert!(xml.contains("<cwes><cwe>79</cwe><cwe>95</cwe></cwes>"));
        assert!(
            xml.contains("<owasp><item>A03:2021 - Injection</item></owasp>"),
            "{xml}"
        );
        assert!(
            xml.contains(
                "<categories><category>security</category><category>PII</category></categories>"
            ),
            "{xml}"
        );
        assert!(xml.contains("<also-reported-by><tool>bearer</tool></also-reported-by>"));
        assert!(
            xml.contains("<snippet>eval(req.query.code); // &lt;script&gt;</snippet>"),
            "{xml}"
        );
        assert!(xml.contains("<fix>safeEval(code)</fix>"), "{xml}");
        assert!(xml.contains(r#"<step kind="source" path="src/app.js" line="5" column="25" end-column="28">req</step>"#), "{xml}");
        assert!(
            xml.contains(r#"<field name="bearer:description">## Description &lt;b&gt;</field>"#),
            "{xml}"
        );
        assert!(
            xml.contains("<message>\u{FFFD}control\u{FFFD}</message>"),
            "control characters are replaced"
        );
        assert!(xml.ends_with("</sasteuuuh-report>\n"));
        // No raw markup from the hostile strings survives.
        assert!(!xml.contains("<b>.js"));
        assert!(!xml.contains("<message> &"));
        assert!(!xml.contains("<script>"));
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
        assert!(!luacheck.contains("confidence="), "{luacheck}");
    }
}
