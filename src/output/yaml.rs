//! YAML: the model as is.

use std::io::Write;

use crate::model::Report;
use crate::output::RenderError;

/// Write the YAML report.
///
/// # Errors
///
/// [`RenderError`] when serialisation or the write fails.
pub fn render(report: &Report, out: &mut impl Write) -> Result<(), RenderError> {
    let text = serde_saphyr::to_string(report).map_err(|e| RenderError::Yaml(e.to_string()))?;
    out.write_all(text.as_bytes())?;
    if !text.ends_with('\n') {
        writeln!(out)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::test_support::sample_report;

    #[test]
    fn round_trips_through_the_model() {
        let report = sample_report();
        let mut out = Vec::new();
        render(&report, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("schema_version: 3"), "{text}");
        assert!(text.contains("severity: critical"), "{text}");
        let back: Report = serde_saphyr::from_str(&text).unwrap();
        assert_eq!(back, report);
    }
}
