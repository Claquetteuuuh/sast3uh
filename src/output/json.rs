//! JSON: the model as is, pretty-printed.

use std::io::Write;

use crate::model::Report;
use crate::output::RenderError;

/// Write the JSON report.
///
/// # Errors
///
/// [`RenderError`] when serialisation or the write fails.
pub fn render(report: &Report, out: &mut impl Write) -> Result<(), RenderError> {
    serde_json::to_writer_pretty(&mut *out, report)?;
    writeln!(out)?;
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
        let back: Report = serde_json::from_slice(&out).unwrap();
        assert_eq!(back, report);
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value["schema_version"], 3);
        assert_eq!(value["summary"]["total"], 5);
        assert_eq!(value["summary"]["suppressed"], 1);
        assert_eq!(value["findings"][0]["flow"][0]["kind"], "source");
        assert_eq!(value["tools"][0]["diagnostics"][0]["rule_id"], "rule.x");
        assert_eq!(value["findings"][0]["also_reported_by"][0], "bearer");
        assert_eq!(value["tools"][1]["status"]["state"], "skipped");
    }
}
