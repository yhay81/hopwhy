use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::engine::digest_report;
use crate::error::{AppError, AppResult, ErrorClass};
use crate::model::{
    CompareResult, PhaseDifference, PhaseName, ReplayResult, Report, COMPARE_SCHEMA_VERSION,
    REPLAY_SCHEMA_VERSION, REPORT_SCHEMA_VERSION,
};

const MAX_REPORT_BYTES: u64 = 8 * 1024 * 1024;

pub fn load_report(path: &Path) -> AppResult<Report> {
    let metadata = fs::metadata(path).map_err(|error| {
        AppError::new(
            ErrorClass::Io,
            "report_metadata_failed",
            format!("could not inspect report {}: {error}", path.display()),
        )
    })?;
    if !metadata.is_file() {
        return Err(AppError::new(
            ErrorClass::Io,
            "report_not_regular_file",
            format!("report {} is not a regular file", path.display()),
        ));
    }
    if metadata.len() > MAX_REPORT_BYTES {
        return Err(AppError::new(
            ErrorClass::Budget,
            "report_too_large",
            format!(
                "report {} exceeds the {} byte offline limit",
                path.display(),
                MAX_REPORT_BYTES
            ),
        ));
    }
    let bytes = fs::read(path).map_err(|error| {
        AppError::new(
            ErrorClass::Io,
            "report_read_failed",
            format!("could not read report {}: {error}", path.display()),
        )
    })?;
    parse_report_document_with_label(&bytes, &path.display().to_string())
}

/// Parses and verifies one bounded offline report without performing file I/O.
///
/// # Errors
///
/// Returns an error when the document is oversized, malformed, uses an
/// unsupported schema, or fails its integrity digest.
pub fn parse_report_document(bytes: &[u8]) -> AppResult<Report> {
    parse_report_document_with_label(bytes, "report document")
}

fn parse_report_document_with_label(bytes: &[u8], label: &str) -> AppResult<Report> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_REPORT_BYTES {
        return Err(AppError::new(
            ErrorClass::Budget,
            "report_too_large",
            format!("report exceeds the {MAX_REPORT_BYTES} byte offline limit"),
        ));
    }
    let report: Report = serde_json::from_slice(bytes).map_err(|error| {
        AppError::new(
            ErrorClass::Contract,
            "invalid_report_json",
            format!("{label} is not a HopWhy report: {error}"),
        )
    })?;
    verify_report(&report)?;
    Ok(report)
}

pub fn verify_report(report: &Report) -> AppResult<()> {
    if report.schema_version != REPORT_SCHEMA_VERSION {
        return Err(AppError::new(
            ErrorClass::Contract,
            "unsupported_report_schema",
            format!(
                "expected {REPORT_SCHEMA_VERSION}, found {}",
                report.schema_version
            ),
        ));
    }
    let expected = report.report_sha256.as_deref().ok_or_else(|| {
        AppError::new(
            ErrorClass::Contract,
            "missing_report_digest",
            "report_sha256 is required for offline operations",
        )
    })?;
    let actual = digest_report(report)?;
    if expected != actual {
        return Err(AppError::new(
            ErrorClass::Contract,
            "report_integrity_mismatch",
            "report_sha256 does not match the report content",
        ));
    }
    Ok(())
}

pub fn replay(report: &Report) -> AppResult<ReplayResult> {
    verify_report(report)?;
    let phase_statuses = report
        .phases
        .iter()
        .map(|phase| (phase_key(phase.name).to_owned(), phase.status))
        .collect::<BTreeMap<_, _>>();
    let next_safe_steps = report
        .hypotheses
        .iter()
        .map(|hypothesis| hypothesis.next_safe_step.clone())
        .collect();

    Ok(ReplayResult {
        schema_version: REPLAY_SCHEMA_VERSION.to_owned(),
        report_sha256: report.report_sha256.clone().unwrap_or_default(),
        integrity_valid: true,
        network_performed: false,
        failed_at: report.failed_at,
        phase_statuses,
        hypotheses: report.hypotheses.clone(),
        next_safe_steps,
    })
}

pub fn compare(left: &Report, right: &Report) -> AppResult<CompareResult> {
    verify_report(left)?;
    verify_report(right)?;

    let left_phases = left
        .phases
        .iter()
        .map(|phase| (phase.name, phase.status))
        .collect::<BTreeMap<_, _>>();
    let right_phases = right
        .phases
        .iter()
        .map(|phase| (phase.name, phase.status))
        .collect::<BTreeMap<_, _>>();
    let names = left_phases
        .keys()
        .chain(right_phases.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    let phase_differences = names
        .into_iter()
        .filter_map(|phase| {
            let left = left_phases.get(&phase).copied();
            let right = right_phases.get(&phase).copied();
            (left != right).then_some(PhaseDifference { phase, left, right })
        })
        .collect::<Vec<_>>();
    let same_intended_target = left.target.intended == right.target.intended;
    let same_failed_phase = left.failed_at == right.failed_at;
    let left_http_statuses = left.http.iter().map(|hop| hop.status).collect::<Vec<_>>();
    let right_http_statuses = right.http.iter().map(|hop| hop.status).collect::<Vec<_>>();

    let mut summary = Vec::new();
    if !same_intended_target {
        summary.push("reports describe different intended targets".to_owned());
    }
    if !same_failed_phase {
        summary.push("earliest failed phase differs".to_owned());
    }
    if !phase_differences.is_empty() {
        summary.push(format!(
            "{} phase status difference(s) observed",
            phase_differences.len()
        ));
    }
    if left_http_statuses != right_http_statuses {
        summary.push("HTTP status sequence differs".to_owned());
    }
    if summary.is_empty() {
        summary.push("no modeled causal difference was found".to_owned());
    }

    Ok(CompareResult {
        schema_version: COMPARE_SCHEMA_VERSION.to_owned(),
        left_report_sha256: left.report_sha256.clone().unwrap_or_default(),
        right_report_sha256: right.report_sha256.clone().unwrap_or_default(),
        same_intended_target,
        same_failed_phase,
        phase_differences,
        left_http_statuses,
        right_http_statuses,
        summary,
    })
}

const fn phase_key(phase: PhaseName) -> &'static str {
    match phase {
        PhaseName::Input => "input",
        PhaseName::Proxy => "proxy",
        PhaseName::Dns => "dns",
        PhaseName::Tcp => "tcp",
        PhaseName::Tls => "tls",
        PhaseName::Http => "http",
        PhaseName::Redirects => "redirects",
        PhaseName::Assertions => "assertions",
    }
}

impl Ord for PhaseName {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        phase_rank(*self).cmp(&phase_rank(*other))
    }
}

impl PartialOrd for PhaseName {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

const fn phase_rank(phase: PhaseName) -> u8 {
    match phase {
        PhaseName::Input => 0,
        PhaseName::Proxy => 1,
        PhaseName::Dns => 2,
        PhaseName::Tcp => 3,
        PhaseName::Tls => 4,
        PhaseName::Http => 5,
        PhaseName::Redirects => 6,
        PhaseName::Assertions => 7,
    }
}
