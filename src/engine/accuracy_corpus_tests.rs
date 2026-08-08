#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::*;
use crate::error::ErrorClass;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    schema_version: String,
    license: String,
    labeling_methodology: String,
    definitive_claim_rubric: String,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    category: String,
    target: String,
    hidden_cause: String,
    root_cause_observable: bool,
    observations: ScenarioObservations,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioObservations {
    dns: DnsObservation,
    tcp: StageObservation,
    tls: StageObservation,
    http: HttpObservation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StageObservation {
    result: String,
    error_code: Option<String>,
    retryable: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DnsObservation {
    result: String,
    error_code: Option<String>,
    retryable: bool,
    all_addresses: Vec<String>,
    permitted_addresses: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpObservation {
    result: String,
    error_code: Option<String>,
    retryable: bool,
    statuses: Vec<u16>,
    redirect_error_code: Option<String>,
    redirect_retryable: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    failed_at: Option<PhaseName>,
    hypothesis_code: String,
    backend_calls: Vec<String>,
}

#[derive(Debug, Default)]
struct CategoryMetrics {
    cases: usize,
    phase_matches: usize,
    short_circuit_matches: usize,
    hypothesis_code_matches: usize,
    unobservable_cause_cases: usize,
    definitive_root_cause_claims: usize,
}

struct ScriptBackend<'a> {
    observations: &'a ScenarioObservations,
    calls: Vec<String>,
}

impl ScriptBackend<'_> {
    fn record_probe(tracker: &mut Tracker, kind: ProbeKind, outcome: &str) -> AppResult<()> {
        let started = Instant::now();
        let probe = tracker.start_probe(kind, "scripted-observation".to_owned())?;
        tracker.finish_probe(probe, started, outcome);
        Ok(())
    }
}

impl DiagnosticBackend for ScriptBackend<'_> {
    fn resolve_addresses(
        &mut self,
        tracker: &mut Tracker,
        _proxy: &ResolvedProxy,
        _options: &InspectionOptions,
    ) -> AppResult<(Vec<SocketAddr>, Vec<SocketAddr>)> {
        self.calls.push("dns".to_owned());
        let stage = &self.observations.dns;
        Self::record_probe(
            tracker,
            ProbeKind::DnsLookup,
            if stage.result == "error" {
                "failed"
            } else {
                "resolved"
            },
        )?;
        if stage.result == "error" {
            return Err(scripted_error(stage.error_code.as_deref(), stage.retryable));
        }
        assert_eq!(stage.result, "success");
        Ok((
            parse_addresses(&stage.all_addresses),
            parse_addresses(&stage.permitted_addresses),
        ))
    }

    fn connect_first(
        &mut self,
        tracker: &mut Tracker,
        addresses: &[SocketAddr],
        _options: &InspectionOptions,
    ) -> AppResult<SocketAddr> {
        self.calls.push("tcp".to_owned());
        let stage = &self.observations.tcp;
        Self::record_probe(
            tracker,
            ProbeKind::TcpConnect,
            if stage.result == "error" {
                "failed"
            } else {
                "connected"
            },
        )?;
        if stage.result == "error" {
            return Err(scripted_error(stage.error_code.as_deref(), stage.retryable));
        }
        assert_eq!(stage.result, "success");
        Ok(*addresses.first().expect("permitted scripted address"))
    }

    fn probe_tls(
        &mut self,
        tracker: &mut Tracker,
        _address: SocketAddr,
        _server_host: &str,
        _show_addresses: bool,
    ) -> AppResult<TlsSummary> {
        self.calls.push("tls".to_owned());
        let stage = &self.observations.tls;
        Self::record_probe(
            tracker,
            ProbeKind::TlsHandshake,
            if stage.result == "error" {
                "failed"
            } else {
                "validated"
            },
        )?;
        if stage.result == "error" {
            return Err(scripted_error(stage.error_code.as_deref(), stage.retryable));
        }
        assert_eq!(stage.result, "success");
        Ok(TlsSummary {
            protocol: Some("TLSv1_3".to_owned()),
            cipher_suite: Some("TLS13_AES_256_GCM_SHA384".to_owned()),
            alpn: Some("h2".to_owned()),
            peer_leaf_sha256: Some("0".repeat(64)),
            peer_certificate_count: 2,
        })
    }

    fn run_http(
        &mut self,
        tracker: &mut Tracker,
        initial_url: &Url,
        _initial_proxy: &ResolvedProxy,
        _initial_address: SocketAddr,
        _options: &InspectionOptions,
    ) -> AppResult<(Vec<HttpHop>, Option<AppError>)> {
        self.calls.push("http".to_owned());
        let stage = &self.observations.http;
        Self::record_probe(
            tracker,
            ProbeKind::HttpRequest,
            if stage.result == "error" {
                "failed"
            } else {
                "response_received"
            },
        )?;
        if stage.result == "error" {
            return Err(scripted_error(stage.error_code.as_deref(), stage.retryable));
        }
        let hops = stage
            .statuses
            .iter()
            .enumerate()
            .map(|(sequence, status)| scripted_hop(sequence, *status, initial_url))
            .collect::<Vec<_>>();
        match stage.result.as_str() {
            "success" => Ok((hops, None)),
            "redirect_error" => Ok((
                hops,
                Some(scripted_error(
                    stage.redirect_error_code.as_deref(),
                    stage.redirect_retryable,
                )),
            )),
            other => panic!("unknown HTTP result {other}"),
        }
    }
}

fn scripted_error(code: Option<&str>, retryable: bool) -> AppError {
    let code = code.expect("scripted error code");
    let class = if code.contains("budget") || code.contains("limit") {
        ErrorClass::Budget
    } else if code.contains("denied") || code == "unsupported_scheme" {
        ErrorClass::Policy
    } else if code.contains("invalid") {
        ErrorClass::Contract
    } else {
        ErrorClass::Io
    };
    AppError::new(class, code, format!("scripted observation: {code}")).retryable(retryable)
}

fn parse_addresses(addresses: &[String]) -> Vec<SocketAddr> {
    addresses
        .iter()
        .map(|address| address.parse().expect("scripted socket address"))
        .collect()
}

fn scripted_hop(sequence: usize, status: u16, initial_url: &Url) -> HttpHop {
    HttpHop {
        sequence,
        url: initial_url.to_string(),
        status,
        version: "HTTP/1.1".to_owned(),
        headers: BTreeMap::new(),
        declared_content_length: Some(0),
        returned_body_bytes: 0,
        body_truncated: false,
        body_sample_sha256: crate::policy::sha256_text(""),
        body_sample_base64: None,
        location: None,
    }
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/diagnostic-accuracy/v0.1")
}

fn phase_label(phase: Option<PhaseName>) -> &'static str {
    match phase {
        Some(PhaseName::Dns) => "dns",
        Some(PhaseName::Tcp) => "tcp",
        Some(PhaseName::Tls) => "tls",
        Some(PhaseName::Http) => "http",
        Some(PhaseName::Redirects) => "redirects",
        None => "success",
        Some(other) => panic!("unexpected scored phase {other:?}"),
    }
}

fn definitive_claims(report: &Report, case: &Case) -> usize {
    if case.root_cause_observable {
        return 0;
    }
    let hidden_words = case.hidden_cause.replace('_', " ");
    report
        .hypotheses
        .iter()
        .filter(|hypothesis| {
            let statement = hypothesis.statement.to_ascii_lowercase();
            hypothesis.confidence >= 1.0
                || hypothesis.evidence_phases != report.failed_at.into_iter().collect::<Vec<_>>()
                || statement.contains(&hidden_words)
                || ["root cause is", "caused by", "proves that", "definitely"]
                    .iter()
                    .any(|phrase| statement.contains(phrase))
        })
        .count()
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        let numerator = u32::try_from(numerator).expect("corpus numerator fits u32");
        let denominator = u32::try_from(denominator).expect("corpus denominator fits u32");
        f64::from(numerator) / f64::from(denominator)
    }
}

#[test]
fn published_diagnostic_accuracy_is_reproducible() {
    let root = fixture_root();
    let corpus_bytes = fs::read(root.join("corpus.json")).expect("read corpus");
    let corpus_value: Value = serde_json::from_slice(&corpus_bytes).expect("corpus JSON");
    let canonical_corpus =
        serde_json::to_vec(&corpus_value).expect("canonical corpus serialization");
    let corpus_text = String::from_utf8(corpus_bytes).expect("corpus is UTF-8");
    let crlf_text = corpus_text.replace("\r\n", "\n").replace('\n', "\r\n");
    let crlf_value: Value = serde_json::from_str(&crlf_text).expect("CRLF corpus JSON");
    assert_eq!(
        serde_json::to_vec(&crlf_value).expect("canonical CRLF corpus"),
        canonical_corpus,
        "logical corpus digest must not depend on checkout line endings"
    );

    let corpus: Corpus = serde_json::from_value(corpus_value).expect("corpus shape");
    assert_eq!(
        corpus.schema_version,
        "hopwhy.diagnostic-accuracy-corpus.v1"
    );
    assert_eq!(corpus.license, "MIT");
    assert!(!corpus.labeling_methodology.is_empty());
    assert!(corpus.definitive_claim_rubric.contains("confidence 1.0"));
    assert_eq!(corpus.cases.len(), 60);

    let mut identifiers = BTreeSet::new();
    let mut phase_matches = 0;
    let mut short_circuit_matches = 0;
    let mut hypothesis_code_matches = 0;
    let mut unobservable_cause_cases = 0;
    let mut definitive_root_cause_claims = 0;
    let mut by_category = BTreeMap::<String, CategoryMetrics>::new();
    let mut confusion = BTreeMap::<String, BTreeMap<String, usize>>::new();

    for case in &corpus.cases {
        assert!(identifiers.insert(&case.id), "duplicate case {}", case.id);
        let specification = InspectSpec {
            target: case.target.clone(),
            options: InspectionOptions {
                disable_proxy: true,
                ..InspectionOptions::default()
            },
        };
        let mut backend = ScriptBackend {
            observations: &case.observations,
            calls: Vec::new(),
        };
        let report = inspect_with_backend(&specification, &mut backend)
            .unwrap_or_else(|error| panic!("{} failed: {error}", case.id));
        let phase_match = report.failed_at == case.expected.failed_at;
        let short_circuit_match = backend.calls == case.expected.backend_calls;
        let hypothesis_code_match = report
            .hypotheses
            .first()
            .is_some_and(|hypothesis| hypothesis.code == case.expected.hypothesis_code);
        let case_definitive_claims = definitive_claims(&report, case);

        phase_matches += usize::from(phase_match);
        short_circuit_matches += usize::from(short_circuit_match);
        hypothesis_code_matches += usize::from(hypothesis_code_match);
        unobservable_cause_cases += usize::from(!case.root_cause_observable);
        definitive_root_cause_claims += case_definitive_claims;
        *confusion
            .entry(phase_label(case.expected.failed_at).to_owned())
            .or_default()
            .entry(phase_label(report.failed_at).to_owned())
            .or_default() += 1;

        assert!(phase_match, "{} earliest phase", case.id);
        assert!(short_circuit_match, "{} backend short circuit", case.id);
        assert!(hypothesis_code_match, "{} hypothesis code", case.id);
        assert_eq!(
            case_definitive_claims, 0,
            "{} made a definitive hidden-cause claim",
            case.id
        );

        let category = by_category.entry(case.category.clone()).or_default();
        category.cases += 1;
        category.phase_matches += usize::from(phase_match);
        category.short_circuit_matches += usize::from(short_circuit_match);
        category.hypothesis_code_matches += usize::from(hypothesis_code_match);
        category.unobservable_cause_cases += usize::from(!case.root_cause_observable);
        category.definitive_root_cause_claims += case_definitive_claims;
    }

    let category_metrics = by_category
        .into_iter()
        .map(|(category, metrics)| {
            (
                category,
                json!({
                    "cases": metrics.cases,
                    "phase_matches": metrics.phase_matches,
                    "short_circuit_matches": metrics.short_circuit_matches,
                    "hypothesis_code_matches": metrics.hypothesis_code_matches,
                    "unobservable_cause_cases": metrics.unobservable_cause_cases,
                    "definitive_root_cause_claims": metrics.definitive_root_cause_claims,
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let phase_confusion = confusion
        .into_iter()
        .map(|(expected, actual)| (expected, json!(actual)))
        .collect::<serde_json::Map<_, _>>();
    let actual_metrics = json!({
        "schema_version": "hopwhy.diagnostic-accuracy-metrics.v1",
        "corpus_sha256": crate::hex::encode_lower(Sha256::digest(&canonical_corpus)),
        "total_cases": corpus.cases.len(),
        "phase_matches": phase_matches,
        "phase_accuracy": ratio(phase_matches, corpus.cases.len()),
        "short_circuit_matches": short_circuit_matches,
        "hypothesis_code_matches": hypothesis_code_matches,
        "unobservable_cause_cases": unobservable_cause_cases,
        "definitive_root_cause_claims": definitive_root_cause_claims,
        "by_category": category_metrics,
        "phase_confusion": phase_confusion,
    });
    let expected_metrics: Value =
        serde_json::from_slice(&fs::read(root.join("metrics.json")).expect("read metrics"))
            .expect("metrics JSON");
    assert_eq!(actual_metrics, expected_metrics);
}
