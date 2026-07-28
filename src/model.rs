use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const REPORT_SCHEMA_VERSION: &str = "hopwhy.report.v1";
pub const PLAN_SCHEMA_VERSION: &str = "hopwhy.plan.v1";
pub const COMPARE_SCHEMA_VERSION: &str = "hopwhy.compare.v1";
pub const REPLAY_SCHEMA_VERSION: &str = "hopwhy.replay.v1";
pub const CAPABILITIES_SCHEMA_VERSION: &str = "hopwhy.capabilities.v1";
pub const ERROR_SCHEMA_VERSION: &str = "hopwhy.error.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RequestMethod {
    Get,
    Head,
}

impl Default for RequestMethod {
    fn default() -> Self {
        Self::Get
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct InspectionOptions {
    pub budget_ms: u64,
    pub max_probes: u32,
    pub max_addresses: usize,
    pub max_redirects: usize,
    pub max_body_bytes: usize,
    pub include_body_sample: bool,
    pub allow_private: bool,
    pub show_addresses: bool,
    pub show_query_values: bool,
    pub disable_proxy: bool,
    pub method: RequestMethod,
}

impl Default for InspectionOptions {
    fn default() -> Self {
        Self {
            budget_ms: 15_000,
            max_probes: 12,
            max_addresses: 4,
            max_redirects: 5,
            max_body_bytes: 4_096,
            include_body_sample: false,
            allow_private: false,
            show_addresses: false,
            show_query_values: false,
            disable_proxy: false,
            method: RequestMethod::Get,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InspectSpec {
    pub target: String,
    #[serde(default)]
    pub options: InspectionOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct TargetSummary {
    pub intended: String,
    pub effective: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct ProxySummary {
    pub selected: bool,
    pub source: Option<String>,
    pub endpoint: Option<String>,
    pub configuration_sha256: Option<String>,
    pub bypass_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PhaseName {
    Input,
    Proxy,
    Dns,
    Tcp,
    Tls,
    Http,
    Redirects,
    Assertions,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PhaseStatus {
    Passed,
    Failed,
    Skipped,
    NotObserved,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Observation {
    pub kind: String,
    pub value: Value,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct DiagnosticError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Phase {
    pub name: PhaseName,
    pub status: PhaseStatus,
    pub duration_ms: u64,
    pub observations: Vec<Observation>,
    pub limitations: Vec<String>,
    pub error: Option<DiagnosticError>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    DnsLookup,
    TcpConnect,
    TlsHandshake,
    HttpRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct ProbeRecord {
    pub sequence: u32,
    pub kind: ProbeKind,
    pub destination: String,
    pub started_ms: u64,
    pub duration_ms: u64,
    pub outcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct AddressObservation {
    pub address: String,
    pub family: String,
    pub permitted: bool,
    pub classification: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct TlsSummary {
    pub protocol: Option<String>,
    pub cipher_suite: Option<String>,
    pub alpn: Option<String>,
    pub peer_leaf_sha256: Option<String>,
    pub peer_certificate_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct HttpHop {
    pub sequence: usize,
    pub url: String,
    pub status: u16,
    pub version: String,
    pub headers: BTreeMap<String, String>,
    pub declared_content_length: Option<u64>,
    pub returned_body_bytes: usize,
    pub body_truncated: bool,
    pub body_sample_sha256: String,
    pub body_sample_base64: Option<String>,
    pub location: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Hypothesis {
    pub code: String,
    pub statement: String,
    pub confidence: f64,
    pub evidence_phases: Vec<PhaseName>,
    pub next_safe_step: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Budget {
    pub duration_ms: u64,
    pub max_probes: u32,
    pub max_addresses: usize,
    pub max_redirects: usize,
    pub max_body_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Usage {
    pub elapsed_ms: u64,
    pub probes_used: u32,
    pub response_bytes_read: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Report {
    pub schema_version: String,
    pub tool_version: String,
    pub started_at_unix_ms: u64,
    pub target: TargetSummary,
    pub proxy: ProxySummary,
    pub options: InspectionOptions,
    pub budget: Budget,
    pub usage: Usage,
    pub probes: Vec<ProbeRecord>,
    pub addresses: Vec<AddressObservation>,
    pub tls: Option<TlsSummary>,
    pub http: Vec<HttpHop>,
    pub phases: Vec<Phase>,
    pub failed_at: Option<PhaseName>,
    pub hypotheses: Vec<Hypothesis>,
    pub ruled_out: Vec<String>,
    pub omissions: Vec<String>,
    pub report_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct PlannedProbe {
    pub sequence: u32,
    pub kind: ProbeKind,
    pub purpose: String,
    pub conditional: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct InspectionPlan {
    pub schema_version: String,
    pub target: TargetSummary,
    pub options: InspectionOptions,
    pub policy: String,
    pub planned_probes: Vec<PlannedProbe>,
    pub network_performed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct PhaseDifference {
    pub phase: PhaseName,
    pub left: Option<PhaseStatus>,
    pub right: Option<PhaseStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct CompareResult {
    pub schema_version: String,
    pub left_report_sha256: String,
    pub right_report_sha256: String,
    pub same_intended_target: bool,
    pub same_failed_phase: bool,
    pub phase_differences: Vec<PhaseDifference>,
    pub left_http_statuses: Vec<u16>,
    pub right_http_statuses: Vec<u16>,
    pub summary: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct ReplayResult {
    pub schema_version: String,
    pub report_sha256: String,
    pub integrity_valid: bool,
    pub network_performed: bool,
    pub failed_at: Option<PhaseName>,
    pub phase_statuses: BTreeMap<String, PhaseStatus>,
    pub hypotheses: Vec<Hypothesis>,
    pub next_safe_steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct AdapterCapability {
    pub phase: PhaseName,
    pub support: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Capabilities {
    pub schema_version: String,
    pub supported_schemes: Vec<String>,
    pub supported_platforms: Vec<String>,
    pub default_private_address_policy: String,
    pub capabilities: Vec<AdapterCapability>,
    pub non_goals: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct ErrorEnvelope {
    pub schema_version: String,
    pub error: DiagnosticError,
}
