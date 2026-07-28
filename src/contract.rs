use schemars::{generate::SchemaSettings, JsonSchema, Schema};
use serde_json::{json, Value};

use crate::error::{AppError, AppResult, ErrorClass};
use crate::model::{
    AdapterCapability, Capabilities, CompareResult, ErrorEnvelope, InspectSpec, InspectionPlan,
    PhaseName, ReplayResult, Report, CAPABILITIES_SCHEMA_VERSION,
};

pub fn capabilities() -> Capabilities {
    Capabilities {
        schema_version: CAPABILITIES_SCHEMA_VERSION.to_owned(),
        supported_schemes: vec!["http".to_owned(), "https".to_owned()],
        supported_platforms: vec!["linux".to_owned(), "macos".to_owned(), "windows".to_owned()],
        default_private_address_policy:
            "deny loopback, private, link-local, multicast, documentation, and reserved addresses"
                .to_owned(),
        capabilities: vec![
            capability(
                PhaseName::Input,
                "full",
                &[
                    "absolute HTTP(S) URL validation",
                    "credential-bearing URLs denied",
                ],
            ),
            capability(
                PhaseName::Proxy,
                "partial",
                &[
                    "HTTP(S) proxy and NO_PROXY environment",
                    "SOCKS and PAC are not supported",
                    "proxy credentials are never emitted",
                ],
            ),
            capability(
                PhaseName::Dns,
                "partial",
                &[
                    "system resolver answers",
                    "upstream resolver identity and DNS transport are not observable",
                ],
            ),
            capability(
                PhaseName::Tcp,
                "full",
                &["bounded IPv4 and IPv6 connection attempts"],
            ),
            capability(
                PhaseName::Tls,
                "partial",
                &[
                    "independent direct-target handshake with public roots",
                    "proxy tunnel TLS is not separated from the HTTP client",
                ],
            ),
            capability(
                PhaseName::Http,
                "full",
                &[
                    "GET and HEAD",
                    "HTTP/1.1 and HTTP/2 client negotiation",
                    "safe response header allowlist and bounded body digest/sample",
                ],
            ),
            capability(
                PhaseName::Redirects,
                "full",
                &["manual redirect following with target policy re-evaluation"],
            ),
            capability(
                PhaseName::Assertions,
                "planned",
                &["0.1 records reachability but does not infer application health"],
            ),
        ],
        non_goals: vec![
            "port scanning".to_owned(),
            "packet capture".to_owned(),
            "continuous monitoring".to_owned(),
            "automatic DNS, proxy, route, firewall, or certificate changes".to_owned(),
            "proof of an unobservable middlebox root cause".to_owned(),
        ],
    }
}

fn capability(phase: PhaseName, support: &str, notes: &[&str]) -> AdapterCapability {
    AdapterCapability {
        phase,
        support: support.to_owned(),
        notes: notes.iter().map(|note| (*note).to_owned()).collect(),
    }
}

pub fn brief_contract() -> Value {
    json!({
        "schema_version": "hopwhy.contract.v1",
        "tool_version": env!("CARGO_PKG_VERSION"),
        "commands": [
            "inspect",
            "compare",
            "replay",
            "capabilities",
            "schema",
            "completions"
        ],
        "data_schemas": {
            "report": "hopwhy.report.v1",
            "plan": "hopwhy.plan.v1",
            "compare": "hopwhy.compare.v1",
            "replay": "hopwhy.replay.v1",
            "capabilities": "hopwhy.capabilities.v1",
            "error": "hopwhy.error.v1"
        },
        "output_formats": ["human", "json", "ndjson"],
        "exit_codes": {
            "0": "successful command, including a diagnostic report whose target path failed",
            "1": "local I/O or transport setup error outside a completed report",
            "2": "invalid CLI usage, target, spec, or limit",
            "3": "policy denial before a report can be produced",
            "4": "local input or operation budget exceeded",
            "5": "machine-contract or report-integrity failure"
        },
        "safety_defaults": {
            "private_addresses": "denied",
            "redirects": "manual and bounded",
            "body_sample": "omitted; digest retained",
            "query_values": "redacted",
            "addresses": "stable hashes",
            "automatic_changes": false
        }
    })
}

pub fn schema_document(document: &str) -> AppResult<Value> {
    match document {
        "brief" => Ok(brief_contract()),
        "spec" => to_value(draft07_schema_for::<InspectSpec>()),
        "report" => to_value(draft07_schema_for::<Report>()),
        "plan" => to_value(draft07_schema_for::<InspectionPlan>()),
        "compare" => to_value(draft07_schema_for::<CompareResult>()),
        "replay" => to_value(draft07_schema_for::<ReplayResult>()),
        "capabilities" => to_value(draft07_schema_for::<Capabilities>()),
        "error" => to_value(draft07_schema_for::<ErrorEnvelope>()),
        _ => Err(AppError::new(
            ErrorClass::Usage,
            "unknown_schema_document",
            format!("unknown schema document {document}"),
        )),
    }
}

fn draft07_schema_for<T: JsonSchema>() -> Schema {
    SchemaSettings::draft07()
        .into_generator()
        .into_root_schema_for::<T>()
}

fn to_value<T: serde::Serialize>(value: T) -> AppResult<Value> {
    serde_json::to_value(value).map_err(|_| {
        AppError::new(
            ErrorClass::Contract,
            "schema_serialization_failed",
            "a JSON Schema document could not be serialized",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::schema_document;
    use crate::error::AppResult;

    #[test]
    fn every_full_schema_uses_the_published_draft() -> AppResult<()> {
        for document in [
            "spec",
            "report",
            "plan",
            "compare",
            "replay",
            "capabilities",
            "error",
        ] {
            let schema = schema_document(document)?;
            assert_eq!(
                schema["$schema"], "http://json-schema.org/draft-07/schema#",
                "{document} changed JSON Schema draft"
            );
        }
        Ok(())
    }
}
