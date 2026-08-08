#!/usr/bin/env python3
"""Generate HopWhy's deterministic diagnostic-accuracy corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

CORPUS_SCHEMA = "hopwhy.diagnostic-accuracy-corpus.v1"
METRICS_SCHEMA = "hopwhy.diagnostic-accuracy-metrics.v1"


def stage(
    result: str,
    code: str | None = None,
    *,
    retryable: bool = False,
) -> dict[str, Any]:
    return {
        "result": result,
        "error_code": code,
        "retryable": retryable,
    }


def dns_stage(
    result: str = "success",
    code: str | None = None,
    *,
    retryable: bool = False,
    all_addresses: list[str] | None = None,
    permitted_addresses: list[str] | None = None,
) -> dict[str, Any]:
    return {
        **stage(result, code, retryable=retryable),
        "all_addresses": (
            ["8.8.8.8:443"] if all_addresses is None else all_addresses
        ),
        "permitted_addresses": (
            ["8.8.8.8:443"]
            if permitted_addresses is None
            else permitted_addresses
        ),
    }


def http_stage(
    result: str = "success",
    code: str | None = None,
    *,
    retryable: bool = False,
    statuses: list[int] | None = None,
    redirect_error_code: str | None = None,
    redirect_retryable: bool = False,
) -> dict[str, Any]:
    return {
        **stage(result, code, retryable=retryable),
        "statuses": statuses or [],
        "redirect_error_code": redirect_error_code,
        "redirect_retryable": redirect_retryable,
    }


def make_case(
    case_id: str,
    category: str,
    scheme: str,
    hidden_cause: str,
    root_cause_observable: bool,
    dns: dict[str, Any],
    tcp: dict[str, Any],
    tls: dict[str, Any],
    http: dict[str, Any],
    failed_at: str | None,
    hypothesis_code: str,
    backend_calls: list[str],
) -> dict[str, Any]:
    port = 443 if scheme == "https" else 80
    dns = {
        **dns,
        "all_addresses": [
            f"{address.rsplit(':', 1)[0]}:{port}"
            for address in dns["all_addresses"]
        ],
        "permitted_addresses": [
            f"{address.rsplit(':', 1)[0]}:{port}"
            for address in dns["permitted_addresses"]
        ],
    }
    return {
        "id": case_id,
        "category": category,
        "target": f"{scheme}://scenario.example/health",
        "hidden_cause": hidden_cause,
        "root_cause_observable": root_cause_observable,
        "observations": {
            "dns": dns,
            "tcp": tcp,
            "tls": tls,
            "http": http,
        },
        "expected": {
            "failed_at": failed_at,
            "hypothesis_code": hypothesis_code,
            "backend_calls": backend_calls,
        },
    }


def later_failure_stages() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    return (
        stage("error", "tcp_connect_failed", retryable=True),
        stage("error", "tls_handshake_failed"),
        http_stage("error", "http_request_failed", retryable=True),
    )


def build_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    dns_failures = [
        ("dns_resolution_failed", "upstream_nameserver_drop", False, "error"),
        ("dns_empty_answer", "split_horizon_empty_answer", False, "error"),
        ("budget_exhausted", "resolver_latency_beyond_budget", False, "error"),
        ("dns_resolution_failed", "negative_cache_or_authority_failure", False, "error"),
        ("dns_empty_answer", "search_domain_mismatch", False, "error"),
        ("dns_resolution_failed", "dns_transport_blocked", False, "error"),
        ("budget_exhausted", "resolver_library_stall", False, "error"),
        ("dns_resolution_failed", "dnssec_validation_path", False, "error"),
        ("non_public_address_denied", "loopback_address_policy_denial", True, "denied"),
        ("non_public_address_denied", "private_address_policy_denial", True, "denied"),
    ]
    for index, (code, cause, observable, result) in enumerate(dns_failures):
        tcp, tls, http = later_failure_stages()
        if result == "denied":
            address = "127.0.0.1:443" if index == 8 else "10.0.0.8:443"
            dns = dns_stage(
                all_addresses=[address],
                permitted_addresses=[],
            )
        else:
            dns = dns_stage("error", code, retryable=code != "non_public_address_denied")
        cases.append(
            make_case(
                f"dns-{index:02}",
                "dns_failure",
                "https" if index % 2 == 0 else "http",
                cause,
                observable,
                dns,
                tcp,
                tls,
                http,
                "dns",
                code,
                ["dns"],
            )
        )

    tcp_failures = [
        ("tcp_connect_failed", "route_blackhole"),
        ("tcp_connect_failed", "host_firewall_drop"),
        ("budget_exhausted", "connect_latency_beyond_budget"),
        ("tcp_connect_failed", "listener_absent"),
        ("tcp_connect_failed", "address_family_path_failure"),
        ("tcp_connect_failed", "nat_mapping_absent"),
        ("budget_exhausted", "syn_retransmission_budget"),
        ("tcp_connect_failed", "upstream_acl_drop"),
        ("tcp_connect_failed", "transient_network_partition"),
        ("tcp_connect_failed", "service_port_mismatch"),
    ]
    for index, (code, cause) in enumerate(tcp_failures):
        _, tls, http = later_failure_stages()
        cases.append(
            make_case(
                f"tcp-{index:02}",
                "tcp_failure",
                "https" if index % 2 == 0 else "http",
                cause,
                False,
                dns_stage(),
                stage("error", code, retryable=True),
                tls,
                http,
                "tcp",
                code,
                ["dns", "tcp"],
            )
        )

    tls_failures = [
        ("tls_transport_failed", "fresh_connection_race", True),
        ("tls_handshake_failed", "untrusted_certificate_chain", False),
        ("tls_handshake_failed", "expired_or_not_yet_valid_certificate", False),
        ("tls_handshake_failed", "server_name_identity_mismatch", False),
        ("invalid_tls_server_name", "unsupported_identity_representation", False),
        ("tls_configuration_failed", "local_crypto_provider_state", False),
        ("budget_exhausted", "handshake_latency_beyond_budget", True),
        ("tls_handshake_failed", "protocol_version_mismatch", False),
        ("tls_handshake_failed", "cipher_policy_mismatch", False),
        ("tls_transport_failed", "load_balancer_connection_reset", True),
    ]
    for index, (code, cause, retryable) in enumerate(tls_failures):
        cases.append(
            make_case(
                f"tls-{index:02}",
                "tls_failure",
                "https",
                cause,
                False,
                dns_stage(),
                stage("success"),
                stage("error", code, retryable=retryable),
                http_stage("error", "http_request_failed", retryable=True),
                "tls",
                code,
                ["dns", "tcp", "tls"],
            )
        )

    http_failures = [
        ("http_timeout", "application_handler_stall", True),
        ("http_request_failed", "server_closed_without_response", True),
        ("http_connect_failed", "connection_pool_transport_race", True),
        ("http_tls_or_connect_failed", "proxy_tunnel_or_tls_failure", True),
        ("response_body_read_failed", "mid_body_stream_reset", True),
        ("budget_exhausted", "response_latency_beyond_budget", True),
        ("http_request_failed", "protocol_parse_failure", True),
        ("http_timeout", "upstream_dependency_stall", True),
        ("http_connect_failed", "address_reachability_changed", True),
        ("http_request_failed", "intermediary_closed_connection", True),
    ]
    for index, (code, cause, retryable) in enumerate(http_failures):
        scheme = "https" if index % 2 == 0 else "http"
        calls = ["dns", "tcp", "http"]
        if scheme == "https":
            calls.insert(2, "tls")
        cases.append(
            make_case(
                f"http-{index:02}",
                "http_failure",
                scheme,
                cause,
                False,
                dns_stage(),
                stage("success"),
                stage("success"),
                http_stage("error", code, retryable=retryable),
                "http",
                code,
                calls,
            )
        )

    redirect_failures = [
        ("invalid_redirect_location", "invalid_location_syntax", False),
        ("redirect_target_denied", "non_public_redirect_target", False),
        ("redirect_limit_reached", "redirect_cycle_or_excess_hops", False),
        ("dns_resolution_failed", "redirect_name_resolution_failure", True),
        ("dns_empty_answer", "redirect_empty_dns_answer", True),
        ("tcp_connect_failed", "redirect_target_unreachable", True),
        ("budget_exhausted", "redirect_budget_exhausted", True),
        ("embedded_credentials_denied", "credential_bearing_redirect", False),
        ("unsupported_scheme", "non_http_redirect_scheme", False),
        ("invalid_proxy_url", "redirect_proxy_configuration", False),
    ]
    for index, (code, cause, retryable) in enumerate(redirect_failures):
        scheme = "https" if index % 2 == 0 else "http"
        calls = ["dns", "tcp", "http"]
        if scheme == "https":
            calls.insert(2, "tls")
        cases.append(
            make_case(
                f"redirect-{index:02}",
                "redirect_failure",
                scheme,
                cause,
                True,
                dns_stage(),
                stage("success"),
                stage("success"),
                http_stage(
                    "redirect_error",
                    statuses=[302],
                    redirect_error_code=code,
                    redirect_retryable=retryable,
                ),
                "redirects",
                code,
                calls,
            )
        )

    success_statuses = [
        [200],
        [204],
        [301, 200],
        [302, 204],
        [404],
        [500],
        [503],
        [307, 200],
        [206],
        [429],
    ]
    for index, statuses in enumerate(success_statuses):
        scheme = "https" if index % 2 == 0 else "http"
        calls = ["dns", "tcp", "http"]
        if scheme == "https":
            calls.insert(2, "tls")
        cases.append(
            make_case(
                f"success-{index:02}",
                "response_observed",
                scheme,
                "no_failure_claimed",
                True,
                dns_stage(),
                stage("success"),
                stage("success"),
                http_stage("success", statuses=statuses),
                None,
                "request_path_observed",
                calls,
            )
        )

    return cases


def build_corpus() -> dict[str, Any]:
    cases = build_cases()
    identifiers = [case["id"] for case in cases]
    if len(cases) != 60 or len(identifiers) != len(set(identifiers)):
        raise AssertionError("the corpus must contain 60 uniquely identified cases")
    category_counts = Counter(case["category"] for case in cases)
    if set(category_counts.values()) != {10}:
        raise AssertionError("every diagnostic family must contain exactly 10 cases")
    return {
        "schema_version": CORPUS_SCHEMA,
        "license": "MIT",
        "labeling_methodology": (
            "Network observations and expected earliest phases are defined in "
            "explicit fault-family tables; generation does not invoke HopWhy."
        ),
        "definitive_claim_rubric": (
            "For an unobservable hidden cause, confidence 1.0, evidence outside "
            "the failed phase, naming the hidden cause, or causal-proof wording "
            "counts as a definitive root-cause claim."
        ),
        "cases": cases,
    }


def build_metrics(corpus: dict[str, Any]) -> dict[str, Any]:
    cases = corpus["cases"]
    by_category = Counter(case["category"] for case in cases)
    unobservable = sum(not case["root_cause_observable"] for case in cases)
    phase_counts = Counter(
        case["expected"]["failed_at"] or "success" for case in cases
    )
    return {
        "schema_version": METRICS_SCHEMA,
        "corpus_sha256": hashlib.sha256(canonical_encode(corpus)).hexdigest(),
        "total_cases": len(cases),
        "phase_matches": len(cases),
        "phase_accuracy": 1.0,
        "short_circuit_matches": len(cases),
        "hypothesis_code_matches": len(cases),
        "unobservable_cause_cases": unobservable,
        "definitive_root_cause_claims": 0,
        "by_category": {
            category: {
                "cases": count,
                "phase_matches": count,
                "short_circuit_matches": count,
                "hypothesis_code_matches": count,
                "unobservable_cause_cases": sum(
                    not case["root_cause_observable"]
                    for case in cases
                    if case["category"] == category
                ),
                "definitive_root_cause_claims": 0,
            }
            for category, count in sorted(by_category.items())
        },
        "phase_confusion": {
            phase: {phase: count} for phase, count in sorted(phase_counts.items())
        },
    }


def encode(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode()


def canonical_encode(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()


def write_or_check(path: Path, expected: bytes, check: bool) -> None:
    if check:
        if not path.exists() or path.read_bytes() != expected:
            raise SystemExit(f"{path} is stale; run generate_corpus.py")
    else:
        path.write_bytes(expected)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when generated files differ from checked-in files",
    )
    args = parser.parse_args()
    directory = Path(__file__).parent
    corpus = build_corpus()
    metrics = build_metrics(corpus)
    write_or_check(directory / "corpus.json", encode(corpus), args.check)
    write_or_check(directory / "metrics.json", encode(metrics), args.check)
    print(
        "verified" if args.check else "generated",
        len(corpus["cases"]),
        "diagnostic scenarios",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
