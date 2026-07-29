use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Once};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use reqwest::blocking::{Client, ClientBuilder, Response};
use reqwest::header::{HeaderMap, LOCATION};
use reqwest::Version;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

use crate::error::{AppError, AppResult, ErrorClass};
use crate::model::{
    AddressObservation, Budget, DiagnosticError, HttpHop, Hypothesis, InspectSpec,
    InspectionOptions, InspectionPlan, Phase, PhaseName, PhaseStatus, PlannedProbe, ProbeKind,
    ProbeRecord, Report, RequestMethod, TargetSummary, TlsSummary, Usage, PLAN_SCHEMA_VERSION,
    REPORT_SCHEMA_VERSION,
};
use crate::policy::{
    address_for_report, classify_ip, is_ip_permitted, parse_target, redact_url, resolve_proxy,
    socket_destination, ResolvedProxy,
};

const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
static CRYPTO_PROVIDER: Once = Once::new();

#[cfg(test)]
mod accuracy_corpus_tests;

pub fn plan(spec: &InspectSpec) -> AppResult<InspectionPlan> {
    validate_options(&spec.options)?;
    let target = parse_target(&spec.target, &spec.options)?;
    let proxy = resolve_proxy(&target.url, &spec.options)?;
    let mut sequence = 1;
    let mut probes = Vec::new();

    probes.push(planned(
        &mut sequence,
        ProbeKind::DnsLookup,
        if proxy.summary.selected {
            "resolve the selected proxy endpoint"
        } else {
            "resolve the intended target through the system resolver"
        },
        false,
    ));
    probes.push(planned(
        &mut sequence,
        ProbeKind::TcpConnect,
        "attempt bounded TCP connections to permitted resolved addresses",
        false,
    ));
    probes.push(planned(
        &mut sequence,
        ProbeKind::TlsHandshake,
        "validate TLS identity and record negotiated protocol metadata",
        target.url.scheme() != "https" || proxy.summary.selected,
    ));
    probes.push(planned(
        &mut sequence,
        ProbeKind::HttpRequest,
        "perform one bounded request with automatic redirects disabled",
        false,
    ));
    probes.push(planned(
        &mut sequence,
        ProbeKind::HttpRequest,
        "repeat only for explicitly observed redirects within the redirect budget",
        true,
    ));

    Ok(InspectionPlan {
        schema_version: PLAN_SCHEMA_VERSION.to_owned(),
        target: target.summary,
        options: spec.options.clone(),
        policy: if spec.options.allow_private {
            "public and explicitly authorized non-public addresses are permitted".to_owned()
        } else {
            "only public addresses are permitted; private, local, special-use, and reserved addresses are denied".to_owned()
        },
        planned_probes: probes,
        network_performed: false,
    })
}

fn planned(sequence: &mut u32, kind: ProbeKind, purpose: &str, conditional: bool) -> PlannedProbe {
    let probe = PlannedProbe {
        sequence: *sequence,
        kind,
        purpose: purpose.to_owned(),
        conditional,
    };
    *sequence += 1;
    probe
}

pub fn inspect(spec: &InspectSpec) -> AppResult<Report> {
    ensure_crypto_provider();
    inspect_with_backend(spec, &mut LiveBackend)
}

fn inspect_with_backend<B: DiagnosticBackend>(
    spec: &InspectSpec,
    backend: &mut B,
) -> AppResult<Report> {
    validate_options(&spec.options)?;
    let parsed = parse_target(&spec.target, &spec.options)?;
    let started_at_unix_ms = unix_time_ms();
    let mut tracker = Tracker::new(&spec.options);
    let mut phases = Vec::new();
    let mut omissions = vec![
        "system resolver internals and upstream DNS transport are not observable".to_owned(),
        "packet paths beyond the host are inferred only from connection outcomes".to_owned(),
    ];

    phases.push(passed_phase(
        PhaseName::Input,
        0,
        vec![observation(
            "normalized_target",
            json!(parsed.summary.intended),
            "parsed with the URL standard and restricted to HTTP(S)",
        )],
    ));

    let proxy_started = Instant::now();
    let proxy = resolve_proxy(&parsed.url, &spec.options)?;
    phases.push(passed_phase(
        PhaseName::Proxy,
        elapsed_ms(proxy_started),
        vec![observation(
            "proxy_selection",
            serde_json::to_value(&proxy.summary).unwrap_or(Value::Null),
            "derived from explicit disable policy, NO_PROXY, and scheme-specific proxy environment",
        )],
    ));

    let dns_started = Instant::now();
    let resolution = backend.resolve_addresses(&mut tracker, &proxy, &spec.options);
    let (all_addresses, permitted_addresses) = match resolution {
        Ok(addresses) => addresses,
        Err(error) => {
            phases.push(failed_phase(
                PhaseName::Dns,
                elapsed_ms(dns_started),
                &error.code,
                &error.message,
                error.retryable,
            ));
            return Ok(finalize_report(
                parsed.summary,
                proxy,
                spec.options.clone(),
                tracker,
                started_at_unix_ms,
                Vec::new(),
                None,
                Vec::new(),
                phases,
                omissions,
            ));
        }
    };

    let address_observations = all_addresses
        .iter()
        .map(|address| AddressObservation {
            address: address_for_report(*address, spec.options.show_addresses),
            family: if address.is_ipv4() {
                "ipv4".to_owned()
            } else {
                "ipv6".to_owned()
            },
            permitted: is_ip_permitted(address.ip(), spec.options.allow_private),
            classification: classify_ip(address.ip()).to_owned(),
        })
        .collect::<Vec<_>>();

    if permitted_addresses.is_empty() {
        phases.push(failed_phase(
            PhaseName::Dns,
            elapsed_ms(dns_started),
            "non_public_address_denied",
            "resolution returned no address allowed by the default public-target policy",
            false,
        ));
        return Ok(finalize_report(
            parsed.summary,
            proxy,
            spec.options.clone(),
            tracker,
            started_at_unix_ms,
            address_observations,
            None,
            Vec::new(),
            phases,
            omissions,
        ));
    }

    phases.push(passed_phase(
        PhaseName::Dns,
        elapsed_ms(dns_started),
        vec![
            observation(
                "resolved_address_count",
                json!(all_addresses.len()),
                "system resolver result after de-duplication",
            ),
            observation(
                "permitted_address_count",
                json!(permitted_addresses.len()),
                "address policy evaluation",
            ),
        ],
    ));

    let tcp_started = Instant::now();
    let selected_address =
        match backend.connect_first(&mut tracker, &permitted_addresses, &spec.options) {
            Ok(address) => address,
            Err(error) => {
                phases.push(failed_phase(
                    PhaseName::Tcp,
                    elapsed_ms(tcp_started),
                    &error.code,
                    &error.message,
                    error.retryable,
                ));
                return Ok(finalize_report(
                    parsed.summary,
                    proxy,
                    spec.options.clone(),
                    tracker,
                    started_at_unix_ms,
                    address_observations,
                    None,
                    Vec::new(),
                    phases,
                    omissions,
                ));
            }
        };
    phases.push(passed_phase(
        PhaseName::Tcp,
        elapsed_ms(tcp_started),
        vec![observation(
            "selected_address",
            json!(address_for_report(
                selected_address,
                spec.options.show_addresses
            )),
            "first successful bounded TCP connection",
        )],
    ));

    let mut tls_summary = None;
    let tls_started = Instant::now();
    if parsed.url.scheme() != "https" {
        phases.push(skipped_phase(
            PhaseName::Tls,
            "the intended target uses plaintext HTTP",
        ));
    } else if proxy.summary.selected {
        phases.push(not_observed_phase(
            PhaseName::Tls,
            "TLS through an HTTP(S) proxy is observed only by the bounded HTTP client; a standalone tunnel handshake is not duplicated",
        ));
        omissions.push(
            "proxy CONNECT negotiation and target TLS handshake are not separated in the HTTP client"
                .to_owned(),
        );
    } else {
        match backend.probe_tls(
            &mut tracker,
            selected_address,
            &parsed.summary.host,
            spec.options.show_addresses,
        ) {
            Ok(summary) => {
                phases.push(passed_phase(
                    PhaseName::Tls,
                    elapsed_ms(tls_started),
                    vec![observation(
                        "tls_negotiation",
                        serde_json::to_value(&summary).unwrap_or(Value::Null),
                        "independent rustls handshake using the Mozilla public root set",
                    )],
                ));
                tls_summary = Some(summary);
            }
            Err(error) => {
                phases.push(failed_phase(
                    PhaseName::Tls,
                    elapsed_ms(tls_started),
                    &error.code,
                    &error.message,
                    error.retryable,
                ));
                return Ok(finalize_report(
                    parsed.summary,
                    proxy,
                    spec.options.clone(),
                    tracker,
                    started_at_unix_ms,
                    address_observations,
                    None,
                    Vec::new(),
                    phases,
                    omissions,
                ));
            }
        }
    }

    let http_started = Instant::now();
    let http_result = backend.run_http(
        &mut tracker,
        &parsed.url,
        &proxy,
        selected_address,
        &spec.options,
    );
    let (hops, redirect_failure) = match http_result {
        Ok(result) => result,
        Err(error) => {
            phases.push(failed_phase(
                PhaseName::Http,
                elapsed_ms(http_started),
                &error.code,
                &error.message,
                error.retryable,
            ));
            return Ok(finalize_report(
                parsed.summary,
                proxy,
                spec.options.clone(),
                tracker,
                started_at_unix_ms,
                address_observations,
                tls_summary,
                Vec::new(),
                phases,
                omissions,
            ));
        }
    };

    phases.push(passed_phase(
        PhaseName::Http,
        elapsed_ms(http_started),
        vec![observation(
            "response_statuses",
            json!(hops.iter().map(|hop| hop.status).collect::<Vec<_>>()),
            "bounded HTTP responses with automatic redirects disabled",
        )],
    ));

    if let Some(error) = redirect_failure {
        phases.push(failed_phase(
            PhaseName::Redirects,
            0,
            &error.code,
            &error.message,
            error.retryable,
        ));
    } else if hops.len() > 1 {
        phases.push(passed_phase(
            PhaseName::Redirects,
            0,
            vec![observation(
                "redirect_hops",
                json!(hops.len() - 1),
                "manually followed after validating each target and budget",
            )],
        ));
    } else {
        phases.push(skipped_phase(
            PhaseName::Redirects,
            "the response did not request a redirect",
        ));
    }

    phases.push(skipped_phase(
        PhaseName::Assertions,
        "no application-level assertion was configured",
    ));

    Ok(finalize_report(
        parsed.summary,
        proxy,
        spec.options.clone(),
        tracker,
        started_at_unix_ms,
        address_observations,
        tls_summary,
        hops,
        phases,
        omissions,
    ))
}

trait DiagnosticBackend {
    fn resolve_addresses(
        &mut self,
        tracker: &mut Tracker,
        proxy: &ResolvedProxy,
        options: &InspectionOptions,
    ) -> AppResult<(Vec<SocketAddr>, Vec<SocketAddr>)>;

    fn connect_first(
        &mut self,
        tracker: &mut Tracker,
        addresses: &[SocketAddr],
        options: &InspectionOptions,
    ) -> AppResult<SocketAddr>;

    fn probe_tls(
        &mut self,
        tracker: &mut Tracker,
        address: SocketAddr,
        server_host: &str,
        show_addresses: bool,
    ) -> AppResult<TlsSummary>;

    fn run_http(
        &mut self,
        tracker: &mut Tracker,
        initial_url: &Url,
        initial_proxy: &ResolvedProxy,
        initial_address: SocketAddr,
        options: &InspectionOptions,
    ) -> AppResult<(Vec<HttpHop>, Option<AppError>)>;
}

struct LiveBackend;

impl DiagnosticBackend for LiveBackend {
    fn resolve_addresses(
        &mut self,
        tracker: &mut Tracker,
        proxy: &ResolvedProxy,
        options: &InspectionOptions,
    ) -> AppResult<(Vec<SocketAddr>, Vec<SocketAddr>)> {
        resolve_addresses(tracker, proxy, options)
    }

    fn connect_first(
        &mut self,
        tracker: &mut Tracker,
        addresses: &[SocketAddr],
        options: &InspectionOptions,
    ) -> AppResult<SocketAddr> {
        connect_first(tracker, addresses, options)
    }

    fn probe_tls(
        &mut self,
        tracker: &mut Tracker,
        address: SocketAddr,
        server_host: &str,
        show_addresses: bool,
    ) -> AppResult<TlsSummary> {
        probe_tls(tracker, address, server_host, show_addresses)
    }

    fn run_http(
        &mut self,
        tracker: &mut Tracker,
        initial_url: &Url,
        initial_proxy: &ResolvedProxy,
        initial_address: SocketAddr,
        options: &InspectionOptions,
    ) -> AppResult<(Vec<HttpHop>, Option<AppError>)> {
        run_http(
            tracker,
            initial_url,
            initial_proxy,
            initial_address,
            options,
        )
    }
}

fn ensure_crypto_provider() {
    CRYPTO_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn validate_options(options: &InspectionOptions) -> AppResult<()> {
    if !(100..=120_000).contains(&options.budget_ms) {
        return Err(AppError::new(
            ErrorClass::Usage,
            "invalid_budget",
            "budget_ms must be between 100 and 120000",
        ));
    }
    if !(1..=64).contains(&options.max_probes) {
        return Err(AppError::new(
            ErrorClass::Usage,
            "invalid_probe_limit",
            "max_probes must be between 1 and 64",
        ));
    }
    if !(1..=16).contains(&options.max_addresses) {
        return Err(AppError::new(
            ErrorClass::Usage,
            "invalid_address_limit",
            "max_addresses must be between 1 and 16",
        ));
    }
    if options.max_redirects > 10 {
        return Err(AppError::new(
            ErrorClass::Usage,
            "invalid_redirect_limit",
            "max_redirects must not exceed 10",
        ));
    }
    if options.max_body_bytes > 1_048_576 {
        return Err(AppError::new(
            ErrorClass::Usage,
            "invalid_body_limit",
            "max_body_bytes must not exceed 1048576",
        ));
    }
    Ok(())
}

fn resolve_addresses(
    tracker: &mut Tracker,
    proxy: &ResolvedProxy,
    options: &InspectionOptions,
) -> AppResult<(Vec<SocketAddr>, Vec<SocketAddr>)> {
    let destination = socket_destination(&proxy.connect_host, proxy.connect_port);
    let probe = tracker.start_probe(ProbeKind::DnsLookup, destination.clone())?;
    let resolution_started = Instant::now();
    let result = destination.to_socket_addrs();
    let addresses = match result {
        Ok(addresses) => {
            let mut seen = HashSet::new();
            let mut addresses = addresses
                .filter(|address| seen.insert(*address))
                .collect::<Vec<_>>();
            addresses.sort_by_key(|address| (address.is_ipv6(), address.ip(), address.port()));
            tracker.finish_probe(probe, resolution_started, "resolved");
            addresses
        }
        Err(_) => {
            tracker.finish_probe(probe, resolution_started, "failed");
            return Err(AppError::new(
                ErrorClass::Io,
                "dns_resolution_failed",
                "the system resolver did not return an address",
            )
            .retryable(true));
        }
    };

    if addresses.is_empty() {
        return Err(AppError::new(
            ErrorClass::Io,
            "dns_empty_answer",
            "the system resolver returned an empty address set",
        )
        .retryable(true));
    }

    let permitted = addresses
        .iter()
        .copied()
        .filter(|address| is_ip_permitted(address.ip(), options.allow_private))
        .take(options.max_addresses)
        .collect();
    Ok((addresses, permitted))
}

fn connect_first(
    tracker: &mut Tracker,
    addresses: &[SocketAddr],
    options: &InspectionOptions,
) -> AppResult<SocketAddr> {
    for address in addresses.iter().take(options.max_addresses) {
        let destination = address_for_report(*address, options.show_addresses);
        let probe = tracker.start_probe(ProbeKind::TcpConnect, destination)?;
        let started = Instant::now();
        let timeout = tracker.remaining()?.min(Duration::from_secs(5));
        match TcpStream::connect_timeout(address, timeout) {
            Ok(stream) => {
                drop(stream);
                tracker.finish_probe(probe, started, "connected");
                return Ok(*address);
            }
            Err(_) => tracker.finish_probe(probe, started, "failed"),
        }
    }

    Err(AppError::new(
        ErrorClass::Io,
        "tcp_connect_failed",
        "no permitted resolved address accepted a bounded TCP connection",
    )
    .retryable(true))
}

fn probe_tls(
    tracker: &mut Tracker,
    address: SocketAddr,
    server_host: &str,
    show_addresses: bool,
) -> AppResult<TlsSummary> {
    let destination = address_for_report(address, show_addresses);
    let probe = tracker.start_probe(ProbeKind::TlsHandshake, destination)?;
    let started = Instant::now();
    let timeout = tracker.remaining()?.min(Duration::from_secs(7));
    let stream = TcpStream::connect_timeout(&address, timeout).map_err(|_| {
        tracker.finish_probe(probe.clone(), started, "tcp_failed");
        AppError::new(
            ErrorClass::Io,
            "tls_transport_failed",
            "a fresh TCP connection for the TLS handshake failed",
        )
        .retryable(true)
    })?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let config = tls_client_config();
    let server_name = ServerName::try_from(server_host.to_owned()).map_err(|_| {
        tracker.finish_probe(probe.clone(), started, "invalid_server_name");
        AppError::new(
            ErrorClass::Usage,
            "invalid_tls_server_name",
            "the target host cannot be represented as a TLS server name",
        )
    })?;
    let connection = ClientConnection::new(Arc::new(config), server_name).map_err(|_| {
        tracker.finish_probe(probe.clone(), started, "configuration_failed");
        AppError::new(
            ErrorClass::Contract,
            "tls_configuration_failed",
            "the TLS client could not initialize",
        )
    })?;
    let mut tls = StreamOwned::new(connection, stream);
    while tls.conn.is_handshaking() {
        if tracker.remaining()?.is_zero() {
            tracker.finish_probe(probe.clone(), started, "budget_exhausted");
            return Err(budget_exhausted());
        }
        tls.conn.complete_io(&mut tls.sock).map_err(|_| {
            tracker.finish_probe(probe.clone(), started, "handshake_failed");
            AppError::new(
                ErrorClass::Io,
                "tls_handshake_failed",
                "TLS negotiation or certificate validation failed",
            )
            .retryable(false)
        })?;
    }

    let certificates = tls.conn.peer_certificates().unwrap_or_default();
    let leaf_digest = certificates
        .first()
        .map(|certificate| crate::hex::encode_lower(Sha256::digest(certificate.as_ref())));
    let summary = TlsSummary {
        protocol: tls
            .conn
            .protocol_version()
            .map(|version| format!("{version:?}")),
        cipher_suite: tls
            .conn
            .negotiated_cipher_suite()
            .map(|suite| format!("{:?}", suite.suite())),
        alpn: tls
            .conn
            .alpn_protocol()
            .map(|protocol| String::from_utf8_lossy(protocol).into_owned()),
        peer_leaf_sha256: leaf_digest,
        peer_certificate_count: certificates.len(),
    };
    tracker.finish_probe(probe, started, "validated");
    Ok(summary)
}

fn run_http(
    tracker: &mut Tracker,
    initial_url: &Url,
    initial_proxy: &ResolvedProxy,
    initial_address: SocketAddr,
    options: &InspectionOptions,
) -> AppResult<(Vec<HttpHop>, Option<AppError>)> {
    let mut current = initial_url.clone();
    let mut hops = Vec::new();
    let mut proxy = initial_proxy.clone();
    let mut selected_address = initial_address;

    for sequence in 0..=options.max_redirects {
        if sequence > 0 {
            let parsed = match parse_target(current.as_str(), options) {
                Ok(parsed) => parsed,
                Err(error) => return Ok((hops, Some(error))),
            };
            proxy = match resolve_proxy(&parsed.url, options) {
                Ok(proxy) => proxy,
                Err(error) => return Ok((hops, Some(error))),
            };
            let (_, permitted) = match resolve_addresses(tracker, &proxy, options) {
                Ok(addresses) => addresses,
                Err(error) => return Ok((hops, Some(error))),
            };
            let Some(address) = permitted.first().copied() else {
                return Ok((
                    hops,
                    Some(AppError::new(
                        ErrorClass::Policy,
                        "redirect_target_denied",
                        "a redirect resolved only to addresses denied by policy",
                    )),
                ));
            };
            selected_address = address;
        }

        let client = build_http_client(tracker, &proxy, selected_address)?;
        let redacted_url = redact_url(&current, options.show_query_values);
        let probe = tracker.start_probe(ProbeKind::HttpRequest, redacted_url.clone())?;
        let started = Instant::now();
        let request = match options.method {
            RequestMethod::Get => client.get(current.clone()),
            RequestMethod::Head => client.head(current.clone()),
        };
        let response = match request.send() {
            Ok(response) => {
                tracker.finish_probe(probe, started, "response_received");
                response
            }
            Err(error) => {
                tracker.finish_probe(probe, started, "request_failed");
                return Err(classify_http_error(&error, current.scheme()));
            }
        };

        let status = response.status();
        let location_header = response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let (next_url, redirect_error) = if status.is_redirection() {
            match location_header
                .as_deref()
                .map(|location| current.join(location))
                .transpose()
            {
                Ok(next_url) => (next_url, None),
                Err(_) => (
                    None,
                    Some(AppError::new(
                        ErrorClass::Contract,
                        "invalid_redirect_location",
                        "the server returned a redirect Location that is not a valid URL reference",
                    )),
                ),
            }
        } else {
            (None, None)
        };
        let location = next_url
            .as_ref()
            .map(|url| redact_url(url, options.show_query_values));
        let hop = response_to_hop(response, sequence, redacted_url, location, tracker, options)?;
        hops.push(hop);

        if let Some(error) = redirect_error {
            return Ok((hops, Some(error)));
        }
        let Some(next_url) = next_url else {
            return Ok((hops, None));
        };
        if sequence == options.max_redirects {
            return Ok((
                hops,
                Some(AppError::new(
                    ErrorClass::Budget,
                    "redirect_limit_reached",
                    "the response requested another redirect after the configured limit",
                )),
            ));
        }
        current = next_url;
    }

    Ok((hops, None))
}

fn build_http_client(
    tracker: &Tracker,
    proxy: &ResolvedProxy,
    selected_address: SocketAddr,
) -> AppResult<Client> {
    let remaining = tracker.remaining()?.min(Duration::from_secs(10));
    let mut builder = ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(remaining)
        .timeout(remaining)
        .user_agent(format!("hopwhy/{TOOL_VERSION}"))
        .no_proxy()
        .resolve(&proxy.connect_host, selected_address)
        .tls_backend_preconfigured(tls_client_config());

    if let Some(proxy_url) = &proxy.url {
        let reqwest_proxy = reqwest::Proxy::all(proxy_url.as_str()).map_err(|_| {
            AppError::new(
                ErrorClass::Policy,
                "proxy_configuration_rejected",
                "the selected proxy could not be configured by the HTTP client",
            )
        })?;
        builder = builder.proxy(reqwest_proxy);
    }

    builder.build().map_err(|_| {
        AppError::new(
            ErrorClass::Contract,
            "http_client_initialization_failed",
            "the bounded HTTP client could not initialize",
        )
    })
}

fn tls_client_config() -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

fn response_to_hop(
    response: Response,
    sequence: usize,
    url: String,
    location: Option<String>,
    tracker: &mut Tracker,
    options: &InspectionOptions,
) -> AppResult<HttpHop> {
    let status = response.status().as_u16();
    let version = version_name(response.version()).to_owned();
    let declared_content_length = response.content_length();
    let headers = safe_headers(response.headers());

    let limit = options.max_body_bytes;
    let read_limit = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut body = Vec::with_capacity(limit.min(65_536).saturating_add(1));
    response
        .take(read_limit)
        .read_to_end(&mut body)
        .map_err(|_| {
            AppError::new(
                ErrorClass::Io,
                "response_body_read_failed",
                "the bounded response body sample could not be read",
            )
            .retryable(true)
        })?;
    let truncated = body.len() > limit;
    if truncated {
        body.truncate(limit);
    }
    tracker.response_bytes_read = tracker.response_bytes_read.saturating_add(body.len());
    let digest = crate::hex::encode_lower(Sha256::digest(&body));
    let encoded = options
        .include_body_sample
        .then(|| base64::engine::general_purpose::STANDARD.encode(&body));

    Ok(HttpHop {
        sequence,
        url,
        status,
        version,
        headers,
        declared_content_length,
        returned_body_bytes: body.len(),
        body_truncated: truncated,
        body_sample_sha256: digest,
        body_sample_base64: encoded,
        location,
    })
}

fn safe_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    [
        "content-type",
        "content-length",
        "cache-control",
        "date",
        "retry-after",
    ]
    .into_iter()
    .filter_map(|name| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(|value| (name.to_owned(), sanitize_header_value(value)))
    })
    .collect()
}

fn sanitize_header_value(value: &str) -> String {
    value
        .chars()
        .take(512)
        .map(|character| {
            if character.is_control() && !matches!(character, '\t') {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}

fn version_name(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "unknown",
    }
}

fn classify_http_error(error: &reqwest::Error, scheme: &str) -> AppError {
    if error.is_timeout() {
        AppError::new(
            ErrorClass::Budget,
            "http_timeout",
            "the HTTP request exceeded its bounded timeout",
        )
        .retryable(true)
    } else if error.is_connect() && scheme == "https" {
        AppError::new(
            ErrorClass::Io,
            "http_tls_or_connect_failed",
            "the HTTP client could not establish the HTTPS transport; inspect the independent TCP and TLS phases",
        )
        .retryable(true)
    } else if error.is_connect() {
        AppError::new(
            ErrorClass::Io,
            "http_connect_failed",
            "the HTTP client could not establish its transport connection",
        )
        .retryable(true)
    } else {
        AppError::new(
            ErrorClass::Io,
            "http_request_failed",
            "the bounded HTTP request failed before a response was available",
        )
        .retryable(true)
    }
}

#[allow(clippy::too_many_arguments)]
fn finalize_report(
    target: TargetSummary,
    proxy: ResolvedProxy,
    options: InspectionOptions,
    tracker: Tracker,
    started_at_unix_ms: u64,
    addresses: Vec<AddressObservation>,
    tls: Option<TlsSummary>,
    http: Vec<HttpHop>,
    phases: Vec<Phase>,
    omissions: Vec<String>,
) -> Report {
    let failed_at = phases
        .iter()
        .find(|phase| phase.status == PhaseStatus::Failed)
        .map(|phase| phase.name);
    let hypotheses = hypotheses_for(failed_at, &phases);
    let ruled_out = ruled_out_for(failed_at, &phases);
    let elapsed_ms = tracker.elapsed_ms();
    let probes_used = u32::try_from(tracker.probes.len()).unwrap_or(u32::MAX);
    let budget = Budget {
        duration_ms: options.budget_ms,
        max_probes: options.max_probes,
        max_addresses: options.max_addresses,
        max_redirects: options.max_redirects,
        max_body_bytes: options.max_body_bytes,
    };
    let mut report = Report {
        schema_version: REPORT_SCHEMA_VERSION.to_owned(),
        tool_version: TOOL_VERSION.to_owned(),
        started_at_unix_ms,
        target,
        proxy: proxy.summary,
        options,
        budget,
        usage: Usage {
            elapsed_ms,
            probes_used,
            response_bytes_read: tracker.response_bytes_read,
        },
        probes: tracker.probes,
        addresses,
        tls,
        http,
        phases,
        failed_at,
        hypotheses,
        ruled_out,
        omissions,
        report_sha256: None,
    };
    report.report_sha256 = digest_report(&report).ok();
    report
}

pub fn digest_report(report: &Report) -> AppResult<String> {
    let mut unsigned = report.clone();
    unsigned.report_sha256 = None;
    digest_serializable(&unsigned)
}

pub fn digest_serializable<T: Serialize>(value: &T) -> AppResult<String> {
    let serialized = serde_json::to_vec(value).map_err(|_| {
        AppError::new(
            ErrorClass::Contract,
            "serialization_failed",
            "a machine-readable document could not be serialized",
        )
    })?;
    Ok(crate::hex::encode_lower(Sha256::digest(serialized)))
}

fn hypotheses_for(failed_at: Option<PhaseName>, phases: &[Phase]) -> Vec<Hypothesis> {
    let Some(phase) = failed_at else {
        return vec![Hypothesis {
            code: "request_path_observed".to_owned(),
            statement: "The configured request reached an HTTP response within budget.".to_owned(),
            confidence: 1.0,
            evidence_phases: vec![PhaseName::Dns, PhaseName::Tcp, PhaseName::Http],
            next_safe_step:
                "Add an explicit application assertion before treating a reachable response as healthy."
                    .to_owned(),
        }];
    };

    let error_code = phases
        .iter()
        .find(|candidate| candidate.name == phase)
        .and_then(|candidate| candidate.error.as_ref())
        .map_or("phase_failed", |error| error.code.as_str());
    let (statement, confidence, next_step) = match phase {
        PhaseName::Input | PhaseName::Proxy => (
            "The request was rejected before network probing.",
            1.0,
            "Correct the target or proxy policy and run a dry-run plan before probing.",
        ),
        PhaseName::Dns => (
            "Progress stopped while resolving or authorizing the connection endpoint.",
            0.95,
            "Compare resolver results and the public/private target policy in the failing environment.",
        ),
        PhaseName::Tcp => (
            "DNS produced an allowed address, but no bounded TCP connection succeeded.",
            0.9,
            "Check listener state, route/firewall policy, and address-family-specific reachability.",
        ),
        PhaseName::Tls => (
            "TCP connectivity succeeded, but TLS negotiation or identity validation did not.",
            0.95,
            "Inspect certificate trust, server name, clock, and TLS policy without disabling validation.",
        ),
        PhaseName::Http => (
            "Earlier transport phases progressed, but the bounded HTTP client received no response.",
            0.8,
            "Inspect proxy behavior and server request handling; preserve TLS validation.",
        ),
        PhaseName::Redirects => (
            "An HTTP response was received, but the redirect chain violated policy or budget.",
            1.0,
            "Review the recorded Location target and increase limits only after confirming intent.",
        ),
        PhaseName::Assertions => (
            "The network path completed, but an application assertion failed.",
            1.0,
            "Inspect the recorded response metadata and the configured assertion.",
        ),
    };
    vec![Hypothesis {
        code: error_code.to_owned(),
        statement: statement.to_owned(),
        confidence,
        evidence_phases: vec![phase],
        next_safe_step: next_step.to_owned(),
    }]
}

fn ruled_out_for(failed_at: Option<PhaseName>, phases: &[Phase]) -> Vec<String> {
    if failed_at.is_none() {
        return Vec::new();
    }
    phases
        .iter()
        .filter(|phase| phase.status == PhaseStatus::Passed)
        .filter_map(|phase| match phase.name {
            PhaseName::Dns => Some("complete DNS resolution failure".to_owned()),
            PhaseName::Tcp => Some("complete TCP reachability failure".to_owned()),
            PhaseName::Tls => Some("TLS negotiation failure on the independent probe".to_owned()),
            PhaseName::Http => Some("absence of every HTTP response".to_owned()),
            _ => None,
        })
        .collect()
}

fn passed_phase(
    name: PhaseName,
    duration_ms: u64,
    observations: Vec<crate::model::Observation>,
) -> Phase {
    Phase {
        name,
        status: PhaseStatus::Passed,
        duration_ms,
        observations,
        limitations: Vec::new(),
        error: None,
    }
}

fn failed_phase(
    name: PhaseName,
    duration_ms: u64,
    code: &str,
    message: &str,
    retryable: bool,
) -> Phase {
    Phase {
        name,
        status: PhaseStatus::Failed,
        duration_ms,
        observations: Vec::new(),
        limitations: Vec::new(),
        error: Some(DiagnosticError {
            code: code.to_owned(),
            message: message.to_owned(),
            retryable,
        }),
    }
}

fn skipped_phase(name: PhaseName, limitation: &str) -> Phase {
    Phase {
        name,
        status: PhaseStatus::Skipped,
        duration_ms: 0,
        observations: Vec::new(),
        limitations: vec![limitation.to_owned()],
        error: None,
    }
}

fn not_observed_phase(name: PhaseName, limitation: &str) -> Phase {
    Phase {
        name,
        status: PhaseStatus::NotObserved,
        duration_ms: 0,
        observations: Vec::new(),
        limitations: vec![limitation.to_owned()],
        error: None,
    }
}

fn observation(kind: &str, value: Value, evidence: &str) -> crate::model::Observation {
    crate::model::Observation {
        kind: kind.to_owned(),
        value,
        evidence: evidence.to_owned(),
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn budget_exhausted() -> AppError {
    AppError::new(
        ErrorClass::Budget,
        "budget_exhausted",
        "the global diagnostic duration or probe budget was exhausted",
    )
    .retryable(true)
}

#[derive(Debug, Clone)]
struct ActiveProbe {
    sequence: u32,
    kind: ProbeKind,
    destination: String,
    started_ms: u64,
}

struct Tracker {
    started: Instant,
    deadline: Instant,
    max_probes: u32,
    probes: Vec<ProbeRecord>,
    response_bytes_read: usize,
}

impl Tracker {
    fn new(options: &InspectionOptions) -> Self {
        let started = Instant::now();
        Self {
            started,
            deadline: started + Duration::from_millis(options.budget_ms),
            max_probes: options.max_probes,
            probes: Vec::new(),
            response_bytes_read: 0,
        }
    }

    fn remaining(&self) -> AppResult<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(budget_exhausted)
    }

    fn start_probe(&mut self, kind: ProbeKind, destination: String) -> AppResult<ActiveProbe> {
        self.remaining()?;
        let used = u32::try_from(self.probes.len()).unwrap_or(u32::MAX);
        if used >= self.max_probes {
            return Err(budget_exhausted());
        }
        Ok(ActiveProbe {
            sequence: used + 1,
            kind,
            destination,
            started_ms: self.elapsed_ms(),
        })
    }

    fn finish_probe(&mut self, probe: ActiveProbe, started: Instant, outcome: &str) {
        self.probes.push(ProbeRecord {
            sequence: probe.sequence,
            kind: probe.kind,
            destination: probe.destination,
            started_ms: probe.started_ms,
            duration_ms: elapsed_ms(started),
            outcome: outcome.to_owned(),
        });
    }

    fn elapsed_ms(&self) -> u64 {
        elapsed_ms(self.started)
    }
}

#[cfg(test)]
mod tests {
    use super::plan;
    use crate::model::{InspectSpec, InspectionOptions};

    #[test]
    fn dry_run_never_performs_network_activity() {
        let specification = InspectSpec {
            target: "https://example.com/private?token=secret".to_owned(),
            options: InspectionOptions::default(),
        };
        let result = plan(&specification);
        assert!(result.is_ok());
        if let Ok(plan) = result {
            assert!(!plan.network_performed);
            assert!(plan.target.intended.contains("REDACTED"));
        }
    }
}
