use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use sha2::{Digest, Sha256};
use url::Url;

use crate::error::{AppError, AppResult, ErrorClass};
use crate::model::{InspectionOptions, ProxySummary, TargetSummary};

#[derive(Debug, Clone)]
pub struct ParsedTarget {
    pub url: Url,
    pub summary: TargetSummary,
}

#[derive(Debug, Clone)]
pub struct ResolvedProxy {
    pub summary: ProxySummary,
    pub url: Option<Url>,
    pub connect_host: String,
    pub connect_port: u16,
}

pub fn parse_target(raw: &str, options: &InspectionOptions) -> AppResult<ParsedTarget> {
    let mut url = Url::parse(raw).map_err(|error| {
        AppError::new(
            ErrorClass::Usage,
            "invalid_target",
            format!("target must be an absolute HTTP(S) URL: {error}"),
        )
    })?;

    if !matches!(url.scheme(), "http" | "https") {
        return Err(AppError::new(
            ErrorClass::Policy,
            "unsupported_scheme",
            "only http and https targets are supported",
        ));
    }
    if url.host_str().is_none() {
        return Err(AppError::new(
            ErrorClass::Usage,
            "missing_target_host",
            "target URL must include a host",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(AppError::new(
            ErrorClass::Policy,
            "embedded_credentials_denied",
            "URL user information is denied; provide an unauthenticated diagnostic target",
        ));
    }

    url.set_fragment(None);
    let host = url.host_str().unwrap_or_default().to_owned();
    let port = url.port_or_known_default().ok_or_else(|| {
        AppError::new(
            ErrorClass::Usage,
            "missing_target_port",
            "target scheme does not imply a port",
        )
    })?;
    let redacted = redact_url(&url, options.show_query_values);

    Ok(ParsedTarget {
        summary: TargetSummary {
            intended: redacted.clone(),
            effective: redacted,
            scheme: url.scheme().to_owned(),
            host,
            port,
        },
        url,
    })
}

pub fn redact_url(url: &Url, show_query_values: bool) -> String {
    let mut redacted = url.clone();
    let _ = redacted.set_username("");
    let _ = redacted.set_password(None);
    redacted.set_fragment(None);

    if redacted.query().is_some() && !show_query_values {
        let keys: Vec<String> = redacted
            .query_pairs()
            .map(|(key, _)| key.into_owned())
            .collect();
        redacted.set_query(None);
        {
            let mut pairs = redacted.query_pairs_mut();
            for key in keys {
                pairs.append_pair(&key, "REDACTED");
            }
        }
    }
    redacted.to_string()
}

pub fn resolve_proxy(target: &Url, options: &InspectionOptions) -> AppResult<ResolvedProxy> {
    let target_host = target.host_str().unwrap_or_default();
    let target_port = target.port_or_known_default().unwrap_or(0);
    if options.disable_proxy {
        return Ok(direct_proxy_summary(
            target_host,
            target_port,
            Some("proxy use disabled by option".to_owned()),
        ));
    }

    if let Some(no_proxy) = first_environment_value(&["no_proxy", "NO_PROXY"]) {
        if no_proxy_matches(&no_proxy.value, target_host, target_port) {
            return Ok(direct_proxy_summary(
                target_host,
                target_port,
                Some(format!("matched {}", no_proxy.key)),
            ));
        }
    }

    let scheme_keys: &[&str] = if target.scheme() == "https" {
        &["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"]
    } else {
        &["http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"]
    };

    let Some(environment) = first_environment_value(scheme_keys) else {
        return Ok(direct_proxy_summary(target_host, target_port, None));
    };

    let normalized = if environment.value.contains("://") {
        environment.value.clone()
    } else {
        format!("http://{}", environment.value)
    };
    let proxy_url = Url::parse(&normalized).map_err(|error| {
        AppError::new(
            ErrorClass::Policy,
            "invalid_proxy_url",
            format!("{} is not a valid proxy URL: {error}", environment.key),
        )
    })?;
    if !matches!(proxy_url.scheme(), "http" | "https") {
        return Err(AppError::new(
            ErrorClass::Policy,
            "unsupported_proxy_scheme",
            format!(
                "{} uses unsupported scheme {}; only HTTP(S) proxies are supported",
                environment.key,
                proxy_url.scheme()
            ),
        ));
    }
    let connect_host = proxy_url
        .host_str()
        .ok_or_else(|| {
            AppError::new(
                ErrorClass::Policy,
                "missing_proxy_host",
                format!("{} does not include a proxy host", environment.key),
            )
        })?
        .to_owned();
    let connect_port = proxy_url.port_or_known_default().ok_or_else(|| {
        AppError::new(
            ErrorClass::Policy,
            "missing_proxy_port",
            format!("{} does not imply a proxy port", environment.key),
        )
    })?;

    let credential_free_endpoint = redact_url(&proxy_url, false);
    Ok(ResolvedProxy {
        summary: ProxySummary {
            selected: true,
            source: Some(environment.key),
            endpoint: Some(credential_free_endpoint.clone()),
            configuration_sha256: Some(sha256_text(&credential_free_endpoint)),
            bypass_reason: None,
        },
        url: Some(proxy_url),
        connect_host,
        connect_port,
    })
}

fn direct_proxy_summary(host: &str, port: u16, bypass_reason: Option<String>) -> ResolvedProxy {
    ResolvedProxy {
        summary: ProxySummary {
            selected: false,
            source: None,
            endpoint: None,
            configuration_sha256: None,
            bypass_reason,
        },
        url: None,
        connect_host: host.to_owned(),
        connect_port: port,
    }
}

#[derive(Debug)]
struct EnvironmentValue {
    key: String,
    value: String,
}

fn first_environment_value(keys: &[&str]) -> Option<EnvironmentValue> {
    keys.iter().find_map(|key| {
        env::var(key)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| EnvironmentValue {
                key: (*key).to_owned(),
                value,
            })
    })
}

fn no_proxy_matches(no_proxy: &str, host: &str, port: u16) -> bool {
    no_proxy.split(',').any(|entry| {
        let mut pattern = entry.trim();
        if pattern.is_empty() {
            return false;
        }
        if pattern == "*" {
            return true;
        }

        let port_suffix = format!(":{port}");
        if pattern.ends_with(&port_suffix) {
            pattern = &pattern[..pattern.len() - port_suffix.len()];
        } else if pattern.rsplit_once(':').is_some_and(|(_, suffix)| {
            !suffix.is_empty() && suffix.chars().all(|character| character.is_ascii_digit())
        }) {
            return false;
        }

        let pattern = pattern.trim_start_matches('.');
        host.eq_ignore_ascii_case(pattern)
            || host
                .to_ascii_lowercase()
                .ends_with(&format!(".{}", pattern.to_ascii_lowercase()))
    })
}

pub fn socket_destination(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub fn address_for_report(address: SocketAddr, show_addresses: bool) -> String {
    if show_addresses {
        address.to_string()
    } else {
        format!(
            "{}#{}",
            if address.is_ipv4() { "ipv4" } else { "ipv6" },
            &sha256_text(&address.to_string())[..12]
        )
    }
}

pub fn classify_ip(address: IpAddr) -> &'static str {
    match address {
        IpAddr::V4(address) => classify_ipv4(address),
        IpAddr::V6(address) => classify_ipv6(address),
    }
}

pub fn is_ip_permitted(address: IpAddr, allow_private: bool) -> bool {
    allow_private || classify_ip(address) == "public"
}

fn classify_ipv4(address: Ipv4Addr) -> &'static str {
    let octets = address.octets();
    if address.is_unspecified() {
        "unspecified"
    } else if address.is_loopback() {
        "loopback"
    } else if address.is_private() {
        "private"
    } else if address.is_link_local() {
        "link_local"
    } else if address.is_multicast() {
        "multicast"
    } else if address.is_broadcast() {
        "broadcast"
    } else if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        "shared"
    } else if (octets[0] == 192 && octets[1] == 0 && octets[2] <= 2)
        || (octets[0] == 198 && matches!(octets[1], 18 | 19 | 51))
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
    {
        "documentation_or_benchmark"
    } else if octets[0] == 0 || octets[0] >= 240 {
        "reserved"
    } else {
        "public"
    }
}

fn classify_ipv6(address: Ipv6Addr) -> &'static str {
    let segments = address.segments();
    if address.is_unspecified() {
        "unspecified"
    } else if address.is_loopback() {
        "loopback"
    } else if address.is_multicast() {
        "multicast"
    } else if segments[0] & 0xfe00 == 0xfc00 {
        "unique_local"
    } else if segments[0] & 0xffc0 == 0xfe80 {
        "link_local"
    } else if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        "documentation"
    } else if let Some(mapped) = address.to_ipv4_mapped() {
        classify_ipv4(mapped)
    } else {
        "public"
    }
}

pub fn sha256_text(value: &str) -> String {
    crate::hex::encode_lower(Sha256::digest(value.as_bytes()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{classify_ip, no_proxy_matches, parse_target, redact_url};
    use crate::model::InspectionOptions;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn classifies_non_public_addresses() {
        assert_eq!(
            classify_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            "loopback"
        );
        assert_eq!(
            classify_ip(IpAddr::V4(Ipv4Addr::new(10, 2, 3, 4))),
            "private"
        );
        assert_eq!(classify_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)), "loopback");
    }

    #[test]
    fn redacts_query_values_and_credentials_are_denied() {
        let options = InspectionOptions::default();
        let parsed =
            parse_target("https://example.com/path?token=secret&empty=", &options).unwrap();
        assert_eq!(
            parsed.summary.intended,
            "https://example.com/path?token=REDACTED&empty=REDACTED"
        );
        assert!(parse_target("https://user:secret@example.com/", &options).is_err());

        let url = url::Url::parse("https://example.com/?a=b").unwrap();
        assert_eq!(redact_url(&url, true), "https://example.com/?a=b");
    }

    #[test]
    fn no_proxy_supports_exact_suffix_port_and_wildcard() {
        assert!(no_proxy_matches(
            "localhost,.example.com",
            "api.example.com",
            443
        ));
        assert!(no_proxy_matches("example.com:443", "example.com", 443));
        assert!(!no_proxy_matches("example.com:80", "example.com", 443));
        assert!(no_proxy_matches("*", "anything.invalid", 123));
    }
}
