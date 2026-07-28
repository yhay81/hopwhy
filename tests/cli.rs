#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

const PROXY_VARIABLES: &[&str] = &[
    "http_proxy",
    "HTTP_PROXY",
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "no_proxy",
    "NO_PROXY",
];
static NETWORK_TEST_LOCK: Mutex<()> = Mutex::new(());

fn network_guard() -> MutexGuard<'static, ()> {
    NETWORK_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn command() -> Command {
    let mut command = Command::cargo_bin("hopwhy").unwrap();
    for variable in PROXY_VARIABLES {
        command.env_remove(variable);
    }
    command
}

fn json_output(arguments: &[&str]) -> Value {
    let output = command()
        .args(arguments)
        .assert()
        .success()
        .get_output()
        .clone();
    serde_json::from_slice(&output.stdout).unwrap()
}

struct Fixture {
    address: SocketAddr,
    handle: JoinHandle<()>,
}

impl Fixture {
    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.address, path)
    }

    fn finish(self) {
        self.handle.join().unwrap();
    }
}

fn fixture(routes: Vec<(&'static str, &'static str)>) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut accepted_connections = 0;
        let mut requests = 0;
        while requests < routes.len() && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    accepted_connections += 1;
                    // Accepted sockets can inherit nonblocking mode differently
                    // across platforms. The fixture needs a bounded blocking
                    // read so it does not close just before request bytes arrive.
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    let mut bytes = [0_u8; 8_192];
                    let read = stream.read(&mut bytes).unwrap_or(0);
                    if read == 0 {
                        continue;
                    }
                    let request = String::from_utf8_lossy(&bytes[..read]);
                    let path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let response = routes
                        .iter()
                        .find(|(route, _)| path.starts_with(route))
                        .map_or(
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        |(_, response)| *response,
                    );
                    stream.write_all(response.as_bytes()).unwrap();
                    requests += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
        assert_eq!(
            requests,
            routes.len(),
            "fixture served {requests}/{} requests after accepting {accepted_connections} connections",
            routes.len()
        );
    });
    Fixture { address, handle }
}

fn write_report(path: &Path, report: &Value) {
    fs::write(path, serde_json::to_vec_pretty(report).unwrap()).unwrap();
}

#[test]
fn version_schema_and_completions_are_available() {
    command()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "hopwhy {}",
            env!("CARGO_PKG_VERSION")
        )));

    let schema = json_output(&["--format", "json", "schema", "--document", "report"]);
    assert_eq!(
        schema["$schema"],
        Value::String("http://json-schema.org/draft-07/schema#".to_owned())
    );
    assert_eq!(schema["title"], Value::String("Report".to_owned()));

    command()
        .args(["completions", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("#compdef hopwhy"));
}

#[test]
fn dry_run_is_network_free_and_redacts_query_values() {
    let result = json_output(&[
        "--format",
        "json",
        "inspect",
        "https://example.com/private?token=secret",
        "--dry-run",
    ]);
    assert_eq!(result["schema_version"], "hopwhy.plan.v1");
    assert_eq!(result["network_performed"], false);
    assert!(result["target"]["intended"]
        .as_str()
        .unwrap()
        .contains("token=REDACTED"));
    assert!(result["planned_probes"].as_array().unwrap().len() >= 4);
}

#[test]
fn non_public_targets_are_denied_by_default_after_resolution() {
    let result = json_output(&[
        "--format",
        "json",
        "inspect",
        "http://127.0.0.1:9/?secret=value",
        "--disable-proxy",
    ]);
    assert_eq!(result["schema_version"], "hopwhy.report.v1");
    assert_eq!(result["failed_at"], "dns");
    assert_eq!(
        result["phases"][2]["error"]["code"],
        "non_public_address_denied"
    );
    assert_eq!(result["usage"]["probes_used"], 1);
    assert!(result["target"]["intended"]
        .as_str()
        .unwrap()
        .contains("secret=REDACTED"));
    assert!(result["addresses"][0]["address"]
        .as_str()
        .unwrap()
        .starts_with("ipv4#"));
}

#[test]
fn local_fixture_report_replays_offline_with_integrity() {
    let _network_guard = network_guard();
    let server = fixture(vec![(
        "/health",
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 7\r\nX-Secret: hidden\r\nConnection: close\r\n\r\nhealthy",
    )]);
    let url = server.url("/health");
    let report = json_output(&[
        "--format",
        "json",
        "inspect",
        &url,
        "--allow-private",
        "--disable-proxy",
    ]);
    server.finish();

    assert_eq!(report["failed_at"], Value::Null);
    assert_eq!(report["http"][0]["status"], 200);
    assert_eq!(report["http"][0]["body_sample_base64"], Value::Null);
    assert_eq!(report["http"][0]["returned_body_bytes"], 7);
    assert!(report["http"][0]["headers"].get("x-secret").is_none());
    assert_eq!(report["phases"][5]["status"], "passed");
    assert_eq!(report["report_sha256"].as_str().unwrap().len(), 64);

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("report.json");
    write_report(&path, &report);
    let replay = json_output(&["--format", "json", "replay", path.to_str().unwrap()]);
    assert_eq!(replay["integrity_valid"], true);
    assert_eq!(replay["network_performed"], false);
    assert_eq!(replay["report_sha256"], report["report_sha256"].clone());
}

#[test]
fn body_samples_require_opt_in_and_remain_bounded() {
    let _network_guard = network_guard();
    let server = fixture(vec![(
        "/body",
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 16\r\nConnection: close\r\n\r\n0123456789abcdef",
    )]);
    let url = server.url("/body");
    let report = json_output(&[
        "--format",
        "json",
        "inspect",
        &url,
        "--allow-private",
        "--disable-proxy",
        "--max-body-bytes",
        "5",
        "--include-body-sample",
    ]);
    server.finish();

    assert_eq!(report["http"][0]["returned_body_bytes"], 5);
    assert_eq!(report["http"][0]["body_truncated"], true);
    assert_eq!(report["http"][0]["body_sample_base64"], "MDEyMzQ=");
}

#[test]
fn redirects_are_followed_manually_and_redacted() {
    let _network_guard = network_guard();
    let server = fixture(vec![
        (
            "/start",
            "HTTP/1.1 302 Found\r\nLocation: /final?token=secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ),
        (
            "/final",
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ),
    ]);
    let url = server.url("/start");
    let report = json_output(&[
        "--format",
        "json",
        "inspect",
        &url,
        "--allow-private",
        "--disable-proxy",
    ]);
    server.finish();

    assert_eq!(report["http"].as_array().unwrap().len(), 2);
    assert_eq!(report["http"][0]["status"], 302);
    assert!(report["http"][0]["location"]
        .as_str()
        .unwrap()
        .contains("token=REDACTED"));
    assert_eq!(report["http"][1]["status"], 204);
    assert_eq!(report["phases"][6]["status"], "passed");
}

#[test]
fn invalid_redirect_locations_fail_the_redirect_phase() {
    let _network_guard = network_guard();
    let server = fixture(vec![(
        "/bad",
        "HTTP/1.1 302 Found\r\nLocation: http://[\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )]);
    let url = server.url("/bad");
    let report = json_output(&[
        "--format",
        "json",
        "inspect",
        &url,
        "--allow-private",
        "--disable-proxy",
    ]);
    server.finish();

    assert_eq!(report["failed_at"], "redirects");
    assert_eq!(
        report["phases"][6]["error"]["code"],
        "invalid_redirect_location"
    );
    assert_eq!(report["http"][0]["status"], 302);
}

#[test]
fn compare_reports_detects_http_status_differences() {
    let _network_guard = network_guard();
    let first = fixture(vec![(
        "/",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )]);
    let first_url = first.url("/");
    let left = json_output(&[
        "--format",
        "json",
        "inspect",
        &first_url,
        "--allow-private",
        "--disable-proxy",
    ]);
    first.finish();

    let second = fixture(vec![(
        "/",
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )]);
    let second_url = second.url("/");
    let right = json_output(&[
        "--format",
        "json",
        "inspect",
        &second_url,
        "--allow-private",
        "--disable-proxy",
    ]);
    second.finish();

    let directory = tempfile::tempdir().unwrap();
    let left_path = directory.path().join("left.json");
    let right_path = directory.path().join("right.json");
    write_report(&left_path, &left);
    write_report(&right_path, &right);

    let result = json_output(&[
        "--format",
        "json",
        "compare",
        left_path.to_str().unwrap(),
        right_path.to_str().unwrap(),
    ]);
    assert_eq!(result["same_failed_phase"], true);
    assert_ne!(result["left_http_statuses"], result["right_http_statuses"]);
    assert!(result["summary"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item == "HTTP status sequence differs"));
}

#[test]
fn proxy_credentials_are_never_emitted() {
    let output = command()
        .env("http_proxy", "http://agent:secret@127.0.0.1:9")
        .args(["--format", "json", "inspect", "http://example.com/"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let rendered = String::from_utf8(output.stdout).unwrap();

    assert_eq!(report["proxy"]["selected"], true);
    assert_eq!(report["proxy"]["source"], "http_proxy");
    assert!(!rendered.contains("agent"));
    assert!(!rendered.contains("secret"));
    assert_eq!(report["failed_at"], "dns");
}

#[test]
fn tampering_is_rejected_with_contract_exit_code() {
    let report = json_output(&[
        "--format",
        "json",
        "inspect",
        "http://127.0.0.1:9/",
        "--disable-proxy",
    ]);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("tampered.json");
    let mut tampered = report;
    tampered["target"]["intended"] = Value::String("http://tampered.invalid/".to_owned());
    write_report(&path, &tampered);

    command()
        .args(["--format", "ndjson", "replay", path.to_str().unwrap()])
        .assert()
        .code(5)
        .stderr(predicate::str::contains("report_integrity_mismatch"));
}

#[test]
fn cli_usage_errors_follow_the_selected_machine_format() {
    command()
        .args(["--format", "ndjson", "inspect"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            r#""schema_version":"hopwhy.error.v1""#,
        ))
        .stderr(predicate::str::contains(
            r#""code":"missing_inspect_input""#,
        ));
}

#[test]
fn probe_budget_exhaustion_is_reported_as_evidence() {
    let result = json_output(&[
        "--format",
        "json",
        "inspect",
        "http://127.0.0.1:9/",
        "--allow-private",
        "--disable-proxy",
        "--max-probes",
        "1",
    ]);
    assert_eq!(result["failed_at"], "tcp");
    assert_eq!(result["phases"][3]["error"]["code"], "budget_exhausted");
    assert_eq!(result["usage"]["probes_used"], 1);
}

#[test]
fn specs_reject_unknown_fields() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bad-spec.json");
    fs::write(
        &path,
        br#"{"target":"https://example.com","options":{"unknown":true}}"#,
    )
    .unwrap();

    command()
        .args([
            "--format",
            "json",
            "inspect",
            "--spec",
            path.to_str().unwrap(),
            "--dry-run",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid_spec"));
}
