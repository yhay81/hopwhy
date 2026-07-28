#![allow(clippy::expect_used, clippy::panic)]

use hopwhy::engine::digest_report;
use hopwhy::model::Report;
use hopwhy::offline::{load_report, replay};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/contracts/v0.1")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("read JSON fixture")).expect("parse JSON fixture")
}

fn file_sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn mutate(document: &mut Value, operation: &str, pointer: &str, value: Value) {
    match operation {
        "replace" => *document.pointer_mut(pointer).expect("replace target") = value,
        "remove" => {
            let (parent_pointer, key) = pointer.rsplit_once('/').expect("pointer parent");
            let parent = document
                .pointer_mut(parent_pointer)
                .expect("remove parent")
                .as_object_mut()
                .expect("object parent");
            assert!(parent.remove(key).is_some());
        }
        other => panic!("unsupported mutation {other}"),
    }
}

#[test]
fn current_offline_reader_accepts_exact_v01_report() {
    let root = corpus_root();
    let manifest = read_json(&root.join("manifest.json"));
    assert_eq!(manifest["schema_version"], "hopwhy.report-corpus.v1");
    let accepted = manifest["accepted"].as_array().expect("accepted reports");
    assert_eq!(accepted.len(), 1);
    let relative = accepted[0]["path"].as_str().expect("accepted path");
    let path = root.join(relative);
    let bytes = fs::read(&path).expect("read accepted report");
    assert_eq!(file_sha256(&bytes), accepted[0]["sha256"]);

    let report = load_report(&path).expect("load sealed golden report");
    let mut serialized = serde_json::to_vec_pretty(&report).expect("serialize golden report");
    serialized.push(b'\n');
    assert_eq!(serialized, bytes);
    let digest = digest_report(&report).expect("digest golden report");
    assert_eq!(report.report_sha256.as_deref(), Some(digest.as_str()));

    let replayed = replay(&report).expect("replay golden report");
    assert!(replayed.integrity_valid);
    assert!(!replayed.network_performed);
    assert_eq!(replayed.failed_at, report.failed_at);
    assert_eq!(report.phases.len(), 8);
}

#[test]
fn declared_v01_mutations_fail_closed() {
    let root = corpus_root();
    let manifest = read_json(&root.join("manifest.json"));
    let golden = read_json(&root.join("dns-failure.report.json"));
    let mut ids = BTreeSet::new();

    for case in manifest["rejections"].as_array().expect("rejection cases") {
        let id = case["id"].as_str().expect("case ID");
        assert!(ids.insert(id.to_owned()));
        let mut document = golden.clone();
        mutate(
            &mut document,
            case["operation"].as_str().expect("operation"),
            case["pointer"].as_str().expect("pointer"),
            case["value"].clone(),
        );
        let directory = tempfile::tempdir().expect("mutation directory");
        let path = directory.path().join("report.json");
        fs::write(
            &path,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&document).expect("serialize mutation")
            ),
        )
        .expect("write mutation");
        let error = load_report(&path).expect_err("mutation must fail");
        assert_eq!(error.code, case["expected_code"], "mutation {id}");
    }
    assert_eq!(ids.len(), 10);
}

#[test]
fn report_shape_remains_forward_extensible_within_v1() {
    let root = corpus_root();
    let mut document = read_json(&root.join("dns-failure.report.json"));
    document["future_extension"] = Value::String("ignored-by-v0.1".to_owned());
    let report: Report = serde_json::from_value(document).expect("unknown report field is ignored");
    replay(&report).expect("known v0.1 fields remain integrity-valid");
}
