#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
result_path="${1:-${root_dir}/benchmark-results.json}"
binary="${root_dir}/target/release/hopwhy"
fixture_server="${root_dir}/benchmarks/http_fixture.py"
golden_report="${root_dir}/tests/fixtures/contracts/v0.1/dns-failure.report.json"

for dependency in cargo git jq python3 stat timeout uname; do
  command -v "${dependency}" >/dev/null || {
    printf 'missing benchmark dependency: %s\n' "${dependency}" >&2
    exit 1
  }
done

if ! /usr/bin/time --version 2>&1 | grep -qi 'GNU time'; then
  printf 'benchmarks/run.sh requires GNU /usr/bin/time (the Ubuntu runner provides it)\n' >&2
  exit 1
fi

temp_dir="$(mktemp -d)"
server_pid=""
cleanup() {
  if test -n "${server_pid}"; then
    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
  fi
  rm -rf "${temp_dir}"
}
trap cleanup EXIT

fixture_metadata="${temp_dir}/fixture.json"
server_log="${temp_dir}/fixture.log"

cd "${root_dir}"
cargo build --release --locked

python3 "${fixture_server}" \
  --port-file "${fixture_metadata}" \
  --body-bytes 65536 >"${server_log}" 2>&1 &
server_pid="$!"

for _attempt in $(seq 1 100); do
  test -s "${fixture_metadata}" && break
  if ! kill -0 "${server_pid}" 2>/dev/null; then
    printf 'fixture server stopped before becoming ready\n' >&2
    sed -n '1,120p' "${server_log}" >&2
    exit 1
  fi
  sleep 0.05
done
test -s "${fixture_metadata}"
jq -e '.schema_version == "hopwhy.http-fixture.v1"' "${fixture_metadata}" >/dev/null
base_url="$(jq -er '.base_url' "${fixture_metadata}")"

measure() {
  local metrics="$1"
  local output="$2"
  shift 2

  /usr/bin/time \
    -f '{"wall_seconds": %e, "max_rss_kib": %M, "exit_code": %x}' \
    -o "${metrics}" \
    timeout --signal=KILL 30s "$@" >"${output}"
  jq -e . "${metrics}" >/dev/null
  jq -e . "${output}" >/dev/null
}

live_metrics="${temp_dir}/live.metrics.json"
live_report="${temp_dir}/live.report.json"
replay_metrics="${temp_dir}/replay.metrics.json"
replay_output="${temp_dir}/replay.json"
compare_metrics="${temp_dir}/compare.metrics.json"
compare_output="${temp_dir}/compare.json"
schema_metrics="${temp_dir}/schema.metrics.json"
schema_output="${temp_dir}/schema.json"

measure "${live_metrics}" "${live_report}" \
  "${binary}" --format json inspect "${base_url}/start" \
  --allow-private \
  --disable-proxy \
  --budget 15s \
  --max-probes 12 \
  --max-addresses 4 \
  --max-redirects 5 \
  --max-body-bytes 4096

jq -e '
  .schema_version == "hopwhy.report.v1"
  and .failed_at == null
  and [.http[].status] == [302, 200]
  and (.http[0].location | contains("token=REDACTED"))
  and .http[1].declared_content_length == 65536
  and .http[1].returned_body_bytes == 4096
  and .http[1].body_truncated
  and .usage.elapsed_ms <= .budget.duration_ms
  and .usage.probes_used <= .budget.max_probes
  and (.report_sha256 | type == "string" and length == 64)
' "${live_report}" >/dev/null

measure "${replay_metrics}" "${replay_output}" \
  "${binary}" --format json replay "${live_report}"
measure "${compare_metrics}" "${compare_output}" \
  "${binary}" --format json compare "${golden_report}" "${live_report}"
measure "${schema_metrics}" "${schema_output}" \
  "${binary}" --format json schema --document report

mkdir -p "$(dirname "${result_path}")"
jq -n \
  --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  --arg git_sha "$(git rev-parse HEAD)" \
  --arg runner_os "${RUNNER_OS:-Linux}" \
  --arg runner_arch "$(uname -m)" \
  --arg runner_image "${ImageOS:-unknown}" \
  --arg runner_image_version "${ImageVersion:-unknown}" \
  --argjson live_output_bytes "$(stat -c '%s' "${live_report}")" \
  --argjson replay_output_bytes "$(stat -c '%s' "${replay_output}")" \
  --argjson compare_output_bytes "$(stat -c '%s' "${compare_output}")" \
  --argjson schema_output_bytes "$(stat -c '%s' "${schema_output}")" \
  --slurpfile fixture "${fixture_metadata}" \
  --slurpfile live_metrics "${live_metrics}" \
  --slurpfile live_report "${live_report}" \
  --slurpfile replay_metrics "${replay_metrics}" \
  --slurpfile replay "${replay_output}" \
  --slurpfile compare_metrics "${compare_metrics}" \
  --slurpfile compare "${compare_output}" \
  --slurpfile schema_metrics "${schema_metrics}" \
  --slurpfile schema "${schema_output}" \
  '{
    schema_version: "hopwhy.benchmark.v1",
    generated_at: $generated_at,
    git_sha: $git_sha,
    runner: {
      os: $runner_os,
      arch: $runner_arch,
      image: $runner_image,
      image_version: $runner_image_version
    },
    fixture: $fixture[0],
    measurements: [
      {
        id: "live_redirect_body_pressure",
        class: "live",
        process: $live_metrics[0],
        output_bytes: $live_output_bytes,
        result: {
          schema_version: $live_report[0].schema_version,
          failed_at: $live_report[0].failed_at,
          http_statuses: [$live_report[0].http[].status],
          redirect_location_redacted:
            ($live_report[0].http[0].location | contains("token=REDACTED")),
          declared_content_length: $live_report[0].http[1].declared_content_length,
          returned_body_bytes: $live_report[0].http[1].returned_body_bytes,
          body_truncated: $live_report[0].http[1].body_truncated,
          elapsed_ms: $live_report[0].usage.elapsed_ms,
          probes_used: $live_report[0].usage.probes_used,
          report_sha256: $live_report[0].report_sha256
        }
      },
      {
        id: "offline_replay_integrity",
        class: "offline",
        process: $replay_metrics[0],
        output_bytes: $replay_output_bytes,
        result: {
          schema_version: $replay[0].schema_version,
          integrity_valid: $replay[0].integrity_valid,
          network_performed: $replay[0].network_performed,
          report_sha256: $replay[0].report_sha256
        }
      },
      {
        id: "offline_compare_golden_to_live",
        class: "offline",
        process: $compare_metrics[0],
        output_bytes: $compare_output_bytes,
        result: {
          schema_version: $compare[0].schema_version,
          left_report_sha256: $compare[0].left_report_sha256,
          right_report_sha256: $compare[0].right_report_sha256,
          same_failed_phase: $compare[0].same_failed_phase
        }
      },
      {
        id: "offline_report_schema",
        class: "offline",
        process: $schema_metrics[0],
        output_bytes: $schema_output_bytes,
        result: {
          draft: $schema[0]."$schema",
          title: $schema[0].title
        }
      }
    ],
    derived: {
      max_peak_rss_mib:
        ([
          $live_metrics[0].max_rss_kib,
          $replay_metrics[0].max_rss_kib,
          $compare_metrics[0].max_rss_kib,
          $schema_metrics[0].max_rss_kib
        ] | max | . / 1024),
      offline_max_wall_ms:
        ([
          $replay_metrics[0].wall_seconds,
          $compare_metrics[0].wall_seconds,
          $schema_metrics[0].wall_seconds
        ] | max | . * 1000)
    },
    threshold_status: "raw_sample"
  }' >"${result_path}"

jq -e '
  .schema_version == "hopwhy.benchmark.v1"
  and .fixture.body_bytes == 65536
  and all(
    .measurements[];
    .process.exit_code == 0
      and .process.wall_seconds >= 0
      and .process.max_rss_kib > 0
      and .output_bytes > 0
  )
  and any(
    .measurements[];
    .id == "live_redirect_body_pressure"
      and .result.failed_at == null
      and .result.http_statuses == [302, 200]
      and .result.redirect_location_redacted
      and .result.returned_body_bytes == 4096
      and .result.body_truncated
  )
  and any(
    .measurements[];
    .id == "offline_replay_integrity"
      and .result.integrity_valid
      and (.result.network_performed | not)
  )
  and any(
    .measurements[];
    .id == "offline_report_schema"
      and .result.draft == "http://json-schema.org/draft-07/schema#"
      and .result.title == "Report"
  )
' "${result_path}" >/dev/null

printf 'wrote %s\n' "${result_path}"
