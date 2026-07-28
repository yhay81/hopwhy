use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Shell};
use serde::Serialize;
use serde_json::Value;

use crate::contract::{capabilities, schema_document};
use crate::engine::{inspect, plan};
use crate::error::{AppError, AppResult, ErrorClass};
use crate::model::{
    CompareResult, InspectSpec, InspectionOptions, InspectionPlan, ReplayResult, Report,
    RequestMethod,
};
use crate::offline::{compare, load_report, replay};

const MAX_SPEC_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
    Ndjson,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum MethodArg {
    Get,
    Head,
}

impl From<MethodArg> for RequestMethod {
    fn from(value: MethodArg) -> Self {
        match value {
            MethodArg::Get => Self::Get,
            MethodArg::Head => Self::Head,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SchemaDocument {
    Brief,
    Spec,
    Report,
    Plan,
    Compare,
    Replay,
    Capabilities,
    Error,
}

impl SchemaDocument {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Brief => "brief",
            Self::Spec => "spec",
            Self::Report => "report",
            Self::Plan => "plan",
            Self::Compare => "compare",
            Self::Replay => "replay",
            Self::Capabilities => "capabilities",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "hopwhy",
    version,
    about = "Bounded causal DNS-to-HTTP diagnostics for humans and agents"
)]
pub struct Cli {
    #[arg(long, value_enum, default_value_t = OutputFormat::Human, global = true)]
    pub format: OutputFormat,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Plan or execute a bounded diagnostic request.
    Inspect {
        /// Absolute HTTP(S) target URL. Mutually exclusive with --spec.
        target: Option<String>,

        /// Read target and options from a versioned JSON spec.
        #[arg(long)]
        spec: Option<PathBuf>,

        /// Return the probe plan without performing network activity.
        #[arg(long)]
        dry_run: bool,

        /// Global wall-clock budget, for example 15s or 500ms.
        #[arg(long)]
        budget: Option<String>,

        /// Maximum network probes across DNS, TCP, TLS, HTTP, and redirects.
        #[arg(long)]
        max_probes: Option<u32>,

        /// Maximum resolved addresses attempted for a phase.
        #[arg(long)]
        max_addresses: Option<usize>,

        /// Maximum redirect hops followed manually.
        #[arg(long)]
        max_redirects: Option<usize>,

        /// Maximum response body bytes read per HTTP hop.
        #[arg(long)]
        max_body_bytes: Option<usize>,

        /// Include bounded response body bytes as base64; off by default.
        #[arg(long)]
        include_body_sample: bool,

        /// Explicitly authorize loopback, private, link-local, and other non-public addresses.
        #[arg(long)]
        allow_private: bool,

        /// Emit resolved addresses instead of stable redacted hashes.
        #[arg(long)]
        show_addresses: bool,

        /// Emit URL query values instead of deterministic redaction.
        #[arg(long)]
        show_query_values: bool,

        /// Ignore proxy environment variables.
        #[arg(long)]
        disable_proxy: bool,

        /// HTTP request method.
        #[arg(long, value_enum)]
        method: Option<MethodArg>,
    },

    /// Compare two integrity-checked reports without network activity.
    Compare { left: PathBuf, right: PathBuf },

    /// Replay the causal explanation in an integrity-checked report without network activity.
    Replay { report: PathBuf },

    /// Describe phase support, safety defaults, and explicit non-goals.
    Capabilities,

    /// Emit the compact contract or a complete JSON Schema document.
    Schema {
        #[arg(long, value_enum, default_value_t = SchemaDocument::Brief)]
        document: SchemaDocument,
    },

    /// Generate a shell completion script.
    Completions { shell: Shell },
}

pub struct CommandOutput {
    pub value: Option<Value>,
    pub human: String,
    pub raw: Option<String>,
}

pub fn run(cli: &Cli) -> AppResult<CommandOutput> {
    match &cli.command {
        Commands::Inspect {
            target,
            spec,
            dry_run,
            budget,
            max_probes,
            max_addresses,
            max_redirects,
            max_body_bytes,
            include_body_sample,
            allow_private,
            show_addresses,
            show_query_values,
            disable_proxy,
            method,
        } => {
            let mut specification = resolve_spec(target.as_deref(), spec.as_deref())?;
            apply_overrides(
                &mut specification.options,
                budget.as_deref(),
                *max_probes,
                *max_addresses,
                *max_redirects,
                *max_body_bytes,
                *include_body_sample,
                *allow_private,
                *show_addresses,
                *show_query_values,
                *disable_proxy,
                *method,
            )?;
            if *dry_run {
                let result = plan(&specification)?;
                structured_output(&result, render_plan(&result))
            } else {
                let result = inspect(&specification)?;
                structured_output(&result, render_report(&result))
            }
        }
        Commands::Compare { left, right } => {
            let left_report = load_report(left)?;
            let right_report = load_report(right)?;
            let result = compare(&left_report, &right_report)?;
            structured_output(&result, render_compare(&result))
        }
        Commands::Replay { report } => {
            let report = load_report(report)?;
            let result = replay(&report)?;
            structured_output(&result, render_replay(&result))
        }
        Commands::Capabilities => {
            let result = capabilities();
            structured_output(
                &result,
                format!(
                    "schemes: {}\nplatforms: {}\nprivate targets: denied by default\n",
                    result.supported_schemes.join(", "),
                    result.supported_platforms.join(", ")
                ),
            )
        }
        Commands::Schema { document } => {
            let result = schema_document(document.as_str())?;
            structured_output(
                &result,
                serde_json::to_string_pretty(&result).unwrap_or_default(),
            )
        }
        Commands::Completions { shell } => {
            let mut command = Cli::command();
            let mut bytes = Vec::new();
            generate(*shell, &mut command, "hopwhy", &mut bytes);
            let raw = String::from_utf8(bytes).map_err(|_| {
                AppError::new(
                    ErrorClass::Contract,
                    "completion_encoding_failed",
                    "completion output was not UTF-8",
                )
            })?;
            Ok(CommandOutput {
                value: None,
                human: String::new(),
                raw: Some(raw),
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_overrides(
    options: &mut InspectionOptions,
    budget: Option<&str>,
    max_probes: Option<u32>,
    max_addresses: Option<usize>,
    max_redirects: Option<usize>,
    max_body_bytes: Option<usize>,
    include_body_sample: bool,
    allow_private: bool,
    show_addresses: bool,
    show_query_values: bool,
    disable_proxy: bool,
    method: Option<MethodArg>,
) -> AppResult<()> {
    if let Some(budget) = budget {
        let duration = humantime::parse_duration(budget).map_err(|error| {
            AppError::new(
                ErrorClass::Usage,
                "invalid_budget",
                format!("could not parse --budget: {error}"),
            )
        })?;
        options.budget_ms = u64::try_from(duration.as_millis()).map_err(|_| {
            AppError::new(ErrorClass::Usage, "invalid_budget", "--budget is too large")
        })?;
    }
    if let Some(value) = max_probes {
        options.max_probes = value;
    }
    if let Some(value) = max_addresses {
        options.max_addresses = value;
    }
    if let Some(value) = max_redirects {
        options.max_redirects = value;
    }
    if let Some(value) = max_body_bytes {
        options.max_body_bytes = value;
    }
    options.include_body_sample |= include_body_sample;
    options.allow_private |= allow_private;
    options.show_addresses |= show_addresses;
    options.show_query_values |= show_query_values;
    options.disable_proxy |= disable_proxy;
    if let Some(value) = method {
        options.method = value.into();
    }
    Ok(())
}

fn resolve_spec(target: Option<&str>, spec_path: Option<&Path>) -> AppResult<InspectSpec> {
    match (target, spec_path) {
        (Some(_), Some(_)) => Err(AppError::new(
            ErrorClass::Usage,
            "ambiguous_inspect_input",
            "provide either a target URL or --spec, not both",
        )),
        (None, None) => Err(AppError::new(
            ErrorClass::Usage,
            "missing_inspect_input",
            "provide a target URL or --spec",
        )),
        (Some(target), None) => Ok(InspectSpec {
            target: target.to_owned(),
            options: InspectionOptions::default(),
        }),
        (None, Some(path)) => load_spec(path),
    }
}

fn load_spec(path: &Path) -> AppResult<InspectSpec> {
    let metadata = fs::metadata(path).map_err(|error| {
        AppError::new(
            ErrorClass::Io,
            "spec_metadata_failed",
            format!("could not inspect spec {}: {error}", path.display()),
        )
    })?;
    if !metadata.is_file() {
        return Err(AppError::new(
            ErrorClass::Io,
            "spec_not_regular_file",
            format!("spec {} is not a regular file", path.display()),
        ));
    }
    if metadata.len() > MAX_SPEC_BYTES {
        return Err(AppError::new(
            ErrorClass::Budget,
            "spec_too_large",
            format!("spec {} exceeds {MAX_SPEC_BYTES} bytes", path.display()),
        ));
    }
    let bytes = fs::read(path).map_err(|error| {
        AppError::new(
            ErrorClass::Io,
            "spec_read_failed",
            format!("could not read spec {}: {error}", path.display()),
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        AppError::new(
            ErrorClass::Usage,
            "invalid_spec",
            format!("{} is not a valid HopWhy spec: {error}", path.display()),
        )
    })
}

fn structured_output<T: Serialize>(value: &T, human: String) -> AppResult<CommandOutput> {
    let value = serde_json::to_value(value).map_err(|_| {
        AppError::new(
            ErrorClass::Contract,
            "serialization_failed",
            "the command result could not be serialized",
        )
    })?;
    Ok(CommandOutput {
        value: Some(value),
        human,
        raw: None,
    })
}

pub fn render(output: &CommandOutput, format: OutputFormat) -> AppResult<String> {
    if let Some(raw) = &output.raw {
        return Ok(raw.clone());
    }
    match format {
        OutputFormat::Human => Ok(output.human.clone()),
        OutputFormat::Json => serde_json::to_string_pretty(&output.value).map_err(|_| {
            AppError::new(
                ErrorClass::Contract,
                "serialization_failed",
                "the command result could not be rendered as JSON",
            )
        }),
        OutputFormat::Ndjson => serde_json::to_string(&output.value).map_err(|_| {
            AppError::new(
                ErrorClass::Contract,
                "serialization_failed",
                "the command result could not be rendered as NDJSON",
            )
        }),
    }
}

pub fn write_stdout(text: &str) -> AppResult<()> {
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(text.as_bytes())
        .map_err(stdout_write_error)?;
    if !text.ends_with('\n') {
        stdout.write_all(b"\n").map_err(stdout_write_error)?;
    }
    Ok(())
}

fn stdout_write_error(error: std::io::Error) -> AppError {
    if error.kind() == std::io::ErrorKind::BrokenPipe {
        AppError::new(
            ErrorClass::Io,
            "stdout_broken_pipe",
            "output consumer closed the pipe",
        )
    } else {
        AppError::new(
            ErrorClass::Io,
            "stdout_write_failed",
            format!("could not write command output: {error}"),
        )
    }
}

pub fn write_error(error: &AppError, format: OutputFormat) {
    let rendered = match format {
        OutputFormat::Human => error.to_string(),
        OutputFormat::Json => {
            serde_json::to_string_pretty(&error.envelope()).unwrap_or_else(|_| error.to_string())
        }
        OutputFormat::Ndjson => {
            serde_json::to_string(&error.envelope()).unwrap_or_else(|_| error.to_string())
        }
    };
    let _ = writeln!(std::io::stderr().lock(), "{rendered}");
}

fn render_plan(plan: &InspectionPlan) -> String {
    let probes = plan
        .planned_probes
        .iter()
        .map(|probe| {
            format!(
                "{}. {:?}: {}{}",
                probe.sequence,
                probe.kind,
                probe.purpose,
                if probe.conditional {
                    " (conditional)"
                } else {
                    ""
                }
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "target: {}\nnetwork performed: no\npolicy: {}\n{}\n",
        plan.target.intended, plan.policy, probes
    )
}

fn render_report(report: &Report) -> String {
    let phases = report
        .phases
        .iter()
        .map(|phase| {
            let error = phase
                .error
                .as_ref()
                .map_or(String::new(), |error| format!(" ({})", error.code));
            format!(
                "- {:?}: {:?} {}ms{}",
                phase.name, phase.status, phase.duration_ms, error
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let diagnosis = report.hypotheses.first().map_or_else(
        || "no hypothesis".to_owned(),
        |hypothesis| {
            format!(
                "{} (confidence {:.2})\nnext: {}",
                hypothesis.statement, hypothesis.confidence, hypothesis.next_safe_step
            )
        },
    );
    format!(
        "target: {}\nfailed at: {}\nprobes: {}/{}\n{}\ndiagnosis: {}\nreport sha256: {}\n",
        report.target.intended,
        report
            .failed_at
            .map_or_else(|| "none".to_owned(), |phase| format!("{phase:?}")),
        report.usage.probes_used,
        report.budget.max_probes,
        phases,
        diagnosis,
        report.report_sha256.as_deref().unwrap_or("unavailable")
    )
}

fn render_compare(result: &CompareResult) -> String {
    format!(
        "same target: {}\nsame failed phase: {}\nphase differences: {}\n{}\n",
        result.same_intended_target,
        result.same_failed_phase,
        result.phase_differences.len(),
        result.summary.join("\n")
    )
}

fn render_replay(result: &ReplayResult) -> String {
    format!(
        "integrity: {}\nnetwork performed: no\nfailed at: {}\n{}\n",
        if result.integrity_valid {
            "valid"
        } else {
            "invalid"
        },
        result
            .failed_at
            .map_or_else(|| "none".to_owned(), |phase| format!("{phase:?}")),
        result.next_safe_steps.join("\n")
    )
}
