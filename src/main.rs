use std::process::ExitCode;

use clap::error::ErrorKind;
use clap::Parser;
use hopwhy::cli::{render, run, write_error, write_stdout, Cli, OutputFormat};
use hopwhy::error::{AppError, ErrorClass};

fn main() -> ExitCode {
    let requested_format = requested_format();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let is_display = matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            );
            if is_display || requested_format == OutputFormat::Human {
                let _ = error.print();
            } else {
                let usage_error = AppError::new(
                    ErrorClass::Usage,
                    "cli_usage",
                    error
                        .to_string()
                        .lines()
                        .next()
                        .unwrap_or("invalid command line")
                        .to_owned(),
                );
                write_error(&usage_error, requested_format);
            }
            return if is_display {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            };
        }
    };
    let format = cli.format;
    match run(&cli)
        .and_then(|output| render(&output, format))
        .and_then(|text| write_stdout(&text))
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if error.code == "stdout_broken_pipe" {
                return ExitCode::SUCCESS;
            }
            write_error(&error, format);
            ExitCode::from(u8::try_from(error.class.exit_code()).unwrap_or(1))
        }
    }
}

fn requested_format() -> OutputFormat {
    let arguments = std::env::args().collect::<Vec<_>>();
    arguments
        .windows(2)
        .find_map(|pair| {
            (pair[0] == "--format").then(|| match pair[1].as_str() {
                "json" => OutputFormat::Json,
                "ndjson" => OutputFormat::Ndjson,
                _ => OutputFormat::Human,
            })
        })
        .unwrap_or(OutputFormat::Human)
}
