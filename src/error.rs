use std::fmt::{Display, Formatter};

use crate::model::{DiagnosticError, ErrorEnvelope, ERROR_SCHEMA_VERSION};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    Io,
    Usage,
    Policy,
    Budget,
    Contract,
}

impl ErrorClass {
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Io => 1,
            Self::Usage => 2,
            Self::Policy => 3,
            Self::Budget => 4,
            Self::Contract => 5,
        }
    }
}

#[derive(Debug)]
pub struct AppError {
    pub class: ErrorClass,
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

impl AppError {
    pub fn new(class: ErrorClass, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            class,
            code: code.into(),
            message: message.into(),
            retryable: false,
        }
    }

    pub fn retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    pub fn envelope(&self) -> ErrorEnvelope {
        ErrorEnvelope {
            schema_version: ERROR_SCHEMA_VERSION.to_owned(),
            error: DiagnosticError {
                code: self.code.clone(),
                message: self.message.clone(),
                retryable: self.retryable,
            },
        }
    }
}

impl Display for AppError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AppError {}

pub type AppResult<T> = Result<T, AppError>;
