// Axel '0vercl0k' Souchet - May 30 2023
//! This defines the [`Result<T>`] & the custom Error type [`RpBfError`] that
//! are used throughout the codebase.
use std::io;
use std::num::ParseIntError;

use bochscpu::mem::VirtMemError;
use thiserror::Error;

/// The [`Result<T>`] type used throughout the codebase.
pub type Result<T> = std::result::Result<T, RpBfError>;

/// The [`Error`] type used throughout the codebase.
#[derive(Debug, Error)]
pub enum RpBfError {
    #[error("Io {0}")]
    Io(#[from] io::Error),
    #[error("No memory stream found")]
    NoMemoryStream,
    #[error("JSON {0}")]
    JSONDecoding(#[from] serde_json::error::Error),
    #[error("No threads found in the dump")]
    NoThreads,
    #[error("Not an x64 dump")]
    NotX64,
    #[error("No context available")]
    NoContext,
    #[error("Virtual memory {0}")]
    VirtMem(#[from] VirtMemError),
    #[error("Kind is malformed")]
    KindMalformed,
    #[error("Parse int {0}")]
    ParseInt(#[from] ParseIntError),
    #[error("Anyhow {0}")]
    Anyhow(#[from] anyhow::Error),
}
