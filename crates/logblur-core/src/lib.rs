//! logblur-core: scrubs sensitive information from log archives, in memory.
//!
//! The main entry point is [`job::run`]: given an input (zip / tar / tar.gz / gz / single file / directory / stdin),
//! an output location and a [`JobConfig`], it decompresses, detects, masks and recompresses concurrently, and returns a
//! [`Report`]. Unmasked plaintext only ever exists in process memory and is never written to disk.
//!
//! Without the default `archive` feature only the scanner is built: [`Engine::scrub_str`] and [`Engine::find`]
//! scrub or locate sensitive data in text a program already holds, without the archive and compression dependencies.
//!
//! UI text is translated via [`i18n`]: English is the source and fallback language, and Simplified Chinese is built in.

#[cfg(feature = "archive")]
pub mod archive;
pub mod category;
pub mod config;
pub mod error;
pub mod i18n;
#[cfg(feature = "archive")]
pub mod job;
pub mod mask;
#[cfg(feature = "archive")]
pub mod pipeline;
#[cfg(feature = "archive")]
pub mod report;
pub mod rules;
pub mod scan;
#[cfg(feature = "archive")]
pub mod stream;
#[cfg(feature = "archive")]
pub mod text;
pub mod util;

pub use category::Category;
pub use config::{BinaryPolicy, JobConfig, MaskMode, MemoryLimit, OutputEncoding, ReportFormat, config_template};
pub use error::{Error, Result};
#[cfg(feature = "archive")]
pub use job::{CancelToken, Input, JobSpec, NoProgress, Output, Phase, ProgressEvent, ProgressSink, run};
#[cfg(feature = "archive")]
pub use report::Report;
pub use scan::Engine;

/// Tool version (from Cargo.toml).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
