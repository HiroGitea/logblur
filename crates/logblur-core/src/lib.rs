//! logblur-core: scrubs sensitive information from log archives, in memory.
//!
//! The main entry point is [`job::run`]: given an input (zip / tar / tar.gz / gz / single file / directory / stdin),
//! an output location and a [`JobConfig`], it decompresses, detects, masks and recompresses concurrently, and returns a
//! [`Report`]. Unmasked plaintext only ever exists in process memory and is never written to disk.
//!
//! UI text is translated via [`i18n`]: English is the source and fallback language, and Simplified Chinese is built in.

pub mod archive;
pub mod category;
pub mod config;
pub mod error;
pub mod i18n;
pub mod job;
pub mod mask;
pub mod pipeline;
pub mod report;
pub mod rules;
pub mod scan;
pub mod text;
pub mod util;

pub use category::Category;
pub use config::{BinaryPolicy, JobConfig, MaskMode, MemoryLimit, OutputEncoding, ReportFormat, config_template};
pub use error::{Error, Result};
pub use job::{CancelToken, Input, JobSpec, NoProgress, Output, Phase, ProgressEvent, ProgressSink, run};
pub use report::Report;
pub use scan::Engine;

/// Tool version (from Cargo.toml).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
