//! logblur-core：在内存中清洗日志压缩包里的敏感信息。
//!
//! 主要入口是 [`job::run`]：给定输入（zip / tar / tar.gz / gz / 单文件 / 文件夹 / stdin）、
//! 输出位置和 [`JobConfig`]，并发地解压、识别、打码、重新压缩，返回 [`Report`]。
//! 未打码的明文只存在于进程内存中，永远不会写到磁盘。
//!
//! 界面文字通过 [`i18n`] 翻译：英文是源语言和回退语言，内置简体中文。

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

/// 工具版本号（来自 Cargo.toml）。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
