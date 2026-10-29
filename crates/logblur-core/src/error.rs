use std::fmt;
use std::io;
use std::path::Path;

/// Unified error type of logblur. The display text is translated into the current UI language.
#[derive(Debug)]
pub enum Error {
    Io {
        context: String,
        source: io::Error,
    },
    #[cfg(feature = "archive")]
    Zip {
        context: String,
        source: zip::result::ZipError,
    },
    Config(String),
    Rule {
        rule: String,
        msg: String,
    },
    OutputExists(String),
    Unsupported(String),
    Cancelled,
    Other(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Error::Io { context, source } => crate::t!("error.io", context = context, source = source),
            #[cfg(feature = "archive")]
            Error::Zip { context, source } => crate::t!("error.zip", context = context, source = source),
            Error::Config(msg) => crate::t!("error.config", msg = msg),
            Error::Rule { rule, msg } => crate::t!("error.rule", rule = rule, msg = msg),
            Error::OutputExists(path) => crate::t!("error.output_exists", path = path),
            Error::Unsupported(msg) => crate::t!("error.unsupported", msg = msg),
            Error::Cancelled => crate::t!("error.cancelled"),
            Error::Other(msg) => msg.clone(),
        };
        f.write_str(&s)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            #[cfg(feature = "archive")]
            Error::Zip { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl Error {
    pub fn io(context: impl Into<String>, source: io::Error) -> Self {
        Error::Io { context: context.into(), source }
    }

    /// `key` is a translation key with a `{path}` placeholder, e.g. `io.open`.
    pub fn io_path(key: &str, path: &Path, source: io::Error) -> Self {
        Error::Io { context: crate::t!(key, path = path.display()), source }
    }

    #[cfg(feature = "archive")]
    pub fn zip(context: impl Into<String>, source: zip::result::ZipError) -> Self {
        Error::Zip { context: context.into(), source }
    }

    pub fn is_cancelled(&self) -> bool {
        matches!(self, Error::Cancelled)
    }
}

/// Adds context to an `io::Result`.
#[cfg(feature = "archive")]
pub(crate) trait IoContext<T> {
    fn ctx(self, context: impl FnOnce() -> String) -> Result<T>;
}

#[cfg(feature = "archive")]
impl<T> IoContext<T> for io::Result<T> {
    fn ctx(self, context: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|e| Error::io(context(), e))
    }
}

#[cfg(feature = "archive")]
pub(crate) trait ZipContext<T> {
    fn zctx(self, context: impl FnOnce() -> String) -> Result<T>;
}

#[cfg(feature = "archive")]
impl<T> ZipContext<T> for zip::result::ZipResult<T> {
    fn zctx(self, context: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|e| Error::zip(context(), e))
    }
}
