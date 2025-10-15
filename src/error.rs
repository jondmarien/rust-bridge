use pyo3::types::PyTracebackMethods;
use pyo3::PyErr;
use std::fmt;

/// Custom error type for memory analysis operations
#[derive(Debug)]
pub enum MemoryAnalysisError {
    /// Python-related errors
    PythonError(String),

    /// Volatility3 framework errors
    VolatilityError(String),

    /// Memory dump file errors
    DumpFileError(String),

    /// Serialization errors
    SerializationError(String),

    /// General I/O errors
    IoError(String),

    /// Other errors
    Other(String),
}

impl fmt::Display for MemoryAnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryAnalysisError::PythonError(msg) => write!(f, "Python error: {}", msg),
            MemoryAnalysisError::VolatilityError(msg) => write!(f, "Volatility error: {}", msg),
            MemoryAnalysisError::DumpFileError(msg) => write!(f, "Dump file error: {}", msg),
            MemoryAnalysisError::SerializationError(msg) => {
                write!(f, "Serialization error: {}", msg)
            }
            MemoryAnalysisError::IoError(msg) => write!(f, "I/O error: {}", msg),
            MemoryAnalysisError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for MemoryAnalysisError {}

impl From<PyErr> for MemoryAnalysisError {
    fn from(err: PyErr) -> Self {
        use pyo3::Python;
        // Try to get more detailed error information including traceback
        let detailed_msg = Python::attach(|py| {
            let traceback = err
                .traceback(py)
                .and_then(|tb| tb.format().ok())
                .unwrap_or_else(|| "(no traceback available)".to_string());
            format!("{}\n{}", err, traceback)
        });
        MemoryAnalysisError::PythonError(detailed_msg)
    }
}

impl From<std::io::Error> for MemoryAnalysisError {
    fn from(err: std::io::Error) -> Self {
        MemoryAnalysisError::IoError(err.to_string())
    }
}

impl From<serde_json::Error> for MemoryAnalysisError {
    fn from(err: serde_json::Error) -> Self {
        MemoryAnalysisError::SerializationError(err.to_string())
    }
}

/// Result type alias for memory analysis operations
pub type MemoryAnalysisResult<T> = Result<T, MemoryAnalysisError>;
