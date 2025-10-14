//! Rust-Python Bridge for PowerShell Memory Analysis Module
//!
//! This library provides a high-performance bridge between Rust and Python,
//! enabling PowerShell cmdlets to interact with Volatility 3 framework.

use pyo3::prelude::*;
use anyhow::Result;

// Module declarations
mod python_manager;
mod error;

pub use error::{MemoryAnalysisError, MemoryAnalysisResult};
pub use python_manager::PythonManager;

/// Initialize the Rust-Python bridge
///
/// This should be called before any other operations
pub fn initialize() -> Result<()> {
    Python::initialize();
    
    // Verify Python interpreter is available  
    Python::attach(|py| {
        let version = py.version_info();
        println!(
            "Python {}.{}.{} initialized",
            version.major, version.minor, version.patch
        );
    });
    
    Ok(())
}

/// Check if Volatility3 is available in the Python environment
pub fn check_volatility_available() -> Result<bool> {
    Python::initialize();
    
    let result = Python::attach(|py| {
        match py.import("volatility3") {
            Ok(_) => true,
            Err(_) => false,
        }
    });
    
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialize() {
        assert!(initialize().is_ok());
    }

    #[test]
    fn test_volatility_check() {
        initialize().unwrap();
        let available = check_volatility_available().unwrap();
        assert!(available, "Volatility3 should be installed in the venv");
    }
}
