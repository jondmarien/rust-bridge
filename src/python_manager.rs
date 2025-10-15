use crate::error::{MemoryAnalysisError, MemoryAnalysisResult};
use pyo3::prelude::*;
use std::sync::Once;

static INIT: Once = Once::new();
static mut INITIALIZED: bool = false;

/// Manages the Python interpreter lifecycle
///
/// This struct provides singleton access to the Python interpreter
/// and handles initialization, configuration, and cleanup.
pub struct PythonManager;

impl PythonManager {
    /// Initialize the Python interpreter (should be called once)
    ///
    /// This uses a singleton pattern with lazy initialization.
    /// Subsequent calls are safe and will do nothing.
    pub fn initialize() -> MemoryAnalysisResult<()> {
        INIT.call_once(|| {
            // Initialize the Python interpreter
            // PyO3 will auto-discover Python from the system
            Python::initialize();

            // Configure Python paths to include venv site-packages
            Self::configure_python_path();

            unsafe {
                INITIALIZED = true;
            }
        });

        Ok(())
    }

    /// Check if the Python interpreter has been initialized
    pub fn is_initialized() -> bool {
        unsafe { INITIALIZED }
    }

    /// Configure additional Python paths after initialization
    fn configure_python_path() {
        Python::attach(|py| {
            let sys = py.import("sys").expect("Failed to import sys");
            let path_list = sys.getattr("path").expect("Failed to get sys.path");

            // Add venv site-packages to sys.path
            let manifest_dir = env!("CARGO_MANIFEST_DIR");
            let venv_site_packages =
                format!("{}\\..\\volatility-env\\Lib\\site-packages", manifest_dir);

            // Normalize the path
            if let Ok(canonical) = std::path::Path::new(&venv_site_packages).canonicalize() {
                if let Some(path_str) = canonical.to_str() {
                    let _ = path_list.call_method1("insert", (0, path_str));
                }
            }
        });
    }

    /// Execute a Python operation with the GIL
    ///
    /// This ensures the interpreter is initialized before executing the closure.
    pub fn with_gil<F, R>(f: F) -> MemoryAnalysisResult<R>
    where
        F: FnOnce(Python) -> PyResult<R>,
    {
        // Ensure initialization
        Self::initialize()?;

        // Execute the operation
        let result = Python::attach(f);

        result.map_err(|e| MemoryAnalysisError::PythonError(e.to_string()))
    }

    /// Get Python version information
    pub fn version_info() -> MemoryAnalysisResult<(u8, u8, u8)> {
        Self::initialize()?;

        let version = Python::attach(|py| {
            let info = py.version_info();
            (info.major, info.minor, info.patch)
        });

        Ok(version)
    }

    /// Check if a Python module is available
    pub fn is_module_available(module_name: &str) -> MemoryAnalysisResult<bool> {
        Self::with_gil(|py| match py.import(module_name) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        })
    }
}

// Cleanup on program exit
impl Drop for PythonManager {
    fn drop(&mut self) {
        // PyO3 handles Python interpreter cleanup automatically
        // No manual cleanup needed with auto-initialize feature
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialization() {
        assert!(PythonManager::initialize().is_ok());
        assert!(PythonManager::is_initialized());
    }

    #[test]
    fn test_multiple_initialization() {
        // Multiple calls should be safe
        assert!(PythonManager::initialize().is_ok());
        assert!(PythonManager::initialize().is_ok());
        assert!(PythonManager::initialize().is_ok());
    }

    #[test]
    fn test_version_info() {
        let version = PythonManager::version_info().unwrap();
        assert_eq!(version.0, 3); // Python 3.x
        assert!(version.1 >= 12); // At least 3.12
    }

    #[test]
    fn test_module_availability() {
        PythonManager::initialize().unwrap();

        // sys should always be available
        assert!(PythonManager::is_module_available("sys").unwrap());

        // A fake module should not be available
        assert!(!PythonManager::is_module_available("this_module_does_not_exist_12345").unwrap());
    }

    #[test]
    fn test_with_gil() {
        let result = PythonManager::with_gil(|py| {
            let sys = py.import("sys")?;
            let version = sys.getattr("version")?;
            Ok(version.to_string())
        });

        assert!(result.is_ok());
        let version_str = result.unwrap();
        assert!(version_str.contains("3.12")); // Should be Python 3.12.x
    }
}
