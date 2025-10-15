use pyo3::prelude::*;
use pyo3::types::PyList;
use crate::error::{MemoryAnalysisError, MemoryAnalysisResult};
use crate::python_manager::PythonManager;

/// Volatility 3 framework wrapper
///
/// Provides a high-level interface to the Volatility 3 framework
pub struct VolatilityAnalyzer {
    _marker: std::marker::PhantomData<()>,
}

impl VolatilityAnalyzer {
    /// Create a new Volatility analyzer instance
    pub fn new() -> MemoryAnalysisResult<Self> {
        // Ensure Python is initialized
        PythonManager::initialize()?;
        
        // Verify Volatility3 is available
        if !PythonManager::is_module_available("volatility3")? {
            return Err(MemoryAnalysisError::VolatilityError(
                "Volatility3 module not found. Please ensure it's installed in the Python environment.".to_string()
            ));
        }
        
        Ok(VolatilityAnalyzer {
            _marker: std::marker::PhantomData,
        })
    }
    
    /// Get Volatility 3 version
    pub fn version(&self) -> MemoryAnalysisResult<String> {
        PythonManager::with_gil(|py| {
            let vol3 = py.import("volatility3")?;
            
            // Try to get version from __version__ attribute
            if let Ok(version) = vol3.getattr("__version__") {
                Ok(version.to_string())
            } else {
                // Fallback to a generic version string
                Ok("2.x.x".to_string())
            }
        })
    }
    
    /// List all available Volatility 3 plugins
    pub fn list_plugins(&self) -> MemoryAnalysisResult<Vec<String>> {
        PythonManager::with_gil(|py| {
            // Import the framework and plugin modules
            let _framework = py.import("volatility3.framework")?;
            let _plugins_module = py.import("volatility3.framework.plugins")?;
            
            // Get the list of plugins
            // This is a simplified version - full implementation would scan plugin directories
            let plugins = PyList::new(py, &[
                "windows.pslist.PsList",
                "windows.pstree.PsTree",
                "windows.cmdline.CmdLine",
                "windows.netscan.NetScan",
                "windows.malfind.Malfind",
                "windows.dlllist.DllList",
                "windows.handles.Handles",
                "windows.registry.hivelist.HiveList",
                "linux.pslist.PsList",
                "linux.pstree.PsTree",
            ]);
            
            let mut result = Vec::new();
            for plugin in plugins.iter() {
                result.push(plugin.to_string());
            }
            
            Ok(result)
        })
    }
    
    /// Check if a specific plugin is available
    pub fn is_plugin_available(&self, plugin_name: &str) -> MemoryAnalysisResult<bool> {
        let plugins = self.list_plugins()?;
        Ok(plugins.iter().any(|p| p.contains(plugin_name)))
    }
    
    /// Initialize Volatility context for a memory dump
    ///
    /// This prepares the Volatility framework to analyze a specific memory dump file
    pub fn initialize_context(&self, dump_path: &str) -> MemoryAnalysisResult<VolatilityContext> {
        // Verify the dump file exists
        let path = std::path::Path::new(dump_path);
        if !path.exists() {
            return Err(MemoryAnalysisError::DumpFileError(
                format!("Memory dump file not found: {}", dump_path)
            ));
        }
        
        // Just store the dump path, we'll create fresh Python objects on each use
        Ok(VolatilityContext {
            dump_path: dump_path.to_string(),
        })
    }
    
    /// Execute a Volatility plugin on a memory dump
    ///
    /// This is a basic implementation that will be expanded in later tasks
    pub fn run_plugin(
        &self,
        _context: &VolatilityContext,
        _plugin_name: &str,
    ) -> MemoryAnalysisResult<String> {
        PythonManager::with_gil(|py| {
            // Import required modules
            let _framework = py.import("volatility3.framework")?;
            
            // For now, return a placeholder result
            // Full implementation will be added in Task 1.4
            Ok(String::from("{}"))
        })
    }
}

/// Represents a Volatility analysis context for a specific memory dump
#[derive(Debug, Clone)]
pub struct VolatilityContext {
    pub dump_path: String,
}

impl VolatilityContext {
    /// Get the path to the memory dump file
    pub fn dump_path(&self) -> &str {
        &self.dump_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_analyzer_creation() {
        let analyzer = VolatilityAnalyzer::new();
        assert!(analyzer.is_ok(), "Should create analyzer successfully");
    }
    
    #[test]
    fn test_version() {
        let analyzer = VolatilityAnalyzer::new().unwrap();
        let version = analyzer.version();
        assert!(version.is_ok(), "Should get version");
        println!("Volatility version: {}", version.unwrap());
    }
    
    #[test]
    fn test_list_plugins() {
        let analyzer = VolatilityAnalyzer::new().unwrap();
        let plugins = analyzer.list_plugins().unwrap();
        
        assert!(!plugins.is_empty(), "Should have plugins");
        assert!(plugins.iter().any(|p| p.contains("PsList")), "Should have PsList plugin");
        
        println!("Available plugins: {:?}", plugins);
    }
    
    #[test]
    fn test_plugin_availability() {
        let analyzer = VolatilityAnalyzer::new().unwrap();
        
        assert!(analyzer.is_plugin_available("PsList").unwrap());
        assert!(!analyzer.is_plugin_available("NonExistentPlugin").unwrap());
    }
    
    #[test]
    fn test_context_with_invalid_path() {
        let analyzer = VolatilityAnalyzer::new().unwrap();
        let result = analyzer.initialize_context("/nonexistent/path/dump.raw");
        
        assert!(result.is_err(), "Should fail with invalid path");
        match result {
            Err(MemoryAnalysisError::DumpFileError(_)) => {},
            _ => panic!("Should be DumpFileError"),
        }
    }
}
