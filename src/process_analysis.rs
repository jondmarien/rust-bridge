//! Process Analysis Functions
//!
//! This module provides memory analysis functions specifically focused on
//! process tree analysis, including process listing, command lines, handles, and DLLs.

use crate::{MemoryAnalysisError, MemoryAnalysisResult, PythonManager};
use crate::volatility::{VolatilityAnalyzer, VolatilityContext};
use serde::{Deserialize, Serialize};
use pyo3::types::{PyAnyMethods, PyTuple, PyListMethods, PyTupleMethods};
use std::ffi::CString;

/// Represents process information extracted from a memory dump
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub offset: String,
    pub threads: u32,
    pub handles: u32,
    pub create_time: String,
}

/// Represents detailed process information with command line
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDetails {
    pub pid: u32,
    pub process_name: String,
    pub command_line: Option<String>,
}

/// Represents a DLL loaded by a process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DllInfo {
    pub pid: u32,
    pub process_name: String,
    pub base: String,
    pub size: u64,
    pub name: String,
    pub path: String,
}

/// Represents a handle owned by a process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleInfo {
    pub pid: u32,
    pub process_name: String,
    pub handle_value: String,
    pub handle_type: String,
    pub granted_access: String,
    pub name: Option<String>,
}

/// Process Analysis Engine
///
/// Provides high-level functions for analyzing processes in memory dumps
pub struct ProcessAnalyzer {
    analyzer: VolatilityAnalyzer,
}

impl ProcessAnalyzer {
    /// Create a new process analyzer
    pub fn new() -> MemoryAnalysisResult<Self> {
        let analyzer = VolatilityAnalyzer::new()?;
        Ok(ProcessAnalyzer { analyzer })
    }

    /// List all processes in a memory dump
    ///
    /// Uses the PsList plugin to enumerate processes  
    pub fn list_processes(&self, context: &VolatilityContext) -> MemoryAnalysisResult<Vec<ProcessInfo>> {
        PythonManager::with_gil(|py| {
            // Import required Volatility modules  
            let contexts_module = py.import("volatility3.framework.contexts")?;
            let plugins_module = py.import("volatility3.framework.plugins")?;
            let automagic_module = py.import("volatility3.framework.automagic")?;
            let pslist_module = py.import("volatility3.plugins.windows.pslist")?;
            let pslist_class = pslist_module.getattr("PsList")?;
            let traceback_module = py.import("traceback")?;
            
            // Create a new Volatility context
            let ctx = contexts_module.getattr("Context")?.call0()?;
            
            // Set the single location (dump file path) in config
            let config = ctx.getattr("config")?;
            let file_url = format!("file:///{}", context.dump_path().replace("\\", "/"));
            config.set_item("automagic.LayerStacker.single_location", file_url)?;
            
            // Get available automagics and choose appropriate ones
            let available_automagics = automagic_module.call_method1("available", (&ctx,))?;
            let chosen_automagics = automagic_module.call_method1("choose_automagic", (&available_automagics, &pslist_class))?;
            
            // Run automagics to set up layers (this is critical!)
            let base_config_path = "plugins";
            let _automagic_errors = automagic_module.call_method(
                "run",
                (&chosen_automagics, &ctx, &pslist_class, base_config_path, py.None()),
                None
            )?;
            
            // Construct the plugin
            let plugin = plugins_module.call_method(
                "construct_plugin",
                (&ctx, &chosen_automagics, &pslist_class, base_config_path, py.None(), py.None()),
                None
            )?;
            
            // Run the plugin to get TreeGrid
            let treegrid = plugin.call_method0("run")?;
            
            // Populate the treegrid
            let code = CString::new("lambda row, accumulator: accumulator.append(row)").unwrap();
            let visitor_fn = py.eval(&code, None, None)?;
            
            let processes_list = pyo3::types::PyList::empty(py);
            treegrid.call_method1("populate", (&visitor_fn, &processes_list))?;
            
            // Extract process information from the treegrid rows
            let mut processes = Vec::new();
            
            for row in processes_list.iter() {
                // Each row is a tuple: (depth, values_tuple)
                let row_tuple = row.downcast::<PyTuple>()?;
                if row_tuple.len() < 2 {
                    continue;
                }
                
                let values_item = row_tuple.get_item(1)?;
                let values = values_item.downcast::<PyTuple>()?;
                
                // Expected columns: PID, PPID, ImageFileName, Offset, Threads, Handles, SessionId, Wow64, CreateTime, ExitTime
                if values.len() >= 6 {
                    let pid: u32 = values.get_item(0)?.extract().unwrap_or(0);
                    let ppid: u32 = values.get_item(1)?.extract().unwrap_or(0);
                    let name: String = values.get_item(2)?.extract().unwrap_or_else(|_| "Unknown".to_string());
                    let offset: String = format!("{:#x}", values.get_item(3)?.extract::<u64>().unwrap_or(0));
                    let threads: u32 = values.get_item(4)?.extract().unwrap_or(0);
                    let handles: u32 = values.get_item(5)?.extract().unwrap_or(0);
                    
                    // CreateTime is typically at index 8
                    let create_time: String = if values.len() > 8 {
                        values.get_item(8)?.extract().unwrap_or_else(|_| "N/A".to_string())
                    } else {
                        "N/A".to_string()
                    };
                    
                    processes.push(ProcessInfo {
                        pid,
                        ppid,
                        name,
                        offset,
                        threads,
                        handles,
                        create_time,
                    });
                }
            }
            
            Ok(processes)
        })
    }

    /// Get process tree structure
    ///
    /// Uses the PsTree plugin to build a hierarchical process tree
    pub fn get_process_tree(&self, _context: &VolatilityContext) -> MemoryAnalysisResult<Vec<ProcessInfo>> {
        PythonManager::with_gil(|py| {
            // Import required modules
            let _vol3 = py.import("volatility3.framework")?;
            let _plugins = py.import("volatility3.framework.plugins")?;
            
            // Placeholder - will be implemented with actual plugin execution
            let tree = vec![];
            Ok(tree)
        })
    }

    /// Get command line arguments for all processes
    ///
    /// Uses the CmdLine plugin to extract process command lines
    pub fn get_command_lines(&self, _context: &VolatilityContext) -> MemoryAnalysisResult<Vec<ProcessDetails>> {
        PythonManager::with_gil(|py| {
            // Import required modules
            let _vol3 = py.import("volatility3.framework")?;
            
            // Placeholder implementation
            let details = vec![];
            Ok(details)
        })
    }

    /// List DLLs loaded by processes
    ///
    /// Uses the DllList plugin to enumerate loaded modules
    pub fn list_dlls(&self, _context: &VolatilityContext, _pid: Option<u32>) -> MemoryAnalysisResult<Vec<DllInfo>> {
        PythonManager::with_gil(|py| {
            // Import required modules
            let _vol3 = py.import("volatility3.framework")?;
            
            // Placeholder implementation
            let dlls = vec![];
            Ok(dlls)
        })
    }

    /// List handles opened by processes
    ///
    /// Uses the Handles plugin to enumerate process handles
    pub fn list_handles(&self, _context: &VolatilityContext, _pid: Option<u32>) -> MemoryAnalysisResult<Vec<HandleInfo>> {
        PythonManager::with_gil(|py| {
            // Import required modules
            let _vol3 = py.import("volatility3.framework")?;
            
            // Placeholder implementation
            let handles = vec![];
            Ok(handles)
        })
    }

    /// Find a process by name
    ///
    /// Returns all processes matching the given name
    pub fn find_process_by_name(&self, context: &VolatilityContext, name: &str) -> MemoryAnalysisResult<Vec<ProcessInfo>> {
        let processes = self.list_processes(context)?;
        Ok(processes
            .into_iter()
            .filter(|p| p.name.to_lowercase().contains(&name.to_lowercase()))
            .collect())
    }

    /// Find a process by PID
    ///
    /// Returns the process with the specified PID, if found
    pub fn find_process_by_pid(&self, context: &VolatilityContext, pid: u32) -> MemoryAnalysisResult<Option<ProcessInfo>> {
        let processes = self.list_processes(context)?;
        Ok(processes.into_iter().find(|p| p.pid == pid))
    }

    /// Execute a generic Volatility plugin
    ///
    /// Provides a wrapper for running any Volatility plugin with error handling
    pub fn execute_plugin(
        &self,
        context: &VolatilityContext,
        plugin_name: &str,
        _options: Option<Vec<(String, String)>>,
    ) -> MemoryAnalysisResult<String> {
        // Verify plugin is available
        if !self.analyzer.is_plugin_available(plugin_name)? {
            return Err(MemoryAnalysisError::VolatilityError(
                format!("Plugin '{}' is not available", plugin_name)
            ));
        }

        PythonManager::with_gil(|py| {
            // Import Volatility framework
            let _vol3 = py.import("volatility3.framework")?;
            
            // Execute the plugin
            // This is a placeholder - actual implementation will use Volatility's plugin system
            let result = format!(
                "{{\"plugin\":\"{}\",\"dump\":\"{}\",\"status\":\"pending\"}}",
                plugin_name,
                context.dump_path()
            );
            
            Ok(result)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_creation() {
        let analyzer = ProcessAnalyzer::new();
        assert!(analyzer.is_ok(), "Should create process analyzer");
    }

    #[test]
    fn test_list_processes_basic() {
        let analyzer = ProcessAnalyzer::new().unwrap();
        
        // Create a dummy context (we won't actually execute plugins in tests)
        let context = VolatilityContext {
            dump_path: "/tmp/dummy.raw".to_string(),
        };
        
        let result = analyzer.list_processes(&context);
        assert!(result.is_ok(), "Should return process list");
        
        let processes = result.unwrap();
        assert!(!processes.is_empty(), "Should have at least one process");
    }

    #[test]
    fn test_find_process_by_name() {
        let analyzer = ProcessAnalyzer::new().unwrap();
        let context = VolatilityContext {
            dump_path: "/tmp/dummy.raw".to_string(),
        };
        
        let result = analyzer.find_process_by_name(&context, "system");
        assert!(result.is_ok(), "Should search for processes");
        
        let processes = result.unwrap();
        assert!(!processes.is_empty(), "Should find System process");
    }

    #[test]
    fn test_find_process_by_pid() {
        let analyzer = ProcessAnalyzer::new().unwrap();
        let context = VolatilityContext {
            dump_path: "/tmp/dummy.raw".to_string(),
        };
        
        let result = analyzer.find_process_by_pid(&context, 4);
        assert!(result.is_ok(), "Should search for process by PID");
        
        let process = result.unwrap();
        assert!(process.is_some(), "Should find process with PID 4");
    }

    #[test]
    fn test_execute_plugin_with_invalid_plugin() {
        let analyzer = ProcessAnalyzer::new().unwrap();
        let context = VolatilityContext {
            dump_path: "/tmp/dummy.raw".to_string(),
        };
        
        let result = analyzer.execute_plugin(&context, "InvalidPlugin", None);
        assert!(result.is_err(), "Should fail with invalid plugin");
    }

    #[test]
    fn test_execute_plugin_with_valid_plugin() {
        let analyzer = ProcessAnalyzer::new().unwrap();
        let context = VolatilityContext {
            dump_path: "/tmp/dummy.raw".to_string(),
        };
        
        let result = analyzer.execute_plugin(&context, "PsList", None);
        assert!(result.is_ok(), "Should execute valid plugin");
    }
}
