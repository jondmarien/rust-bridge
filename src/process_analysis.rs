//! Process Analysis Functions
//!
//! This module provides memory analysis functions specifically focused on
//! process tree analysis, including process listing, command lines, handles, and DLLs.

use crate::volatility::{VolatilityAnalyzer, VolatilityContext};
use crate::{MemoryAnalysisError, MemoryAnalysisResult, PythonManager};
use pyo3::types::{PyAnyMethods, PyListMethods};
use serde::{Deserialize, Serialize};

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
    pub fn list_processes(
        &self,
        context: &VolatilityContext,
    ) -> MemoryAnalysisResult<Vec<ProcessInfo>> {
        PythonManager::with_gil(|py| {
            // Execute Python code that mimics the Volatility CLI approach
            let python_code = format!(
                r#"
import sys
from volatility3 import framework
from volatility3.framework import contexts, plugins, automagic
from volatility3.plugins.windows import pslist

def run_pslist(dump_path):
    # Create context
    ctx = contexts.Context()
    
    # Set the dump file location
    file_url = 'file:///' + dump_path.replace('\\', '/')
    ctx.config['automagic.LayerStacker.single_location'] = file_url
    
    # Setup plugin
    plugin_class = pslist.PsList
    base_config_path = 'plugins'
    
    # Get available automagics
    automagics = automagic.available(ctx)
    
    # Choose automagics for the plugin
    plugin_list = automagic.choose_automagic(automagics, plugin_class)
    
    # Run automagics to populate configuration
    errors = automagic.run(plugin_list, ctx, plugin_class, base_config_path, None)
    if errors:
        raise Exception(f"Automagic failed with errors: {{errors}}")
    
    # Construct the plugin - now that automagics have run
    plugin = plugins.construct_plugin(ctx, plugin_list, plugin_class, base_config_path, None, None)
    
    # Run the plugin
    treegrid = plugin.run()
    
    # Collect results
    results = []
    def visitor(node, accumulator):
        if accumulator is not None:
            accumulator.append(node)
        return accumulator  # Return accumulator for chaining
    
    treegrid.populate(visitor, results)
    
    return results

results = run_pslist(r'{}')
"#,
                context.dump_path()
            );

            // Use exec to run the Python code
            let builtins = py.import("builtins")?;
            let exec_fn = builtins.getattr("exec")?;
            let globals = pyo3::types::PyDict::new(py);
            globals.set_item("__builtins__", builtins)?;
            exec_fn.call1((&python_code, &globals))?;

            // Get results from globals (since that's where our script puts it)
            let results = globals.get_item("results")?;
            let processes_list = results.downcast::<pyo3::types::PyList>()?;

            // Extract process information from the treegrid rows
            let mut processes = Vec::new();

            for row in processes_list.iter() {
                // Each row is a TreeNode object with a 'values' attribute (which is a list)
                let node_values = row.getattr("values")?;
                let values = node_values.downcast::<pyo3::types::PyList>()?;

                // Expected columns: PID, PPID, ImageFileName, Offset(V), Threads, Handles, SessionId, Wow64, CreateTime, ExitTime
                if values.len() >= 6 {
                    // Extract values - PID/PPID are Pointer types, need to convert via str
                    let pid: u32 = values.get_item(0)?.str()?.to_string().parse().unwrap_or(0);
                    let ppid: u32 = values.get_item(1)?.str()?.to_string().parse().unwrap_or(0);

                    // Name is a string
                    let name: String = values
                        .get_item(2)?
                        .extract()
                        .unwrap_or_else(|_| "Unknown".to_string());

                    // Offset is an integer
                    let offset: String =
                        format!("{:#x}", values.get_item(3)?.extract::<u64>().unwrap_or(0));

                    // Threads is an integer
                    let threads: u32 = values.get_item(4)?.extract().unwrap_or(0);

                    // Handles might be UnreadableValue - try to extract or default to 0
                    let handles: u32 = values.get_item(5)?.extract().unwrap_or(0);

                    // CreateTime at index 8 - convert to string
                    let create_time: String = if values.len() > 8 {
                        values
                            .get_item(8)?
                            .str()
                            .map(|s| s.to_string())
                            .unwrap_or_else(|_| "N/A".to_string())
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
    pub fn get_process_tree(
        &self,
        _context: &VolatilityContext,
    ) -> MemoryAnalysisResult<Vec<ProcessInfo>> {
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
    pub fn get_command_lines(
        &self,
        context: &VolatilityContext,
    ) -> MemoryAnalysisResult<Vec<crate::types::CommandLineInfo>> {
        PythonManager::with_gil(|py| {
            // Execute Python code that runs the CmdLine plugin
            let python_code = format!(
                r#"
import sys
from volatility3 import framework
from volatility3.framework import contexts, plugins, automagic
from volatility3.plugins.windows import cmdline

def run_cmdline(dump_path):
    # Create context
    ctx = contexts.Context()
    
    # Set the dump file location
    file_url = 'file:///' + dump_path.replace('\\', '/')
    ctx.config['automagic.LayerStacker.single_location'] = file_url
    
    # Setup plugin
    plugin_class = cmdline.CmdLine
    base_config_path = 'plugins'
    
    # Get available automagics
    automagics = automagic.available(ctx)
    
    # Choose automagics for the plugin
    plugin_list = automagic.choose_automagic(automagics, plugin_class)
    
    # Run automagics to populate configuration
    errors = automagic.run(plugin_list, ctx, plugin_class, base_config_path, None)
    if errors:
        raise Exception(f"Automagic failed with errors: {{errors}}")
    
    # Construct the plugin
    plugin = plugins.construct_plugin(ctx, plugin_list, plugin_class, base_config_path, None, None)
    
    # Run the plugin
    treegrid = plugin.run()
    
    # Collect results
    results = []
    def visitor(node, accumulator):
        if accumulator is not None:
            accumulator.append(node)
        return accumulator
    
    treegrid.populate(visitor, results)
    
    return results

results = run_cmdline(r'{}')
"#,
                context.dump_path()
            );

            // Use exec to run the Python code
            let builtins = py.import("builtins")?;
            let exec_fn = builtins.getattr("exec")?;
            let globals = pyo3::types::PyDict::new(py);
            globals.set_item("__builtins__", builtins)?;
            exec_fn.call1((&python_code, &globals))?;

            // Get results from globals
            let results = globals.get_item("results")?;
            let cmdline_list = results.downcast::<pyo3::types::PyList>()?;

            // Extract command line information from the treegrid rows
            let mut command_lines = Vec::new();

            for row in cmdline_list.iter() {
                // Each row is a TreeNode object with a 'values' attribute
                let node_values = row.getattr("values")?;
                let values = node_values.downcast::<pyo3::types::PyList>()?;

                // Expected columns: PID, Process, Args
                if values.len() >= 3 {
                    // Extract PID
                    let pid: u32 = values.get_item(0)?.str()?.to_string().parse().unwrap_or(0);

                    // Extract process name
                    let process_name: String = values
                        .get_item(1)?
                        .extract()
                        .unwrap_or_else(|_| "Unknown".to_string());

                    // Extract command line - handle potential UnreadableValue
                    let command_line: String = values
                        .get_item(2)?
                        .str()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|_| "<unreadable>".to_string());

                    command_lines.push(crate::types::CommandLineInfo {
                        pid,
                        process_name,
                        command_line,
                    });
                }
            }

            Ok(command_lines)
        })
    }

    /// List DLLs loaded by processes
    ///
    /// Uses the DllList plugin to enumerate loaded modules
    pub fn list_dlls(
        &self,
        context: &VolatilityContext,
        pid_filter: Option<u32>,
    ) -> MemoryAnalysisResult<Vec<crate::types::DllInfo>> {
        PythonManager::with_gil(|py| {
            // Build Python code with optional PID filter
            let pid_filter_code = if let Some(pid) = pid_filter {
                format!("pid_filter = {}", pid)
            } else {
                "pid_filter = None".to_string()
            };

            // Execute Python code that runs the DllList plugin
            let python_code = format!(
                r#"
import sys
from volatility3 import framework
from volatility3.framework import contexts, plugins, automagic
from volatility3.plugins.windows import dlllist

def run_dlllist(dump_path, pid_filter=None):
    # Create context
    ctx = contexts.Context()
    
    # Set the dump file location
    file_url = 'file:///' + dump_path.replace('\\', '/')
    ctx.config['automagic.LayerStacker.single_location'] = file_url
    
    # Setup plugin
    plugin_class = dlllist.DllList
    base_config_path = 'plugins'
    
    # Get available automagics
    automagics = automagic.available(ctx)
    
    # Choose automagics for the plugin
    plugin_list = automagic.choose_automagic(automagics, plugin_class)
    
    # Run automagics to populate configuration
    errors = automagic.run(plugin_list, ctx, plugin_class, base_config_path, None)
    if errors:
        raise Exception(f"Automagic failed with errors: {{errors}}")
    
    # Construct the plugin with optional PID filter
    if pid_filter is not None:
        ctx.config['plugins.DllList.pid'] = [pid_filter]
    
    plugin = plugins.construct_plugin(ctx, plugin_list, plugin_class, base_config_path, None, None)
    
    # Run the plugin
    treegrid = plugin.run()
    
    # Collect results
    results = []
    def visitor(node, accumulator):
        if accumulator is not None:
            accumulator.append(node)
        return accumulator
    
    treegrid.populate(visitor, results)
    
    return results

{}
results = run_dlllist(r'{}', pid_filter)
"#,
                pid_filter_code,
                context.dump_path()
            );

            // Use exec to run the Python code
            let builtins = py.import("builtins")?;
            let exec_fn = builtins.getattr("exec")?;
            let globals = pyo3::types::PyDict::new(py);
            globals.set_item("__builtins__", builtins)?;
            exec_fn.call1((&python_code, &globals))?;

            // Get results from globals
            let results = globals.get_item("results")?;
            let dll_list = results.downcast::<pyo3::types::PyList>()?;

            // Extract DLL information from the treegrid rows
            let mut dlls = Vec::new();

            for row in dll_list.iter() {
                // Each row is a TreeNode object with a 'values' attribute
                let node_values = row.getattr("values")?;
                let values = node_values.downcast::<pyo3::types::PyList>()?;

                // Expected columns: PID, Process, Base, Size, Name, Path
                if values.len() >= 6 {
                    // Extract PID
                    let pid: u32 = values.get_item(0)?.str()?.to_string().parse().unwrap_or(0);

                    // Extract process name
                    let process_name: String = values
                        .get_item(1)?
                        .extract()
                        .unwrap_or_else(|_| "Unknown".to_string());

                    // Extract base address
                    let base_address: String = values.get_item(2)?.str()?.to_string();

                    // Extract size
                    let size: u64 = values.get_item(3)?.str()?.to_string().parse().unwrap_or(0);

                    // Extract DLL name
                    let dll_name: String = values
                        .get_item(4)?
                        .extract()
                        .unwrap_or_else(|_| "Unknown".to_string());

                    // Extract DLL path - handle potential UnreadableValue
                    let dll_path: String = values
                        .get_item(5)?
                        .str()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|_| "<unreadable>".to_string());

                    dlls.push(crate::types::DllInfo {
                        pid,
                        process_name,
                        base_address,
                        size,
                        dll_name,
                        dll_path,
                    });
                }
            }

            Ok(dlls)
        })
    }

    /// Scan network connections in the memory dump
    ///
    /// Uses the NetScan plugin to enumerate active and closed network connections
    pub fn scan_network_connections(
        &self,
        context: &VolatilityContext,
    ) -> MemoryAnalysisResult<Vec<crate::types::NetworkConnectionInfo>> {
        PythonManager::with_gil(|py| {
            // Execute Python code that runs the NetScan plugin
            let python_code = format!(
                r#"
import sys
from volatility3 import framework
from volatility3.framework import contexts, plugins, automagic
from volatility3.plugins.windows import netscan

def run_netscan(dump_path):
    # Create context
    ctx = contexts.Context()
    
    # Set the dump file location
    file_url = 'file:///' + dump_path.replace('\\', '/')
    ctx.config['automagic.LayerStacker.single_location'] = file_url
    
    # Setup plugin
    plugin_class = netscan.NetScan
    base_config_path = 'plugins'
    
    # Get available automagics
    automagics = automagic.available(ctx)
    
    # Choose automagics for the plugin
    plugin_list = automagic.choose_automagic(automagics, plugin_class)
    
    # Run automagics to populate configuration
    errors = automagic.run(plugin_list, ctx, plugin_class, base_config_path, None)
    if errors:
        raise Exception(f"Automagic failed with errors: {{errors}}")
    
    # Construct the plugin
    plugin = plugins.construct_plugin(ctx, plugin_list, plugin_class, base_config_path, None, None)
    
    # Run the plugin
    treegrid = plugin.run()
    
    # Collect results
    results = []
    def visitor(node, accumulator):
        if accumulator is not None:
            accumulator.append(node)
        return accumulator
    
    treegrid.populate(visitor, results)
    
    return results

results = run_netscan(r'{}')
"#,
                context.dump_path()
            );

            // Use exec to run the Python code
            let builtins = py.import("builtins")?;
            let exec_fn = builtins.getattr("exec")?;
            let globals = pyo3::types::PyDict::new(py);
            globals.set_item("__builtins__", builtins)?;
            exec_fn.call1((&python_code, &globals))?;

            // Get results from globals
            let results = globals.get_item("results")?;
            let netscan_list = results.downcast::<pyo3::types::PyList>()?;

            // Extract network connection information from the treegrid rows
            let mut connections = Vec::new();

            for row in netscan_list.iter() {
                // Each row is a TreeNode object with a 'values' attribute
                let node_values = row.getattr("values")?;
                let values = node_values.downcast::<pyo3::types::PyList>()?;

                // Expected columns: Offset, Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, Created
                if values.len() >= 10 {
                    // Extract PID (index 7)
                    let pid: u32 = values.get_item(7)?.str()?.to_string().parse().unwrap_or(0);

                    // Extract process name/owner (index 8)
                    let process_name: String = values
                        .get_item(8)?
                        .extract()
                        .unwrap_or_else(|_| "Unknown".to_string());

                    // Extract protocol (index 1)
                    let protocol: String = values
                        .get_item(1)?
                        .extract()
                        .unwrap_or_else(|_| "Unknown".to_string());

                    // Extract local address (index 2)
                    let local_address: String = values
                        .get_item(2)?
                        .extract()
                        .unwrap_or_else(|_| "0.0.0.0".to_string());

                    // Extract local port (index 3)
                    let local_port: u16 =
                        values.get_item(3)?.str()?.to_string().parse().unwrap_or(0);

                    // Extract foreign address (index 4)
                    let foreign_address: String = values
                        .get_item(4)?
                        .extract()
                        .unwrap_or_else(|_| "0.0.0.0".to_string());

                    // Extract foreign port (index 5)
                    let foreign_port: u16 =
                        values.get_item(5)?.str()?.to_string().parse().unwrap_or(0);

                    // Extract state (index 6)
                    let state: String = values
                        .get_item(6)?
                        .extract()
                        .unwrap_or_else(|_| "UNKNOWN".to_string());

                    // Extract created time (index 9) - handle potential UnreadableValue
                    let created_time: String = values
                        .get_item(9)?
                        .str()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|_| "N/A".to_string());

                    connections.push(crate::types::NetworkConnectionInfo {
                        pid,
                        process_name,
                        local_address,
                        local_port,
                        foreign_address,
                        foreign_port,
                        protocol,
                        state,
                        created_time,
                    });
                }
            }

            Ok(connections)
        })
    }

    /// Detect potential malware using Malfind plugin
    ///
    /// Uses the Malfind plugin to detect code injection and suspicious memory regions
    pub fn detect_malware(
        &self,
        context: &VolatilityContext,
    ) -> MemoryAnalysisResult<Vec<crate::types::MalwareDetection>> {
        PythonManager::with_gil(|py| {
            // Execute Python code that runs the Malfind plugin
            let python_code = format!(
                r#"
import sys
import warnings
warnings.filterwarnings('ignore')  # Suppress deprecation warnings
from volatility3 import framework
from volatility3.framework import contexts, plugins, automagic
from volatility3.plugins.windows.malware import malfind

def run_malfind(dump_path):
    # Create context
    ctx = contexts.Context()
    
    # Set the dump file location
    file_url = 'file:///' + dump_path.replace('\\', '/')
    ctx.config['automagic.LayerStacker.single_location'] = file_url
    
    # Setup plugin
    plugin_class = malfind.Malfind
    base_config_path = 'plugins'
    
    # Get available automagics
    automagics = automagic.available(ctx)
    
    # Choose automagics for the plugin
    plugin_list = automagic.choose_automagic(automagics, plugin_class)
    
    # Run automagics to populate configuration
    errors = automagic.run(plugin_list, ctx, plugin_class, base_config_path, None)
    if errors:
        raise Exception(f"Automagic failed with errors: {{errors}}")
    
    # Construct the plugin
    plugin = plugins.construct_plugin(ctx, plugin_list, plugin_class, base_config_path, None, None)
    
    # Run the plugin
    treegrid = plugin.run()
    
    # Collect results
    results = []
    def visitor(node, accumulator):
        if accumulator is not None:
            accumulator.append(node)
        return accumulator
    
    treegrid.populate(visitor, results)
    
    return results

results = run_malfind(r'{}')
"#,
                context.dump_path()
            );

            // Use exec to run the Python code
            let builtins = py.import("builtins")?;
            let exec_fn = builtins.getattr("exec")?;
            let globals = pyo3::types::PyDict::new(py);
            globals.set_item("__builtins__", builtins)?;
            exec_fn.call1((&python_code, &globals))?;

            // Get results from globals
            let results = globals.get_item("results")?;
            let malfind_list = results.downcast::<pyo3::types::PyList>()?;

            // Extract malware detection information from the treegrid rows
            let mut detections = Vec::new();

            for row in malfind_list.iter() {
                // Each row is a TreeNode object with a 'values' attribute
                let node_values = row.getattr("values")?;
                let values = node_values.downcast::<pyo3::types::PyList>()?;

                // Expected columns: PID, Process, Start VPN, End VPN, Tag, Protection, Hexdump, Disasm
                if values.len() >= 8 {
                    // Extract PID (index 0)
                    let pid: u32 = values.get_item(0)?.str()?.to_string().parse().unwrap_or(0);

                    // Extract process name (index 1)
                    let process_name: String = values
                        .get_item(1)?
                        .extract()
                        .unwrap_or_else(|_| "Unknown".to_string());

                    // Extract memory region start (index 2)
                    let start_vpn: String = values.get_item(2)?.str()?.to_string();

                    // Extract memory region end (index 3)
                    let end_vpn: String = values.get_item(3)?.str()?.to_string();

                    // Extract tag (index 4)
                    let tag: String = values
                        .get_item(4)?
                        .extract()
                        .unwrap_or_else(|_| "Unknown".to_string());

                    // Extract protection (index 5)
                    let protection: String = values
                        .get_item(5)?
                        .extract()
                        .unwrap_or_else(|_| "Unknown".to_string());

                    // Build indicators list
                    let mut indicators = Vec::new();
                    indicators.push(format!("Memory region: {} - {}", start_vpn, end_vpn));
                    indicators.push(format!("Protection: {}", protection));
                    if !tag.is_empty() && tag != "Unknown" {
                        indicators.push(format!("Tag: {}", tag));
                    }

                    // Determine severity and confidence based on protection flags
                    let (severity, confidence) = if protection.contains("PAGE_EXECUTE_READWRITE") {
                        ("High".to_string(), 85)
                    } else if protection.contains("PAGE_EXECUTE") {
                        ("Medium".to_string(), 70)
                    } else {
                        ("Low".to_string(), 50)
                    };

                    let details = format!(
                        "Suspicious memory region detected at {}-{} with {} protection",
                        start_vpn, end_vpn, protection
                    );

                    detections.push(crate::types::MalwareDetection {
                        pid,
                        process_name,
                        detection_type: "Code Injection".to_string(),
                        severity,
                        confidence,
                        indicators,
                        details,
                    });
                }
            }

            Ok(detections)
        })
    }

    /// List handles opened by processes
    ///
    /// Uses the Handles plugin to enumerate process handles
    pub fn list_handles(
        &self,
        _context: &VolatilityContext,
        _pid: Option<u32>,
    ) -> MemoryAnalysisResult<Vec<HandleInfo>> {
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
    pub fn find_process_by_name(
        &self,
        context: &VolatilityContext,
        name: &str,
    ) -> MemoryAnalysisResult<Vec<ProcessInfo>> {
        let processes = self.list_processes(context)?;
        Ok(processes
            .into_iter()
            .filter(|p| p.name.to_lowercase().contains(&name.to_lowercase()))
            .collect())
    }

    /// Find a process by PID
    ///
    /// Returns the process with the specified PID, if found
    pub fn find_process_by_pid(
        &self,
        context: &VolatilityContext,
        pid: u32,
    ) -> MemoryAnalysisResult<Option<ProcessInfo>> {
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
            return Err(MemoryAnalysisError::VolatilityError(format!(
                "Plugin '{}' is not available",
                plugin_name
            )));
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
    #[ignore] // Requires actual memory dump file - run locally with test dumps
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
    #[ignore] // Requires actual memory dump file - run locally with test dumps
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
    #[ignore] // Requires actual memory dump file - run locally with test dumps
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
