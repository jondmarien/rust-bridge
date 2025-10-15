//! Rust-Python Bridge for PowerShell Memory Analysis Module
//!
//! This library provides a high-performance bridge between Rust and Python,
//! enabling PowerShell cmdlets to interact with Volatility 3 framework.

use pyo3::prelude::*;
use anyhow::Result;

// Module declarations
mod python_manager;
mod error;
mod volatility;
mod process_analysis;
mod types;

pub use error::{MemoryAnalysisError, MemoryAnalysisResult};
pub use python_manager::PythonManager;
pub use volatility::{VolatilityAnalyzer, VolatilityContext};
pub use process_analysis::{ProcessAnalyzer, ProcessInfo, ProcessDetails, DllInfo, HandleInfo};
pub use types::{
    AnalysisResult, AnalysisMetadata, VersionInfo, PluginInfo, DumpMetadata,
    KeyValue, PyConverter, JsonSerializable,
};

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
    PythonManager::initialize()?;
    
    let result = PythonManager::with_gil(|py| {
        match py.import("volatility3") {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    })?;
    
    Ok(result)
}

// FFI exports for C# interop
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

// Global debug flag controlled by environment variable
static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

/// Check if debug logging is enabled via environment variable
fn is_debug_enabled() -> bool {
    DEBUG_ENABLED.load(Ordering::Relaxed)
}

/// Initialize debug mode from environment variable
fn init_debug_mode() {
    if let Ok(val) = std::env::var("RUST_BRIDGE_DEBUG") {
        let enabled = matches!(val.to_lowercase().as_str(), "1" | "true" | "yes" | "on");
        DEBUG_ENABLED.store(enabled, Ordering::Relaxed);
        if enabled {
            eprintln!("[rust_bridge] Debug logging enabled");
        }
    }
}

/// Log debug messages only when debug mode is enabled
fn log_debug(msg: &str) {
    if !is_debug_enabled() {
        return;
    }
    
    let log_path = "J:\\projects\\personal-projects\\MemoryAnalysis\\rust-bridge-debug.log";
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
        let _ = writeln!(file, "[{}] {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"), msg);
    }
    eprintln!("[rust_bridge] {}", msg);
}

/// Initialize the Rust-Python bridge (FFI export)
#[no_mangle]
pub extern "C" fn rust_bridge_initialize() -> i32 {
    // Initialize debug mode from environment
    init_debug_mode();
    
    match initialize() {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// Check if Volatility3 is available (FFI export)
#[no_mangle]
pub extern "C" fn rust_bridge_check_volatility() -> i32 {
    match check_volatility_available() {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -1,
    }
}

/// Get version information as JSON string (FFI export)
#[no_mangle]
pub extern "C" fn rust_bridge_get_version() -> *mut c_char {
    let version = VersionInfo {
        rust_bridge_version: env!("CARGO_PKG_VERSION").to_string(),
        volatility_version: "2.26.2".to_string(),
        python_version: "3.12.11".to_string(),
    };
    
    match serde_json::to_string(&version) {
        Ok(json) => {
            match CString::new(json) {
                Ok(c_str) => c_str.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a string allocated by Rust (FFI export)
#[no_mangle]
pub extern "C" fn rust_bridge_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

/// List processes in a memory dump (FFI export)
#[no_mangle]
pub extern "C" fn rust_bridge_list_processes(dump_path: *const c_char) -> *mut c_char {
    if dump_path.is_null() {
        log_debug("Error: dump_path is null");
        return std::ptr::null_mut();
    }
    
    let c_str = unsafe { CStr::from_ptr(dump_path) };
    let path_str = match c_str.to_str() {
        Ok(s) => s,
        Err(e) => {
            log_debug(&format!("Error converting path to string: {}", e));
            return std::ptr::null_mut();
        }
    };
    
    log_debug(&format!("Processing dump: {}", path_str));
    
    // Create analyzer and context
    let analyzer = match ProcessAnalyzer::new() {
        Ok(a) => a,
        Err(e) => {
            log_debug(&format!("Error creating analyzer: {}", e));
            return std::ptr::null_mut();
        }
    };
    
    let context = VolatilityContext {
        dump_path: path_str.to_string(),
    };
    
    // Get process list
    let processes = match analyzer.list_processes(&context) {
        Ok(procs) => procs,
        Err(e) => {
            log_debug(&format!("Error listing processes: {}", e));
            return std::ptr::null_mut();
        }
    };
    
    log_debug(&format!("Successfully extracted {} processes", processes.len()));
    
    // Serialize to JSON
    let json = match serde_json::to_string(&processes) {
        Ok(j) => j,
        Err(e) => {
            log_debug(&format!("Error serializing to JSON: {}", e));
            return std::ptr::null_mut();
        }
    };
    
    match CString::new(json) {
        Ok(c_str) => c_str.into_raw(),
        Err(e) => {
            log_debug(&format!("Error creating CString: {}", e));
            std::ptr::null_mut()
        }
    }
}

/// Get command lines for processes in a memory dump (FFI export)
#[no_mangle]
pub extern "C" fn rust_bridge_get_command_lines(dump_path: *const c_char) -> *mut c_char {
    if dump_path.is_null() {
        log_debug("Error: dump_path is null");
        return std::ptr::null_mut();
    }
    
    let c_str = unsafe { CStr::from_ptr(dump_path) };
    let path_str = match c_str.to_str() {
        Ok(s) => s,
        Err(e) => {
            log_debug(&format!("Error converting path to string: {}", e));
            return std::ptr::null_mut();
        }
    };
    
    log_debug(&format!("Getting command lines from dump: {}", path_str));
    
    // Create analyzer and context
    let analyzer = match ProcessAnalyzer::new() {
        Ok(a) => a,
        Err(e) => {
            log_debug(&format!("Error creating analyzer: {}", e));
            return std::ptr::null_mut();
        }
    };
    
    let context = VolatilityContext {
        dump_path: path_str.to_string(),
    };
    
    // Get command lines
    let command_lines = match analyzer.get_command_lines(&context) {
        Ok(cmds) => cmds,
        Err(e) => {
            log_debug(&format!("Error getting command lines: {}", e));
            return std::ptr::null_mut();
        }
    };
    
    log_debug(&format!("Successfully extracted {} command lines", command_lines.len()));
    
    // Serialize to JSON
    let json = match serde_json::to_string(&command_lines) {
        Ok(j) => j,
        Err(e) => {
            log_debug(&format!("Error serializing to JSON: {}", e));
            return std::ptr::null_mut();
        }
    };
    
    match CString::new(json) {
        Ok(c_str) => c_str.into_raw(),
        Err(e) => {
            log_debug(&format!("Error creating CString: {}", e));
            std::ptr::null_mut()
        }
    }
}

/// List DLLs for processes in a memory dump (FFI export)
/// 
/// # Parameters
/// * `dump_path` - Path to the memory dump file
/// * `pid` - Optional process ID to filter by (0 = no filter)
#[no_mangle]
pub extern "C" fn rust_bridge_list_dlls(
    dump_path: *const c_char,
    pid: u32,
) -> *mut c_char {
    if dump_path.is_null() {
        log_debug("Error: dump_path is null");
        return std::ptr::null_mut();
    }
    
    let c_str = unsafe { CStr::from_ptr(dump_path) };
    let path_str = match c_str.to_str() {
        Ok(s) => s,
        Err(e) => {
            log_debug(&format!("Error converting path to string: {}", e));
            return std::ptr::null_mut();
        }
    };
    
    let pid_filter = if pid == 0 { None } else { Some(pid) };
    let filter_msg = if let Some(p) = pid_filter {
        format!(" (filtered to PID {})", p)
    } else {
        String::new()
    };
    
    log_debug(&format!("Listing DLLs from dump: {}{}", path_str, filter_msg));
    
    // Create analyzer and context
    let analyzer = match ProcessAnalyzer::new() {
        Ok(a) => a,
        Err(e) => {
            log_debug(&format!("Error creating analyzer: {}", e));
            return std::ptr::null_mut();
        }
    };
    
    let context = VolatilityContext {
        dump_path: path_str.to_string(),
    };
    
    // Get DLL list
    let dlls = match analyzer.list_dlls(&context, pid_filter) {
        Ok(dll_list) => dll_list,
        Err(e) => {
            log_debug(&format!("Error listing DLLs: {}", e));
            return std::ptr::null_mut();
        }
    };
    
    log_debug(&format!("Successfully extracted {} DLLs", dlls.len()));
    
    // Serialize to JSON
    let json = match serde_json::to_string(&dlls) {
        Ok(j) => j,
        Err(e) => {
            log_debug(&format!("Error serializing to JSON: {}", e));
            return std::ptr::null_mut();
        }
    };
    
    match CString::new(json) {
        Ok(c_str) => c_str.into_raw(),
        Err(e) => {
            log_debug(&format!("Error creating CString: {}", e));
            std::ptr::null_mut()
        }
    }
}

/// Scan network connections in a memory dump (FFI export)
/// 
/// # Parameters
/// * `dump_path` - Path to the memory dump file
#[no_mangle]
pub extern "C" fn rust_bridge_scan_network_connections(
    dump_path: *const c_char,
) -> *mut c_char {
    if dump_path.is_null() {
        log_debug("Error: dump_path is null");
        return std::ptr::null_mut();
    }
    
    let c_str = unsafe { CStr::from_ptr(dump_path) };
    let path_str = match c_str.to_str() {
        Ok(s) => s,
        Err(e) => {
            log_debug(&format!("Error converting path to string: {}", e));
            return std::ptr::null_mut();
        }
    };
    
    log_debug(&format!("Scanning network connections from dump: {}", path_str));
    
    // Create analyzer and context
    let analyzer = match ProcessAnalyzer::new() {
        Ok(a) => a,
        Err(e) => {
            log_debug(&format!("Error creating analyzer: {}", e));
            return std::ptr::null_mut();
        }
    };
    
    let context = VolatilityContext {
        dump_path: path_str.to_string(),
    };
    
    // Scan network connections
    let connections = match analyzer.scan_network_connections(&context) {
        Ok(conn_list) => conn_list,
        Err(e) => {
            log_debug(&format!("Error scanning network connections: {}", e));
            return std::ptr::null_mut();
        }
    };
    
    log_debug(&format!("Successfully extracted {} network connections", connections.len()));
    
    // Serialize to JSON
    let json = match serde_json::to_string(&connections) {
        Ok(j) => j,
        Err(e) => {
            log_debug(&format!("Error serializing to JSON: {}", e));
            return std::ptr::null_mut();
        }
    };
    
    match CString::new(json) {
        Ok(c_str) => c_str.into_raw(),
        Err(e) => {
            log_debug(&format!("Error creating CString: {}", e));
            std::ptr::null_mut()
        }
    }
}

/// Detect malware in a memory dump (FFI export)
/// 
/// # Parameters
/// * `dump_path` - Path to the memory dump file
#[no_mangle]
pub extern "C" fn rust_bridge_detect_malware(
    dump_path: *const c_char,
) -> *mut c_char {
    if dump_path.is_null() {
        log_debug("Error: dump_path is null");
        return std::ptr::null_mut();
    }
    
    let c_str = unsafe { CStr::from_ptr(dump_path) };
    let path_str = match c_str.to_str() {
        Ok(s) => s,
        Err(e) => {
            log_debug(&format!("Error converting path to string: {}", e));
            return std::ptr::null_mut();
        }
    };
    
    log_debug(&format!("Detecting malware in dump: {}", path_str));
    
    // Create analyzer and context
    let analyzer = match ProcessAnalyzer::new() {
        Ok(a) => a,
        Err(e) => {
            log_debug(&format!("Error creating analyzer: {}", e));
            return std::ptr::null_mut();
        }
    };
    
    let context = VolatilityContext {
        dump_path: path_str.to_string(),
    };
    
    // Detect malware
    let detections = match analyzer.detect_malware(&context) {
        Ok(detections_list) => detections_list,
        Err(e) => {
            log_debug(&format!("Error detecting malware: {}", e));
            return std::ptr::null_mut();
        }
    };
    
    log_debug(&format!("Found {} potential malware detections", detections.len()));
    
    // Serialize to JSON
    let json = match serde_json::to_string(&detections) {
        Ok(j) => j,
        Err(e) => {
            log_debug(&format!("Error serializing to JSON: {}", e));
            return std::ptr::null_mut();
        }
    };
    
    match CString::new(json) {
        Ok(c_str) => c_str.into_raw(),
        Err(e) => {
            log_debug(&format!("Error creating CString: {}", e));
            std::ptr::null_mut()
        }
    }
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
