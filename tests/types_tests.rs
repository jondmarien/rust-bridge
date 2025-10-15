use rust_bridge::types::{CommandLineInfo, MalwareDetection, NetworkConnectionInfo, VersionInfo};
use rust_bridge::{DllInfo, ProcessInfo};

// ProcessInfo tests (from process_analysis.rs)
#[test]
fn test_process_info_creation() {
    let process = ProcessInfo {
        pid: 1234,
        ppid: 100,
        name: "explorer.exe".to_string(),
        offset: "0xFFFF800012345678".to_string(),
        threads: 42,
        handles: 512,
        create_time: "2025-01-01 12:00:00".to_string(),
    };

    assert_eq!(process.pid, 1234);
    assert_eq!(process.ppid, 100);
    assert_eq!(process.name, "explorer.exe");
    assert_eq!(process.threads, 42);
}

#[test]
fn test_process_info_json_serialization() {
    let process = ProcessInfo {
        pid: 4096,
        ppid: 1000,
        name: "svchost.exe".to_string(),
        offset: "0x12345".to_string(),
        threads: 8,
        handles: 256,
        create_time: "2025-01-01 10:30:45".to_string(),
    };

    let json = serde_json::to_string(&process).unwrap();
    assert!(json.contains("4096"));
    assert!(json.contains("svchost.exe"));
}

// DllInfo tests (from process_analysis.rs)
#[test]
fn test_dll_info_creation() {
    let dll = DllInfo {
        pid: 1234,
        process_name: "notepad.exe".to_string(),
        base: "0x7FF800000000".to_string(),
        size: 0x1000000,
        name: "kernel32.dll".to_string(),
        path: "C:\\Windows\\System32\\kernel32.dll".to_string(),
    };

    assert_eq!(dll.pid, 1234);
    assert_eq!(dll.name, "kernel32.dll");
}

#[test]
fn test_dll_info_json_serialization() {
    let dll = DllInfo {
        pid: 1234,
        process_name: "notepad.exe".to_string(),
        base: "0x7FF800000000".to_string(),
        size: 0x1000000,
        name: "kernel32.dll".to_string(),
        path: "C:\\Windows\\System32\\kernel32.dll".to_string(),
    };

    let json = serde_json::to_string(&dll).unwrap();
    assert!(json.contains("kernel32.dll"));
    assert!(json.contains("1234"));
}

// CommandLineInfo tests (from types.rs)
#[test]
fn test_command_line_info() {
    let cmdline = CommandLineInfo {
        pid: 1234,
        process_name: "cmd.exe".to_string(),
        command_line: "cmd.exe /c dir".to_string(),
    };

    assert_eq!(cmdline.pid, 1234);
    assert_eq!(cmdline.command_line, "cmd.exe /c dir");
}

#[test]
fn test_command_line_json() {
    let cmdline = CommandLineInfo {
        pid: 5678,
        process_name: "powershell.exe".to_string(),
        command_line: "powershell.exe -File script.ps1".to_string(),
    };

    let json = serde_json::to_string(&cmdline).unwrap();
    assert!(json.contains("5678"));
    assert!(json.contains("powershell.exe"));
}

// NetworkConnectionInfo tests (from types.rs)
#[test]
fn test_network_connection_info() {
    let conn = NetworkConnectionInfo {
        pid: 1234,
        process_name: "chrome.exe".to_string(),
        local_address: "192.168.1.100".to_string(),
        local_port: 12345,
        foreign_address: "8.8.8.8".to_string(),
        foreign_port: 80,
        protocol: "TCPv4".to_string(),
        state: "ESTABLISHED".to_string(),
        created_time: "2025-01-01 12:00:00".to_string(),
    };

    assert_eq!(conn.protocol, "TCPv4");
    assert_eq!(conn.state, "ESTABLISHED");
}

#[test]
fn test_network_connection_json() {
    let conn = NetworkConnectionInfo {
        pid: 9999,
        process_name: "firefox.exe".to_string(),
        local_address: "10.0.0.1".to_string(),
        local_port: 443,
        foreign_address: "1.1.1.1".to_string(),
        foreign_port: 443,
        protocol: "TCPv6".to_string(),
        state: "LISTENING".to_string(),
        created_time: "2025-01-01 13:00:00".to_string(),
    };

    let json = serde_json::to_string(&conn).unwrap();
    assert!(json.contains("9999"));
    assert!(json.contains("TCPv6"));
}

// MalwareDetection tests (from types.rs)
#[test]
fn test_malware_detection() {
    let detection = MalwareDetection {
        pid: 6666,
        process_name: "suspicious.exe".to_string(),
        detection_type: "Code Injection".to_string(),
        severity: "High".to_string(),
        confidence: 85,
        indicators: vec![
            "VirtualAllocEx".to_string(),
            "WriteProcessMemory".to_string(),
        ],
        details: "Detected suspicious memory allocation".to_string(),
    };

    assert_eq!(detection.confidence, 85);
    assert_eq!(detection.severity, "High");
    assert_eq!(detection.indicators.len(), 2);
}

#[test]
fn test_malware_detection_json() {
    let detection = MalwareDetection {
        pid: 7777,
        process_name: "malware.exe".to_string(),
        detection_type: "Rootkit".to_string(),
        severity: "Critical".to_string(),
        confidence: 95,
        indicators: vec!["SSDT Hook".to_string()],
        details: "Detected kernel hooks".to_string(),
    };

    let json = serde_json::to_string(&detection).unwrap();
    assert!(json.contains("Rootkit"));
    assert!(json.contains("95"));
}

// VersionInfo tests (from types.rs)
#[test]
fn test_version_info() {
    let version = VersionInfo {
        rust_bridge_version: "0.1.0".to_string(),
        volatility_version: "3.2.26".to_string(),
        python_version: "3.12.11".to_string(),
    };

    assert_eq!(version.rust_bridge_version, "0.1.0");
    assert_eq!(version.python_version, "3.12.11");
}

#[test]
fn test_version_info_json() {
    let version = VersionInfo {
        rust_bridge_version: "0.2.0".to_string(),
        volatility_version: "3.2.27".to_string(),
        python_version: "3.13.0".to_string(),
    };

    let json = serde_json::to_string(&version).unwrap();
    assert!(json.contains("0.2.0"));
    assert!(json.contains("3.13.0"));
}

// Test JSON deserialization
#[test]
fn test_process_info_deserialization() {
    let json = r#"{"pid":1234,"ppid":100,"name":"test.exe","offset":"0x1000","threads":4,"handles":100,"create_time":"2025-01-01"}"#;
    let process: ProcessInfo = serde_json::from_str(json).unwrap();

    assert_eq!(process.pid, 1234);
    assert_eq!(process.name, "test.exe");
}
