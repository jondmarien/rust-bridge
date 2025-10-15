use rust_bridge::error::MemoryAnalysisError;

#[test]
fn test_python_error() {
    let error = MemoryAnalysisError::PythonError("Test error".to_string());
    let error_msg = format!("{}", error);
    assert!(error_msg.contains("Python error"));
    assert!(error_msg.contains("Test error"));
}

#[test]
fn test_volatility_error() {
    let error = MemoryAnalysisError::VolatilityError("Plugin failed".to_string());
    let error_msg = format!("{}", error);
    assert!(error_msg.contains("Volatility error"));
    assert!(error_msg.contains("Plugin failed"));
}

#[test]
fn test_dump_file_error() {
    let error = MemoryAnalysisError::DumpFileError("File not found".to_string());
    let error_msg = format!("{}", error);
    assert!(error_msg.contains("Dump file error"));
}

#[test]
fn test_serialization_error() {
    let error = MemoryAnalysisError::SerializationError("JSON parse failed".to_string());
    let error_msg = format!("{}", error);
    assert!(error_msg.contains("Serialization error"));
}

#[test]
fn test_io_error() {
    let error = MemoryAnalysisError::IoError("Read failed".to_string());
    let error_msg = format!("{}", error);
    assert!(error_msg.contains("I/O error"));
}

#[test]
fn test_other_error() {
    let error = MemoryAnalysisError::Other("Unknown error".to_string());
    let error_msg = format!("{}", error);
    assert!(error_msg.contains("Error:"));
}

#[test]
fn test_error_debug_format() {
    let error = MemoryAnalysisError::PythonError("Debug test".to_string());
    let debug_msg = format!("{:?}", error);
    assert!(debug_msg.contains("PythonError"));
}
