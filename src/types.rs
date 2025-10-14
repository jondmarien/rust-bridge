//! Type Definitions and Serialization Utilities
//!
//! This module contains common data types used across the memory analysis framework
//! and utilities for converting between Python objects and Rust structs.

use serde::{Deserialize, Serialize};
use serde_json::{self, Value as JsonValue};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyAny};
use crate::{MemoryAnalysisError, MemoryAnalysisResult};

/// Common result wrapper for analysis operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub metadata: AnalysisMetadata,
}

/// Metadata about an analysis operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisMetadata {
    pub timestamp: String,
    pub plugin_name: String,
    pub dump_path: String,
    pub duration_ms: u64,
}

/// Version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub rust_bridge_version: String,
    pub volatility_version: String,
    pub python_version: String,
}

/// Plugin information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub name: String,
    pub description: Option<String>,
    pub version: Option<String>,
    pub supported_platforms: Vec<String>,
}

/// Memory dump metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpMetadata {
    pub path: String,
    pub size_bytes: u64,
    pub profile: Option<String>,
    pub architecture: Option<String>,
    pub os_version: Option<String>,
}

/// Generic key-value pair for flexible data structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyValue {
    pub key: String,
    pub value: String,
}

impl<T> AnalysisResult<T> 
where
    T: Serialize,
{
    /// Create a successful result
    pub fn success(data: T, metadata: AnalysisMetadata) -> Self {
        AnalysisResult {
            success: true,
            data: Some(data),
            error: None,
            metadata,
        }
    }

    /// Create a failed result
    pub fn failure(error: String, metadata: AnalysisMetadata) -> Self {
        AnalysisResult {
            success: false,
            data: None,
            error: Some(error),
            metadata,
        }
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> MemoryAnalysisResult<String> {
        serde_json::to_string(self)
            .map_err(|e| MemoryAnalysisError::SerializationError(e.to_string()))
    }

    /// Convert to pretty-printed JSON string
    pub fn to_json_pretty(&self) -> MemoryAnalysisResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| MemoryAnalysisError::SerializationError(e.to_string()))
    }
}

impl AnalysisMetadata {
    /// Create new metadata with current timestamp
    pub fn new(plugin_name: String, dump_path: String) -> Self {
        AnalysisMetadata {
            timestamp: chrono::Utc::now().to_rfc3339(),
            plugin_name,
            dump_path,
            duration_ms: 0,
        }
    }

    /// Update duration
    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = duration_ms;
        self
    }
}

/// Utilities for converting Python objects to Rust types
pub struct PyConverter;

impl PyConverter {
    /// Convert a Python dictionary to a JSON value
    pub fn dict_to_json(py_dict: &Bound<'_, PyDict>) -> MemoryAnalysisResult<JsonValue> {
        let mut map = serde_json::Map::new();
        
        for (key, value) in py_dict.iter() {
            let key_str = key.to_string();
            let value_json = Self::py_to_json(value)?;
            map.insert(key_str, value_json);
        }
        
        Ok(JsonValue::Object(map))
    }

    /// Convert a Python list to a JSON value
    pub fn list_to_json(py_list: &Bound<'_, PyList>) -> MemoryAnalysisResult<JsonValue> {
        let mut vec = Vec::new();
        
        for item in py_list.iter() {
            vec.push(Self::py_to_json(item)?);
        }
        
        Ok(JsonValue::Array(vec))
    }

    /// Convert any Python object to a JSON value
    pub fn py_to_json(py_obj: Bound<'_, PyAny>) -> MemoryAnalysisResult<JsonValue> {
        // Try to extract as basic types
        if let Ok(s) = py_obj.extract::<String>() {
            return Ok(JsonValue::String(s));
        }
        
        if let Ok(i) = py_obj.extract::<i64>() {
            return Ok(JsonValue::Number(i.into()));
        }
        
        if let Ok(f) = py_obj.extract::<f64>() {
            if let Some(n) = serde_json::Number::from_f64(f) {
                return Ok(JsonValue::Number(n));
            }
        }
        
        if let Ok(b) = py_obj.extract::<bool>() {
            return Ok(JsonValue::Bool(b));
        }
        
        // Check if it's None
        if py_obj.is_none() {
            return Ok(JsonValue::Null);
        }
        
        // Try dict
        if let Ok(dict) = py_obj.downcast::<PyDict>() {
            return Self::dict_to_json(dict);
        }
        
        // Try list
        if let Ok(list) = py_obj.downcast::<PyList>() {
            return Self::list_to_json(list);
        }
        
        // Fallback to string representation
        Ok(JsonValue::String(py_obj.to_string()))
    }

    /// Convert a JSON value to a Rust type
    pub fn json_to_type<T>(json: JsonValue) -> MemoryAnalysisResult<T> 
    where
        T: for<'de> Deserialize<'de>,
    {
        serde_json::from_value(json)
            .map_err(|e| MemoryAnalysisError::SerializationError(e.to_string()))
    }
}

/// Trait for types that can be converted to/from JSON
pub trait JsonSerializable: Serialize + for<'de> Deserialize<'de> {
    /// Convert to JSON string
    fn to_json(&self) -> MemoryAnalysisResult<String> {
        serde_json::to_string(self)
            .map_err(|e| MemoryAnalysisError::SerializationError(e.to_string()))
    }

    /// Convert to pretty-printed JSON string
    fn to_json_pretty(&self) -> MemoryAnalysisResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| MemoryAnalysisError::SerializationError(e.to_string()))
    }

    /// Parse from JSON string
    fn from_json(json: &str) -> MemoryAnalysisResult<Self> 
    where
        Self: Sized,
    {
        serde_json::from_str(json)
            .map_err(|e| MemoryAnalysisError::SerializationError(e.to_string()))
    }
}

// Implement JsonSerializable for common types
impl JsonSerializable for VersionInfo {}
impl JsonSerializable for PluginInfo {}
impl JsonSerializable for DumpMetadata {}
impl JsonSerializable for KeyValue {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_result_success() {
        let metadata = AnalysisMetadata::new(
            "test_plugin".to_string(),
            "/tmp/test.raw".to_string(),
        );
        
        let result: AnalysisResult<Vec<String>> = AnalysisResult::success(
            vec!["item1".to_string(), "item2".to_string()],
            metadata,
        );
        
        assert!(result.success);
        assert!(result.data.is_some());
        assert!(result.error.is_none());
    }

    #[test]
    fn test_analysis_result_failure() {
        let metadata = AnalysisMetadata::new(
            "test_plugin".to_string(),
            "/tmp/test.raw".to_string(),
        );
        
        let result: AnalysisResult<Vec<String>> = AnalysisResult::failure(
            "Test error".to_string(),
            metadata,
        );
        
        assert!(!result.success);
        assert!(result.data.is_none());
        assert!(result.error.is_some());
    }

    #[test]
    fn test_analysis_result_to_json() {
        let metadata = AnalysisMetadata::new(
            "test_plugin".to_string(),
            "/tmp/test.raw".to_string(),
        );
        
        let result: AnalysisResult<Vec<String>> = AnalysisResult::success(
            vec!["item1".to_string()],
            metadata,
        );
        
        let json = result.to_json();
        assert!(json.is_ok());
        
        let json_str = json.unwrap();
        assert!(json_str.contains("\"success\":true"));
        assert!(json_str.contains("\"data\""));
    }

    #[test]
    fn test_version_info_serialization() {
        let version = VersionInfo {
            rust_bridge_version: "0.1.0".to_string(),
            volatility_version: "2.26.2".to_string(),
            python_version: "3.12.11".to_string(),
        };
        
        let json = version.to_json();
        assert!(json.is_ok());
        
        let parsed: MemoryAnalysisResult<VersionInfo> = VersionInfo::from_json(&json.unwrap());
        assert!(parsed.is_ok());
        
        let parsed_version = parsed.unwrap();
        assert_eq!(parsed_version.rust_bridge_version, "0.1.0");
    }

    #[test]
    fn test_metadata_with_duration() {
        let metadata = AnalysisMetadata::new(
            "test_plugin".to_string(),
            "/tmp/test.raw".to_string(),
        ).with_duration(150);
        
        assert_eq!(metadata.duration_ms, 150);
        assert_eq!(metadata.plugin_name, "test_plugin");
    }

    #[test]
    fn test_plugin_info_serialization() {
        let plugin = PluginInfo {
            name: "windows.pslist.PsList".to_string(),
            description: Some("List processes".to_string()),
            version: Some("1.0".to_string()),
            supported_platforms: vec!["windows".to_string()],
        };
        
        let json = plugin.to_json_pretty();
        assert!(json.is_ok());
        assert!(json.unwrap().contains("windows.pslist.PsList"));
    }
}
