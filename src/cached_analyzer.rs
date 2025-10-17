//! Cached Process Analysis
//!
//! Wraps the `ProcessAnalyzer` with LRU caching for improved performance
//! when analyzing the same memory dumps multiple times.
//!
//! # Features
//!
//! - **Automatic Caching**: Results from Volatility plugins are cached
//! - **Smart Invalidation**: File hash changes trigger cache invalidation
//! - **Configurable TTL**: Cache entries expire after configured time
//! - **Statistics**: Track cache hit/miss rates for performance monitoring
//!
//! # Examples
//!
//! ```no_run
//! use rust_bridge::cached_analyzer::{CachedProcessAnalyzer, AnalyzerConfig};
//! use rust_bridge::volatility::VolatilityContext;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = AnalyzerConfig::default();
//! let analyzer = CachedProcessAnalyzer::new(config)?;
//!
//! let context = VolatilityContext {
//!     dump_path: "memory.vmem".to_string(),
//! };
//!
//! // First call: Executes plugin and caches result
//! let processes1 = analyzer.list_processes_cached(&context)?;
//!
//! // Second call: Returns from cache
//! let processes2 = analyzer.list_processes_cached(&context)?;
//!
//! assert_eq!(processes1.len(), processes2.len());
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

use crate::cache::{calculate_file_hash, CacheConfig, LruCache};
use crate::process_analysis::{ProcessAnalyzer, ProcessInfo};
use crate::types::{CommandLineInfo, DllInfo, MalwareDetection, NetworkConnectionInfo};
use crate::volatility::VolatilityContext;

/// Configuration for cached analyzer
#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    /// Cache configuration
    pub cache_config: CacheConfig,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        let mut cache_config = CacheConfig::default();
        cache_config.max_entries = 20; // Reasonable default for process dumps
        cache_config.ttl_secs = 7200; // 2 hours
        cache_config.persist_to_disk = false; // Disable disk persistence by default

        AnalyzerConfig { cache_config }
    }
}

/// Cached process analyzer with LRU caching
///
/// Wraps `ProcessAnalyzer` to provide transparent caching of Volatility
/// plugin results. All caching is handled internally.
pub struct CachedProcessAnalyzer {
    /// Underlying analyzer
    analyzer: ProcessAnalyzer,
    /// Process list cache
    process_cache: Arc<LruCache<Vec<ProcessInfo>>>,
    /// Command line cache
    command_cache: Arc<LruCache<Vec<CommandLineInfo>>>,
    /// DLL list cache
    dll_cache: Arc<LruCache<Vec<DllInfo>>>,
    /// Network connections cache
    network_cache: Arc<LruCache<Vec<NetworkConnectionInfo>>>,
    /// Malware detections cache
    malware_cache: Arc<LruCache<Vec<MalwareDetection>>>,
}

impl CachedProcessAnalyzer {
    /// Create a new cached analyzer with configuration
    ///
    /// # Arguments
    ///
    /// * `config` - Analyzer configuration including cache settings
    ///
    /// # Returns
    ///
    /// A new `CachedProcessAnalyzer` or error if initialization fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rust_bridge::cached_analyzer::{CachedProcessAnalyzer, AnalyzerConfig};
    ///
    /// let config = AnalyzerConfig::default();
    /// let analyzer = CachedProcessAnalyzer::new(config)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(config: AnalyzerConfig) -> crate::MemoryAnalysisResult<Self> {
        let analyzer = ProcessAnalyzer::new()?;

        Ok(CachedProcessAnalyzer {
            analyzer,
            process_cache: Arc::new(LruCache::new(config.cache_config.clone(), "processes")),
            command_cache: Arc::new(LruCache::new(config.cache_config.clone(), "command_lines")),
            dll_cache: Arc::new(LruCache::new(config.cache_config.clone(), "dlls")),
            network_cache: Arc::new(LruCache::new(config.cache_config.clone(), "networks")),
            malware_cache: Arc::new(LruCache::new(config.cache_config.clone(), "malware")),
        })
    }

    /// List processes with caching
    ///
    /// Caches process list results with file hash validation for
    /// automatic invalidation on dump changes.
    ///
    /// # Arguments
    ///
    /// * `context` - Analysis context with dump path
    ///
    /// # Returns
    ///
    /// Process list or error
    pub fn list_processes_cached(
        &self,
        context: &VolatilityContext,
    ) -> crate::MemoryAnalysisResult<Vec<ProcessInfo>> {
        let file_hash = calculate_file_hash(&context.dump_path)?;
        let cache_key = format!("processes_{}", context.dump_path);

        // Try cache first
        if let Some(cached) = self.process_cache.get(&cache_key, &file_hash) {
            return Ok(cached);
        }

        // Cache miss: execute plugin
        let processes = self.analyzer.list_processes(context)?;

        // Store in cache
        self.process_cache
            .put(cache_key, processes.clone(), file_hash);

        Ok(processes)
    }

    /// Get command lines with caching
    pub fn get_command_lines_cached(
        &self,
        context: &VolatilityContext,
    ) -> crate::MemoryAnalysisResult<Vec<CommandLineInfo>> {
        let file_hash = calculate_file_hash(&context.dump_path)?;
        let cache_key = format!("cmdlines_{}", context.dump_path);

        if let Some(cached) = self.command_cache.get(&cache_key, &file_hash) {
            return Ok(cached);
        }

        let command_lines = self.analyzer.get_command_lines(context)?;
        self.command_cache
            .put(cache_key, command_lines.clone(), file_hash);

        Ok(command_lines)
    }

    /// List DLLs with caching
    pub fn list_dlls_cached(
        &self,
        context: &VolatilityContext,
        pid_filter: Option<u32>,
    ) -> crate::MemoryAnalysisResult<Vec<DllInfo>> {
        let file_hash = calculate_file_hash(&context.dump_path)?;
        let pid_str = pid_filter.map(|p| format!("_{}", p)).unwrap_or_default();
        let cache_key = format!("dlls_{}{}", context.dump_path, pid_str);

        if let Some(cached) = self.dll_cache.get(&cache_key, &file_hash) {
            return Ok(cached);
        }

        let dlls = self.analyzer.list_dlls(context, pid_filter)?;
        self.dll_cache.put(cache_key, dlls.clone(), file_hash);

        Ok(dlls)
    }

    /// Scan network connections with caching
    pub fn scan_network_connections_cached(
        &self,
        context: &VolatilityContext,
    ) -> crate::MemoryAnalysisResult<Vec<NetworkConnectionInfo>> {
        let file_hash = calculate_file_hash(&context.dump_path)?;
        let cache_key = format!("networks_{}", context.dump_path);

        if let Some(cached) = self.network_cache.get(&cache_key, &file_hash) {
            return Ok(cached);
        }

        let connections = self.analyzer.scan_network_connections(context)?;
        self.network_cache
            .put(cache_key, connections.clone(), file_hash);

        Ok(connections)
    }

    /// Detect malware with caching
    pub fn detect_malware_cached(
        &self,
        context: &VolatilityContext,
    ) -> crate::MemoryAnalysisResult<Vec<MalwareDetection>> {
        let file_hash = calculate_file_hash(&context.dump_path)?;
        let cache_key = format!("malware_{}", context.dump_path);

        if let Some(cached) = self.malware_cache.get(&cache_key, &file_hash) {
            return Ok(cached);
        }

        let detections = self.analyzer.detect_malware(context)?;
        self.malware_cache
            .put(cache_key, detections.clone(), file_hash);

        Ok(detections)
    }

    /// Clear all caches
    ///
    /// Useful when you know dumps have changed or to free memory.
    pub fn clear_all_caches(&self) {
        self.process_cache.clear();
        self.command_cache.clear();
        self.dll_cache.clear();
        self.network_cache.clear();
        self.malware_cache.clear();
    }

    /// Get cache statistics for all caches
    pub fn cache_stats(&self) -> CacheStatsCollection {
        CacheStatsCollection {
            processes: self.process_cache.stats(),
            command_lines: self.command_cache.stats(),
            dlls: self.dll_cache.stats(),
            network_connections: self.network_cache.stats(),
            malware_detections: self.malware_cache.stats(),
        }
    }
}

/// Collection of cache statistics from all caches
#[derive(Debug, Clone)]
pub struct CacheStatsCollection {
    pub processes: crate::cache::CacheStats,
    pub command_lines: crate::cache::CacheStats,
    pub dlls: crate::cache::CacheStats,
    pub network_connections: crate::cache::CacheStats,
    pub malware_detections: crate::cache::CacheStats,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_analyzer_creation() {
        let config = AnalyzerConfig::default();
        let analyzer = CachedProcessAnalyzer::new(config);
        assert!(analyzer.is_ok());
    }

    #[test]
    fn test_clear_all_caches() {
        let config = AnalyzerConfig::default();
        let analyzer = CachedProcessAnalyzer::new(config).unwrap();

        // Cache should be empty initially
        let stats = analyzer.cache_stats();
        assert_eq!(stats.processes.entries_count, 0);

        // Clear (should not panic)
        analyzer.clear_all_caches();

        let stats = analyzer.cache_stats();
        assert_eq!(stats.processes.entries_count, 0);
    }

    #[test]
    fn test_cache_stats_collection() {
        let config = AnalyzerConfig::default();
        let expected_max_entries = config.cache_config.max_entries;
        let analyzer = CachedProcessAnalyzer::new(config).unwrap();

        let stats = analyzer.cache_stats();
        assert_eq!(stats.processes.max_entries, expected_max_entries);
        assert_eq!(stats.command_lines.max_entries, expected_max_entries);
        assert_eq!(stats.dlls.max_entries, expected_max_entries);
        assert_eq!(stats.network_connections.max_entries, expected_max_entries);
        assert_eq!(stats.malware_detections.max_entries, expected_max_entries);
    }
}
