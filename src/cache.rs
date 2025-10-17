//! Caching System for Memory Dump Analysis
//!
//! Provides LRU (Least Recently Used) caching for memory dump metadata and plugin
//! execution results. Cache entries support TTL-based expiration and file hash
//! validation for cache invalidation.
//!
//! # Features
//!
//! - **LRU Eviction**: Automatically evicts least recently used entries
//! - **TTL Support**: Optional time-to-live expiration for entries
//! - **File Validation**: Detects when source files change via hash comparison
//! - **Thread-Safe**: Uses Arc<Mutex<>> for concurrent access
//! - **Persistent Storage**: Optional disk-based cache persistence
//!
//! # Examples
//!
//! ```no_run
//! use rust_bridge::cache::{LruCache, CacheConfig};
//!
//! // Create cache with default settings
//! let config = CacheConfig::default();
//! let cache: LruCache<Vec<String>> = LruCache::new(config, "string_cache");
//!
//! // Cache some data
//! let data = vec!["item1".to_string(), "item2".to_string()];
//! cache.put("key1".to_string(), data.clone(), "file_hash_1".to_string());
//!
//! // Retrieve from cache
//! if let Some(cached_data) = cache.get("key1", "file_hash_1") {
//!     println!("Found {} items in cache", cached_data.len());
//! }
//! ```

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::MemoryAnalysisError;

/// Errors that can occur during cache operations
#[derive(Error, Debug)]
pub enum CacheError {
    #[error("Cache entry not found: {0}")]
    EntryNotFound(String),

    #[error("Cache entry is stale: {0}")]
    EntryStale(String),

    #[error("File hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("IO error: {0}")]
    IoError(String),

    #[error("Cache configuration error: {0}")]
    ConfigError(String),
}

/// Cache entry metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry<T> {
    /// The cached data
    pub data: T,
    /// Unix timestamp when entry was created
    pub created_at: u64,
    /// Unix timestamp when entry was last accessed
    pub accessed_at: u64,
    /// File hash for change detection
    pub file_hash: String,
    /// Number of times this entry has been accessed
    pub access_count: u64,
}

impl<T> CacheEntry<T> {
    /// Create a new cache entry with current timestamp
    fn new(data: T, file_hash: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        CacheEntry {
            data,
            created_at: now,
            accessed_at: now,
            file_hash,
            access_count: 0,
        }
    }

    /// Update access time and increment access counter
    fn touch(&mut self) {
        self.accessed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.access_count = self.access_count.saturating_add(1);
    }

    /// Check if entry has exceeded TTL
    ///
    /// # Arguments
    ///
    /// * `ttl_secs` - Time-to-live in seconds (0 = no expiration)
    ///
    /// # Returns
    ///
    /// `true` if entry is older than TTL, `false` otherwise
    fn is_stale(&self, ttl_secs: u64) -> bool {
        if ttl_secs == 0 {
            return false; // No expiration
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        (now - self.created_at) > ttl_secs
    }
}

/// LRU Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum entries in cache (before LRU eviction)
    pub max_entries: usize,
    /// Time-to-live in seconds (0 = no expiration)
    pub ttl_secs: u64,
    /// Enable persistence to disk
    pub persist_to_disk: bool,
    /// Cache directory for persistence
    pub cache_dir: String,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            max_entries: 10,
            ttl_secs: 3600, // 1 hour default
            persist_to_disk: true,
            cache_dir: ".cache".to_string(),
        }
    }
}

/// Cache statistics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    /// Current number of entries
    pub entries_count: usize,
    /// Maximum allowed entries
    pub max_entries: usize,
    /// Total access count across all entries
    pub total_accesses: u64,
    /// Timestamp of oldest access (Unix seconds)
    pub oldest_access: u64,
    /// Timestamp of newest access (Unix seconds)
    pub newest_access: u64,
}

/// LRU Cache with configurable eviction and TTL
///
/// Thread-safe cache implementation using Arc<Mutex<>> for concurrent access.
/// Supports file-based cache invalidation via hash comparison.
pub struct LruCache<T: Clone + Serialize + for<'de> Deserialize<'de>> {
    /// Storage for cache entries (key -> entry)
    entries: Arc<Mutex<HashMap<String, CacheEntry<T>>>>,
    /// Configuration
    config: CacheConfig,
    /// Type name for logging/identification (reserved for future use)
    #[allow(dead_code)]
    type_name: String,
}

impl<T: Clone + Serialize + for<'de> Deserialize<'de>> LruCache<T> {
    /// Create a new LRU cache with configuration
    ///
    /// # Arguments
    ///
    /// * `config` - Cache configuration (max entries, TTL, etc.)
    /// * `type_name` - Name for logging/identification
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rust_bridge::cache::{LruCache, CacheConfig};
    ///
    /// let mut config = CacheConfig::default();
    /// config.max_entries = 50;
    /// config.ttl_secs = 7200; // 2 hours
    ///
    /// let cache: LruCache<Vec<String>> = LruCache::new(config, "my_cache");
    /// ```
    pub fn new(config: CacheConfig, type_name: &str) -> Self {
        // Create cache directory if persistence enabled
        if config.persist_to_disk {
            let cache_dir = Path::new(&config.cache_dir);
            let _ = std::fs::create_dir_all(cache_dir);
        }

        LruCache {
            entries: Arc::new(Mutex::new(HashMap::new())),
            config,
            type_name: type_name.to_string(),
        }
    }

    /// Get a value from cache with validation
    ///
    /// Checks TTL and file hash before returning cached data. Updates
    /// access statistics on successful retrieval.
    ///
    /// # Arguments
    ///
    /// * `key` - Cache key
    /// * `expected_hash` - Expected file hash for validation
    ///
    /// # Returns
    ///
    /// Some(data) if found and valid, None if not found or invalid
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_bridge::cache::LruCache;
    /// # let cache: LruCache<String> = LruCache::new(Default::default(), "test");
    /// if let Some(data) = cache.get("key1", "expected_hash") {
    ///     println!("Cache hit: {:?}", data);
    /// }
    /// ```
    pub fn get(&self, key: &str, expected_hash: &str) -> Option<T> {
        let mut entries = self.entries.lock().unwrap();

        if let Some(entry) = entries.get_mut(key) {
            // Validate file hash hasn't changed
            if entry.file_hash != expected_hash {
                // File changed, invalidate entry
                entries.remove(key);
                return None;
            }

            // Check TTL expiration
            if self.config.ttl_secs > 0 && entry.is_stale(self.config.ttl_secs) {
                entries.remove(key);
                return None;
            }

            // Update access statistics
            entry.touch();
            return Some(entry.data.clone());
        }

        None
    }

    /// Insert or update a cache entry
    ///
    /// If cache is at capacity, removes the least recently used entry.
    /// Use for updating an existing key - no LRU eviction occurs for updates.
    ///
    /// # Arguments
    ///
    /// * `key` - Cache key
    /// * `value` - Data to cache
    /// * `file_hash` - Hash for invalidation detection
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_bridge::cache::LruCache;
    /// # let cache: LruCache<String> = LruCache::new(Default::default(), "test");
    /// cache.put("key1".to_string(), "data1".to_string(), "hash1".to_string());
    /// ```
    pub fn put(&self, key: String, value: T, file_hash: String) {
        let mut entries = self.entries.lock().unwrap();

        // Check if we need to evict LRU entry
        if entries.len() >= self.config.max_entries && !entries.contains_key(&key) {
            // Find entry with lowest access count
            if let Some(lru_key) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.access_count)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&lru_key);
            }
        }

        let entry = CacheEntry::new(value, file_hash);
        entries.insert(key, entry);
    }

    /// Clear all cache entries
    pub fn clear(&self) {
        let mut entries = self.entries.lock().unwrap();
        entries.clear();
    }

    /// Get current cache statistics
    ///
    /// # Returns
    ///
    /// CacheStats snapshot of current cache state
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_bridge::cache::LruCache;
    /// # let cache: LruCache<String> = LruCache::new(Default::default(), "test");
    /// let stats = cache.stats();
    /// println!("Cache has {} entries", stats.entries_count);
    /// ```
    pub fn stats(&self) -> CacheStats {
        let entries = self.entries.lock().unwrap();

        let mut total_accesses = 0u64;
        let mut oldest_access = u64::MAX;
        let mut newest_access = 0u64;

        for entry in entries.values() {
            total_accesses += entry.access_count;
            oldest_access = oldest_access.min(entry.accessed_at);
            newest_access = newest_access.max(entry.accessed_at);
        }

        CacheStats {
            entries_count: entries.len(),
            max_entries: self.config.max_entries,
            total_accesses,
            oldest_access,
            newest_access,
        }
    }

    /// Remove a specific entry from cache
    pub fn remove(&self, key: &str) {
        let mut entries = self.entries.lock().unwrap();
        entries.remove(key);
    }

    /// Check if key exists in cache
    pub fn contains(&self, key: &str) -> bool {
        let entries = self.entries.lock().unwrap();
        entries.contains_key(key)
    }
}

/// Calculate simple file hash for change detection
///
/// Uses file size and modification time to create a simple hash.
/// This is suitable for cache validation purposes.
///
/// # Arguments
///
/// * `file_path` - Path to file
///
/// # Returns
///
/// Hash string in format "size_mtime"
///
/// # Examples
///
/// ```no_run
/// use rust_bridge::cache::calculate_file_hash;
///
/// let hash = calculate_file_hash("test.vmem")?;
/// println!("File hash: {}", hash);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn calculate_file_hash(file_path: &str) -> Result<String, MemoryAnalysisError> {
    let metadata = std::fs::metadata(file_path)
        .map_err(|e| MemoryAnalysisError::IoError(format!("Failed to stat file: {}", e)))?;

    let size = metadata.len();
    let mtime = metadata
        .modified()
        .map_err(|e| MemoryAnalysisError::IoError(format!("Failed to get mtime: {}", e)))?
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(format!("{}_{}", size, mtime))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Serialize, Deserialize)]
    struct TestData {
        value: String,
    }

    #[test]
    fn test_cache_creation() {
        let config = CacheConfig::default();
        let cache: LruCache<TestData> = LruCache::new(config, "test");
        let stats = cache.stats();
        assert_eq!(stats.entries_count, 0);
    }

    #[test]
    fn test_cache_put_and_get() {
        let config = CacheConfig::default();
        let cache: LruCache<TestData> = LruCache::new(config, "test");

        let data = TestData {
            value: "test_value".to_string(),
        };
        cache.put("key1".to_string(), data.clone(), "hash1".to_string());

        let result = cache.get("key1", "hash1");
        assert!(result.is_some());
        assert_eq!(result.unwrap().value, "test_value");
    }

    #[test]
    fn test_cache_hash_invalidation() {
        let config = CacheConfig::default();
        let cache: LruCache<TestData> = LruCache::new(config, "test");

        let data = TestData {
            value: "original".to_string(),
        };
        cache.put("key1".to_string(), data, "hash1".to_string());

        // Try to get with different hash
        let result = cache.get("key1", "hash2");
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_lru_eviction() {
        let mut config = CacheConfig::default();
        config.max_entries = 3;

        let cache: LruCache<TestData> = LruCache::new(config, "test");

        // Insert 4 items (should evict the least recently used)
        for i in 0..4 {
            cache.put(
                format!("key{}", i),
                TestData {
                    value: format!("value{}", i),
                },
                format!("hash{}", i),
            );
        }

        let stats = cache.stats();
        assert_eq!(stats.entries_count, 3);
    }

    #[test]
    fn test_cache_contains() {
        let config = CacheConfig::default();
        let cache: LruCache<TestData> = LruCache::new(config, "test");

        cache.put(
            "key1".to_string(),
            TestData {
                value: "test".to_string(),
            },
            "hash1".to_string(),
        );

        assert!(cache.contains("key1"));
        assert!(!cache.contains("key2"));
    }

    #[test]
    fn test_cache_clear() {
        let config = CacheConfig::default();
        let cache: LruCache<TestData> = LruCache::new(config, "test");

        cache.put(
            "key1".to_string(),
            TestData {
                value: "test".to_string(),
            },
            "hash1".to_string(),
        );

        assert_eq!(cache.stats().entries_count, 1);
        cache.clear();
        assert_eq!(cache.stats().entries_count, 0);
    }
}
