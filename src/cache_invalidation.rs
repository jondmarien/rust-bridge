use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// Configuration for cache invalidation
#[derive(Clone, Debug)]
pub struct InvalidationConfig {
    /// Enable automatic invalidation on file changes
    pub enable_file_monitoring: bool,
    /// Debounce duration in milliseconds
    pub debounce_ms: u64,
}

impl Default for InvalidationConfig {
    fn default() -> Self {
        Self {
            enable_file_monitoring: true,
            debounce_ms: 100,
        }
    }
}

/// Event triggered when cache invalidation occurs
#[derive(Clone, Debug)]
pub struct InvalidationEvent {
    /// File path that triggered invalidation
    pub file_path: PathBuf,
    /// Reason for invalidation
    pub reason: String,
    /// When invalidation occurred
    pub timestamp: SystemTime,
}

/// Tracks file metadata for change detection
#[derive(Clone, Debug)]
struct FileMetadata {
    /// Size + modification time hash
    hash: u64,
    /// When we last checked this file
    last_checked: SystemTime,
}

/// File change monitor with invalidation tracking
pub struct CacheInvalidationMonitor {
    #[allow(dead_code)]
    config: InvalidationConfig,
    files: Arc<Mutex<HashMap<PathBuf, FileMetadata>>>,
    invalidation_count: Arc<Mutex<u64>>,
}

impl CacheInvalidationMonitor {
    /// Create a new cache invalidation monitor
    pub fn new(config: InvalidationConfig) -> Self {
        Self {
            config,
            files: Arc::new(Mutex::new(HashMap::new())),
            invalidation_count: Arc::new(Mutex::new(0)),
        }
    }

    /// Start monitoring a file for changes
    ///
    /// # Arguments
    /// * `file_path` - Path to the file to monitor
    ///
    /// # Errors
    /// Returns error if file cannot be accessed
    pub fn watch_file(&self, file_path: &Path) -> Result<(), String> {
        if !file_path.exists() {
            return Err(format!("File does not exist: {:?}", file_path));
        }

        let hash = Self::calculate_file_hash(file_path)?;
        let metadata = FileMetadata {
            hash,
            last_checked: SystemTime::now(),
        };

        let mut files = self
            .files
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?;
        files.insert(file_path.to_path_buf(), metadata);

        Ok(())
    }

    /// Stop monitoring a file
    pub fn unwatch_file(&self, file_path: &Path) -> Result<(), String> {
        let mut files = self
            .files
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?;
        files.remove(file_path);
        Ok(())
    }

    /// Check if a file has changed
    ///
    /// # Returns
    /// `Ok(true)` if file has changed, `Ok(false)` if unchanged or not watched
    pub fn check_file_changed(&self, file_path: &Path) -> Result<bool, String> {
        let mut files = self
            .files
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?;

        if let Some(metadata) = files.get_mut(file_path) {
            let current_hash = Self::calculate_file_hash(file_path)?;

            if current_hash != metadata.hash {
                metadata.hash = current_hash;
                metadata.last_checked = SystemTime::now();
                return Ok(true);
            }

            metadata.last_checked = SystemTime::now();
            Ok(false)
        } else {
            Ok(false) // Not being watched
        }
    }

    /// Validate all monitored files
    ///
    /// # Returns
    /// A vector of files that have changed
    pub fn validate_all_files(&self) -> Result<Vec<PathBuf>, String> {
        // Collect file paths first to avoid holding lock during checks
        let file_paths: Vec<PathBuf> = {
            let files = self
                .files
                .lock()
                .map_err(|e| format!("Lock error: {}", e))?;
            files.keys().cloned().collect()
        };

        let mut changed = Vec::new();

        for file_path in file_paths {
            if self.check_file_changed(&file_path)? {
                changed.push(file_path);
            }
        }

        Ok(changed)
    }

    /// Get list of monitored files
    pub fn get_watched_files(&self) -> Result<Vec<PathBuf>, String> {
        let files = self
            .files
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?;
        Ok(files.keys().cloned().collect())
    }

    /// Get invalidation event count
    pub fn get_invalidation_count(&self) -> Result<u64, String> {
        let count = self
            .invalidation_count
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?;
        Ok(*count)
    }

    /// Increment invalidation counter
    pub fn increment_invalidation_count(&self) -> Result<(), String> {
        let mut count = self
            .invalidation_count
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?;
        *count += 1;
        Ok(())
    }

    /// Calculate file hash for change detection
    fn calculate_file_hash(file_path: &Path) -> Result<u64, String> {
        std::fs::metadata(file_path)
            .map_err(|e| format!("Cannot read file metadata: {}", e))
            .and_then(|metadata| {
                let size = metadata.len();

                let mtime = metadata
                    .modified()
                    .map_err(|e| format!("Cannot read modification time: {}", e))?;

                let mtime_secs = mtime
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_err(|e| format!("Time error: {}", e))?
                    .as_secs();

                // Combine size and mtime into a hash
                Ok((size.wrapping_mul(397)) ^ mtime_secs)
            })
    }

    /// Clear all monitored files
    pub fn clear_all(&self) -> Result<(), String> {
        let mut files = self
            .files
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?;
        files.clear();
        Ok(())
    }
}

impl Default for CacheInvalidationMonitor {
    fn default() -> Self {
        Self::new(InvalidationConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_watch_file() -> Result<(), String> {
        let mut temp_file = NamedTempFile::new().map_err(|e| e.to_string())?;
        temp_file.write_all(b"test").map_err(|e| e.to_string())?;

        let monitor = CacheInvalidationMonitor::default();
        monitor.watch_file(temp_file.path())?;

        let watched = monitor.get_watched_files()?;
        assert_eq!(watched.len(), 1);
        assert_eq!(watched[0], temp_file.path());

        Ok(())
    }

    #[test]
    fn test_detect_file_change() -> Result<(), String> {
        let mut temp_file = NamedTempFile::new().map_err(|e| e.to_string())?;
        let file_path = temp_file.path().to_path_buf();
        temp_file.write_all(b"test").map_err(|e| e.to_string())?;
        temp_file.flush().map_err(|e| e.to_string())?;

        let monitor = CacheInvalidationMonitor::default();
        monitor.watch_file(&file_path)?;

        // Initially no change
        let changed = monitor.check_file_changed(&file_path)?;
        assert!(!changed);

        // Modify file by writing to the same file handle
        std::thread::sleep(std::time::Duration::from_millis(100));
        temp_file
            .write_all(b"modified")
            .map_err(|e| e.to_string())?;
        temp_file.flush().map_err(|e| e.to_string())?;

        // Check again - should detect change
        let changed = monitor.check_file_changed(&file_path)?;
        assert!(changed);

        Ok(())
    }

    #[test]
    fn test_unwatch_file() -> Result<(), String> {
        let mut temp_file = NamedTempFile::new().map_err(|e| e.to_string())?;
        temp_file.write_all(b"test").map_err(|e| e.to_string())?;

        let monitor = CacheInvalidationMonitor::default();
        monitor.watch_file(temp_file.path())?;

        monitor.unwatch_file(temp_file.path())?;

        let watched = monitor.get_watched_files()?;
        assert_eq!(watched.len(), 0);

        Ok(())
    }

    #[test]
    fn test_invalidation_counter() -> Result<(), String> {
        let monitor = CacheInvalidationMonitor::default();

        assert_eq!(monitor.get_invalidation_count()?, 0);

        monitor.increment_invalidation_count()?;
        assert_eq!(monitor.get_invalidation_count()?, 1);

        monitor.increment_invalidation_count()?;
        assert_eq!(monitor.get_invalidation_count()?, 2);

        Ok(())
    }

    #[test]
    fn test_clear_all() -> Result<(), String> {
        let mut temp_file = NamedTempFile::new().map_err(|e| e.to_string())?;
        temp_file.write_all(b"test").map_err(|e| e.to_string())?;

        let monitor = CacheInvalidationMonitor::default();
        monitor.watch_file(temp_file.path())?;

        let watched = monitor.get_watched_files()?;
        assert_eq!(watched.len(), 1);

        monitor.clear_all()?;

        let watched = monitor.get_watched_files()?;
        assert_eq!(watched.len(), 0);

        Ok(())
    }
}
