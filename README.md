# Rust-Python Bridge for Volatility 3

High-performance FFI bridge between PowerShell/C# and Volatility 3 using PyO3.

> **Repository:** This is a Git submodule of [MemoryAnalysis.Powershell](https://github.com/jondmarien/MemoryAnalysis.Powershell.git)  
> **Standalone:** <https://github.com/jondmarien/rust-bridge.git>

## Overview

This Rust library provides a high-performance bridge to Volatility 3 for memory forensics. It embeds Python using PyO3 and exposes C-compatible FFI functions that can be called from C#/PowerShell.

**Performance Target:** < 100ms overhead per operation ✅

## Architecture

```text
┌─────────────────────────────────────┐
│   C# / PowerShell (P/Invoke)        │
└─────────────────────────────────────┘
                 │
                 ▼ FFI (C ABI)
┌─────────────────────────────────────┐
│   Rust Bridge (this crate)          │
│   - FFI exports (#[no_mangle])      │
│   - Python interpreter management   │
│   - PyO3 GIL handling               │
│   - JSON serialization              │
└─────────────────────────────────────┘
                 │
                 ▼ PyO3
┌─────────────────────────────────────┐
│   Python 3.12 + Volatility 3        │
│   - Memory forensics plugins        │
│   - TreeGrid result extraction      │
└─────────────────────────────────────┘
```

## Features

### ✅ Implemented (Phase 1)

- **Process Listing** (`windows.pslist.PsList`)
  - FFI export: `rust_bridge_list_processes()`
  - Returns: JSON array of `ProcessInfo`

- **Command Line Extraction** (`windows.cmdline.CmdLine`)
  - FFI export: `rust_bridge_get_command_lines()`
  - Returns: JSON array of `CommandLineInfo`

- **DLL Listing** (`windows.dlllist.DllList`)
  - FFI export: `rust_bridge_list_dlls(dump_path, pid)`
  - Supports optional PID filtering
  - Returns: JSON array of `DllInfo`

### 🔄 In Progress

- **Network Connections** (`windows.netscan.NetScan`)
- **Malware Detection** (`windows.malfind.Malfind`, `windows.psxview.PsXview`)

## Building

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test

# Check code
cargo clippy
```

**Build Output:** `target/release/rust_bridge.dll` (Windows)

## FFI Exports

All FFI functions follow the C ABI convention and return JSON strings as `*mut c_char`.

### Memory Management

```rust
// Caller must free returned strings
#[no_mangle]
pub extern "C" fn rust_bridge_free_string(ptr: *mut c_char);
```

### Version Information

```rust
#[no_mangle]
pub extern "C" fn rust_bridge_get_version() -> *mut c_char;
```

Returns:

```json
{
  "rust_bridge_version": "0.1.0",
  "volatility_version": "2.26.2",
  "python_version": "3.12.11"
}
```

### Process Listing

```rust
#[no_mangle]
pub extern "C" fn rust_bridge_list_processes(dump_path: *const c_char) -> *mut c_char;
```

Returns:

```json
[
  {
    "pid": 4,
    "ppid": 0,
    "name": "System",
    "offset": "0xfa8000000000",
    "threads": 226,
    "handles": 9876,
    "create_time": "2024-01-15 12:34:56"
  }
]
```

### Command Line Extraction

```rust
#[no_mangle]
pub extern "C" fn rust_bridge_get_command_lines(dump_path: *const c_char) -> *mut c_char;
```

Returns:

```json
[
  {
    "pid": 1234,
    "process_name": "powershell.exe",
    "command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass"
  }
]
```

### DLL Listing

```rust
#[no_mangle]
pub extern "C" fn rust_bridge_list_dlls(
    dump_path: *const c_char,
    pid: u32  // 0 = all processes
) -> *mut c_char;
```

Returns:

```json
[
  {
    "pid": 1234,
    "process_name": "explorer.exe",
    "base_address": "0x7ff8a0000000",
    "size": 1048576,
    "dll_name": "kernel32.dll",
    "dll_path": "C:\\Windows\\System32\\kernel32.dll"
  }
]
```

## Module Structure

```tree
src/
├── lib.rs                  # FFI exports and initialization
├── python_manager.rs       # Python interpreter lifecycle
├── volatility.rs           # Volatility framework integration
├── process_analysis.rs     # Memory analysis functions
├── types.rs                # Data structures and serialization
└── error.rs                # Error handling
```

## Data Types

### ProcessInfo

- `pid: u32` - Process ID
- `ppid: u32` - Parent process ID
- `name: String` - Process name
- `offset: String` - Memory offset (hex)
- `threads: u32` - Thread count
- `handles: u32` - Handle count
- `create_time: String` - Creation timestamp

### CommandLineInfo

- `pid: u32` - Process ID
- `process_name: String` - Process name
- `command_line: String` - Full command line

### DllInfo

- `pid: u32` - Process ID
- `process_name: String` - Process name
- `base_address: String` - Base address (hex)
- `size: u64` - DLL size in bytes
- `dll_name: String` - DLL filename
- `dll_path: String` - Full path to DLL

## Python Integration

### Volatility Context Flow

Critical pattern for all plugins:

```rust
// 1. Create Context
let ctx = contexts.Context();

// 2. Set dump location
ctx.config[`automagic.LayerStacker.single_location`] = file_url;

// 3. Get automagics
let automagics = automagic.available(ctx);

// 4. Choose automagics for plugin
let plugin_list = automagic.choose_automagic(automagics, plugin_class);

// 5. RUN AUTOMAGICS (critical!)
automagic.run(plugin_list, ctx, plugin_class, base_config_path, None);

// 6. Construct plugin
let plugin = plugins.construct_plugin(...);

// 7. Run plugin
let treegrid = plugin.run();

// 8. Extract results with visitor
treegrid.populate(visitor, results);
```

**Important:** Step 5 (automagics.run) is required for symbol resolution and layer stacking!

## Debug Logging

Set environment variable to enable debug logging:

```powershell
$env:RUST_BRIDGE_DEBUG = "1"
```

Logs are written to: `J:\projects\personal-projects\MemoryAnalysis\rust-bridge-debug.log`

## Error Handling

All errors are logged and returned as JSON:

```json
{
  "success": false,
  "error": "Failed to load memory dump: File not found",
  "metadata": {
    "plugin": "list_processes",
    "dump_path": "memory.raw"
  }
}
```

## Performance Notes

- **PyO3 GIL:** Properly released between operations
- **Memory:** JSON strings must be freed by caller using `rust_bridge_free_string()`
- **Parallel:** Multiple dumps can be processed in parallel (separate Python interpreters)
- **Overhead:** < 100ms per operation (measured)

## Dependencies

```toml
[dependencies]
pyo3 = { version = "0.23.3", features = ["auto-initialize"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
anyhow = "1.0"
```

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Test specific module
cargo test python_manager
```

## C# Integration

Example P/Invoke declarations:

```csharp
[DllImport("rust_bridge.dll", CallingConvention = CallingConvention.Cdecl)]
private static extern IntPtr rust_bridge_list_processes(
    [MarshalAs(UnmanagedType.LPStr)] string dumpPath
);

[DllImport("rust_bridge.dll", CallingConvention = CallingConvention.Cdecl)]
private static extern void rust_bridge_free_string(IntPtr ptr);
```

## Contributing

1. Follow Rust conventions and `cargo clippy` recommendations
2. Add tests for new FFI functions
3. Update this README with new exports
4. Ensure < 100ms overhead target is maintained

## License

Copyright (c) 2025. All rights reserved.

## Links

- **Main Project:** [MemoryAnalysis.Powershell](https://github.com/jondmarien/MemoryAnalysis.Powershell.git)
- **Volatility 3:** <https://github.com/volatilityfoundation/volatility3>
- **PyO3:** <https://github.com/PyO3/pyo3>
