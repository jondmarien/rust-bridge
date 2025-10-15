use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;

// Note: These benchmarks require a test memory dump file
// Place a small test dump at: test_data/mini_dump.raw

fn benchmark_json_serialization(c: &mut Criterion) {
    use rust_bridge::ProcessInfo;

    let process = ProcessInfo {
        pid: 1234,
        ppid: 100,
        name: "test.exe".to_string(),
        offset: "0xFFFF800012345678".to_string(),
        threads: 4,
        handles: 100,
        create_time: "2025-01-01 12:00:00".to_string(),
    };

    c.bench_function("json_serialize_process_info", |b| {
        b.iter(|| serde_json::to_string(black_box(&process)).unwrap());
    });
}

fn benchmark_json_deserialization(c: &mut Criterion) {
    use rust_bridge::ProcessInfo;

    let json = r#"{
        "pid": 1234,
        "ppid": 100,
        "name": "test.exe",
        "offset": "0xFFFF800012345678",
        "threads": 4,
        "handles": 100,
        "create_time": "2025-01-01 12:00:00"
    }"#;

    c.bench_function("json_deserialize_process_info", |b| {
        b.iter(|| serde_json::from_str::<ProcessInfo>(black_box(json)).unwrap());
    });
}

fn benchmark_multiple_processes_serialization(c: &mut Criterion) {
    use rust_bridge::ProcessInfo;

    // Create a vector of processes
    let processes: Vec<ProcessInfo> = (0..100)
        .map(|i| ProcessInfo {
            pid: i,
            ppid: i / 2,
            name: format!("process_{}.exe", i),
            offset: format!("0x{:X}", 0xFFFF800012345678u64 + (i as u64 * 0x1000)),
            threads: 4,
            handles: 100,
            create_time: "2025-01-01 12:00:00".to_string(),
        })
        .collect();

    c.bench_function("json_serialize_100_processes", |b| {
        b.iter(|| serde_json::to_string(black_box(&processes)).unwrap());
    });
}

fn benchmark_string_allocation(c: &mut Criterion) {
    use std::ffi::CString;

    c.bench_function("cstring_allocation", |b| {
        b.iter(|| CString::new(black_box("test string for FFI")).unwrap());
    });
}

fn benchmark_large_json_serialization(c: &mut Criterion) {
    use rust_bridge::ProcessInfo;

    // Simulate serializing large process list (similar to 830 processes)
    let mut group = c.benchmark_group("large_json");
    group.measurement_time(Duration::from_secs(10));

    for size in [10, 100, 500, 1000].iter() {
        let processes: Vec<ProcessInfo> = (0..*size)
            .map(|i| ProcessInfo {
                pid: i,
                ppid: i / 2,
                name: format!("process_{}.exe", i),
                offset: format!("0x{:X}", 0xFFFF800012345678u64 + (i as u64 * 0x1000)),
                threads: (i % 20) + 1,
                handles: (i % 200) + 50,
                create_time: "2025-01-01 12:00:00".to_string(),
            })
            .collect();

        group.bench_with_input(BenchmarkId::from_parameter(size), &processes, |b, procs| {
            b.iter(|| serde_json::to_string(black_box(procs)).unwrap());
        });
    }
    group.finish();
}

fn benchmark_error_creation(c: &mut Criterion) {
    use rust_bridge::error::MemoryAnalysisError;

    c.bench_function("error_creation", |b| {
        b.iter(|| MemoryAnalysisError::VolatilityError(black_box("Test error".to_string())));
    });
}

criterion_group!(
    benches,
    benchmark_json_serialization,
    benchmark_json_deserialization,
    benchmark_multiple_processes_serialization,
    benchmark_large_json_serialization,
    benchmark_string_allocation,
    benchmark_error_creation
);

criterion_main!(benches);
