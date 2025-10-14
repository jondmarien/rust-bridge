use std::env;

fn main() {
    // Configure PyO3 to use the virtual environment's Python
    // This ensures we use the same Python that has Volatility3 installed
    
    let venv_path = env::var("VIRTUAL_ENV")
        .or_else(|_| -> Result<String, env::VarError> {
            // If not in venv, try to find it relative to the project
            let manifest_dir = env::var("CARGO_MANIFEST_DIR")?;
            let venv = format!("{}/../volatility-env", manifest_dir);
            Ok(venv)
        })
        .expect("Could not find Python virtual environment");
    
    println!("cargo:rerun-if-env-changed=VIRTUAL_ENV");
    println!("cargo:rerun-if-changed=build.rs");
    
    // Set Python home for PyO3
    println!("cargo:rustc-env=PYTHON_HOME={}", venv_path);
}
