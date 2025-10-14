fn main() {
    // PyO3 will use the Python interpreter from PYO3_PYTHON environment variable
    // or auto-discover from the system
    
    println!("cargo:rerun-if-env-changed=PYO3_PYTHON");
    println!("cargo:rerun-if-changed=build.rs");
    
    // Note: For runtime, users should set PYTHONHOME to point to the base Python installation
    // Example: C:\\Users\\nucle\\AppData\\Roaming\\uv\\python\\cpython-3.12.11-windows-x86_64-none
    // The rust library will add the venv's site-packages to sys.path at runtime
}
