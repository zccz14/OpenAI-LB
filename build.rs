use std::{path::Path, process::Command};

fn main() {
    for path in [
        "web/src",
        "web/index.html",
        "web/package.json",
        "web/package-lock.json",
        "web/vite.config.ts",
        "web/tsconfig.json",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    if !Path::new("web/node_modules").exists() {
        panic!("web dependencies are missing; run `cd web && npm ci` before Cargo");
    }
    let status = Command::new("npm")
        .args(["run", "build"])
        .current_dir("web")
        .status()
        .expect("failed to start npm");
    assert!(status.success(), "web production build failed");
}
