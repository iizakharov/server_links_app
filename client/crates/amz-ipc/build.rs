//! AMZ_BUILD_ID: hash of the helper/tunnel sources, so the app notices an outdated installed helper.
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;

fn hash_dir(dir: &Path, h: &mut DefaultHasher) {
    let mut entries: Vec<_> = std::fs::read_dir(dir).into_iter().flatten().flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            hash_dir(&p, h);
        } else if p.extension().is_some_and(|e| e == "rs" || e == "go") {
            println!("cargo:rerun-if-changed={}", p.display());
            std::fs::read(&p).unwrap_or_default().hash(h);
        }
    }
}

fn main() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut h = DefaultHasher::new();
    for c in ["amz-ipc/src", "amz-helper/src", "amz-tunnel/src", "amz-core/src", "../go/libawg"] {
        hash_dir(&crates.join(c), &mut h);
    }
    println!("cargo:rustc-env=AMZ_BUILD_ID={:08x}", h.finish() as u32);
}
