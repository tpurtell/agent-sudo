fn main() {
    // The UI is built into web/dist by `npm run build`. Make sure the folder exists so
    // the service still compiles (and serves a placeholder) without a UI build.
    let dist = std::path::Path::new("web/dist");
    if !dist.join("index.html").exists() {
        std::fs::create_dir_all(dist).expect("create web/dist");
        std::fs::write(
            dist.join("index.html"),
            "<!doctype html><meta charset=utf-8><title>agent-sudo</title><p>The web UI has not been built. Run <code>npm ci && npm run build</code> in service/web.</p>",
        )
        .expect("write placeholder");
    }
    println!("cargo:rerun-if-changed=web/dist");
}
