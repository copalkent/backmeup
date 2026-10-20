fn main() {
    // The Google OAuth client secret is compiled in with `option_env!`, and
    // cargo does not notice when an environment variable changes: without
    // this, a build with a new secret would silently reuse the old
    // compilation and ship the old secret inside the binary.
    println!("cargo:rerun-if-env-changed=BACKMEUP_OAUTH_CLIENT_SECRET");

    tauri_build::build()
}
