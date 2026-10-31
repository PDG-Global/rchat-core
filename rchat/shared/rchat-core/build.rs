// The JNI parity tests read the Android app's Kotlin bridge, which exists only in the
// private repo. They compile only when it is present, so the public tree builds and tests on its own.
fn main() {
    const BRIDGE: &str = "../../android/app/src/main/java/net/rchat/client/core";
    println!("cargo::rustc-check-cfg=cfg(rchat_app_tree)");
    println!("cargo::rerun-if-changed={BRIDGE}");
    if std::path::Path::new(BRIDGE).join("RChatCore.kt").exists() {
        println!("cargo::rustc-cfg=rchat_app_tree");
    }
}
