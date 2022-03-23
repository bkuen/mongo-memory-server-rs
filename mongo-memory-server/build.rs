fn main() {
    println!(
        "cargo:rustc-env=TARGET_ARCH={}",
        std::env::var("CARGO_CFG_TARGET_ARCH").unwrap()
    );
}