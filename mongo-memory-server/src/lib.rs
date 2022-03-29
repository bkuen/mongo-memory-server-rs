//! # Mongo In-Memory Server for Rust unit tests
//!
//! This package spins up a `MongoDB` instance programmatically from within `Rust`.
//! It is the counterpart to the NodeJS implementation of [nodkz](https://github.com/nodkz) 's npm package [mongodb-memory-server](https://github.com/nodkz/mongodb-memory-server).
//!
//! The crate is currently in active development and is not yet fully ready. At the moment, only `MongoDB` version `5.2.0` is tested.
//! If you encounter any errors with different versions, feel free to contact us.
//!
//! The crate will automatically download the binary to the corresponding version if it doesn't yet exist.
//! Make sure to have a stable internet connection because a failed download might end up in undefined behaviour at this point in the development cycle.
//!
//! # Requirements
//!
//! To use this crate, make sure the following requirements are fulfilled:
//! * Supported operating systems: `Windows`, `Debian`, `Ubuntu`, `Mint (not tested)`
//! * Supported architectures: `ia32`, `x86_64`, `arm64`, `aarch64`
//! * If you work on `unix`-like operating systems. Make sure, `libssl` is installed. Otherwise,
//! the `MongoDB` binaries could not extracted.
//!     ```bash
//!     $ apt install -y libssl-dev
//!     ```
//!
//! # Example
//!
//! The library works great with the [test_context](https://docs.rs/test-context/latest/test_context/) crate.
//! Therefore, add the following to your `Cargo.toml` to use this library.
//!
//! ```toml
//! [dev-dependencies]
//! async-trait = "0.1.52"
//! mongo-memory-server = "0.1.0"
//! test-context = "0.1.3"
//! tokio = { version = "1.17.0", features = ["test-util"] }
//! ```
//!
//! Afterwards, some setup tasks are required
//!
//! ```rust
//! use mongo_memory_server::server::{MongoServer, MongoOptions};
//! use test_context::{test_context, AsyncTestContext};
//! use test_context::futures;
//!
//! struct MyTestContext;
//!
//! #[async_trait::async_trait]
//! impl AsyncTestContext for MyTestContext {
//!     async fn setup() -> MyTestContext {
//!         let mongo_options = MongoOptions::builder()
//!             .host("127.0.0.1")
//!             .port(28000)
//!             .build();
//!
//!         let mut server = MongoServer::new(mongo_options).unwrap();
//!         let _ = server.start().await.unwrap();
//!
//!         MyTestContext{}
//!     }
//! }
//! ```
//!
//! Of course, you could use the library with different testing setups as well.

pub mod download;
pub mod error;
pub mod server;

#[cfg(test)]
mod tests {
    use crate::download::{BinaryDownload, MongoBinary};
    use crate::server::{MongoOptions, MongoServer};

    use std::path::Path;

    use semver::Version;
    use test_context::{test_context, AsyncTestContext};
    use test_context::futures;

    struct BinaryContext;

    #[async_trait::async_trait]
    impl AsyncTestContext for BinaryContext {
        async fn setup() -> BinaryContext {
            let cargo_home = std::env::var("CARGO_HOME").unwrap();
            let mongo_version = Version::parse("5.2.0").unwrap();
            let path = Path::new(&cargo_home).join("mongo-memory-server");

            let os_info = os_info::get();
            let arch = env!("TARGET_ARCH").to_string();

            let binary = MongoBinary::new(os_info.clone(), mongo_version.clone(), arch.clone()).unwrap();
            if !binary.is_present(&path).unwrap() {
                let binary_download = BinaryDownload::new(os_info, mongo_version, arch).unwrap();
                let archive_name = binary.archive_name().unwrap();
                let file_ending = binary.archive_file_ending().unwrap();
                let binary_dir = path.join(format!("{}.{}", archive_name, file_ending));

                binary_download.download(&path).await.unwrap();
                binary_download.extract(&binary_dir).unwrap();
            }

            Self
        }
    }

    #[test_context(BinaryContext)]
    #[tokio::test]
    async fn test_binary_is_present_after_potential_download(ctx: &mut BinaryContext) {
        let cargo_home = std::env::var("CARGO_HOME").unwrap();
        let mongo_version = Version::parse("5.2.0").unwrap();
        let os_info = os_info::get();
        let arch = env!("TARGET_ARCH").to_string();
        let path = Path::new(&cargo_home).join("mongo-memory-server");

        let binary = MongoBinary::new(os_info.clone(), mongo_version.clone(), arch).unwrap();
        assert!(binary.is_present(&path).unwrap())
    }

    #[test_context(BinaryContext)]
    #[tokio::test]
    async fn test_server_start(ctx: &mut BinaryContext) {
        let mut server = MongoServer::new(MongoOptions::default()).unwrap();
        let _ = server.start().await.unwrap();

        assert!(server.is_running());
    }

}