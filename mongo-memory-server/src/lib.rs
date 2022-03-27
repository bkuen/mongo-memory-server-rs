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
    #[ignore]
    #[tokio::test]
    async fn test_server_start(ctx: &mut BinaryContext) {
        let cargo_home = std::env::var("CARGO_HOME").unwrap();
        let path = Path::new(&cargo_home).join("mongo-memory-server");
        let working_dir = path.join("mongodb-windows-x86_64-5.2.0\\bin");

        let mut server = MongoServer::new(&working_dir, MongoOptions::default()).unwrap();
        let _ = server.start().await.unwrap();

        assert!(server.is_running());
    }

}