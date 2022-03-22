use crate::download::{BinaryDownload, MongoBinary};
use crate::server::{MongoOptions, MongoServer};

use std::io;
use std::path::Path;
use std::time::Duration;

use semver::Version;

pub mod download;
pub mod error;
pub mod server;

#[tokio::main]
async fn main() -> io::Result<()> {
    let cargo_home = std::env::var("CARGO_HOME").unwrap();
    let mongo_version = Version::parse("5.2.0").unwrap();
    let path = Path::new(&cargo_home).join("mongo-memory-server");

    let os_info = os_info::get();

    let binary = MongoBinary::new(os_info.clone(), mongo_version.clone());
    if !binary.is_present(&path).unwrap() {
        let binary_download = BinaryDownload::new(os_info, mongo_version);
        binary_download.download(&path).await.unwrap();
        binary_download.extract_zip(&path.join("mongodb-windows-x86_64-5.2.0.zip")).unwrap();
    }

    let working_dir = path.join("mongodb-windows-x86_64-5.2.0\\bin");
    let mut server = MongoServer::new(&working_dir, MongoOptions::default()).unwrap();
    let _ = server.start().await.unwrap();

    println!("Ready");

    std::thread::sleep(Duration::from_secs(60*60));

    Ok(())
}
