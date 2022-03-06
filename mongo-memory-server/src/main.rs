use crate::download::BinaryDownload;

use std::{fs, io};
use std::path::Path;

use semver::Version;

pub mod download;
pub mod error;

#[tokio::main]
async fn main() -> io::Result<()> {
    let cargo_home = std::env::var("CARGO_HOME").unwrap();
    let mongo_version = Version::parse("5.2.0").unwrap();
    let path = Path::new(&cargo_home).join("mongo-memory-server");

    println!("Path: {:?}", &path.as_path());

    fs::create_dir_all(&path)?;

    let os_info = os_info::get();
    let binary_download = BinaryDownload::new(os_info, mongo_version);
    binary_download.download(&path).await.unwrap();
    binary_download.extract_zip(&path.join("mongodb-windows-x86_64-5.2.0.zip")).unwrap();

    Ok(())
}
