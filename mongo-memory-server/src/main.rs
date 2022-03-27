use crate::server::{MongoOptions, MongoServer};

use std::io;
use std::time::Duration;

pub mod download;
pub mod error;
pub mod server;

#[tokio::main]
async fn main() -> io::Result<()> {
    let mut server = MongoServer::new(MongoOptions::default()).unwrap();
    let _ = server.start().await.unwrap();

    println!("Ready");

    std::thread::sleep(Duration::from_secs(60*60));

    Ok(())
}
