use crate::server::{MongoOptions, MongoServer};

use std::io;
use std::time::Duration;
use log::info;

pub mod download;
pub mod error;
pub mod server;

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();

    let info = os_info::get();
    info!("detecting os information...");
    info!("{:?}", info);

    let mut server = MongoServer::new(MongoOptions::default()).unwrap();
    server.start().await.unwrap();

    info!("mongo memory server is ready");

    server.stop().unwrap();

    std::thread::sleep(Duration::from_secs(60*60));

    Ok(())
}
