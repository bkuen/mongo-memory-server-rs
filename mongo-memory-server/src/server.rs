use crate::download::{BinaryDownload, MongoBinary};
use crate::error::MemoryServerError;

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use regex::Regex;
use semver::Version;
use tempfile::TempDir;

/// This version constant should correspond to the latest stable version of `MongoDB`
const DEFAULT_MONGODB_VERSION: &str = "5.2.0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MongoServerStatus {
    Stopped,
    Starting,
    Ready,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageEngine {
    EphemeralForTest,
    WiredTiger,
}

impl From<StorageEngine> for String {
    fn from(engine: StorageEngine) -> Self {
        match engine {
            StorageEngine::EphemeralForTest => "ephemeralForTest".to_string(),
            StorageEngine::WiredTiger => "wiredTiger".to_string(),
        }
    }
}

/// Settings that are passed on to the `mongod` process.
pub struct MongoOptions {
    host: String,
    port: u16,
    init_database: String,
    storage_engine: StorageEngine,
    download_dir: PathBuf,
    version: Version,
}

impl MongoOptions {
    /// Returns an option builder
    pub fn builder() -> MongoOptionsBuilder {
        MongoOptionsBuilder {
            options: Default::default(),
        }
    }

    /// Returns the uri described in https://www.mongodb.com/docs/manual/reference/connection-string/
    pub fn uri(&self) -> String {
        format!("mongodb://{}:{}/{}", self.host, self.port, self.init_database)
    }
}

impl Default for MongoOptions {
    fn default() -> Self {
        let cargo_home = std::env::var("CARGO_HOME").unwrap();
        let download_dir = Path::new(&cargo_home).join("mongo-memory-server");
        let version = Version::parse(DEFAULT_MONGODB_VERSION).unwrap();

        Self {
            host: "0.0.0.0".to_string(),
            port: 27777,
            init_database: "test".to_string(),
            storage_engine: StorageEngine::EphemeralForTest,
            download_dir,
            version,
        }
    }
}

/// A builder for `MongoOptions`.
pub struct MongoOptionsBuilder {
    options: MongoOptions,
}

impl MongoOptionsBuilder {
    pub fn host<S: Into<String>>(mut self, host: S) -> Self {
        self.options.host = host.into();
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.options.port = port;
        self
    }

    pub fn init_database<S: Into<String>>(mut self, init_database: S) -> Self {
        self.options.init_database = init_database.into();
        self
    }

    pub fn storage_engine(mut self, storage_engine: StorageEngine) -> Self {
        self.options.storage_engine = storage_engine;
        self
    }

    pub fn download_dir<P: AsRef<Path>>(mut self, download_dir: &P) -> Self {
        self.options.download_dir = download_dir.as_ref().to_path_buf();
        self
    }

    pub fn build(self) -> MongoOptions {
        self.options
    }
}

/// A struct representing a `MongoDB` memory server
pub struct MongoServer {
    options: MongoOptions,
    binary: MongoBinary,
    arch: String,
    data_dir: TempDir,
    child: Option<Child>,
    status: Arc<Mutex<MongoServerStatus>>,
}

impl MongoServer {
    /// Creates a new `MongoDB` memory server in the background
    ///
    /// # Arguments
    ///
    /// * `options` - The options used to start the instance
    pub fn new(options: MongoOptions) -> Result<Self, MemoryServerError> {
        let os_info = os_info::get();
        let arch = env!("TARGET_ARCH").to_string();

        let binary = MongoBinary::new(os_info, options.version.clone(), arch.clone()).unwrap();

        Ok(Self {
            binary,
            arch,
            options,
            data_dir: TempDir::new()?,
            child: None,
            status: Arc::new(Mutex::new(MongoServerStatus::Stopped)),
        })
    }

    /// Start the binary in the `Windows` background
    pub async fn start(&mut self) -> Result<(), MemoryServerError> {
        let options = &self.options;
        let download_dir = &options.download_dir;
        let working_dir = download_dir.join(self.binary.archive_name()?).join("bin");

        println!("Download directory: {:?}", download_dir);
        println!("Working directory: {:?}", working_dir);

        let mongo_version = options.version.clone();

        let data_dir = self.data_dir.as_ref();

        let arch = self.arch.clone();
        let binary = &self.binary;
        let os_info = binary.os_info().clone();

        if !binary.is_present(download_dir).unwrap() {
            let binary_download = BinaryDownload::new(os_info, mongo_version, arch).unwrap();
            let archive_name = binary.archive_name().unwrap();
            let file_ending = binary.archive_file_ending().unwrap();
            let binary_dir = download_dir.join(format!("{}.{}", archive_name, file_ending));

            binary_download.download(download_dir).await.unwrap();
            binary_download.extract(&binary_dir).unwrap();
        }

        #[cfg(target_family = "windows")]
        let service_binary_path = working_dir.join("mongod.exe");

        #[cfg(target_family = "unix")]
        let service_binary_path = working_dir.join("mongod");

        let mut child = std::process::Command::new(service_binary_path)
            .arg("--dbpath")
            .arg(data_dir)
            .arg("--storageEngine")
            .arg(String::from(self.options.storage_engine).as_str())
            .arg("--bind_ip")
            .arg(&self.options.host)
            .arg("--port")
            .arg(self.options.port.to_string().as_str())
            .arg("--noauth")
            .arg("--journal")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        {
            let mut status = self.status.lock().unwrap();
            *status = MongoServerStatus::Starting;
        }

        listen_on_events(&mut child, self.status.clone());

        self.child = Some(child);

        loop {
            let status = self.status.lock().unwrap();
            if *status == MongoServerStatus::Ready {
                break;
            }
        }

        Ok(())
    }

    /// Stops the server by killing the child process
    pub fn stop(&mut self) -> Result<(), MemoryServerError> {
        if let Some(child) = self.child.as_mut() {
            child.kill()?;
            self.child = None;
        }

        let mut status = self.status.lock().unwrap();
        *status = MongoServerStatus::Stopped;

        Ok(())
    }

    /// Returns `true` if a `MongoDB` memory server is running in the background
    pub fn is_running(&self) -> bool {
        let status = self.status.lock().unwrap();
        *status == MongoServerStatus::Ready
    }

    /// Returns the uri described in https://www.mongodb.com/docs/manual/reference/connection-string/
    pub fn uri(&self) -> String {
        self.options.uri()
    }
}

impl Drop for MongoServer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn listen_on_events(child: &mut Child, status: Arc<Mutex<MongoServerStatus>>) {
    let stdout = child.stdout.take().unwrap();

    thread::spawn(move || {
        let mut stdout_reader = BufReader::new(stdout);

        loop {
            let mut stdout_buf = String::new();

            match stdout_reader.read_line(&mut stdout_buf) {
                Ok(_) => stdout_handler(stdout_buf, status.clone()),
                Err(_) => unreachable!(),
            }
        }
    });

}

lazy_static::lazy_static! {
    static ref RE_READY: Regex = Regex::new(r"(?i)waiting for connections").unwrap();
}

fn stdout_handler(buf: String, status: Arc<Mutex<MongoServerStatus>>) {
    let buf_str = buf.as_str();

    let mut status = status.lock().unwrap();

    if RE_READY.is_match(buf_str) {
        *status = MongoServerStatus::Ready;
    }
}

#[cfg(test)]
mod tests {
    use crate::server::{MongoOptions, StorageEngine};

    #[test]
    fn test_mongo_options_builder() {
        let mongo_options = MongoOptions::builder()
            .host("127.0.0.1")
            .port(28000)
            .init_database("initdb")
            .storage_engine(StorageEngine::EphemeralForTest)
            .build();

        assert_eq!(mongo_options.host, "127.0.0.1");
        assert_eq!(mongo_options.port, 28000);
        assert_eq!(mongo_options.init_database, "initdb");
        assert_eq!(mongo_options.storage_engine, StorageEngine::EphemeralForTest);
    }

    #[test]
    fn test_mongo_options_uri() {
        let mongo_options = MongoOptions::builder()
            .host("127.0.0.1")
            .port(28000)
            .init_database("test")
            .storage_engine(StorageEngine::EphemeralForTest)
            .build();

        assert_eq!(mongo_options.uri(), "mongodb://127.0.0.1:28000/test".to_string())
    }
}