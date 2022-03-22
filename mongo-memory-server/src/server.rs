use crate::error::MemoryServerError;

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use regex::Regex;

use tempfile::TempDir;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MongoServerStatus {
    Stopped,
    Starting,
    Ready,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageEngine {
    EphemeralForTest,
}

impl From<StorageEngine> for String {
    fn from(engine: StorageEngine) -> Self {
        match engine {
            StorageEngine::EphemeralForTest => "ephemeralForTest".to_string(),
        }
    }
}

/// Settings that are passed on to the `mongod` process.
pub struct MongoOptions<'a> {
    host: &'a str,
    port: u16,
    storage_engine: StorageEngine,
}

impl<'a> MongoOptions<'a> {
    pub fn builder() -> MongoOptionsBuilder<'a> {
        MongoOptionsBuilder {
            options: Default::default(),
        }
    }
}

impl<'a> Default for MongoOptions<'a> {
    fn default() -> Self {
        Self {
            host: "0.0.0.0",
            port: 27777,
            storage_engine: StorageEngine::EphemeralForTest,
        }
    }
}

/// A builder for `MongoOptions`.
pub struct MongoOptionsBuilder<'a> {
    options: MongoOptions<'a>,
}

impl<'a> MongoOptionsBuilder<'a> {
    pub fn host(mut self, host: &'a str) -> Self {
        self.options.host = host;
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.options.port = port;
        self
    }

    pub fn storage_engine(mut self, storage_engine: StorageEngine) -> Self {
        self.options.storage_engine = storage_engine;
        self
    }

    pub fn build(self) -> MongoOptions<'a> {
        self.options
    }
}

/// A struct representing a `MongoDB` memory server
pub struct MongoServer<'a> {
    working_dir: &'a Path,
    options: MongoOptions<'a>,
    data_dir: TempDir,
    child: Option<Child>,
    status: Arc<Mutex<MongoServerStatus>>,
}

impl<'a> MongoServer<'a> {
    /// Creates a new `MongoDB` memory server in the background
    ///
    /// # Arguments
    ///
    /// * `working_dir` - The working directory containing the binary
    pub fn new<P: AsRef<Path> + 'a>(working_dir: &'a P, options: MongoOptions<'a>) -> Result<Self, MemoryServerError> {
        Ok(Self {
            working_dir: working_dir.as_ref(),
            options,
            data_dir: TempDir::new()?,
            child: None,
            status: Arc::new(Mutex::new(MongoServerStatus::Stopped)),
        })
    }

    /// Start the binary in the `Windows` background
    pub async fn start(&mut self) -> Result<(), MemoryServerError> {
        let data_dir = self.data_dir.as_ref();

        let service_binary_path = self.working_dir.join("mongod.exe");

        let mut child = std::process::Command::new(service_binary_path)
            .arg("--dbpath")
            .arg(data_dir)
            .arg("--storageEngine")
            .arg(String::from(self.options.storage_engine).as_str())
            .arg("--bind_ip")
            .arg(self.options.host)
            .arg("--port")
            .arg(self.options.port.to_string().as_str())
            .arg("--noauth")
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

    /// Returns `true` if a `MongoDB` memory server is running in the background
    pub fn is_running(&self) -> bool {
        let status = self.status.lock().unwrap();
        *status == MongoServerStatus::Ready
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
            .storage_engine(StorageEngine::EphemeralForTest)
            .build();

        assert_eq!(mongo_options.host, "127.0.0.1");
        assert_eq!(mongo_options.port, 28000);
        assert_eq!(mongo_options.storage_engine, StorageEngine::EphemeralForTest);
    }
}