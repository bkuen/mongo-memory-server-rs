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

/// A struct representing a `MongoDB` memory server
pub struct MongoServer<'a> {
    working_dir: &'a Path,
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
    pub fn new<P: AsRef<Path> + 'a>(working_dir: &'a P) -> Result<Self, MemoryServerError> {
        Ok(Self {
            working_dir: working_dir.as_ref(),
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
            .arg("ephemeralForTest")
            .arg("--bind_ip")
            .arg("0.0.0.0")
            .arg("--port")
            .arg("27777")
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

        // let task_proc_time = time::Duration::from_millis(500);
        loop {
            let status = self.status.lock().unwrap();
            if *status == MongoServerStatus::Ready {
                break;
            }

            // thread::sleep(task_proc_time);
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

}