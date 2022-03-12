use crate::error::MemoryServerError;

use std::path::Path;
use std::process::{Child, Stdio};

use tempfile::TempDir;

/// A struct representing a `MongoDB` memory server
pub struct MongoServer<'a> {
    working_dir: &'a Path,
    data_dir: TempDir,
    child: Option<Child>,
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
        })
    }

    /// Start the binary in the `Windows` background
    pub fn start(&mut self) -> Result<(), MemoryServerError> {
        let data_dir = self.data_dir.as_ref();

        let service_binary_path = self.working_dir.join("mongod.exe");
        self.child = Some(std::process::Command::new(service_binary_path)
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
            .spawn()?);

        Ok(())
    }

    /// Returns `true` if a `MongoDB` memory server is running in the background
    pub fn is_running(&self) -> bool {
        self.child.is_some()
    }
}

#[cfg(test)]
mod tests {

}