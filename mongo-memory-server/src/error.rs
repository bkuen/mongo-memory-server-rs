use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MemoryServerError {
    #[error("unsupported os: {0}")]
    UnsupportedOs(String),
    #[error("unsupported os arch: {0}")]
    UnsupportedOsArch(String),
    #[error("invalid download url: {0}")]
    InvalidDownloadUrl(String),
    #[error("error while downloading file")]
    DownloadFailed,
    #[error("binary download failed: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("zip error occurred: {0}")]
    Zip(#[from] piz::result::ZipError),
    #[error("windows service error occurred: {0}")]
    WinService(#[from] windows_service::Error),
}