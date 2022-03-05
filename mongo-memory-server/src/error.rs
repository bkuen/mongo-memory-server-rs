use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MemoryServerError {
    #[error("unsupported os: {0}")]
    UnsupportedOsError(String),
    #[error("unsupported os arch: {0}")]
    UnsupportedOsArch(String),
    #[error("invalid download url: {0}")]
    InvalidDownloadUrl(String),
    #[error("error while downloading file")]
    DownloadFailed,
    #[error("binary download failed: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("{0}")]
    IoError(#[from] io::Error)
}