use crate::error::MemoryServerError;

use std::cmp::min;
use std::{fs, io, path};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use futures_util::StreamExt;
use os_info::{Bitness, Info as OsInfo, Type as OsType};
use piz::ZipArchive;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use semver::{Version, VersionReq};

const BINARY_URL: &str = "https://fastdl.mongodb.org";

/// A struct representing a `MongoDB` binary
pub struct MongoBinary {
    os_info: OsInfo,
    mongo_version: Version,
    arch: String,
    platform: String,
}

impl MongoBinary {
    /// Creates a new binary download url for the given OS information and `MongoDB` version
    ///
    /// # Arguments
    ///
    /// * `os_info` - Os information required to detect the correct platform, architecture and file ending
    /// * `mongo_version` - The `MongoDB` version to download
    /// * `arch` - The underlying architecture the download depends on
    pub fn new(os_info: OsInfo, mongo_version: Version, arch: String) -> Result<Self, MemoryServerError> {
        let platform = MongoBinary::translate_platform(os_info.os_type(), &mongo_version)?;
        let arch = MongoBinary::translate_arch(arch, platform.clone())?;

        Ok(Self {
            os_info,
            mongo_version,
            arch,
            platform,
        })
    }

    /// Returns true if the binary is already present at the given path
    ///
    /// # Arguments
    ///
    /// * `path` - The path
    pub fn is_present<P: AsRef<Path>>(&self, path: P) -> Result<bool, MemoryServerError> {
        let archive_name = self.archive_name()?;
        Ok(path.as_ref().join(archive_name).exists())
    }

    /// Returns the archive name
    pub fn archive_name(&self) -> Result<String, MemoryServerError> {
        match self.os_info.os_type() {
            OsType::Windows => self.win_archive_name(),
            OsType::Debian | OsType::Ubuntu => self.linux_archive_name(),
            _ => Err(MemoryServerError::UnsupportedOs(self.os_info.os_type().to_string()))
        }
    }

    /// Returns the archive file ending
    pub fn archive_file_ending(&self) -> Result<String, MemoryServerError> {
        match self.os_info.os_type() {
            OsType::Windows => Ok("zip".to_string()),
            OsType::Debian | OsType::Ubuntu => Ok("tgz".to_string()),
            _ => Err(MemoryServerError::UnsupportedOs(self.os_info.os_type().to_string()))
        }
    }

    /// Returns the download archive name
    pub fn download_archive_name(&self) -> Result<String, MemoryServerError> {
        let archive_platform = &self.platform;
        let archive_name = self.archive_name()?;
        let archive_file_ending = self.archive_file_ending()?;
        Ok(format!("{}/{}.{}", archive_platform, archive_name, archive_file_ending))
    }

    /// Returns the download url
    pub fn download_url(&self) -> Result<String, MemoryServerError> {
        let archive = self.download_archive_name()?;
        Ok(format!("{}/{}", BINARY_URL, archive))
    }

    /// Returns the archive name for `Linux` architectures
    /// - https://www.mongodb.org/dl/linux
    fn linux_archive_name(&self) -> Result<String, MemoryServerError> {
        todo!()
    }

    /// Returns the archive name for `Windows`:
    /// - https://www.mongodb.org/dl/win32 for `MongoDB <= 4.2.x`
    /// - https://www.mongodb.org/dl/windows for `MongoDB >= 4.3.0`
    fn win_archive_name(&self) -> Result<String, MemoryServerError> {
        let arch = match &self.os_info.bitness() {
            Bitness::X64 => Ok("x86_64"),
            _ => Err(MemoryServerError::UnsupportedOsArch(self.os_info.bitness().to_string())),
        }?;

        let platform = if VersionReq::parse("<4.3.0").unwrap().matches(&self.mongo_version) {
            "win32".to_string()
        } else {
            "windows".to_string()
        };

        let mut name = format!("mongodb-{}-{}", platform, arch);

        if semver::VersionReq::parse("~4.2.0").unwrap().matches(&self.mongo_version) {
            name = format!("{}-2012plus", name);
        } else if semver::Version::parse("4.1.0").unwrap() > self.mongo_version {
            name = format!("{}-2008plus-ssl", name);
        }

        Ok(format!("{}-{}", name, self.mongo_version))
    }

    /// Translate input platform to `MongoDB` known
    ///
    /// # Arguments
    ///
    /// * `platform` - The [OsType](os_info::type::Type) platform to translate
    /// * `mongo_version` - The `MongoDB` version to download or already used
    fn translate_platform(platform: OsType, mongo_version: &Version) -> Result<String, MemoryServerError> {
        match platform {
            OsType::Windows => {
                if mongo_version >= &semver::Version::parse("4.3.0").unwrap() {
                    Ok("windows")
                } else {
                    Ok("win32")
                }
            },
            OsType::Debian | OsType::Ubuntu => Ok("linux"),
            _ => Err(MemoryServerError::UnsupportedOs(platform.to_string()))
        }.map(|s| s.to_string())
    }

    /// Translate input arch to `MongoDB` known arch
    ///
    /// # Arguments
    ///
    /// * `arch` - The architecture to translate
    /// * `platform` - The platform
    ///
    /// # Example
    ///
    /// `x64` -> `x86_64`
    fn translate_arch(arch: String, platform: String) -> Result<String, MemoryServerError> {
        let platform = platform.as_str();
        match arch.as_str() {
            "ia32" => {
                if platform == "linux" {
                    Ok("i686")
                } else if platform == "win32" {
                    Ok("i386")
                } else {
                    Err(MemoryServerError::UnsupportedOsArch(arch))
                }
            },
            "x64" | "x86_64" => Ok("x86_64"),
            "arm64" => Ok("arm64"),
            "aarch64" => Ok("aarch64"),
            _ => Err(MemoryServerError::UnsupportedOsArch(arch))
        }.map(|s| s.to_string())
    }
}

/// A struct managing downloads from `<https://fastdl.mongodb.org/>`
/// according to the the operating system
pub struct BinaryDownload {
    binary: MongoBinary,
}

impl BinaryDownload {
    /// Creates a new binary download struct for the given `MongoDB` version
    ///
    /// # Arguments
    ///
    /// * `os_info` - Os information required to detect the correct platform, architecture and file ending
    /// * `mongo_version` - The `MongoDB` version to download
    /// * `arch` - The architecture the download depends on
    pub fn new(os_info: OsInfo, mongo_version: Version, arch: String) -> Result<Self, MemoryServerError> {
        let binary = MongoBinary::new(os_info, mongo_version, arch)?;
        Ok(Self {
            binary,
        })
    }

    /// Extracts a zip compressed `MongoDB` (Windows) binary located at the given path
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the compressed binary
    pub fn extract_zip<P: AsRef<Path>>(&self, path: P) -> Result<(), MemoryServerError> {
        let path_str = path.as_ref().to_str().unwrap();

        // The name of the binary will be our base directory name
        let parent_dir = path.as_ref().with_extension("");

        let mut zip_file = File::open(&path)?;
        let mut zip_buf = Vec::with_capacity(zip_file.metadata().unwrap().len() as usize);
        zip_file.read_to_end(&mut zip_buf)?;

        let archive = ZipArchive::new(&zip_buf)?;

        println!("Extracting {}...", path_str);

        // Initialize progress bar
        let mp = MultiProgress::new();

        let extract_result: Result<(), io::Error> = archive.entries()
            .par_iter()
            .try_for_each(|entry| {
                // We extract each file directly in our new directory so we can skip the first directory
                let entry_path: path::PathBuf = entry.path.iter().skip(1)
                    .collect();

                if let Some(parent) = entry_path.parent() {
                    // Create parent directories as needed.
                    fs::create_dir_all(parent_dir.join(parent))?;
                }

                let reader = archive.read(entry).unwrap();

                // Initialize progress_bar
                let total_size = entry.size;
                let pb = ProgressBar::new(total_size as u64);
                pb.set_style(ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})").unwrap()
                    .progress_chars("#>-"));

                mp.add(pb.clone());

                let mut save_to = File::create(parent_dir.join(&entry_path))?;
                let mut reader = pb.wrap_read(reader);
                io::copy(&mut reader, &mut save_to)?;

                Ok(())
            });

        extract_result?;

        println!("Extracted {}...", path_str);

        Ok(())
    }

    /// Returns the download_url
    pub fn download_url(&self) -> Result<String, MemoryServerError> {
        self.binary.download_url()
    }

    /// Downloads the binary into the given directory path
    ///
    /// # Argument
    ///
    /// * `path` - The path to download the binary into
    pub async fn download<P: AsRef<Path>>(&self, path: P) -> Result<(), MemoryServerError> {
        fs::create_dir_all(&path)?;

        let dir: &Path = path.as_ref();
        let download_url = self.download_url()?;

        // Initialize download of `MongoDB` binaries
        let res = reqwest::get(download_url.clone()).await
            .map_err(MemoryServerError::Reqwest)?;

        let total_size = res.content_length()
            .ok_or_else(|| MemoryServerError::InvalidDownloadUrl(format!("content length missing for {}", download_url)))?;

        // Extract file name and create file to write the binary data in
        let mut dest = {
            let file_name = res
                .url()
                .path_segments()
                .and_then(|segments| segments.last())
                .and_then(|name| if name.is_empty() { None } else { Some(name) })
                .unwrap_or("tmp.bin");

            let file_name = dir.join(file_name);
            File::create(file_name).unwrap()
        };

        // Initialize progress bar
        let pb = ProgressBar::new(total_size);
        pb.set_style(ProgressStyle::default_bar()
            .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})").unwrap()
            .progress_chars("#>-"));
        pb.set_message(format!("Downloading {}", &download_url));

        // Download binary chunks
        let mut downloaded: u64 = 0;
        let mut stream = res.bytes_stream();

        while let Some(item) = stream.next().await {
            let chunk = item.or(Err(MemoryServerError::DownloadFailed))?;
            dest.write_all(&chunk)?;
            let pos = min(downloaded + (chunk.len() as u64), total_size);
            downloaded = pos;
            pb.set_position(pos);
        }

        pb.finish_with_message(format!("Downloaded {} to {}", &download_url, dir.to_str().unwrap()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::download::{BinaryDownload, MongoBinary};

    use std::fs;
    use std::fs::File;
    use std::io::Write;

    use os_info::{Bitness, Type as OsType, Version as OsVersion};
    use semver::Version;
    use serde::Serialize;
    use tempfile::TempDir;
    use zip::CompressionMethod;

    #[derive(Serialize)]
    struct OsInfo {
        pub os_type: OsType,
        pub version: OsVersion,
        pub edition: Option<String>,
        pub codename: Option<String>,
        pub bitness: Bitness,
    }

    fn create_win_os() -> (os_info::Info, String) {
        let os_info = OsInfo {
            os_type: OsType::Windows,
            version: OsVersion::Unknown,
            edition: None,
            codename: None,
            bitness: Bitness::X64,
        };

        let os_info = serde_json::from_str::<os_info::Info>(serde_json::to_string(&os_info).unwrap().as_str()).unwrap();
        let arch = "x86_64".to_string();
        (os_info, arch)
    }

    #[test]
    fn test_binary_translate_platform_windows() {
        let mongo_version = Version::parse("5.2.0").unwrap();
        let (os_info, arch) = create_win_os();
        let os_type = os_info.os_type();
        let mongo_binary = MongoBinary::new(os_info, mongo_version.clone(), arch).unwrap();
        let platform = MongoBinary::translate_platform(os_type, &mongo_version).unwrap();

        assert_eq!(platform, "windows".to_string());
    }

    #[test]
    fn test_binary_translate_platform() {
        let mongo_version = Version::parse("5.2.0").unwrap();
        let mongo_version_win32 = Version::parse("4.1.0").unwrap();

        assert_eq!(MongoBinary::translate_platform(OsType::Windows, &mongo_version).unwrap(), "windows".to_string());
        assert_eq!(MongoBinary::translate_platform(OsType::Windows, &mongo_version_win32).unwrap(), "win32".to_string());
        assert_eq!(MongoBinary::translate_platform(OsType::Debian, &mongo_version).unwrap(), "linux".to_string());
        assert_eq!(MongoBinary::translate_platform(OsType::Ubuntu, &mongo_version).unwrap(), "linux".to_string());
    }

    #[test]
    fn test_binary_translate_arch() {
        assert_eq!(MongoBinary::translate_arch("ia32".to_string(), "linux".to_string()).unwrap(), "i686".to_string());
        assert_eq!(MongoBinary::translate_arch("ia32".to_string(), "win32".to_string()).unwrap(), "i386".to_string());
        assert!(MongoBinary::translate_arch("ia32".to_string(), "osx".to_string()).is_err());
        assert_eq!(MongoBinary::translate_arch("x86_64".to_string(), "win32".to_string()).unwrap(), "x86_64".to_string());
        assert_eq!(MongoBinary::translate_arch("x64".to_string(), "win32".to_string()).unwrap(), "x86_64".to_string());
        assert_eq!(MongoBinary::translate_arch("arm64".to_string(), "linux".to_string()).unwrap(), "arm64".to_string());
        assert_eq!(MongoBinary::translate_arch("aarch64".to_string(), "linux".to_string()).unwrap(), "aarch64".to_string());
        assert!(MongoBinary::translate_arch("powerpc64".to_string(), "linux".to_string()).is_err());
    }

    #[test]
    fn test_binary_win_archive_name_gte_4_3_0() {
        let mongo_version = Version::parse("5.2.0").unwrap();
        let (os_info, arch) = create_win_os();
        let mongo_binary = MongoBinary::new(os_info, mongo_version, arch).unwrap();
        let archive = mongo_binary.win_archive_name().unwrap();

        assert_eq!(archive, "mongodb-windows-x86_64-5.2.0".to_string());
    }

    #[test]
    fn test_binary_win_archive_name_4_3_0() {
        let mongo_version = Version::parse("5.2.0").unwrap();
        let (os_info, arch) = create_win_os();
        let mongo_binary = MongoBinary::new(os_info, mongo_version, arch).unwrap();
        let archive = mongo_binary.win_archive_name().unwrap();

        assert_eq!(archive, "mongodb-windows-x86_64-5.2.0".to_string());
    }

    #[test]
    fn test_binary_win_archive_name_4_2_x() {
        let mongo_version = Version::parse("4.2.1").unwrap();
        let (os_info, arch) = create_win_os();
        let binary_download_url = MongoBinary::new(os_info, mongo_version, arch).unwrap();
        let mongo_binary = binary_download_url.win_archive_name().unwrap();

        assert_eq!(mongo_binary, "mongodb-win32-x86_64-2012plus-4.2.1".to_string());
    }

    #[test]
    fn test_binary_win_archive_name_4_1_0() {
        let mongo_version = Version::parse("4.1.0").unwrap();
        let (os_info, arch) = create_win_os();
        let mongo_binary = MongoBinary::new(os_info, mongo_version, arch).unwrap();
        let archive = mongo_binary.win_archive_name().unwrap();

        assert_eq!(archive, "mongodb-win32-x86_64-4.1.0".to_string());
    }

    #[test]
    fn test_binary_win_archive_name_lte_4_1_0() {
        let mongo_version = Version::parse("3.4.0").unwrap();
        let (os_info, arch) = create_win_os();
        let mongo_binary = MongoBinary::new(os_info, mongo_version, arch).unwrap();
        let archive = mongo_binary.win_archive_name().unwrap();

        assert_eq!(archive, "mongodb-win32-x86_64-2008plus-ssl-3.4.0".to_string());
    }

    #[test]
    fn test_binary_archive_download_url() {
        let mongo_version = Version::parse("5.2.0").unwrap();
        let (os_info, arch) = create_win_os();
        let mongo_binary = MongoBinary::new(os_info, mongo_version, arch).unwrap();
        let url = mongo_binary.download_url().unwrap();

        assert_eq!(url, "https://fastdl.mongodb.org/windows/mongodb-windows-x86_64-5.2.0.zip".to_string());
    }

    #[test]
    fn test_binary_download_extract_zip() {
        let mongo_version = Version::parse("5.2.0").unwrap();
        let (os_info, arch) = create_win_os();
        let binary_download = BinaryDownload::new(os_info, mongo_version, arch).unwrap();

        let temp_dir = TempDir::new().unwrap();
        let zip_path = temp_dir.path().join("mongodb-windows-x86_64-5.2.0.zip");

        let zip_file = File::create(&zip_path).unwrap();
        let mut zip = zip::write::ZipWriter::new(zip_file);
        let options = zip::write::FileOptions::default().compression_method(CompressionMethod::Deflated);

        zip.start_file("data/test.txt", options).unwrap();
        zip.write(b"Test").unwrap();
        zip.finish().unwrap();

        binary_download.extract_zip(&zip_path).unwrap();

        let unzip_path = temp_dir.path().join("mongodb-windows-x86_64-5.2.0");
        assert!(unzip_path.exists());
    }

    #[test]
    fn test_binary_is_present() {
        let (os_info, arch) = create_win_os();
        let mongo_version = Version::parse("5.2.0").unwrap();
        let mongo_binary = MongoBinary::new(os_info, mongo_version, arch).unwrap();
        let temp_dir = TempDir::new().unwrap();

        assert!(!mongo_binary.is_present(&temp_dir).unwrap());

        fs::create_dir_all(temp_dir.path().join("mongodb-windows-x86_64-5.2.0")).unwrap();
        assert!(mongo_binary.is_present(&temp_dir).unwrap());
    }
}