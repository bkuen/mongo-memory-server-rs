use crate::error::MemoryServerError;

use std::cmp::min;
use std::{fs, io, path};
use std::fs::File;
use std::io::{Write};
use std::path::{Path};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use futures_util::StreamExt;
use log::warn;
use os_info::{Info as OsInfo, Type as OsType};
use semver::{Version, VersionReq};

/// The default binary url from which binaries are downloaded
const BINARY_URL: &str = "https://fastdl.mongodb.org";

/// This version constant should correspond to the latest LTS version of `Ubuntu`
const CURRENT_UBUNTU_LTS_VERSION: &str = "22.04";

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

    /// Returns the archive name without the file ending
    pub fn archive_name(&self) -> Result<String, MemoryServerError> {
        match self.os_info.os_type() {
            OsType::Windows => Ok(self.win_archive_name()),
            OsType::Debian |
            OsType::Ubuntu |
            OsType::Pop |
            OsType::Fedora |
            OsType::Mint => Ok(self.linux_archive_name()),
            _ => Err(MemoryServerError::UnsupportedOs(self.os_info.os_type().to_string()))
        }
    }

    /// Returns the archive file ending
    pub fn archive_file_ending(&self) -> Result<String, MemoryServerError> {
        match self.os_info.os_type() {
            OsType::Windows => Ok("zip".to_string()),
            OsType::Debian | OsType::Ubuntu | OsType::Pop | OsType::Fedora => Ok("tgz".to_string()),
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

    /// Returns os information
    pub(crate) fn os_info(&self) -> &os_info::Info {
        &self.os_info
    }

    /// Returns the archive name for `Linux` architectures
    /// - https://www.mongodb.org/dl/linux
    fn linux_archive_name(&self) -> String {
        let mut arch = self.arch.clone();
        let version = &self.mongo_version;

        // The highest version for `i686` seems to be `3.3`
        let mut name = "".to_string();
        if arch != "i686" {
            if let Ok((os_string, os_arch)) = self.linux_os_string() {
                arch = os_arch;
                name = format!("-{}", os_string);
            }
        }

        format!("mongodb-linux-{}{}-{}", arch, name, version)
    }

    /// Returns the name for a `Linux` os in a `MongoDB` understandable way
    fn linux_os_string(&self) -> Result<(String, String), MemoryServerError> {
        match self.os_info.os_type() {
            OsType::Debian => self.linux_debian_os_string()
                .map(|os_string| (os_string, self.arch.clone())),
            OsType::Ubuntu | OsType::Mint | OsType::Pop => self.linux_ubuntu_os_string(),
            OsType::Fedora => self.linux_fedora_os_string(),
            _ => unreachable!()
        }
    }

    /// Returns the name for a `Debian` os in a `MongoDB` understandable way
    fn linux_debian_os_string(&self) -> Result<String, MemoryServerError> {
        let version = self.os_info.version();
        let version = semver::Version::parse(version.to_string().as_str()).unwrap();

        let release = if semver::VersionReq::parse(">=11").unwrap().matches(&version) {
            if semver::VersionReq::parse("<=5.0.8").unwrap().matches(&self.mongo_version) {
                warn!("debian 11 detected, but version below 5.0.8 requested, using debian 10");
                "10"
            } else {
                "11"
            }
        } else if semver::VersionReq::parse(">=10.0").unwrap().matches(&version) {
            "10"
        } else if semver::VersionReq::parse(">=9.0").unwrap().matches(&version) {
            "92"
        } else if semver::VersionReq::parse(">=8.1").unwrap().matches(&version) {
            "81"
        } else if semver::VersionReq::parse(">=7.1").unwrap().matches(&version) {
            "71"
        } else {
            ""
        };

        Ok(format!("debian{}", release))
    }

    /// Returns the name for a `Ubuntu` os in a `MongoDB` understandable way
    fn linux_ubuntu_os_string(&self) -> Result<(String, String), MemoryServerError> {
        let os_info = &self.os_info;
        let os_version = self.os_info.version();
        let ubuntu_os = match os_info.os_type() {
            OsType::Ubuntu | OsType::Pop => {
                if let os_info::Version::Rolling(Some(version)) = os_version {
                    version
                } else {
                    CURRENT_UBUNTU_LTS_VERSION
                }
            }
            OsType::Mint => {
                if let os_info::Version::Custom(version) = os_version {
                    match version.split('.').next().unwrap() {
                        "17" => "14.04",
                        "18" => "16.04",
                        "19" => "18.04",
                        "20" => "20.04",
                        "22" => "22.04",
                        _ => CURRENT_UBUNTU_LTS_VERSION
                    }
                } else {
                    unreachable!()
                }
            }
            _ => unreachable!()
        };

        let ubuntu_year: u8 = ubuntu_os.split('.').next().unwrap().parse().unwrap();
        let mut arch = self.arch.clone();

        // Currently, `MongoDB` only really provides `arm64` binaries for `ubuntu1604`
        if arch.as_str() == "arm64" || arch.as_str() == "aarch64" {
            if semver::VersionReq::parse("<4.1.0").unwrap().matches(&self.mongo_version) {
                // Before before version `4.1.10`, everything for `arm64` / `aarch64` were just `arm64` and for `ubuntu1604`
                arch = "arm64".to_string();

                return Ok(("ubuntu1604".to_string(), arch));
            }

            if semver::VersionReq::parse(">=4.1.10").unwrap().matches(&self.mongo_version) {
                // `MongoDB` changed since `4.1.0` to use `aarch64` instead of `arm64`
                arch = "aarch64".to_string();

                if semver::VersionReq::parse("<4.4.0").unwrap().matches(&self.mongo_version) {
                    return Ok(("ubuntu1804".to_string(), arch));
                }

                return Ok((format!("ubuntu{}04", ubuntu_year), arch));
            }
        }

        if ubuntu_os == "14.10" {
            return Ok(("ubuntu1410-clang".to_string(), arch));
        }

        // There are no `MongoDB 3.x binary distributions` for `Ubuntu` >= `18`
        // https://www.mongodb.org/dl/linux/x86_64-ubuntu1604
        if ubuntu_year >= 18 && semver::VersionReq::parse("3.x.x").unwrap().matches(&self.mongo_version) {
            return Ok(("ubuntu1604".to_string(), arch));
        }

        // There are no `MongoDB <=4.3.x binary distributions` for `Ubuntu` > `18`
        // https://www.mongodb.org/dl/linux/x86_64-ubuntu1804
        if ubuntu_year > 18 && semver::VersionReq::parse("<=4.3.x").unwrap().matches(&self.mongo_version) {
            return Ok(("ubuntu1804".to_string(), arch));
        }

        if ubuntu_year >= 21 {
            return Ok(("ubuntu2004".to_string(), arch));
        }

        return Ok((format!("ubuntu{}04", ubuntu_year), arch));
    }

    /// Returns the name for a `Fedora` os in a `MongoDB` understandable way
    fn linux_fedora_os_string(&self) -> Result<(String, String), MemoryServerError> {
        let os_version = self.os_info.version();
        let arch = self.arch.clone();

        if let os_info::Version::Semantic(fedora_version, _, _) = os_version {
            let fedora_version = *fedora_version;

            let release = if fedora_version >= 34 {
                "80"
            } else if (19..34).contains(&fedora_version) {
                "70"
            } else if (12..19).contains(&fedora_version) {
                "62"
            } else if (6..12).contains(&fedora_version) {
                "55"
            } else {
                return Err(MemoryServerError::VersionIncompatible(fedora_version.to_string()))
            };

            return Ok((format!("rhel{}", release), arch))
        }

        Err(MemoryServerError::VersionIncompatible(os_version.to_string()))
    }

    /// Returns the archive name for `Windows`:
    /// - https://www.mongodb.org/dl/win32 for `MongoDB <= 4.2.x`
    /// - https://www.mongodb.org/dl/windows for `MongoDB >= 4.3.0`
    fn win_archive_name(&self) -> String {
        let arch = &self.arch;

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

        format!("{}-{}", name, self.mongo_version)
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
            OsType::Debian | OsType::Ubuntu | OsType::Pop | OsType::Fedora => Ok("linux"),
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

    /// Extracts zip or tgz compressed binaries located at the given path depending on the os
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the compressed binary
    pub fn extract<P: AsRef<Path>>(&self, path: P) -> Result<(), MemoryServerError> {
        let file_ending = self.binary.archive_file_ending()?;
        match file_ending.as_str() {
            #[cfg(target_family = "windows")]
            "zip" => self.extract_zip(path),
            #[cfg(target_family = "unix")]
            "tgz" => self.extract_tgz(path),
            _ => Ok(())
        }
    }

    /// Extracts a zip compressed `MongoDB` (Windows) binary located at the given path
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the compressed binary
    #[cfg(target_family = "windows")]
    pub fn extract_zip<P: AsRef<Path>>(&self, path: P) -> Result<(), MemoryServerError> {
        use std::io::Read;

        use piz::ZipArchive;
        use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};

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

    /// Extracts a tgz compressed `MongoDB` binary located at the given path
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the compressed binary
    #[cfg(target_family = "unix")]
    pub fn extract_tgz<P: AsRef<Path>>(&self, path: P) -> Result<(), MemoryServerError> {
        use std::path::PathBuf;

        use flate2::read::GzDecoder;
        use tar::{Archive as TarArchive};

        let path_str = path.as_ref().to_str().unwrap();

        // The name of the binary will be our base directory name
        let parent_dir = path.as_ref().with_extension("");
        fs::create_dir_all(&parent_dir)?;

        let tgz_file = File::open(&path)?;
        let tar = GzDecoder::new(tgz_file);
        let mut archive = TarArchive::new(tar);

        println!("Extracting {}...", path_str);

        // Initialize progress bar
        let mp = MultiProgress::new();

        // archive
        //     .entries()?
        //     .for_each(|entry| {
        //         println!("{:?}", entry.unwrap().path().unwrap());
        //     });

        archive
            .entries()?
            .filter_map(|e| e.ok())
            .map(|mut entry| -> io::Result<PathBuf> {
                // We extract each file directly in our new directory so we can skip the first directory
                let entry_path: path::PathBuf = entry.path()?.to_path_buf().iter().skip(1)
                    .collect();

                println!("--> Entry: {:?}", &entry_path);

                let dest_path = parent_dir.join(&entry_path);
                fs::create_dir_all(dest_path.parent().unwrap())?;

                println!("--> {:?}", &dest_path);

                let pb = ProgressBar::new_spinner();
                pb.set_style(ProgressStyle::default_spinner());
                mp.add(pb.clone());

                entry.unpack(&dest_path)?;
                pb.set_position(1);

                Ok(dest_path)
            })
            .filter_map(|e| e.ok())
            .for_each(|x| println!("> {}", x.display()));

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

    use std::collections::HashMap;
    use std::fs;
    use std::fs::File;
    use std::io::Write;

    use os_info::{Bitness, Type as OsType, Version as OsVersion};
    use rstest::rstest;
    use semver::Version;
    use serde::Serialize;
    use tempfile::TempDir;

    #[derive(Clone, Serialize)]
    struct OsInfo {
        pub os_type: OsType,
        pub version: OsVersion,
        pub edition: Option<String>,
        pub codename: Option<String>,
        pub bitness: Bitness,
    }

    impl From<OsInfo> for os_info::Info {
        fn from(os_info: OsInfo) -> Self {
            serde_json::from_str::<os_info::Info>(serde_json::to_string(&os_info).unwrap().as_str()).unwrap()
        }
    }

    fn create_win_os() -> (os_info::Info, String) {
        let os_info = OsInfo {
            os_type: OsType::Windows,
            version: OsVersion::Unknown,
            edition: None,
            codename: None,
            bitness: Bitness::X64,
        };

        let os_info = os_info::Info::from(os_info);
        let arch = "x86_64".to_string();
        (os_info, arch)
    }

    fn create_linux_debian_os() -> (OsInfo, String) {
        let os_info = OsInfo {
            os_type: OsType::Debian,
            version: OsVersion::Semantic(10, 0, 0),
            edition: None,
            codename: None,
            bitness: Bitness::X64,
        };

        let arch = "arm64".to_string();
        (os_info, arch)
    }

    fn create_linux_fedora_os() -> (OsInfo, String) {
        let os_info = OsInfo {
            os_type: OsType::Fedora,
            version: OsVersion::Semantic(37, 0, 0),
            edition: None,
            codename: None,
            bitness: Bitness::X64,
        };

        let arch = "x86_64".to_string();
        (os_info, arch)
    }

    #[test]
    fn test_binary_translate_platform_windows() {
        let mongo_version = Version::parse("5.2.0").unwrap();
        let (os_info, _) = create_win_os();
        let os_type = os_info.os_type();
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
        assert_eq!(MongoBinary::translate_platform(OsType::Pop, &mongo_version).unwrap(), "linux".to_string());
        assert_eq!(MongoBinary::translate_platform(OsType::Fedora, &mongo_version).unwrap(), "linux".to_string());
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
        let archive = mongo_binary.win_archive_name();

        assert_eq!(archive, "mongodb-windows-x86_64-5.2.0".to_string());
    }

    #[test]
    fn test_binary_win_archive_name_4_3_0() {
        let mongo_version = Version::parse("5.2.0").unwrap();
        let (os_info, arch) = create_win_os();
        let mongo_binary = MongoBinary::new(os_info, mongo_version, arch).unwrap();
        let archive = mongo_binary.win_archive_name();

        assert_eq!(archive, "mongodb-windows-x86_64-5.2.0".to_string());
    }

    #[test]
    fn test_binary_win_archive_name_4_2_x() {
        let mongo_version = Version::parse("4.2.1").unwrap();
        let (os_info, arch) = create_win_os();
        let binary_download_url = MongoBinary::new(os_info, mongo_version, arch).unwrap();
        let mongo_binary = binary_download_url.win_archive_name();

        assert_eq!(mongo_binary, "mongodb-win32-x86_64-2012plus-4.2.1".to_string());
    }

    #[test]
    fn test_binary_win_archive_name_4_1_0() {
        let mongo_version = Version::parse("4.1.0").unwrap();
        let (os_info, arch) = create_win_os();
        let mongo_binary = MongoBinary::new(os_info, mongo_version, arch).unwrap();
        let archive = mongo_binary.win_archive_name();

        assert_eq!(archive, "mongodb-win32-x86_64-4.1.0".to_string());
    }

    #[test]
    fn test_binary_win_archive_name_lte_4_1_0() {
        let mongo_version = Version::parse("3.4.0").unwrap();
        let (os_info, arch) = create_win_os();
        let mongo_binary = MongoBinary::new(os_info, mongo_version, arch).unwrap();
        let archive = mongo_binary.win_archive_name();

        assert_eq!(archive, "mongodb-win32-x86_64-2008plus-ssl-3.4.0".to_string());
    }

    #[rstest]
    #[case(37, "mongodb-linux-x86_64-rhel80-5.2.0")]
    #[case(34, "mongodb-linux-x86_64-rhel80-5.2.0")]
    #[case(33, "mongodb-linux-x86_64-rhel70-5.2.0")]
    #[case(19, "mongodb-linux-x86_64-rhel70-5.2.0")]
    #[case(18, "mongodb-linux-x86_64-rhel62-5.2.0")]
    #[case(12, "mongodb-linux-x86_64-rhel62-5.2.0")]
    #[case(11, "mongodb-linux-x86_64-rhel55-5.2.0")]
    #[case(6, "mongodb-linux-x86_64-rhel55-5.2.0")]
    fn test_binary_linux_fedora_archive_name(#[case] version: u64, #[case] expected: &str) {
        let mongo_version = Version::parse("5.2.0").unwrap();
        let (mut os_info, arch) = create_linux_fedora_os();
        os_info.version = OsVersion::Semantic(version, 0, 0);

        let mongo_binary = MongoBinary::new(os_info::Info::from(os_info), mongo_version.clone(), arch.clone()).unwrap();
        let archive = mongo_binary.linux_archive_name();

        assert_eq!(archive, expected.to_string());
    }

    #[test]
    fn test_binary_linux_debian_archive_name() {
        let mongo_version = Version::parse("5.2.0").unwrap();
        let (mut os_info, arch) = create_linux_debian_os();

        let test_cases = HashMap::from([
            ("10.0", "mongodb-linux-arm64-debian10-5.2.0"),
            ("9.0", "mongodb-linux-arm64-debian92-5.2.0"),
            ("8.2", "mongodb-linux-arm64-debian81-5.2.0"),
            ("8.0", "mongodb-linux-arm64-debian71-5.2.0"),
            ("7.1", "mongodb-linux-arm64-debian71-5.2.0"),
            ("6.0", "mongodb-linux-arm64-debian-5.2.0"),
        ]);

        for (ver, expected) in test_cases {
            os_info.version = OsVersion::from_string(ver);
            let mongo_binary = MongoBinary::new(os_info::Info::from(os_info.clone()), mongo_version.clone(), arch.clone()).unwrap();
            let archive = mongo_binary.linux_archive_name();
            assert_eq!(archive, expected.to_string());
        }
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
    #[cfg(target_family = "windows")]
    fn test_binary_download_extract_zip() {
        use zip::CompressionMethod;

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
    #[cfg(target_family = "unix")]
    fn test_binary_download_extract_tgz() {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let mongo_version = Version::parse("5.2.0").unwrap();
        let (os_info, arch) = create_linux_debian_os();
        let binary_download = BinaryDownload::new(os_info::Info::from(os_info), mongo_version, arch).unwrap();

        let temp_dir = TempDir::new().unwrap();
        let tgz_path = temp_dir.path().join("mongodb-linux-arm64-debian10-5.2.0.tgz");

        let data_dir_path = temp_dir.path().join("data_test");
        fs::create_dir(&data_dir_path).unwrap();

        {
            let mut data_file = File::create(temp_dir.path().join("data_test/data.txt")).unwrap();
            data_file.write_all(b"Hello world").unwrap();
        }

        {
            let tgz_file = File::create(&tgz_path).unwrap();
            let encoder = GzEncoder::new(tgz_file, Compression::default());

            let mut tar = tar::Builder::new(encoder);
            tar.append_dir_all("data", &data_dir_path).unwrap();
            let _ = tar.finish().unwrap();
        }

        binary_download.extract_tgz(&tgz_path).unwrap();

        let uncompressed_path = temp_dir.path().join("mongodb-linux-arm64-debian10-5.2.0/data.txt");
        assert!(uncompressed_path.exists());
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