//! Pin the verified cgroup v2 object, rather than infer removal from a pathname.
use rustix::fs::{Mode, OFlags, ResolveFlags, fstatfs, openat2};
use std::{
    fs::File,
    io::Read,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Component, Path, PathBuf},
    sync::Arc,
};

#[derive(Clone)]
pub(super) struct SessionGroup {
    directory: Arc<File>,
    original: PathBuf,
}

fn descriptor_path(file: &File) -> Result<PathBuf, String> {
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(|e| e.to_string())
}

fn directory(parent: &File, path: &Path) -> Result<File, String> {
    openat2(
        parent,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    )
    .map(File::from)
    .map_err(|e| e.to_string())
}

fn read_at(parent: &File, name: &str) -> Result<String, std::io::Error> {
    let fd = openat2(
        parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    )?;
    let mut text = String::new();
    File::from(fd).take(16385).read_to_string(&mut text)?;
    if text.len() > 16384 {
        return Err(std::io::Error::other("oversized cgroup state"));
    }
    Ok(text)
}

fn relative_group<'a>(group: &'a str, expected: &str) -> Result<&'a Path, String> {
    let path = Path::new(group)
        .strip_prefix("/")
        .map_err(|e| e.to_string())?;
    if path.file_name().and_then(|s| s.to_str()) != Some(expected)
        || !path.components().all(|c| matches!(c, Component::Normal(_)))
    {
        return Err("unexpected SSH control group".into());
    }
    Ok(path)
}

fn require_cgroup2(directory: &File) -> Result<(), String> {
    // Linux cgroup2 filesystem magic; reject v1 and ordinary directory trees.
    if !directory.metadata().map_err(|e| e.to_string())?.is_dir()
        || fstatfs(directory).map_err(|e| e.to_string())?.f_type != 0x6367_7270
    {
        return Err("SSH enforcement requires cgroup v2".into());
    }
    Ok(())
}

fn process_start(pid: u32) -> Result<u64, String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|e| e.to_string())?;
    stat.rsplit_once(") ")
        .and_then(|(_, tail)| tail.split_whitespace().nth(19))
        .ok_or("invalid SSH process identity")?
        .parse()
        .map_err(|e| format!("{e}"))
}

impl SessionGroup {
    pub(super) fn capture(pid: u32, start: u64, unit: &str) -> Result<Self, String> {
        let output = super::bounded_command("/usr/bin/systemctl")
            .args([
                "show",
                "--no-ask-password",
                "--property=ControlGroup",
                "--value",
                unit,
            ])
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() || output.stdout.len() > 4096 {
            return Err("SSH control group unavailable".into());
        }
        let group = std::str::from_utf8(&output.stdout)
            .map_err(|e| e.to_string())?
            .trim_end();
        let relative = relative_group(group, unit)?;
        if process_start(pid)? != start {
            return Err("SSH process changed".into());
        }
        let membership =
            std::fs::read_to_string(format!("/proc/{pid}/cgroup")).map_err(|e| e.to_string())?;
        if membership.trim_end() != format!("0::{group}") {
            return Err("SSH process/control group namespace mismatch".into());
        }
        let root = File::open("/sys/fs/cgroup").map_err(|e| e.to_string())?;
        require_cgroup2(&root)?;
        let directory = directory(&root, relative)?;
        if root.metadata().map_err(|e| e.to_string())?.dev()
            != directory.metadata().map_err(|e| e.to_string())?.dev()
        {
            return Err("SSH control group mount mismatch".into());
        }
        require_cgroup2(&directory)?;
        let members = read_at(&directory, "cgroup.procs").map_err(|e| e.to_string())?;
        if !members.lines().any(|member| member == pid.to_string()) || process_start(pid)? != start
        {
            return Err("SSH process is not in the pinned control group".into());
        }
        let original = descriptor_path(&directory)?;
        if original.file_name().and_then(|s| s.to_str()) != Some(unit) {
            return Err("SSH control group descriptor mismatch".into());
        }
        let pinned = Self {
            directory: Arc::new(directory),
            original,
        };
        if pinned.empty()? {
            return Err("SSH control group already empty".into());
        }
        Ok(pinned)
    }

    pub(super) fn same(&self, other: &Self) -> Result<bool, String> {
        let a = self.directory.metadata().map_err(|e| e.to_string())?;
        let b = other.directory.metadata().map_err(|e| e.to_string())?;
        Ok(a.dev() == b.dev() && a.ino() == b.ino())
    }

    pub(super) fn empty(&self) -> Result<bool, String> {
        // Only a previously verified cgroup2 directory can reach this branch.
        // Removing a cgroup2 directory requires no live processes/children.
        // fstat of the pinned inode distinguishes removal from a missing path,
        // a changed mount/namespace, or a new unit reusing the same pathname.
        if self
            .directory
            .metadata()
            .map_err(|e| e.to_string())?
            .nlink()
            == 0
        {
            return Ok(true);
        }
        // Older kernfs versions retain a stale link count after rmdir. procfs
        // reports unlinking of THIS pinned dentry with the " (deleted)" suffix.
        // Compare the complete original descriptor target, not an arbitrary path
        // ending in that text. Missing procfs or an unexpected namespace fails.
        let mut deleted = self.original.as_os_str().to_os_string();
        deleted.push(" (deleted)");
        if descriptor_path(&self.directory)?.as_os_str() == deleted {
            return Ok(true);
        }
        let events = read_at(&self.directory, "cgroup.events").map_err(|e| e.to_string())?;
        let values: Vec<_> = events
            .lines()
            .filter_map(|line| line.strip_prefix("populated "))
            .collect();
        match values.as_slice() {
            ["0"] => Ok(true),
            ["1"] => Ok(false),
            _ => Err("invalid SSH cgroup population state".into()),
        }
    }

    #[cfg(test)]
    pub(super) fn fixture(path: &Path) -> Self {
        let directory = File::open(path).unwrap();
        let original = descriptor_path(&directory).unwrap();
        Self {
            directory: Arc::new(directory),
            original,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn slice_is_observed_and_unsafe_or_wrong_unit_paths_are_rejected() {
        let unit = "authority-ssh-42-1.service";
        assert!(relative_group(&format!("/custom.slice/{unit}"), unit).is_ok());
        for path in [
            "",
            "system.slice/authority-ssh-42-1.service",
            "/../authority-ssh-42-1.service",
            "/system.slice/other.service",
        ] {
            assert!(relative_group(path, unit).is_err());
        }
    }
    #[test]
    fn missing_events_or_malformed_population_never_prove_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let group = SessionGroup::fixture(directory.path());
        assert!(group.empty().is_err());
        for text in ["", "populated 2\n", "populated 0\npopulated 1\n"] {
            std::fs::write(directory.path().join("cgroup.events"), text).unwrap();
            assert!(group.empty().is_err());
        }
        std::fs::write(directory.path().join("cgroup.events"), "populated 1\n").unwrap();
        assert!(!group.empty().unwrap());
        std::fs::write(directory.path().join("cgroup.events"), "populated 0\n").unwrap();
        assert!(group.empty().unwrap());
    }
    #[test]
    fn ordinary_filesystems_and_symlinked_evidence_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let file = File::open(directory.path()).unwrap();
        assert!(require_cgroup2(&file).is_err());
        let elsewhere = directory.path().join("evidence");
        std::fs::write(&elsewhere, "populated 0\n").unwrap();
        std::os::unix::fs::symlink(&elsewhere, directory.path().join("cgroup.events")).unwrap();
        assert!(SessionGroup::fixture(directory.path()).empty().is_err());
    }

    #[test]
    fn pinned_directory_is_independent_of_path_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("unit");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("cgroup.events"), "populated 1\n").unwrap();
        let group = SessionGroup::fixture(&path);
        std::fs::rename(&path, directory.path().join("moved")).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("cgroup.events"), "populated 0\n").unwrap();
        assert!(!group.empty().unwrap());
    }
}
