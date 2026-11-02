//! Locating executables on `PATH` — the only way a scanner binary is ever resolved.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Find `binary` on `path_var` (a `PATH`-style list), returning the first match.
///
/// Only the directories listed in `path_var` are searched: a relative or absolute `binary` is
/// never run as given, a name containing a path separator is never found, and an empty `PATH`
/// entry does not mean the current directory.
pub fn find_in_path(binary: &str, path_var: Option<&OsStr>) -> Option<PathBuf> {
    if binary.is_empty() || binary.contains(['/', '\\']) {
        return None;
    }
    let path_var = path_var?;
    std::env::split_paths(path_var)
        .filter(|dir| !dir.as_os_str().is_empty())
        .flat_map(|dir| candidates(&dir, binary))
        .find(|candidate| candidate.is_file())
}

fn candidates(dir: &Path, binary: &str) -> Vec<PathBuf> {
    let mut out = vec![dir.join(binary)];
    if cfg!(windows) {
        out.push(dir.join(format!("{binary}.exe")));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_in_path_returns_the_first_file_match() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        std::fs::create_dir(first.path().join("tool")).unwrap(); // a directory, not a match
        std::fs::write(second.path().join("tool"), b"#!/bin/sh\n").unwrap();
        let path_var = std::env::join_paths([first.path(), second.path()]).unwrap();
        let found = find_in_path("tool", Some(&path_var)).unwrap();
        assert_eq!(found, second.path().join("tool"));
    }

    #[test]
    fn find_in_path_without_a_path_variable_finds_nothing() {
        assert_eq!(find_in_path("sh", None), None);
    }

    #[test]
    fn find_in_path_never_resolves_a_path_as_a_binary() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("tool");
        std::fs::write(&file, b"x").unwrap();
        let path_var = std::env::join_paths([dir.path()]).unwrap();
        assert_eq!(find_in_path(file.to_str().unwrap(), Some(&path_var)), None);
        assert_eq!(find_in_path("./tool", Some(&path_var)), None);
        assert_eq!(find_in_path("", Some(&path_var)), None);
    }

    #[test]
    fn find_in_path_skips_empty_entries() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("tool"), b"x").unwrap();
        let mut path_var = std::ffi::OsString::from("");
        path_var.push(std::env::join_paths([dir.path()]).unwrap());
        // An empty PATH entry means "current directory" to a shell; it must not here.
        assert_eq!(find_in_path("Cargo.toml", Some(&path_var)), None);
        assert!(find_in_path("tool", Some(&path_var)).is_some());
    }
}
