use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

const NIX_BASE32: &str = "0123456789abcdfghijklmnpqrsvwxyz";

pub fn sanitize_http_cache_path(target: &str) -> Result<String> {
    let path = target.split_once('?').map_or(target, |(path, _query)| path);
    let Some(path) = path.strip_prefix('/') else {
        bail!("HTTP cache path must start with /: {target}");
    };
    sanitize_cache_path(path)
}

pub fn sanitize_cache_path(path: &str) -> Result<String> {
    if path == "nix-cache-info" {
        return Ok(path.to_string());
    }

    if path.starts_with('/') || path.contains('\\') {
        bail!("invalid cache path: {path}");
    }

    if let Some(stem) = path.strip_suffix(".narinfo") {
        if !path.contains('/') && valid_narinfo_stem(stem) {
            return Ok(path.to_string());
        }
        bail!("invalid narinfo path: {path}");
    }

    if let Some(rest) = path.strip_prefix("nar/") {
        if valid_relative_segments(rest) && valid_nar_file_name(rest) {
            return Ok(path.to_string());
        }
        bail!("invalid NAR path: {path}");
    }

    bail!("unsupported cache path: {path}");
}

pub fn cache_file_path(cache_dir: &Path, path: &str) -> Result<PathBuf> {
    let path = sanitize_cache_path(path)?;
    Ok(cache_dir.join(path))
}

fn valid_narinfo_stem(stem: &str) -> bool {
    stem.len() == 32 && stem.chars().all(|c| NIX_BASE32.contains(c))
}

fn valid_relative_segments(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.ends_with('/')
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment.chars().all(valid_cache_file_char)
        })
}

fn valid_nar_file_name(path: &str) -> bool {
    let Some(file_name) = path.rsplit('/').next() else {
        return false;
    };
    file_name.ends_with(".nar") || file_name.contains(".nar.")
}

fn valid_cache_file_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+' | '=')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_cache_paths() {
        for path in [
            "nix-cache-info",
            "00000000000000000000000000000000.narinfo",
            "nar/abc123.nar",
            "nar/abc123.nar.xz",
            "nar/subdir/abc123.nar.zst",
        ] {
            assert_eq!(sanitize_cache_path(path).unwrap(), path);
        }
    }

    #[test]
    fn accepts_http_cache_paths() {
        assert_eq!(
            sanitize_http_cache_path("/nix-cache-info?priority=40").unwrap(),
            "nix-cache-info"
        );
        assert_eq!(
            sanitize_http_cache_path("/nar/abc123.nar.xz").unwrap(),
            "nar/abc123.nar.xz"
        );
    }

    #[test]
    fn rejects_bad_cache_paths() {
        for path in [
            "",
            "/nix-cache-info",
            "../nix-cache-info",
            "nar/../x.nar",
            "nar//x.nar",
            "nar/./x.nar",
            "nar/x",
            "nar/x nar",
            "nar/%2e%2e/x.nar",
            "nar\\x.nar",
            "foo",
            "0000000000000000000000000000000.narinfo",
            "00000000000000000000000000000000.narinfo/evil",
        ] {
            assert!(sanitize_cache_path(path).is_err(), "accepted {path}");
        }
    }
}
