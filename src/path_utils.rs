//! Path manipulation utilities for hierarchical folder navigation
//!
//! This module provides functions for working with Unix-style paths in the storage system.
//! All paths use forward slashes and follow these conventions:
//! - Root is always "/"
//! - No trailing slashes except for display purposes (`format_full_path` with `is_folder=true`)
//! - ".." navigates up one level
//! - "." refers to current directory

/// Format a full path by joining folder path and item name
///
/// # Arguments
/// * `folder_path` - The folder path (e.g., "/", "/work", "work")
/// * `key` - The item name (e.g., "secret", "`api_key`")
/// * `is_folder` - Whether to add a trailing slash for display
///
/// # Examples
/// ```
/// use rcypher::format_full_path;
/// assert_eq!(format_full_path("/", "key", false), "/key");
/// assert_eq!(format_full_path("/work", "key", false), "/work/key");
/// assert_eq!(format_full_path("/work", "folder", true), "/work/folder/");
/// assert_eq!(format_full_path("", "key", false), "key");
/// ```
pub fn format_full_path(folder_path: &str, key: &str, is_folder: bool) -> String {
    let path = if folder_path.is_empty() {
        key.to_string()
    } else if folder_path == "/" {
        format!("/{key}")
    } else {
        format!("{}/{key}", folder_path.trim_end_matches('/'))
    };

    if is_folder { format!("{path}/") } else { path }
}

/// Compute relative path from root to path
///
/// Returns the path relative to root, with no leading or trailing slashes.
/// If path equals root, returns empty string.
///
/// # Arguments
/// * `root` - The root path to compute relative to
/// * `path` - The target path
///
/// # Examples
/// ```
/// use rcypher::relative_path_from;
/// assert_eq!(relative_path_from("/", "/work"), "work");
/// assert_eq!(relative_path_from("/", "/work/api"), "work/api");
/// assert_eq!(relative_path_from("/work", "/work/api"), "api");
/// assert_eq!(relative_path_from("/", "/"), "");
/// // Handles trailing slashes
/// assert_eq!(relative_path_from("/", "/work/"), "work");
/// assert_eq!(relative_path_from("/work/", "/work/api"), "api");
/// ```
pub fn relative_path_from(root: &str, path: &str) -> String {
    // Normalize both paths by trimming slashes
    let root_normalized = root.trim_matches('/');
    let path_normalized = path.trim_matches('/');

    if root_normalized.is_empty() {
        // Root is "/"
        path_normalized.to_string()
    } else if path_normalized == root_normalized {
        // Same path
        String::new()
    } else if let Some(relative) = path_normalized.strip_prefix(root_normalized) {
        // path is under root
        relative.trim_start_matches('/').to_string()
    } else {
        // path is not under root - return as is
        path_normalized.to_string()
    }
}

/// Normalize a path by resolving . and .. components
///
/// # Arguments
/// * `path` - The path to normalize
///
/// # Examples
/// ```
/// use rcypher::normalize_path;
/// assert_eq!(normalize_path("/work/../personal"), "/personal");
/// assert_eq!(normalize_path("/work/./secret"), "/work/secret");
/// assert_eq!(normalize_path("/work//secret"), "/work/secret");
/// assert_eq!(normalize_path("/../.."), "/");
/// ```
pub fn normalize_path(path: &str) -> String {
    let mut components: Vec<&str> = Vec::new();

    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            name => {
                components.push(name);
            }
        }
    }

    if components.is_empty() {
        String::from("/")
    } else {
        format!("/{}", components.join("/"))
    }
}

/// Resolve a path (absolute or relative) from a given current directory
///
/// Handles both absolute paths (starting with /) and relative paths (using . and ..).
///
/// # Arguments
/// * `current_path` - The current working directory
/// * `path` - The path to resolve (absolute or relative)
///
/// # Examples
/// ```
/// use rcypher::resolve_path;
/// assert_eq!(resolve_path("/work", "../personal"), "/personal");
/// assert_eq!(resolve_path("/work", "secret"), "/work/secret");
/// assert_eq!(resolve_path("/work", "/absolute"), "/absolute");
/// assert_eq!(resolve_path("/", "work"), "/work");
/// assert_eq!(resolve_path("/work/api", ".."), "/work");
/// ```
pub fn resolve_path(current_path: &str, path: &str) -> String {
    if path.is_empty() {
        return current_path.to_string();
    }

    if path.starts_with('/') {
        // Absolute path
        return normalize_path(path);
    }

    // Relative path - resolve from current directory
    let mut components: Vec<&str> = if current_path == "/" {
        Vec::new()
    } else {
        current_path.trim_matches('/').split('/').collect()
    };

    // Process each component of the path
    for component in path.trim_end_matches('/').split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            name => {
                components.push(name);
            }
        }
    }

    if components.is_empty() {
        String::from("/")
    } else {
        format!("/{}", components.join("/"))
    }
}

/// Parse a key path into folder path and key name
///
/// Splits a path like "work/secret" into ("/work", "secret") relative to `current_path`.
/// If no slash is present, returns (`current_path`, `key_arg`).
///
/// # Arguments
/// * `current_path` - The current working directory
/// * `key_arg` - The key path argument (may contain slashes)
///
/// # Examples
/// ```
/// use rcypher::parse_key_path;
/// assert_eq!(parse_key_path("/", "work/secret"), ("/work".to_string(), "secret"));
/// assert_eq!(parse_key_path("/", "secret"), ("/".to_string(), "secret"));
/// assert_eq!(parse_key_path("/work", "../personal/key"), ("/personal".to_string(), "key"));
/// assert_eq!(parse_key_path("/work", "key"), ("/work".to_string(), "key"));
/// ```
pub fn parse_key_path<'a>(current_path: &str, key_arg: &'a str) -> (String, &'a str) {
    if let Some(last_slash) = key_arg.rfind('/') {
        let dir_part = &key_arg[..last_slash];
        let key_name = &key_arg[last_slash + 1..];
        let resolved_path = resolve_path(current_path, dir_part);
        (resolved_path, key_name)
    } else {
        (current_path.to_string(), key_arg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_full_path_root() {
        assert_eq!(format_full_path("/", "key", false), "/key");
        assert_eq!(format_full_path("/", "folder", true), "/folder/");
    }

    #[test]
    fn test_format_full_path_subfolder() {
        assert_eq!(format_full_path("/work", "secret", false), "/work/secret");
        assert_eq!(
            format_full_path("/work", "subfolder", true),
            "/work/subfolder/"
        );
    }

    #[test]
    fn test_format_full_path_nested() {
        assert_eq!(format_full_path("/work/api", "key", false), "/work/api/key");
        assert_eq!(
            format_full_path("/work/api", "folder", true),
            "/work/api/folder/"
        );
    }

    #[test]
    fn test_format_full_path_empty_folder() {
        assert_eq!(format_full_path("", "key", false), "key");
        assert_eq!(format_full_path("", "folder", true), "folder/");
    }

    #[test]
    fn test_format_full_path_trailing_slash() {
        // Should handle trailing slashes in folder_path
        assert_eq!(format_full_path("/work/", "key", false), "/work/key");
    }

    #[test]
    fn test_relative_path_from_root() {
        assert_eq!(relative_path_from("/", "/work"), "work");
        assert_eq!(relative_path_from("/", "/work/api"), "work/api");
        assert_eq!(relative_path_from("/", "/"), "");
    }

    #[test]
    fn test_relative_path_from_subfolder() {
        assert_eq!(relative_path_from("/work", "/work/api"), "api");
        assert_eq!(relative_path_from("/work", "/work/api/key"), "api/key");
        assert_eq!(relative_path_from("/work", "/work"), "");
    }

    #[test]
    fn test_relative_path_from_trailing_slashes() {
        // Should handle trailing slashes in both arguments
        assert_eq!(relative_path_from("/", "/work/"), "work");
        assert_eq!(relative_path_from("/work/", "/work/api"), "api");
        assert_eq!(relative_path_from("/work/", "/work/api/"), "api");
    }

    #[test]
    fn test_relative_path_from_not_under_root() {
        // When path is not under root, return path as-is (normalized)
        assert_eq!(relative_path_from("/work", "/personal"), "personal");
    }

    #[test]
    fn test_normalize_path_simple() {
        assert_eq!(normalize_path("/work/secret"), "/work/secret");
        assert_eq!(normalize_path("/"), "/");
    }

    #[test]
    fn test_normalize_path_parent_dir() {
        assert_eq!(normalize_path("/work/../personal"), "/personal");
        assert_eq!(normalize_path("/work/api/../../personal"), "/personal");
        assert_eq!(normalize_path("/../.."), "/");
    }

    #[test]
    fn test_normalize_path_current_dir() {
        assert_eq!(normalize_path("/work/./secret"), "/work/secret");
        assert_eq!(normalize_path("/./work"), "/work");
    }

    #[test]
    fn test_normalize_path_double_slashes() {
        assert_eq!(normalize_path("/work//secret"), "/work/secret");
        assert_eq!(normalize_path("//work///secret//"), "/work/secret");
    }

    #[test]
    fn test_resolve_path_absolute() {
        assert_eq!(resolve_path("/work", "/absolute"), "/absolute");
        assert_eq!(resolve_path("/", "/work/secret"), "/work/secret");
    }

    #[test]
    fn test_resolve_path_relative() {
        assert_eq!(resolve_path("/work", "secret"), "/work/secret");
        assert_eq!(resolve_path("/", "work"), "/work");
        assert_eq!(resolve_path("/work", "api/key"), "/work/api/key");
    }

    #[test]
    fn test_resolve_path_parent_dir() {
        assert_eq!(resolve_path("/work", ".."), "/");
        assert_eq!(resolve_path("/work/api", ".."), "/work");
        assert_eq!(resolve_path("/work", "../personal"), "/personal");
        assert_eq!(resolve_path("/work/api", "../../personal"), "/personal");
    }

    #[test]
    fn test_resolve_path_current_dir() {
        assert_eq!(resolve_path("/work", "."), "/work");
        assert_eq!(resolve_path("/work", "./secret"), "/work/secret");
    }

    #[test]
    fn test_resolve_path_empty() {
        assert_eq!(resolve_path("/work", ""), "/work");
        assert_eq!(resolve_path("/", ""), "/");
    }

    #[test]
    fn test_resolve_path_from_root() {
        assert_eq!(resolve_path("/", "work"), "/work");
        assert_eq!(resolve_path("/", "work/api"), "/work/api");
        assert_eq!(resolve_path("/", ".."), "/");
    }

    #[test]
    fn test_parse_key_path_simple() {
        assert_eq!(parse_key_path("/", "secret"), ("/".to_string(), "secret"));
        assert_eq!(parse_key_path("/work", "key"), ("/work".to_string(), "key"));
    }

    #[test]
    fn test_parse_key_path_with_folder() {
        assert_eq!(
            parse_key_path("/", "work/secret"),
            ("/work".to_string(), "secret")
        );
        assert_eq!(
            parse_key_path("/", "work/api/key"),
            ("/work/api".to_string(), "key")
        );
    }

    #[test]
    fn test_parse_key_path_absolute() {
        assert_eq!(
            parse_key_path("/work", "/personal/key"),
            ("/personal".to_string(), "key")
        );
    }

    #[test]
    fn test_parse_key_path_parent_dir() {
        assert_eq!(
            parse_key_path("/work", "../personal/key"),
            ("/personal".to_string(), "key")
        );
        assert_eq!(
            parse_key_path("/work/api", "../../key"),
            ("/".to_string(), "key")
        );
    }

    #[test]
    fn test_parse_key_path_current_dir() {
        assert_eq!(
            parse_key_path("/work", "./key"),
            ("/work".to_string(), "key")
        );
    }
}
