use anyhow::Result;
use std::{collections::HashMap, fs, path::Path};

pub fn read_kv(path: &Path) -> Result<HashMap<String, String>> {
    let mut out = HashMap::new();
    if !path.exists() {
        return Ok(out);
    }
    for line in fs::read_to_string(path)?.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            out.insert(k.trim().to_string(), unquote(v.trim()));
        }
    }
    Ok(out)
}
pub fn write_kv(path: &Path, values: &HashMap<String, String>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut keys: Vec<_> = values.keys().collect();
    keys.sort();
    let text = keys
        .into_iter()
        .map(|k| format!("{}='{}'", k, values[k].replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let temp = path.with_extension(format!("{}.tmp", std::process::id()));
    fs::write(&temp, text)?;
    fs::rename(&temp, path)?;
    protect(path)?;
    Ok(())
}
fn unquote(v: &str) -> String {
    v.trim_matches('"').trim_matches('\'').replace("'\\''", "'")
}
#[cfg(windows)]
fn protect(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn protect(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replaces_existing_configuration_atomically() {
        let path =
            std::env::temp_dir().join(format!("rust-acmesh-config-{}.conf", uuid::Uuid::new_v4()));
        let mut first = HashMap::new();
        first.insert("Key".into(), "one".into());
        write_kv(&path, &first).unwrap();
        let mut second = HashMap::new();
        second.insert("Key".into(), "two".into());
        write_kv(&path, &second).unwrap();
        assert_eq!(read_kv(&path).unwrap()["Key"], "two");
    }
}
#[cfg(not(any(windows, unix)))]
fn protect(_path: &Path) -> Result<()> {
    Ok(())
}
