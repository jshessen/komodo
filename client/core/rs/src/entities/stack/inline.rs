use std::{
  collections::BTreeSet,
  path::{Component, Path},
};

use anyhow::{bail, ensure};

use super::{StackConfig, default_stack_file_paths};

pub const INLINE_MANIFEST: &str = ".komodo-inline-files.json";
pub const MAX_INLINE_FILES: usize = 512;
pub const MAX_INLINE_BYTES: usize = 32 * 1024 * 1024;

pub fn validate_inline_path(path: &str) -> anyhow::Result<()> {
  ensure!(
    path.len() <= 4096,
    "UI source path exceeds the local path limit"
  );
  let components = Path::new(path)
    .components()
    .map(|component| match component {
      Component::Normal(value) => value.to_str(),
      _ => None,
    })
    .collect::<Option<Vec<_>>>();
  ensure!(
    !path.is_empty()
      && !path.contains(['\0', '\\', ':'])
      && components.as_ref().is_some_and(|components| {
        !components.contains(&".git")
          && components.iter().all(|component| component.len() <= 255)
          && components.join("/") == path
      }),
    "UI source paths must be normalized relative paths without traversal"
  );
  Ok(())
}

impl StackConfig {
  pub fn inline_sources(&self) -> anyhow::Result<Vec<(&str, &str)>> {
    ensure!(
      !self.file_contents.trim().is_empty(),
      "UI stacks require primary Compose contents"
    );
    ensure!(
      self.inline_files.len() < MAX_INLINE_FILES,
      "Too many UI source files"
    );
    let roots = if self.file_paths.is_empty() {
      default_stack_file_paths()
    } else {
      &self.file_paths
    };
    let mut files =
      vec![(roots[0].as_str(), self.file_contents.as_str())];
    files.extend(
      self
        .inline_files
        .iter()
        .map(|file| (file.path.as_str(), file.contents.as_str())),
    );
    let mut paths = BTreeSet::new();
    let mut bytes = 0usize;
    for (path, contents) in &files {
      validate_inline_path(path)?;
      ensure!(paths.insert(*path), "UI source paths must be unique");
      bytes = bytes
        .checked_add(contents.len())
        .filter(|bytes| *bytes <= MAX_INLINE_BYTES)
        .ok_or_else(|| {
          anyhow::anyhow!("UI source text exceeds the size limit")
        })?;
    }
    for root in roots {
      validate_inline_path(root)?;
      ensure!(
        paths.contains(root.as_str()),
        "Every configured UI Compose root must have supplied contents"
      );
    }
    validate_inline_path(&self.env_file_path)?;
    for reserved in [self.env_file_path.as_str(), INLINE_MANIFEST] {
      ensure!(
        paths.insert(reserved),
        "UI sources collide with a reserved managed file"
      );
    }
    for path in &paths {
      let mut parent = Path::new(path).parent();
      while let Some(directory) = parent {
        if let Some(directory) = directory.to_str()
          && paths.contains(directory)
        {
          bail!("UI source file and directory paths collide");
        }
        parent = directory.parent();
      }
    }

    Ok(files)
  }
}

#[cfg(test)]
mod tests {
  use super::super::PartialStackConfig;
  use super::*;
  use crate::entities::{FileContents, stack::Stack};

  #[test]
  fn compose_include_inline_config_preserves_legacy_defaults_and_explicit_clear()
  -> anyhow::Result<()> {
    let legacy: StackConfig =
      serde_json::from_value(serde_json::json!({}))?;
    assert!(legacy.inline_files.is_empty());
    let omitted: PartialStackConfig =
      serde_json::from_value(serde_json::json!({}))?;
    assert!(omitted.inline_files.is_none());
    let clear: PartialStackConfig = serde_json::from_value(
      serde_json::json!({"inline_files": []}),
    )?;
    assert_eq!(clear.inline_files, Some(Vec::new()));
    assert!(
      serde_json::to_value(omitted)?.get("inline_files").is_none()
    );
    let partial: PartialStackConfig = serde_json::from_value(
      serde_json::json!({
        "file_contents":"include: [modules/child.yaml]",
        "inline_files":[{"path":"modules/child.yaml","contents":"services: {}"}],
      }),
    )?;
    let full: StackConfig = partial.into();
    assert_eq!(full.inline_sources()?.len(), 2);
    assert!(full.file_paths.is_empty());
    Ok(())
  }

  #[test]
  fn compose_include_inline_companions_are_tracked_without_additional_roots()
  -> anyhow::Result<()> {
    let mut stack = Stack::default();
    stack.config.file_paths =
      vec!["compose.yaml".into(), "override.yaml".into()];
    stack.config.file_contents =
      "include: [modules/child.yaml]".into();
    stack.config.inline_files = vec![FileContents {
      path: "modules/child.yaml".into(),
      contents: "services: {}".into(),
    }];
    let tracked = stack.all_tracked_file_paths();
    assert_eq!(
      tracked,
      ["compose.yaml", "override.yaml", "modules/child.yaml"]
    );
    let dependencies = stack.all_file_dependencies();
    assert_eq!(dependencies.len(), 3);
    assert_eq!(dependencies[2].path, "modules/child.yaml");
    assert_eq!(
      stack.compose_file_paths(),
      ["compose.yaml", "override.yaml"]
    );
    Ok(())
  }
}
