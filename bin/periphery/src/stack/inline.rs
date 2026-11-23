use std::{
  collections::BTreeSet,
  fs::{self, DirBuilder, OpenOptions},
  io::{Read, Write},
  os::unix::fs::{DirBuilderExt, OpenOptionsExt},
  path::{Path, PathBuf},
};

use super::{
  include::{ErrorKind, IncludeError},
  resolve::{
    PreparedSource, Resolved, WorkerRequest, resolve_prepared_sources,
  },
};
use anyhow::{Context, ensure};
use komodo_client::entities::stack::{
  ComposeResolutionError, ComposeResolutionSource,
  ComposeResolutionStage,
};
use komodo_client::entities::stack::{
  INLINE_MANIFEST, MAX_INLINE_BYTES, MAX_INLINE_FILES, StackConfig,
  validate_inline_path,
};
use periphery_client::api::compose::{
  ResolveComposeStack, ResolveComposeStackResponse,
};
use std::{collections::HashMap, time::Instant};

pub(super) async fn resolve_ui_sources(
  mut request: ResolveComposeStack,
  executable: &Path,
  secrets: &HashMap<String, String>,
  deadline: Instant,
  run: impl AsyncFnMut(
    &WorkerRequest,
    &str,
    Instant,
  ) -> Result<Resolved, IncludeError>,
) -> Result<ResolveComposeStackResponse, ComposeResolutionError> {
  let error = |kind| {
    ComposeResolutionError::new(kind, ComposeResolutionStage::Prepare)
  };
  request.validate()?;
  if request.request_identity.source != ComposeResolutionSource::Ui {
    return Err(error(ErrorKind::InvalidIdentity));
  }
  if !request.stack.config.skip_secret_interp {
    let mut interpolator =
      interpolate::Interpolator::new(None, secrets);
    interpolator
      .interpolate_string(&mut request.stack.config.file_contents)
      .map_err(|_| error(ErrorKind::Interpolation))?;
    interpolator
      .interpolate_string(&mut request.stack.config.environment)
      .map_err(|_| error(ErrorKind::Interpolation))?;
    for file in &mut request.stack.config.inline_files {
      interpolator
        .interpolate_string(&mut file.contents)
        .map_err(|_| error(ErrorKind::Interpolation))?;
    }
    request.replacers.extend(interpolator.secret_replacers);
  }
  let tree = PrivateSourceTree::new()
    .map_err(|_| error(ErrorKind::SourceAccess))?;
  let result = async {
    request
      .stack
      .config
      .inline_sources()
      .map_err(|_| error(ErrorKind::InvalidSource))?;
    write_sources(tree.path(), &request.stack.config)
      .map_err(|_| error(ErrorKind::SourceAccess))?;
    checked_path(
      tree.path(),
      &request.stack.config.env_file_path,
      true,
    )
    .map_err(|_| error(ErrorKind::InvalidPath))?;
    let environment = request
      .stack
      .config
      .env_vars()
      .map_err(|_| error(ErrorKind::InvalidSource))?;
    super::repository::write_environment(
      tree.path(),
      tree.path(),
      &request.stack.config.env_file_path,
      &environment,
    )
    .await?;
    let source = PreparedSource {
      directory: tree.path().to_path_buf(),
      source_root: Some(tree.path().to_path_buf()),
      revision: None,
    };
    resolve_prepared_sources(
      request, source, executable, secrets, deadline, run,
    )
    .await
  }
  .await;
  tree.close().map_err(|_| error(ErrorKind::SourceAccess))?;
  if Instant::now() >= deadline {
    return Err(error(ErrorKind::Timeout));
  }
  result
}

pub(super) struct PrivateSourceTree(Option<PathBuf>);

impl PrivateSourceTree {
  pub(super) fn new() -> anyhow::Result<Self> {
    let path = std::env::temp_dir()
      .join(format!("komodo-inline-{}", uuid::Uuid::new_v4()));
    DirBuilder::new().mode(0o700).create(&path)?;
    Ok(Self(Some(path)))
  }

  pub(super) fn path(&self) -> &Path {
    self
      .0
      .as_deref()
      .expect("private source tree already closed")
  }

  pub(super) fn close(mut self) -> anyhow::Result<()> {
    fs::remove_dir_all(self.path())?;
    self.0.take();
    Ok(())
  }
}

impl Drop for PrivateSourceTree {
  fn drop(&mut self) {
    if let Some(path) = &self.0
      && let Err(error) = fs::remove_dir_all(path)
    {
      warn!(%error, "Failed to clean up private UI source tree");
    }
  }
}

pub(super) fn checked_path(
  root: &Path,
  relative: &str,
  create_parents: bool,
) -> anyhow::Result<PathBuf> {
  validate_inline_path(relative)?;
  ensure!(
    fs::symlink_metadata(root)?.is_dir(),
    "UI source directory must not be a symlink"
  );
  let mut path = root.to_path_buf();
  let components =
    Path::new(relative).components().collect::<Vec<_>>();
  for (index, component) in components.iter().enumerate() {
    path.push(component);
    let last = index + 1 == components.len();
    match fs::symlink_metadata(&path) {
      Ok(metadata) => ensure!(
        if last {
          metadata.is_file()
        } else {
          metadata.is_dir()
        },
        "UI managed paths must be regular files and directories, without symlinks"
      ),
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
        if !last && create_parents {
          DirBuilder::new().mode(0o700).create(&path)?;
        } else {
          return Ok(root.join(relative));
        }
      }
      Err(error) => return Err(error.into()),
    }
  }
  Ok(path)
}

fn atomic_write(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
  let temporary = path
    .parent()
    .context("UI managed file requires a parent directory")?
    .join(format!(".komodo-write-{}", uuid::Uuid::new_v4()));
  let mut file = OpenOptions::new()
    .write(true)
    .create_new(true)
    .mode(0o600)
    .open(&temporary)?;
  let result = (|| {
    file.write_all(contents)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    anyhow::Ok(())
  })();
  if result.is_err() {
    fs::remove_file(&temporary)
      .context("Failed to clean up a managed UI source write")?;
  }
  result
}

fn read_manifest(root: &Path) -> anyhow::Result<BTreeSet<String>> {
  let path = checked_path(root, INLINE_MANIFEST, false)?;
  let mut contents = Vec::new();
  match fs::File::open(path) {
    Ok(file) => {
      file
        .take(MAX_INLINE_BYTES as u64 + 1)
        .read_to_end(&mut contents)?;
    }
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      return Ok(BTreeSet::new());
    }
    Err(error) => return Err(error.into()),
  }
  ensure!(
    contents.len() <= MAX_INLINE_BYTES,
    "UI ownership manifest is too large"
  );
  let paths: Vec<String> = serde_json::from_slice(&contents)
    .context("Invalid UI ownership manifest")?;
  ensure!(
    paths.len() < 2 * MAX_INLINE_FILES,
    "Invalid UI ownership manifest size"
  );
  let mut owned = BTreeSet::new();
  for path in paths {
    validate_inline_path(&path)?;
    ensure!(
      path != INLINE_MANIFEST && owned.insert(path),
      "Invalid UI ownership manifest entry"
    );
  }
  Ok(owned)
}

pub(super) fn write_sources(
  root: &Path,
  config: &StackConfig,
) -> anyhow::Result<()> {
  let sources = config.inline_sources()?;
  let previous = read_manifest(root)?;
  let current = config
    .inline_files
    .iter()
    .map(|file| file.path.clone())
    .collect::<BTreeSet<_>>();
  ensure!(
    previous.union(&current).count() < 2 * MAX_INLINE_FILES,
    "UI ownership cleanup must complete before adding more companions"
  );
  let manifest = checked_path(root, INLINE_MANIFEST, false)?;
  checked_path(root, &config.env_file_path, false)?;
  for (index, (path, _)) in sources.iter().enumerate() {
    let target = checked_path(root, path, false)?;
    ensure!(
      index == 0 || previous.contains(*path) || !target.exists(),
      "Refusing to overwrite an unowned UI companion file"
    );
  }
  for path in &previous {
    checked_path(root, path, false)?;
  }

  let mut created = Vec::new();
  let result = (|| {
    for (index, (path, contents)) in sources.iter().enumerate() {
      let target = checked_path(root, path, true)?;
      if index != 0 && !previous.contains(*path) {
        let mut file = OpenOptions::new()
          .write(true)
          .create_new(true)
          .mode(0o600)
          .open(&target)?;
        created.push((*path).to_string());
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
      } else {
        atomic_write(&target, contents.as_bytes())?;
      }
    }
    // Keep ownership of removed inputs until their individual cleanup succeeds.
    let retained = previous.union(&current).collect::<BTreeSet<_>>();
    atomic_write(&manifest, &serde_json::to_vec(&retained)?)?;
    anyhow::Ok(())
  })();
  if let Err(error) = result {
    for path in created {
      fs::remove_file(checked_path(root, &path, false)?)
        .context("Failed to roll back a new UI companion file")?;
    }
    return Err(error);
  }
  for path in previous.difference(&current) {
    if sources.iter().any(|(source, _)| source == path)
      || path == &config.env_file_path
    {
      continue;
    }
    let target = checked_path(root, path, false)?;
    match fs::remove_file(target) {
      Ok(()) => {}
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
      Err(error) => return Err(error.into()),
    }
  }
  atomic_write(&manifest, &serde_json::to_vec(&current)?)?;
  Ok(())
}
