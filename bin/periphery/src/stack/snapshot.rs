use std::{
  collections::BTreeMap,
  fs::File,
  io::Write,
  os::fd::{AsRawFd, FromRawFd},
  path::{Path, PathBuf},
};

use anyhow::{Context, anyhow, ensure};
use serde_yaml_ng::{Mapping, Value};

use super::include::{DependencyKind, Graph, MAX_BYTES, MAX_FILES};

pub(super) struct SealedSnapshot {
  files: Vec<File>,
  bytes: usize,
}

impl SealedSnapshot {
  pub(super) fn new() -> Self {
    Self {
      files: Vec::new(),
      bytes: 0,
    }
  }

  pub(super) fn add(
    &mut self,
    contents: &[u8],
  ) -> anyhow::Result<PathBuf> {
    ensure!(
      self.files.len() < MAX_FILES,
      "Snapshot file limit exceeded"
    );
    let bytes = self
      .bytes
      .checked_add(contents.len())
      .context("Snapshot byte limit exceeded")?;
    ensure!(bytes <= MAX_BYTES, "Snapshot byte limit exceeded");
    // The returned descriptor is owned by File and never inherited by the child.
    let fd = unsafe {
      libc::memfd_create(
        c"komodo-compose-snapshot".as_ptr(),
        libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
      )
    };
    if fd < 0 {
      return Err(std::io::Error::last_os_error())
        .context("Cannot create immutable Compose source");
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file
      .write_all(contents)
      .context("Cannot write immutable Compose source")?;
    let seals = libc::F_SEAL_WRITE
      | libc::F_SEAL_GROW
      | libc::F_SEAL_SHRINK
      | libc::F_SEAL_SEAL;
    if unsafe {
      libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals)
    } < 0
    {
      return Err(std::io::Error::last_os_error())
        .context("Cannot seal immutable Compose source");
    }
    let path = PathBuf::from(format!(
      "/proc/{}/fd/{}",
      std::process::id(),
      file.as_raw_fd()
    ));
    self.files.push(file);
    self.bytes = bytes;
    Ok(path)
  }
}

pub(crate) struct CapturedCompose {
  _storage: SealedSnapshot,
  pub(crate) roots: Vec<PathBuf>,
  pub(crate) env_files: Vec<PathBuf>,
  pub(crate) project_directory: PathBuf,
}

impl CapturedCompose {
  pub(super) fn from_graph(graph: &Graph) -> anyhow::Result<Self> {
    ensure!(
      !graph.has_untracked_remote
        && !graph.contexts.is_empty()
        && !graph.contexts.iter().any(|context| {
          context
            .context
            .environment
            .keys()
            .any(|key| key.starts_with("COMPOSE_"))
        })
        && !graph.dependencies.iter().any(|dependency| dependency
          .kind
          == DependencyKind::Auxiliary),
      "Compose sources cannot be captured safely"
    );
    let mut capture = Capture {
      graph,
      storage: SealedSnapshot::new(),
      contexts: (0..graph.contexts.len()).map(|_| None).collect(),
      environments: BTreeMap::new(),
    };
    let roots = capture.context(0)?;
    let mut env_files =
      capture.environments(&graph.root_env_files)?;
    if env_files.is_empty() {
      env_files.push(PathBuf::from("/dev/null"));
    }
    let project_directory =
      graph.contexts[0].context.project_directory.clone();
    Ok(Self {
      _storage: capture.storage,
      roots,
      env_files,
      project_directory,
    })
  }
}

struct Capture<'a> {
  graph: &'a Graph,
  storage: SealedSnapshot,
  contexts: Vec<Option<Vec<PathBuf>>>,
  environments: BTreeMap<PathBuf, PathBuf>,
}

impl Capture<'_> {
  fn environments(
    &mut self,
    sources: &[PathBuf],
  ) -> anyhow::Result<Vec<PathBuf>> {
    let mut result = Vec::with_capacity(sources.len());
    for source in sources {
      let staged = if let Some(staged) = self.environments.get(source)
      {
        staged.clone()
      } else {
        let contents = self
          .graph
          .contents
          .get(source)
          .context("Captured environment source is missing")?;
        let staged = self.storage.add(contents.as_bytes())?;
        self.environments.insert(source.clone(), staged.clone());
        staged
      };
      result.push(staged);
    }
    Ok(result)
  }

  fn context(
    &mut self,
    index: usize,
  ) -> anyhow::Result<Vec<PathBuf>> {
    if let Some(staged) = &self.contexts[index] {
      return Ok(staged.clone());
    }
    let context = &self.graph.contexts[index];
    ensure!(
      context.source_identities.len() == context.context.paths.len(),
      "Captured Compose context is incomplete"
    );
    let mut staged =
      Vec::with_capacity(context.source_identities.len());
    for (file_index, source) in
      context.source_identities.iter().enumerate()
    {
      let text = self
        .graph
        .contents
        .get(source)
        .context("Captured Compose source is missing")?;
      let mut model: Value =
        serde_yaml_ng::from_str(text).map_err(|_| {
          anyhow!("Cannot parse captured Compose source")
        })?;
      validate_model(&model)?;
      for edge in context
        .includes
        .iter()
        .filter(|edge| edge.declaring_file == file_index)
      {
        let child =
          edge.child.context("Remote includes cannot be captured")?;
        let child_paths = self.context(child)?;
        let env_files = self.environments(&edge.env_files)?;
        let include = model
          .as_mapping_mut()
          .and_then(|model| model.get_mut("include"))
          .and_then(Value::as_sequence_mut)
          .and_then(|includes| includes.get_mut(edge.include_index))
          .context("Captured include context is inconsistent")?;
        let mut replacement = Mapping::new();
        replacement.insert(
          Value::String("path".into()),
          Value::Sequence(
            child_paths
              .iter()
              .map(|path| compose_path(path))
              .collect::<anyhow::Result<_>>()?,
          ),
        );
        replacement.insert(
          Value::String("project_directory".into()),
          compose_path(
            &self.graph.contexts[child].context.project_directory,
          )?,
        );
        let env_files = if env_files.is_empty() {
          vec![Value::String("/dev/null".into())]
        } else {
          env_files
            .iter()
            .map(|path| compose_path(path))
            .collect::<anyhow::Result<_>>()?
        };
        replacement.insert(
          Value::String("env_file".into()),
          Value::Sequence(env_files),
        );
        *include = Value::Mapping(replacement);
      }
      let contents =
        serde_yaml_ng::to_string(&model).map_err(|_| {
          anyhow!("Cannot render captured Compose source")
        })?;
      staged.push(self.storage.add(contents.as_bytes())?);
    }
    self.contexts[index] = Some(staged.clone());
    Ok(staged)
  }
}

fn compose_path(path: &Path) -> anyhow::Result<Value> {
  let path = path.to_str().context("Compose path is not UTF-8")?;
  Ok(Value::String(path.replace('$', "$$")))
}

fn validate_model(model: &Value) -> anyhow::Result<()> {
  fn reject_unsupported_values(value: &Value) -> anyhow::Result<()> {
    match value {
      Value::Tagged(_) => {
        Err(anyhow!("Tagged Compose sources cannot be captured"))
      }
      Value::Mapping(mapping) => {
        ensure!(
          !mapping.contains_key("<<"),
          "Compose YAML merges cannot be captured"
        );
        for (key, value) in mapping {
          reject_unsupported_values(key)?;
          reject_unsupported_values(value)?;
        }
        Ok(())
      }
      Value::Sequence(values) => {
        for value in values {
          reject_unsupported_values(value)?;
        }
        Ok(())
      }
      _ => Ok(()),
    }
  }
  reject_unsupported_values(model)?;
  let model = model
    .as_mapping()
    .context("Compose source is not a mapping")?;
  ensure!(
    !model.contains_key("configs") && !model.contains_key("secrets"),
    "Compose configs and secrets cannot be captured"
  );
  if let Some(services) = model.get("services") {
    let services =
      services.as_mapping().context("Invalid Compose services")?;
    for service in services.values() {
      let service =
        service.as_mapping().context("Invalid Compose service")?;
      for key in service.keys() {
        let key =
          key.as_str().context("Invalid Compose service field")?;
        ensure!(
          matches!(
            key,
            "image"
              | "command"
              | "entrypoint"
              | "environment"
              | "ports"
              | "volumes"
              | "networks"
              | "depends_on"
              | "restart"
              | "profiles"
              | "container_name"
              | "labels"
              | "healthcheck"
              | "deploy"
              | "pull_policy"
              | "user"
              | "working_dir"
              | "hostname"
              | "init"
              | "stop_grace_period"
          ) || key.starts_with("x-"),
          "Compose service uses an uncaptured input or unsupported field"
        );
      }
    }
  }
  Ok(())
}

pub(super) fn validate_deployment_graph(
  graph: &Graph,
) -> anyhow::Result<()> {
  fn no_interpolation(value: &Value) -> anyhow::Result<()> {
    match value {
      Value::String(value) => ensure!(
        !value.contains('$'),
        "Compose interpolation cannot be captured as change evidence"
      ),
      Value::Sequence(values) => {
        for value in values {
          no_interpolation(value)?;
        }
      }
      Value::Mapping(values) => {
        for (key, value) in values {
          no_interpolation(key)?;
          no_interpolation(value)?;
        }
      }
      Value::Tagged(_) => {
        return Err(anyhow!(
          "Tagged Compose sources cannot be captured"
        ));
      }
      _ => {}
    }
    Ok(())
  }
  for dependency in graph
    .dependencies
    .iter()
    .filter(|dependency| dependency.kind == DependencyKind::Compose)
  {
    let text = graph
      .contents
      .get(&dependency.path)
      .context("Captured Compose source is missing")?;
    let model: Value = serde_yaml_ng::from_str(text)
      .map_err(|_| anyhow!("Cannot parse captured Compose source"))?;
    no_interpolation(&model)?;
    let fields = model
      .as_mapping()
      .context("Compose source is not a mapping")?;
    for field in fields.keys() {
      let field =
        field.as_str().context("Invalid Compose source field")?;
      ensure!(
        matches!(
          field,
          "version"
            | "name"
            | "include"
            | "services"
            | "networks"
            | "volumes"
        ) || field.starts_with("x-"),
        "Compose source uses an unsupported field"
      );
    }
    if let Some(services) = model.get("services") {
      let services =
        services.as_mapping().context("Invalid Compose services")?;
      for service in services.values() {
        let service =
          service.as_mapping().context("Invalid Compose service")?;
        if let Some(environment) = service.get("environment") {
          match environment {
            Value::Mapping(values) => ensure!(
              values.values().all(|value| !value.is_null()),
              "Inherited service environment cannot be captured"
            ),
            Value::Sequence(values) => ensure!(
              values.iter().all(|value| value.as_str().is_some_and(
                |value| value
                  .split_once('=')
                  .is_some_and(|(key, _)| !key.is_empty())
              )),
              "Inherited service environment cannot be captured"
            ),
            _ => return Err(anyhow!("Invalid service environment")),
          }
        }
      }
    }
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use std::{
    collections::BTreeMap, fs, os::unix::fs::MetadataExt,
    os::unix::fs::symlink, process::Command,
  };

  use anyhow::{Context, ensure};

  use super::{
    CapturedCompose, SealedSnapshot, validate_deployment_graph,
  };
  use crate::stack::Fixture;
  use crate::stack::include::inspect;

  #[test]
  fn compose_include_snapshot_seals_inputs_and_cleans_up()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let original = fixture.root.join("source");
    fs::write(&original, b"initial")?;
    let mut snapshot = SealedSnapshot::new();
    let staged = snapshot.add(&fs::read(&original)?)?;
    fs::write(&original, b"changed")?;
    assert_eq!(fs::read(&staged)?, b"initial");
    assert!(fs::write(&staged, b"changed").is_err());
    let result = Command::new("cat").arg(&staged).output()?;
    assert!(result.status.success());
    assert_eq!(result.stdout, b"initial");
    fs::write(&original, b"initial")?;
    assert_eq!(fs::read(&staged)?, b"initial");
    let captured = fs::File::open(&staged)?;
    let identity = captured.metadata()?;
    drop(snapshot);
    if let Ok(reused) = fs::metadata(&staged) {
      assert_ne!(
        (reused.dev(), reused.ino()),
        (identity.dev(), identity.ino()),
        "snapshot descriptor still refers to the captured file"
      );
    }
    Ok(())
  }

  #[test]
  fn compose_include_snapshot_uses_captured_symlink_target()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(
      fixture.root.join("compose.yaml"),
      "include: [child.yaml]\n",
    )?;
    fs::write(
      fixture.root.join("first.yaml"),
      "services:\n  old:\n    image: synthetic/old\n",
    )?;
    fs::write(
      fixture.root.join("second.yaml"),
      "services:\n  new:\n    image: synthetic/new\n",
    )?;
    let link = fixture.root.join("child.yaml");
    symlink("first.yaml", &link)?;
    let graph = inspect(
      &fixture.root,
      &["compose.yaml".into()],
      &[],
      BTreeMap::new(),
    )?;
    fs::remove_file(&link)?;
    symlink("second.yaml", &link)?;
    let snapshot = CapturedCompose::from_graph(&graph)?;
    let root: serde_yaml_ng::Value =
      serde_yaml_ng::from_slice(&fs::read(&snapshot.roots[0])?)?;
    let child = root["include"][0]["path"][0]
      .as_str()
      .expect("staged child path");
    let staged_child = fs::read_to_string(child)?;
    assert!(staged_child.contains("synthetic/old"));
    assert!(!staged_child.contains("synthetic/new"));
    Ok(())
  }

  #[test]
  fn compose_include_snapshot_uses_captured_env_symlink_target()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(fixture.root.join("first.env"), "VALUE=original\n")?;
    fs::write(fixture.root.join("second.env"), "VALUE=changed\n")?;
    let link = fixture.root.join("selected.env");
    symlink("first.env", &link)?;
    let graph = inspect(
      &fixture.root,
      &["compose.yaml".into()],
      &["selected.env".into()],
      BTreeMap::new(),
    )?;
    fs::remove_file(&link)?;
    symlink("second.env", &link)?;
    let snapshot = CapturedCompose::from_graph(&graph)?;
    assert_eq!(
      fs::read_to_string(&snapshot.env_files[0])?,
      "VALUE=original\n"
    );
    Ok(())
  }

  #[test]
  fn compose_include_snapshot_rejects_uncaptured_inputs()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    for source in [
      "services:\n  app:\n    image: synthetic/app\n    env_file: app.env\n",
      "services:\n  app:\n    image: synthetic/app\n    extends: {service: other}\n",
      "services:\n  app:\n    image: synthetic/app\n    build: .\n",
      "configs:\n  app: {file: ./app.conf}\nservices: {}\n",
      "services:\n  app:\n    image: !reset null\n",
      "x-common: &common {image: synthetic/app}\nservices:\n  app:\n    <<: *common\n",
    ] {
      fs::write(fixture.root.join("compose.yaml"), source)?;
      let graph = inspect(
        &fixture.root,
        &["compose.yaml".into()],
        &[],
        BTreeMap::new(),
      )?;
      assert!(CapturedCompose::from_graph(&graph).is_err());
    }
    Ok(())
  }

  #[test]
  fn compose_include_deployment_rejects_untracked_process_environment()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    for source in [
      "services:\n  app:\n    image: synthetic/app:${TAG}\n",
      "services:\n  app:\n    image: synthetic/app\n    environment: [INHERITED]\n",
      "services:\n  app:\n    image: synthetic/app\n    environment: {INHERITED: null}\n",
    ] {
      fs::write(fixture.root.join("compose.yaml"), source)?;
      let graph = inspect(
        &fixture.root,
        &["compose.yaml".into()],
        &[],
        BTreeMap::new(),
      )?;
      assert!(validate_deployment_graph(&graph).is_err());
    }
    Ok(())
  }

  #[test]
  fn compose_include_snapshot_rejects_compose_environment_controls()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(
      fixture.root.join(".env"),
      "COMPOSE_DISABLE_ENV_FILE=true\n",
    )?;
    let graph = inspect(
      &fixture.root,
      &["compose.yaml".into()],
      &[],
      BTreeMap::new(),
    )?;
    assert!(CapturedCompose::from_graph(&graph).is_err());
    Ok(())
  }

  #[test]
  #[ignore = "requires Docker Compose"]
  fn compose_include_snapshot_cli_model_parity() -> anyhow::Result<()>
  {
    for name in ["nested", "long"] {
      let fixture = Fixture::new(name)?;
      assert_model_parity(&fixture, &["compose.yaml"], &[])?;
    }
    Ok(())
  }

  #[test]
  #[ignore = "requires Docker Compose"]
  fn compose_include_snapshot_cli_multiple_contexts_and_source_race()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    for (name, contents) in [
      (
        "compose.yaml",
        "include:\n  - path: common.yaml\n    project_directory: a\nservices:\n  root:\n    image: synthetic/root:${ROOT_TAG}\n",
      ),
      (
        "override.yaml",
        "include:\n  - path: common.yaml\n    project_directory: b\nservices:\n  root:\n    image: synthetic/override:${ROOT_TAG}\n",
      ),
      ("common.yaml", "include: [\"${CHILD:?required}\"]\n"),
      ("first.env", "ROOT_TAG=one\n"),
      ("second.env", "ROOT_TAG=two\n"),
    ] {
      fs::write(fixture.root.join(name), contents)?;
    }
    for directory in ["a", "b"] {
      fs::create_dir(fixture.root.join(directory))?;
      fs::write(
        fixture.root.join(directory).join(".env"),
        "CHILD=child.yaml\n",
      )?;
      fs::write(
        fixture.root.join(directory).join("child.yaml"),
        format!(
          "services:\n  {directory}:\n    image: synthetic/{directory}\n"
        ),
      )?;
    }
    assert_model_parity(
      &fixture,
      &["compose.yaml", "override.yaml"],
      &["first.env", "second.env"],
    )
  }

  #[test]
  #[ignore = "requires Docker Compose"]
  fn compose_include_snapshot_cli_relative_bind_paths()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::create_dir(fixture.root.join("child"))?;
    fs::write(
      fixture.root.join("compose.yaml"),
      "include: [child/compose.yaml]\nservices:\n  root:\n    image: synthetic/root\n    volumes: [./root-data:/data]\n",
    )?;
    fs::write(
      fixture.root.join("child/compose.yaml"),
      "services:\n  child:\n    image: synthetic/child\n    volumes: [./child-data:/data]\n",
    )?;
    assert_model_parity(&fixture, &["compose.yaml"], &[])
  }

  #[test]
  #[ignore = "requires Docker Compose"]
  fn compose_include_snapshot_cli_ignores_later_default_env()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(
      fixture.root.join("compose.yaml"),
      "services:\n  app:\n    image: 'synthetic/app:${TAG:-original}'\n",
    )?;
    let graph = inspect(
      &fixture.root,
      &["compose.yaml".into()],
      &[],
      BTreeMap::new(),
    )?;
    let snapshot = CapturedCompose::from_graph(&graph)?;
    fs::write(fixture.root.join(".env"), "TAG=changed\n")?;
    let model = snapshot_model(&fixture, &snapshot)?;
    assert_eq!(
      model["services"]["app"]["image"],
      "synthetic/app:original"
    );
    Ok(())
  }

  fn assert_model_parity(
    fixture: &Fixture,
    roots: &[&str],
    env_files: &[&str],
  ) -> anyhow::Result<()> {
    let expected = fixture.compose_model(roots, env_files)?;
    let graph = inspect(
      &fixture.root,
      &roots.iter().map(|root| (*root).into()).collect::<Vec<_>>(),
      &env_files
        .iter()
        .map(|file| (*file).into())
        .collect::<Vec<_>>(),
      BTreeMap::new(),
    )?;
    let snapshot = CapturedCompose::from_graph(&graph)?;
    assert_eq!(snapshot_model(fixture, &snapshot)?, expected);
    let root = fixture.root.join(roots[0]);
    let original = fs::read(&root)?;
    fs::write(
      &root,
      b"services:\n  changed:\n    image: synthetic/changed\n",
    )?;
    assert_eq!(snapshot_model(fixture, &snapshot)?, expected);
    let replacement = fixture.root.join("replacement.yaml");
    fs::write(
      &replacement,
      b"services:\n  replacement:\n    image: synthetic/replacement\n",
    )?;
    fs::rename(&replacement, &root)?;
    assert_eq!(snapshot_model(fixture, &snapshot)?, expected);
    fs::write(&root, original)?;
    assert_eq!(snapshot_model(fixture, &snapshot)?, expected);
    Ok(())
  }

  fn snapshot_model(
    fixture: &Fixture,
    snapshot: &CapturedCompose,
  ) -> anyhow::Result<serde_json::Value> {
    let mut command = Command::new("docker");
    command
      .args(["compose", "-p", "komodo-include-conformance"])
      .arg("--project-directory")
      .arg(&snapshot.project_directory)
      .env_clear()
      .env(
        "PATH",
        std::env::var_os("PATH").context("PATH is missing")?,
      )
      .env("HOME", &fixture.root)
      .env("COMPOSE_EXPERIMENTAL_GIT_REMOTE", "false")
      .env("COMPOSE_EXPERIMENTAL_OCI_REMOTE", "false")
      .current_dir(&fixture.root);
    for root in &snapshot.roots {
      command.arg("-f").arg(root);
    }
    for env_file in &snapshot.env_files {
      command.arg("--env-file").arg(env_file);
    }
    let output =
      command.args(["config", "--format", "json"]).output()?;
    assert!(
      output.status.success(),
      "synthetic staged Compose config failed: {}",
      String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
  }

  #[test]
  #[ignore = "requires Docker engine and KOMODO_SNAPSHOT_TEST_IMAGE"]
  fn snapshot_deployment_uses_captured_inputs() -> anyhow::Result<()>
  {
    let image = std::env::var("KOMODO_SNAPSHOT_TEST_IMAGE").context(
      "KOMODO_SNAPSHOT_TEST_IMAGE must name an existing local image",
    )?;
    let fixture = Fixture::new("nested")?;
    fs::create_dir(fixture.root.join("staged-child"))?;
    fs::write(
      fixture.root.join("compose.yaml"),
      "include: [staged-child/compose.yaml]\nservices:\n  root:\n    image: ${IMAGE}\n    entrypoint: [sleep, '120']\n    stop_grace_period: 1s\n    environment: {ROOT_VALUE: '${ROOT_VALUE}'}\n",
    )?;
    fs::write(
      fixture.root.join("staged-child/compose.yaml"),
      "services:\n  child:\n    image: ${IMAGE}\n    entrypoint: [sleep, '120']\n    stop_grace_period: 1s\n    environment: {CHILD_VALUE: '${CHILD_VALUE}'}\n",
    )?;
    let root_env = fixture.root.join(".env");
    let child_env = fixture.root.join("staged-child/.env");
    let original_root_env =
      format!("IMAGE={image}\nROOT_VALUE=original\n");
    fs::write(&root_env, &original_root_env)?;
    fs::write(&child_env, "CHILD_VALUE=original\n")?;
    let graph = inspect(
      &fixture.root,
      &["compose.yaml".into()],
      &[],
      BTreeMap::new(),
    )?;
    let snapshot = CapturedCompose::from_graph(&graph)?;
    let project =
      format!("komodo-snapshot-{}", uuid::Uuid::new_v4().simple());
    let path = std::env::var_os("PATH").context("PATH is missing")?;
    let compose = || {
      let mut command = Command::new("docker");
      command
        .args(["compose", "-p", &project, "--project-directory"])
        .arg(&snapshot.project_directory)
        .env_clear()
        .env("PATH", &path)
        .env("HOME", &fixture.root)
        .current_dir(&fixture.root);
      for root in &snapshot.roots {
        command.arg("-f").arg(root);
      }
      for file in &snapshot.env_files {
        command.arg("--env-file").arg(file);
      }
      command
    };
    fs::write(
      &root_env,
      format!("IMAGE={image}\nROOT_VALUE=changed\n"),
    )?;
    fs::write(&child_env, "CHILD_VALUE=changed\n")?;
    let result = (|| -> anyhow::Result<()> {
      let up =
        compose().args(["up", "-d", "--pull", "never"]).output()?;
      ensure!(
        up.status.success(),
        "Synthetic Compose deployment failed: {}",
        String::from_utf8_lossy(&up.stderr)
      );
      fs::write(&root_env, &original_root_env)?;
      fs::write(&child_env, "CHILD_VALUE=original\n")?;
      for (service, value) in [
        ("root", "ROOT_VALUE=original"),
        ("child", "CHILD_VALUE=original"),
      ] {
        let container =
          compose().args(["ps", "-q", service]).output()?;
        ensure!(
          container.status.success(),
          "Cannot inspect fixture service"
        );
        let id = String::from_utf8(container.stdout)?;
        ensure!(
          !id.trim().is_empty(),
          "Fixture service did not start"
        );
        let inspect = Command::new("docker")
          .args([
            "inspect",
            "--format",
            "{{json .Config.Env}}",
            id.trim(),
          ])
          .output()?;
        ensure!(
          inspect.status.success(),
          "Cannot inspect fixture container"
        );
        let environment: Vec<String> =
          serde_json::from_slice(&inspect.stdout)?;
        ensure!(
          environment.iter().any(|entry| entry == value),
          "Fixture container did not use the captured environment"
        );
        let label = Command::new("docker")
          .args([
            "inspect",
            "--format",
            "{{index .Config.Labels \"com.docker.compose.project.config_files\"}}",
            id.trim(),
          ])
          .output()?;
        ensure!(
          label.status.success(),
          "Cannot inspect fixture label"
        );
        ensure!(
          String::from_utf8(label.stdout)?.trim()
            == snapshot.roots[0].to_string_lossy(),
          "Compose did not record the staged root"
        );
      }
      Ok(())
    })();
    let down = compose().args(["down", "--timeout", "2"]).output()?;
    ensure!(
      down.status.success(),
      "Cannot clean up synthetic Compose deployment: {}",
      String::from_utf8_lossy(&down.stderr)
    );
    for kind in ["container", "network"] {
      let mut command = Command::new("docker");
      command.args([kind, "ls", "-q"]);
      if kind == "container" {
        command.arg("--all");
      }
      let remaining = command
        .args([
          "--filter",
          &format!("label=com.docker.compose.project={project}"),
        ])
        .output()?;
      ensure!(
        remaining.status.success() && remaining.stdout.is_empty(),
        "Synthetic {kind} resources remain"
      );
    }
    result
  }
}
