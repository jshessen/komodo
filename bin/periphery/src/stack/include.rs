use std::{
  collections::{BTreeMap, BTreeSet},
  fs,
  io::Read,
  path::{Component, Path, PathBuf},
};

use serde::de::{
  DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess,
  Visitor,
};
use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value;
use sha2::{Digest, Sha256};

const MAX_DEPTH: usize = 64;
pub(super) const MAX_FILES: usize = 512;
pub(super) const MAX_BYTES: usize = 32 * 1024 * 1024;
const MAX_STATE_BYTES: usize = 64 * 1024 * 1024;

pub(super) use komodo_client::entities::stack::ComposeResolutionErrorKind as ErrorKind;

#[derive(Debug)]
pub(super) struct IncludeError {
  pub(super) kind: ErrorKind,
  pub(super) path: Option<PathBuf>,
}

impl std::fmt::Display for IncludeError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "Compose dependency inspection failed: {:?}", self.kind)
  }
}

impl std::error::Error for IncludeError {}

#[derive(
  Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub(super) enum DependencyKind {
  Compose,
  Environment,
  Auxiliary,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Dependency {
  pub(super) path: PathBuf,
  pub(super) kind: DependencyKind,
  pub(super) project_directory: PathBuf,
  pub(super) fingerprint: String,
  #[serde(default)]
  pub(super) policy:
    Option<komodo_client::entities::stack::StackFileDependency>,
}

#[derive(PartialEq, Eq)]
pub(super) struct Graph {
  pub(super) roots: Vec<PathBuf>,
  pub(super) dependencies: Vec<Dependency>,
  pub(super) contents: BTreeMap<PathBuf, String>,
  pub(super) has_untracked_remote: bool,
}

pub(super) fn inspect(
  directory: &Path,
  roots: &[String],
  env_files: &[String],
  environment: BTreeMap<String, String>,
) -> Result<Graph, IncludeError> {
  inspect_within(directory, roots, env_files, environment, None)
}

pub(super) fn inspect_within(
  directory: &Path,
  roots: &[String],
  env_files: &[String],
  environment: BTreeMap<String, String>,
  source_root: Option<&Path>,
) -> Result<Graph, IncludeError> {
  let (directory, mut walker) =
    root_walker(directory, roots, source_root)?;
  let roots = walker.graph.roots.clone();
  let project_directory = roots[0].parent().unwrap().to_path_buf();
  let environment = walker.environment(
    &directory,
    &project_directory,
    env_files,
    environment,
    true,
  )?;
  walker.load(&roots, &project_directory, environment, &[], 0)?;
  Ok(walker.graph)
}

fn root_walker(
  directory: &Path,
  roots: &[String],
  source_root: Option<&Path>,
) -> Result<(PathBuf, Walker), IncludeError> {
  let source_root = source_root.map(canonical).transpose()?;
  let directory = canonical(directory)?;
  if let Some(root) = &source_root {
    ensure_within(root, &directory)?;
  }
  let roots = roots
    .iter()
    .map(|path| local_path(&directory, path))
    .collect::<Result<Vec<_>, _>>()?;
  if roots.is_empty() {
    return Err(error(ErrorKind::InvalidSource, None));
  }
  if roots[0].parent().is_none() {
    return Err(error(ErrorKind::InvalidSource, Some(&roots[0])));
  }
  let walker = Walker {
    graph: Graph {
      roots: roots.clone(),
      dependencies: Vec::new(),
      contents: BTreeMap::new(),
      has_untracked_remote: false,
    },
    bytes: 0,
    state_bytes: 0,
    loaded: BTreeSet::new(),
    source_root,
  };
  Ok((directory, walker))
}

/// Classify only explicit roots, before any Compose loader or include-only capability check.
pub(super) fn inspect_roots(
  directory: &Path,
  roots: &[String],
  source_root: Option<&Path>,
) -> Result<(Graph, bool), IncludeError> {
  let (_, mut walker) = root_walker(directory, roots, source_root)?;
  let roots = walker.graph.roots.clone();
  let project = roots[0].parent().unwrap();
  let mut includes = false;
  for path in &roots {
    let text = walker.read(path, DependencyKind::Compose, project)?;
    let bytes = model_bytes(&text)?;
    charge_bytes(&mut walker.state_bytes, bytes, MAX_STATE_BYTES)?;
    let mut model: Value = serde_yaml_ng::from_str(&text)
      .map_err(|_| error(ErrorKind::InvalidSource, Some(path)))?;
    reject_tags(&model)?;
    model
      .apply_merge()
      .map_err(|_| error(ErrorKind::UnsupportedForm, Some(path)))?;
    let model = model
      .as_mapping()
      .ok_or_else(|| error(ErrorKind::InvalidSource, Some(path)))?;
    if let Some(include) = model.get("include") {
      includes |= !include.is_null()
        && !include.as_sequence().is_some_and(Vec::is_empty);
    }
    walker.state_bytes -= bytes;
  }
  Ok((walker.graph, includes))
}

pub(super) fn with_files(
  graph: Graph,
  directory: &Path,
  files: &[komodo_client::entities::stack::StackFileDependency],
  source_root: Option<&Path>,
) -> Result<Graph, IncludeError> {
  let bytes = graph.contents.values().map(String::len).sum();
  let mut state_bytes = 0;
  for dependency in &graph.dependencies {
    charge_bytes(
      &mut state_bytes,
      descriptor_bytes(
        &dependency.path,
        &dependency.project_directory,
      )?,
      MAX_STATE_BYTES,
    )?;
  }
  let mut walker = Walker {
    graph,
    bytes,
    state_bytes,
    loaded: BTreeSet::new(),
    source_root: source_root.map(canonical).transpose()?,
  };
  for file in files {
    let path = local_path(directory, &file.path)?;
    if let Some(root) = &walker.source_root {
      ensure_within(root, &path)?;
    }
    let path = canonical(&path)?;
    if !walker.graph.dependencies.iter().any(|dependency| {
      dependency.path == path
        && dependency.kind != DependencyKind::Environment
    }) {
      walker.read(&path, DependencyKind::Auxiliary, directory)?;
    }
    for dependency in walker
      .graph
      .dependencies
      .iter_mut()
      .filter(|dependency| dependency.path == path)
    {
      let policy_bytes = file.services.iter().try_fold(
        128 + file.path.len(),
        |bytes, service| {
          let mut bytes = bytes;
          charge_bytes(
            &mut bytes,
            service.len() + 24,
            MAX_STATE_BYTES,
          )?;
          Ok::<_, IncludeError>(bytes)
        },
      )?;
      charge_bytes(
        &mut walker.state_bytes,
        policy_bytes,
        MAX_STATE_BYTES,
      )?;
      dependency.policy = Some(file.clone());
    }
  }
  Ok(walker.graph)
}

fn descriptor_bytes(
  path: &Path,
  project: &Path,
) -> Result<usize, IncludeError> {
  let mut bytes = 128;
  charge_bytes(&mut bytes, path.as_os_str().len(), MAX_STATE_BYTES)?;
  charge_bytes(
    &mut bytes,
    project.as_os_str().len(),
    MAX_STATE_BYTES,
  )?;
  Ok(bytes)
}

#[cfg(test)]
pub(super) async fn inspect_and_run_config<T>(
  directory: &Path,
  source_root: Option<&Path>,
  roots: &[String],
  env_files: &[String],
  environment: BTreeMap<String, String>,
  run_config: impl AsyncFnOnce(
    &[String],
    &[String],
    &BTreeMap<String, String>,
  ) -> Result<T, IncludeError>,
) -> Result<(Graph, T), IncludeError> {
  let graph = match source_root {
    Some(root) => inspect_within(
      directory,
      roots,
      env_files,
      environment.clone(),
      Some(root),
    ),
    None => inspect(directory, roots, env_files, environment.clone()),
  }?;
  let output = run_config(roots, env_files, &environment).await?;
  Ok((graph, output))
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Context {
  paths: Vec<PathBuf>,
  project_directory: PathBuf,
  environment: BTreeMap<String, String>,
}

struct ModelBudget {
  bytes: usize,
  failure: Option<ErrorKind>,
}

impl ModelBudget {
  fn charge<E: serde::de::Error>(
    &mut self,
    bytes: usize,
  ) -> Result<(), E> {
    charge_bytes(&mut self.bytes, bytes, MAX_STATE_BYTES).map_err(
      |error| {
        self.failure = Some(error.kind);
        E::custom("Compose model limit exceeded")
      },
    )
  }
}

impl<'de> DeserializeSeed<'de> for &mut ModelBudget {
  type Value = ();

  fn deserialize<D: serde::Deserializer<'de>>(
    self,
    deserializer: D,
  ) -> Result<(), D::Error> {
    self.charge(128)?;
    deserializer.deserialize_any(self)
  }
}

impl<'de> Visitor<'de> for &mut ModelBudget {
  type Value = ();

  fn expecting(
    &self,
    formatter: &mut std::fmt::Formatter,
  ) -> std::fmt::Result {
    formatter.write_str("a bounded Compose source")
  }

  fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
    Ok(())
  }
  fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
    Ok(())
  }
  fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
    Ok(())
  }
  fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> {
    Ok(())
  }
  fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
    Ok(())
  }

  fn visit_str<E: serde::de::Error>(
    self,
    value: &str,
  ) -> Result<(), E> {
    self.charge(value.len())
  }

  fn visit_seq<A: SeqAccess<'de>>(
    self,
    mut sequence: A,
  ) -> Result<(), A::Error> {
    while sequence.next_element_seed(&mut *self)?.is_some() {}
    Ok(())
  }

  fn visit_map<A: MapAccess<'de>>(
    self,
    mut mapping: A,
  ) -> Result<(), A::Error> {
    while mapping.next_key_seed(&mut *self)?.is_some() {
      mapping.next_value_seed(&mut *self)?;
    }
    Ok(())
  }

  fn visit_enum<A: EnumAccess<'de>>(
    self,
    data: A,
  ) -> Result<(), A::Error> {
    let (_, value) = data.variant::<String>()?;
    value.newtype_variant_seed(self)
  }
}

fn model_bytes(text: &str) -> Result<usize, IncludeError> {
  // Count alias expansion before allocating Values; callers also charge retained parents.
  let mut budget = ModelBudget {
    bytes: 0,
    failure: None,
  };
  (&mut budget)
    .deserialize(serde_yaml_ng::Deserializer::from_str(text))
    .map_err(|_| {
      error(budget.failure.unwrap_or(ErrorKind::InvalidSource), None)
    })?;
  Ok(budget.bytes)
}

struct Walker {
  graph: Graph,
  bytes: usize,
  state_bytes: usize,
  loaded: BTreeSet<Context>,
  source_root: Option<PathBuf>,
}

impl Walker {
  fn read(
    &mut self,
    path: &Path,
    kind: DependencyKind,
    project_directory: &Path,
  ) -> Result<String, IncludeError> {
    if let Some(root) = &self.source_root {
      ensure_within(root, path)?;
    }
    let path = canonical(path)?;
    // Opening a FIFO can block before the descriptor can be inspected.
    if !fs::metadata(&path)
      .map_err(|err| io_error(err, &path))?
      .is_file()
    {
      return Err(error(ErrorKind::UnsupportedForm, Some(&path)));
    }
    let mut file =
      fs::File::open(&path).map_err(|err| io_error(err, &path))?;
    let metadata =
      file.metadata().map_err(|err| io_error(err, &path))?;
    if !metadata.is_file() {
      return Err(error(ErrorKind::UnsupportedForm, Some(&path)));
    }
    let remaining = MAX_BYTES - self.bytes;
    let maximum = if self.graph.contents.contains_key(&path) {
      MAX_BYTES
    } else {
      remaining
    };
    if metadata.len() > maximum as u64 {
      return Err(error(ErrorKind::Limit, Some(&path)));
    }
    let mut bytes = Vec::new();
    file
      .by_ref()
      .take(maximum as u64 + 1)
      .read_to_end(&mut bytes)
      .map_err(|err| io_error(err, &path))?;
    if bytes.len() > maximum {
      return Err(error(ErrorKind::Limit, Some(&path)));
    }
    let fingerprint =
      data_encoding::HEXLOWER.encode(&Sha256::digest(&bytes));
    let text = String::from_utf8(bytes)
      .map_err(|_| error(ErrorKind::InvalidSource, Some(&path)))?;
    if let Some(previous) = self.graph.contents.get(&path) {
      if previous != &text {
        return Err(error(ErrorKind::SourceChanged, Some(&path)));
      }
    } else {
      if self.graph.contents.len() >= MAX_FILES {
        return Err(error(ErrorKind::Limit, Some(&path)));
      }
      self.bytes += text.len();
      self.graph.contents.insert(path.clone(), text.clone());
    }
    charge_bytes(
      &mut self.state_bytes,
      descriptor_bytes(&path, project_directory)?,
      MAX_STATE_BYTES,
    )?;
    self.graph.dependencies.push(Dependency {
      path,
      kind,
      project_directory: project_directory.to_path_buf(),
      fingerprint,
      policy: None,
    });
    Ok(text)
  }

  fn environment(
    &mut self,
    declaring_directory: &Path,
    project_directory: &Path,
    files: &[String],
    mut inherited: BTreeMap<String, String>,
    is_root: bool,
  ) -> Result<BTreeMap<String, String>, IncludeError> {
    if let Some(root) = &self.source_root {
      ensure_within(root, project_directory)?;
    }
    environment_bytes(&inherited)?;
    let mut configured_files = Vec::new();
    if is_root
      && files.is_empty()
      && let Some(value) = inherited.get("COMPOSE_ENV_FILES")
    {
      for path in value.split(',').filter(|value| !value.is_empty()) {
        if configured_files.len() == MAX_FILES {
          return Err(error(ErrorKind::Limit, None));
        }
        configured_files.push(path.to_string());
      }
    }
    let selected_files = if !files.is_empty() {
      files
    } else {
      &configured_files
    };
    let disabled = is_root
      && inherited
        .get("COMPOSE_DISABLE_ENV_FILE")
        .is_some_and(|value| compose_true(value));
    let default_selected = selected_files.is_empty() && !disabled;
    let files = if !selected_files.is_empty() {
      selected_files
        .iter()
        .filter(|file| file.as_str() != "/dev/null")
        .map(|file| local_path(declaring_directory, file))
        .collect::<Result<Vec<_>, _>>()?
    } else if disabled {
      Vec::new()
    } else {
      let default = project_directory.join(".env");
      match fs::metadata(&default) {
        Ok(metadata) if !metadata.is_dir() => vec![default],
        Ok(_) => Vec::new(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
          Vec::new()
        }
        Err(err) => return Err(io_error(err, &default)),
      }
    };
    let mut from_files = BTreeMap::new();
    let mut file_bytes = 0;
    let mut loaded = Vec::new();
    for path in files {
      let text = self.read(
        &path,
        DependencyKind::Environment,
        project_directory,
      )?;
      let lookup = merge_environment(&from_files, &inherited)?;
      let parsed =
        parse_environment(&text, &lookup).map_err(|mut err| {
          err.path = Some(path.clone());
          err
        })?;
      for (key, value) in parsed {
        insert_environment(
          &mut from_files,
          &mut file_bytes,
          key,
          value,
        )?;
      }
      loaded.push((path, text));
    }
    if is_root {
      for (key, value) in &from_files {
        if key.starts_with("COMPOSE_") && !inherited.contains_key(key)
        {
          inherited.insert(key.clone(), value.clone());
        }
      }
      let disabled_after_preload = default_selected
        && inherited
          .get("COMPOSE_DISABLE_ENV_FILE")
          .is_some_and(|value| compose_true(value));
      from_files.clear();
      file_bytes = 0;
      if !disabled_after_preload {
        for (path, text) in loaded {
          let lookup = merge_environment(&from_files, &inherited)?;
          let parsed = parse_environment(&text, &lookup).map_err(
            |mut err| {
              err.path = Some(path);
              err
            },
          )?;
          for (key, value) in parsed {
            insert_environment(
              &mut from_files,
              &mut file_bytes,
              key,
              value,
            )?;
          }
        }
      }
    }
    for (key, value) in inherited {
      insert_environment(
        &mut from_files,
        &mut file_bytes,
        key,
        value,
      )?;
    }
    Ok(from_files)
  }

  fn load(
    &mut self,
    paths: &[PathBuf],
    project_directory: &Path,
    environment: BTreeMap<String, String>,
    ancestors: &[PathBuf],
    depth: usize,
  ) -> Result<(), IncludeError> {
    if depth > MAX_DEPTH {
      return Err(error(
        ErrorKind::Limit,
        paths.first().map(PathBuf::as_path),
      ));
    }
    let identities = paths
      .iter()
      .map(|path| canonical(path))
      .collect::<Result<Vec<_>, _>>()?;
    if identities.iter().any(|path| ancestors.contains(path)) {
      return Err(error(
        ErrorKind::IncludeCycle,
        paths.first().map(PathBuf::as_path),
      ));
    }
    let context = Context {
      paths: paths.to_vec(),
      project_directory: project_directory.to_path_buf(),
      environment,
    };
    if self.loaded.contains(&context) {
      return Ok(());
    }
    let mut context_bytes = environment_bytes(&context.environment)?;
    charge_bytes(&mut context_bytes, 128, MAX_STATE_BYTES)?;
    charge_bytes(
      &mut context_bytes,
      project_directory.as_os_str().len(),
      MAX_STATE_BYTES,
    )?;
    for path in paths {
      charge_bytes(&mut context_bytes, 24, MAX_STATE_BYTES)?;
      charge_bytes(
        &mut context_bytes,
        path.as_os_str().len(),
        MAX_STATE_BYTES,
      )?;
    }
    charge_bytes(
      &mut self.state_bytes,
      context_bytes,
      MAX_STATE_BYTES,
    )?;
    for (path, identity) in paths.iter().zip(identities) {
      let mut declaring_ancestors = ancestors.to_vec();
      declaring_ancestors.push(identity);
      let text = self.read(
        path,
        DependencyKind::Compose,
        project_directory,
      )?;
      let model_bytes = model_bytes(&text).map_err(|mut error| {
        error.path = Some(path.clone());
        error
      })?;
      charge_bytes(
        &mut self.state_bytes,
        model_bytes,
        MAX_STATE_BYTES,
      )?;
      let result: Result<(), IncludeError> = (|| {
        let mut model: Value = serde_yaml_ng::from_str(&text)
          .map_err(|_| error(ErrorKind::InvalidSource, Some(path)))?;
        reject_tags(&model).map_err(|_| {
          error(ErrorKind::UnsupportedForm, Some(path))
        })?;
        model.apply_merge().map_err(|_| {
          error(ErrorKind::UnsupportedForm, Some(path))
        })?;
        let model = model.as_mapping().ok_or_else(|| {
          error(ErrorKind::InvalidSource, Some(path))
        })?;
        let Some(include) = model.get("include") else {
          return Ok(());
        };
        if include.is_null() {
          return Ok(());
        }
        let includes = include.as_sequence().ok_or_else(|| {
          error(ErrorKind::UnsupportedForm, Some(path))
        })?;
        for include in includes {
          self
            .include(
              include,
              project_directory,
              &context.environment,
              &declaring_ancestors,
              depth + 1,
            )
            .map_err(|mut err| {
              if err.path.is_none() {
                err.path = Some(path.clone());
              }
              err
            })?;
        }
        Ok(())
      })();
      self.state_bytes -= model_bytes;
      result?;
    }
    self.loaded.insert(context);
    Ok(())
  }

  fn include(
    &mut self,
    include: &Value,
    declaring_directory: &Path,
    environment: &BTreeMap<String, String>,
    ancestors: &[PathBuf],
    depth: usize,
  ) -> Result<(), IncludeError> {
    let (paths, directory, env_files) = match include {
      Value::String(path) => (vec![path.clone()], None, Vec::new()),
      Value::Mapping(fields) => {
        if fields.keys().any(|key| {
          !matches!(
            key.as_str(),
            Some("path" | "project_directory" | "env_file")
          )
        }) {
          return Err(error(ErrorKind::UnsupportedForm, None));
        }
        let paths =
          strings(fields.get("path").ok_or_else(|| {
            error(ErrorKind::UnsupportedForm, None)
          })?)?;
        let directory = fields
          .get("project_directory")
          .map(|value| {
            value
              .as_str()
              .ok_or_else(|| error(ErrorKind::UnsupportedForm, None))
          })
          .transpose()?;
        let env_files = fields
          .get("env_file")
          .map(strings)
          .transpose()?
          .unwrap_or_default();
        (paths, directory, env_files)
      }
      _ => return Err(error(ErrorKind::UnsupportedForm, None)),
    };
    if paths.is_empty() {
      return Err(error(ErrorKind::InvalidSource, None));
    }
    let expanded = paths
      .iter()
      .map(|path| expand(path, environment))
      .collect::<Result<Vec<_>, _>>()?;
    if expanded.iter().any(|path| is_remote_reference(path)) {
      self.graph.has_untracked_remote = true;
      return Ok(());
    }
    let paths = expanded
      .iter()
      .map(|path| local_path(declaring_directory, path))
      .collect::<Result<Vec<_>, _>>()?;
    let directory = directory
      .map(|directory| expand(directory, environment))
      .transpose()?;
    let project_directory = match directory {
      Some(directory) if !directory.is_empty() => {
        local_path(declaring_directory, &directory)?
      }
      _ => paths[0]
        .parent()
        .ok_or_else(|| {
          error(ErrorKind::InvalidSource, Some(&paths[0]))
        })?
        .to_path_buf(),
    };
    let env_files = env_files
      .iter()
      .map(|file| expand(file, environment))
      .collect::<Result<Vec<_>, _>>()?;
    let environment = self.environment(
      declaring_directory,
      &project_directory,
      &env_files,
      environment.clone(),
      false,
    )?;
    self.load(
      &paths,
      &project_directory,
      environment,
      ancestors,
      depth,
    )
  }
}

fn strings(value: &Value) -> Result<Vec<String>, IncludeError> {
  match value {
    Value::String(value) => Ok(vec![value.clone()]),
    Value::Sequence(values) => values
      .iter()
      .map(|value| {
        value
          .as_str()
          .map(str::to_owned)
          .ok_or_else(|| error(ErrorKind::UnsupportedForm, None))
      })
      .collect(),
    _ => Err(error(ErrorKind::UnsupportedForm, None)),
  }
}

fn reject_tags(value: &Value) -> Result<(), IncludeError> {
  match value {
    Value::Tagged(tagged) => {
      if tagged.tag != "!reset" && tagged.tag != "!override" {
        return Err(error(ErrorKind::UnsupportedForm, None));
      }
      reject_tags(&tagged.value)
    }
    Value::Mapping(fields) => {
      for (key, value) in fields {
        reject_tags(key)?;
        reject_tags(value)?;
      }
      Ok(())
    }
    Value::Sequence(values) => {
      for value in values {
        reject_tags(value)?;
      }
      Ok(())
    }
    _ => Ok(()),
  }
}

fn local_path(
  directory: &Path,
  value: &str,
) -> Result<PathBuf, IncludeError> {
  if value.is_empty() || value.contains('\0') {
    return Err(error(ErrorKind::InvalidSource, None));
  }
  if is_remote_reference(value) {
    return Err(error(ErrorKind::RemoteSource, None));
  }
  let mut path = PathBuf::new();
  for component in directory.join(value).components() {
    match component {
      Component::CurDir => {}
      Component::ParentDir => {
        path.pop();
      }
      other => path.push(other),
    }
  }
  Ok(path)
}

fn is_remote_reference(value: &str) -> bool {
  !Path::new(value).is_absolute()
    && !value.starts_with("./")
    && !value.starts_with("../")
    && (value.contains(':') || value.starts_with("github.com/"))
}

pub(super) fn confined_path(
  root: &Path,
  directory: &Path,
  value: &str,
) -> Result<PathBuf, IncludeError> {
  let path = local_path(directory, value)?;
  ensure_within(root, &path)?;
  Ok(path)
}

fn ensure_within(
  root: &Path,
  path: &Path,
) -> Result<(), IncludeError> {
  let allowed = |path: &Path| {
    path.strip_prefix(root).is_ok_and(|relative| {
      !relative
        .components()
        .any(|component| component.as_os_str() == ".git")
    })
  };
  if !allowed(path) {
    return Err(error(ErrorKind::InvalidPath, Some(path)));
  }
  for ancestor in path.ancestors() {
    match fs::canonicalize(ancestor) {
      Ok(physical) if allowed(&physical) => return Ok(()),
      Ok(_) => return Err(error(ErrorKind::InvalidPath, Some(path))),
      Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
      Err(err) => return Err(io_error(err, path)),
    }
  }
  Err(error(ErrorKind::InvalidPath, Some(path)))
}

fn canonical(path: &Path) -> Result<PathBuf, IncludeError> {
  fs::canonicalize(path).map_err(|err| io_error(err, path))
}

fn io_error(err: std::io::Error, path: &Path) -> IncludeError {
  error(
    if err.kind() == std::io::ErrorKind::NotFound {
      ErrorKind::MissingSource
    } else {
      ErrorKind::SourceAccess
    },
    Some(path),
  )
}

fn error(kind: ErrorKind, path: Option<&Path>) -> IncludeError {
  IncludeError {
    kind,
    path: path.map(Path::to_path_buf),
  }
}

fn expand(
  input: &str,
  environment: &BTreeMap<String, String>,
) -> Result<String, IncludeError> {
  expand_at_depth(input, environment, 0)
}

fn expand_at_depth(
  input: &str,
  environment: &BTreeMap<String, String>,
  depth: usize,
) -> Result<String, IncludeError> {
  if depth > MAX_DEPTH {
    return Err(error(ErrorKind::Limit, None));
  }
  let bytes = input.as_bytes();
  let mut output = String::new();
  let mut index = 0;
  while index < bytes.len() {
    if output.len() > MAX_BYTES {
      return Err(error(ErrorKind::Limit, None));
    }
    if bytes[index] != b'$' {
      let end = input[index..]
        .find('$')
        .map(|offset| index + offset)
        .unwrap_or(bytes.len());
      output.push_str(&input[index..end]);
      index = end;
      continue;
    }
    index += 1;
    if bytes.get(index) == Some(&b'$') {
      output.push('$');
      index += 1;
      continue;
    }
    let braced = bytes.get(index) == Some(&b'{');
    let start = index + usize::from(braced);
    let mut end = start;
    while end < bytes.len()
      && (bytes[end].is_ascii_alphabetic()
        || bytes[end] == b'_'
        || (end > start && bytes[end].is_ascii_digit()))
    {
      end += 1;
    }
    if end == start {
      if braced {
        return Err(error(ErrorKind::Interpolation, None));
      }
      output.push('$');
      continue;
    }
    let value = environment.get(&input[start..end]);
    if !braced {
      if let Some(value) = value {
        output.push_str(value);
      }
      index = end;
      continue;
    }
    let mut closing = end;
    let mut nesting = 1;
    while closing < bytes.len() {
      if bytes[closing] == b'$'
        && bytes.get(closing + 1) == Some(&b'{')
      {
        nesting += 1;
        closing += 1;
      } else if bytes[closing] == b'}' {
        nesting -= 1;
        if nesting == 0 {
          break;
        }
      }
      closing += 1;
    }
    if closing == bytes.len() {
      return Err(error(ErrorKind::Interpolation, None));
    }
    let expression = &input[end..closing];
    if expression.is_empty() {
      if let Some(value) = value {
        output.push_str(value);
      }
    } else {
      let (nonempty, expression) = expression
        .strip_prefix(':')
        .map(|rest| (true, rest))
        .unwrap_or((false, expression));
      let present =
        value.is_some_and(|value| !nonempty || !value.is_empty());
      let operand = expression
        .get(1..)
        .ok_or_else(|| error(ErrorKind::Interpolation, None))?;
      match expression.as_bytes()[0] {
        b'-' if !present => {
          output.push_str(&expand_at_depth(
            operand,
            environment,
            depth + 1,
          )?);
        }
        b'+' if present => {
          output.push_str(&expand_at_depth(
            operand,
            environment,
            depth + 1,
          )?);
        }
        b'?' if !present => {
          return Err(error(ErrorKind::Interpolation, None));
        }
        b'-' | b'?' => {
          if let Some(value) = value {
            output.push_str(value);
          }
        }
        b'+' => {}
        _ => return Err(error(ErrorKind::Interpolation, None)),
      }
    }
    if output.len() > MAX_BYTES {
      return Err(error(ErrorKind::Limit, None));
    }
    index = closing + 1;
  }
  if output.len() > MAX_BYTES {
    return Err(error(ErrorKind::Limit, None));
  }
  Ok(output)
}

fn compose_true(value: &str) -> bool {
  matches!(value, "1" | "t" | "T" | "true" | "TRUE" | "True")
}

pub(super) fn charge_bytes(
  size: &mut usize,
  additional: usize,
  limit: usize,
) -> Result<(), IncludeError> {
  *size = size
    .checked_add(additional)
    .filter(|size| *size <= limit)
    .ok_or_else(|| error(ErrorKind::Limit, None))?;
  Ok(())
}

fn environment_entry_bytes(
  key: &str,
  value: &str,
) -> Result<usize, IncludeError> {
  let mut bytes = 64;
  charge_bytes(&mut bytes, key.len(), MAX_STATE_BYTES)?;
  charge_bytes(&mut bytes, value.len(), MAX_STATE_BYTES)?;
  Ok(bytes)
}

fn environment_bytes(
  environment: &BTreeMap<String, String>,
) -> Result<usize, IncludeError> {
  let mut bytes = 0;
  for (key, value) in environment {
    charge_bytes(
      &mut bytes,
      environment_entry_bytes(key, value)?,
      MAX_STATE_BYTES,
    )?;
  }
  Ok(bytes)
}

fn insert_environment(
  environment: &mut BTreeMap<String, String>,
  bytes: &mut usize,
  key: String,
  value: String,
) -> Result<(), IncludeError> {
  let previous = environment
    .get(&key)
    .map(|value| environment_entry_bytes(&key, value))
    .transpose()?
    .unwrap_or(0);
  let mut next = *bytes - previous;
  charge_bytes(
    &mut next,
    environment_entry_bytes(&key, &value)?,
    MAX_STATE_BYTES,
  )?;
  environment.insert(key, value);
  *bytes = next;
  Ok(())
}

fn merge_environment(
  lower: &BTreeMap<String, String>,
  higher: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, IncludeError> {
  let mut merged = BTreeMap::new();
  let mut bytes = 0;
  for (key, value) in lower
    .iter()
    .filter(|(key, _)| !higher.contains_key(*key))
    .chain(higher)
  {
    charge_bytes(
      &mut bytes,
      environment_entry_bytes(key, value)?,
      MAX_STATE_BYTES,
    )?;
    merged.insert(key.clone(), value.clone());
  }
  Ok(merged)
}

fn parse_environment(
  text: &str,
  inherited: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, IncludeError> {
  let mut remaining = text.trim_start_matches('\u{feff}');
  environment_bytes(inherited)?;
  let mut values = BTreeMap::new();
  let mut value_bytes = 0;
  while !remaining.is_empty() {
    remaining = remaining.trim_start();
    if remaining.is_empty() {
      break;
    }
    if remaining.starts_with('#') {
      remaining = remaining
        .split_once('\n')
        .map(|(_, rest)| rest)
        .unwrap_or("");
      continue;
    }
    if let Some(rest) = remaining.strip_prefix("export")
      && rest.starts_with([' ', '\t'])
    {
      remaining = rest.trim_start_matches([' ', '\t']);
    }
    let end = remaining
      .find(|character: char| {
        !(character.is_ascii_alphanumeric() || character == '_')
      })
      .unwrap_or(remaining.len());
    if end == 0 || remaining.as_bytes()[0].is_ascii_digit() {
      return Err(error(ErrorKind::UnsupportedForm, None));
    }
    let key = remaining[..end].to_owned();
    remaining = remaining[end..].trim_start_matches([' ', '\t']);
    if remaining.is_empty() || remaining.starts_with(['\n', '\r']) {
      if let Some(value) = inherited.get(&key) {
        insert_environment(
          &mut values,
          &mut value_bytes,
          key,
          value.clone(),
        )?;
      }
      continue;
    }
    if !remaining.starts_with('=') {
      return Err(error(ErrorKind::UnsupportedForm, None));
    }
    remaining = remaining[1..].trim_start_matches([' ', '\t']);
    let mut value = String::new();
    let quote = remaining
      .chars()
      .next()
      .filter(|character| matches!(character, '\'' | '"'));
    if let Some(quote) = quote {
      remaining = &remaining[1..];
      let mut closed = false;
      while let Some(character) = remaining.chars().next() {
        remaining = &remaining[character.len_utf8()..];
        if character == quote {
          closed = true;
          break;
        }
        if character == '\\' {
          let next = remaining
            .chars()
            .next()
            .ok_or_else(|| error(ErrorKind::InvalidSource, None))?;
          if quote == '"' && next == '$' {
            value.push_str("$$");
            remaining = &remaining[1..];
            continue;
          }
          if quote == '"'
            && !matches!(next, '"' | '\\' | 'n' | 'r' | 't')
          {
            return Err(error(ErrorKind::UnsupportedForm, None));
          }
          if next == quote
            || (quote == '"'
              && matches!(next, '\\' | 'n' | 'r' | 't'))
          {
            value.push(match next {
              'n' => '\n',
              'r' => '\r',
              't' => '\t',
              other => other,
            });
            remaining = &remaining[next.len_utf8()..];
            continue;
          }
        }
        value.push(character);
      }
      if !closed {
        return Err(error(ErrorKind::InvalidSource, None));
      }
      remaining = remaining.trim_start_matches([' ', '\t']);
      if remaining.starts_with('#') {
        remaining = remaining
          .split_once('\n')
          .map(|(_, rest)| rest)
          .unwrap_or("");
      } else if !remaining.is_empty()
        && !remaining.starts_with(['\n', '\r'])
      {
        return Err(error(ErrorKind::UnsupportedForm, None));
      }
    } else {
      let end =
        remaining.find(['\n', '\r']).unwrap_or(remaining.len());
      let line = &remaining[..end];
      let end = line
        .char_indices()
        .find(|(index, character)| {
          *character == '#'
            && (*index == 0
              || line.as_bytes()[index - 1].is_ascii_whitespace())
        })
        .map(|(index, _)| index)
        .unwrap_or(line.len());
      value.push_str(line[..end].trim_end());
      remaining = &remaining[line.len()..];
    }
    if quote != Some('\'') {
      let lookup = merge_environment(&values, inherited)?;
      value = expand(&value, &lookup)?;
    }
    insert_environment(&mut values, &mut value_bytes, key, value)?;
  }
  Ok(values)
}

#[cfg(test)]
pub(crate) mod tests {
  use std::{
    cell::Cell,
    collections::BTreeMap,
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::{Command, Output},
  };

  use anyhow::{Context, bail};

  use super::{DependencyKind, ErrorKind, Graph, expand, inspect};

  pub(crate) struct Fixture {
    pub(crate) root: PathBuf,
  }

  impl Fixture {
    pub(crate) fn new(name: &str) -> anyhow::Result<Self> {
      let root = std::env::temp_dir().join(format!(
        "komodo-compose-include-{}",
        uuid::Uuid::new_v4()
      ));
      fs::DirBuilder::new().mode(0o700).create(&root)?;
      let fixture = Self { root };
      copy_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
          .join("src/stack/fixtures/compose_include")
          .join(name),
        &fixture.root,
      )?;
      Ok(fixture)
    }

    fn compose(&self) -> anyhow::Result<Output> {
      Command::new("docker")
        .args([
          "compose",
          "-p",
          "komodo-include-conformance",
          "-f",
          "compose.yaml",
          "config",
          "--services",
        ])
        .current_dir(&self.root)
        .env("COMPOSE_DISABLE_ENV_FILE", "true")
        .env("COMPOSE_ENV_FILES", "")
        .output()
        .context("cannot run Compose")
    }

    pub(crate) fn compose_model(
      &self,
      roots: &[&str],
      env_files: &[&str],
    ) -> anyhow::Result<serde_json::Value> {
      let mut command = Command::new("docker");
      command
        .args(["compose", "-p", "komodo-include-conformance"])
        .env_clear()
        .env(
          "PATH",
          std::env::var_os("PATH").context("PATH is missing")?,
        )
        .env("HOME", &self.root)
        .env("COMPOSE_EXPERIMENTAL_GIT_REMOTE", "false")
        .env("COMPOSE_EXPERIMENTAL_OCI_REMOTE", "false")
        .current_dir(&self.root);
      for root in roots {
        command.args(["-f", root]);
      }
      for file in env_files {
        command.args(["--env-file", file]);
      }
      let output =
        command.args(["config", "--format", "json"]).output()?;
      if !output.status.success() {
        bail!(
          "synthetic Compose model evaluation failed with {}",
          output.status
        );
      }
      serde_json::from_slice(&output.stdout)
        .context("synthetic Compose model was not JSON")
    }
  }

  impl Drop for Fixture {
    fn drop(&mut self) {
      if let Err(error) = fs::remove_dir_all(&self.root) {
        eprintln!("cannot remove synthetic Compose fixture: {error}");
      }
    }
  }

  fn copy_sources(
    source: &Path,
    destination: &Path,
  ) -> anyhow::Result<()> {
    for entry in fs::read_dir(source)? {
      let entry = entry?;
      let target = destination.join(entry.file_name());
      let kind = entry.file_type()?;
      if kind.is_dir() {
        fs::create_dir(&target)?;
        copy_sources(&entry.path(), &target)?;
      } else if kind.is_file() {
        fs::copy(entry.path(), target)?;
      } else {
        bail!("synthetic fixture contains an unsupported file type");
      }
    }
    Ok(())
  }

  pub(crate) struct FakeCompose {
    pub(crate) calls: Cell<usize>,
  }

  impl FakeCompose {
    pub(crate) fn new() -> Self {
      Self {
        calls: Cell::new(0),
      }
    }
  }

  fn graph(
    fixture: &Fixture,
    environment: std::collections::BTreeMap<String, String>,
  ) -> Result<Graph, super::IncludeError> {
    inspect(&fixture.root, &["compose.yaml".into()], &[], environment)
  }

  #[tokio::test]
  async fn compose_include_config_rejects_graph_before_execution()
  -> anyhow::Result<()> {
    for (yaml, expected) in [
      ("include: [missing.yaml]\n", ErrorKind::MissingSource),
      ("include: [compose.yaml]\n", ErrorKind::IncludeCycle),
      ("include: [\n", ErrorKind::InvalidSource),
      (
        "include: [\"${MISSING:?synthetic-secret}\"]\n",
        ErrorKind::Interpolation,
      ),
    ] {
      let fixture = Fixture::new("nested")?;
      fs::write(fixture.root.join("compose.yaml"), yaml)?;
      let compose = FakeCompose::new();
      let result = super::inspect_and_run_config(
        &fixture.root,
        None,
        &["compose.yaml".into()],
        &[],
        [(
          "REMOTE".into(),
          "https://synthetic-user:synthetic-secret@compose-include.invalid/stack.git".into(),
        )]
        .into(),
        async |_, _, _| {
          compose.run("config").map_err(|_| {
            super::error(ErrorKind::ComposeValidation, None)
          })
        },
      )
      .await;
      let error = result.err().expect("invalid graph must fail");
      assert_eq!(error.kind, expected, "{yaml}");
      assert_eq!(compose.calls.get(), 0, "{yaml}");
      assert!(!error.to_string().contains("synthetic-secret"));
    }
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_config_preserves_roots_environment_and_single_call()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(fixture.root.join("override.yaml"), "services: {}\n")?;
    fs::write(fixture.root.join("first.env"), "VALUE=first\n")?;
    fs::write(fixture.root.join("last.env"), "VALUE=last\n")?;
    let roots = ["override.yaml".into(), "compose.yaml".into()];
    let env_files = ["first.env".into(), "last.env".into()];
    let environment =
      [("VALUE".into(), "synthetic-override".into())].into();
    let compose = FakeCompose::new();
    let (graph, _) = super::inspect_and_run_config(
      &fixture.root,
      None,
      &roots,
      &env_files,
      environment,
      async |actual_roots, actual_env_files, actual_environment| {
        assert_eq!(actual_roots, roots);
        assert_eq!(actual_env_files, env_files);
        assert_eq!(actual_environment["VALUE"], "synthetic-override");
        compose.run("config").map_err(|_| {
          super::error(ErrorKind::ComposeValidation, None)
        })
      },
    )
    .await?;
    assert_eq!(compose.calls.get(), 1);
    assert_eq!(graph.contents.len(), 6);
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_config_resource_limit_prevents_execution()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(
      fixture.root.join("compose.yaml"),
      "include: [oversized.yaml]\n",
    )?;
    fs::File::create(fixture.root.join("oversized.yaml"))?
      .set_len(super::MAX_BYTES as u64 + 1)?;
    let compose = FakeCompose::new();
    let error = super::inspect_and_run_config(
      &fixture.root,
      None,
      &["compose.yaml".into()],
      &[],
      Default::default(),
      async |_, _, _| {
        compose.run("config").map_err(|_| {
          super::error(ErrorKind::ComposeValidation, None)
        })
      },
    )
    .await
    .err()
    .expect("oversized graph must fail before config");
    assert_eq!(error.kind, ErrorKind::Limit);
    assert_eq!(compose.calls.get(), 0);
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_config_marks_nested_remote_untracked()
  -> anyhow::Result<()> {
    for path in ["modules/compose.yaml", "modules/child/compose.yaml"]
    {
      let fixture = Fixture::new("nested")?;
      fs::write(
        fixture.root.join(path),
        "include: [https://compose-include.invalid/stack.git]\n",
      )?;
      let compose = FakeCompose::new();
      let (graph, _) = super::inspect_and_run_config(
        &fixture.root,
        None,
        &["compose.yaml".into()],
        &[],
        Default::default(),
        async |_, _, _| {
          compose.run("config").map_err(|_| {
            super::error(ErrorKind::ComposeValidation, None)
          })
        },
      )
      .await?;
      assert!(graph.has_untracked_remote);
      assert_eq!(compose.calls.get(), 1);
    }
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_config_failure_is_not_retried_or_successful()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let compose = FakeCompose::new();
    let result = super::inspect_and_run_config(
      &fixture.root,
      None,
      &["compose.yaml".into()],
      &[],
      Default::default(),
      async |_, _, _| {
        compose.run("config").map_err(|_| {
          super::error(ErrorKind::ComposeValidation, None)
        })?;
        Err::<(), _>(super::error(ErrorKind::ComposeValidation, None))
      },
    )
    .await;
    let error =
      result.err().expect("failed config must not return a graph");
    assert_eq!(error.kind, ErrorKind::ComposeValidation);
    assert_eq!(compose.calls.get(), 1);
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_config_special_source_prevents_execution()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(
      fixture.root.join("compose.yaml"),
      "include: [special.yaml]\n",
    )?;
    let _socket = std::os::unix::net::UnixDatagram::bind(
      fixture.root.join("special.yaml"),
    )?;
    let compose = FakeCompose::new();
    let error = super::inspect_and_run_config(
      &fixture.root,
      None,
      &["compose.yaml".into()],
      &[],
      Default::default(),
      async |_, _, _| {
        compose.run("config").map_err(|_| {
          super::error(ErrorKind::ComposeValidation, None)
        })
      },
    )
    .await
    .err()
    .expect("non-regular source must fail before config");
    assert_eq!(error.kind, ErrorKind::UnsupportedForm);
    assert_eq!(compose.calls.get(), 0);
    Ok(())
  }

  #[test]
  fn compose_include_walk_nested_sources() -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let graph = graph(&fixture, Default::default())?;
    assert_eq!(graph.roots, [fixture.root.join("compose.yaml")]);
    let mut paths = graph
      .dependencies
      .iter()
      .filter(|file| file.kind == DependencyKind::Compose)
      .map(|file| file.path.strip_prefix(&fixture.root).unwrap())
      .collect::<Vec<_>>();
    paths.sort_unstable();
    assert_eq!(
      paths,
      [
        Path::new("compose.yaml"),
        Path::new("modules/child/compose.yaml"),
        Path::new("modules/compose.yaml"),
      ]
    );
    Ok(())
  }

  #[test]
  fn compose_include_walk_long_context_and_environment()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("long")?;
    let graph = graph(&fixture, Default::default())?;
    for path in ["module/compose.yaml", "module/override.yaml"] {
      assert!(graph.dependencies.iter().any(|file| {
        file.path == fixture.root.join(path)
          && file.project_directory == fixture.root.join("project")
      }));
    }
    assert_eq!(
      graph
        .dependencies
        .iter()
        .filter(|file| {
          file.kind == DependencyKind::Compose
            && file.path != fixture.root.join("compose.yaml")
        })
        .map(|file| file.path.strip_prefix(&fixture.root).unwrap())
        .collect::<Vec<_>>(),
      [
        Path::new("module/compose.yaml"),
        Path::new("module/override.yaml"),
      ]
    );
    assert!(graph.dependencies.iter().any(|file| {
      file.kind == DependencyKind::Environment
        && file.path == fixture.root.join("include.env")
    }));
    Ok(())
  }

  #[test]
  fn compose_include_walk_default_environment_and_precedence()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(
      fixture.root.join("compose.yaml"),
      "include: [\"${CHILD:?required}\"]\n",
    )?;
    fs::write(
      fixture.root.join(".env"),
      "CHILD=missing.yaml\nLEAF=child/compose.yaml\n",
    )?;
    fs::write(
      fixture.root.join("modules/compose.yaml"),
      "include: [\"${LEAF:?required}\"]\n",
    )?;
    fs::write(
      fixture.root.join("modules/.env"),
      "LEAF=missing.yaml\n",
    )?;
    let graph = graph(
      &fixture,
      [("CHILD".into(), "modules/compose.yaml".into())].into(),
    )?;
    assert!(graph.contents.contains_key(
      &fixture.root.join("modules/child/compose.yaml")
    ));
    assert!(
      graph
        .contents
        .contains_key(&fixture.root.join("modules/.env"))
    );
    Ok(())
  }

  #[test]
  fn compose_include_walk_process_environment_controls()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(
      fixture.root.join("compose.yaml"),
      "include: [\"${CHILD:?required}\"]\nservices: {}\n",
    )?;
    fs::write(fixture.root.join(".env"), "CHILD=missing.yaml\n")?;
    fs::write(
      fixture.root.join("first.env"),
      "CHILD=missing.yaml\n",
    )?;
    fs::write(
      fixture.root.join("second.env"),
      "CHILD=modules/compose.yaml\n",
    )?;
    fs::write(fixture.root.join("modules/.env"), "MODULE=ok\n")?;
    let roots = vec!["compose.yaml".into()];
    let controls = BTreeMap::from([(
      "COMPOSE_ENV_FILES".into(),
      "first.env,,second.env".into(),
    )]);
    let result = inspect(&fixture.root, &roots, &[], controls)?;
    for path in ["first.env", "second.env", "modules/.env"] {
      assert!(result.contents.contains_key(&fixture.root.join(path)));
    }
    assert!(
      !result.contents.contains_key(&fixture.root.join(".env"))
    );
    assert!(result.contents.contains_key(
      &fixture.root.join("modules/child/compose.yaml")
    ));

    let controls = BTreeMap::from([
      ("COMPOSE_ENV_FILES".into(), "missing.env".into()),
      ("COMPOSE_DISABLE_ENV_FILE".into(), "true".into()),
    ]);
    let result = inspect(
      &fixture.root,
      &roots,
      &["second.env".into()],
      controls,
    )?;
    assert!(
      result
        .contents
        .contains_key(&fixture.root.join("second.env"))
    );
    assert!(
      result
        .contents
        .contains_key(&fixture.root.join("modules/.env"))
    );
    assert!(
      !result.contents.contains_key(&fixture.root.join(".env"))
    );

    let controls = BTreeMap::from([
      ("COMPOSE_DISABLE_ENV_FILE".into(), "true".into()),
      ("CHILD".into(), "modules/compose.yaml".into()),
    ]);
    let result = inspect(&fixture.root, &roots, &[], controls)?;
    assert!(
      !result.contents.contains_key(&fixture.root.join(".env"))
    );
    assert!(
      result
        .contents
        .contains_key(&fixture.root.join("modules/.env"))
    );
    Ok(())
  }

  #[test]
  #[ignore = "requires Docker Compose"]
  fn compose_include_cli_process_environment_controls()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(
      fixture.root.join("compose.yaml"),
      "include: [\"${CHILD:?required}\"]\nservices:\n  root:\n    image: synthetic/root\n",
    )?;
    fs::write(
      fixture.root.join("modules/compose.yaml"),
      "include: [\"${LEAF:?required}\"]\nservices:\n  module:\n    image: synthetic/module\n",
    )?;
    fs::write(fixture.root.join(".env"), "CHILD=missing.yaml\n")?;
    fs::write(
      fixture.root.join("first.env"),
      "CHILD=missing.yaml\n",
    )?;
    fs::write(
      fixture.root.join("second.env"),
      "CHILD=modules/compose.yaml\n",
    )?;
    fs::write(
      fixture.root.join("modules/.env"),
      "LEAF=child/compose.yaml\n",
    )?;
    let scenarios = [
      (
        BTreeMap::from([(
          "COMPOSE_ENV_FILES".to_string(),
          "first.env,,second.env".to_string(),
        )]),
        Vec::new(),
      ),
      (
        BTreeMap::from([
          ("COMPOSE_ENV_FILES".into(), "missing.env".into()),
          ("COMPOSE_DISABLE_ENV_FILE".into(), "true".into()),
        ]),
        vec!["second.env".to_string()],
      ),
      (
        BTreeMap::from([
          ("COMPOSE_DISABLE_ENV_FILE".into(), "true".into()),
          ("CHILD".into(), "modules/compose.yaml".into()),
        ]),
        Vec::new(),
      ),
    ];
    for (environment, files) in scenarios {
      let graph = inspect(
        &fixture.root,
        &["compose.yaml".into()],
        &files,
        environment.clone(),
      )?;
      assert!(graph.contents.contains_key(
        &fixture.root.join("modules/child/compose.yaml")
      ));
      let mut command = Command::new("docker");
      command
        .env_clear()
        .env(
          "PATH",
          std::env::var_os("PATH").context("missing PATH")?,
        )
        .env("HOME", &fixture.root)
        .envs(&environment)
        .current_dir(&fixture.root)
        .args([
          "compose",
          "-p",
          "komodo-env-controls",
          "-f",
          "compose.yaml",
        ]);
      for file in &files {
        command.args(["--env-file", file]);
      }
      let output = command.args(["config", "--services"]).output()?;
      assert!(
        output.status.success(),
        "Compose rejected synthetic environment-control fixture: {}",
        String::from_utf8_lossy(&output.stderr)
      );
      let mut services = String::from_utf8(output.stdout)?
        .lines()
        .map(str::to_string)
        .collect::<Vec<_>>();
      services.sort();
      assert_eq!(services, ["leaf", "module", "root"]);
    }
    for (key, value) in [
      ("COMPOSE_ENV_FILES", "missing.env"),
      ("COMPOSE_DISABLE_ENV_FILE", "true"),
    ] {
      fs::write(
        fixture.root.join(".env"),
        format!("CHILD=modules/compose.yaml\n{key}={value}\n"),
      )?;
      let output = Command::new("docker")
        .env_clear()
        .env(
          "PATH",
          std::env::var_os("PATH").context("missing PATH")?,
        )
        .env("HOME", &fixture.root)
        .current_dir(&fixture.root)
        .args([
          "compose",
          "-p",
          "komodo-env-controls",
          "-f",
          "compose.yaml",
          "config",
          "--services",
        ])
        .output()?;
      let walker = inspect(
        &fixture.root,
        &["compose.yaml".into()],
        &[],
        BTreeMap::new(),
      );
      if key == "COMPOSE_DISABLE_ENV_FILE" {
        assert!(!output.status.success());
        assert_eq!(
          walker.err().unwrap().kind,
          ErrorKind::Interpolation
        );
        let environment = BTreeMap::from([(
          "CHILD".into(),
          "modules/compose.yaml".into(),
        )]);
        let graph = inspect(
          &fixture.root,
          &["compose.yaml".into()],
          &[],
          environment,
        )?;
        assert!(
          graph.contents.contains_key(&fixture.root.join(".env"))
        );
      } else {
        assert!(
          output.status.success(),
          "Compose rejected synthetic dotenv control {key}: {}",
          String::from_utf8_lossy(&output.stderr)
        );
        assert!(walker.is_ok());
      }
    }
    fs::write(
      fixture.root.join(".env"),
      "CHILD=${COMPOSE_CHILD:-missing.yaml}\nCOMPOSE_CHILD=modules/compose.yaml\n",
    )?;
    let graph = inspect(
      &fixture.root,
      &["compose.yaml".into()],
      &[],
      BTreeMap::new(),
    )?;
    assert!(graph.contents.contains_key(
      &fixture.root.join("modules/child/compose.yaml")
    ));
    let output = Command::new("docker")
      .env_clear()
      .env("PATH", std::env::var_os("PATH").context("missing PATH")?)
      .env("HOME", &fixture.root)
      .current_dir(&fixture.root)
      .args([
        "compose",
        "-p",
        "komodo-env-controls",
        "-f",
        "compose.yaml",
        "config",
        "--services",
      ])
      .output()?;
    assert!(
      output.status.success(),
      "Compose rejected synthetic dotenv preloading: {}",
      String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
  }

  #[test]
  fn compose_include_walk_aliases_and_merges() -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(
      fixture.root.join("compose.yaml"),
      "x-inputs: &inputs\n  include: [modules/compose.yaml]\n<<: *inputs\n",
    )?;
    assert_eq!(
      graph(&fixture, Default::default())?.contents.len(),
      3
    );
    Ok(())
  }

  #[test]
  fn compose_include_walk_repeated_loading_contexts()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(
      fixture.root.join("compose.yaml"),
      "include:\n  - path: common.yaml\n    project_directory: a\n  - path: common.yaml\n    project_directory: b\n",
    )?;
    fs::write(
      fixture.root.join("common.yaml"),
      "include: [\"${LEAF:?required}\"]\n",
    )?;
    for directory in ["a", "b"] {
      fs::create_dir(fixture.root.join(directory))?;
      fs::write(
        fixture.root.join(directory).join(".env"),
        "LEAF=child.yaml\n",
      )?;
      fs::write(
        fixture.root.join(directory).join("child.yaml"),
        "services: {}\n",
      )?;
    }
    let graph = graph(&fixture, Default::default())?;
    let contexts = graph
      .dependencies
      .iter()
      .filter(|file| file.path == fixture.root.join("common.yaml"))
      .map(|file| &file.project_directory)
      .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(contexts.len(), 2);
    for directory in ["a", "b"] {
      assert!(graph.contents.contains_key(
        &fixture.root.join(directory).join("child.yaml")
      ));
    }
    Ok(())
  }

  #[test]
  fn compose_include_walk_rejects_missing_cycles_and_tags()
  -> anyhow::Result<()> {
    for (yaml, expected) in [
      ("include: [missing.yaml]\n", ErrorKind::MissingSource),
      ("include: [compose.yaml]\n", ErrorKind::IncludeCycle),
      (
        "include: [modules/compose.yaml]\nx-test: !custom value\n",
        ErrorKind::UnsupportedForm,
      ),
      ("include: [\n", ErrorKind::InvalidSource),
      (
        "include: [{path: modules/compose.yaml, unknown: value}]\n",
        ErrorKind::UnsupportedForm,
      ),
    ] {
      let fixture = Fixture::new("nested")?;
      fs::write(fixture.root.join("compose.yaml"), yaml)?;
      let error = graph(&fixture, Default::default())
        .err()
        .expect("invalid dependency graph must fail");
      assert_eq!(error.kind, expected, "{yaml}");
    }
    Ok(())
  }

  #[test]
  #[ignore = "requires Docker Compose"]
  fn compose_include_cli_compose_override_tags() -> anyhow::Result<()>
  {
    let fixture = Fixture::new("nested")?;
    fs::write(
      fixture.root.join("compose.yaml"),
      "include: [modules/compose.yaml]\nservices:\n  root:\n    image: synthetic/root\n    ports: !reset []\n    environment: !override {TEST: value}\n",
    )?;
    let graph = graph(&fixture, Default::default())?;
    assert!(
      graph
        .contents
        .contains_key(&fixture.root.join("modules/compose.yaml"))
    );
    let output = fixture.compose()?;
    assert!(
      output.status.success(),
      "{}",
      String::from_utf8_lossy(&output.stderr)
    );
    let mut services = String::from_utf8(output.stdout)?
      .lines()
      .map(str::to_owned)
      .collect::<Vec<_>>();
    services.sort();
    assert_eq!(services, ["leaf", "module", "root"]);
    Ok(())
  }

  #[test]
  fn compose_include_walk_marks_interpolated_remote_sources_untracked()
  -> anyhow::Result<()> {
    for remote in [
      "https://synthetic-user:synthetic-secret@compose-include.invalid/stack.git",
      "http://compose-include.invalid/compose.yaml",
      "oci://compose-include.invalid/stack:synthetic",
      "git@compose-include.invalid:stack.git",
      "ssh://git@compose-include.invalid/stack.git",
      "git://compose-include.invalid/stack.git",
      "github.com/komodo-conformance/absent.git",
    ] {
      let fixture = Fixture::new("nested")?;
      fs::write(
        fixture.root.join("compose.yaml"),
        "include: [\"${REMOTE:?required}\"]\n",
      )?;
      let graph =
        graph(&fixture, [("REMOTE".into(), remote.into())].into())?;
      assert!(graph.has_untracked_remote);
    }
    Ok(())
  }

  #[test]
  fn compose_include_interpolation_operators_and_escaping()
  -> anyhow::Result<()> {
    let environment = [
      ("SET".into(), "value".into()),
      ("EMPTY".into(), String::new()),
    ]
    .into();
    for (input, expected) in [
      ("$SET/${SET}", "value/value"),
      ("${MISSING:-${SET}}", "value"),
      ("${EMPTY:-fallback}", "fallback"),
      ("${EMPTY-fallback}", ""),
      ("${SET:+alternate}", "alternate"),
      ("${EMPTY:+alternate}", ""),
      ("${EMPTY+alternate}", "alternate"),
      ("$${SET}", "${SET}"),
      ("${SET:?required}", "value"),
    ] {
      assert_eq!(expand(input, &environment)?, expected, "{input}");
    }
    for input in
      ["${MISSING?required}", "${EMPTY:?synthetic-secret}", "${SET"]
    {
      let error = expand(input, &environment).unwrap_err();
      assert_eq!(error.kind, ErrorKind::Interpolation);
      assert!(!error.to_string().contains("synthetic-secret"));
    }
    Ok(())
  }

  #[test]
  fn compose_include_walk_root_order_and_explicit_env_files()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(fixture.root.join("first.env"), "NEXT=missing.yaml\n")?;
    fs::write(
      fixture.root.join("last.env"),
      "NEXT=modules/compose.yaml\n",
    )?;
    fs::write(fixture.root.join("override.yaml"), "services: {}\n")?;
    fs::write(
      fixture.root.join("compose.yaml"),
      "include: [\"${NEXT:?required}\"]\n",
    )?;
    let graph = inspect(
      &fixture.root,
      &["override.yaml".into(), "compose.yaml".into()],
      &["first.env".into(), "last.env".into()],
      Default::default(),
    )?;
    assert_eq!(
      graph.roots,
      [
        fixture.root.join("override.yaml"),
        fixture.root.join("compose.yaml")
      ]
    );
    assert!(
      graph
        .contents
        .contains_key(&fixture.root.join("modules/compose.yaml"))
    );
    Ok(())
  }

  #[test]
  fn compose_include_walk_fingerprints_track_exact_source_bytes()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let before = graph(&fixture, Default::default())?;
    let changed = fixture.root.join("modules/compose.yaml");
    let text = fs::read_to_string(&changed)?;
    fs::write(&changed, format!("{text}\n# synthetic change\n"))?;
    let after = graph(&fixture, Default::default())?;
    for previous in before.dependencies {
      let current = after
        .dependencies
        .iter()
        .find(|file| file.path == previous.path)
        .expect("dependency must still exist");
      assert_eq!(
        previous.fingerprint == current.fingerprint,
        previous.path != changed
      );
    }
    Ok(())
  }

  #[test]
  fn compose_include_walk_canonical_symlink_cycle()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(
      fixture.root.join("compose.yaml"),
      "include: [alias.yaml]\n",
    )?;
    std::os::unix::fs::symlink(
      fixture.root.join("compose.yaml"),
      fixture.root.join("alias.yaml"),
    )?;
    let error = graph(&fixture, Default::default())
      .err()
      .expect("alias cycle must fail");
    assert_eq!(error.kind, ErrorKind::IncludeCycle);
    Ok(())
  }

  #[test]
  fn compose_include_walk_depth_boundary() -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(
      fixture.root.join("compose.yaml"),
      "include: [level-1.yaml]\n",
    )?;
    for level in 1..=super::MAX_DEPTH {
      let text = if level == super::MAX_DEPTH {
        "services: {}\n".into()
      } else {
        format!("include: [level-{}.yaml]\n", level + 1)
      };
      fs::write(
        fixture.root.join(format!("level-{level}.yaml")),
        text,
      )?;
    }
    graph(&fixture, Default::default())?;
    fs::write(
      fixture
        .root
        .join(format!("level-{}.yaml", super::MAX_DEPTH)),
      "include: [too-deep.yaml]\n",
    )?;
    fs::write(fixture.root.join("too-deep.yaml"), "services: {}\n")?;
    let error = graph(&fixture, Default::default())
      .err()
      .expect("excessive depth must fail");
    assert_eq!(error.kind, ErrorKind::Limit);
    Ok(())
  }

  #[test]
  fn compose_include_walk_file_count_boundary() -> anyhow::Result<()>
  {
    let fixture = Fixture::new("nested")?;
    let mut includes = String::from("include:\n");
    for index in 1..super::MAX_FILES {
      let path = format!("source-{index}.yaml");
      fs::write(fixture.root.join(&path), "services: {}\n")?;
      includes.push_str(&format!("  - {path}\n"));
    }
    fs::write(fixture.root.join("compose.yaml"), &includes)?;
    assert_eq!(
      graph(&fixture, Default::default())?.contents.len(),
      super::MAX_FILES
    );
    fs::write(fixture.root.join("overflow.yaml"), "services: {}\n")?;
    includes.push_str("  - overflow.yaml\n");
    fs::write(fixture.root.join("compose.yaml"), includes)?;
    let error = graph(&fixture, Default::default())
      .err()
      .expect("excessive sources must fail");
    assert_eq!(error.kind, ErrorKind::Limit);
    Ok(())
  }

  #[test]
  fn compose_include_walk_limits_configured_env_files()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let controls = BTreeMap::from([(
      "COMPOSE_ENV_FILES".into(),
      vec!["unused.env"; super::MAX_FILES + 1].join(","),
    )]);
    let roots = vec!["compose.yaml".into()];
    let error = inspect(&fixture.root, &roots, &[], controls.clone())
      .err()
      .expect("excessive configured env files must fail");
    assert_eq!(error.kind, ErrorKind::Limit);

    fs::write(fixture.root.join("selected.env"), "")?;
    inspect(
      &fixture.root,
      &roots,
      &["selected.env".into()],
      controls,
    )?;
    Ok(())
  }

  #[test]
  fn compose_include_walk_byte_boundary() -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let header = "include: [padded.yaml]\n";
    fs::write(fixture.root.join("compose.yaml"), header)?;
    let padding = format!(
      "services: {{}}\n#{}",
      "x".repeat(super::MAX_BYTES - header.len() - 14)
    );
    fs::write(fixture.root.join("padded.yaml"), padding)?;
    let graph_at_limit = graph(&fixture, Default::default())?;
    assert_eq!(
      graph_at_limit
        .contents
        .values()
        .map(String::len)
        .sum::<usize>(),
      super::MAX_BYTES
    );
    drop(graph_at_limit);
    let mut file = fs::OpenOptions::new()
      .append(true)
      .open(fixture.root.join("padded.yaml"))?;
    std::io::Write::write_all(&mut file, b"x")?;
    let error = graph(&fixture, Default::default())
      .err()
      .expect("excessive bytes must fail");
    assert_eq!(error.kind, ErrorKind::Limit);
    Ok(())
  }

  #[test]
  fn compose_include_walk_context_state_is_bounded_without_losing_reuse()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let value = "x".repeat(1024 * 1024);
    fs::write(fixture.root.join(".env"), format!("BASE={value}\n"))?;
    fs::write(fixture.root.join("common.yaml"), "services: {}\n")?;
    let contexts = super::MAX_STATE_BYTES / value.len() + 1;
    let mut source = String::from("include:\n");
    for index in 0..contexts {
      source.push_str(&format!(
        "  - path: common.yaml\n    project_directory: context-{index}\n    env_file: /dev/null\n",
      ));
    }
    fs::write(fixture.root.join("compose.yaml"), source)?;
    let error = graph(&fixture, Default::default()).err().unwrap();
    assert_eq!(error.kind, ErrorKind::Limit);

    let reused =
      "  - path: common.yaml\n    project_directory: reused\n    env_file: /dev/null\n".repeat(contexts);
    fs::write(
      fixture.root.join("compose.yaml"),
      format!("include:\n{reused}"),
    )?;
    assert_eq!(
      graph(&fixture, Default::default())?.contents.len(),
      3
    );
    Ok(())
  }

  #[test]
  fn compose_include_environment_aggregate_expansion_is_bounded()
  -> anyhow::Result<()> {
    let value = "x".repeat(1024 * 1024);
    let inherited = BTreeMap::from([("BASE".into(), value.clone())]);
    let copies = super::MAX_STATE_BYTES / value.len() + 1;
    let mut text = String::new();
    for index in 0..copies {
      text.push_str(&format!("COPY_{index}=${{BASE}}\n"));
    }
    let error =
      super::parse_environment(&text, &inherited).err().unwrap();
    assert_eq!(error.kind, ErrorKind::Limit);
    let replaced = super::parse_environment(
      &"COPY=${BASE}\n".repeat(copies),
      &inherited,
    )?;
    assert_eq!(replaced["COPY"], value);
    assert_eq!(replaced.len(), 1);
    Ok(())
  }

  #[test]
  fn compose_include_walk_expanded_models_share_the_state_budget()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let base = format!(
      "services: {{}}\nx-base: &base '{}'\nx-copies:\n",
      "x".repeat(1024 * 1024)
    );
    fs::write(
      fixture.root.join("compose.yaml"),
      format!("{base}{}", "  - *base\n".repeat(65)),
    )?;
    assert_eq!(
      graph(&fixture, Default::default()).err().unwrap().kind,
      ErrorKind::Limit
    );
    for (path, child) in [
      ("compose.yaml", "include: [modules/compose.yaml]\n"),
      ("modules/compose.yaml", "include: [child/compose.yaml]\n"),
      ("modules/child/compose.yaml", ""),
    ] {
      fs::write(
        fixture.root.join(path),
        format!("{child}{base}{}", "  - *base\n".repeat(25)),
      )?;
    }
    assert_eq!(
      graph(&fixture, Default::default()).err().unwrap().kind,
      ErrorKind::Limit
    );
    fs::write(
      fixture.root.join("compose.yaml"),
      format!("{base}{}", "  - *base\n".repeat(2)),
    )?;
    assert_eq!(
      graph(&fixture, Default::default())?.contents.len(),
      1
    );
    Ok(())
  }

  #[test]
  fn compose_include_environment_quotes_and_substitution()
  -> anyhow::Result<()> {
    let inherited = [("BASE".into(), "inherited".into())].into();
    let values = super::parse_environment(
      "BASE=file\nNEXT=\"${BASE}/${FALLBACK:-module}\"\nLITERAL='${BASE}'\nMULTILINE='first\nsecond'\nESCAPED=\"one\\ntwo\"\nCOMMENT=value # comment\nHASH=value#literal\n",
      &inherited,
    )?;
    assert_eq!(values["NEXT"], "inherited/module");
    assert_eq!(values["LITERAL"], "${BASE}");
    assert_eq!(values["MULTILINE"], "first\nsecond");
    assert_eq!(values["ESCAPED"], "one\ntwo");
    assert_eq!(values["COMMENT"], "value");
    assert_eq!(values["HASH"], "value#literal");
    let unsupported = super::parse_environment(
      "VALUE=\"\\u0061\"\n",
      &Default::default(),
    )
    .unwrap_err();
    assert_eq!(unsupported.kind, ErrorKind::UnsupportedForm);
    Ok(())
  }

  #[test]
  #[ignore = "requires Docker Compose"]
  fn compose_include_cli_dependency_and_environment_parity()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(
      fixture.root.join("compose.yaml"),
      "include: [\"${NEXT:?required}\"]\nservices:\n  root:\n    image: \"${IMAGE:?required}\"\n",
    )?;
    fs::write(
      fixture.root.join(".env"),
      "BASE=conformance\nIMAGE=\"${BASE}/root:synthetic\"\nNEXT='modules/compose.yaml'\nLEAF=child/compose.yaml\n",
    )?;
    fs::write(
      fixture.root.join("modules/compose.yaml"),
      "include: [\"${LEAF:?required}\"]\nservices:\n  module:\n    image: conformance/module:synthetic\n",
    )?;
    fs::write(
      fixture.root.join("modules/.env"),
      "LEAF=missing.yaml\n",
    )?;
    let graph = graph(&fixture, Default::default())?;
    assert!(graph.contents.contains_key(
      &fixture.root.join("modules/child/compose.yaml")
    ));
    let model = fixture.compose_model(&["compose.yaml"], &[])?;
    let services =
      model["services"].as_object().context("missing services")?;
    assert_eq!(
      services.keys().map(String::as_str).collect::<Vec<_>>(),
      ["leaf", "module", "root"]
    );
    assert_eq!(
      services["root"]["image"],
      "conformance/root:synthetic"
    );
    Ok(())
  }

  #[test]
  #[ignore = "requires Docker Compose"]
  fn compose_include_cli_environment_syntax_parity()
  -> anyhow::Result<()> {
    for text in [
      "VALUE='${LITERAL}'\n",
      "VALUE=\"one\\ntwo\"\n",
      "VALUE=\"\\${LITERAL}\"\n",
      "VALUE\n",
      "VALUE=discarded\nVALUE\n",
      "VALUE=content#literal\n",
      "VALUE=content # comment\n",
      "VALUE='first\nsecond'\n",
      "BASE=module\nVALUE=${MISSING:-${BASE}}\n",
      "VALUE='Let\\'s test'\n",
    ] {
      let fixture = Fixture::new("nested")?;
      fs::write(
        fixture.root.join("compose.yaml"),
        "include: [\"${VALUE-UNSET}.yaml\"]\nservices:\n  root:\n    image: conformance/root:synthetic\n",
      )?;
      fs::write(fixture.root.join(".env"), text)?;
      let parsed =
        super::parse_environment(text, &Default::default())?;
      let expected =
        parsed.get("VALUE").map(String::as_str).unwrap_or("UNSET");
      fs::write(
        fixture.root.join(format!("{expected}.yaml")),
        "services:\n  child:\n    image: conformance/child:synthetic\n",
      )?;
      graph(&fixture, Default::default())?;
      let model = fixture
        .compose_model(&["compose.yaml"], &[])
        .with_context(|| format!("environment syntax: {text}"))?;
      assert!(model["services"].get("child").is_some());
    }
    Ok(())
  }

  #[test]
  #[ignore = "requires Docker Compose"]
  fn compose_include_cli_shared_root_override_is_not_a_cycle()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(
      fixture.root.join("compose.yaml"),
      "include:\n  - path: [module.yaml, override.yaml]\nservices:\n  root:\n    image: conformance/root:synthetic\n",
    )?;
    fs::write(
      fixture.root.join("module.yaml"),
      "services:\n  module:\n    image: conformance/module:base\n",
    )?;
    fs::write(
      fixture.root.join("override.yaml"),
      "services:\n  module:\n    image: conformance/module:override\n",
    )?;
    let model = fixture
      .compose_model(&["compose.yaml", "override.yaml"], &[])?;
    assert_eq!(
      model["services"]["module"]["image"],
      "conformance/module:override"
    );
    let graph = inspect(
      &fixture.root,
      &["compose.yaml".into(), "override.yaml".into()],
      &[],
      Default::default(),
    )?;
    assert_eq!(graph.contents.len(), 3);
    assert_eq!(
      graph.roots,
      [
        fixture.root.join("compose.yaml"),
        fixture.root.join("override.yaml")
      ]
    );
    Ok(())
  }

  #[test]
  #[ignore = "requires Docker Compose"]
  fn compose_include_cli_nested_root_project_directory()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let model =
      fixture.compose_model(&["modules/compose.yaml"], &[])?;
    assert!(model["services"].get("leaf").is_some());
    let graph = inspect(
      &fixture.root,
      &["modules/compose.yaml".into()],
      &[],
      Default::default(),
    )?;
    assert!(graph.contents.contains_key(
      &fixture.root.join("modules/child/compose.yaml")
    ));
    Ok(())
  }

  #[test]
  #[ignore = "requires Docker Compose"]
  fn compose_include_cli_logical_symlink_context()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    for directory in ["logical", "physical"] {
      fs::create_dir(fixture.root.join(directory))?;
    }
    fs::write(
      fixture.root.join("compose.yaml"),
      "include: [logical/compose.yaml]\n",
    )?;
    fs::write(
      fixture.root.join("physical/compose.yaml"),
      "include: [leaf.yaml]\n",
    )?;
    fs::write(
      fixture.root.join("logical/leaf.yaml"),
      "services:\n  logical:\n    image: conformance/logical:synthetic\n",
    )?;
    fs::write(
      fixture.root.join("physical/leaf.yaml"),
      "services:\n  physical:\n    image: conformance/physical:synthetic\n",
    )?;
    std::os::unix::fs::symlink(
      "../physical/compose.yaml",
      fixture.root.join("logical/compose.yaml"),
    )?;
    let model = fixture.compose_model(&["compose.yaml"], &[])?;
    assert!(model["services"].get("logical").is_some());
    let graph = graph(&fixture, Default::default())?;
    assert!(
      graph
        .contents
        .contains_key(&fixture.root.join("logical/leaf.yaml"))
    );
    assert!(
      !graph
        .contents
        .contains_key(&fixture.root.join("physical/leaf.yaml"))
    );
    Ok(())
  }

  #[test]
  #[ignore = "requires Docker Compose"]
  fn compose_include_cli_uncreated_project_directory()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(
      fixture.root.join("compose.yaml"),
      "include:\n  - path: module.yaml\n    project_directory: not-created\n",
    )?;
    fs::write(
      fixture.root.join("module.yaml"),
      "services:\n  module:\n    image: conformance/module:synthetic\n",
    )?;
    let model = fixture.compose_model(&["compose.yaml"], &[])?;
    assert!(model["services"].get("module").is_some());
    let graph = graph(&fixture, Default::default())?;
    assert!(graph.dependencies.iter().any(|file| {
      file.project_directory == fixture.root.join("not-created")
    }));
    Ok(())
  }

  #[test]
  #[ignore = "requires Docker Compose"]
  fn compose_include_cli_nested_root_environment_priority()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(
      fixture.root.join("modules/compose.yaml"),
      "include: [\"${NEXT:?required}\"]\n",
    )?;
    fs::write(
      fixture.root.join("modules/.env"),
      "NEXT=child/compose.yaml\n",
    )?;
    let model =
      fixture.compose_model(&["modules/compose.yaml"], &[])?;
    assert!(model["services"].get("leaf").is_some());
    inspect(
      &fixture.root,
      &["modules/compose.yaml".into()],
      &[],
      Default::default(),
    )?;
    fs::write(fixture.root.join(".env"), "NEXT=alternative.yaml\n")?;
    fs::write(
      fixture.root.join("modules/alternative.yaml"),
      "services:\n  alternative:\n    image: conformance/alternative:synthetic\n",
    )?;
    let model =
      fixture.compose_model(&["modules/compose.yaml"], &[])?;
    assert!(model["services"].get("leaf").is_some());
    assert!(model["services"].get("alternative").is_none());
    let graph = inspect(
      &fixture.root,
      &["modules/compose.yaml".into()],
      &[],
      Default::default(),
    )?;
    assert!(graph.contents.contains_key(
      &fixture.root.join("modules/child/compose.yaml")
    ));
    assert!(!graph.contents.contains_key(&fixture.root.join(".env")));
    fs::remove_file(fixture.root.join("modules/.env"))?;
    assert!(
      fixture
        .compose_model(&["modules/compose.yaml"], &[])
        .is_err()
    );
    let error = inspect(
      &fixture.root,
      &["modules/compose.yaml".into()],
      &[],
      Default::default(),
    )
    .err()
    .expect("working-directory environment must not replace the project environment");
    assert_eq!(error.kind, ErrorKind::Interpolation);
    Ok(())
  }

  #[test]
  #[ignore = "requires Docker Compose"]
  fn compose_include_cli_explicit_local_uri_shaped_names()
  -> anyhow::Result<()> {
    for path in [
      "./https://synthetic/module.yaml",
      "./oci://synthetic/module.yaml",
      "./github.com/synthetic/module.yaml",
    ] {
      let fixture = Fixture::new("nested")?;
      let target = fixture.root.join(path);
      fs::create_dir_all(target.parent().context("missing parent")?)?;
      fs::write(
        &target,
        "services:\n  module:\n    image: conformance/module:synthetic\n",
      )?;
      fs::write(
        fixture.root.join("compose.yaml"),
        format!("include: ['{path}']\n"),
      )?;
      let model = fixture.compose_model(&["compose.yaml"], &[])?;
      assert!(model["services"].get("module").is_some());
      let graph = graph(&fixture, Default::default())?;
      assert!(
        graph.contents.contains_key(&fs::canonicalize(target)?)
      );
    }
    Ok(())
  }

  impl FakeCompose {
    pub(crate) fn run(
      &self,
      subcommand: &str,
    ) -> anyhow::Result<String> {
      if subcommand != "config" {
        bail!(
          "remote fetching and lifecycle commands are forbidden in fixtures"
        );
      }
      self.calls.set(self.calls.get() + 1);
      Ok("services:\n  fixture:\n    image: conformance/fixture:synthetic\n".into())
    }
  }

  #[test]
  #[ignore = "requires Docker Compose"]
  fn compose_include_cli_nested_services() -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let output = fixture.compose()?;
    assert!(
      output.status.success(),
      "local synthetic Compose model failed: {}",
      String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    let mut services = stdout.lines().collect::<Vec<_>>();
    services.sort_unstable();
    assert_eq!(services, ["leaf", "module", "root"]);
    Ok(())
  }

  #[test]
  #[ignore = "requires Docker Compose"]
  fn compose_include_cli_long_syntax() -> anyhow::Result<()> {
    let fixture = Fixture::new("long")?;
    let output = fixture.compose()?;
    assert!(
      output.status.success(),
      "long-syntax synthetic Compose model failed: {}",
      String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8(output.stdout)?.trim(), "module");
    Ok(())
  }
}
