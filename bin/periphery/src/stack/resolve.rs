//! Read-only source preparation and private worker for authenticated Compose discovery.
//! The caller owns the deadline and process group.

use std::{
  collections::{BTreeMap, BTreeSet, HashMap},
  io::{Read, Write},
  path::{Path, PathBuf},
  sync::{Arc, LazyLock, Weak},
  time::{Duration, Instant},
};

use command::{
  CommandOptions, CommandOutput, run_shell_command,
  run_standard_command,
};
use komodo_client::entities::stack::{
  ComposeDependencyKind, ComposeFile, ComposeResolutionError,
  ComposeResolutionSource, ComposeResolutionStage,
  DerivedComposeDependency, ObservedComposeSnapshot,
  StackFileRequires, StackRemoteFileContents, StackServiceNames,
};
use komodo_client::{
  entities::update::Log, parsers::parse_multiline_command,
};
use periphery_client::api::compose::{
  ResolveComposeStack, ResolveComposeStackResponse,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, OwnedMutexGuard};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::docker::compose::{
  ConfigFormat, config_command, parse_compose_config,
};

use super::include::{
  Dependency, DependencyKind, ErrorKind, Graph, IncludeError,
  MAX_BYTES, MAX_FILES, charge_bytes,
};

pub(crate) const WORKER_FLAG: &str = "--komodo-compose-resolver";
const MAX_RESULT_BYTES: usize = 64 * 1024 * 1024;
// JSON strings can require six bytes per byte; allow map punctuation and the envelope.
const MAX_REPLY: usize = 6 * MAX_RESULT_BYTES + 6 * MAX_FILES + 1024;

#[derive(Clone, Copy, Default, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum WorkerMode {
  #[default]
  Guarded,
  Refresh {
    legacy_cli: bool,
  },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerRequest {
  id: Uuid,
  #[serde(default)]
  mode: WorkerMode,
  project_name: String,
  roots: Vec<String>,
  #[serde(default)]
  files: Vec<komodo_client::entities::stack::StackFileDependency>,
  #[serde(default)]
  legacy_exclusions: Vec<String>,
  env_files: Vec<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  optional_env_file: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  source_root: Option<PathBuf>,
  replacers: Vec<(String, String)>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Resolved {
  directory: PathBuf,
  services: Vec<StackServiceNames>,
  dependencies: Vec<Dependency>,
  contents: BTreeMap<PathBuf, String>,
  has_untracked_remote: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(
  tag = "status",
  rename_all = "snake_case",
  deny_unknown_fields
)]
enum WorkerReply {
  Success {
    id: Uuid,
    result: Resolved,
  },
  Failure {
    id: Option<Uuid>,
    kind: ErrorKind,
    path: Option<PathBuf>,
  },
}

fn fail(kind: ErrorKind) -> IncludeError {
  IncludeError { kind, path: None }
}

pub(crate) async fn worker_entry() -> anyhow::Result<()> {
  let request = if std::env::args_os().count() == 2 {
    read_request(std::io::stdin().lock(), MAX_BYTES)
  } else {
    Err(fail(ErrorKind::WorkerInput))
  };
  let id = request.as_ref().ok().map(|request| request.id);
  let reply = match request {
    Ok(mut request) => match resolve_worker(&mut request).await {
      Ok(result) => WorkerReply::Success {
        id: request.id,
        result,
      },
      Err(mut error) => {
        if let Some(path) = error.path.take() {
          match redact_text(
            path.to_string_lossy().into_owned(),
            &request,
          ) {
            Ok(path) => error.path = Some(path.into()),
            Err(redaction) => error = redaction,
          }
        }
        WorkerReply::Failure {
          id,
          kind: error.kind,
          path: error.path,
        }
      }
    },
    Err(error) => WorkerReply::Failure {
      id,
      kind: error.kind,
      path: None,
    },
  };
  let success = matches!(reply, WorkerReply::Success { .. });
  let (bytes, success) = match encode_bounded(&reply, MAX_REPLY) {
    Ok(bytes) => (bytes, success),
    Err(error) => (
      encode_bounded(
        &WorkerReply::Failure {
          id,
          kind: error.kind,
          path: None,
        },
        MAX_REPLY,
      )?,
      false,
    ),
  };
  std::io::stdout().lock().write_all(&bytes).map_err(|_| {
    anyhow::anyhow!("Cannot write Compose resolver response")
  })?;
  if success {
    Ok(())
  } else {
    Err(anyhow::anyhow!("Compose resolver worker failed"))
  }
}

async fn resolve_worker(
  request: &mut WorkerRequest,
) -> Result<Resolved, IncludeError> {
  let directory = std::env::current_dir()
    .map_err(|_| fail(ErrorKind::SourceAccess))?;
  let environment = effective_environment()?;
  resolve_in_context(
    &directory,
    request,
    environment,
    async |roots, env_files, environment| {
      let command = config_command(
        "docker compose",
        &request.project_name,
        roots,
        env_files,
        ConfigFormat::Json,
      );
      let output = run_standard_command(
        &command,
        CommandOptions::default()
          .env(environment)
          .output_limit(MAX_BYTES)
          .inherit_process_group(true),
      )
      .await;
      if !output.success() {
        return Err(fail(
          if output.stderr.contains("Command output limit exceeded") {
            ErrorKind::Limit
          } else {
            ErrorKind::ComposeValidation
          },
        ));
      }
      Ok(output.stdout)
    },
  )
  .await
}

fn effective_environment()
-> Result<BTreeMap<String, String>, IncludeError> {
  std::env::vars_os()
    .map(|(key, value)| {
      Ok((
        key
          .into_string()
          .map_err(|_| fail(ErrorKind::UnsupportedForm))?,
        value
          .into_string()
          .map_err(|_| fail(ErrorKind::UnsupportedForm))?,
      ))
    })
    .collect()
}

async fn resolve_in_context(
  directory: &Path,
  request: &WorkerRequest,
  environment: BTreeMap<String, String>,
  run_config: impl AsyncFnOnce(
    &[String],
    &[String],
    &BTreeMap<String, String>,
  ) -> Result<String, IncludeError>,
) -> Result<Resolved, IncludeError> {
  validate_request(request)?;
  for value in std::iter::once(&request.project_name)
    .chain(&request.roots)
    .chain(&request.env_files)
    .chain(request.files.iter().map(|file| &file.path))
  {
    if redact_text(value.clone(), request)? != *value {
      return Err(fail(ErrorKind::UnsupportedForm));
    }
  }
  if let WorkerMode::Refresh { legacy_cli } = request.mode {
    let (graph, includes) = super::include::inspect_roots(
      directory,
      &request.roots,
      request.source_root.as_deref(),
    )?;
    if !includes {
      let graph = super::include::with_files(
        graph,
        directory,
        &request.files,
        request.source_root.as_deref(),
      )?;
      let mut services = Vec::new();
      for path in &graph.roots {
        if request
          .legacy_exclusions
          .iter()
          .any(|excluded| path.to_string_lossy().ends_with(excluded))
        {
          continue;
        }
        let text = graph
          .contents
          .get(
            &std::fs::canonicalize(path)
              .map_err(|_| fail(ErrorKind::SourceAccess))?,
          )
          .ok_or_else(|| fail(ErrorKind::SourceChanged))?;
        parse_compose_config(text, ConfigFormat::Yaml)
          .map_err(|_| fail(ErrorKind::ComposeValidation))?
          .append_source_services(
            &request.project_name,
            &HashMap::new(),
            &mut services,
          );
      }
      let (verified, _) = super::include::inspect_roots(
        directory,
        &request.roots,
        request.source_root.as_deref(),
      )
      .map_err(|_| fail(ErrorKind::SourceChanged))?;
      let verified = super::include::with_files(
        verified,
        directory,
        &request.files,
        request.source_root.as_deref(),
      )
      .map_err(|_| fail(ErrorKind::SourceChanged))?;
      if graph != verified {
        return Err(fail(ErrorKind::SourceChanged));
      }
      return finish_resolution(directory, graph, services, request);
    }
    if legacy_cli {
      return Err(fail(ErrorKind::UnsupportedCapability));
    }
  }
  let mut effective = request.clone();
  if let Some(file) = &request.optional_env_file {
    match std::fs::metadata(directory.join(file)) {
      Ok(metadata) if metadata.is_file() => {
        effective.env_files.retain(|path| path != file);
        effective.env_files.push(file.clone());
      }
      Ok(_) => {}
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
      Err(_) => {
        return Err(IncludeError {
          kind: ErrorKind::SourceAccess,
          path: Some(file.into()),
        });
      }
    }
  }
  let request = &effective;
  let graph =
    inspect_sources(directory, request, environment.clone())?;
  let model =
    run_config(&request.roots, &request.env_files, &environment)
      .await?;
  let verified = inspect_sources(directory, request, environment)
    .map_err(|_| fail(ErrorKind::SourceChanged))?;
  if graph != verified {
    return Err(fail(ErrorKind::SourceChanged));
  }
  drop(verified);
  if model.len() > MAX_BYTES {
    return Err(fail(ErrorKind::Limit));
  }
  let compose = parse_compose_config(&model, ConfigFormat::Json)
    .map_err(|_| fail(ErrorKind::ComposeValidation))?;
  drop(model);
  check_service_budget(&compose, &request.project_name)?;
  let mut services = Vec::new();
  crate::docker::compose::append_compose_services(
    compose,
    &request.project_name,
    &mut services,
  );
  finish_resolution(directory, graph, services, request)
}

fn inspect_sources(
  directory: &Path,
  request: &WorkerRequest,
  environment: BTreeMap<String, String>,
) -> Result<Graph, IncludeError> {
  let graph = match request.source_root.as_deref() {
    Some(root) => super::include::inspect_within(
      directory,
      &request.roots,
      &request.env_files,
      environment,
      Some(root),
    ),
    None => super::include::inspect(
      directory,
      &request.roots,
      &request.env_files,
      environment,
    ),
  }?;
  super::include::with_files(
    graph,
    directory,
    &request.files,
    request.source_root.as_deref(),
  )
}

pub(crate) fn deployment_snapshot(
  stack: &komodo_client::entities::stack::Stack,
  directory: &Path,
  env_files: &[String],
  expected: &komodo_client::entities::stack::AcceptedComposeResolution,
  replacers: &[(String, String)],
  revision: Option<&str>,
) -> anyhow::Result<
  Option<komodo_client::entities::stack::AcceptedComposeResolution>,
> {
  let identity = &expected.source_identity;
  if identity.request_identity.stack_id != stack.id
    || identity
      .observed_snapshot
      .validate(&identity.request_identity, &expected.dependencies)
      .is_err()
  {
    return Ok(None);
  }
  let (roots, includes) = super::include::inspect_roots(
    directory,
    stack.compose_file_paths(),
    None,
  )?;
  let graph = if includes {
    super::include::inspect(
      directory,
      stack.compose_file_paths(),
      env_files,
      effective_environment()?,
    )?
  } else {
    roots
  };
  let graph = super::include::with_files(
    graph,
    directory,
    &stack.all_file_dependencies(),
    None,
  )?;
  deployment_snapshot_from_graph(
    stack, directory, env_files, expected, replacers, revision, graph,
  )
}

#[cfg(target_os = "linux")]
pub(crate) struct DeploymentCapture {
  pub(crate) compose: super::snapshot::CapturedCompose,
  pub(crate) environment: BTreeMap<String, String>,
  pub(crate) evidence:
    komodo_client::entities::stack::AcceptedComposeResolution,
}

#[cfg(target_os = "linux")]
fn capture_deployment(
  stack: &komodo_client::entities::stack::Stack,
  directory: &Path,
  env_files: &[String],
  expected: &komodo_client::entities::stack::AcceptedComposeResolution,
  replacers: &[(String, String)],
  revision: Option<&str>,
  environment: BTreeMap<String, String>,
) -> anyhow::Result<Option<DeploymentCapture>> {
  let (_, includes) = super::include::inspect_roots(
    directory,
    stack.compose_file_paths(),
    None,
  )?;
  let graph = super::include::inspect(
    directory,
    stack.compose_file_paths(),
    env_files,
    environment.clone(),
  )?;
  if !includes && !graph.root_env_files.is_empty() {
    return Ok(None);
  }
  let graph = super::include::with_files(
    graph,
    directory,
    &stack.all_file_dependencies(),
    None,
  )?;
  super::snapshot::validate_deployment_graph(&graph)?;
  let compose = super::snapshot::CapturedCompose::from_graph(&graph)?;
  anyhow::ensure!(
    compose.project_directory.to_str().is_some(),
    "Compose project directory is not UTF-8"
  );
  let Some(evidence) = deployment_snapshot_from_graph(
    stack, directory, env_files, expected, replacers, revision, graph,
  )?
  else {
    return Ok(None);
  };
  Ok(Some(DeploymentCapture {
    compose,
    environment,
    evidence,
  }))
}

#[cfg(target_os = "linux")]
pub(crate) fn capture_current_deployment(
  stack: &komodo_client::entities::stack::Stack,
  directory: &Path,
  env_files: &[String],
  expected: &komodo_client::entities::stack::AcceptedComposeResolution,
  replacers: &[(String, String)],
  revision: Option<&str>,
) -> anyhow::Result<Option<DeploymentCapture>> {
  capture_deployment(
    stack,
    directory,
    env_files,
    expected,
    replacers,
    revision,
    effective_environment()?,
  )
}

fn deployment_snapshot_from_graph(
  stack: &komodo_client::entities::stack::Stack,
  directory: &Path,
  env_files: &[String],
  expected: &komodo_client::entities::stack::AcceptedComposeResolution,
  replacers: &[(String, String)],
  revision: Option<&str>,
  graph: Graph,
) -> anyhow::Result<
  Option<komodo_client::entities::stack::AcceptedComposeResolution>,
> {
  use komodo_client::entities::stack::{
    AcceptedComposeResolution, ComposeSourceIdentity,
  };
  let identity = &expected.source_identity;
  if identity.request_identity.stack_id != stack.id
    || identity
      .observed_snapshot
      .validate(&identity.request_identity, &expected.dependencies)
      .is_err()
  {
    return Ok(None);
  }
  if graph.has_untracked_remote {
    return Ok(None);
  }
  let worker = WorkerRequest {
    id: Uuid::new_v4(),
    mode: WorkerMode::Guarded,
    project_name: stack.project_name(true),
    roots: stack.compose_file_paths().to_vec(),
    files: stack.all_file_dependencies(),
    legacy_exclusions: Vec::new(),
    env_files: env_files.to_vec(),
    optional_env_file: None,
    source_root: None,
    replacers: replacers.to_vec(),
  };
  let resolved =
    redact_snapshot(directory, graph, Vec::new(), &worker, 0)?;
  let display = |path: &Path| {
    let path = path.strip_prefix(&resolved.directory).unwrap_or(path);
    path
      .to_str()
      .map(|path| if path.is_empty() { "." } else { path }.to_owned())
  };
  let mut dependencies =
    Vec::with_capacity(resolved.dependencies.len());
  for dependency in resolved.dependencies {
    let (Some(path), Some(project_directory)) = (
      display(&dependency.path),
      display(&dependency.project_directory),
    ) else {
      return Ok(None);
    };
    dependencies.push(DerivedComposeDependency {
      path,
      project_directory,
      kind: match dependency.kind {
        DependencyKind::Compose => ComposeDependencyKind::Compose,
        DependencyKind::Environment => {
          ComposeDependencyKind::Environment
        }
        DependencyKind::Auxiliary => ComposeDependencyKind::Auxiliary,
      },
      fingerprint: dependency.fingerprint,
      requires: dependency
        .policy
        .as_ref()
        .map(|policy| policy.requires)
        .unwrap_or(StackFileRequires::Redeploy),
      services: dependency
        .policy
        .map(|policy| policy.services)
        .unwrap_or_default(),
    });
  }
  let mut request_identity = identity.request_identity.clone();
  let commit_id =
    if let ComposeResolutionSource::Repository { commit_id, .. } =
      &mut request_identity.source
    {
      let Some(revision) = revision else {
        return Ok(None);
      };
      *commit_id = revision.into();
      Some(revision.into())
    } else {
      None
    };
  let observed_snapshot = ObservedComposeSnapshot {
    complete: true,
    dependency_fingerprints: dependencies
      .iter()
      .map(DerivedComposeDependency::observed_fingerprint)
      .collect(),
    commit_id,
    config_generation: (request_identity.source
      == ComposeResolutionSource::Ui)
      .then(|| request_identity.config_generation.clone()),
  };
  observed_snapshot.validate(&request_identity, &dependencies)?;
  Ok(Some(AcceptedComposeResolution {
    deployment_proven: false,
    source_identity: ComposeSourceIdentity {
      request_identity,
      observed_snapshot,
    },
    dependencies,
  }))
}

fn finish_resolution(
  directory: &Path,
  graph: Graph,
  mut services: Vec<StackServiceNames>,
  request: &WorkerRequest,
) -> Result<Resolved, IncludeError> {
  let mut output_size = 0;
  for service in &mut services {
    charge_bytes(&mut output_size, 256, MAX_RESULT_BYTES)?;
    for value in [
      &mut service.service_name,
      &mut service.container_name,
      &mut service.image,
    ] {
      *value = redact_text(std::mem::take(value), request)?;
      charge_bytes(&mut output_size, value.len(), MAX_RESULT_BYTES)?;
    }
  }
  redact_snapshot(directory, graph, services, request, output_size)
}

fn check_service_budget(
  compose: &ComposeFile,
  project: &str,
) -> Result<(), IncludeError> {
  let mut total = 0usize;
  for (name, service) in &compose.services {
    let count = service
      .deploy
      .as_ref()
      .and_then(|deploy| deploy.replicas)
      .unwrap_or(1)
      .max(1);
    let count =
      usize::try_from(count).map_err(|_| fail(ErrorKind::Limit))?;
    let bytes = project.len()
      + 2 * name.len()
      + service.image.as_ref().map(String::len).unwrap_or(0)
      + service
        .container_name
        .as_ref()
        .map(String::len)
        .unwrap_or(0);
    // Include JSON escaping, replica suffixes, and per-entry allocation overhead.
    let cost = bytes
      .checked_mul(6)
      .and_then(|bytes| bytes.checked_add(256))
      .and_then(|bytes| bytes.checked_mul(count))
      .ok_or_else(|| fail(ErrorKind::Limit))?;
    total = total
      .checked_add(cost)
      .filter(|total| *total <= MAX_RESULT_BYTES)
      .ok_or_else(|| fail(ErrorKind::Limit))?;
  }
  Ok(())
}

fn redact_text(
  mut text: String,
  request: &WorkerRequest,
) -> Result<String, IncludeError> {
  for pair @ (value, name) in &request.replacers {
    let occurrences = text.matches(value.as_str()).count();
    let size = occurrences
      .checked_mul(name.len() + 2)
      .and_then(|replacement| {
        (text.len() - occurrences * value.len())
          .checked_add(replacement)
      })
      .filter(|size| *size <= MAX_RESULT_BYTES)
      .ok_or_else(|| fail(ErrorKind::Limit))?;
    text = svi::replace_in_string(&text, std::slice::from_ref(pair));
    if text.len() != size {
      return Err(fail(ErrorKind::WorkerOutput));
    }
  }
  Ok(text)
}

fn redact_snapshot(
  directory: &Path,
  mut graph: Graph,
  services: Vec<StackServiceNames>,
  request: &WorkerRequest,
  mut output_size: usize,
) -> Result<Resolved, IncludeError> {
  let compose = graph
    .dependencies
    .iter()
    .filter(|dependency| {
      dependency.kind != DependencyKind::Environment
    })
    .map(|dependency| dependency.path.clone())
    .collect::<BTreeSet<_>>();
  let mut paths = BTreeMap::<PathBuf, PathBuf>::new();
  let mut redact_path =
    |path: &Path| -> Result<PathBuf, IncludeError> {
      let text = path
        .to_str()
        .ok_or_else(|| fail(ErrorKind::UnsupportedForm))?;
      let redacted =
        PathBuf::from(redact_text(text.into(), request)?);
      if let Some(original) =
        paths.insert(redacted.clone(), path.into())
        && original != path
      {
        return Err(fail(ErrorKind::UnsupportedForm));
      }
      Ok(redacted)
    };
  let mut contents = BTreeMap::new();
  for (path, text) in graph.contents {
    if compose.contains(&path) {
      let path = redact_path(&path)?;
      let text = redact_text(text, request)?;
      charge_bytes(
        &mut output_size,
        path.as_os_str().len(),
        MAX_RESULT_BYTES,
      )?;
      charge_bytes(&mut output_size, text.len(), MAX_RESULT_BYTES)?;
      contents.insert(path, text);
    }
  }
  for dependency in &mut graph.dependencies {
    if let Some(policy) = &mut dependency.policy {
      charge_bytes(&mut output_size, 128, MAX_RESULT_BYTES)?;
      for value in
        std::iter::once(&mut policy.path).chain(&mut policy.services)
      {
        *value = redact_text(std::mem::take(value), request)?;
        charge_bytes(
          &mut output_size,
          value.len() + 24,
          MAX_RESULT_BYTES,
        )?;
      }
    }
    dependency.path = redact_path(&dependency.path)?;
    dependency.project_directory =
      redact_path(&dependency.project_directory)?;
    charge_bytes(&mut output_size, 128, MAX_RESULT_BYTES)?;
    charge_bytes(
      &mut output_size,
      dependency.path.as_os_str().len(),
      MAX_RESULT_BYTES,
    )?;
    charge_bytes(
      &mut output_size,
      dependency.project_directory.as_os_str().len(),
      MAX_RESULT_BYTES,
    )?;
  }
  let directory = redact_path(directory)?;
  charge_bytes(
    &mut output_size,
    directory.as_os_str().len(),
    MAX_RESULT_BYTES,
  )?;
  Ok(Resolved {
    directory,
    services,
    dependencies: graph.dependencies,
    contents,
    has_untracked_remote: graph.has_untracked_remote,
  })
}

fn validate_request(
  request: &WorkerRequest,
) -> Result<(), IncludeError> {
  if request.roots.is_empty()
    || request.project_name.is_empty()
    || request.project_name.contains('\0')
    || request
      .replacers
      .iter()
      .any(|(value, name)| value.is_empty() || name.is_empty())
  {
    return Err(fail(ErrorKind::WorkerInput));
  }
  Ok(())
}

struct BoundedWriter {
  bytes: Vec<u8>,
  limit: usize,
  exceeded: bool,
}

impl Write for BoundedWriter {
  fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
    if bytes.len() > self.limit - self.bytes.len() {
      self.exceeded = true;
      return Err(std::io::Error::other(
        "Resolver output limit exceeded",
      ));
    }
    self.bytes.extend_from_slice(bytes);
    Ok(bytes.len())
  }

  fn flush(&mut self) -> std::io::Result<()> {
    Ok(())
  }
}

fn encode_bounded<T: Serialize>(
  value: &T,
  limit: usize,
) -> Result<Vec<u8>, IncludeError> {
  let mut writer = BoundedWriter {
    bytes: Vec::new(),
    limit,
    exceeded: false,
  };
  serde_json::to_writer(&mut writer, value).map_err(|_| {
    fail(if writer.exceeded {
      ErrorKind::Limit
    } else {
      ErrorKind::WorkerOutput
    })
  })?;
  Ok(writer.bytes)
}

fn read_request(
  reader: impl Read,
  limit: usize,
) -> Result<WorkerRequest, IncludeError> {
  let mut bytes = Vec::new();
  reader
    .take(limit.saturating_add(1) as u64)
    .read_to_end(&mut bytes)
    .map_err(|_| fail(ErrorKind::WorkerInput))?;
  if bytes.len() > limit {
    return Err(fail(ErrorKind::Limit));
  }
  let request: WorkerRequest = serde_json::from_slice(&bytes)
    .map_err(|_| fail(ErrorKind::WorkerInput))?;
  validate_request(&request)?;
  Ok(request)
}

fn decode_reply(
  request: &WorkerRequest,
  output: CommandOutput,
) -> Result<Resolved, IncludeError> {
  if output.stdout.len() > MAX_REPLY {
    return Err(fail(ErrorKind::Limit));
  }
  if output.stdout.is_empty() && !output.success() {
    return Err(fail(
      if output.stderr.starts_with("Command timed out after") {
        ErrorKind::Timeout
      } else if output.stderr.starts_with("Command cancelled") {
        ErrorKind::Cancelled
      } else if output
        .stderr
        .contains("Command output limit exceeded")
      {
        ErrorKind::Limit
      } else if output
        .stderr
        .contains("Command output is not valid UTF-8")
      {
        ErrorKind::WorkerOutput
      } else {
        ErrorKind::WrapperFailure
      },
    ));
  }
  let reply: WorkerReply = serde_json::from_str(&output.stdout)
    .map_err(|_| fail(ErrorKind::WorkerOutput))?;
  match reply {
    WorkerReply::Success { id, result } if id == request.id => {
      if !output.success() {
        return Err(fail(ErrorKind::WrapperFailure));
      }
      Ok(result)
    }
    WorkerReply::Failure {
      id: Some(id),
      kind,
      path,
    } if id == request.id => {
      let path = path
        .map(|path| {
          redact_text(path.to_string_lossy().into_owned(), request)
            .map(PathBuf::from)
        })
        .transpose()?;
      Err(IncludeError { kind, path })
    }
    _ => Err(fail(ErrorKind::WorkerOutput)),
  }
}

async fn invoke_worker(
  request: &WorkerRequest,
  command: &str,
  options: CommandOptions<'_>,
  deadline: Instant,
) -> Result<Resolved, IncludeError> {
  let payload =
    String::from_utf8(encode_bounded(request, MAX_BYTES)?)
      .map_err(|_| fail(ErrorKind::WorkerInput))?;
  let remaining = deadline
    .checked_duration_since(Instant::now())
    .ok_or_else(|| fail(ErrorKind::Timeout))?;
  let options = CommandOptions {
    stdin: Some(&payload),
    timeout: Some(remaining),
    output_limit: Some(MAX_REPLY),
    inherit_process_group: false,
    ..options
  };
  decode_reply(request, run_shell_command(command, options).await)
}

pub(super) fn worker_command(
  executable: &Path,
  wrapper: &str,
  wrapper_include: &[String],
) -> Result<String, Log> {
  let executable = executable
    .to_str()
    .filter(|value| !value.is_empty() && !value.contains('\0'))
    .ok_or_else(|| {
      Log::error(
        "Compose Resolver",
        "Resolver worker executable must be a nonempty UTF-8 path"
          .into(),
      )
    })?;
  let command = format!(
    "{} {WORKER_FLAG}",
    shell_escape::escape(executable.into()),
  );
  let wrapper = parse_multiline_command(wrapper);
  // The legacy empty-list default is "up", so it cannot select "config".
  let (command, wrapped) = crate::api::maybe_wrap_command(
    command,
    &wrapper,
    wrapper_include,
    "config",
  )?;
  if wrapped && wrapper.matches("[[COMPOSE_COMMAND]]").count() != 1 {
    return Err(Log::error(
      "Compose Resolver",
      "The config wrapper must contain [[COMPOSE_COMMAND]] exactly once".into(),
    ));
  }
  Ok(command)
}

static RESOLUTION_SLOTS: LazyLock<
  Mutex<HashMap<(String, String), Weak<Mutex<()>>>>,
> = LazyLock::new(Mutex::default);

async fn acquire_slot(
  core: &str,
  stack_id: &str,
  cancel: &CancellationToken,
) -> Result<OwnedMutexGuard<()>, IncludeError> {
  tokio::select! {
    biased;
    _ = cancel.cancelled() => Err(fail(ErrorKind::Cancelled)),
    guard = async {
      let slot = {
        let mut slots = RESOLUTION_SLOTS.lock().await;
        slots.retain(|_, slot| slot.strong_count() > 0);
        let key = (core.to_string(), stack_id.to_string());
        match slots.get(&key).and_then(Weak::upgrade) {
          Some(slot) => slot,
          None => {
            let slot = Arc::new(Mutex::new(()));
            slots.insert(key, Arc::downgrade(&slot));
            slot
          },
        }
      };
      slot.lock_owned().await
    } => Ok(guard),
  }
}

pub(super) fn resolution_error(
  error: IncludeError,
  stage: ComposeResolutionStage,
) -> ComposeResolutionError {
  let mut result = ComposeResolutionError::new(error.kind, stage);
  result.path = error.path.map(|path| path.display().to_string());
  result
}

pub(crate) async fn resolve_sources(
  request: ResolveComposeStack,
  core: String,
  config: &'static komodo_client::entities::config::periphery::PeripheryConfig,
) -> ResolveComposeStackResponse {
  let identity = request.request_identity.clone();
  let cancel = CancellationToken::new();
  // Keep the command future alive to kill its process group if the RPC caller disappears.
  let _cancel_on_drop = cancel.clone().drop_guard();
  let task = tokio::spawn(async move {
    let _slot = acquire_slot(&core, &request.stack.id, &cancel)
      .await
      .map_err(|error| {
        resolution_error(error, ComposeResolutionStage::Prepare)
      })?;
    let deadline = Instant::now() + Duration::from_secs(60);
    let executable = std::env::current_exe().map_err(|_| {
      ComposeResolutionError::new(
        ErrorKind::UnsupportedCapability,
        ComposeResolutionStage::Prepare,
      )
    })?;
    let runner_cancel = cancel.clone();
    let legacy_cli = config.legacy_compose_cli;
    let run = async move |request: &WorkerRequest,
                          command: &str,
                          deadline| {
      let mut request = request.clone();
      request.mode = WorkerMode::Refresh { legacy_cli };
      invoke_worker(
        &request,
        command,
        CommandOptions::default().cancel(runner_cancel.clone()),
        deadline,
      )
      .await
    };
    if matches!(
      &request.request_identity.source,
      ComposeResolutionSource::Repository { .. }
    ) {
      super::repository::resolve_repository_sources(
        request,
        &executable,
        &config.secrets,
        deadline,
        cancel,
        run,
      )
      .await
    } else if request.request_identity.source
      == ComposeResolutionSource::Ui
    {
      super::inline::resolve_ui_sources(
        request,
        &executable,
        &config.secrets,
        deadline,
        run,
      )
      .await
    } else {
      resolve_host_sources(
        request,
        &config.stack_dir(),
        &executable,
        &config.secrets,
        deadline,
        run,
      )
      .await
    }
  });
  match task.await {
    Ok(Ok(response)) => response,
    Ok(Err(error)) => ResolveComposeStackResponse::Failure {
      request_identity: Some(identity),
      error,
    },
    Err(_) => ResolveComposeStackResponse::Failure {
      request_identity: Some(identity),
      error: ComposeResolutionError::new(
        ErrorKind::WorkerOutput,
        ComposeResolutionStage::Prepare,
      ),
    },
  }
}

async fn resolve_host_sources(
  request: ResolveComposeStack,
  stack_directory: &Path,
  executable: &Path,
  secrets: &HashMap<String, String>,
  deadline: Instant,
  run: impl AsyncFnMut(
    &WorkerRequest,
    &str,
    Instant,
  ) -> Result<Resolved, IncludeError>,
) -> Result<ResolveComposeStackResponse, ComposeResolutionError> {
  request.validate()?;
  if !matches!(
    &request.request_identity.source,
    ComposeResolutionSource::Host { .. }
  ) {
    return Err(ComposeResolutionError::new(
      ErrorKind::InvalidIdentity,
      ComposeResolutionStage::Identity,
    ));
  }
  let source = PreparedSource {
    directory: stack_directory
      .join(komodo_client::entities::to_path_compatible_name(
        &request.stack.name,
      ))
      .join(&request.stack.config.run_directory),
    source_root: None,
    revision: None,
  };
  resolve_prepared_sources(
    request, source, executable, secrets, deadline, run,
  )
  .await
}

pub(super) struct PreparedSource {
  pub directory: PathBuf,
  pub source_root: Option<PathBuf>,
  pub revision: Option<git::CommitInfo>,
}

pub(super) async fn resolve_prepared_sources(
  request: ResolveComposeStack,
  source: PreparedSource,
  executable: &Path,
  secrets: &HashMap<String, String>,
  deadline: Instant,
  mut run: impl AsyncFnMut(
    &WorkerRequest,
    &str,
    Instant,
  ) -> Result<Resolved, IncludeError>,
) -> Result<ResolveComposeStackResponse, ComposeResolutionError> {
  request.validate()?;
  let host = matches!(
    &request.request_identity.source,
    ComposeResolutionSource::Host { .. }
  );
  let stack = &request.stack;
  let mut wrapper = stack.config.compose_cmd_wrapper.clone();
  let mut replacers = request.replacers;
  if !stack.config.skip_secret_interp {
    let mut interpolator =
      interpolate::Interpolator::new(None, secrets);
    interpolator.interpolate_string(&mut wrapper).map_err(|_| {
      ComposeResolutionError::new(
        ErrorKind::Interpolation,
        ComposeResolutionStage::Prepare,
      )
    })?;
    replacers.extend(interpolator.secret_replacers);
  }
  let worker = WorkerRequest {
    id: Uuid::new_v4(),
    mode: WorkerMode::Guarded,
    project_name: stack.project_name(true),
    roots: stack.compose_file_paths().to_vec(),
    files: stack.all_file_dependencies(),
    legacy_exclusions: stack
      .config
      .config_files
      .iter()
      .map(|file| file.path.clone())
      .collect(),
    env_files: crate::docker::compose::ordered_env_files(
      None,
      &stack.config.additional_env_files,
    ),
    optional_env_file: Some(stack.config.env_file_path.clone()),
    source_root: source.source_root,
    replacers,
  };
  validate_request(&worker).map_err(|error| {
    resolution_error(error, ComposeResolutionStage::Prepare)
  })?;
  let directory = source
    .directory
    .to_str()
    .filter(|directory| !directory.contains('\0'))
    .ok_or_else(|| {
      ComposeResolutionError::new(
        ErrorKind::InvalidPath,
        ComposeResolutionStage::Prepare,
      )
    })?;
  if redact_text(directory.into(), &worker).map_err(|error| {
    resolution_error(error, ComposeResolutionStage::Prepare)
  })?
    != directory
  {
    return Err(ComposeResolutionError::new(
      ErrorKind::UnsupportedForm,
      ComposeResolutionStage::Prepare,
    ));
  }
  let command = worker_command(
    executable,
    &wrapper,
    &stack.config.compose_cmd_wrapper_include,
  )
  .map_err(|_| {
    ComposeResolutionError::new(
      ErrorKind::WrapperFailure,
      ComposeResolutionStage::Prepare,
    )
  })?;
  let command = format!(
    "cd -- {} && ( {command} )",
    shell_escape::escape(directory.into())
  );
  for attempt in 0..if host { 2 } else { 1 } {
    if Instant::now() >= deadline {
      return Err(ComposeResolutionError::new(
        ErrorKind::Timeout,
        ComposeResolutionStage::Prepare,
      ));
    }
    let result = match run(&worker, &command, deadline).await {
      Ok(result) => result,
      Err(error)
        if host
          && error.kind == ErrorKind::SourceChanged
          && attempt == 0 =>
      {
        continue;
      }
      Err(error) => {
        return Err(resolution_error(
          error,
          ComposeResolutionStage::Config,
        ));
      }
    };
    let Resolved {
      directory,
      services,
      dependencies,
      contents,
      has_untracked_remote,
    } = result;
    let display_path =
      |path: &Path| -> Result<String, ComposeResolutionError> {
        let path = path.strip_prefix(&directory).unwrap_or(path);
        let path = path.to_str().ok_or_else(|| {
          ComposeResolutionError::new(
            ErrorKind::WorkerOutput,
            ComposeResolutionStage::Verify,
          )
        })?;
        Ok(if path.is_empty() {
          ".".into()
        } else {
          path.into()
        })
      };
    let dependencies: Vec<DerivedComposeDependency> = dependencies
      .into_iter()
      .map(|dependency| {
        Ok(DerivedComposeDependency {
          path: display_path(&dependency.path)?,
          project_directory: display_path(
            &dependency.project_directory,
          )?,
          kind: match dependency.kind {
            DependencyKind::Compose => ComposeDependencyKind::Compose,
            DependencyKind::Environment => {
              ComposeDependencyKind::Environment
            }
            DependencyKind::Auxiliary => {
              ComposeDependencyKind::Auxiliary
            }
          },
          fingerprint: dependency.fingerprint,
          requires: dependency
            .policy
            .as_ref()
            .map(|policy| policy.requires)
            .unwrap_or(StackFileRequires::Redeploy),
          services: dependency
            .policy
            .map(|policy| policy.services)
            .unwrap_or_default(),
        })
      })
      .collect::<Result<Vec<_>, ComposeResolutionError>>()?;
    let contents = contents
      .into_iter()
      .map(|(path, contents)| {
        let path = display_path(&path)?;
        let policy = dependencies.iter().find(|dependency| {
          dependency.path == path
            && dependency.kind != ComposeDependencyKind::Environment
        });
        Ok(StackRemoteFileContents {
          path,
          contents,
          services: policy
            .map(|dependency| dependency.services.clone())
            .unwrap_or_default(),
          requires: policy
            .map(|dependency| dependency.requires)
            .unwrap_or(StackFileRequires::Redeploy),
        })
      })
      .collect::<Result<Vec<_>, ComposeResolutionError>>()?;
    let observed_snapshot = ObservedComposeSnapshot {
      complete: !has_untracked_remote,
      dependency_fingerprints: dependencies
        .iter()
        .map(DerivedComposeDependency::observed_fingerprint)
        .collect(),
      commit_id: source
        .revision
        .as_ref()
        .map(|revision| revision.id.clone()),
      config_generation: (request.request_identity.source
        == ComposeResolutionSource::Ui)
        .then(|| request.request_identity.config_generation.clone()),
    };
    observed_snapshot
      .validate(&request.request_identity, &dependencies)?;
    if Instant::now() >= deadline {
      return Err(ComposeResolutionError::new(
        ErrorKind::Timeout,
        ComposeResolutionStage::Verify,
      ));
    }
    return Ok(ResolveComposeStackResponse::Success {
      request_identity: request.request_identity,
      observed_snapshot,
      services,
      dependencies,
      contents,
      commit_hash: source
        .revision
        .as_ref()
        .map(|revision| revision.display.hash.clone()),
      commit_message: source
        .revision
        .as_ref()
        .map(|revision| {
          redact_text(revision.display.message.clone(), &worker)
            .map_err(|error| {
              resolution_error(error, ComposeResolutionStage::Verify)
            })
        })
        .transpose()?,
    });
  }
  unreachable!(
    "Resolution attempts return or retry a host source race once"
  )
}

#[cfg(test)]
mod tests {
  use super::super::include::tests::Fixture;
  use std::{
    fs,
    os::unix::{ffi::OsStringExt, fs::PermissionsExt},
    time::Duration,
  };

  use super::*;
  use komodo_client::entities::stack::ResolutionRequestIdentity;

  #[tokio::test]
  async fn compose_include_refresh_legacy_preserves_root_merges_without_config()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(
      fixture.root.join("compose.yaml"),
      "services:\n  app:\n    image: original\n    container_name: custom\n    deploy:\n      replicas: 3\n",
    )?;
    fs::write(
      fixture.root.join("override.yaml"),
      "services:\n  app:\n    image: overridden\n  other:\n    image: other\n",
    )?;
    let mut request = request();
    request.roots.push("override.yaml".into());
    request.mode = WorkerMode::Refresh { legacy_cli: true };
    request.env_files = vec!["missing.env".into()];
    let result = resolve_in_context(
      &fixture.root,
      &request,
      BTreeMap::new(),
      async |_, _, _| {
        panic!("Legacy refresh must not invoke Compose or its probes")
      },
    )
    .await?;
    assert_eq!(result.services.len(), 2);
    let app = result
      .services
      .iter()
      .find(|service| service.service_name == "app")
      .unwrap();
    assert_eq!(app.container_name, "custom");
    assert_eq!(app.image, "overridden");
    assert_eq!(result.dependencies.len(), 2);
    assert_eq!(request.roots, ["compose.yaml", "override.yaml"]);
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_refresh_tracks_explicit_auxiliary_without_parsing_services()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(
      fixture.root.join("application.conf"),
      "not: [valid yaml",
    )?;
    let mut request = request();
    request.files =
      vec![komodo_client::entities::stack::StackFileDependency {
        path: "application.conf".into(),
        services: vec!["root".into()],
        requires: StackFileRequires::Restart,
      }];
    let result = resolve_in_context(
      &fixture.root,
      &request,
      BTreeMap::new(),
      async |_, _, _| {
        Ok(
          r#"{"services":{"root":{"image":"synthetic/root"}}}"#
            .into(),
        )
      },
    )
    .await?;
    assert_eq!(result.services.len(), 1);
    assert_eq!(
      result
        .contents
        .get(&fixture.root.join("application.conf"))
        .unwrap(),
      "not: [valid yaml"
    );
    let dependency = result
      .dependencies
      .iter()
      .find(|dependency| dependency.kind == DependencyKind::Auxiliary)
      .unwrap();
    let policy = dependency.policy.as_ref().unwrap();
    assert_eq!(policy.services, ["root"]);
    assert_eq!(policy.requires, StackFileRequires::Restart);
    let result = resolve_in_context(
      &fixture.root,
      &request,
      BTreeMap::new(),
      async |_, _, _| {
        fs::write(fixture.root.join("application.conf"), "changed")
          .unwrap();
        Ok(r#"{"services":{}}"#.into())
      },
    )
    .await;
    assert_eq!(result.err().unwrap().kind, ErrorKind::SourceChanged);
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_refresh_classifies_merged_include_before_legacy_config()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    for contents in [
      "include: [modules/compose.yaml]\n",
      "x-base: &base\n  include: [modules/compose.yaml]\n<<: *base\n",
    ] {
      fs::write(fixture.root.join("compose.yaml"), contents)?;
      let mut request = request();
      request.mode = WorkerMode::Refresh { legacy_cli: true };
      let result = resolve_in_context(
        &fixture.root,
        &request,
        BTreeMap::new(),
        async |_, _, _| {
          panic!("Include inputs cannot enter legacy config")
        },
      )
      .await;
      assert_eq!(
        result.err().unwrap().kind,
        ErrorKind::UnsupportedCapability
      );
      request.mode = WorkerMode::Refresh { legacy_cli: false };
      let mut calls = 0;
      let result = resolve_in_context(&fixture.root, &request, BTreeMap::new(),
        async |_, _, _| { calls += 1; Ok(r#"{"services":{"effective":{"image":"synthetic/effective"}}}"#.into()) }).await?;
      assert_eq!(calls, 1);
      assert_eq!(result.services[0].service_name, "effective");
    }
    Ok(())
  }

  #[tokio::test]
  #[ignore = "requires a freshly built resolver executable, Compose CLI"]
  async fn compose_include_cli_refresh_classifies_inside_selected_wrapper()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let executable = worker_binary()?;
    let marker = fixture.root.join("unexpected-compose");
    let bin = fixture.root.join("bin");
    fs::create_dir(&bin)?;
    let docker = bin.join("docker");
    fs::write(
      &docker,
      format!(
        "#!/bin/sh\nprintf invoked > {}\nexit 99\n",
        shell_escape::escape(marker.to_string_lossy())
      ),
    )?;
    fs::set_permissions(&docker, fs::Permissions::from_mode(0o700))?;
    let wrapper = "printf 'services:\\n  prepared:\\n    image: synthetic/prepared\\n' > compose.yaml; [[COMPOSE_COMMAND]]";
    let defaults = komodo_client::entities::stack::Stack::default()
      .config
      .compose_cmd_wrapper_include;
    for (include, expected) in [
      (vec!["config".into()], "prepared"),
      (vec!["up".into()], "original"),
      (defaults, "original"),
    ] {
      fs::write(
        fixture.root.join("compose.yaml"),
        "services:\n  original:\n    image: synthetic/original\n",
      )?;
      let mut request = request();
      request.mode = WorkerMode::Refresh { legacy_cli: true };
      let command =
        worker_command(&executable, wrapper, &include).unwrap();
      let path =
        format!("{}:{}", bin.display(), std::env::var("PATH")?);
      let result = invoke_worker(
        &request,
        &command,
        CommandOptions::default()
          .path(fixture.root.as_path())
          .env(&BTreeMap::from([("PATH".into(), path)])),
        Instant::now() + Duration::from_secs(30),
      )
      .await?;
      assert_eq!(result.services.len(), 1);
      assert_eq!(result.services[0].service_name, expected);
      assert!(
        !marker.exists(),
        "No-include refresh must not execute a Compose probe or config"
      );
    }
    let wrapper = "printf 'include: [modules/compose.yaml]\\n' > compose.yaml; [[COMPOSE_COMMAND]]";
    let command =
      worker_command(&executable, wrapper, &["config".into()])
        .unwrap();
    let mut request = request();
    request.mode = WorkerMode::Refresh { legacy_cli: true };
    let result = invoke_worker(
      &request,
      &command,
      CommandOptions::default().path(fixture.root.as_path()),
      Instant::now() + Duration::from_secs(30),
    )
    .await;
    assert_eq!(
      result.err().unwrap().kind,
      ErrorKind::UnsupportedCapability
    );
    request.mode = WorkerMode::Refresh { legacy_cli: false };
    let result = invoke_worker(
      &request,
      &command,
      CommandOptions::default().path(fixture.root.as_path()),
      Instant::now() + Duration::from_secs(30),
    )
    .await?;
    assert_eq!(result.services.len(), 2);
    assert!(!marker.exists());
    Ok(())
  }

  fn host_request(fixture: &Fixture) -> ResolveComposeStack {
    host_request_at(&fixture.root)
  }

  fn host_request_at(root: &Path) -> ResolveComposeStack {
    let mut stack = komodo_client::entities::stack::Stack::default();
    stack.id = "a".repeat(24);
    stack.name = "host-discovery".into();
    stack.config.files_on_host = true;
    stack.config.server_id = "synthetic-server".into();
    stack.config.run_directory = root.to_str().unwrap().into();
    stack.config.environment = "IMAGE=not-yet-deployed".into();
    stack.config.pre_deploy.command = format!(
      "touch {} && [[UNUSED_HOOK_SECRET]]",
      root.join("pre-deploy-ran").display()
    );
    stack.config.post_deploy.command =
      format!("touch {}", root.join("post-deploy-ran").display());
    ResolveComposeStack {
      request_identity: ResolutionRequestIdentity {
        stack_id: stack.id.clone(),
        config_generation: "generation".into(),
        source: ComposeResolutionSource::Host {
          server_id: stack.config.server_id.clone(),
          run_directory: stack.config.run_directory.clone(),
        },
      },
      stack,
      repo: None,
      git_token: None,
      replacers: Vec::new(),
    }
  }

  #[tokio::test]
  async fn compose_include_host_returns_remote_services_without_complete_snapshot()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(
      fixture.root.join("compose.yaml"),
      "include: [oci://example.invalid/project:tag]\nservices: {}\n",
    )?;
    let request = host_request(&fixture);
    let identity = request.request_identity.clone();
    let response = resolve_host_sources(
      request,
      Path::new("/unused"),
      Path::new("/synthetic/periphery"),
      &HashMap::new(),
      Instant::now() + Duration::from_secs(10),
      async |worker, _, _| {
        resolve_in_context(
          &fixture.root,
          worker,
          BTreeMap::new(),
          async |_, _, _| {
            Ok(
              r#"{"services":{"remote":{"image":"synthetic/app"}}}"#
                .into(),
            )
          },
        )
        .await
      },
    )
    .await?;
    response.validate_current(&identity, "generation")?;
    let ResolveComposeStackResponse::Success {
      observed_snapshot,
      services,
      ..
    } = response
    else {
      panic!("expected successful discovery");
    };
    assert!(!observed_snapshot.complete);
    assert_eq!(services[0].service_name, "remote");
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_deployment_evidence_detects_source_races()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let request = host_request(&fixture);
    let stack = request.stack.clone();
    let response = resolve_host_sources(
      request,
      Path::new("/unused"),
      Path::new("/synthetic/periphery"),
      &HashMap::new(),
      Instant::now() + Duration::from_secs(10),
      async |worker, _, _| {
        resolve_in_context(
          &fixture.root,
          worker,
          BTreeMap::new(),
          async |_, _, _| {
            Ok(
              r#"{"services":{"root":{"image":"synthetic/app"}}}"#
                .into(),
            )
          },
        )
        .await
      },
    )
    .await?;
    let ResolveComposeStackResponse::Success {
      request_identity,
      observed_snapshot,
      dependencies,
      ..
    } = response
    else {
      panic!("expected successful discovery");
    };
    let expected =
      komodo_client::entities::stack::AcceptedComposeResolution {
        deployment_proven: false,
        source_identity:
          komodo_client::entities::stack::ComposeSourceIdentity {
            request_identity,
            observed_snapshot,
          },
        dependencies,
      };
    let directory = fixture.root.canonicalize()?;
    let first = deployment_snapshot(
      &stack,
      &directory,
      &[],
      &expected,
      &[],
      None,
    )?
    .unwrap();
    assert!(first == expected);
    let captured = super::super::include::inspect(
      &directory,
      stack.compose_file_paths(),
      &[],
      BTreeMap::new(),
    )?;
    #[cfg(target_os = "linux")]
    let staged = capture_deployment(
      &stack,
      &directory,
      &[],
      &expected,
      &[],
      None,
      BTreeMap::new(),
    )?
    .expect("capture should be supported");
    let child = fixture.root.join("modules/compose.yaml");
    let original = fs::read_to_string(&child)?;
    fs::write(
      &child,
      format!("{original}\n# changed before deploy\n"),
    )?;
    let changed = deployment_snapshot(
      &stack,
      &directory,
      &[],
      &expected,
      &[],
      None,
    )?
    .unwrap();
    assert!(changed != first);
    let captured_evidence = deployment_snapshot_from_graph(
      &stack,
      &directory,
      &[],
      &expected,
      &[],
      None,
      captured,
    )?
    .unwrap();
    assert!(captured_evidence == first);
    assert!(!captured_evidence.deployment_proven);
    #[cfg(target_os = "linux")]
    {
      assert!(staged.evidence == first);
      let staged_root: serde_yaml_ng::Value =
        serde_yaml_ng::from_slice(&fs::read(
          &staged.compose.roots[0],
        )?)?;
      let staged_child = staged_root["include"][0]["path"][0]
        .as_str()
        .expect("staged child");
      let staged_text = fs::read_to_string(staged_child)?;
      assert_eq!(
        serde_yaml_ng::from_str::<serde_yaml_ng::Value>(
          &staged_text
        )?["services"]["module"]["image"],
        "conformance/module:synthetic"
      );
      assert_capture_cancels_with_dropped_caller(
        staged,
        &fixture.root,
      )
      .await?;
    }
    assert!(
      deployment_snapshot(
        &stack,
        &directory,
        &[],
        &expected,
        &[],
        None,
      )?
      .unwrap()
        == changed
    );
    fs::write(&child, &original)?;
    assert!(
      deployment_snapshot(
        &stack,
        &directory,
        &[],
        &expected,
        &[],
        None,
      )?
      .unwrap()
        == first
    );
    fs::write(
      &child,
      format!("{original}\n# changed during deploy\n"),
    )?;
    assert!(
      deployment_snapshot(
        &stack,
        &directory,
        &[],
        &expected,
        &[],
        None,
      )?
      .unwrap()
        != first
    );
    let runs =
      std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = runs.clone();
    let source = stack.clone();
    let root = directory.clone();
    let baseline = expected.clone();
    let response = crate::api::observed_restart(
      &expected,
      move || {
        let source = source.clone();
        let root = root.clone();
        let baseline = baseline.clone();
        async move {
          deployment_snapshot(
            &source,
            &root,
            &[],
            &baseline,
            &[],
            None,
          )
          .expect("snapshot must succeed")
        }
      },
      move || async move {
        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Log::simple("restart", "ok".into())
      },
    )
    .await;
    assert!(!response.log.success);
    assert_eq!(runs.load(std::sync::atomic::Ordering::SeqCst), 0);

    fs::write(&child, &original)?;
    let source = stack.clone();
    let root = directory.clone();
    let baseline = expected.clone();
    let changed_child = child.clone();
    let changed_contents =
      format!("{original}\n# changed during restart\n");
    let response = crate::api::observed_restart(
      &expected,
      move || {
        let source = source.clone();
        let root = root.clone();
        let baseline = baseline.clone();
        async move {
          deployment_snapshot(
            &source,
            &root,
            &[],
            &baseline,
            &[],
            None,
          )
          .expect("snapshot must succeed")
        }
      },
      move || async move {
        fs::write(changed_child, changed_contents).unwrap();
        Log::simple("restart", "ok".into())
      },
    )
    .await;
    assert!(response.log.success);
    assert!(response.observed_resolution.is_none());

    fs::write(&child, &original)?;
    let source = stack.clone();
    let root = directory.clone();
    let baseline = expected.clone();
    let changed_child = child.clone();
    let restored_contents = original.clone();
    let response = crate::api::observed_restart(
      &expected,
      move || {
        let source = source.clone();
        let root = root.clone();
        let baseline = baseline.clone();
        async move {
          deployment_snapshot(
            &source,
            &root,
            &[],
            &baseline,
            &[],
            None,
          )
          .expect("snapshot must succeed")
        }
      },
      move || async move {
        fs::write(&changed_child, "# transient source\n").unwrap();
        fs::write(&changed_child, restored_contents).unwrap();
        Log::simple("restart", "ok".into())
      },
    )
    .await;
    assert!(response.log.success);
    assert!(response.observed_resolution.is_none());
    Ok(())
  }

  #[cfg(target_os = "linux")]
  async fn assert_capture_cancels_with_dropped_caller(
    capture: DeploymentCapture,
    directory: &Path,
  ) -> anyhow::Result<()> {
    use anyhow::ensure;
    use shell_escape::unix::escape;
    use std::sync::Arc;

    let ready = directory.join("capture-ready");
    let child_pid = directory.join("capture-child-pid");
    let done = directory.join("capture-done");
    let script = format!(
      "/bin/sleep 30 & echo $! > {}; /usr/bin/touch {}; wait; /usr/bin/touch {}",
      escape(child_pid.to_string_lossy()),
      escape(ready.to_string_lossy()),
      escape(done.to_string_lossy()),
    );
    let command = format!("/bin/sh -c {}", escape(script.into()));
    let capture = Arc::new(capture);
    let weak = Arc::downgrade(&capture);
    let directory = directory.to_path_buf();
    let caller = tokio::spawn(crate::api::run_captured_command(
      "Capture lifetime test",
      command,
      directory,
      capture.clone(),
    ));
    drop(capture);
    tokio::time::timeout(Duration::from_secs(5), async {
      while !ready.exists() {
        tokio::time::sleep(Duration::from_millis(10)).await;
      }
    })
    .await?;
    caller.abort();
    let _ = caller.await;
    tokio::time::timeout(Duration::from_secs(5), async {
      while weak.upgrade().is_some() {
        tokio::time::sleep(Duration::from_millis(10)).await;
      }
    })
    .await?;
    let pid: u32 = fs::read_to_string(child_pid)?.trim().parse()?;
    tokio::time::timeout(Duration::from_secs(5), async {
      loop {
        match fs::read_to_string(format!("/proc/{pid}/stat")) {
          Ok(status)
            if status.rsplit_once(") ").is_some_and(
              |(_, fields)| {
                fields.starts_with("Z ") || fields.starts_with("X ")
              },
            ) =>
          {
            break;
          }
          Ok(_) => {}
          Err(error)
            if error.kind() == std::io::ErrorKind::NotFound =>
          {
            break;
          }
          Err(error) => return Err(error),
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
      }
      Ok(())
    })
    .await??;
    ensure!(!done.exists(), "Cancelled command continued");
    Ok(())
  }

  #[cfg(target_os = "linux")]
  #[tokio::test]
  #[ignore = "requires Docker engine and KOMODO_SNAPSHOT_TEST_IMAGE"]
  async fn compose_include_deploy_uses_captured_graph_through_aba()
  -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use mogh_resolver::Resolve;
    use periphery_client::api::compose::ComposeUp;

    if std::env::var_os("KOMODO_CAPTURE_CHILD").is_none() {
      let image = std::env::var("KOMODO_SNAPSHOT_TEST_IMAGE")?;
      let fixture = Fixture::new("nested")?;
      let project =
        format!("komodo-proof-{}", Uuid::new_v4().simple());
      let root = &fixture.root;
      let child = root.join("modules/compose.yaml");
      let original = format!(
        "services:\n  child:\n    image: {image}\n    pull_policy: never\n    entrypoint: [sleep, '120']\n    stop_grace_period: 1s\n    environment: {{MARKER: original}}\n"
      );
      let changed =
        original.replace("MARKER: original", "MARKER: changed");
      fs::write(
        root.join("compose.yaml"),
        format!(
          "include: [modules/compose.yaml]\nservices:\n  root:\n    image: {image}\n    pull_policy: never\n    entrypoint: [sleep, '120']\n    stop_grace_period: 1s\n"
        ),
      )?;
      fs::write(&child, &original)?;
      fs::write(root.join("changed.yaml"), changed)?;
      let git = |args: &[&str]| -> anyhow::Result<String> {
        let output = std::process::Command::new("/usr/bin/git")
          .args(args)
          .current_dir(root)
          .env_clear()
          .env("PATH", "/usr/bin:/bin")
          .env("HOME", root)
          .env("GIT_CONFIG_NOSYSTEM", "1")
          .output()?;
        ensure!(
          output.status.success(),
          "Synthetic Git setup failed: {}",
          String::from_utf8_lossy(&output.stderr)
        );
        Ok(String::from_utf8(output.stdout)?.trim().to_owned())
      };
      git(&["init", "--initial-branch=main", "working"])?;
      fs::create_dir(root.join("working/modules"))?;
      fs::copy(
        root.join("compose.yaml"),
        root.join("working/compose.yaml"),
      )?;
      fs::copy(&child, root.join("working/modules/compose.yaml"))?;
      git(&[
        "-C",
        "working",
        "add",
        "compose.yaml",
        "modules/compose.yaml",
      ])?;
      git(&[
        "-C",
        "working",
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-m",
        "Synthetic fixture",
      ])?;
      let revision = git(&["-C", "working", "rev-parse", "HEAD"])?;
      fs::create_dir(root.join("git-export"))?;
      git(&["clone", "--bare", "working", "git-export/repo.git"])?;
      git(&["--git-dir=git-export/repo.git", "update-server-info"])?;
      let listener =
        tokio::net::TcpListener::bind("127.0.0.1:0").await?;
      let port = listener.local_addr()?.port();
      drop(listener);
      let mut git_server =
        tokio::process::Command::new("/usr/bin/python3")
          .args([
            "-m",
            "http.server",
            &port.to_string(),
            "--bind",
            "127.0.0.1",
            "--directory",
          ])
          .arg(root.join("git-export"))
          .env_clear()
          .env("PATH", "/usr/bin:/bin")
          .env("HOME", root)
          .stdout(std::process::Stdio::null())
          .stderr(std::process::Stdio::null())
          .kill_on_drop(true)
          .spawn()?;
      tokio::time::timeout(Duration::from_secs(5), async {
        while tokio::net::TcpStream::connect(("127.0.0.1", port))
          .await
          .is_err()
        {
          tokio::time::sleep(Duration::from_millis(20)).await;
        }
      })
      .await?;
      fs::create_dir(root.join("bin"))?;
      let wrapper = root.join("bin/docker");
      fs::write(
        &wrapper,
        r#"#!/bin/sh
config=no
staged=no
for arg in "$@"; do
  [ "$arg" = config ] && config=yes
  case "$arg" in /proc/*/fd/*) staged=yes ;; esac
done
if [ "$config" = yes ] && [ "$staged" = yes ] && [ -e "$KOMODO_CAPTURE_MISMATCH" ]; then
  printf '{"services":{}}\n'
  exit 0
fi
for arg in "$@"; do
  if [ "$arg" = up ]; then
    if [ -e "$KOMODO_CAPTURE_FAIL" ]; then exit 42; fi
    cp "$KOMODO_CAPTURE_SOURCE" "$KOMODO_CAPTURE_BACKUP" || exit 1
    cp "$KOMODO_CAPTURE_CHANGED" "$KOMODO_CAPTURE_REPLACEMENT" || exit 1
    mv "$KOMODO_CAPTURE_REPLACEMENT" "$KOMODO_CAPTURE_SOURCE" || exit 1
    touch "$KOMODO_CAPTURE_MARKER"
    /usr/bin/docker "$@"
    status=$?
    mv "$KOMODO_CAPTURE_BACKUP" "$KOMODO_CAPTURE_SOURCE" || exit 1
    exit "$status"
  fi
done
exec /usr/bin/docker "$@"
"#,
      )?;
      fs::set_permissions(
        &wrapper,
        fs::Permissions::from_mode(0o700),
      )?;
      let test = std::env::current_exe()?;
      let result = tokio::process::Command::new(test)
        .args([
          "--exact",
          "stack::resolve::tests::compose_include_deploy_uses_captured_graph_through_aba",
          "--ignored",
          "--nocapture",
        ])
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", root.join("bin").display()))
        .env("HOME", root)
        .env("KOMODO_CAPTURE_CHILD", root)
        .env("KOMODO_CAPTURE_PROJECT", &project)
        .env("KOMODO_CAPTURE_SOURCE", &child)
        .env("KOMODO_CAPTURE_CHANGED", root.join("changed.yaml"))
        .env("KOMODO_CAPTURE_BACKUP", root.join("backup.yaml"))
        .env("KOMODO_CAPTURE_REPLACEMENT", root.join("replacement.yaml"))
        .env("KOMODO_CAPTURE_MARKER", root.join("race-ran"))
        .env("KOMODO_CAPTURE_FAIL", root.join("fail-up"))
        .env("KOMODO_CAPTURE_MISMATCH", root.join("model-mismatch"))
        .env("KOMODO_CAPTURE_GIT_PROVIDER", format!("127.0.0.1:{port}"))
        .env("KOMODO_CAPTURE_GIT_REVISION", revision)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("PERIPHERY_STACK_DIR", root.join("managed"))
        .env("KOMODO_SNAPSHOT_TEST_IMAGE", image)
        .output()
        .await?;
      let server_stop = git_server.kill().await;
      let server_exit = git_server.wait().await;
      let cleanup = std::process::Command::new("/usr/bin/docker")
        .args(["compose", "-p", &project, "-f"])
        .arg(root.join("compose.yaml"))
        .args(["down", "--remove-orphans", "--timeout", "2"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", root)
        .current_dir(root)
        .output()?;
      ensure!(
        cleanup.status.success(),
        "Cannot clean synthetic deployment: {}",
        String::from_utf8_lossy(&cleanup.stderr)
      );
      let ui_project = format!("{project}-ui");
      let git_project = format!("{project}-git");
      for extra_project in [&ui_project, &git_project] {
        let cleanup = std::process::Command::new("/usr/bin/docker")
          .args([
            "compose",
            "-p",
            extra_project,
            "down",
            "--timeout",
            "2",
          ])
          .env_clear()
          .env("PATH", "/usr/bin:/bin")
          .env("HOME", root)
          .current_dir(root)
          .output()?;
        ensure!(
          cleanup.status.success(),
          "Cannot clean synthetic deployment: {}",
          String::from_utf8_lossy(&cleanup.stderr)
        );
      }
      for project in [&project, &ui_project, &git_project] {
        for kind in ["container", "network"] {
          let mut command =
            std::process::Command::new("/usr/bin/docker");
          command.args([kind, "ls", "-q"]);
          if kind == "container" {
            command.arg("--all");
          }
          let remaining = command
            .args([
              "--filter",
              &format!("label=com.docker.compose.project={project}"),
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", root)
            .output()?;
          ensure!(
            remaining.status.success() && remaining.stdout.is_empty(),
            "Synthetic {kind} resources remain"
          );
        }
      }
      ensure!(
        result.status.success(),
        "Captured deployment subprocess failed:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
      );
      server_stop.context("Cannot stop synthetic Git server")?;
      server_exit.context("Cannot reap synthetic Git server")?;
      return Ok(());
    }

    let root = PathBuf::from(
      std::env::var_os("KOMODO_CAPTURE_CHILD").unwrap(),
    );
    let project = std::env::var("KOMODO_CAPTURE_PROJECT")?;
    let mut request = host_request_at(&root);
    request.stack.name = project.clone();
    request.stack.config.environment.clear();
    request.stack.config.pre_deploy = Default::default();
    request.stack.config.post_deploy = Default::default();
    request.stack.config.auto_pull = false;
    let stack = request.stack.clone();
    let response = resolve_host_sources(
      request,
      Path::new("/unused"),
      Path::new("/synthetic/periphery"),
      &HashMap::new(),
      Instant::now() + Duration::from_secs(10),
      async |worker, _, _| {
        resolve_in_context(&root, worker, BTreeMap::new(), async |_, _, _| {
          Ok(r#"{"services":{"root":{"image":"synthetic/root"},"child":{"image":"synthetic/child"}}}"#.into())
        }).await
      },
    ).await?;
    let ResolveComposeStackResponse::Success {
      request_identity,
      observed_snapshot,
      dependencies,
      ..
    } = response
    else {
      anyhow::bail!("Synthetic discovery failed");
    };
    let expected =
      komodo_client::entities::stack::AcceptedComposeResolution {
        deployment_proven: false,
        source_identity:
          komodo_client::entities::stack::ComposeSourceIdentity {
            request_identity,
            observed_snapshot,
          },
        dependencies,
      };
    let up = ComposeUp {
      stack,
      services: Vec::new(),
      repo: None,
      git_token: None,
      registry_token: None,
      replacers: Vec::new(),
      expected_resolution: Some(expected.clone()),
      supports_deployment_proof: true,
    };
    let args = crate::api::Args {
      core: "synthetic".into(),
      id: Uuid::new_v4(),
    };
    let result = up.clone().resolve(&args).await?;
    ensure!(
      result.deployed,
      "Synthetic ComposeUp failed: {:?}",
      result.logs
    );
    let evidence = result
      .deployed_resolution
      .context("Missing deployment proof")?;
    ensure!(
      evidence.deployment_proven,
      "Deployment proof was not marked verified"
    );
    ensure!(
      evidence.dependencies == expected.dependencies,
      "Proof does not describe the captured graph"
    );
    ensure!(
      root.join("race-ran").exists(),
      "The A-B-A race did not run"
    );
    let child = std::process::Command::new("/usr/bin/docker")
      .args([
        "ps",
        "-q",
        "--filter",
        &format!("label=com.docker.compose.project={project}"),
        "--filter",
        "label=com.docker.compose.service=child",
      ])
      .output()?;
    ensure!(child.status.success(), "Cannot find child container");
    let id = String::from_utf8(child.stdout)?;
    ensure!(!id.trim().is_empty(), "Child container was not started");
    let inspect = std::process::Command::new("/usr/bin/docker")
      .args([
        "inspect",
        "--format",
        "{{json .Config.Env}}",
        id.trim(),
      ])
      .output()?;
    ensure!(
      inspect.status.success(),
      "Cannot inspect child container"
    );
    let environment: Vec<String> =
      serde_json::from_slice(&inspect.stdout)?;
    ensure!(
      environment.iter().any(|entry| entry == "MARKER=original"),
      "Container did not use captured child"
    );
    ensure!(
      !environment.iter().any(|entry| entry == "MARKER=changed"),
      "Container used the replacement child"
    );

    fs::write(root.join("model-mismatch"), "")?;
    let mismatch = up.clone().resolve(&args).await?;
    ensure!(
      mismatch.deployed && mismatch.deployed_resolution.is_none(),
      "A changed captured model must fall back without proof"
    );
    fs::remove_file(root.join("model-mismatch"))?;

    let source = root.join("modules/compose.yaml");
    let original = fs::read_to_string(&source)?;
    fs::write(root.join("modules/service.env"), "EXTRA=synthetic\n")?;
    fs::write(
      &source,
      format!("{original}    env_file: service.env\n"),
    )?;
    let unverified = up.clone().resolve(&args).await?;
    ensure!(
      unverified.deployed,
      "Unsupported input must retain manual deployment"
    );
    ensure!(
      unverified.deployed_resolution.is_none(),
      "Unsupported input was marked verified"
    );
    fs::write(
      &source,
      original.replace(
        "MARKER: original",
        "MARKER: '${UNTRACKED:-original}'",
      ),
    )?;
    let unverified = up.clone().resolve(&args).await?;
    ensure!(
      unverified.deployed && unverified.deployed_resolution.is_none(),
      "Interpolation must deploy manually without verified evidence"
    );
    fs::write(&source, original)?;

    fs::write(root.join("fail-up"), "")?;
    let failed = up.clone().resolve(&args).await?;
    ensure!(
      !failed.deployed,
      "Failed Compose up was reported successful"
    );
    ensure!(
      failed.deployed_resolution.is_none(),
      "Failed Compose up returned proof"
    );
    fs::remove_file(root.join("fail-up"))?;

    let single_source =
      fs::read_to_string(root.join("compose.yaml"))?
        .replace("include: [modules/compose.yaml]\n", "");
    fs::write(root.join("single.yaml"), single_source)?;
    let mut single_stack = up.stack.clone();
    single_stack.config.file_paths = vec!["single.yaml".into()];
    let mut single_request = host_request_at(&root);
    single_request.stack = single_stack.clone();
    let response = resolve_host_sources(
      single_request,
      Path::new("/unused"),
      Path::new("/synthetic/periphery"),
      &HashMap::new(),
      Instant::now() + Duration::from_secs(10),
      async |worker, _, _| {
        let mut worker = worker.clone();
        worker.mode = WorkerMode::Refresh { legacy_cli: false };
        resolve_in_context(
          &root,
          &worker,
          BTreeMap::new(),
          async |_, _, _| {
            panic!("No-include discovery must not invoke Compose")
          },
        )
        .await
      },
    )
    .await?;
    let ResolveComposeStackResponse::Success {
      request_identity,
      observed_snapshot,
      dependencies,
      ..
    } = response
    else {
      anyhow::bail!("Synthetic no-include discovery failed");
    };
    let single_expected =
      komodo_client::entities::stack::AcceptedComposeResolution {
        deployment_proven: false,
        source_identity:
          komodo_client::entities::stack::ComposeSourceIdentity {
            request_identity,
            observed_snapshot,
          },
        dependencies,
      };
    let single_result = ComposeUp {
      stack: single_stack,
      services: Vec::new(),
      repo: None,
      git_token: None,
      registry_token: None,
      replacers: Vec::new(),
      expected_resolution: Some(single_expected.clone()),
      supports_deployment_proof: true,
    }
    .resolve(&args)
    .await?;
    let single_evidence = single_result
      .deployed_resolution
      .context("Missing no-include deployment proof")?;
    ensure!(
      single_result.deployed
        && single_evidence.deployment_proven
        && single_evidence.dependencies
          == single_expected.dependencies,
      "No-include deployment did not use the discovered captured graph"
    );

    let mut ui = komodo_client::entities::stack::Stack::default();
    ui.id = "b".repeat(24);
    ui.name = format!("{project}-ui");
    ui.config.file_contents =
      fs::read_to_string(root.join("compose.yaml"))?;
    ui.config.inline_files =
      vec![komodo_client::entities::FileContents {
        path: "modules/compose.yaml".into(),
        contents: fs::read_to_string(
          root.join("modules/compose.yaml"),
        )?,
      }];
    ui.config.auto_pull = false;
    let ui_request = ResolveComposeStack {
      request_identity: ResolutionRequestIdentity {
        stack_id: ui.id.clone(),
        config_generation: "ui-generation".into(),
        source: ComposeResolutionSource::Ui,
      },
      stack: ui.clone(),
      repo: None,
      git_token: None,
      replacers: Vec::new(),
    };
    let response = super::super::inline::resolve_ui_sources(
      ui_request,
      Path::new("/synthetic/periphery"),
      &HashMap::new(),
      Instant::now() + Duration::from_secs(10),
      async |worker, _, _| {
        let directory = worker.source_root.clone().unwrap();
        resolve_in_context(&directory, worker, BTreeMap::new(), async |_, _, _| {
          Ok(r#"{"services":{"root":{"image":"synthetic/root"},"child":{"image":"synthetic/child"}}}"#.into())
        }).await
      },
    ).await?;
    let ResolveComposeStackResponse::Success {
      request_identity,
      observed_snapshot,
      dependencies,
      ..
    } = response
    else {
      anyhow::bail!("Synthetic UI discovery failed");
    };
    let ui_expected =
      komodo_client::entities::stack::AcceptedComposeResolution {
        deployment_proven: false,
        source_identity:
          komodo_client::entities::stack::ComposeSourceIdentity {
            request_identity,
            observed_snapshot,
          },
        dependencies,
      };
    let ui_up = ComposeUp {
      stack: ui.clone(),
      services: Vec::new(),
      repo: None,
      git_token: None,
      registry_token: None,
      replacers: Vec::new(),
      expected_resolution: Some(ui_expected.clone()),
      supports_deployment_proof: true,
    };
    let ui_result = ui_up.clone().resolve(&args).await?;
    let ui_evidence = ui_result
      .deployed_resolution
      .context("Missing UI deployment proof")?;
    ensure!(
      ui_result.deployed
        && ui_evidence.deployment_proven
        && ui_evidence.dependencies == ui_expected.dependencies,
      "UI deployment did not use the discovered captured graph"
    );
    let ui_child = || -> anyhow::Result<String> {
      let output = std::process::Command::new("/usr/bin/docker")
        .args([
          "ps",
          "-q",
          "--filter",
          &format!("label=com.docker.compose.project={}", ui.name),
          "--filter",
          "label=com.docker.compose.service=child",
        ])
        .output()?;
      ensure!(
        output.status.success(),
        "Cannot find UI child container"
      );
      let id = String::from_utf8(output.stdout)?;
      ensure!(!id.trim().is_empty(), "UI child did not start");
      Ok(id)
    };
    let id = ui_child()?;
    let ui_again = ui_up.clone().resolve(&args).await?;
    ensure!(
      ui_again
        .deployed_resolution
        .is_some_and(|evidence| evidence.deployment_proven),
      "UI redeployment was not verified"
    );
    ensure!(ui_child()? == id, "Unchanged UI child was recreated");

    let mut legacy_request = serde_json::to_value(&ui_up)?;
    legacy_request
      .as_object_mut()
      .context("Invalid request")?
      .remove("supports_deployment_proof");
    let legacy_up: ComposeUp =
      serde_json::from_value(legacy_request)?;
    ensure!(
      !legacy_up.supports_deployment_proof,
      "Legacy caller unexpectedly negotiated proof"
    );
    let legacy_result = legacy_up.resolve(&args).await?;
    ensure!(
      legacy_result.deployed
        && legacy_result.deployed_resolution.is_none(),
      "Legacy caller received an incompatible proof"
    );

    let provider = std::env::var("KOMODO_CAPTURE_GIT_PROVIDER")?;
    let revision = std::env::var("KOMODO_CAPTURE_GIT_REVISION")?;
    let mut git_stack =
      komodo_client::entities::stack::Stack::default();
    git_stack.id = "c".repeat(24);
    git_stack.name = format!("{project}-git");
    git_stack.config.git_provider = provider.clone();
    git_stack.config.git_https = false;
    git_stack.config.repo = "repo.git".into();
    git_stack.config.branch = "main".into();
    git_stack.config.run_directory = ".".into();
    git_stack.config.auto_pull = false;
    let git_request = ResolveComposeStack {
      request_identity: ResolutionRequestIdentity {
        stack_id: git_stack.id.clone(),
        config_generation: "git-generation".into(),
        source: ComposeResolutionSource::Repository {
          provider,
          repository: "repo.git".into(),
          commit_id: revision.clone(),
          run_directory: ".".into(),
        },
      },
      stack: git_stack.clone(),
      repo: None,
      git_token: None,
      replacers: Vec::new(),
    };
    let response = super::super::repository::resolve_repository_sources(
      git_request,
      Path::new("/synthetic/periphery"),
      &HashMap::new(),
      Instant::now() + Duration::from_secs(30),
      CancellationToken::new(),
      async |worker, _, _| {
        let directory = worker.source_root.clone().unwrap();
        resolve_in_context(&directory, worker, BTreeMap::new(), async |_, _, _| {
          Ok(r#"{"services":{"root":{"image":"synthetic/root"},"child":{"image":"synthetic/child"}}}"#.into())
        }).await
      },
    ).await?;
    let ResolveComposeStackResponse::Success {
      request_identity,
      observed_snapshot,
      dependencies,
      ..
    } = response
    else {
      anyhow::bail!("Synthetic Git discovery failed");
    };
    let git_expected =
      komodo_client::entities::stack::AcceptedComposeResolution {
        deployment_proven: false,
        source_identity:
          komodo_client::entities::stack::ComposeSourceIdentity {
            request_identity,
            observed_snapshot,
          },
        dependencies,
      };
    let git_result = ComposeUp {
      stack: git_stack,
      services: Vec::new(),
      repo: None,
      git_token: None,
      registry_token: None,
      replacers: Vec::new(),
      expected_resolution: Some(git_expected.clone()),
      supports_deployment_proof: true,
    }
    .resolve(&args)
    .await?;
    let git_evidence = git_result
      .deployed_resolution
      .context("Missing Git deployment proof")?;
    ensure!(
      git_result.deployed
        && git_evidence.deployment_proven
        && git_evidence.dependencies == git_expected.dependencies
        && git_evidence
          .source_identity
          .observed_snapshot
          .commit_id
          .as_deref()
          == Some(revision.as_str()),
      "Git deployment did not use the discovered captured revision"
    );
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_repository_boundary_rejects_external_sources_before_config()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let outside = Fixture::new("nested")?;
    for source in [
      format!(
        "include:\n  - {}\n",
        outside.root.join("compose.yaml").display()
      ),
      format!(
        "include:\n  - path: modules/compose.yaml\n    env_file: {}\n",
        outside.root.join("outside.env").display()
      ),
      format!(
        "include:\n  - path: modules/compose.yaml\n    project_directory: {}\n",
        outside.root.display()
      ),
    ] {
      fs::write(
        outside.root.join("outside.env"),
        "IMAGE=synthetic/outside\n",
      )?;
      fs::write(fixture.root.join("compose.yaml"), &source)?;
      let mut request = request();
      request.source_root = Some(fixture.root.clone());
      let mut calls = 0;
      let result = resolve_in_context(
        &fixture.root,
        &request,
        BTreeMap::new(),
        async |_, _, _| {
          calls += 1;
          Ok(r#"{"services":{}}"#.into())
        },
      )
      .await;
      assert_eq!(
        result.err().unwrap().kind,
        ErrorKind::InvalidPath,
        "{source}"
      );
      assert_eq!(calls, 0);
    }
    let external = fixture.root.join("external.yaml");
    std::os::unix::fs::symlink(
      outside.root.join("compose.yaml"),
      &external,
    )?;
    fs::write(
      fixture.root.join("compose.yaml"),
      "include:\n  - external.yaml\n",
    )?;
    let mut request = request();
    request.source_root = Some(fixture.root.clone());
    let result = resolve_in_context(
      &fixture.root,
      &request,
      BTreeMap::new(),
      async |_, _, _| panic!("Escaped sources must not reach config"),
    )
    .await;
    assert_eq!(result.err().unwrap().kind, ErrorKind::InvalidPath);
    Ok(())
  }

  struct RepositoryFixture {
    source: Fixture,
    provider: String,
    selected: String,
    latest: String,
    server: tokio::task::JoinHandle<()>,
  }

  impl Drop for RepositoryFixture {
    fn drop(&mut self) {
      self.server.abort();
    }
  }

  impl RepositoryFixture {
    async fn new() -> anyhow::Result<Self> {
      use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
      };
      let source = Fixture::new("nested")?;
      fs::write(
        source.root.join("compose.yaml"),
        "# selected\nservices:\n  root:\n    image: ${DISCOVERY_IMAGE}\ninclude:\n  - ${MODULE_FILE:?missing module}\n",
      )?;
      fs::write(
        source.root.join("runtime.env"),
        "DISCOVERY_IMAGE=synthetic/tracked\n",
      )?;
      fs::write(
        source.root.join("lower.env"),
        "DISCOVERY_IMAGE=synthetic/lower\n",
      )?;
      let git = |args: &[&str]| -> anyhow::Result<String> {
        let output = std::process::Command::new("git")
          .args([
            "-c",
            "user.name=Compose Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
          ])
          .args(args)
          .env("GIT_CONFIG_GLOBAL", "/dev/null")
          .env("GIT_CONFIG_NOSYSTEM", "1")
          .current_dir(&source.root)
          .output()?;
        anyhow::ensure!(
          output.status.success(),
          "Fixture Git failed: {}",
          String::from_utf8_lossy(&output.stderr)
        );
        Ok(String::from_utf8(output.stdout)?.trim().into())
      };
      git(&["init", "--template="])?;
      git(&["add", "."])?;
      git(&["commit", "-m", "selected synthetic-secret"])?;
      let selected = git(&["rev-parse", "HEAD"])?;
      fs::write(
        source.root.join("compose.yaml"),
        "services:\n  latest_only:\n    image: synthetic/latest\n",
      )?;
      git(&["add", "compose.yaml"])?;
      git(&["commit", "-m", "latest"])?;
      let latest = git(&["rev-parse", "HEAD"])?;
      git(&["update-server-info"])?;
      let listener = TcpListener::bind("127.0.0.1:0").await?;
      let provider = listener.local_addr()?.to_string();
      let root = source.root.join(".git");
      let server = tokio::spawn(async move {
        loop {
          let (mut stream, _) = listener.accept().await.unwrap();
          let mut request = [0; 8192];
          let mut used = 0;
          while used < request.len()
            && !request[..used]
              .windows(4)
              .any(|bytes| bytes == b"\r\n\r\n")
          {
            let count =
              stream.read(&mut request[used..]).await.unwrap();
            if count == 0 {
              break;
            }
            used += count;
          }
          let text = std::str::from_utf8(&request[..used]).unwrap();
          let path = text
            .split_whitespace()
            .nth(1)
            .unwrap()
            .split('?')
            .next()
            .unwrap();
          let file = path
            .strip_prefix("/fixture.git/")
            .and_then(|path| fs::canonicalize(root.join(path)).ok());
          let body = file
            .filter(|path| path.starts_with(&root))
            .and_then(|path| fs::read(path).ok());
          let (status, body) = match body {
            Some(body) => ("200 OK", body),
            None => ("404 Not Found", Vec::new()),
          };
          let header = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
            body.len()
          );
          // A cancelled Git client can close while the fixture is replying.
          if stream.write_all(header.as_bytes()).await.is_ok() {
            let _ = stream.write_all(&body).await;
          }
        }
      });
      Ok(Self {
        source,
        provider,
        selected,
        latest,
        server,
      })
    }
  }

  async fn repository_resolution_case(
    cli: bool,
    tamper: bool,
  ) -> anyhow::Result<()> {
    use git::discovery::DiscoveryCheckout;
    use komodo_client::entities::{
      RepoExecutionArgs, repo::Repo, stack::AdditionalEnvFile,
    };
    for linked in [false, true] {
      let fixture = RepositoryFixture::new().await?;
      let mut request = host_request(&fixture.source);
      request.stack.config.files_on_host = false;
      request.stack.config.git_provider = fixture.provider.clone();
      request.stack.config.git_https = false;
      request.stack.config.repo = "fixture.git".into();
      request.stack.config.run_directory = ".".into();
      request.stack.config.environment =
        "DISCOVERY_IMAGE=synthetic/configured\nTOKEN=[[SECRET]]"
          .into();
      request.stack.config.env_file_path = "runtime.env".into();
      request.stack.config.additional_env_files =
        vec![AdditionalEnvFile {
          path: "lower.env".into(),
          track: false,
        }];
      request.stack.config.compose_cmd_wrapper_include =
        vec!["config".into()];
      request.stack.config.compose_cmd_wrapper =
        "env MODULE_FILE=modules/compose.yaml [[COMPOSE_COMMAND]]"
          .into();
      if linked {
        let mut repo = Repo::default();
        repo.id = "b".repeat(24);
        repo.config.git_provider = fixture.provider.clone();
        repo.config.git_https = false;
        repo.config.repo = "fixture.git".into();
        repo.config.environment = "REPO_ONLY=[[SECRET]]".into();
        repo.config.env_file_path = "repo.env".into();
        repo.config.on_clone.command =
          "[[UNUSED_CLONE_SECRET]]".into();
        repo.config.on_pull.command = "[[UNUSED_PULL_SECRET]]".into();
        request.stack.config.linked_repo = repo.id.clone();
        request.stack.config.additional_env_files.push(
          AdditionalEnvFile {
            path: "repo.env".into(),
            track: false,
          },
        );
        request.repo = Some(repo);
      }
      request.request_identity.source =
        ComposeResolutionSource::Repository {
          provider: fixture.provider.clone(),
          repository: "fixture.git".into(),
          commit_id: fixture.selected.clone(),
          run_directory: ".".into(),
        };
      let identity = request.request_identity.clone();
      let args: RepoExecutionArgs = request
        .repo
        .as_ref()
        .map(Into::into)
        .unwrap_or((&request.stack).into());
      let options_environment = BTreeMap::from([
        ("NO_PROXY".into(), "127.0.0.1".into()),
        ("no_proxy".into(), "127.0.0.1".into()),
      ]);
      let deadline = Instant::now() + Duration::from_secs(60);
      let checkout = DiscoveryCheckout::prepare(
        &args,
        None,
        &fixture.selected,
        deadline,
        CommandOptions::default().env(&options_environment),
      )
      .await?;
      let directory = checkout.path().to_path_buf();
      let executable = if cli {
        worker_binary()?
      } else {
        PathBuf::from("/synthetic/periphery")
      };
      let environment = test_environment(&fixture.source)?;
      let mut calls = 0;
      let result = super::super::repository::resolve_checkout_sources(
        request, checkout, &executable,
        &HashMap::from([("SECRET".into(), "synthetic-secret".into())]), deadline,
        async |worker, command, observed_deadline| {
          calls += 1;
          assert_eq!(deadline, observed_deadline);
          assert_eq!(worker.roots, ["compose.yaml"]);
          assert_eq!(worker.source_root.as_deref(), Some(directory.as_path()));
          assert_eq!(fs::metadata(directory.join("runtime.env")).unwrap().permissions().mode() & 0o777, 0o600);
          let result = if cli {
            invoke_worker(worker, command, CommandOptions::default().env(&environment), deadline).await
          } else {
            let mut environment = BTreeMap::new();
            environment.insert("MODULE_FILE".into(), "modules/compose.yaml".into());
            resolve_in_context(&directory, worker, environment, async |_,_,_| {
              Ok(r#"{"services":{"root":{"image":"synthetic/configured"}}}"#.into())
            }).await
          };
          if tamper { fs::remove_file(directory.join(".git/HEAD")).unwrap(); }
          result
        },
      ).await;
      assert_eq!(
        calls, 1,
        "Repository source failures must not retry"
      );
      assert!(
        !directory.exists(),
        "Discovery checkout must be cleaned up"
      );
      if tamper {
        let error = result
          .err()
          .expect("Invalidated HEAD must reject the result");
        assert_eq!(error.stage, ComposeResolutionStage::Verify);
      } else {
        let response = result?;
        response.validate_current(&identity, "generation")?;
        let ResolveComposeStackResponse::Success {
          services,
          contents,
          observed_snapshot,
          commit_hash,
          commit_message,
          ..
        } = response
        else {
          panic!("Expected Repository success")
        };
        assert_eq!(
          observed_snapshot.commit_id.as_deref(),
          Some(fixture.selected.as_str())
        );
        assert!(
          fixture.selected.starts_with(commit_hash.as_ref().unwrap())
        );
        assert_ne!(
          observed_snapshot.commit_id.as_deref(),
          Some(fixture.latest.as_str())
        );
        assert!(
          commit_message.as_ref().unwrap().contains("selected")
        );
        assert!(
          !commit_message.unwrap().contains("synthetic-secret")
        );
        assert!(
          services
            .iter()
            .any(|service| service.service_name == "root"
              && service.image == "synthetic/configured")
        );
        assert!(
          !services
            .iter()
            .any(|service| service.service_name == "latest_only")
        );
        if cli {
          assert_eq!(services.len(), 3);
        }
        assert!(
          contents.iter().any(|file| file.path == "compose.yaml"
            && file.contents.starts_with("# selected"))
        );
        assert!(
          !contents.iter().any(|file| file.path.ends_with(".env"))
        );
      }
      assert!(
        fs::read_to_string(fixture.source.root.join("compose.yaml"))?
          .contains("latest_only")
      );
      assert_eq!(
        fs::read_to_string(fixture.source.root.join("runtime.env"))?,
        "DISCOVERY_IMAGE=synthetic/tracked\n"
      );
      assert!(!fixture.source.root.join("repo.env").exists());
      assert!(!fixture.source.root.join("pre-deploy-ran").exists());
      assert!(!fixture.source.root.join("post-deploy-ran").exists());
    }
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_repository_returns_selected_revision_and_private_environment()
  -> anyhow::Result<()> {
    repository_resolution_case(false, false).await
  }

  #[tokio::test]
  async fn compose_include_repository_rechecks_head_after_model_without_retry()
  -> anyhow::Result<()> {
    repository_resolution_case(false, true).await
  }

  #[tokio::test]
  #[ignore = "requires freshly built KOMODO_COMPOSE_RESOLVER_EXE, Docker Compose"]
  async fn compose_include_cli_repository_pins_model_and_contents_for_inline_and_linked_sources()
  -> anyhow::Result<()> {
    repository_resolution_case(true, false).await
  }

  #[tokio::test]
  async fn compose_include_host_retries_only_source_races_with_one_deadline()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let original = fs::read(fixture.root.join("compose.yaml"))?;
    for (error_kind, recovers) in [
      (ErrorKind::SourceChanged, true),
      (ErrorKind::SourceChanged, false),
      (ErrorKind::ComposeValidation, false),
    ] {
      let request = host_request(&fixture);
      let identity = request.request_identity.clone();
      let deadline = Instant::now() + Duration::from_secs(60);
      let mut calls = 0;
      let result = resolve_host_sources(
        request, Path::new("/unused"), Path::new("/synthetic/periphery"), &HashMap::new(), deadline,
        async |request, command, observed_deadline| {
          calls += 1;
          assert_eq!(deadline, observed_deadline);
          assert_eq!(request.roots, ["compose.yaml"]);
          assert_eq!(request.optional_env_file.as_deref(), Some(".env"));
          assert!(command.starts_with("cd -- "));
          assert!(!command.contains("not-yet-deployed"));
          if calls == 1 || !recovers { return Err(fail(error_kind)); }
          resolve_in_context(&fixture.root, request, BTreeMap::new(), async |_,_,_| {
            Ok(r#"{"services":{"accepted":{"image":"synthetic/accepted"}}}"#.into())
          }).await
        },
      ).await;
      if recovers {
        let response = result?;
        response.validate_current(&identity, "generation")?;
        let ResolveComposeStackResponse::Success {
          services,
          contents,
          ..
        } = response
        else {
          panic!("Expected verified host result");
        };
        assert_eq!(services[0].service_name, "accepted");
        assert!(
          contents.iter().any(|file| file.path == "compose.yaml")
        );
        assert_eq!(calls, 2);
      } else {
        assert_eq!(result.err().unwrap().category, error_kind);
        assert_eq!(
          calls,
          if error_kind == ErrorKind::SourceChanged {
            2
          } else {
            1
          }
        );
      }
    }
    assert_eq!(
      fs::read(fixture.root.join("compose.yaml"))?,
      original
    );
    let mut calls = 0;
    let result = resolve_host_sources(
      host_request(&fixture),
      Path::new("/unused"),
      Path::new("/synthetic/periphery"),
      &HashMap::new(),
      Instant::now() - Duration::from_secs(1),
      async |_, _, _| {
        calls += 1;
        Err(fail(ErrorKind::SourceChanged))
      },
    )
    .await;
    assert_eq!(result.err().unwrap().category, ErrorKind::Timeout);
    assert_eq!(calls, 0);
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_host_slot_wait_is_cancellable_and_independent()
  -> anyhow::Result<()> {
    let cancel = CancellationToken::new();
    let held =
      acquire_slot("synthetic-core", "shared", &cancel).await?;
    let independent = tokio::time::timeout(
      Duration::from_secs(5),
      acquire_slot("synthetic-core", "independent", &cancel),
    )
    .await??;
    let waiting_cancel = CancellationToken::new();
    let token = waiting_cancel.clone();
    let waiting = tokio::spawn(async move {
      acquire_slot("synthetic-core", "shared", &token).await
    });
    waiting_cancel.cancel();
    assert_eq!(
      tokio::time::timeout(Duration::from_secs(5), waiting)
        .await??
        .err()
        .unwrap()
        .kind,
      ErrorKind::Cancelled
    );
    drop((held, independent));
    Ok(())
  }

  #[cfg(target_os = "linux")]
  #[tokio::test]
  async fn compose_include_host_dropped_request_kills_owned_wrapper_descendants()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let mut request = host_request(&fixture);
    request.stack.config.compose_cmd_wrapper_include =
      vec!["config".into()];
    request.stack.config.compose_cmd_wrapper =
      "sleep 60 & descendant=$!; printf '%s' \"$descendant\" > descendant.pid; wait \"$descendant\"; [[COMPOSE_COMMAND]]".into();
    static CONFIG: LazyLock<
      komodo_client::entities::config::periphery::PeripheryConfig,
    > = LazyLock::new(Default::default);
    let task = tokio::spawn(resolve_sources(
      request,
      "synthetic-drop-core".into(),
      &CONFIG,
    ));
    let pid_path = fixture.root.join("descendant.pid");
    let started =
      tokio::time::timeout(Duration::from_secs(5), async {
        loop {
          match fs::read_to_string(&pid_path) {
            Ok(value) if !value.is_empty() => {
              break Ok::<u32, anyhow::Error>(value.parse()?);
            }
            Ok(_) => {}
            Err(error)
              if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(anyhow::Error::from(error)),
          }
          tokio::time::sleep(Duration::from_millis(10)).await;
        }
      })
      .await;
    task.abort();
    assert!(
      task
        .await
        .err()
        .expect("Request task was not cancelled")
        .is_cancelled()
    );
    let pid = started??;
    tokio::time::timeout(Duration::from_secs(5), async {
      loop {
        match fs::read_to_string(format!("/proc/{pid}/stat")) {
          Ok(stat)
            if stat
              .split_once(") ")
              .is_some_and(|(_, fields)| fields.starts_with('Z')) =>
          {
            break;
          }
          Ok(_) => {}
          Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
              || error.raw_os_error() == Some(libc::ESRCH) =>
          {
            break;
          }
          Err(error) => return Err(anyhow::Error::from(error)),
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
      }
      Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
  }

  #[tokio::test]
  #[ignore = "requires freshly built KOMODO_COMPOSE_RESOLVER_EXE, Docker Compose"]
  async fn compose_include_cli_host_uses_observed_environment_and_preserves_sources()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let outside = Fixture::new("nested")?;
    fs::write(
      outside.root.join("compose.yaml"),
      "services:\n  outside:\n    image: synthetic/outside\n",
    )?;
    let key = format!("KOMODO_TEST_{}", Uuid::new_v4().simple());
    let source = format!(
      "services:\n  root:\n    image: ${{{key}}}\ninclude:\n  - modules/compose.yaml\n  - {}\n",
      outside.root.join("compose.yaml").display()
    );
    fs::write(fixture.root.join("compose.yaml"), &source)?;
    let env = format!("{key}=synthetic/on-host\n");
    fs::write(fixture.root.join("runtime.env"), &env)?;
    fs::write(
      fixture.root.join("lower.env"),
      format!("{key}=synthetic/lower-priority\n"),
    )?;
    let mut request = host_request(&fixture);
    request.stack.config.env_file_path = "runtime.env".into();
    request.stack.config.additional_env_files =
      ["runtime.env", "lower.env"]
        .map(|path| {
          komodo_client::entities::stack::AdditionalEnvFile {
            path: path.into(),
            track: false,
          }
        })
        .to_vec();
    request.stack.config.environment =
      format!("{key}=synthetic/not-deployed");
    request.stack.config.file_paths = vec![
      fixture.root.join("compose.yaml").to_str().unwrap().into(),
    ];
    let identity = request.request_identity.clone();
    let environment = test_environment(&fixture)?;
    let executable = worker_binary()?;
    let response = resolve_host_sources(
      request,
      Path::new("/unused"),
      &executable,
      &HashMap::new(),
      Instant::now() + Duration::from_secs(60),
      async |request, command, deadline| {
        invoke_worker(
          request,
          command,
          CommandOptions::default().env(&environment),
          deadline,
        )
        .await
      },
    )
    .await?;
    response.validate_current(&identity, "generation")?;
    let ResolveComposeStackResponse::Success {
      services,
      dependencies,
      contents,
      ..
    } = response
    else {
      panic!("Expected host discovery");
    };
    assert_eq!(services.len(), 4);
    assert!(
      services.iter().any(|service| service.service_name == "root"
        && service.image == "synthetic/on-host")
    );
    assert!(dependencies.iter().any(|dependency| dependency.kind
      == ComposeDependencyKind::Environment
      && dependency.path == "runtime.env"));
    assert!(
      !contents
        .iter()
        .any(|contents| contents.path.ends_with(".env"))
    );
    assert_eq!(
      fs::read_to_string(fixture.root.join("runtime.env"))?,
      env
    );
    assert_eq!(
      fs::read_to_string(fixture.root.join("compose.yaml"))?,
      source
    );
    assert!(!fixture.root.join("pre-deploy-ran").exists());
    assert!(!fixture.root.join("post-deploy-ran").exists());
    Ok(())
  }

  fn request() -> WorkerRequest {
    WorkerRequest {
      mode: WorkerMode::Guarded,
      files: Vec::new(),
      legacy_exclusions: Vec::new(),
      id: Uuid::new_v4(),
      project_name: "conformance".into(),
      roots: vec!["compose.yaml".into()],
      env_files: Vec::new(),
      optional_env_file: None,
      source_root: None,
      replacers: vec![(
        "synthetic-secret".into(),
        "SYNTHETIC_SECRET".into(),
      )],
    }
  }

  fn success(request: &WorkerRequest) -> WorkerReply {
    WorkerReply::Success {
      id: request.id,
      result: Resolved {
        directory: PathBuf::from("/synthetic"),
        services: Vec::new(),
        dependencies: Vec::new(),
        contents: BTreeMap::new(),
        has_untracked_remote: false,
      },
    }
  }

  fn output(stdout: Vec<u8>, success: bool) -> CommandOutput {
    use std::os::unix::process::ExitStatusExt;
    CommandOutput::from(Ok(std::process::Output {
      status: std::process::ExitStatus::from_raw(if success {
        0
      } else {
        256
      }),
      stdout,
      stderr: b"synthetic-secret diagnostics".to_vec(),
    }))
  }

  #[test]
  fn compose_include_worker_bounded_redaction_preserves_svi_order()
  -> anyhow::Result<()> {
    let mut request = request();
    request.replacers = vec![
      ("short".into(), "SHORT".into()),
      ("short-long".into(), "LONG".into()),
      ("<SHORT>".into(), "NEXT".into()),
    ];
    let text = "short-long short short-long".to_string();
    assert_eq!(
      redact_text(text.clone(), &request)?,
      svi::replace_in_string(&text, &request.replacers)
    );
    request.replacers = vec![("x".into(), "N".repeat(1024))];
    let error =
      redact_text("x".repeat(MAX_RESULT_BYTES / 1026 + 1), &request)
        .err()
        .unwrap();
    assert_eq!(error.kind, ErrorKind::Limit);
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_worker_tracks_dotenv_environment_controls()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let request = request();
    for (key, value) in [
      ("COMPOSE_ENV_FILES", "untracked.env"),
      ("COMPOSE_DISABLE_ENV_FILE", "true"),
    ] {
      fs::write(
        fixture.root.join(".env"),
        format!("{key}={value}\n"),
      )?;
      let result = resolve_in_context(
        &fixture.root,
        &request,
        BTreeMap::new(),
        async |_, _, _| Ok(r#"{"services":{}}"#.into()),
      )
      .await?;
      assert!(result.dependencies.iter().any(|dependency| {
        dependency.path == fixture.root.join(".env")
          && dependency.kind == DependencyKind::Environment
      }));
      fs::remove_file(fixture.root.join(".env"))?;
    }
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_worker_context_preserves_environment_and_redaction()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::write(
      fixture.root.join(".env"),
      "SYNTHETIC_SECRET=synthetic-secret\n",
    )?;
    let root = fixture.root.join("compose.yaml");
    let contents =
      fs::read_to_string(&root)? + "# synthetic-secret\n";
    fs::write(&root, contents)?;
    let request = request();
    let result = resolve_in_context(
      &fixture.root, &request,
      BTreeMap::from([("COMPOSE_EXPERIMENTAL_GIT_REMOTE".into(), "true".into())]),
      async |roots, env_files, environment| {
        assert_eq!(roots, request.roots);
        assert_eq!(env_files, request.env_files);
        assert_eq!(environment.get("COMPOSE_EXPERIMENTAL_GIT_REMOTE").map(String::as_str), Some("true"));
        assert!(!environment.contains_key("COMPOSE_EXPERIMENTAL_OCI_REMOTE"));
        Ok(r#"{"services":{"resolved":{"image":"synthetic-secret","deploy":{"replicas":2}}}}"#.into())
      },
    ).await?;
    assert_eq!(result.services.len(), 2);
    assert!(
      result
        .services
        .iter()
        .any(|service| service.service_name == "resolved-2")
    );
    assert!(
      result
        .services
        .iter()
        .all(|service| service.image == "<SYNTHETIC_SECRET>")
    );
    assert!(result.dependencies.iter().any(|dependency| {
      dependency.kind == DependencyKind::Environment
    }));
    assert!(
      !result
        .contents
        .keys()
        .any(|path| path.file_name().unwrap() == ".env")
    );
    assert!(
      !String::from_utf8(encode_bounded(&result, MAX_REPLY)?)?
        .contains("synthetic-secret")
    );
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_worker_changed_source_discards_model_without_retry()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let request = request();
    let mut calls = 0;
    let error = resolve_in_context(
      &fixture.root,
      &request,
      BTreeMap::new(),
      async |_, _, _| {
        calls += 1;
        fs::write(
          fixture.root.join("compose.yaml"),
          "services: {}\n",
        )
        .unwrap();
        Ok(
          r#"{"services":{"stale":{"image":"synthetic/image"}}}"#
            .into(),
        )
      },
    )
    .await
    .err()
    .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(error.kind, ErrorKind::SourceChanged);
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_worker_replica_expansion_is_bounded()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let request = request();
    let error = resolve_in_context(
      &fixture.root, &request, BTreeMap::new(),
      async |_, _, _| Ok(r#"{"services":{"huge":{"deploy":{"replicas":9223372036854775807}}}}"#.into()),
    ).await.err().unwrap();
    assert_eq!(error.kind, ErrorKind::Limit);
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_worker_missing_model_services_is_not_empty_success()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let error = resolve_in_context(
      &fixture.root,
      &request(),
      BTreeMap::new(),
      async |_, _, _| Ok("{}".into()),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(error.kind, ErrorKind::ComposeValidation);
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_worker_total_redaction_expansion_is_bounded()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let mut request = request();
    request.replacers = vec![("x".into(), "N".repeat(1024))];
    let model = serde_json::json!({"services":{"replicated":{
      "image":"x".repeat(MAX_RESULT_BYTES / 2 / 1026 + 1),
      "deploy":{"replicas":2},
    }}})
    .to_string();
    let error = resolve_in_context(
      &fixture.root,
      &request,
      BTreeMap::new(),
      async |_, _, _| Ok(model),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(error.kind, ErrorKind::Limit);
    Ok(())
  }

  fn worker_binary() -> anyhow::Result<PathBuf> {
    let executable = std::env::var_os("KOMODO_COMPOSE_RESOLVER_EXE")
      .ok_or_else(|| anyhow::anyhow!("Set KOMODO_COMPOSE_RESOLVER_EXE to the freshly built Periphery executable"))?;
    Ok(PathBuf::from(executable).canonicalize()?)
  }

  async fn ui_resolution_case(real: bool) -> anyhow::Result<()> {
    use komodo_client::entities::{FileContents, stack::Stack};
    let mut stack = Stack::default();
    stack.id = "a".repeat(24);
    stack.config.file_paths = vec!["root.yaml".into()];
    stack.config.file_contents = "include: [modules/child.yaml]\nservices:\n  root:\n    image: ${DISCOVERY_IMAGE}\n".into();
    stack.config.inline_files = vec![
      FileContents {
        path: "modules/child.yaml".into(),
        contents: "include: [nested.yaml]\nservices:\n  child:\n    image: '[[IMAGE]]'\n".into(),
      },
      FileContents {
        path: "modules/nested.yaml".into(),
        contents: "services:\n  nested:\n    image: synthetic/nested\n".into(),
      },
    ];
    stack.config.environment = "DISCOVERY_IMAGE=[[IMAGE]]".into();
    stack.config.pre_deploy.command = "[[UNUSED_HOOK_SECRET]]".into();
    let request = ResolveComposeStack {
      request_identity:
        komodo_client::entities::stack::ResolutionRequestIdentity {
          stack_id: stack.id.clone(),
          config_generation: "ui-generation".into(),
          source: ComposeResolutionSource::Ui,
        },
      stack,
      repo: None,
      git_token: None,
      replacers: Vec::new(),
    };
    let identity = request.request_identity.clone();
    let executable = if real {
      worker_binary()?
    } else {
      PathBuf::from("/synthetic/periphery")
    };
    let mut observed = None;
    let secrets = HashMap::from([(
      "IMAGE".into(),
      "synthetic-inline-secret".into(),
    )]);
    let response = super::super::inline::resolve_ui_sources(
      request, &executable, &secrets, Instant::now() + Duration::from_secs(60),
      async |worker, command, deadline| {
        let directory = worker.source_root.clone().unwrap();
        observed = Some(directory.clone());
        assert_eq!(worker.roots, ["root.yaml"]);
        assert!(fs::read_to_string(directory.join("modules/child.yaml")).unwrap().contains("synthetic-inline-secret"));
        assert_eq!(fs::read_to_string(directory.join(".env")).unwrap(), "DISCOVERY_IMAGE=synthetic-inline-secret\n");
        if real {
          invoke_worker(worker, command, CommandOptions::default(), deadline).await
        } else {
          resolve_in_context(&directory, worker, BTreeMap::new(), async |_,_,_| {
            Ok(r#"{"services":{"root":{"image":"synthetic-inline-secret"},"child":{"image":"synthetic-inline-secret"},"nested":{"image":"synthetic/nested"}}}"#.into())
          }).await
        }
      },
    ).await?;
    response.validate_current(&identity, "ui-generation")?;
    assert!(!observed.unwrap().exists());
    assert!(
      !serde_json::to_string(&response)?
        .contains("synthetic-inline-secret")
    );
    let ResolveComposeStackResponse::Success {
      services,
      contents,
      observed_snapshot,
      ..
    } = response
    else {
      panic!("Expected UI resolution");
    };
    assert_eq!(services.len(), 3);
    assert_eq!(contents.len(), 3);
    assert!(!contents.iter().any(|file| file.path == ".env"));
    assert_eq!(
      observed_snapshot.config_generation.as_deref(),
      Some("ui-generation")
    );
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_inline_discovery_is_private_generation_bound_and_redacted()
  -> anyhow::Result<()> {
    ui_resolution_case(false).await
  }

  #[tokio::test]
  async fn compose_include_inline_failed_discovery_cleans_sources_without_retry()
  -> anyhow::Result<()> {
    let mut stack = komodo_client::entities::stack::Stack::default();
    stack.id = "a".repeat(24);
    stack.config.file_contents = "services: {}".into();
    let request = ResolveComposeStack {
      request_identity:
        komodo_client::entities::stack::ResolutionRequestIdentity {
          stack_id: stack.id.clone(),
          config_generation: "ui-generation".into(),
          source: ComposeResolutionSource::Ui,
        },
      stack,
      repo: None,
      git_token: None,
      replacers: Vec::new(),
    };
    let mut directory = None;
    let mut calls = 0;
    let result = super::super::inline::resolve_ui_sources(
      request,
      Path::new("/synthetic/periphery"),
      &HashMap::new(),
      Instant::now() + Duration::from_secs(60),
      async |worker, _, _| {
        directory = worker.source_root.clone();
        calls += 1;
        Err(fail(ErrorKind::SourceChanged))
      },
    )
    .await;
    assert_eq!(
      result.err().unwrap().category,
      ErrorKind::SourceChanged
    );
    assert_eq!(calls, 1);
    assert!(!directory.unwrap().exists());
    Ok(())
  }

  #[tokio::test]
  #[ignore = "requires freshly built KOMODO_COMPOSE_RESOLVER_EXE, Docker Compose"]
  async fn compose_include_cli_inline_discovers_nested_companions_without_deployment()
  -> anyhow::Result<()> {
    ui_resolution_case(true).await
  }

  fn resource_wrapper() -> &'static str {
    if std::env::var_os("KOMODO_COMPOSE_MEASURE_RSS").is_some() {
      "/usr/bin/time -q -f %M -o worker-rss-kib [[COMPOSE_COMMAND]]"
    } else {
      "[[COMPOSE_COMMAND]]"
    }
  }

  fn report_worker_memory(
    fixture: &Fixture,
    case: &str,
  ) -> anyhow::Result<()> {
    if std::env::var_os("KOMODO_COMPOSE_MEASURE_RSS").is_some() {
      let kib: u64 =
        fs::read_to_string(fixture.root.join("worker-rss-kib"))?
          .trim()
          .parse()?;
      println!("resource-case {case}: peak-worker-rss-kib={kib}");
    }
    Ok(())
  }

  async fn production_worker(
    fixture: &Fixture,
    request: &WorkerRequest,
    wrapper: &str,
    environment: &BTreeMap<String, String>,
    timeout: Duration,
    cancel: Option<tokio_util::sync::CancellationToken>,
  ) -> anyhow::Result<Result<Resolved, IncludeError>> {
    let command =
      worker_command(&worker_binary()?, wrapper, &["config".into()])
        .map_err(|_| anyhow::anyhow!("Invalid synthetic wrapper"))?;
    Ok(
      invoke_worker(
        request,
        &command,
        CommandOptions::default()
          .path(fixture.root.as_path())
          .env(environment)
          .cancel(cancel),
        Instant::now() + timeout,
      )
      .await,
    )
  }

  fn test_environment(
    fixture: &Fixture,
  ) -> anyhow::Result<BTreeMap<String, String>> {
    Ok(BTreeMap::from([
      ("PATH".into(), std::env::var("PATH")?),
      ("HOME".into(), fixture.root.to_str().unwrap().into()),
      ("COMPOSE_ENV_FILES".into(), String::new()),
      ("COMPOSE_DISABLE_ENV_FILE".into(), "false".into()),
    ]))
  }

  #[tokio::test]
  #[ignore = "requires freshly built KOMODO_COMPOSE_RESOLVER_EXE, Docker Compose, OpenSSL"]
  async fn compose_include_cli_worker_wrapper_contexts()
  -> anyhow::Result<()> {
    for wrapper in [
      "[[COMPOSE_COMMAND]]",
      "env MODULE_FILE=modules/compose.yaml [[COMPOSE_COMMAND]]",
      "openssl enc -d -aes-256-cbc -pbkdf2 -iter 1000 -pass file:wrapper.key -in sealed.bin -out compose.yaml && env MODULE_FILE=modules/compose.yaml [[COMPOSE_COMMAND]]",
    ] {
      let fixture = Fixture::new("nested")?;
      if wrapper != "[[COMPOSE_COMMAND]]" {
        fs::write(
          fixture.root.join("compose.yaml"),
          "services:\n  root:\n    image: conformance/root:synthetic\ninclude:\n  - ${MODULE_FILE:?synthetic-secret}\n",
        )?;
      }
      if wrapper.starts_with("openssl ") {
        fs::rename(
          fixture.root.join("compose.yaml"),
          fixture.root.join("prepared.yaml"),
        )?;
        let key = fixture.root.join("wrapper.key");
        fs::write(&key, "synthetic-wrapper-test-key\n")?;
        fs::set_permissions(key, fs::Permissions::from_mode(0o600))?;
        let encrypted = std::process::Command::new("openssl")
          .args([
            "enc",
            "-aes-256-cbc",
            "-pbkdf2",
            "-iter",
            "1000",
            "-pass",
            "file:wrapper.key",
            "-in",
            "prepared.yaml",
            "-out",
            "sealed.bin",
          ])
          .current_dir(&fixture.root)
          .output()?;
        anyhow::ensure!(
          encrypted.status.success(),
          "Cannot encrypt synthetic wrapper fixture"
        );
        fs::remove_file(fixture.root.join("prepared.yaml"))?;
      }
      let result = production_worker(
        &fixture,
        &request(),
        wrapper,
        &test_environment(&fixture)?,
        Duration::from_secs(10),
        None,
      )
      .await??;
      let mut names = result
        .services
        .iter()
        .map(|service| service.service_name.as_str())
        .collect::<Vec<_>>();
      names.sort_unstable();
      assert_eq!(names, ["leaf", "module", "root"]);
      assert_eq!(result.contents.len(), 3);
    }
    Ok(())
  }

  #[tokio::test]
  #[ignore = "requires freshly built KOMODO_COMPOSE_RESOLVER_EXE"]
  async fn compose_include_cli_worker_rejects_output_and_failure_noise()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    for (wrapper, kind) in [
      (
        "printf 'synthetic-secret noise'; [[COMPOSE_COMMAND]]",
        ErrorKind::WorkerOutput,
      ),
      ("[[COMPOSE_COMMAND]]; exit 7", ErrorKind::WrapperFailure),
      (
        "printf 'synthetic-secret' >&2; exit 9; [[COMPOSE_COMMAND]]",
        ErrorKind::WrapperFailure,
      ),
    ] {
      let error = production_worker(
        &fixture,
        &request(),
        wrapper,
        &test_environment(&fixture)?,
        Duration::from_secs(10),
        None,
      )
      .await?
      .err()
      .unwrap();
      assert_eq!(error.kind, kind);
      assert!(!error.to_string().contains("synthetic-secret"));
    }
    Ok(())
  }

  fn fake_docker(
    fixture: &Fixture,
    body: &str,
  ) -> anyhow::Result<BTreeMap<String, String>> {
    let directory = fixture.root.join("bin");
    fs::create_dir(&directory)?;
    let path = directory.join("docker");
    fs::write(&path, format!("#!/bin/sh\n{body}\n"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    let mut environment = test_environment(fixture)?;
    environment.insert(
      "PATH".into(),
      format!("{}:{}", directory.display(), std::env::var("PATH")?),
    );
    Ok(environment)
  }

  #[tokio::test]
  #[ignore = "requires freshly built KOMODO_COMPOSE_RESOLVER_EXE"]
  async fn compose_include_cli_worker_does_not_require_namespaces()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let environment = fake_docker(
      &fixture,
      r#"
printf x >> config.calls
printf '%s' '{"services":{"root":{"image":"synthetic/root"}}}'
"#,
    )?;
    let unshare = fixture.root.join("bin/unshare");
    fs::write(&unshare, "#!/bin/sh\nexit 127\n")?;
    fs::set_permissions(unshare, fs::Permissions::from_mode(0o700))?;
    let result = production_worker(
      &fixture,
      &request(),
      "[[COMPOSE_COMMAND]]",
      &environment,
      Duration::from_secs(10),
      None,
    )
    .await??;
    assert_eq!(result.services[0].service_name, "root");
    assert_eq!(
      fs::read_to_string(fixture.root.join("config.calls"))?,
      "x"
    );
    Ok(())
  }

  #[tokio::test]
  #[ignore = "requires freshly built KOMODO_COMPOSE_RESOLVER_EXE"]
  async fn compose_include_cli_worker_preserves_wrapper_environment()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let environment = fake_docker(
      &fixture,
      r#"
test "$COMPOSE_EXPERIMENTAL_GIT_REMOTE" = true || exit 81
test "$COMPOSE_EXPERIMENTAL_OCI_REMOTE" = true || exit 82
test "$*" = "compose -p conformance -f compose.yaml config --format json" || exit 83
printf '%s' '{"services":{"guarded":{"image":"synthetic/guarded"}}}'
"#,
    )?;
    let result = production_worker(
      &fixture, &request(),
      "env COMPOSE_EXPERIMENTAL_GIT_REMOTE=true COMPOSE_EXPERIMENTAL_OCI_REMOTE=true [[COMPOSE_COMMAND]]",
      &environment, Duration::from_secs(10), None,
    ).await??;
    assert_eq!(result.services[0].service_name, "guarded");
    Ok(())
  }

  #[tokio::test]
  #[ignore = "requires freshly built KOMODO_COMPOSE_RESOLVER_EXE"]
  async fn compose_include_cli_worker_marks_remote_source_untracked()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("remote_git")?;
    let environment = fake_docker(
      &fixture,
      r#"printf '%s' '{"services":{"remote":{"image":"synthetic/app"}}}'"#,
    )?;
    let result = production_worker(
      &fixture,
      &request(),
      "[[COMPOSE_COMMAND]]",
      &environment,
      Duration::from_secs(10),
      None,
    )
    .await??;
    assert!(result.has_untracked_remote);
    assert_eq!(result.services[0].service_name, "remote");
    Ok(())
  }

  #[tokio::test]
  #[ignore = "requires freshly built KOMODO_COMPOSE_RESOLVER_EXE, Docker Compose"]
  async fn compose_include_cli_worker_source_privacy_and_invalid_input()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let root = fixture.root.join("compose.yaml");
    fs::write(
      &root,
      fs::read_to_string(&root)?
        .replace("conformance/root:synthetic", "${MODEL_IMAGE}"),
    )?;
    fs::write(
      fixture.root.join(".env"),
      "MODEL_IMAGE=synthetic-secret\n",
    )?;
    let request = request();
    let result = production_worker(
      &fixture,
      &request,
      "[[COMPOSE_COMMAND]]",
      &test_environment(&fixture)?,
      Duration::from_secs(10),
      None,
    )
    .await??;
    assert!(
      result
        .services
        .iter()
        .any(|service| service.service_name == "root"
          && service.image == "<SYNTHETIC_SECRET>")
    );
    assert!(
      !result
        .contents
        .keys()
        .any(|path| path.file_name().unwrap() == ".env")
    );
    assert!(
      !String::from_utf8(encode_bounded(&result, MAX_REPLY)?)?
        .contains("synthetic-secret")
    );

    let command = worker_command(&worker_binary()?, "", &[])
      .map_err(|_| {
        anyhow::anyhow!("Cannot construct private worker command")
      })?;
    let output = run_shell_command(
      &command,
      CommandOptions::default()
        .path(fixture.root.as_path())
        .stdin(r#"{"synthetic-secret":true}"#)
        .timeout(Duration::from_secs(5))
        .output_limit(MAX_REPLY),
    )
    .await;
    assert!(!output.success());
    assert!(!output.stdout.contains("synthetic-secret"));
    assert!(!output.stderr.contains("synthetic-secret"));
    assert!(matches!(
      serde_json::from_str::<WorkerReply>(&output.stdout)?,
      WorkerReply::Failure {
        id: None,
        kind: ErrorKind::WorkerInput,
        ..
      }
    ));
    Ok(())
  }

  #[tokio::test]
  #[ignore = "requires freshly built KOMODO_COMPOSE_RESOLVER_EXE"]
  async fn compose_include_cli_worker_rejects_changed_sources()
  -> anyhow::Result<()> {
    for name in ["remote_git", "remote_oci", "nested"] {
      let fixture = Fixture::new(name)?;
      let environment = fake_docker(
        &fixture,
        r#"
printf x >> config.calls
printf 'services: {}\n' > compose.yaml
printf '%s' '{"services":{"stale":{"image":"synthetic/stale"}}}'
"#,
      )?;
      let error = production_worker(
        &fixture,
        &request(),
        "[[COMPOSE_COMMAND]]",
        &environment,
        Duration::from_secs(10),
        None,
      )
      .await?
      .err()
      .unwrap();
      assert_eq!(error.kind, ErrorKind::SourceChanged);
      assert_eq!(
        fs::read_to_string(fixture.root.join("config.calls"))?,
        "x"
      );
    }
    Ok(())
  }

  #[tokio::test]
  #[ignore = "requires freshly built KOMODO_COMPOSE_RESOLVER_EXE"]
  async fn compose_include_cli_worker_source_and_wire_budgets()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let environment = fake_docker(
      &fixture,
      r#"
printf x >> config.calls
printf '%s' '{"services":{"root":{"image":"synthetic/root"}}}'
"#,
    )?;
    for padding in ['x', '\t'] {
      let mut source = String::from(
        "services:\n  root:\n    image: synthetic/root\n#",
      );
      source.extend(std::iter::repeat_n(
        padding,
        MAX_BYTES - source.len(),
      ));
      fs::write(fixture.root.join("compose.yaml"), &source)?;
      drop(source);
      fs::write(fixture.root.join("config.calls"), "")?;
      let result = production_worker(
        &fixture,
        &request(),
        resource_wrapper(),
        &environment,
        Duration::from_secs(60),
        None,
      )
      .await?;
      report_worker_memory(
        &fixture,
        if padding == 'x' {
          "plain-source"
        } else {
          "escaped-source"
        },
      )?;
      assert_eq!(
        fs::read_to_string(fixture.root.join("config.calls"))?,
        "x",
      );
      let result = result?;
      assert_eq!(result.services.len(), 1);
      assert_eq!(result.services[0].service_name, "root");
      assert_eq!(result.dependencies.len(), 1);
      assert_eq!(result.contents.len(), 1);
      assert_eq!(
        result.contents.values().next().unwrap().len(),
        MAX_BYTES
      );
      if padding == '\t' {
        assert!(
          encode_bounded(&result, MAX_REPLY)?.len()
            > 64 * 1024 * 1024
        );
      }
    }
    Ok(())
  }

  #[tokio::test]
  #[ignore = "requires freshly built KOMODO_COMPOSE_RESOLVER_EXE"]
  async fn compose_include_cli_worker_rejects_amplified_state()
  -> anyhow::Result<()> {
    for case in ["environment", "contexts", "model"] {
      let fixture = Fixture::new("nested")?;
      let value = "x".repeat(1024 * 1024);
      let mut dotenv = format!("BASE={value}\n");
      let mut source = String::from("services: {}\n");
      if case == "environment" {
        for index in 0..65 {
          dotenv.push_str(&format!("COPY_{index}=${{BASE}}\n"));
        }
      } else if case == "contexts" {
        fs::write(
          fixture.root.join("common.yaml"),
          "services: {}\n",
        )?;
        source.push_str("include:\n");
        for index in 0..65 {
          source.push_str(&format!(
            "  - path: common.yaml\n    project_directory: context-{index}\n    env_file: /dev/null\n",
          ));
        }
      } else {
        source.push_str(&format!(
          "x-base: &base '{value}'\nx-copies:\n{}",
          "  - *base\n".repeat(65)
        ));
      }
      fs::write(fixture.root.join(".env"), dotenv)?;
      fs::write(fixture.root.join("compose.yaml"), source)?;
      let environment =
        fake_docker(&fixture, "printf x >> config.calls")?;
      let result = production_worker(
        &fixture,
        &request(),
        resource_wrapper(),
        &environment,
        Duration::from_secs(60),
        None,
      )
      .await?;
      assert_eq!(result.err().unwrap().kind, ErrorKind::Limit);
      assert!(!fixture.root.join("config.calls").exists());
      report_worker_memory(&fixture, case)?;
    }
    Ok(())
  }

  #[tokio::test]
  #[ignore = "requires freshly built KOMODO_COMPOSE_RESOLVER_EXE"]
  async fn compose_include_cli_worker_timeout_cancellation_clean_descendants()
  -> anyhow::Result<()> {
    for phase in ["source", "probe"] {
      let fixture = Fixture::new("nested")?;
      let request = request();
      let body = r#"
sleep 30 &
descendant=$!
printf '%s' "$PPID" > worker.pid
printf '%s' "$descendant" > descendant.pid
wait "$descendant"
"#;
      let environment = fake_docker(&fixture, body)?;
      if phase == "probe" {
        fs::write(
          fixture.root.join("bin/docker"),
          format!("#!/bin/sh\n{body}"),
        )?;
      }
      for cancelled in [false, true] {
        let cancel = tokio_util::sync::CancellationToken::new();
        let interrupt = async {
          for _ in 0..500 {
            if fixture.root.join("descendant.pid").exists() {
              let worker =
                fs::read_to_string(fixture.root.join("worker.pid"))
                  .unwrap();
              let args =
                fs::read(format!("/proc/{worker}/cmdline")).unwrap();
              assert!(
                !args
                  .windows(b"synthetic-secret".len())
                  .any(|part| part == b"synthetic-secret")
              );
              if cancelled {
                cancel.cancel();
              }
              return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
          }
          panic!("fake config did not start");
        };
        let (result, ()) = tokio::join!(
          production_worker(
            &fixture,
            &request,
            "[[COMPOSE_COMMAND]]",
            &environment,
            Duration::from_secs(3),
            Some(cancel.clone())
          ),
          interrupt,
        );
        let error = result?.err().unwrap();
        assert_eq!(
          error.kind,
          if cancelled {
            ErrorKind::Cancelled
          } else {
            ErrorKind::Timeout
          }
        );
        let pid: u32 =
          fs::read_to_string(fixture.root.join("descendant.pid"))?
            .parse()?;
        let mut running = true;
        for _ in 0..50 {
          running =
            match fs::read_to_string(format!("/proc/{pid}/stat")) {
              Ok(stat) => {
                !stat.rsplit_once(") ").unwrap().1.starts_with('Z')
              }
              Err(error)
                if error.kind() == std::io::ErrorKind::NotFound =>
              {
                false
              }
              Err(error) => return Err(error.into()),
            };
          if !running {
            break;
          }
          tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if running {
          std::process::Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status()?;
        }
        assert!(
          !running,
          "owned config descendant survived cancellation/timeout"
        );
        fs::remove_file(fixture.root.join("descendant.pid"))?;
      }
    }
    Ok(())
  }

  #[test]
  fn compose_include_worker_protocol_exact_bounds()
  -> anyhow::Result<()> {
    let request = request();
    let bytes = serde_json::to_vec(&request)?;
    let decoded = read_request(bytes.as_slice(), bytes.len())?;
    assert_eq!(decoded.id, request.id);
    assert_eq!(
      read_request(bytes.as_slice(), bytes.len() - 1)
        .err()
        .unwrap()
        .kind,
      ErrorKind::Limit
    );
    assert_eq!(encode_bounded(&request, bytes.len())?, bytes);
    assert_eq!(
      encode_bounded(&request, bytes.len() - 1)
        .err()
        .unwrap()
        .kind,
      ErrorKind::Limit
    );
    Ok(())
  }

  #[test]
  fn compose_include_worker_protocol_rejects_extra_stdout_and_stale_reply()
  -> anyhow::Result<()> {
    let request = request();
    let bytes = serde_json::to_vec(&success(&request))?;
    decode_reply(&request, output(bytes.clone(), true))?;
    let extra = b"\nsynthetic-secret extra stdout\n";
    for bytes in [
      [extra.as_slice(), bytes.as_slice()].concat(),
      [bytes.as_slice(), extra.as_slice()].concat(),
    ] {
      let error =
        decode_reply(&request, output(bytes, true)).err().unwrap();
      assert_eq!(error.kind, ErrorKind::WorkerOutput);
      assert!(!error.to_string().contains("synthetic-secret"));
    }
    let other = self::request();
    let bytes = serde_json::to_vec(&success(&other))?;
    assert_eq!(
      decode_reply(&request, output(bytes, true))
        .err()
        .unwrap()
        .kind,
      ErrorKind::WorkerOutput
    );
    Ok(())
  }

  #[test]
  fn compose_include_worker_nonzero_exit_cannot_publish_success()
  -> anyhow::Result<()> {
    let request = request();
    let bytes = serde_json::to_vec(&success(&request))?;
    assert_eq!(
      decode_reply(&request, output(bytes, false))
        .err()
        .unwrap()
        .kind,
      ErrorKind::WrapperFailure
    );
    Ok(())
  }

  #[test]
  fn compose_include_worker_invalid_input_is_sanitized() {
    for bytes in [
      b"{synthetic-secret".as_slice(),
      br#"{"id":"synthetic-secret","roots":[]}"#.as_slice(),
    ] {
      let error = read_request(bytes, MAX_BYTES).err().unwrap();
      assert_eq!(error.kind, ErrorKind::WorkerInput);
      assert!(!error.to_string().contains("synthetic-secret"));
    }
  }

  #[test]
  fn compose_include_worker_protocol_rejects_unknown_fields()
  -> anyhow::Result<()> {
    let request = request();
    let mut input = serde_json::to_value(&request)?;
    input["synthetic-secret"] = serde_json::json!(true);
    let input = serde_json::to_vec(&input)?;
    assert_eq!(
      read_request(input.as_slice(), MAX_BYTES)
        .err()
        .unwrap()
        .kind,
      ErrorKind::WorkerInput
    );
    let mut reply = serde_json::to_value(success(&request))?;
    reply["synthetic-secret"] = serde_json::json!(true);
    let error = decode_reply(
      &request,
      output(serde_json::to_vec(&reply)?, true),
    )
    .err()
    .unwrap();
    assert_eq!(error.kind, ErrorKind::WorkerOutput);
    assert!(!error.to_string().contains("synthetic-secret"));
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_worker_invocation_has_bounded_controls()
  -> anyhow::Result<()> {
    let request = request();
    let reply = serde_json::to_string(&success(&request))?;
    let command = format!(
      "cat >/dev/null; printf '%s' {}",
      shell_escape::escape(reply.into()),
    );
    invoke_worker(
      &request,
      &command,
      CommandOptions::default(),
      Instant::now() + Duration::from_secs(5),
    )
    .await?;
    let error = invoke_worker(
      &request,
      "sleep 30",
      CommandOptions::default(),
      Instant::now() + Duration::from_millis(100),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(error.kind, ErrorKind::Timeout);
    let cancel = tokio_util::sync::CancellationToken::new();
    cancel.cancel();
    let error = invoke_worker(
      &request,
      "sleep 30",
      CommandOptions::default().cancel(cancel),
      Instant::now() + Duration::from_secs(5),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(error.kind, ErrorKind::Cancelled);
    for command in ["printf '\\377'", "printf '\\377' >&2"] {
      let error = invoke_worker(
        &request,
        command,
        CommandOptions::default(),
        Instant::now() + Duration::from_secs(5),
      )
      .await
      .err()
      .unwrap();
      assert_eq!(error.kind, ErrorKind::WorkerOutput);
    }
    Ok(())
  }

  #[test]
  fn compose_include_worker_failure_paths_are_redacted()
  -> anyhow::Result<()> {
    let request = request();
    let reply = WorkerReply::Failure {
      id: Some(request.id),
      kind: ErrorKind::MissingSource,
      path: Some("synthetic-secret/compose.yaml".into()),
    };
    let error = decode_reply(
      &request,
      output(serde_json::to_vec(&reply)?, false),
    )
    .err()
    .unwrap();
    assert_eq!(error.kind, ErrorKind::MissingSource);
    assert_eq!(
      error.path,
      Some("<SYNTHETIC_SECRET>/compose.yaml".into())
    );
    assert!(!error.to_string().contains("synthetic-secret"));
    Ok(())
  }

  #[test]
  fn compose_include_worker_wrapper_selection_preserves_defaults() {
    let executable = Path::new("/synthetic/periphery");
    for (wrapper, selected) in [
      ("", vec!["config".into()]),
      ("invalid synthetic-secret wrapper", Vec::new()),
      ("invalid synthetic-secret wrapper", vec!["up".into()]),
    ] {
      let command = worker_command(executable, wrapper, &selected)
        .expect(
          "unselected config wrapper must not run or be validated",
        );
      assert_eq!(
        shlex::split(&command).unwrap(),
        [executable.to_str().unwrap(), WORKER_FLAG],
      );
    }
  }

  #[test]
  fn compose_include_worker_selected_wrappers_use_existing_parser() {
    for (wrapper, expected_prefix) in [
      ("[[COMPOSE_COMMAND]]", Vec::<&str>::new()),
      (
        "# comment\nenv RESOLVER_SENTINEL=synthetic [[COMPOSE_COMMAND]]",
        vec!["env", "RESOLVER_SENTINEL=synthetic"],
      ),
    ] {
      let command = worker_command(
        Path::new("/synthetic/periphery"),
        wrapper,
        &["config".into()],
      )
      .expect(
        "selected wrapper must receive the opaque worker command",
      );
      let mut expected = expected_prefix;
      expected.extend(["/synthetic/periphery", WORKER_FLAG]);
      assert_eq!(shlex::split(&command).unwrap(), expected);
    }
  }

  #[test]
  fn compose_include_worker_rejects_missing_or_repeated_placeholders()
  {
    for wrapper in [
      "echo synthetic-secret",
      "[[COMPOSE_COMMAND]]; [[COMPOSE_COMMAND]]",
    ] {
      let error = worker_command(
        Path::new("/synthetic/periphery"),
        wrapper,
        &["config".into()],
      )
      .expect_err("worker command must occur exactly once");
      assert!(error.stderr.contains("[[COMPOSE_COMMAND]]"));
      assert!(!error.stderr.contains("synthetic-secret"));
    }
  }

  #[test]
  fn compose_include_worker_executable_is_one_shell_argument() {
    let executable =
      Path::new("/synthetic/path with '; marker/periphery");
    let command = worker_command(executable, "", &[])
      .expect("executable path must be quoted");
    assert_eq!(
      shlex::split(&command).unwrap(),
      [executable.to_str().unwrap(), WORKER_FLAG],
    );
  }

  #[test]
  fn compose_include_worker_rejects_unrepresentable_executable() {
    for executable in [
      std::ffi::OsString::new(),
      std::ffi::OsString::from_vec(vec![b'/', 0xff]),
    ] {
      assert!(
        worker_command(Path::new(&executable), "", &[]).is_err()
      );
    }
  }
}
