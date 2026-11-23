use komodo_client::entities::{
  FileContents, RepoExecutionResponse, SearchCombinator,
  repo::Repo,
  stack::{
    ComposeResolutionError, ComposeResolutionErrorKind,
    ComposeResolutionSource, ComposeResolutionStage,
    DerivedComposeDependency, ObservedComposeSnapshot,
    ResolutionRequestIdentity, Stack, StackFileDependency,
    StackRemoteFileContents, StackServiceNames,
  },
  update::Log,
};
use mogh_resolver::Resolve;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::api::DeployStackResponse;

/// Inspect and resolve Compose sources without running deployment or repository hooks.
///
/// Capability failures must be surfaced, never retried through root-only discovery.
#[derive(Clone, Serialize, Deserialize, Resolve)]
#[response(ResolveComposeStackResponse)]
#[error(anyhow::Error)]
#[serde(deny_unknown_fields)]
pub struct ResolveComposeStack {
  pub stack: Stack,
  #[serde(default)]
  pub repo: Option<Repo>,
  pub request_identity: ResolutionRequestIdentity,
  #[serde(default)]
  pub git_token: Option<String>,
  #[serde(default)]
  pub replacers: Vec<(String, String)>,
}

impl std::fmt::Debug for ResolveComposeStack {
  fn fmt(
    &self,
    formatter: &mut std::fmt::Formatter,
  ) -> std::fmt::Result {
    formatter.write_str("ResolveComposeStack { .. }")
  }
}

impl ResolveComposeStack {
  pub fn validate(&self) -> Result<(), ComposeResolutionError> {
    self.request_identity.validate()?;
    let config = &self.stack.config;
    let matches = self.request_identity.stack_id == self.stack.id
      && match &self.request_identity.source {
        ComposeResolutionSource::Host {
          server_id,
          run_directory,
        } => {
          config.files_on_host
            && server_id == &config.server_id
            && run_directory == &config.run_directory
        }
        ComposeResolutionSource::Repository {
          provider,
          repository,
          run_directory,
          ..
        } => {
          let linked_repo_valid = if config.linked_repo.is_empty() {
            self.repo.is_none()
          } else {
            self
              .repo
              .as_ref()
              .is_some_and(|repo| repo.id == config.linked_repo)
          };
          let (effective_provider, effective_repo) = self
            .repo
            .as_ref()
            .map(|repo| {
              (&repo.config.git_provider, &repo.config.repo)
            })
            .unwrap_or((&config.git_provider, &config.repo));
          !config.files_on_host
            && linked_repo_valid
            && provider == effective_provider
            && repository == effective_repo
            && run_directory == &config.run_directory
        }
        ComposeResolutionSource::Ui => {
          !config.files_on_host
            && config.repo.is_empty()
            && config.linked_repo.is_empty()
            && self.repo.is_none()
            && !config.file_contents.is_empty()
        }
      };
    if !matches {
      return Err(ComposeResolutionError::new(
        ComposeResolutionErrorKind::InvalidIdentity,
        ComposeResolutionStage::Identity,
      ));
    }
    if self.request_identity.source == ComposeResolutionSource::Ui {
      config.inline_sources().map_err(|_| {
        ComposeResolutionError::new(
          ComposeResolutionErrorKind::InvalidSource,
          ComposeResolutionStage::Prepare,
        )
      })?;
    }
    Ok(())
  }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(
  tag = "status",
  rename_all = "snake_case",
  deny_unknown_fields
)]
pub enum ResolveComposeStackResponse {
  Success {
    request_identity: ResolutionRequestIdentity,
    observed_snapshot: ObservedComposeSnapshot,
    services: Vec<StackServiceNames>,
    dependencies: Vec<DerivedComposeDependency>,
    contents: Vec<StackRemoteFileContents>,
    #[serde(default)]
    commit_hash: Option<String>,
    #[serde(default)]
    commit_message: Option<String>,
  },
  Failure {
    request_identity: Option<ResolutionRequestIdentity>,
    error: ComposeResolutionError,
  },
}

impl ResolveComposeStackResponse {
  pub fn validate_current(
    &self,
    expected: &ResolutionRequestIdentity,
    current_generation: &str,
  ) -> Result<(), ComposeResolutionError> {
    if expected.config_generation != current_generation {
      return Err(ComposeResolutionError::new(
        ComposeResolutionErrorKind::StaleGeneration,
        ComposeResolutionStage::Identity,
      ));
    }
    expected.validate()?;
    match self {
      Self::Success {
        request_identity,
        observed_snapshot,
        dependencies,
        ..
      } => {
        if request_identity != expected {
          return Err(ComposeResolutionError::new(
            ComposeResolutionErrorKind::InvalidIdentity,
            ComposeResolutionStage::Identity,
          ));
        }
        observed_snapshot.validate(request_identity, dependencies)
      }
      Self::Failure {
        request_identity,
        error,
      } => {
        if request_identity
          .as_ref()
          .is_some_and(|identity| identity != expected)
        {
          return Err(ComposeResolutionError::new(
            ComposeResolutionErrorKind::InvalidIdentity,
            ComposeResolutionStage::Identity,
          ));
        }
        Err(error.clone())
      }
    }
  }
}

#[cfg(test)]
mod resolution_tests {
  use super::*;

  #[test]
  fn compose_resolution_legacy_deploy_has_no_verified_evidence()
  -> anyhow::Result<()> {
    let response = crate::api::DeployStackResponse::default();
    let mut value = serde_json::to_value(response)?;
    value.as_object_mut().unwrap().remove("deployed_resolution");
    let legacy: crate::api::DeployStackResponse =
      serde_json::from_value(value)?;
    assert!(legacy.deployed_resolution.is_none());
    Ok(())
  }

  fn request() -> ResolveComposeStack {
    let mut stack = Stack::default();
    stack.id = "a".repeat(24);
    stack.config.files_on_host = true;
    stack.config.server_id = "server-id".into();
    stack.config.run_directory = ".".into();
    stack.config.file_paths =
      vec!["compose.yaml".into(), "override.yaml".into()];
    ResolveComposeStack {
      stack,
      repo: None,
      git_token: Some("synthetic-secret".into()),
      replacers: vec![("synthetic-secret".into(), "SENTINEL".into())],
      request_identity: ResolutionRequestIdentity {
        stack_id: "a".repeat(24),
        config_generation: "generation-1".into(),
        source: ComposeResolutionSource::Host {
          server_id: "server-id".into(),
          run_directory: ".".into(),
        },
      },
    }
  }

  #[test]
  fn compose_resolution_contract_tags_and_sensitive_debug()
  -> anyhow::Result<()> {
    let request = request();
    request.validate()?;
    assert!(!format!("{request:?}").contains("synthetic-secret"));
    let encoded = serde_json::to_value(&request)?;
    assert_eq!(
      encoded["stack"]["config"]["file_paths"],
      serde_json::json!(["compose.yaml", "override.yaml"])
    );
    let failure = ResolveComposeStackResponse::Failure {
      request_identity: Some(request.request_identity.clone()),
      error: ComposeResolutionError::new(
        ComposeResolutionErrorKind::UnsupportedCapability,
        ComposeResolutionStage::Prepare,
      ),
    };
    let mut value = serde_json::to_value(&failure)?;
    assert_eq!(value["status"], "failure");
    value["observed_snapshot"] = serde_json::json!({});
    assert!(
      serde_json::from_value::<ResolveComposeStackResponse>(value)
        .is_err()
    );
    for malformed in [
      serde_json::json!({}),
      serde_json::json!({"status":"success","services":[]}),
    ] {
      assert!(
        serde_json::from_value::<ResolveComposeStackResponse>(
          malformed
        )
        .is_err()
      );
    }
    Ok(())
  }

  #[test]
  fn compose_resolution_contract_rejects_stale_or_mismatched_identity()
  -> anyhow::Result<()> {
    let mut request = request();
    let dependency: DerivedComposeDependency =
      serde_json::from_value(serde_json::json!({
        "path":"compose.yaml","project_directory":".","kind":"compose","fingerprint":"a".repeat(64),
      }))?;
    let response = ResolveComposeStackResponse::Success {
      request_identity: request.request_identity.clone(),
      observed_snapshot: ObservedComposeSnapshot {
        complete: true,
        dependency_fingerprints: vec![
          dependency.observed_fingerprint(),
        ],
        commit_id: None,
        config_generation: None,
      },
      services: Vec::new(),
      dependencies: vec![dependency],
      contents: Vec::new(),
      commit_hash: None,
      commit_message: None,
    };
    response
      .validate_current(&request.request_identity, "generation-1")?;
    assert_eq!(
      response
        .validate_current(&request.request_identity, "new-generation")
        .unwrap_err()
        .category,
      ComposeResolutionErrorKind::StaleGeneration
    );
    request.request_identity.stack_id = "different-stack".into();
    assert!(request.validate().is_err());
    assert!(
      response
        .validate_current(&request.request_identity, "generation-1")
        .is_err()
    );
    Ok(())
  }

  #[test]
  fn compose_resolution_contract_checks_effective_source_context()
  -> anyhow::Result<()> {
    let mut request = request();
    if let ComposeResolutionSource::Host { server_id, .. } =
      &mut request.request_identity.source
    {
      *server_id = "another-server".into();
    }
    assert!(request.validate().is_err());
    request.stack.config.files_on_host = false;
    request.stack.config.git_provider = "github.com".into();
    request.stack.config.repo = "synthetic/repository".into();
    request.request_identity.source =
      ComposeResolutionSource::Repository {
        provider: "github.com".into(),
        repository: "synthetic/repository".into(),
        commit_id: "a".repeat(40),
        run_directory: ".".into(),
      };
    request.validate()?;
    // Switching the editor from UI to Git retains the previous inline text.
    request.stack.config.file_contents = "services: {}".into();
    request.validate()?;
    let mut linked = Repo::default();
    linked.id = "b".repeat(24);
    linked.config.git_provider = "github.com".into();
    linked.config.repo = "synthetic/repository".into();
    request.stack.config.linked_repo = linked.id.clone();
    request.stack.config.repo = "not-the-linked-repository".into();
    assert!(request.validate().is_err());
    request.repo = Some(linked);
    request.validate()?;
    if let ComposeResolutionSource::Repository { commit_id, .. } =
      &mut request.request_identity.source
    {
      *commit_id = "short".into();
    }
    assert!(request.validate().is_err());
    request.request_identity.source = ComposeResolutionSource::Ui;
    assert!(request.validate().is_err());
    request.stack.config.file_contents = "services: {}".into();
    assert!(request.validate().is_err());
    request.stack.config.repo.clear();
    request.stack.config.linked_repo.clear();
    request.repo = None;
    assert!(request.validate().is_err());
    request.stack.config.inline_files = vec![FileContents {
      path: "override.yaml".into(),
      contents: "services: {}".into(),
    }];
    request.validate()?;
    Ok(())
  }
}

//

/// Get the compose contents on the host, for stacks using
/// `files_on_host`.
#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[response(GetComposeContentsOnHostResponse)]
#[error(anyhow::Error)]
pub struct GetComposeContentsOnHost {
  /// The name of the stack
  pub name: String,
  pub run_directory: String,
  /// Both compose files and env / additional files, all relative to run directory.
  pub file_paths: Vec<StackFileDependency>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GetComposeContentsOnHostResponse {
  pub contents: Vec<StackRemoteFileContents>,
  pub errors: Vec<FileContents>,
}

//

/// The stack folder must already exist for this to work
#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[response(Log)]
#[error(anyhow::Error)]
pub struct GetComposeLog {
  /// The name of the project
  pub project: String,
  /// Filter the logs to only ones from specific services.
  /// If empty, will include logs from all services.
  #[serde(default)]
  pub services: Vec<String>,
  /// Pass `--tail` for only recent log contents. Max of 5000
  #[serde(default = "default_tail")]
  pub tail: u64,
  /// Enable `--timestamps`
  #[serde(default)]
  pub timestamps: bool,
}

fn default_tail() -> u64 {
  50
}

//

/// The stack folder must already exist for this to work
#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[response(Log)]
#[error(anyhow::Error)]
pub struct GetComposeLogSearch {
  /// The name of the project
  pub project: String,
  /// Filter the logs to only ones from specific services.
  /// If empty, will include logs from all services.
  #[serde(default)]
  pub services: Vec<String>,
  /// The search terms.
  pub terms: Vec<String>,
  /// And: Only lines matching all terms
  /// Or: Lines matching any one of the terms
  #[serde(default)]
  pub combinator: SearchCombinator,
  /// Invert the search (search for everything not matching terms)
  #[serde(default)]
  pub invert: bool,
  /// Enable `--timestamps`
  #[serde(default)]
  pub timestamps: bool,
}

//

/// Write the compose / additional file contents to the file on the host, for stacks using
/// `files_on_host`.
#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[response(Log)]
#[error(anyhow::Error)]
pub struct WriteComposeContentsToHost {
  /// The name of the stack
  pub name: String,
  /// The run directory of the stack
  pub run_directory: String,
  /// Relative to the stack folder + run directory,
  /// or absolute path.
  pub file_path: String,
  /// The contents to write.
  pub contents: String,
}

//

/// Write and commit compose contents.
/// Only works with git repo based stacks.
#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[response(RepoExecutionResponse)]
#[error(anyhow::Error)]
pub struct WriteCommitComposeContents {
  /// The stack to write to.
  pub stack: Stack,
  /// Optional linked repo.
  pub repo: Option<Repo>,
  /// The username of user which committed the file.
  pub username: Option<String>,
  /// Relative to the stack folder + run directory.
  pub file_path: String,
  /// The contents to write.
  pub contents: String,
  /// If provided, use it to login in. Otherwise check periphery local git providers.
  pub git_token: Option<String>,
}

//

/// Rewrites the compose directory, pulls any images, takes down existing containers,
/// and runs docker compose up. Response: [ComposePullResponse]
#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[response(ComposePullResponse)]
#[error(anyhow::Error)]
pub struct ComposePull {
  /// The stack to deploy
  pub stack: Stack,
  /// Filter to only pull specific services.
  /// If empty, will pull all services.
  #[serde(default)]
  pub services: Vec<String>,
  /// The linked repo, if it exists.
  pub repo: Option<Repo>,
  /// If provided, use it to login in. Otherwise check periphery local git providers.
  pub git_token: Option<String>,
  /// If provided, use it to login in. Otherwise check periphery local registry providers.
  pub registry_token: Option<String>,
  /// Propogate any secret replacers from core interpolation.
  #[serde(default)]
  pub replacers: Vec<(String, String)>,
}

/// Response for [ComposePull]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComposePullResponse {
  /// If any of the required files are missing, they will be here.
  pub missing_files: Vec<String>,
  /// The error in getting remote file contents at the path, or null
  pub remote_errors: Vec<FileContents>,
  /// The logs produced by the pull
  pub logs: Vec<Log>,
}

//

/// docker compose up.
#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[response(DeployStackResponse)]
#[error(anyhow::Error)]
pub struct ComposeUp {
  /// The stack to deploy
  pub stack: Stack,
  /// Filter to only deploy specific services.
  /// If empty, will deploy all services.
  #[serde(default)]
  pub services: Vec<String>,
  /// The linked repo, if it exists.
  pub repo: Option<Repo>,
  /// If provided, use it to login in. Otherwise check periphery local registries.
  pub git_token: Option<String>,
  /// If provided, use it to login in. Otherwise check periphery local git providers.
  pub registry_token: Option<String>,
  /// Propogate any secret replacers from core interpolation.
  #[serde(default)]
  pub replacers: Vec<(String, String)>,
  /// Prior discovery evidence to verify against the deployed sources.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub expected_resolution:
    Option<komodo_client::entities::stack::AcceptedComposeResolution>,
}

//

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComposeRunResponse {
  /// Logs produced during stack write/prepare for the run
  pub logs: Vec<Log>,
}

//

/// General compose command runner
#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[response(Log)]
#[error(anyhow::Error)]
pub struct ComposeExecution {
  /// The compose project name to run the execution on.
  /// Usually its he name of the stack / folder under the `stack_dir`.
  pub project: String,
  /// The command in `docker compose -p {project} {command}`
  pub command: String,
}

/// Restart services while observing the sources used for a change decision.
#[derive(Clone, Serialize, Deserialize, Resolve)]
#[response(ComposeRestartObservedResponse)]
#[error(anyhow::Error)]
pub struct ComposeRestartObserved {
  pub project: String,
  pub stack: Stack,
  pub repo: Option<Repo>,
  pub services: Vec<String>,
  pub expected_resolution:
    komodo_client::entities::stack::AcceptedComposeResolution,
  #[serde(default)]
  pub replacers: Vec<(String, String)>,
}

impl std::fmt::Debug for ComposeRestartObserved {
  fn fmt(
    &self,
    formatter: &mut std::fmt::Formatter,
  ) -> std::fmt::Result {
    formatter.write_str("ComposeRestartObserved { .. }")
  }
}

#[derive(Serialize, Deserialize)]
pub struct ComposeRestartObservedResponse {
  pub log: Log,
  pub observed_resolution:
    Option<komodo_client::entities::stack::AcceptedComposeResolution>,
}

//

/// docker compose run one-time service execution.
#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[response(Log)]
#[error(anyhow::Error)]
pub struct ComposeRun {
  /// The stack to run a service for
  pub stack: Stack,
  /// The linked repo, if it exists.
  pub repo: Option<Repo>,
  /// If provided, use it to login in. Otherwise check periphery local registries.
  pub git_token: Option<String>,
  /// If provided, use it to login in. Otherwise check periphery local git providers.
  pub registry_token: Option<String>,
  /// Propogate any secret replacers from core interpolation.
  #[serde(default)]
  pub replacers: Vec<(String, String)>,

  /// Service to run
  pub service: String,
  /// Command
  #[serde(default)]
  pub command: Option<Vec<String>>,
  /// Do not allocate TTY
  #[serde(default)]
  pub no_tty: Option<bool>,
  /// Do not start linked services
  #[serde(default)]
  pub no_deps: Option<bool>,
  /// Detach container on run
  #[serde(default)]
  pub detach: Option<bool>,
  /// Map service ports to the host
  #[serde(default)]
  pub service_ports: Option<bool>,
  /// Extra environment variables for the run
  #[serde(default)]
  pub env: Option<HashMap<String, String>>,
  /// Working directory inside the container
  #[serde(default)]
  pub workdir: Option<String>,
  /// User to run as inside the container
  #[serde(default)]
  pub user: Option<String>,
  /// Override the default entrypoint
  #[serde(default)]
  pub entrypoint: Option<String>,
  /// Pull the image before running
  #[serde(default)]
  pub pull: Option<bool>,
}
