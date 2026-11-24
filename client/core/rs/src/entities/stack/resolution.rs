#[cfg(test)]
mod tests {
  use super::*;
  use crate::entities::stack::{Stack, StackFileRequires, StackInfo};

  fn identity() -> ResolutionRequestIdentity {
    ResolutionRequestIdentity {
      stack_id: "stack-id".into(),
      config_generation: "generation-1".into(),
      source: ComposeResolutionSource::Host {
        server_id: "server-id".into(),
        run_directory: ".".into(),
      },
    }
  }

  fn dependency() -> DerivedComposeDependency {
    serde_json::from_value(serde_json::json!({
      "path":"compose.yaml", "kind":"compose", "project_directory":".",
      "fingerprint":"a".repeat(64),
    })).unwrap()
  }

  fn snapshot(
    dependencies: &[DerivedComposeDependency],
  ) -> ObservedComposeSnapshot {
    ObservedComposeSnapshot {
      complete: true,
      dependency_fingerprints: dependencies
        .iter()
        .map(DerivedComposeDependency::observed_fingerprint)
        .collect(),
      commit_id: None,
      config_generation: None,
    }
  }

  #[test]
  fn compose_resolution_host_snapshot_is_observed_not_predicted()
  -> anyhow::Result<()> {
    let request = identity();
    let dependencies = vec![dependency()];
    let observed = snapshot(&dependencies);
    observed.validate(&request, &dependencies)?;
    let encoded = serde_json::to_value(&request)?;
    assert!(encoded.get("dependency_fingerprints").is_none());
    assert!(
      !serde_json::to_string(&request)?.contains(&"a".repeat(64))
    );
    assert_eq!(dependencies[0].requires, StackFileRequires::Redeploy);
    let mut changed = dependencies.clone();
    changed[0].fingerprint = "b".repeat(64);
    assert_eq!(
      observed.validate(&request, &changed).unwrap_err().category,
      ComposeResolutionErrorKind::SnapshotMismatch
    );
    assert!(observed.validate(&request, &[]).is_err());
    let mut context = dependency();
    context.project_directory = "module".into();
    let contexts = vec![dependency(), context];
    let observed = snapshot(&contexts);
    let mut reordered = contexts.clone();
    reordered.reverse();
    observed.validate(&request, &reordered)?;
    reordered[0].project_directory = "different-context".into();
    assert!(observed.validate(&request, &reordered).is_err());
    Ok(())
  }

  #[test]
  fn compose_resolution_legacy_snapshot_is_not_assumed_complete()
  -> anyhow::Result<()> {
    let mut value = serde_json::to_value(snapshot(&[dependency()]))?;
    value.as_object_mut().unwrap().remove("complete");
    let restored: ObservedComposeSnapshot =
      serde_json::from_value(value)?;
    assert!(!restored.complete);
    Ok(())
  }

  #[test]
  fn compose_resolution_revision_and_generation_evidence_are_source_specific()
  -> anyhow::Result<()> {
    let dependencies = vec![dependency()];
    let mut request = identity();
    request.source = ComposeResolutionSource::Repository {
      provider: "github.com".into(),
      repository: "synthetic/repository".into(),
      commit_id: "a".repeat(40),
      run_directory: ".".into(),
    };
    let mut observed = snapshot(&dependencies);
    assert!(observed.validate(&request, &dependencies).is_err());
    observed.commit_id = Some("a".repeat(40));
    observed.validate(&request, &dependencies)?;
    observed.commit_id = Some("b".repeat(40));
    assert!(observed.validate(&request, &dependencies).is_err());
    request.source = ComposeResolutionSource::Ui;
    observed.commit_id = None;
    observed.config_generation =
      Some(request.config_generation.clone());
    observed.validate(&request, &dependencies)?;
    observed.config_generation = Some("stale".into());
    assert!(observed.validate(&request, &dependencies).is_err());
    request.source = identity().source;
    assert!(observed.validate(&request, &dependencies).is_err());
    Ok(())
  }

  #[test]
  fn compose_resolution_cache_is_private_but_persisted_without_losing_legacy_state()
  -> anyhow::Result<()> {
    let legacy = serde_json::json!({
      "latest_services":[{"service_name":"latest","container_name":"p-latest","image":"synthetic/latest"}],
      "deployed_services":[{"service_name":"deployed","container_name":"p-deployed","image":"synthetic/deployed"}],
      "deployed_contents":[{"path":"compose.yaml","contents":"synthetic deployed source"}],
      "deployed_config":"synthetic deployed model",
      "remote_contents":[{"path":"compose.yaml","contents":"synthetic latest source"}],
      "remote_errors":[{"path":"synthetic","contents":"safe diagnostic"}],
    });
    let mut info: StackInfo = serde_json::from_value(legacy)?;
    let baseline = serde_json::to_value(&info)?;
    assert!(info.resolution.is_none());
    assert!(info.deployed_resolution.is_none());
    let dependencies = vec![dependency()];
    let accepted = AcceptedComposeResolution {
      deployment_proven: false,
      source_identity: ComposeSourceIdentity {
        request_identity: identity(),
        observed_snapshot: snapshot(&dependencies),
      },
      dependencies,
    };
    info.resolution =
      Some(ComposeResolutionState::Success(accepted.clone()));
    info.deployed_resolution = Some(accepted);
    let document = info.to_document()?;
    assert!(document.contains_key("resolution"));
    let stored: StackInfo = bson::from_document(document)?;
    assert!(matches!(
      stored.resolution,
      Some(ComposeResolutionState::Success(_))
    ));
    assert_eq!(
      serde_json::to_value(&stored.deployed_resolution)?,
      serde_json::to_value(&info.deployed_resolution)?,
    );
    let public = serde_json::to_value(&stored)?;
    assert!(public.get("resolution").is_none());
    assert!(public.get("deployed_resolution").is_none());
    assert!(!public.to_string().contains(&"a".repeat(64)));
    assert_eq!(public, baseline);
    #[cfg(feature = "utoipa")]
    {
      let schema = serde_json::to_value(
        <StackInfo as utoipa::PartialSchema>::schema(),
      )?;
      assert!(schema["properties"].get("resolution").is_none());
      assert!(
        schema["properties"].get("deployed_resolution").is_none()
      );
    }
    let stack: Stack = serde_json::from_value(serde_json::json!({
      "name":"legacy", "config": {"file_paths":["override.yaml","compose.yaml"]}
    }))?;
    assert_eq!(
      stack.compose_file_paths(),
      ["override.yaml", "compose.yaml"]
    );
    assert!(
      serde_json::from_value::<StackInfo>(public)?
        .resolution
        .is_none()
    );
    Ok(())
  }

  #[test]
  fn compose_resolution_failed_cache_cannot_carry_an_observed_snapshot()
  -> anyhow::Result<()> {
    let state = ComposeResolutionState::Failed {
      source_identity: Some(identity()),
      error: ComposeResolutionError::new(
        ComposeResolutionErrorKind::Timeout,
        ComposeResolutionStage::Config,
      ),
    };
    let mut value = serde_json::to_value(&state)?;
    assert!(value.get("observed_snapshot").is_none());
    value["observed_snapshot"] = serde_json::json!({});
    assert!(
      serde_json::from_value::<ComposeResolutionState>(value)
        .is_err()
    );
    Ok(())
  }
}
use serde::{Deserialize, Serialize};

use super::StackFileRequires;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionRequestIdentity {
  pub stack_id: String,
  pub config_generation: String,
  pub source: ComposeResolutionSource,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ComposeResolutionSource {
  Host {
    server_id: String,
    run_directory: String,
  },
  Repository {
    provider: String,
    repository: String,
    commit_id: String,
    run_directory: String,
  },
  Ui,
}

impl ResolutionRequestIdentity {
  pub fn validate(&self) -> Result<(), ComposeResolutionError> {
    let valid_source = match &self.source {
      ComposeResolutionSource::Host { server_id, .. } => {
        !server_id.is_empty()
      }
      ComposeResolutionSource::Repository {
        provider,
        repository,
        commit_id,
        ..
      } => {
        !provider.is_empty()
          && !repository.is_empty()
          && matches!(commit_id.len(), 40 | 64)
          && lower_hex(commit_id)
      }
      ComposeResolutionSource::Ui => true,
    };
    if self.stack_id.is_empty()
      || self.config_generation.is_empty()
      || !valid_source
    {
      return Err(ComposeResolutionError::new(
        ComposeResolutionErrorKind::InvalidIdentity,
        ComposeResolutionStage::Identity,
      ));
    }
    Ok(())
  }
}

#[derive(
  Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ComposeDependencyKind {
  Compose,
  Environment,
  Auxiliary,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedComposeDependency {
  pub path: String,
  pub kind: ComposeDependencyKind,
  pub project_directory: String,
  pub fingerprint: String,
  #[serde(default = "redeploy")]
  pub requires: StackFileRequires,
  #[serde(default)]
  pub services: Vec<String>,
}

fn redeploy() -> StackFileRequires {
  StackFileRequires::Redeploy
}

impl DerivedComposeDependency {
  pub fn observed_fingerprint(&self) -> ComposeDependencyFingerprint {
    ComposeDependencyFingerprint {
      path: self.path.clone(),
      kind: self.kind,
      project_directory: self.project_directory.clone(),
      fingerprint: self.fingerprint.clone(),
    }
  }
}

#[derive(
  Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct ComposeDependencyFingerprint {
  pub path: String,
  pub kind: ComposeDependencyKind,
  pub project_directory: String,
  pub fingerprint: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedComposeSnapshot {
  #[serde(default)]
  pub complete: bool,
  pub dependency_fingerprints: Vec<ComposeDependencyFingerprint>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub commit_id: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub config_generation: Option<String>,
}

impl ObservedComposeSnapshot {
  pub fn validate(
    &self,
    request: &ResolutionRequestIdentity,
    dependencies: &[DerivedComposeDependency],
  ) -> Result<(), ComposeResolutionError> {
    request.validate()?;
    let evidence_matches = match &request.source {
      ComposeResolutionSource::Host { .. } => {
        self.commit_id.is_none() && self.config_generation.is_none()
      }
      ComposeResolutionSource::Repository { commit_id, .. } => {
        self.commit_id.as_ref() == Some(commit_id)
          && self.config_generation.is_none()
      }
      ComposeResolutionSource::Ui => {
        self.commit_id.is_none()
          && self.config_generation.as_ref()
            == Some(&request.config_generation)
      }
    };
    let mut fingerprints = self.dependency_fingerprints.clone();
    fingerprints.sort();
    let mut expected = dependencies
      .iter()
      .map(DerivedComposeDependency::observed_fingerprint)
      .collect::<Vec<_>>();
    expected.sort();
    if !evidence_matches
      || fingerprints != expected
      || !dependencies.iter().any(|dependency| {
        dependency.kind == ComposeDependencyKind::Compose
      })
      || fingerprints.iter().any(|fingerprint| {
        fingerprint.path.is_empty()
          || fingerprint.project_directory.is_empty()
          || fingerprint.fingerprint.len() != 64
          || !lower_hex(&fingerprint.fingerprint)
      })
    {
      return Err(ComposeResolutionError::new(
        ComposeResolutionErrorKind::SnapshotMismatch,
        ComposeResolutionStage::Verify,
      ));
    }
    Ok(())
  }
}

fn lower_hex(value: &str) -> bool {
  value
    .bytes()
    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[derive(
  Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ComposeResolutionErrorKind {
  MissingSource,
  SourceAccess,
  InvalidSource,
  UnsupportedForm,
  UnsupportedCapability,
  RemoteSource,
  SourceChanged,
  IncludeCycle,
  Limit,
  Interpolation,
  ComposeValidation,
  WorkerInput,
  WorkerOutput,
  WrapperFailure,
  Timeout,
  Cancelled,
  InvalidPath,
  InvalidIdentity,
  StaleGeneration,
  SnapshotMismatch,
}

#[derive(
  Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ComposeResolutionStage {
  Identity,
  Prepare,
  Inspect,
  Config,
  Verify,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComposeResolutionError {
  pub category: ComposeResolutionErrorKind,
  pub stage: ComposeResolutionStage,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub path: Option<String>,
  pub message: String,
}

impl ComposeResolutionError {
  pub fn new(
    category: ComposeResolutionErrorKind,
    stage: ComposeResolutionStage,
  ) -> Self {
    use ComposeResolutionErrorKind::*;
    let message = match category {
      MissingSource => "A required Compose source is missing",
      SourceAccess => "Cannot read a required Compose source",
      InvalidSource => "A Compose source is invalid",
      UnsupportedForm => "A Compose source form is unsupported",
      UnsupportedCapability => {
        "Required Compose resolution capabilities are unavailable"
      }
      RemoteSource => "Remote Compose sources are unsupported",
      SourceChanged => "Compose sources changed during resolution",
      IncludeCycle => "Compose sources contain an include cycle",
      Limit => "A Compose resolution resource limit was exceeded",
      Interpolation => "Compose source interpolation failed",
      ComposeValidation => "Compose model validation failed",
      WorkerInput => "Compose resolver input is invalid",
      WorkerOutput => "Compose resolver output is invalid",
      WrapperFailure => "The Compose resolver wrapper failed",
      Timeout => "Compose resolution timed out",
      Cancelled => "Compose resolution was cancelled",
      InvalidPath => "A Compose source path is invalid",
      InvalidIdentity => {
        "Compose resolution request identity is invalid"
      }
      StaleGeneration => {
        "Compose resolution belongs to a stale configuration"
      }
      SnapshotMismatch => {
        "Compose source snapshot does not match the resolution"
      }
    };
    Self {
      category,
      stage,
      path: None,
      message: message.into(),
    }
  }
}

impl std::fmt::Display for ComposeResolutionError {
  fn fmt(
    &self,
    formatter: &mut std::fmt::Formatter,
  ) -> std::fmt::Result {
    formatter.write_str(&self.message)
  }
}

impl std::fmt::Debug for ComposeResolutionError {
  fn fmt(
    &self,
    formatter: &mut std::fmt::Formatter,
  ) -> std::fmt::Result {
    formatter
      .debug_struct("ComposeResolutionError")
      .field("category", &self.category)
      .field("stage", &self.stage)
      .finish_non_exhaustive()
  }
}

impl std::error::Error for ComposeResolutionError {}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComposeSourceIdentity {
  pub request_identity: ResolutionRequestIdentity,
  pub observed_snapshot: ObservedComposeSnapshot,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedComposeResolution {
  pub source_identity: ComposeSourceIdentity,
  pub dependencies: Vec<DerivedComposeDependency>,
  /// True only when these inputs were immutably bound to the operation.
  #[serde(default, skip_serializing_if = "is_unproven")]
  pub deployment_proven: bool,
}

fn is_unproven(proven: &bool) -> bool {
  !proven
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(
  tag = "status",
  rename_all = "snake_case",
  deny_unknown_fields
)]
pub enum ComposeResolutionState {
  Success(AcceptedComposeResolution),
  Failed {
    source_identity: Option<ResolutionRequestIdentity>,
    error: ComposeResolutionError,
  },
}

impl std::fmt::Debug for ComposeResolutionState {
  fn fmt(
    &self,
    formatter: &mut std::fmt::Formatter,
  ) -> std::fmt::Result {
    formatter.write_str("ComposeResolutionState { .. }")
  }
}

impl std::fmt::Debug for AcceptedComposeResolution {
  fn fmt(
    &self,
    formatter: &mut std::fmt::Formatter,
  ) -> std::fmt::Result {
    formatter.write_str("AcceptedComposeResolution { .. }")
  }
}
