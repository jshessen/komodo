use anyhow::Context;
use database::bson::{self, Document, doc, oid::ObjectId};
use komodo_client::entities::{
  FileContents,
  repo::Repo,
  stack::{
    AcceptedComposeResolution, ComposeResolutionError,
    ComposeResolutionErrorKind, ComposeResolutionSource,
    ComposeResolutionStage, ComposeResolutionState,
    ComposeSourceIdentity, ResolutionRequestIdentity, Stack,
    StackInfo,
  },
};
use periphery_client::api::compose::{
  ResolveComposeStack, ResolveComposeStackResponse,
};
use sha2::{Digest, Sha256};
use std::{
  collections::HashMap,
  sync::{LazyLock, Weak},
};
use tokio::sync::Mutex;

static SLOTS: LazyLock<Mutex<HashMap<String, Weak<Mutex<()>>>>> =
  LazyLock::new(Mutex::default);

async fn acquire_slot(
  stack: &str,
) -> tokio::sync::OwnedMutexGuard<()> {
  let slot = {
    let mut slots = SLOTS.lock().await;
    slots.retain(|_, slot| slot.strong_count() > 0);
    if let Some(slot) = slots.get(stack).and_then(Weak::upgrade) {
      slot
    } else {
      let slot = std::sync::Arc::new(Mutex::new(()));
      slots.insert(stack.into(), std::sync::Arc::downgrade(&slot));
      slot
    }
  };
  slot.lock_owned().await
}

pub fn uses_discovery(stack: &Stack, repo: Option<&Repo>) -> bool {
  stack.config.swarm_id.is_empty()
    && (stack.config.files_on_host
      || !stack.config.repo.is_empty()
      || repo.is_some()
      || !stack.config.file_contents.trim().is_empty()
      || !stack.config.inline_files.is_empty())
}

pub async fn ensure_companion_capability(
  stack: &Stack,
) -> anyhow::Result<()> {
  if stack.config.files_on_host
    || !stack.config.repo.is_empty()
    || !stack.config.linked_repo.is_empty()
    || stack.config.inline_files.is_empty()
  {
    return Ok(());
  }
  anyhow::ensure!(
    stack.config.swarm_id.is_empty(),
    "UI companion sources require a Compose server target"
  );
  // Probe the additive operation again before sending input an older agent would ignore.
  refresh(stack.clone(), None).await?;
  let current = crate::resource::get::<Stack>(&stack.id).await?;
  anyhow::ensure!(
    generation(stack, None)? == generation(&current, None)?,
    "Stack source configuration changed before execution"
  );
  ensure_current(&current).await
}

pub fn generation(
  stack: &Stack,
  repo: Option<&Repo>,
) -> anyhow::Result<String> {
  let bytes = serde_json::to_vec(&(
    &stack.name,
    &stack.config,
    repo.map(|repo| (&repo.id, &repo.name, &repo.config)),
  ))?;
  Ok(data_encoding::HEXLOWER.encode(&Sha256::digest(bytes)))
}

pub fn request(
  stack: Stack,
  repo: Option<Repo>,
  commit_id: Option<&str>,
) -> anyhow::Result<ResolveComposeStack> {
  let source = if stack.config.files_on_host {
    ComposeResolutionSource::Host {
      server_id: stack.config.server_id.clone(),
      run_directory: stack.config.run_directory.clone(),
    }
  } else if repo.is_some() || !stack.config.repo.is_empty() {
    let (provider, repository) = repo
      .as_ref()
      .map(|repo| (&repo.config.git_provider, &repo.config.repo))
      .unwrap_or((&stack.config.git_provider, &stack.config.repo));
    ComposeResolutionSource::Repository {
      provider: provider.clone(),
      repository: repository.clone(),
      run_directory: stack.config.run_directory.clone(),
      commit_id: commit_id
        .ok_or_else(|| {
          ComposeResolutionError::new(
            ComposeResolutionErrorKind::InvalidIdentity,
            ComposeResolutionStage::Identity,
          )
        })?
        .into(),
    }
  } else {
    ComposeResolutionSource::Ui
  };
  let request = ResolveComposeStack {
    request_identity: ResolutionRequestIdentity {
      stack_id: stack.id.clone(),
      config_generation: generation(&stack, repo.as_ref())?,
      source,
    },
    stack,
    repo,
    git_token: None,
    replacers: Vec::new(),
  };
  request.validate()?;
  Ok(request)
}

fn safe_error(
  kind: ComposeResolutionErrorKind,
  stage: ComposeResolutionStage,
) -> ComposeResolutionError {
  ComposeResolutionError::new(kind, stage)
}

fn accept(
  mut info: StackInfo,
  expected: Option<&ResolutionRequestIdentity>,
  result: Result<ResolveComposeStackResponse, ComposeResolutionError>,
  current_generation: &str,
) -> anyhow::Result<StackInfo> {
  if expected.is_some_and(|identity| {
    identity.config_generation != current_generation
  }) {
    return Err(
      safe_error(
        ComposeResolutionErrorKind::StaleGeneration,
        ComposeResolutionStage::Identity,
      )
      .into(),
    );
  }
  let result = result.and_then(|response| {
    let expected = expected.ok_or_else(|| {
      safe_error(
        ComposeResolutionErrorKind::InvalidIdentity,
        ComposeResolutionStage::Identity,
      )
    })?;
    response.validate_current(expected, current_generation)?;
    Ok(response)
  });
  info.missing_files.clear();
  match result {
    Ok(ResolveComposeStackResponse::Success {
      request_identity,
      observed_snapshot,
      mut services,
      dependencies,
      contents,
      commit_hash,
      commit_message,
    }) => {
      for service in &mut services {
        service.image_digest = info
          .latest_services
          .iter()
          .find(|previous| {
            previous.service_name == service.service_name
          })
          .and_then(|previous| previous.image_digest.clone());
      }
      info.latest_services = services;
      info.remote_contents = Some(contents);
      info.remote_errors = Some(Vec::new());
      info.latest_hash = commit_hash;
      info.latest_message = commit_message;
      info.resolution = Some(ComposeResolutionState::Success(
        AcceptedComposeResolution {
          deployment_proven: false,
          source_identity: ComposeSourceIdentity {
            request_identity,
            observed_snapshot,
          },
          dependencies,
        },
      ));
    }
    Ok(ResolveComposeStackResponse::Failure { .. }) => unreachable!(
      "Failure responses are rejected by validate_current"
    ),
    Err(error) => {
      if error.category == ComposeResolutionErrorKind::MissingSource
        && let Some(path) = &error.path
      {
        info.missing_files.push(path.clone());
      }
      info.latest_services.clear();
      info.remote_contents = None;
      info.remote_errors = Some(vec![FileContents {
        path: error
          .path
          .clone()
          .unwrap_or_else(|| "Compose resolution".into()),
        contents: error.message.clone(),
      }]);
      info.latest_hash = None;
      info.latest_message = None;
      info.resolution = Some(ComposeResolutionState::Failed {
        source_identity: expected.cloned(),
        error,
      });
    }
  }
  Ok(info)
}

pub async fn refresh(
  stack: Stack,
  repo: Option<Repo>,
) -> anyhow::Result<()> {
  use ComposeResolutionErrorKind as Kind;
  use ComposeResolutionStage as Stage;
  let _slot = acquire_slot(&stack.id).await;
  let expected_generation = generation(&stack, repo.as_ref())?;
  let mut identity = None;
  let result = async {
    let revision = if stack.config.files_on_host
      || (stack.config.repo.is_empty() && repo.is_none()) {
      None
    } else {
      Some(
        super::remote::select_repo_revision(&stack, repo.as_ref())
          .await
          .map_err(|_| {
            safe_error(Kind::SourceAccess, Stage::Prepare)
          })?,
      )
    };
    let mut request = request(
      stack.clone(),
      repo.clone(),
      revision.as_ref().map(|revision| revision.id.as_str()),
    )
    .map_err(|_| {
      safe_error(Kind::InvalidIdentity, Stage::Identity)
    })?;
    identity = Some(request.request_identity.clone());
    if matches!(&request.request_identity.source, ComposeResolutionSource::Repository { .. }) {
      request.git_token = crate::helpers::stack_git_token(
        &mut request.stack,
        request.repo.as_mut(),
      )
      .await
      .map_err(|_| safe_error(Kind::SourceAccess, Stage::Prepare))?;
    }
    if !request.stack.config.skip_secret_interp
      || request
        .repo
        .as_ref()
        .is_some_and(|repo| !repo.config.skip_secret_interp)
    {
      let context =
        crate::helpers::query::get_variables_and_secrets()
          .await
          .map_err(|_| {
            safe_error(Kind::Interpolation, Stage::Prepare)
          })?;
      interpolate_request(
        &mut request,
        &context.variables,
        &context.secrets,
      )
      .map_err(|_| safe_error(Kind::Interpolation, Stage::Prepare))?;
    }
    let target = crate::helpers::query::get_swarm_or_server(
      &stack.config.swarm_id,
      &stack.config.server_id,
    )
    .await
    .map_err(|_| safe_error(Kind::SourceAccess, Stage::Prepare))?;
    crate::helpers::swarm_or_server_request(&target, request)
      .await
      .map_err(|_| {
        let mut error = safe_error(Kind::UnsupportedCapability, Stage::Prepare);
        error.message = "Compose discovery is unavailable; verify the server connection and use a compatible Periphery version".into();
        error
      })
  }
  .await;
  let collection = crate::state::db_client()
    .stacks
    .clone_with_type::<Document>();
  let id = ObjectId::parse_str(&stack.id)?;
  let document = collection
    .find_one(doc! { "_id": id })
    .await?
    .context("Stack was removed during Compose discovery")?;
  let current: Stack = bson::from_document(document.clone())?;
  let current_repo = if !current.config.files_on_host
    && !current.config.linked_repo.is_empty()
  {
    Some(
      crate::resource::get::<Repo>(&current.config.linked_repo)
        .await?,
    )
  } else {
    None
  };
  let current_generation =
    generation(&current, current_repo.as_ref())?;
  anyhow::ensure!(
    expected_generation == current_generation,
    "Compose resolution belongs to a stale configuration"
  );
  let info = accept(
    current.info,
    identity.as_ref(),
    result,
    &current_generation,
  )?;
  let failure = match &info.resolution {
    Some(ComposeResolutionState::Failed { error, .. }) => {
      Some(error.clone())
    }
    _ => None,
  };
  // Match the exact observed config and cache so concurrent edits/deploys cannot be overwritten.
  let mut filter = doc! { "_id": id, "name": &current.name };
  for field in ["config", "info"] {
    filter.insert(
      field,
      document.get(field).cloned().unwrap_or(bson::Bson::Null),
    );
  }
  let updated = collection
    .update_one(
      filter,
      doc! { "$set": { "info": info.to_document()? } },
    )
    .await?;
  anyhow::ensure!(
    updated.matched_count == 1,
    "Stack changed before Compose discovery could be accepted"
  );
  if let Some(error) = failure {
    warn!(stack = stack.id, category = ?error.category, stage = ?error.stage, "Compose discovery failed");
    return Err(error.into());
  }
  Ok(())
}

pub async fn ensure_current(stack: &Stack) -> anyhow::Result<()> {
  let repo = if !stack.config.files_on_host
    && !stack.config.linked_repo.is_empty()
  {
    Some(
      crate::resource::get::<Repo>(&stack.config.linked_repo).await?,
    )
  } else {
    None
  };
  if !uses_discovery(stack, repo.as_ref()) {
    return Ok(());
  }
  let Some(ComposeResolutionState::Success(accepted)) =
    &stack.info.resolution
  else {
    anyhow::bail!(
      "A successful Compose source refresh is required before comparing or updating this stack"
    );
  };
  anyhow::ensure!(
    accepted.source_identity.request_identity.config_generation
      == generation(stack, repo.as_ref())?,
    "Compose resolution belongs to a stale configuration"
  );
  accepted.source_identity.observed_snapshot.validate(
    &accepted.source_identity.request_identity,
    &accepted.dependencies,
  )?;
  Ok(())
}

pub async fn ensure_change_comparable(
  stack: &Stack,
) -> anyhow::Result<()> {
  ensure_current(stack).await?;
  if !stack.config.swarm_id.is_empty()
    || (!uses_discovery(stack, None)
      && stack.config.linked_repo.is_empty())
  {
    return Ok(());
  }
  if let Some(ComposeResolutionState::Success(accepted)) =
    &stack.info.resolution
  {
    anyhow::ensure!(
      accepted.source_identity.observed_snapshot.complete,
      "Compose includes untracked remote sources; automatic change decisions are unavailable"
    );
  }
  Ok(())
}

fn interpolate_request(
  request: &mut ResolveComposeStack,
  variables: &std::collections::HashMap<String, String>,
  secrets: &std::collections::HashMap<String, String>,
) -> anyhow::Result<()> {
  let mut interpolator =
    interpolate::Interpolator::new(Some(variables), secrets);
  if !request.stack.config.skip_secret_interp {
    interpolator.interpolate_string(
      &mut request.stack.config.compose_cmd_wrapper,
    )?;
    if !request.stack.config.files_on_host {
      interpolator
        .interpolate_string(&mut request.stack.config.environment)?;
    }
    if request.request_identity.source == ComposeResolutionSource::Ui
    {
      interpolator.interpolate_string(
        &mut request.stack.config.file_contents,
      )?;
      for file in &mut request.stack.config.inline_files {
        interpolator.interpolate_string(&mut file.contents)?;
      }
    }
  }
  if let Some(repo) = &mut request.repo
    && !repo.config.skip_secret_interp
  {
    interpolator.interpolate_string(&mut repo.config.environment)?;
  }
  request.replacers.extend(interpolator.secret_replacers);
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use komodo_client::entities::{ImageDigest, stack::*};
  use periphery_client::api::compose::ResolveComposeStackResponse;

  #[test]
  fn compose_include_inline_core_interpolates_sources_without_hooks_and_binds_generation()
  -> anyhow::Result<()> {
    let mut stack = Stack::default();
    stack.id = "a".repeat(24);
    stack.config.file_contents = "include: [child.yaml]".into();
    stack.config.inline_files = vec![FileContents {
      path: "child.yaml".into(),
      contents: "services: {child: {image: '[[IMAGE]]'}}".into(),
    }];
    stack.config.pre_deploy.command = "[[UNUSED_HOOK]]".into();
    let initial = generation(&stack, None)?;
    let mut request = super::request(stack.clone(), None, None)?;
    assert!(matches!(
      request.request_identity.source,
      ComposeResolutionSource::Ui
    ));
    interpolate_request(
      &mut request,
      &HashMap::new(),
      &HashMap::from([("IMAGE".into(), "synthetic-secret".into())]),
    )?;
    assert!(
      request.stack.config.inline_files[0]
        .contents
        .contains("synthetic-secret")
    );
    assert_eq!(
      request.stack.config.pre_deploy.command,
      "[[UNUSED_HOOK]]"
    );
    assert_eq!(request.request_identity.config_generation, initial);
    stack.config.inline_files[0].contents.push('\n');
    assert_ne!(generation(&stack, None)?, initial);
    Ok(())
  }

  #[test]
  fn compose_include_core_interpolates_only_effective_discovery_fields()
  -> anyhow::Result<()> {
    let mut stack = Stack::default();
    stack.id = "a".repeat(24);
    stack.config.repo = "synthetic/repository".into();
    stack.config.environment =
      "IMAGE=[[IMAGE]]\nTOKEN=[[TOKEN]]".into();
    stack.config.compose_cmd_wrapper =
      "TOKEN=[[TOKEN]] [[COMPOSE_COMMAND]]".into();
    stack.config.pre_deploy.command = "[[UNUSED_HOOK]]".into();
    let mut request = request(stack, None, Some(&"b".repeat(40)))?;
    let variables =
      HashMap::from([("IMAGE".into(), "synthetic/image".into())]);
    let secrets =
      HashMap::from([("TOKEN".into(), "synthetic-secret".into())]);
    interpolate_request(&mut request, &variables, &secrets)?;
    assert!(
      request
        .stack
        .config
        .environment
        .contains("IMAGE=synthetic/image")
    );
    assert!(
      request
        .stack
        .config
        .environment
        .contains("TOKEN=synthetic-secret")
    );
    assert!(
      request
        .stack
        .config
        .compose_cmd_wrapper
        .contains("[[COMPOSE_COMMAND]]")
    );
    assert_eq!(
      request.stack.config.pre_deploy.command,
      "[[UNUSED_HOOK]]"
    );
    assert!(
      request
        .replacers
        .iter()
        .any(|(value, _)| value == "synthetic-secret")
    );
    request.stack.config.files_on_host = true;
    request.stack.config.environment =
      "TOKEN=[[UNDEPLOYED_HOST_SECRET]]".into();
    request.stack.config.compose_cmd_wrapper.clear();
    interpolate_request(
      &mut request,
      &HashMap::new(),
      &HashMap::new(),
    )?;
    assert_eq!(
      request.stack.config.environment,
      "TOKEN=[[UNDEPLOYED_HOST_SECRET]]"
    );
    request.stack.config.skip_secret_interp = true;
    request.stack.config.compose_cmd_wrapper =
      "[[TOKEN]] [[COMPOSE_COMMAND]]".into();
    interpolate_request(&mut request, &variables, &secrets)?;
    assert_eq!(
      request.stack.config.compose_cmd_wrapper,
      "[[TOKEN]] [[COMPOSE_COMMAND]]"
    );
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_core_decisions_require_current_success()
  -> anyhow::Result<()> {
    let mut stack = Stack::default();
    stack.id = "a".repeat(24);
    stack.config.files_on_host = true;
    stack.config.server_id = "server".into();
    assert!(ensure_current(&stack).await.is_err());
    let identity =
      request(stack.clone(), None, None)?.request_identity;
    let dependency = DerivedComposeDependency {
      path: "compose.yaml".into(),
      project_directory: ".".into(),
      kind: ComposeDependencyKind::Compose,
      fingerprint: "a".repeat(64),
      requires: StackFileRequires::Redeploy,
      services: Vec::new(),
    };
    stack.info.resolution = Some(ComposeResolutionState::Success(
      AcceptedComposeResolution {
        deployment_proven: false,
        source_identity: ComposeSourceIdentity {
          request_identity: identity,
          observed_snapshot: ObservedComposeSnapshot {
            complete: true,
            commit_id: None,
            config_generation: None,
            dependency_fingerprints: vec![
              dependency.observed_fingerprint(),
            ],
          },
        },
        dependencies: vec![dependency],
      },
    ));
    ensure_current(&stack).await?;
    if let Some(ComposeResolutionState::Success(accepted)) =
      &mut stack.info.resolution
    {
      accepted.source_identity.observed_snapshot.complete = false;
    }
    ensure_current(&stack).await?;
    let error = ensure_change_comparable(&stack).await.unwrap_err();
    assert!(error.to_string().contains("untracked remote sources"));
    let mut swarm = stack.clone();
    swarm.config.swarm_id = "swarm".into();
    ensure_change_comparable(&swarm).await?;
    let mut inactive = stack.clone();
    inactive.config.files_on_host = false;
    ensure_change_comparable(&inactive).await?;
    if let Some(ComposeResolutionState::Success(accepted)) =
      &mut stack.info.resolution
    {
      accepted.source_identity.observed_snapshot.complete = true;
    }
    stack.config.environment = "IMAGE=new".into();
    assert!(ensure_current(&stack).await.is_err());
    stack.info.resolution = Some(ComposeResolutionState::Failed {
      source_identity: None,
      error: safe_error(
        ComposeResolutionErrorKind::Timeout,
        ComposeResolutionStage::Config,
      ),
    });
    assert!(ensure_current(&stack).await.is_err());
    stack.config.swarm_id = "swarm".into();
    ensure_current(&stack).await?;
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_core_serializes_refreshes_but_not_other_stacks()
   {
    let first = acquire_slot("same-stack").await;
    let other = acquire_slot("other-stack").await;
    let waiting = tokio::time::timeout(
      std::time::Duration::from_millis(20),
      acquire_slot("same-stack"),
    )
    .await;
    assert!(waiting.is_err());
    drop(first);
    let second = acquire_slot("same-stack").await;
    drop((second, other));
  }

  #[test]
  fn compose_include_core_accepts_snapshot_by_name_and_clears_failed_latest_only()
  -> anyhow::Result<()> {
    let mut stack = Stack::default();
    stack.id = "a".repeat(24);
    stack.config.files_on_host = true;
    stack.config.server_id = "server".into();
    stack.info.latest_services = vec![StackServiceNames {
      service_name: "app".into(),
      container_name: "old-app".into(),
      image: "synthetic/app".into(),
      image_digest: Some(ImageDigest::new(
        "synthetic/app",
        "sha256:old",
      )),
    }];
    stack.info.deployed_services =
      Some(stack.info.latest_services.clone());
    stack.info.deployed_contents =
      Some(vec![komodo_client::entities::FileContents {
        path: "compose.yaml".into(),
        contents: "deployed".into(),
      }]);
    let root =
      komodo_client::entities::stack::StackRemoteFileContents {
        path: "compose.yaml".into(),
        contents: "include: [nested/compose.yaml]".into(),
        ..Default::default()
      };
    let nested =
      komodo_client::entities::stack::StackRemoteFileContents {
        path: "nested/compose.yaml".into(),
        contents: "services: {app: {image: synthetic/app}}".into(),
        ..Default::default()
      };
    stack.info.remote_contents = Some(vec![root.clone()]);
    let request = request(stack.clone(), None, None)?;
    let identity = request.request_identity;
    let dependency = DerivedComposeDependency {
      path: "compose.yaml".into(),
      project_directory: ".".into(),
      kind: ComposeDependencyKind::Compose,
      fingerprint: "a".repeat(64),
      requires: StackFileRequires::Redeploy,
      services: Vec::new(),
    };
    let response = ResolveComposeStackResponse::Success {
      request_identity: identity.clone(),
      observed_snapshot: ObservedComposeSnapshot {
        complete: true,
        commit_id: None,
        config_generation: None,
        dependency_fingerprints: vec![
          dependency.observed_fingerprint(),
        ],
      },
      services: vec![
        StackServiceNames {
          service_name: "new".into(),
          container_name: "p-new".into(),
          image: "synthetic/new".into(),
          image_digest: None,
        },
        StackServiceNames {
          service_name: "app".into(),
          container_name: "p-app".into(),
          image: "synthetic/app".into(),
          image_digest: None,
        },
      ],
      dependencies: vec![dependency],
      contents: vec![root, nested],
      commit_hash: None,
      commit_message: None,
    };
    let generation = &identity.config_generation;
    let info = accept(
      stack.info.clone(),
      Some(&identity),
      Ok(response.clone()),
      generation,
    )?;
    assert!(info.latest_services[0].image_digest.is_none());
    assert_eq!(
      info.latest_services[1]
        .image_digest
        .as_ref()
        .map(ImageDigest::as_str),
      stack.info.latest_services[0]
        .image_digest
        .as_ref()
        .map(ImageDigest::as_str)
    );
    assert!(matches!(
      info.resolution,
      Some(ComposeResolutionState::Success(_))
    ));
    assert_eq!(
      info
        .remote_contents
        .as_ref()
        .unwrap()
        .iter()
        .map(|file| file.path.as_str())
        .collect::<Vec<_>>(),
      ["compose.yaml", "nested/compose.yaml"]
    );
    assert_eq!(
      serde_json::to_value(&info.deployed_contents)?,
      serde_json::to_value(&stack.info.deployed_contents)?
    );
    assert!(
      accept(
        stack.info.clone(),
        Some(&identity),
        Ok(response),
        "new-generation"
      )
      .is_err()
    );
    let error = ComposeResolutionError::new(
      ComposeResolutionErrorKind::Timeout,
      ComposeResolutionStage::Config,
    );
    let failed = accept(
      stack.info.clone(),
      Some(&identity),
      Err(error),
      generation,
    )?;
    assert!(failed.latest_services.is_empty());
    assert_eq!(
      serde_json::to_value(failed.deployed_services)?,
      serde_json::to_value(stack.info.deployed_services)?
    );
    assert_eq!(
      serde_json::to_value(failed.deployed_contents)?,
      serde_json::to_value(stack.info.deployed_contents)?
    );
    assert!(failed.remote_contents.is_none());
    assert!(
      failed
        .remote_errors
        .as_ref()
        .is_some_and(|errors| !errors.is_empty())
    );
    assert!(matches!(
      failed.resolution,
      Some(ComposeResolutionState::Failed { .. })
    ));
    Ok(())
  }

  #[test]
  fn compose_include_core_request_uses_full_revision_and_effective_source()
  -> anyhow::Result<()> {
    let mut stack = Stack::default();
    stack.id = "a".repeat(24);
    stack.config.repo = "synthetic/stack".into();
    stack.config.file_contents = "services: {previous_ui: {}}".into();
    stack.config.file_paths =
      vec!["override.yaml".into(), "compose.yaml".into()];
    let selected = "b".repeat(40);
    let request = request(stack.clone(), None, Some(&selected))?;
    assert!(matches!(request.request_identity.source,
      ComposeResolutionSource::Repository { commit_id, repository, .. }
        if commit_id == selected && repository == "synthetic/stack"));
    assert_eq!(
      request.stack.compose_file_paths(),
      ["override.yaml", "compose.yaml"]
    );
    assert!(
      super::request(stack.clone(), None, Some(&selected[..7]))
        .is_err()
    );
    assert!(super::request(stack.clone(), None, None).is_err());
    let mut repo = Repo::default();
    repo.id = "c".repeat(24);
    repo.config.repo = "synthetic/linked".into();
    stack.config.linked_repo = repo.id.clone();
    let request = super::request(
      stack.clone(),
      Some(repo.clone()),
      Some(&selected),
    )?;
    assert!(matches!(request.request_identity.source,
      ComposeResolutionSource::Repository { repository, .. } if repository == "synthetic/linked"));
    let before = generation(&stack, Some(&repo))?;
    repo.config.environment = "IMAGE=changed".into();
    assert_ne!(before, generation(&stack, Some(&repo))?);
    Ok(())
  }

  #[test]
  fn compose_include_core_host_routing_and_generation_exclude_cache_state()
  -> anyhow::Result<()> {
    let mut stack = Stack::default();
    stack.id = "a".repeat(24);
    stack.config.files_on_host = true;
    stack.config.server_id = "server".into();
    assert!(uses_discovery(&stack, None));
    let before = generation(&stack, None)?;
    let request = request(stack.clone(), None, None)?;
    assert!(matches!(
      request.request_identity.source,
      ComposeResolutionSource::Host { .. }
    ));
    stack.info.latest_hash = Some("cache-only".into());
    assert_eq!(before, generation(&stack, None)?);
    stack.config.compose_cmd_wrapper_include = vec!["config".into()];
    assert_ne!(before, generation(&stack, None)?);
    stack.config.swarm_id = "swarm".into();
    assert!(!uses_discovery(&stack, None));
    stack.config.swarm_id.clear();
    stack.config.files_on_host = false;
    stack.config.file_contents = "services: {}".into();
    assert!(uses_discovery(&stack, None));
    Ok(())
  }
}
