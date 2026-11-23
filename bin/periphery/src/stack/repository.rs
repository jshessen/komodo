use std::{
  collections::HashMap,
  os::unix::fs::PermissionsExt,
  path::{Path, PathBuf},
  time::Instant,
};

use command::CommandOptions;
use git::discovery::{DiscoveryCheckout, DiscoveryError};
use komodo_client::entities::{
  RepoExecutionArgs,
  stack::{
    ComposeResolutionError, ComposeResolutionSource,
    ComposeResolutionStage,
  },
};
use periphery_client::api::compose::{
  ResolveComposeStack, ResolveComposeStackResponse,
};
use tokio_util::sync::CancellationToken;

use super::{
  include::{ErrorKind, IncludeError, confined_path},
  resolve::{
    PreparedSource, Resolved, WorkerRequest, resolve_prepared_sources,
  },
};

fn prepare_error(kind: ErrorKind) -> ComposeResolutionError {
  ComposeResolutionError::new(kind, ComposeResolutionStage::Prepare)
}

fn checkout_error(error: DiscoveryError) -> ComposeResolutionError {
  prepare_error(match error {
    DiscoveryError::InvalidIdentity => ErrorKind::InvalidIdentity,
    DiscoveryError::SourceAccess => ErrorKind::SourceAccess,
    DiscoveryError::SourceChanged => ErrorKind::SourceChanged,
    DiscoveryError::Timeout => ErrorKind::Timeout,
    DiscoveryError::Cancelled => ErrorKind::Cancelled,
  })
}

pub(super) async fn resolve_repository_sources(
  mut request: ResolveComposeStack,
  executable: &Path,
  secrets: &HashMap<String, String>,
  deadline: Instant,
  cancel: CancellationToken,
  run: impl AsyncFnMut(
    &WorkerRequest,
    &str,
    Instant,
  ) -> Result<Resolved, IncludeError>,
) -> Result<ResolveComposeStackResponse, ComposeResolutionError> {
  request.validate()?;
  let ComposeResolutionSource::Repository { commit_id, .. } =
    &request.request_identity.source
  else {
    return Err(prepare_error(ErrorKind::InvalidIdentity));
  };
  let args: RepoExecutionArgs = request
    .repo
    .as_ref()
    .map(Into::into)
    .unwrap_or((&request.stack).into());
  let token =
    crate::helpers::git_token(request.git_token.take(), &args)
      .map_err(|_| prepare_error(ErrorKind::SourceAccess))?;
  let checkout = DiscoveryCheckout::prepare(
    &args,
    token.as_deref(),
    commit_id,
    deadline,
    CommandOptions::default().cancel(cancel),
  )
  .await
  .map_err(checkout_error)?;
  resolve_checkout_sources(
    request, checkout, executable, secrets, deadline, run,
  )
  .await
}

pub(super) async fn resolve_checkout_sources(
  mut request: ResolveComposeStack,
  checkout: DiscoveryCheckout,
  executable: &Path,
  secrets: &HashMap<String, String>,
  deadline: Instant,
  run: impl AsyncFnMut(
    &WorkerRequest,
    &str,
    Instant,
  ) -> Result<Resolved, IncludeError>,
) -> Result<ResolveComposeStackResponse, ComposeResolutionError> {
  let result = async {
    request.validate()?;
    let revision = checkout.verify().await.map_err(checkout_error)?;
    if !matches!(
      &request.request_identity.source,
      ComposeResolutionSource::Repository { commit_id, .. } if commit_id == &revision.id
    ) {
      return Err(prepare_error(ErrorKind::InvalidIdentity));
    }
    let directory = prepare_environment(&mut request, checkout.path(), secrets).await?;
    let source = PreparedSource {
      directory,
      source_root: Some(checkout.path().to_path_buf()),
      revision: Some(revision),
    };
    let response = resolve_prepared_sources(
      request, source, executable, secrets, deadline, run,
    ).await?;
    checkout.verify().await.map_err(|error| {
      let mut error = checkout_error(error);
      error.stage = ComposeResolutionStage::Verify;
      error
    })?;
    Ok(response)
  }.await;
  checkout.close().map_err(checkout_error)?;
  if Instant::now() >= deadline {
    return Err(ComposeResolutionError::new(
      ErrorKind::Timeout,
      ComposeResolutionStage::Verify,
    ));
  }
  result
}

async fn prepare_environment(
  request: &mut ResolveComposeStack,
  root: &Path,
  secrets: &HashMap<String, String>,
) -> Result<PathBuf, ComposeResolutionError> {
  let directory =
    confined_path(root, root, &request.stack.config.run_directory)
      .map_err(|error| prepare_error(error.kind))?;
  let directory =
    std::fs::canonicalize(directory).map_err(|error| {
      prepare_error(if error.kind() == std::io::ErrorKind::NotFound {
        ErrorKind::MissingSource
      } else {
        ErrorKind::SourceAccess
      })
    })?;
  if let Some(repo) = &mut request.repo {
    interpolate_environment(
      &mut repo.config.environment,
      repo.config.skip_secret_interp,
      secrets,
      &mut request.replacers,
    )?;
    let environment = repo
      .config
      .env_vars()
      .map_err(|_| prepare_error(ErrorKind::InvalidSource))?;
    write_environment(
      root,
      root,
      &repo.config.env_file_path,
      &environment,
    )
    .await?;
  }
  interpolate_environment(
    &mut request.stack.config.environment,
    request.stack.config.skip_secret_interp,
    secrets,
    &mut request.replacers,
  )?;
  let environment = request
    .stack
    .config
    .env_vars()
    .map_err(|_| prepare_error(ErrorKind::InvalidSource))?;
  write_environment(
    root,
    &directory,
    &request.stack.config.env_file_path,
    &environment,
  )
  .await?;
  Ok(directory)
}

fn interpolate_environment(
  environment: &mut String,
  skip: bool,
  secrets: &HashMap<String, String>,
  replacers: &mut Vec<(String, String)>,
) -> Result<(), ComposeResolutionError> {
  if !skip {
    let mut interpolator =
      interpolate::Interpolator::new(None, secrets);
    interpolator
      .interpolate_string(environment)
      .map_err(|_| prepare_error(ErrorKind::Interpolation))?;
    replacers.extend(interpolator.secret_replacers);
  }
  Ok(())
}

pub(super) async fn write_environment(
  root: &Path,
  directory: &Path,
  file: &str,
  environment: &[komodo_client::entities::EnvironmentVar],
) -> Result<(), ComposeResolutionError> {
  if environment.is_empty() {
    return Ok(());
  }
  let path = confined_path(root, directory, file)
    .map_err(|error| prepare_error(error.kind))?;
  let file = path
    .to_str()
    .ok_or_else(|| prepare_error(ErrorKind::InvalidPath))?;
  let mut logs = Vec::new();
  let written =
    environment::write_env_file(environment, root, file, &mut logs)
      .await;
  if written.is_none()
    || !komodo_client::entities::all_logs_success(&logs)
  {
    return Err(prepare_error(ErrorKind::SourceAccess));
  }
  tokio::fs::set_permissions(
    &path,
    std::fs::Permissions::from_mode(0o600),
  )
  .await
  .map_err(|_| prepare_error(ErrorKind::SourceAccess))?;
  Ok(())
}

#[cfg(test)]
mod tests {
  use std::{collections::HashMap, fs};

  use komodo_client::entities::{repo::Repo, stack::Stack};
  use periphery_client::api::compose::ResolveComposeStack;

  use super::super::Fixture;
  use super::*;

  fn request() -> ResolveComposeStack {
    let mut stack = Stack::default();
    stack.id = "a".repeat(24);
    stack.config.repo = "synthetic/repository".into();
    stack.config.run_directory = "stack".into();
    stack.config.environment =
      "IMAGE=synthetic/stack\nTOKEN=[[SECRET]]".into();
    stack.config.env_file_path = "stack.env".into();
    stack.config.pre_deploy.command =
      "[[UNUSED_LIFECYCLE_SECRET]]".into();
    let mut repo = Repo::default();
    repo.id = "b".repeat(24);
    repo.config.repo = "synthetic/repository".into();
    repo.config.environment = "REPO_TOKEN=[[SECRET]]".into();
    repo.config.env_file_path = "repo.env".into();
    repo.config.on_clone.command = "[[UNUSED_CLONE_SECRET]]".into();
    repo.config.on_pull.command = "[[UNUSED_PULL_SECRET]]".into();
    stack.config.linked_repo = repo.id.clone();
    ResolveComposeStack {
      request_identity: komodo_client::entities::stack::ResolutionRequestIdentity {
        stack_id: stack.id.clone(),
        config_generation: "generation".into(),
        source: komodo_client::entities::stack::ComposeResolutionSource::Repository {
          provider: repo.config.git_provider.clone(),
          repository: repo.config.repo.clone(),
          commit_id: "a".repeat(40),
          run_directory: stack.config.run_directory.clone(),
        },
      },
      stack, repo: Some(repo), git_token: None, replacers: Vec::new(),
    }
  }

  #[tokio::test]
  async fn compose_include_repository_environment_is_private_and_skips_hooks()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    fs::create_dir(fixture.root.join("stack"))?;
    let mut request = request();
    let secrets =
      HashMap::from([("SECRET".into(), "synthetic-secret".into())]);
    let directory =
      prepare_environment(&mut request, &fixture.root, &secrets)
        .await?;
    assert_eq!(directory, fixture.root.join("stack"));
    assert!(
      fs::read_to_string(directory.join("stack.env"))?
        .contains("TOKEN=synthetic-secret")
    );
    assert!(
      fs::read_to_string(fixture.root.join("repo.env"))?
        .contains("REPO_TOKEN=synthetic-secret")
    );
    assert!(
      request
        .replacers
        .iter()
        .any(|(value, _)| value == "synthetic-secret")
    );
    assert_eq!(
      request.stack.config.pre_deploy.command,
      "[[UNUSED_LIFECYCLE_SECRET]]"
    );
    assert_eq!(
      request.repo.as_ref().unwrap().config.on_clone.command,
      "[[UNUSED_CLONE_SECRET]]"
    );
    request.stack.config.skip_secret_interp = true;
    request.repo.as_mut().unwrap().config.skip_secret_interp = true;
    request.stack.config.environment = "TOKEN=[[SECRET]]".into();
    request.repo.as_mut().unwrap().config.environment =
      "REPO_TOKEN=[[SECRET]]".into();
    request.replacers.clear();
    prepare_environment(&mut request, &fixture.root, &HashMap::new())
      .await?;
    assert!(
      fs::read_to_string(directory.join("stack.env"))?
        .contains("TOKEN=[[SECRET]]")
    );
    assert!(
      fs::read_to_string(fixture.root.join("repo.env"))?
        .contains("REPO_TOKEN=[[SECRET]]")
    );
    assert!(request.replacers.is_empty());
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_repository_environment_rejects_escape_and_git_metadata()
  -> anyhow::Result<()> {
    let fixture = Fixture::new("nested")?;
    let outside = Fixture::new("nested")?;
    fs::create_dir(fixture.root.join("stack"))?;
    fs::create_dir(fixture.root.join(".git"))?;
    fs::write(fixture.root.join(".git/config"), "metadata")?;
    fs::write(outside.root.join("outside.env"), "unchanged")?;
    std::os::unix::fs::symlink(
      outside.root.join("outside.env"),
      fixture.root.join("stack/link.env"),
    )?;
    for path in ["../../outside.env", "../.git/config", "link.env"] {
      let mut request = request();
      request.stack.config.environment =
        "IMAGE=synthetic/private".into();
      request.stack.config.env_file_path = path.into();
      request.repo.as_mut().unwrap().config.environment.clear();
      let error = prepare_environment(
        &mut request,
        &fixture.root,
        &HashMap::new(),
      )
      .await
      .err()
      .unwrap();
      assert_eq!(error.category, komodo_client::entities::stack::ComposeResolutionErrorKind::InvalidPath);
    }
    let mut request = request();
    request.stack.config.run_directory =
      outside.root.to_str().unwrap().into();
    assert_eq!(
      prepare_environment(&mut request, &fixture.root, &HashMap::new()).await.err().unwrap().category,
      komodo_client::entities::stack::ComposeResolutionErrorKind::InvalidPath,
    );
    assert_eq!(
      fs::read_to_string(outside.root.join("outside.env"))?,
      "unchanged"
    );
    assert_eq!(
      fs::read_to_string(fixture.root.join(".git/config"))?,
      "metadata"
    );
    Ok(())
  }
}
