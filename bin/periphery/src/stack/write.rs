use std::{os::unix::fs::DirBuilderExt, path::PathBuf};

use anyhow::{Context, anyhow};
use formatting::format_serror;
use komodo_client::entities::{
  FileContents, RepoExecutionArgs, all_logs_success, repo::Repo,
  stack::Stack, to_path_compatible_name, update::Log,
};
use mogh_resolver::Resolve;
use periphery_client::api::{
  DeployStackResponse,
  compose::{ComposePullResponse, ComposeRunResponse},
  git::{CloneRepo, PullOrCloneRepo},
};

use crate::{api::Args, config::periphery_config, helpers};

pub trait WriteStackRes {
  fn logs(&mut self) -> &mut Vec<Log>;
  fn add_remote_error(&mut self, _contents: FileContents) {}
  fn set_commit_hash(&mut self, _hash: Option<String>) {}
  fn set_commit_message(&mut self, _message: Option<String>) {}
}

impl WriteStackRes for &mut DeployStackResponse {
  fn logs(&mut self) -> &mut Vec<Log> {
    &mut self.logs
  }
  fn add_remote_error(&mut self, contents: FileContents) {
    self.remote_errors.push(contents);
  }
  fn set_commit_hash(&mut self, hash: Option<String>) {
    self.commit_hash = hash;
  }
  fn set_commit_message(&mut self, message: Option<String>) {
    self.commit_message = message;
  }
}

impl WriteStackRes for &mut ComposePullResponse {
  fn logs(&mut self) -> &mut Vec<Log> {
    &mut self.logs
  }
}

impl WriteStackRes for &mut ComposeRunResponse {
  fn logs(&mut self) -> &mut Vec<Log> {
    &mut self.logs
  }
}

/// Either writes the stack file_contents to a file, or clones the repo.
/// Asssumes all interpolation is already complete.
/// Returns (run_directory, env_file_path, periphery_replacers)
#[instrument(
  "WriteStack",
  skip_all,
  fields(
    stack = stack.name,
    repo = repo.as_ref().map(|repo| &repo.name),
  )
)]
pub async fn write_stack<'a>(
  stack: &'a Stack,
  repo: Option<&Repo>,
  git_token: Option<String>,
  replacers: Vec<(String, String)>,
  res: impl WriteStackRes,
  req_args: &Args,
) -> anyhow::Result<(
  // run_directory
  PathBuf,
  // env_file_path
  Option<&'a str>,
)> {
  if stack.config.files_on_host {
    write_stack_files_on_host(stack, res).await
  } else if let Some(repo) = repo {
    write_stack_linked_repo(
      stack, repo, git_token, replacers, res, req_args,
    )
    .await
  } else if !stack.config.repo.is_empty() {
    write_stack_inline_repo(stack, git_token, res, req_args).await
  } else {
    write_stack_ui_defined(stack, res).await
  }
}

#[instrument("WriteStackFilesOnHost", skip_all)]
async fn write_stack_files_on_host(
  stack: &Stack,
  mut res: impl WriteStackRes,
) -> anyhow::Result<(
  // run_directory
  PathBuf,
  // env_file_path
  Option<&str>,
)> {
  let run_directory = periphery_config()
    .stack_dir()
    .join(to_path_compatible_name(&stack.name))
    .join(&stack.config.run_directory)
    .components()
    .collect::<PathBuf>();
  let env_file_path = environment::write_env_file(
    &stack.config.env_vars()?,
    run_directory.as_path(),
    &stack.config.env_file_path,
    res.logs(),
  )
  .await;
  if all_logs_success(res.logs()) {
    Ok((
      run_directory,
      // Env file paths are expected to be already relative to run directory,
      // so need to pass original env_file_path here.
      env_file_path
        .is_some()
        .then_some(&stack.config.env_file_path),
    ))
  } else {
    Err(anyhow!("Failed to write env file, stopping run."))
  }
}

#[instrument("WriteStackLinkedRepo", skip_all)]
async fn write_stack_linked_repo<'a>(
  stack: &'a Stack,
  repo: &Repo,
  git_token: Option<String>,
  replacers: Vec<(String, String)>,
  mut res: impl WriteStackRes,
  req_args: &Args,
) -> anyhow::Result<(
  // run_directory
  PathBuf,
  // env_file_path
  Option<&'a str>,
)> {
  let root = periphery_config()
    .repo_dir()
    .join(to_path_compatible_name(&repo.name))
    .join(&repo.config.path)
    .components()
    .collect::<PathBuf>();

  let mut args: RepoExecutionArgs = repo.into();
  // Set the clone destination to the one created for this run
  args.destination = Some(root.display().to_string());

  let git_token = stack_git_token(git_token, &args, &mut res)?;

  let env_file_path = root
    .join(&repo.config.env_file_path)
    .components()
    .collect::<PathBuf>()
    .display()
    .to_string();

  let on_clone = (!repo.config.on_clone.is_none())
    .then_some(repo.config.on_clone.clone());
  let on_pull = (!repo.config.on_pull.is_none())
    .then_some(repo.config.on_pull.clone());

  let clone_res = if stack.config.reclone {
    CloneRepo {
      args,
      git_token,
      environment: repo.config.env_vars()?,
      env_file_path,
      on_clone,
      on_pull,
      skip_secret_interp: repo.config.skip_secret_interp,
      replacers,
    }
    .resolve(req_args)
    .await?
  } else {
    PullOrCloneRepo {
      args,
      git_token,
      environment: repo.config.env_vars()?,
      env_file_path,
      on_clone,
      on_pull,
      skip_secret_interp: repo.config.skip_secret_interp,
      replacers,
    }
    .resolve(req_args)
    .await?
  };

  res.logs().extend(clone_res.res.logs);
  res.set_commit_hash(clone_res.res.commit_hash);
  res.set_commit_message(clone_res.res.commit_message);

  if !all_logs_success(res.logs()) {
    return Ok((root, None));
  }

  let run_directory = root
    .join(&stack.config.run_directory)
    .components()
    .collect::<PathBuf>();

  let env_file_path = environment::write_env_file(
    &stack.config.env_vars()?,
    run_directory.as_path(),
    &stack.config.env_file_path,
    res.logs(),
  )
  .await;
  if !all_logs_success(res.logs()) {
    return Err(anyhow!("Failed to write env file, stopping run"));
  }

  Ok((
    run_directory,
    env_file_path
      .is_some()
      .then_some(&stack.config.env_file_path),
  ))
}

#[instrument("WriteStackInlineRepo", skip_all)]
async fn write_stack_inline_repo<'a>(
  stack: &'a Stack,
  git_token: Option<String>,
  mut res: impl WriteStackRes,
  req_args: &Args,
) -> anyhow::Result<(
  // run_directory
  PathBuf,
  // env_file_path
  Option<&'a str>,
)> {
  let root = periphery_config()
    .stack_dir()
    .join(to_path_compatible_name(&stack.name))
    .join(&stack.config.clone_path)
    .components()
    .collect::<PathBuf>();

  let mut args: RepoExecutionArgs = stack.into();
  // Set the clone destination to the one created for this run
  args.destination = Some(root.display().to_string());

  let git_token = stack_git_token(git_token, &args, &mut res)?;

  let clone_res = if stack.config.reclone {
    CloneRepo {
      args,
      git_token,
      environment: Default::default(),
      env_file_path: Default::default(),
      on_clone: Default::default(),
      on_pull: Default::default(),
      skip_secret_interp: Default::default(),
      replacers: Default::default(),
    }
    .resolve(req_args)
    .await?
  } else {
    PullOrCloneRepo {
      args,
      git_token,
      environment: Default::default(),
      env_file_path: Default::default(),
      on_clone: Default::default(),
      on_pull: Default::default(),
      skip_secret_interp: Default::default(),
      replacers: Default::default(),
    }
    .resolve(req_args)
    .await?
  };

  res.logs().extend(clone_res.res.logs);
  res.set_commit_hash(clone_res.res.commit_hash);
  res.set_commit_message(clone_res.res.commit_message);

  if !all_logs_success(res.logs()) {
    return Ok((root, None));
  }

  let run_directory = root
    .join(&stack.config.run_directory)
    .components()
    .collect::<PathBuf>();

  let env_file_path = environment::write_env_file(
    &stack.config.env_vars()?,
    run_directory.as_path(),
    &stack.config.env_file_path,
    res.logs(),
  )
  .await;
  if !all_logs_success(res.logs()) {
    return Err(anyhow!("Failed to write env file, stopping run"));
  }

  Ok((
    run_directory,
    env_file_path
      .is_some()
      .then_some(&stack.config.env_file_path),
  ))
}

#[instrument("WriteStackUiDefined", skip_all)]
async fn write_stack_ui_defined(
  stack: &Stack,
  mut res: impl WriteStackRes,
) -> anyhow::Result<(
  // run_directory
  PathBuf,
  // env_file_path
  Option<&str>,
)> {
  stack.config.inline_sources()?;

  let run_directory = periphery_config()
    .stack_dir()
    .join(to_path_compatible_name(&stack.name))
    .components()
    .collect::<PathBuf>();

  // Ensure run directory exists
  std::fs::DirBuilder::new()
    .recursive(true)
    .mode(0o700)
    .create(&run_directory)
    .with_context(|| {
      format!(
        "failed to create stack run directory at {run_directory:?}"
      )
    })?;
  super::inline::write_sources(&run_directory, &stack.config)?;
  super::inline::checked_path(
    &run_directory,
    &stack.config.env_file_path,
    true,
  )?;
  let env_file_path = environment::write_env_file(
    &stack.config.env_vars()?,
    run_directory.as_path(),
    &stack.config.env_file_path,
    res.logs(),
  )
  .await;
  if !all_logs_success(res.logs()) {
    return Err(anyhow!("Failed to write env file, stopping run"));
  }

  Ok((
    run_directory,
    env_file_path
      .is_some()
      .then_some(&stack.config.env_file_path),
  ))
}

fn stack_git_token<R: WriteStackRes>(
  core_token: Option<String>,
  args: &RepoExecutionArgs,
  res: &mut R,
) -> anyhow::Result<Option<String>> {
  helpers::git_token(core_token, args).map_err(|e| {
    let error = format_serror(&e.into());
    res
      .logs()
      .push(Log::error("Missing git token", error.clone()));
    res.add_remote_error(FileContents {
      path: Default::default(),
      contents: error,
    });
    anyhow!("failed to find required git token, stopping run")
  })
}

#[cfg(test)]
mod tests {
  use super::super::inline::{PrivateSourceTree, write_sources};
  use super::*;
  use std::os::unix::fs::{PermissionsExt, symlink};

  fn inline_stack() -> Stack {
    let mut stack = Stack::default();
    stack.config.file_contents =
      "include: [modules/child.yaml]\n".into();
    stack.config.inline_files = vec![FileContents {
      path: "modules/child.yaml".into(),
      contents: "services: {child: {image: synthetic/child}}".into(),
    }];
    stack
  }

  #[test]
  fn compose_include_inline_materializes_and_removes_only_owned_companions()
  -> anyhow::Result<()> {
    let tree = PrivateSourceTree::new()?;
    let mut stack = inline_stack();
    std::fs::write(tree.path().join("unmanaged.txt"), "keep")?;
    std::fs::write(
      tree.path().join("compose.yaml"),
      "legacy primary",
    )?;
    std::fs::set_permissions(
      tree.path().join("compose.yaml"),
      std::fs::Permissions::from_mode(0o644),
    )?;
    write_sources(tree.path(), &stack.config)?;
    assert_eq!(
      std::fs::metadata(tree.path().join("compose.yaml"))?
        .permissions()
        .mode()
        & 0o777,
      0o600
    );
    let child = tree.path().join("modules/child.yaml");
    assert_eq!(
      std::fs::read_to_string(&child)?,
      stack.config.inline_files[0].contents
    );
    assert_eq!(
      std::fs::metadata(&child)?.permissions().mode() & 0o777,
      0o600
    );
    assert_eq!(
      std::fs::metadata(child.parent().unwrap())?
        .permissions()
        .mode()
        & 0o777,
      0o700
    );
    assert!(
      !std::fs::read_to_string(
        tree
          .path()
          .join(komodo_client::entities::stack::INLINE_MANIFEST)
      )?
      .contains("synthetic/child")
    );
    stack.config.inline_files[0].path = "renamed/child.yaml".into();
    stack.config.file_contents =
      "include: [renamed/child.yaml]".into();
    write_sources(tree.path(), &stack.config)?;
    assert!(!child.exists());
    assert!(tree.path().join("renamed/child.yaml").is_file());
    stack.config.file_contents = "services: {}".into();
    stack.config.inline_files.clear();
    write_sources(tree.path(), &stack.config)?;
    assert!(!child.exists());
    assert!(!tree.path().join("renamed/child.yaml").exists());
    assert_eq!(
      std::fs::read_to_string(tree.path().join("unmanaged.txt"))?,
      "keep"
    );
    assert_eq!(
      std::fs::read_to_string(tree.path().join("compose.yaml"))?,
      "services: {}"
    );
    tree.close()?;
    Ok(())
  }

  #[test]
  fn compose_include_inline_rejects_unowned_files_symlinks_and_corrupt_manifests()
  -> anyhow::Result<()> {
    let tree = PrivateSourceTree::new()?;
    let outside = PrivateSourceTree::new()?;
    let stack = inline_stack();
    std::fs::write(outside.path().join("child.yaml"), "untouched")?;
    symlink(outside.path(), tree.path().join("modules"))?;
    assert!(write_sources(tree.path(), &stack.config).is_err());
    std::fs::remove_file(tree.path().join("modules"))?;
    std::fs::create_dir(tree.path().join("modules"))?;
    symlink(
      outside.path().join("child.yaml"),
      tree.path().join("modules/child.yaml"),
    )?;
    assert!(write_sources(tree.path(), &stack.config).is_err());
    std::fs::remove_file(tree.path().join("modules/child.yaml"))?;
    std::fs::write(
      tree.path().join("modules/child.yaml"),
      "user file",
    )?;
    assert!(write_sources(tree.path(), &stack.config).is_err());
    assert_eq!(
      std::fs::read_to_string(
        tree.path().join("modules/child.yaml")
      )?,
      "user file"
    );
    assert_eq!(
      std::fs::read_to_string(outside.path().join("child.yaml"))?,
      "untouched"
    );
    std::fs::remove_file(tree.path().join("modules/child.yaml"))?;
    std::fs::write(
      tree
        .path()
        .join(komodo_client::entities::stack::INLINE_MANIFEST),
      "[\"../escape\"]",
    )?;
    assert!(write_sources(tree.path(), &stack.config).is_err());
    assert!(!tree.path().join("compose.yaml").exists());
    tree.close()?;
    outside.close()?;
    Ok(())
  }

  #[test]
  fn compose_include_inline_sources_validate_paths_roots_and_collisions()
  -> anyhow::Result<()> {
    let mut stack = inline_stack();
    assert_eq!(stack.config.inline_sources()?.len(), 2);
    let long_component = "x".repeat(256);
    for path in [
      long_component.as_str(),
      "",
      "../escape.yaml",
      "/absolute.yaml",
      "a/../b.yaml",
      "./child.yaml",
      "a//b.yaml",
      "a\\b.yaml",
      ".git/config",
      ".env",
      "compose.yaml",
      "modules/child.yaml/descendant",
    ] {
      let mut invalid = stack.clone();
      if path == "modules/child.yaml/descendant" {
        invalid.config.inline_files.push(FileContents {
          path: path.into(),
          contents: String::new(),
        });
      } else {
        invalid.config.inline_files[0].path = path.into();
      }
      assert!(invalid.config.inline_sources().is_err(), "{path}");
    }
    stack.config.file_paths =
      vec!["compose.yaml".into(), "missing.yaml".into()];
    assert!(stack.config.inline_sources().is_err());
    stack.config.file_paths[1] = "modules/child.yaml".into();
    assert_eq!(stack.config.inline_sources()?.len(), 2);
    stack.config.inline_files.clear();
    stack.config.file_paths.clear();
    assert_eq!(
      stack.config.inline_sources()?,
      [("compose.yaml", stack.config.file_contents.as_str())]
    );
    Ok(())
  }

  #[test]
  fn compose_include_inline_sources_enforce_exact_count_and_byte_limits()
  -> anyhow::Result<()> {
    use komodo_client::entities::stack::{
      MAX_INLINE_BYTES, MAX_INLINE_FILES,
    };
    let mut stack = inline_stack();
    stack.config.inline_files = (1..MAX_INLINE_FILES)
      .map(|index| FileContents {
        path: format!("file-{index}.yaml"),
        contents: String::new(),
      })
      .collect();
    assert_eq!(
      stack.config.inline_sources()?.len(),
      MAX_INLINE_FILES
    );
    stack.config.inline_files.push(FileContents {
      path: "extra.yaml".into(),
      contents: String::new(),
    });
    assert!(stack.config.inline_sources().is_err());
    stack.config.inline_files = vec![FileContents {
      path: "large.txt".into(),
      contents: "x"
        .repeat(MAX_INLINE_BYTES - stack.config.file_contents.len()),
    }];
    stack.config.inline_sources()?;
    stack.config.inline_files[0].contents.push('x');
    assert!(stack.config.inline_sources().is_err());
    Ok(())
  }
}
