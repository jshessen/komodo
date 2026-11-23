use std::{
  fs,
  path::{Path, PathBuf},
};

use anyhow::{Context, ensure};
use formatting::format_serror;
use komodo_client::entities::{
  FileContents, RepoExecutionArgs,
  repo::Repo,
  stack::{Stack, StackRemoteFileContents},
  update::Log,
};

use crate::{config::core_config, helpers::git_token};

#[derive(Default)]
pub struct RemoteComposeContents {
  pub successful: Vec<StackRemoteFileContents>,
  pub errored: Vec<FileContents>,
  pub revision: Option<git::CommitInfo>,
  // pub logs: Vec<Log>,
}

pub async fn select_repo_revision(
  stack: &Stack,
  repo: Option<&Repo>,
) -> anyhow::Result<git::CommitInfo> {
  let args = repo.map(Into::into).unwrap_or(stack.into());
  let (path, logs, _, _) = ensure_remote_repo(args).await?;
  ensure!(
    logs.iter().all(|log| log.success),
    "Cannot select the stack repository revision"
  );
  git::get_commit_info(&path).await
}

/// Read configured dependencies with full revision identity and display metadata.
/// These remain working-tree reads, not a revision-pinned discovery checkout.
pub async fn get_repo_compose_contents(
  stack: &Stack,
  repo: Option<&Repo>,
  // Collect any files which are missing in the repo.
  missing_files: Option<&mut Vec<String>>,
) -> anyhow::Result<RemoteComposeContents> {
  let clone_args: RepoExecutionArgs =
    repo.map(Into::into).unwrap_or(stack.into());
  let (repo_path, logs, _, _) = ensure_remote_repo(clone_args)
    .await
    .context("Failed to clone stack repo")?;

  // Ensure clone / pull successful,
  // propogate error log -> 'errored' and return.
  if let Some(failure) = logs.iter().find(|log| !log.success) {
    return Ok(RemoteComposeContents {
      errored: vec![FileContents {
        path: format!("Failed at: {}", failure.stage),
        contents: failure.combined(),
      }],
      ..Default::default()
    });
  }

  read_repo_compose_contents(
    &repo_path,
    stack,
    missing_files,
    |path| fs::read_to_string(path),
  )
  .await
}

async fn read_repo_compose_contents(
  repo_path: &Path,
  stack: &Stack,
  mut missing_files: Option<&mut Vec<String>>,
  mut read_file: impl FnMut(&Path) -> std::io::Result<String>,
) -> anyhow::Result<RemoteComposeContents> {
  let revision = git::get_commit_info(repo_path)
    .await
    .context("Failed to select stack repository revision")?;
  let run_directory = repo_path.join(&stack.config.run_directory);
  // This will remove any intermediate '/./' which can be a problem for some OS.
  let run_directory = run_directory.components().collect::<PathBuf>();

  let mut successful = Vec::new();
  let mut errored = Vec::new();

  for file in stack.all_file_dependencies() {
    let file_path = run_directory.join(&file.path);
    if !file_path.exists()
      && let Some(missing_files) = &mut missing_files
    {
      missing_files.push(file.path.clone());
    }
    // If file does not exist, will show up in err case so the log is handled
    match read_file(&file_path).with_context(|| {
      format!("Failed to read file contents from {file_path:?}")
    }) {
      Ok(contents) => successful.push(StackRemoteFileContents {
        path: file.path,
        contents,
        services: file.services,
        requires: file.requires,
      }),
      Err(e) => errored.push(FileContents {
        path: file.path,
        contents: format_serror(&e.into()),
      }),
    }
  }

  let observed = git::get_commit_info(repo_path)
    .await
    .context("Failed to verify stack repository revision")?;
  ensure!(
    observed.id == revision.id,
    "Stack repository revision changed while reading source files"
  );

  Ok(RemoteComposeContents {
    successful,
    errored,
    revision: Some(revision),
  })
}

/// Returns (destination, logs, hash, message)
pub async fn ensure_remote_repo(
  mut clone_args: RepoExecutionArgs,
) -> anyhow::Result<(PathBuf, Vec<Log>, Option<String>, Option<String>)>
{
  let config = core_config();

  let access_token = if let Some(username) = &clone_args.account {
    git_token(&clone_args.provider, username, |https| {
        clone_args.https = https
      })
      .await
      .with_context(
        || format!("Failed to get git token in call to db. Stopping run. | {} | {username}", clone_args.provider),
      )?
  } else {
    None
  };

  let repo_path =
    clone_args.unique_path(&core_config().repo_directory)?;
  clone_args.destination = Some(repo_path.display().to_string());

  git::pull_or_clone(clone_args, &config.repo_directory, access_token)
    .await
    .context("Failed to clone stack repo")
    .map(|(res, _)| {
      (repo_path, res.logs, res.commit_hash, res.commit_message)
    })
}

#[cfg(test)]
mod tests {
  use std::process::Command;

  use super::*;

  struct Repository(PathBuf);

  impl Repository {
    fn new() -> Self {
      let repo = Self(std::env::temp_dir().join(format!(
        "komodo-core-compose-revision-{}",
        uuid::Uuid::new_v4()
      )));
      fs::create_dir(&repo.0).unwrap();
      repo.git(&["init"]);
      repo
    }

    fn git(&self, args: &[&str]) -> String {
      let output = Command::new("git")
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
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .current_dir(&self.0)
        .output()
        .unwrap();
      assert!(output.status.success(), "Fixture Git command failed");
      String::from_utf8(output.stdout).unwrap().trim().into()
    }

    fn commit(&self, image: &str, message: &str) -> String {
      fs::create_dir_all(self.0.join("stack")).unwrap();
      fs::write(
        self.0.join("stack/compose.yaml"),
        format!("services:\n  app:\n    image: {image}\n"),
      )
      .unwrap();
      self.git(&["add", "stack/compose.yaml"]);
      self.git(&["commit", "-m", message]);
      self.git(&["rev-parse", "HEAD"])
    }
  }

  impl Drop for Repository {
    fn drop(&mut self) {
      fs::remove_dir_all(&self.0).unwrap();
    }
  }

  #[tokio::test]
  async fn compose_include_remote_contents_selects_full_head_not_configured_short_hash()
  -> anyhow::Result<()> {
    let repo = Repository::new();
    let selected = repo.commit("fixture:first", "first");
    let latest = repo.commit("fixture:second", "second");
    let mut stack = Stack::default();
    stack.config.run_directory = "stack".into();
    stack.config.file_paths = vec!["compose.yaml".into()];
    stack.config.commit = selected[..7].into();
    let mut missing = Vec::new();

    let latest_contents = read_repo_compose_contents(
      &repo.0,
      &stack,
      Some(&mut missing),
      |path| fs::read_to_string(path),
    )
    .await?;
    let revision = latest_contents.revision.as_ref().unwrap();
    assert_eq!(revision.id, latest);
    assert_eq!(revision.display.message, "second");
    assert!(
      latest_contents.successful[0]
        .contents
        .contains("fixture:second")
    );
    assert!(latest_contents.errored.is_empty());
    assert!(missing.is_empty());
    assert_eq!(stack.config.file_paths, ["compose.yaml"]);

    repo.git(&["checkout", "--detach", &selected]);
    let selected_contents =
      read_repo_compose_contents(&repo.0, &stack, None, |path| {
        fs::read_to_string(path)
      })
      .await?;
    let revision = selected_contents.revision.as_ref().unwrap();
    assert_eq!(revision.id, selected);
    assert_eq!(
      revision.display.hash,
      repo.git(&["rev-parse", "--short", "HEAD"])
    );
    assert_eq!(revision.display.message, "first");
    assert!(
      selected_contents.successful[0]
        .contents
        .contains("fixture:first")
    );
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_remote_contents_preserves_missing_files_and_rejects_unborn_head()
  -> anyhow::Result<()> {
    let repo = Repository::new();
    let mut stack = Stack::default();
    stack.config.run_directory = "stack".into();
    stack.config.file_paths =
      vec!["compose.yaml".into(), "missing.yaml".into()];
    assert!(
      read_repo_compose_contents(&repo.0, &stack, None, |path| {
        fs::read_to_string(path)
      })
      .await
      .is_err()
    );
    let selected = repo.commit("fixture:first", "first");
    let mut missing = Vec::new();
    let contents = read_repo_compose_contents(
      &repo.0,
      &stack,
      Some(&mut missing),
      |path| fs::read_to_string(path),
    )
    .await?;
    assert_eq!(contents.revision.as_ref().unwrap().id, selected);
    assert_eq!(contents.successful.len(), 1);
    assert_eq!(contents.errored.len(), 1);
    assert_eq!(contents.errored[0].path, "missing.yaml");
    assert_eq!(missing, ["missing.yaml"]);
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_remote_contents_rejects_revision_change_during_read()
  -> anyhow::Result<()> {
    let repo = Repository::new();
    let selected = repo.commit("fixture:first", "first");
    let latest = repo.commit("fixture:second", "second");
    repo.git(&["checkout", "--detach", &selected]);
    let mut stack = Stack::default();
    stack.config.run_directory = "stack".into();
    stack.config.file_paths = vec!["compose.yaml".into()];
    let result =
      read_repo_compose_contents(&repo.0, &stack, None, |path| {
        let contents = fs::read_to_string(path)?;
        assert!(contents.contains("fixture:first"));
        repo.git(&["checkout", "--detach", &latest]);
        Ok(contents)
      })
      .await;
    let error = result.err().expect("Mixed revisions must fail");
    assert!(
      error
        .to_string()
        .contains("revision changed while reading source files")
    );
    Ok(())
  }
}
