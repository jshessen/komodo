use std::{path::Path, time::Duration};

use anyhow::anyhow;
use command::{CommandOptions, run_standard_command};
use formatting::{bold, muted};
use komodo_client::entities::{
  LatestCommit, komodo_timestamp, update::Log,
};

mod clone;
mod commit;
#[cfg(unix)]
pub mod discovery;
mod init;
mod installed;
mod pull;
mod pull_or_clone;

pub use crate::{
  clone::clone,
  commit::{commit_all, commit_file, write_commit_file},
  init::init_folder_as_repo,
  installed::check_installed,
  pull::pull,
  pull_or_clone::pull_or_clone,
};

const COMMIT_INFO_COMMAND: &str =
  "git log -1 --no-show-signature --format=%H%x00%h%x00%B HEAD --";

pub struct CommitInfo {
  /// Full immutable object ID, separate from the abbreviated display hash.
  pub id: String,
  pub display: LatestCommit,
}

pub async fn get_commit_hash_info(
  repo_dir: &Path,
) -> anyhow::Result<LatestCommit> {
  Ok(get_commit_info(repo_dir).await?.display)
}

/// Read full ID, display hash, and message from one selected commit.
pub async fn get_commit_info(
  repo_dir: &Path,
) -> anyhow::Result<CommitInfo> {
  get_commit_info_with_options(
    repo_dir,
    CommandOptions::default().timeout(Duration::from_secs(2)),
  )
  .await
}

pub async fn get_commit_info_with_options(
  repo_dir: &Path,
  options: CommandOptions<'_>,
) -> anyhow::Result<CommitInfo> {
  let output =
    run_standard_command(COMMIT_INFO_COMMAND, options.path(repo_dir))
      .await;
  if !output.success() {
    return Err(anyhow!("Failed to get Git commit info"));
  }
  let fields = output.stdout.splitn(3, '\0').collect::<Vec<_>>();
  let [id, hash, message] = fields.as_slice() else {
    return Err(anyhow!("Invalid Git commit info"));
  };
  if !full_commit_id(id) || hash.is_empty() || !id.starts_with(*hash)
  {
    return Err(anyhow!("Invalid Git commit identity"));
  }
  Ok(CommitInfo {
    id: (*id).into(),
    display: LatestCommit {
      hash: (*hash).into(),
      message: message.trim().into(),
    },
  })
}

fn full_commit_id(id: &str) -> bool {
  matches!(id.len(), 40 | 64)
    && id
      .bytes()
      .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
/// returns (Log, commit hash, commit message)
pub async fn get_commit_hash_log(
  repo_dir: &Path,
) -> anyhow::Result<(Log, String, String)> {
  let start_ts = komodo_timestamp();
  let LatestCommit { hash, message } =
    get_commit_hash_info(repo_dir).await?;
  let log = Log {
    stage: "Latest Commit".into(),
    command: COMMIT_INFO_COMMAND.into(),
    stdout: format!(
      "{} {}\n{} {}",
      muted("hash:"),
      bold(&hash),
      muted("message:"),
      bold(&message),
    ),
    stderr: String::new(),
    success: true,
    start_ts,
    end_ts: komodo_timestamp(),
  };
  Ok((log, hash, message))
}

/// Gets the remote url, with `.git` stripped from the end.
pub async fn get_remote_url(path: &Path) -> anyhow::Result<String> {
  check_installed().await?;
  let output = run_standard_command(
    "git remote show origin",
    CommandOptions::default()
      .path(path)
      .timeout(Duration::from_secs(2)),
  )
  .await;
  if output.success() {
    Ok(
      output
        .stdout
        .trim()
        .strip_suffix(".git")
        .map(str::to_string)
        .unwrap_or(output.stdout),
    )
  } else {
    Err(anyhow!(
      "Failed to get remote url | stdout: {} | stderr: {}",
      output.stdout,
      output.stderr
    ))
  }
}

#[cfg(test)]
mod tests {
  use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::SystemTime,
  };

  use super::*;

  pub(crate) struct Repository(pub(crate) PathBuf);

  impl Repository {
    pub(crate) fn new(format: &str) -> Self {
      static NEXT: AtomicU64 = AtomicU64::new(0);
      let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
      let path = std::env::temp_dir().join(format!(
        "komodo-git-revision-{}-{nonce}-{format}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
      ));
      fs::create_dir(&path).unwrap();
      let repo = Self(path);
      repo.git(&["init", &format!("--object-format={format}")]);
      repo
    }

    pub(crate) fn git(&self, args: &[&str]) -> String {
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
      assert!(
        output.status.success(),
        "Fixture Git command failed at {:?}: {:?}: {}",
        self.0,
        args,
        String::from_utf8_lossy(&output.stderr)
      );
      String::from_utf8(output.stdout).unwrap().trim().into()
    }

    pub(crate) fn commit(
      &self,
      image: &str,
      message: &str,
    ) -> String {
      fs::write(
        self.0.join("compose.yaml"),
        format!("services:\n  app:\n    image: {image}\n"),
      )
      .unwrap();
      self.git(&["add", "compose.yaml"]);
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
  async fn compose_include_revision_keeps_full_id_separate_from_display()
  -> anyhow::Result<()> {
    for (format, length) in [("sha1", 40), ("sha256", 64)] {
      let repo = Repository::new(format);
      let expected = repo.commit("fixture:first", "first\n\nbody");
      let info = get_commit_info(&repo.0).await?;
      assert_eq!(info.id, expected);
      assert_eq!(info.id.len(), length);
      assert_eq!(
        info.display.hash,
        repo.git(&["rev-parse", "--short", "HEAD"])
      );
      assert_eq!(info.display.message, "first\n\nbody");
      let legacy = get_commit_hash_info(&repo.0).await?;
      assert_eq!(legacy.hash, info.display.hash);
      assert_eq!(legacy.message, info.display.message);
    }
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_revision_observes_detached_selected_commit()
  -> anyhow::Result<()> {
    let repo = Repository::new("sha1");
    let selected = repo.commit("fixture:first", "first");
    let latest = repo.commit("fixture:second", "second");
    assert_eq!(get_commit_info(&repo.0).await?.id, latest);
    repo.git(&["checkout", "--detach", &selected]);
    let info = get_commit_info(&repo.0).await?;
    assert_eq!(info.id, selected);
    assert_eq!(info.display.message, "first");
    assert_eq!(
      info.display.hash,
      repo.git(&["rev-parse", "--short", &selected])
    );
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_revision_rejects_unborn_head() {
    let repo = Repository::new("sha1");
    assert!(get_commit_info(&repo.0).await.is_err());
  }
}
