use std::{
  collections::BTreeMap,
  fs,
  os::unix::fs::DirBuilderExt,
  path::{Path, PathBuf},
  sync::atomic::{AtomicU64, Ordering},
  time::{Instant, SystemTime},
};

use command::{CommandOptions, run_standard_command};
use komodo_client::entities::RepoExecutionArgs;

use crate::{
  CommitInfo, full_commit_id, get_commit_info_with_options,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryError {
  InvalidIdentity,
  SourceAccess,
  SourceChanged,
  Timeout,
  Cancelled,
}

impl std::fmt::Display for DiscoveryError {
  fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    f.write_str(match self {
      Self::InvalidIdentity => "Invalid Git discovery revision",
      Self::SourceAccess => "Cannot prepare Git discovery sources",
      Self::SourceChanged => "Git discovery revision changed",
      Self::Timeout => "Git discovery timed out",
      Self::Cancelled => "Git discovery cancelled",
    })
  }
}

impl std::error::Error for DiscoveryError {}

/// Operation-owned checkout. Never uses the active Stack or Repo destination.
/// Credentials stay in scoped child environment, not argv or repository config.
pub struct DiscoveryCheckout {
  path: PathBuf,
  commit_id: String,
  environment: BTreeMap<String, String>,
  options: CommandOptions<'static>,
  deadline: Instant,
}

impl DiscoveryCheckout {
  /// The earlier of `deadline` and `options.timeout` bounds the entire checkout,
  /// including later verification. Cancellation also cleans up a dropped preparation.
  pub async fn prepare(
    args: &RepoExecutionArgs,
    access_token: Option<&str>,
    commit_id: &str,
    deadline: Instant,
    options: CommandOptions<'_>,
  ) -> Result<Self, DiscoveryError> {
    let remote = args
      .remote_url(access_token)
      .map_err(|_| DiscoveryError::SourceAccess)?;
    Self::prepare_remote(remote, commit_id, deadline, options).await
  }

  async fn prepare_remote(
    remote: String,
    commit_id: &str,
    deadline: Instant,
    options: CommandOptions<'_>,
  ) -> Result<Self, DiscoveryError> {
    let checkout = Self::new(remote, commit_id, deadline, options)?;
    checkout.prepare_supervised().await
  }

  async fn prepare_supervised(
    mut self,
  ) -> Result<Self, DiscoveryError> {
    let cancel = self
      .options
      .cancel
      .get_or_insert_with(Default::default)
      .clone();
    let cancel_on_drop = cancel.drop_guard();
    // Retain command supervision until cancellation has cleaned up Git descendants.
    let result = tokio::spawn(async move {
      self.initialize().await?;
      Ok(self)
    })
    .await
    .map_err(|_| DiscoveryError::SourceAccess)?;
    if result.is_ok() {
      cancel_on_drop.disarm();
    }
    result
  }

  fn new(
    remote: String,
    commit_id: &str,
    deadline: Instant,
    options: CommandOptions<'_>,
  ) -> Result<Self, DiscoveryError> {
    if !full_commit_id(commit_id) {
      return Err(DiscoveryError::InvalidIdentity);
    }
    let deadline = options
      .timeout
      .and_then(|timeout| Instant::now().checked_add(timeout))
      .map_or(deadline, |timeout| deadline.min(timeout));
    active(deadline, &options)?;
    let mut environment = options.env.cloned().unwrap_or_default();
    let path = create_directory()?;
    let mut checkout = Self {
      path,
      commit_id: commit_id.into(),
      environment: BTreeMap::new(),
      options: CommandOptions {
        cancel: options.cancel,
        output_limit: Some(64 * 1024),
        ..Default::default()
      },
      deadline,
    };
    let root =
      checkout.path.to_str().ok_or(DiscoveryError::SourceAccess)?;
    // Override inherited Git context so commands cannot select an active checkout.
    for (key, value) in [
      ("GIT_DIR", format!("{root}/.git")),
      ("GIT_WORK_TREE", root.into()),
      ("GIT_COMMON_DIR", format!("{root}/.git")),
      ("GIT_INDEX_FILE", format!("{root}/.git/index")),
      ("GIT_SHALLOW_FILE", format!("{root}/.git/shallow")),
      ("GIT_OBJECT_DIRECTORY", format!("{root}/.git/objects")),
      ("GIT_ALTERNATE_OBJECT_DIRECTORIES", String::new()),
      ("GIT_NAMESPACE", String::new()),
      ("GIT_CONFIG_NOSYSTEM", "1".into()),
      ("GIT_CONFIG_GLOBAL", "/dev/null".into()),
      ("GIT_CONFIG_PARAMETERS", String::new()),
      ("GIT_CONFIG_COUNT", "1".into()),
      ("GIT_CONFIG_KEY_0", "remote.origin.url".into()),
      ("GIT_CONFIG_VALUE_0", remote),
      ("GIT_TERMINAL_PROMPT", "0".into()),
      ("GIT_ASKPASS", "/bin/false".into()),
      ("SSH_ASKPASS", "/bin/false".into()),
    ] {
      environment.insert(key.into(), value);
    }
    checkout.environment = environment;
    Ok(checkout)
  }

  async fn initialize(&self) -> Result<(), DiscoveryError> {
    let format = if self.commit_id.len() == 64 {
      "sha256"
    } else {
      "sha1"
    };
    self
      .run(&format!("init --template= --object-format={format}"))
      .await?;
    self
      .run(&format!(
        "fetch --no-auto-maintenance --no-write-fetch-head --no-tags --no-recurse-submodules origin {}",
        self.commit_id
      ))
      .await?;
    self
      .run(&format!("checkout --detach {} --", self.commit_id))
      .await?;
    self.verify().await?;
    Ok(())
  }

  pub fn path(&self) -> &Path {
    &self.path
  }

  /// Uses the original deadline and cancellation token; verification cannot reset them.
  pub async fn verify(&self) -> Result<CommitInfo, DiscoveryError> {
    let info = get_commit_info_with_options(
      &self.path,
      self.command_options()?,
    )
    .await;
    active(self.deadline, &self.options)?;
    let info = info.map_err(|_| DiscoveryError::SourceAccess)?;
    if info.id != self.commit_id {
      return Err(DiscoveryError::SourceChanged);
    }
    Ok(info)
  }

  async fn run(&self, arguments: &str) -> Result<(), DiscoveryError> {
    // No clone templates, Git hooks, credential helpers, filters from user config,
    // or recursive submodule commands belong in discovery.
    let command = format!(
      "git -c core.hooksPath=/dev/null -c credential.helper= -c submodule.recurse=false -c gc.auto=0 {arguments}"
    );
    let output =
      run_standard_command(&command, self.command_options()?).await;
    active(self.deadline, &self.options)?;
    if !output.success() {
      return Err(DiscoveryError::SourceAccess);
    }
    Ok(())
  }

  fn command_options(
    &self,
  ) -> Result<CommandOptions<'_>, DiscoveryError> {
    active(self.deadline, &self.options)?;
    let remaining =
      self.deadline.saturating_duration_since(Instant::now());
    Ok(CommandOptions {
      path: Some(&self.path),
      env: Some(&self.environment),
      timeout: Some(remaining),
      ..self.options.clone()
    })
  }

  pub fn close(mut self) -> Result<(), DiscoveryError> {
    fs::remove_dir_all(&self.path)
      .map_err(|_| DiscoveryError::SourceAccess)?;
    self.path = PathBuf::new();
    Ok(())
  }
}

impl Drop for DiscoveryCheckout {
  fn drop(&mut self) {
    if !self.path.as_os_str().is_empty()
      && let Err(error) = fs::remove_dir_all(&self.path)
      && error.kind() != std::io::ErrorKind::NotFound
    {
      eprintln!("Failed to remove private Git discovery checkout");
    }
  }
}

fn active(
  deadline: Instant,
  options: &CommandOptions<'_>,
) -> Result<(), DiscoveryError> {
  if options
    .cancel
    .as_ref()
    .is_some_and(|cancel| cancel.is_cancelled())
  {
    return Err(DiscoveryError::Cancelled);
  }
  if Instant::now() >= deadline {
    return Err(DiscoveryError::Timeout);
  }
  Ok(())
}

fn create_directory() -> Result<PathBuf, DiscoveryError> {
  static NEXT: AtomicU64 = AtomicU64::new(0);
  let timestamp = SystemTime::now()
    .duration_since(SystemTime::UNIX_EPOCH)
    .map_err(|_| DiscoveryError::SourceAccess)?
    .as_nanos();
  for _ in 0..16 {
    let path = std::env::temp_dir().join(format!(
      "komodo-git-discovery-{}-{timestamp}-{}",
      std::process::id(),
      NEXT.fetch_add(1, Ordering::Relaxed),
    ));
    match fs::DirBuilder::new().mode(0o700).create(&path) {
      Ok(()) => match fs::canonicalize(&path) {
        Ok(path) => return Ok(path),
        Err(_) => {
          if fs::remove_dir(&path).is_err() {
            eprintln!(
              "Failed to remove private Git discovery directory"
            );
          }
          return Err(DiscoveryError::SourceAccess);
        }
      },
      Err(error)
        if error.kind() == std::io::ErrorKind::AlreadyExists => {}
      Err(_) => return Err(DiscoveryError::SourceAccess),
    }
  }
  Err(DiscoveryError::SourceAccess)
}

#[cfg(test)]
mod tests {
  use std::{os::unix::fs::PermissionsExt, time::Duration};

  use super::*;
  use crate::tests::Repository;

  fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
  }

  #[tokio::test]
  async fn compose_include_discovery_pins_selected_revision_without_touching_source()
  -> anyhow::Result<()> {
    for format in ["sha1", "sha256"] {
      let repo = Repository::new(format);
      let selected = repo.commit("fixture:first", "selected");
      let latest = repo.commit("fixture:second", "latest");
      let hooks = repo.0.join(".git/discovery-hooks");
      fs::create_dir(&hooks)?;
      let marker = hooks.join("ran");
      fs::write(
        hooks.join("post-checkout"),
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
      )?;
      fs::set_permissions(
        hooks.join("post-checkout"),
        fs::Permissions::from_mode(0o700),
      )?;
      let global = repo.0.join(".git/discovery-global");
      repo.git(&[
        "config",
        "--file",
        global.to_str().unwrap(),
        "core.hooksPath",
        hooks.to_str().unwrap(),
      ]);
      let environment = BTreeMap::from([
        ("GIT_CONFIG_GLOBAL".into(), global.to_str().unwrap().into()),
        (
          "GIT_DIR".into(),
          repo.0.join(".git").to_str().unwrap().into(),
        ),
        ("GIT_WORK_TREE".into(), repo.0.to_str().unwrap().into()),
      ]);
      let checkout = DiscoveryCheckout::prepare_remote(
        format!("file://{}", repo.0.display()),
        &selected,
        deadline(),
        CommandOptions::default().env(&environment),
      )
      .await?;
      assert_ne!(checkout.path(), repo.0);
      assert_eq!(
        fs::metadata(checkout.path())?.permissions().mode() & 0o777,
        0o700
      );
      assert!(
        fs::read_to_string(checkout.path().join("compose.yaml"))?
          .contains("fixture:first")
      );
      let observed = checkout.verify().await?;
      assert_eq!(observed.id, selected);
      assert_eq!(observed.display.message, "selected");
      assert_eq!(repo.git(&["rev-parse", "HEAD"]), latest);
      assert!(repo.git(&["status", "--porcelain"]).is_empty());
      assert!(
        !marker.exists(),
        "Discovery must not run configured Git hooks"
      );
      assert!(
        !fs::read_to_string(checkout.path().join(".git/config"))?
          .contains("remote")
      );
      assert!(!checkout.path().join(".git/FETCH_HEAD").exists());
      let path = checkout.path().to_path_buf();
      checkout.close()?;
      assert!(!path.exists());
    }
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_discovery_rejects_changed_head_and_cleans_up()
  -> anyhow::Result<()> {
    let repo = Repository::new("sha1");
    let first = repo.commit("fixture:first", "first");
    let selected = repo.commit("fixture:second", "second");
    let checkout = DiscoveryCheckout::prepare_remote(
      format!("file://{}", repo.0.display()),
      &selected,
      deadline(),
      CommandOptions::default(),
    )
    .await?;
    checkout
      .run(&format!("checkout --detach {first} --"))
      .await?;
    assert_eq!(
      checkout.verify().await.err(),
      Some(DiscoveryError::SourceChanged)
    );
    let path = checkout.path().to_path_buf();
    drop(checkout);
    assert!(!path.exists());
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_discovery_failed_fetch_is_private_and_cleaned_up()
  -> anyhow::Result<()> {
    let repo = Repository::new("sha1");
    repo.commit("fixture:first", "first");
    let checkout = DiscoveryCheckout::new(
      format!("file://{}/missing-SYNTHETIC_TOKEN", repo.0.display()),
      &"a".repeat(40),
      deadline(),
      CommandOptions::default(),
    )?;
    let path = checkout.path().to_path_buf();
    let error =
      checkout.initialize().await.err().expect("Fetch must fail");
    assert_eq!(error, DiscoveryError::SourceAccess);
    assert!(!error.to_string().contains("SYNTHETIC_TOKEN"));
    drop(checkout);
    assert!(!path.exists());
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_discovery_shared_deadline_and_cancel_are_not_reset()
  -> anyhow::Result<()> {
    let repo = Repository::new("sha1");
    let selected = repo.commit("fixture:first", "first");
    let options =
      CommandOptions::default().timeout(Duration::from_secs(2));
    let checkout = DiscoveryCheckout::prepare_remote(
      format!("file://{}", repo.0.display()),
      &selected,
      deadline(),
      options,
    )
    .await?;
    tokio::time::sleep_until(
      tokio::time::Instant::from_std(checkout.deadline)
        + Duration::from_millis(20),
    )
    .await;
    assert_eq!(
      checkout.verify().await.err(),
      Some(DiscoveryError::Timeout)
    );
    assert_eq!(
      DiscoveryCheckout::new(
        "unused".into(),
        "short",
        deadline(),
        CommandOptions::default()
      )
      .err(),
      Some(DiscoveryError::InvalidIdentity),
    );
    let options = CommandOptions {
      cancel: Some(Default::default()),
      ..Default::default()
    };
    let cancel = options.cancel.clone().unwrap();
    let cancelled = DiscoveryCheckout::prepare_remote(
      format!("file://{}", repo.0.display()),
      &selected,
      deadline(),
      options,
    )
    .await?;
    cancel.cancel();
    assert_eq!(
      cancelled.verify().await.err(),
      Some(DiscoveryError::Cancelled)
    );
    let path = cancelled.path().to_path_buf();
    drop(cancelled);
    assert!(!path.exists());
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_discovery_dropped_preparation_cancels_fetch_and_removes_tree()
  -> anyhow::Result<()> {
    use std::sync::Arc;
    use tokio::{io::AsyncReadExt, net::TcpListener, sync::Notify};

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let started = Arc::new(Notify::new());
    let notification = started.clone();
    let closed = Arc::new(Notify::new());
    let connection_closed = closed.clone();
    let server = tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.unwrap();
      let mut byte = [0];
      stream.read_exact(&mut byte).await.unwrap();
      notification.notify_one();
      let mut buffer = [0; 1024];
      loop {
        match stream.read(&mut buffer).await {
          Ok(0) => break,
          Ok(_) => {}
          Err(error)
            if error.kind()
              == std::io::ErrorKind::ConnectionReset =>
          {
            break;
          }
          Err(error) => panic!("Fixture connection failed: {error}"),
        }
      }
      connection_closed.notify_one();
    });
    let environment = BTreeMap::from([
      ("NO_PROXY".into(), "127.0.0.1".into()),
      ("no_proxy".into(), "127.0.0.1".into()),
    ]);
    let checkout = DiscoveryCheckout::new(
      format!("http://{address}/fixture"),
      &"a".repeat(40),
      deadline(),
      CommandOptions::default().env(&environment),
    )?;
    let path = checkout.path().to_path_buf();
    let preparation = tokio::spawn(checkout.prepare_supervised());
    let reached_fetch = tokio::time::timeout(
      Duration::from_secs(5),
      started.notified(),
    )
    .await;
    preparation.abort();
    let _ = preparation.await;
    let fetch_stopped =
      tokio::time::timeout(Duration::from_secs(5), closed.notified())
        .await;
    let removed =
      tokio::time::timeout(Duration::from_secs(5), async {
        while path.exists() {
          tokio::time::sleep(Duration::from_millis(10)).await;
        }
      })
      .await;
    server.abort();
    let _ = server.await;
    reached_fetch?;
    fetch_stopped?;
    removed?;
    Ok(())
  }
}
