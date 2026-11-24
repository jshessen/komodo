use std::{collections::BTreeMap, path::Path, time::Duration};

use tokio_util::sync::CancellationToken;

/// Controls for how a command is executed.
///
/// Timeout, cancellation, or an output limit creates an owned process group,
/// unless explicitly inheriting a supervised parent's group. Controls kill
/// the owned group, not just the direct child. Dropping an in-flight
/// controlled command also kills its owned group.
#[derive(Default, Clone)]
pub struct CommandOptions<'a> {
  /// Run the command at a particular path
  pub path: Option<&'a Path>,
  /// Kill the command (and its process group) if this duration elapses
  /// before it finishes.
  pub timeout: Option<Duration>,
  /// Kill the command (and its process group) when this token is
  /// cancelled, allowing cancellation from elsewhere.
  pub cancel: Option<CancellationToken>,
  /// Write this to the command's standard input. Without it,
  /// the command gets no input at all.
  ///
  /// Use this to hand a secret to a command which reads it from stdin,
  /// such as `docker login --password-stdin`. Unlike interpolating the
  /// secret into the command, it never appears in the process arguments,
  /// where any user on the host could read it out of `ps`.
  pub stdin: Option<&'a str>,
  /// Set these variables in this child; inherit others unless cleared.
  pub env: Option<&'a BTreeMap<String, String>>,
  /// Do not inherit the parent environment.
  pub clear_env: bool,
  /// Maximum bytes captured from each output stream. Exceeding it fails
  /// without returning truncated output. Owned groups are cleaned up on
  /// completion, including success, to stop residual descendants.
  /// Bounded text capture rejects invalid UTF-8 instead of substituting it.
  pub output_limit: Option<usize>,
  /// For a nested worker whose parent supervises the whole process group.
  /// Cannot be combined with this command's own timeout or cancellation.
  /// The parent must clean up descendants when this nested command fails.
  pub inherit_process_group: bool,
}

impl<'a> CommandOptions<'a> {
  pub fn path(mut self, path: impl Into<Option<&'a Path>>) -> Self {
    self.path = path.into();
    self
  }

  pub fn stdin(mut self, stdin: impl Into<Option<&'a str>>) -> Self {
    self.stdin = stdin.into();
    self
  }

  pub fn env(
    mut self,
    env: impl Into<Option<&'a BTreeMap<String, String>>>,
  ) -> Self {
    self.env = env.into();
    self
  }

  pub fn clear_env(mut self, clear: bool) -> Self {
    self.clear_env = clear;
    self
  }
}

impl CommandOptions<'_> {
  pub fn inherit_process_group(mut self, inherit: bool) -> Self {
    self.inherit_process_group = inherit;
    self
  }

  pub fn output_limit(
    mut self,
    output_limit: impl Into<Option<usize>>,
  ) -> Self {
    self.output_limit = output_limit.into();
    self
  }

  pub fn timeout(
    mut self,
    timeout: impl Into<Option<Duration>>,
  ) -> Self {
    self.timeout = timeout.into();
    self
  }

  pub fn cancel(
    mut self,
    cancel: impl Into<Option<CancellationToken>>,
  ) -> Self {
    self.cancel = cancel.into();
    self
  }
}
