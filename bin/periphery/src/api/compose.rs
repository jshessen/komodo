use std::{
  borrow::Cow, path::PathBuf, sync::LazyLock, time::Duration,
};

use anyhow::{Context, anyhow};
use command::{
  CommandOptions, KomodoCommandMode,
  run_komodo_command_with_sanitization, run_komodo_shell_command,
  run_komodo_standard_command,
};
use formatting::format_serror;
use git::write_commit_file;
use interpolate::Interpolator;
use komodo_client::{
  entities::{
    FileContents, RepoExecutionResponse, all_logs_success,
    stack::StackRemoteFileContents, to_path_compatible_name,
    update::Log,
  },
  parsers::parse_multiline_command,
};
use mogh_resolver::Resolve;
use periphery_client::api::{DeployStackResponse, compose::*};
use shell_escape::unix::escape;
use tracing::Instrument;

use crate::{
  config::periphery_config,
  docker::compose::{
    ConfigFormat, compose_command, config_command, docker_compose,
    ordered_env_files, parse_compose_services,
  },
  helpers::{format_extra_args, format_log_grep},
  stack::{
    maybe_login_registry, pull_or_clone_stack, validate_files,
    write::write_stack,
  },
};

impl Resolve<crate::api::Args> for GetComposeLog {
  async fn resolve(
    self,
    _: &crate::api::Args,
  ) -> anyhow::Result<Log> {
    let GetComposeLog {
      project,
      services,
      tail,
      timestamps,
    } = self;
    let docker_compose = docker_compose();
    let timestamps = if timestamps {
      " --timestamps"
    } else {
      Default::default()
    };
    let command = format!(
      "{docker_compose} -p {project} logs --tail {tail}{timestamps} -- {}",
      services.join(" ")
    );
    Ok(
      run_komodo_standard_command(
        "Get Stack Log",
        command,
        CommandOptions::default().timeout(Duration::from_secs(10)),
      )
      .await,
    )
  }
}

impl Resolve<crate::api::Args> for GetComposeLogSearch {
  async fn resolve(
    self,
    _: &crate::api::Args,
  ) -> anyhow::Result<Log> {
    let GetComposeLogSearch {
      project,
      services,
      terms,
      combinator,
      invert,
      timestamps,
    } = self;
    let docker_compose = docker_compose();
    let grep = format_log_grep(&terms, combinator, invert);
    let timestamps = if timestamps {
      " --timestamps"
    } else {
      Default::default()
    };
    let command = format!(
      "{docker_compose} -p {} logs --tail 5000{timestamps} -- {} 2>&1 | {grep}",
      escape(project.into()),
      services
        .iter()
        .map(|service| escape(service.into()))
        .collect::<Vec<_>>()
        .join(" ")
    );
    Ok(
      run_komodo_shell_command(
        "Search Stack Log",
        command,
        CommandOptions::default().timeout(Duration::from_secs(10)),
      )
      .await,
    )
  }
}

//

impl Resolve<crate::api::Args> for GetComposeContentsOnHost {
  async fn resolve(
    self,
    _: &crate::api::Args,
  ) -> anyhow::Result<GetComposeContentsOnHostResponse> {
    let GetComposeContentsOnHost {
      name,
      run_directory,
      file_paths,
    } = self;
    let root = periphery_config()
      .stack_dir()
      .join(to_path_compatible_name(&name));
    let run_directory =
      root.join(&run_directory).components().collect::<PathBuf>();

    let mut res = GetComposeContentsOnHostResponse::default();

    for file in file_paths {
      let full_path = run_directory
        .join(&file.path)
        .components()
        .collect::<PathBuf>();
      match tokio::fs::read_to_string(&full_path).await.with_context(
        || {
          format!(
            "Failed to read compose file contents at {full_path:?}"
          )
        },
      ) {
        Ok(contents) => {
          // The path we store here has to be the same as incoming file path in the array,
          // in order for WriteComposeContentsToHost to write to the correct path.
          res.contents.push(StackRemoteFileContents {
            path: file.path,
            contents,
            services: file.services,
            requires: file.requires,
          });
        }
        Err(e) => {
          res.errors.push(FileContents {
            path: file.path,
            contents: format_serror(&e.into()),
          });
        }
      }
    }

    Ok(res)
  }
}

//

impl Resolve<crate::api::Args> for WriteComposeContentsToHost {
  #[instrument(
    "WriteComposeContentsToHost",
    skip_all,
    fields(
      id = args.id.to_string(),
      core = args.core,
      stack = self.name,
      run_directory = self.run_directory,
      file_path = self.file_path,
    )
  )]
  async fn resolve(
    self,
    args: &crate::api::Args,
  ) -> anyhow::Result<Log> {
    let WriteComposeContentsToHost {
      name,
      run_directory,
      file_path,
      contents,
    } = self;
    let file_path = periphery_config()
      .stack_dir()
      .join(to_path_compatible_name(&name))
      .join(&run_directory)
      .join(file_path)
      .components()
      .collect::<PathBuf>();
    mogh_secret_file::write_async(&file_path, contents)
      .await
      .with_context(|| {
        format!(
          "Failed to write compose file contents to {file_path:?}"
        )
      })?;
    Ok(Log::simple(
      "Write contents to host",
      format!("File contents written to {file_path:?}"),
    ))
  }
}

//

impl Resolve<crate::api::Args> for WriteCommitComposeContents {
  #[instrument(
    "WriteCommitComposeContents",
    skip_all,
    fields(
      id = args.id.to_string(),
      core = args.core,
      stack = &self.stack.name,
      username = &self.username,
      file_path = &self.file_path,
    )
  )]
  async fn resolve(
    self,
    args: &crate::api::Args,
  ) -> anyhow::Result<RepoExecutionResponse> {
    let WriteCommitComposeContents {
      stack,
      repo,
      username,
      file_path,
      contents,
      git_token,
    } = self;

    let root =
      pull_or_clone_stack(&stack, repo.as_ref(), git_token, args)
        .await?;

    let file_path = stack
      .config
      .run_directory
      .parse::<PathBuf>()
      .context("Run directory is not a valid path")?
      .join(&file_path);

    let msg = if let Some(username) = username {
      format!("{username}: Write Compose File")
    } else {
      "Write Compose File".to_string()
    };

    write_commit_file(
      &msg,
      &root,
      &file_path,
      &contents,
      &stack.config.branch,
    )
    .await
  }
}

//

impl Resolve<crate::api::Args> for ComposePull {
  #[instrument(
    "ComposePull",
    skip_all,
    fields(
      id = args.id.to_string(),
      core = args.core,
      stack = &self.stack.name,
      services = format!("{:?}", self.services),
    )
  )]
  async fn resolve(
    self,
    args: &crate::api::Args,
  ) -> anyhow::Result<ComposePullResponse> {
    let ComposePull {
      mut stack,
      repo,
      services,
      git_token,
      registry_token,
      mut replacers,
    } = self;

    let mut res = ComposePullResponse::default();

    let mut interpolator =
      Interpolator::new(None, &periphery_config().secrets);
    // Only interpolate Stack. Repo interpolation will be handled
    // by the CloneRepo / PullOrCloneRepo call.
    interpolator
      .interpolate_stack(&mut stack)?
      .push_logs(&mut res.logs);
    replacers.extend(interpolator.secret_replacers);

    let (run_directory, env_file_path) = match write_stack(
      &stack,
      repo.as_ref(),
      git_token,
      replacers.clone(),
      &mut res,
      args,
    )
    .await
    {
      Ok(res) => res,
      Err(e) => {
        res
          .logs
          .push(Log::error("Write Stack", format_serror(&e.into())));
        return Ok(res);
      }
    };

    // Canonicalize the path to ensure it exists, and is the cleanest path to the run directory.
    let run_directory = run_directory.canonicalize().with_context(||
      format!("Failed to validate run directory on host after stack write (canonicalize error), path={}", run_directory.to_string_lossy()),
    )?;

    let file_paths = stack
      .all_tracked_file_paths()
      .into_iter()
      .map(|path| {
        (
          // This will remove any intermediate uneeded '/./' in the path
          run_directory.join(&path).components().collect::<PathBuf>(),
          path,
        )
      })
      .collect::<Vec<_>>();

    // Validate files
    for (full_path, path) in &file_paths {
      if !full_path.exists() {
        return Err(anyhow!("Missing compose file at {path}"));
      }
    }

    maybe_login_registry(&stack, registry_token, &mut res.logs).await;
    if !all_logs_success(&res.logs) {
      return Ok(res);
    }

    let docker_compose = docker_compose();

    let service_args = if services.is_empty() {
      String::new()
    } else {
      // `--` so a service beginning with `-` is not parsed as a flag.
      format!(" -- {}", services.join(" "))
    };

    let env_files = ordered_env_files(
      env_file_path,
      &stack.config.additional_env_files,
    );

    let project_name = stack.project_name(false);
    let compose_command = compose_command(
      docker_compose,
      &project_name,
      stack.compose_file_paths(),
      &env_files,
    );

    // Parse wrapper configuration
    let compose_cmd_wrapper =
      parse_multiline_command(&stack.config.compose_cmd_wrapper);
    // If wrapper_include is empty but wrapper is set, use default ["up"] for backward compatibility
    let default_include = vec![String::from("up")];
    let wrapper_include =
      if stack.config.compose_cmd_wrapper_include.is_empty()
        && !compose_cmd_wrapper.is_empty()
      {
        &default_include
      } else {
        &stack.config.compose_cmd_wrapper_include
      };

    let pull_command =
      format!("{compose_command} pull{service_args}");
    let (pull_command, wrapped) = match maybe_wrap_command(
      pull_command,
      &compose_cmd_wrapper,
      wrapper_include,
      "pull",
    ) {
      Ok(result) => result,
      Err(log) => {
        res.logs.push(log);
        return Ok(res);
      }
    };

    let span = info_span!("RunComposePull");
    let mode = if wrapped {
      KomodoCommandMode::Shell
    } else {
      KomodoCommandMode::Standard
    };
    let Some(log) = run_komodo_command_with_sanitization(
      "Compose Pull",
      pull_command,
      CommandOptions::default().path(run_directory.as_path()),
      mode,
      &replacers,
    )
    .instrument(span)
    .await
    else {
      // Only reachable if command is empty,
      // not the case since it is provided above.
      unreachable!()
    };

    res.logs.push(log);

    Ok(res)
  }
}

//

impl Resolve<crate::api::Args> for ComposeUp {
  #[instrument(
    "ComposeUp",
    skip_all,
    fields(
      id = args.id.to_string(),
      core = args.core,
      stack = self.stack.name,
      repo = self.repo.as_ref().map(|repo| &repo.name),
      services = format!("{:?}", self.services),
    )
  )]
  async fn resolve(
    self,
    args: &crate::api::Args,
  ) -> anyhow::Result<DeployStackResponse> {
    let ComposeUp {
      mut stack,
      repo,
      services,
      git_token,
      registry_token,
      mut replacers,
      expected_resolution,
      supports_deployment_proof,
    } = self;
    #[cfg(not(target_os = "linux"))]
    let _ = supports_deployment_proof;

    let mut res = DeployStackResponse::default();

    let mut interpolator =
      Interpolator::new(None, &periphery_config().secrets);
    // Only interpolate Stack. Repo interpolation will be handled
    // by the CloneRepo / PullOrCloneRepo call.
    interpolator
      .interpolate_stack(&mut stack)?
      .push_logs(&mut res.logs);
    replacers.extend(interpolator.secret_replacers);

    let (run_directory, env_file_path) = match write_stack(
      &stack,
      repo.as_ref(),
      git_token,
      replacers.clone(),
      &mut res,
      args,
    )
    .await
    {
      Ok(res) => res,
      Err(e) => {
        res
          .logs
          .push(Log::error("Write Stack", format_serror(&e.into())));
        return Ok(res);
      }
    };

    // Canonicalize the path to ensure it exists, and is the cleanest path to the run directory.
    let run_directory = run_directory.canonicalize().with_context(||
      format!("Failed to validate run directory on host after stack write (canonicalize error), path={}", run_directory.to_string_lossy()),
    )?;

    validate_files(&stack, &run_directory, &mut res).await;
    if !all_logs_success(&res.logs) {
      return Ok(res);
    }

    maybe_login_registry(&stack, registry_token, &mut res.logs).await;
    if !all_logs_success(&res.logs) {
      return Ok(res);
    }

    // Pre deploy
    if !stack.config.pre_deploy.is_none() {
      let pre_deploy_path =
        run_directory.join(&stack.config.pre_deploy.path);
      let span = info_span!("ExecutePreDeploy");
      if let Some(log) = run_komodo_command_with_sanitization(
        "Pre Deploy",
        &stack.config.pre_deploy.command,
        CommandOptions::default().path(pre_deploy_path.as_path()),
        if stack.config.pre_deploy.shell_mode {
          KomodoCommandMode::Shell
        } else {
          KomodoCommandMode::Multiline
        },
        &replacers,
      )
      .instrument(span)
      .await
      {
        res.logs.push(log);
        if !all_logs_success(&res.logs) {
          return Ok(res);
        }
      };
    }

    let docker_compose = docker_compose();

    let service_args = if services.is_empty() {
      String::new()
    } else {
      // `--` so a service beginning with `-` is not parsed as a flag.
      format!(" -- {}", services.join(" "))
    };

    // This will be the last project name, which is the one that needs to be destroyed.
    // Might be different from the current project name, if user renames stack / changes to custom project name.
    let last_project_name = stack.project_name(false);
    let project_name = stack.project_name(true);

    let env_files = ordered_env_files(
      env_file_path,
      &stack.config.additional_env_files,
    );
    // Parse wrapper configuration once for reuse
    let compose_cmd_wrapper =
      parse_multiline_command(&stack.config.compose_cmd_wrapper);
    // If wrapper_include is empty but wrapper is set, use default ["up"] for backward compatibility
    let default_include = vec![String::from("up")];
    let wrapper_include =
      if stack.config.compose_cmd_wrapper_include.is_empty()
        && !compose_cmd_wrapper.is_empty()
      {
        &default_include
      } else {
        &stack.config.compose_cmd_wrapper_include
      };

    #[cfg(target_os = "linux")]
    let verifiable = expected_resolution.as_ref().filter(|_| {
      services.is_empty()
        && stack.config.compose_cmd_wrapper.trim().is_empty()
    });
    #[cfg(target_os = "linux")]
    let mut capture = if let Some(expected) =
      verifiable.filter(|_| {
        supports_deployment_proof
          && !stack.config.run_build
          && stack.config.extra_args.is_empty()
          && stack.config.post_deploy.is_none()
      }) {
      match deployment_revision(&stack, &run_directory, expected)
        .await
      {
        Some(revision) => {
          match crate::stack::resolve::capture_current_deployment(
            &stack,
            &run_directory,
            &env_files,
            expected,
            &replacers,
            revision.as_deref(),
          ) {
            Ok(capture) => capture.map(std::sync::Arc::new),
            Err(error) => {
              warn!(%error, "Unable to capture Compose sources");
              None
            }
          }
        }
        None => None,
      }
    } else {
      None
    };
    #[cfg(target_os = "linux")]
    if let Some(candidate) = &capture
      && !captured_model_matches(
        docker_compose,
        &project_name,
        stack.compose_file_paths(),
        &env_files,
        &run_directory,
        candidate.clone(),
      )
      .await
    {
      warn!(
        "Captured Compose model did not match the original model"
      );
      capture = None;
    }
    #[cfg(target_os = "linux")]
    let captured_arguments = capture.as_ref().map(|capture| {
      (
        format!(
          "{docker_compose} --project-directory {}",
          escape(capture.compose.project_directory.to_string_lossy())
        ),
        capture
          .compose
          .roots
          .iter()
          .map(|path| path.to_string_lossy().into_owned())
          .collect::<Vec<_>>(),
        capture
          .compose
          .env_files
          .iter()
          .map(|path| path.to_string_lossy().into_owned())
          .collect::<Vec<_>>(),
      )
    });
    #[cfg(not(target_os = "linux"))]
    let captured_arguments: Option<(
      String,
      Vec<String>,
      Vec<String>,
    )> = None;
    let (compose_cli, compose_roots, compose_env_files) =
      captured_arguments
        .as_ref()
        .map(|(cli, roots, env)| {
          (cli.as_str(), roots.as_slice(), env.as_slice())
        })
        .unwrap_or((
          docker_compose,
          stack.compose_file_paths(),
          &env_files,
        ));
    let compose_command = compose_command(
      compose_cli,
      &project_name,
      compose_roots,
      compose_env_files,
    );

    // Uses 'docker compose config' command to extract services (including image)
    // after performing interpolation
    {
      let command = config_command(
        compose_cli,
        &project_name,
        compose_roots,
        compose_env_files,
        ConfigFormat::Yaml,
      );
      let (command, wrapped) = match maybe_wrap_command(
        command,
        &compose_cmd_wrapper,
        wrapper_include,
        "config",
      ) {
        Ok(result) => result,
        Err(log) => {
          res.logs.push(log);
          return Ok(res);
        }
      };
      let span = info_span!("GetComposeConfig", command);
      #[cfg(target_os = "linux")]
      let captured_log = if let Some(capture) = &capture {
        Some(
          run_captured_command(
            "Compose Config",
            command.clone(),
            run_directory.clone(),
            capture.clone(),
          )
          .await,
        )
      } else {
        None
      };
      #[cfg(not(target_os = "linux"))]
      let captured_log: Option<Log> = None;
      let mut config_log = if let Some(log) = captured_log {
        log
      } else if wrapped {
        run_komodo_shell_command(
          "Compose Config",
          command,
          CommandOptions::default().path(run_directory.as_path()),
        )
        .instrument(span)
        .await
      } else {
        run_komodo_standard_command(
          "Compose Config",
          command,
          CommandOptions::default().path(run_directory.as_path()),
        )
        .instrument(span)
        .await
      };

      if !config_log.success {
        config_log.sanitize(&replacers);
        res.logs.push(config_log);
        return Ok(res);
      }

      // attach sanitized merged config in any case.
      res.merged_config =
        svi::replace_in_string(&config_log.stdout, &replacers).into();

      if let Err(e) = parse_compose_services(
        &config_log.stdout,
        &project_name,
        &mut res.services,
      ) {
        config_log.sanitize(&replacers);
        res.logs.push(config_log);
        res.logs.push(Log::error(
          "Parse Compose Services",
          format_serror(&e.into()),
        ));
        // early return with error log
        // including sanitized config log
        // and parse error for clear view
        // of what the issue might be.
        return Ok(res);
      }

      config_log.sanitize(&replacers);
      res.logs.push(config_log);
    }

    if stack.config.run_build {
      let build_extra_args =
        format_extra_args(&stack.config.build_extra_args);
      let command = format!(
        "{compose_command} build{build_extra_args}{service_args}",
      );
      let (command, wrapped) = match maybe_wrap_command(
        command,
        &compose_cmd_wrapper,
        wrapper_include,
        "build",
      ) {
        Ok(result) => result,
        Err(log) => {
          res.logs.push(log);
          return Ok(res);
        }
      };
      let mode = if wrapped {
        KomodoCommandMode::Shell
      } else {
        KomodoCommandMode::Standard
      };
      let span = info_span!("ExecuteComposeBuild");
      let Some(log) = run_komodo_command_with_sanitization(
        "Compose Build",
        command,
        CommandOptions::default().path(run_directory.as_path()),
        mode,
        &replacers,
      )
      .instrument(span)
      .await
      else {
        unreachable!()
      };
      res.logs.push(log);
      if !all_logs_success(&res.logs) {
        return Ok(res);
      }
    }

    // Pull images before deploying
    if stack.config.auto_pull {
      // Pull images before destroying to minimize downtime.
      // If this fails, do not continue.
      let command = format!("{compose_command} pull{service_args}");
      let (command, wrapped) = match maybe_wrap_command(
        command,
        &compose_cmd_wrapper,
        wrapper_include,
        "pull",
      ) {
        Ok(result) => result,
        Err(log) => {
          res.logs.push(log);
          return Ok(res);
        }
      };
      let mode = if wrapped {
        KomodoCommandMode::Shell
      } else {
        KomodoCommandMode::Standard
      };
      let span = info_span!("RunComposePull");
      #[cfg(target_os = "linux")]
      let captured_log = if let Some(capture) = &capture {
        let mut log = run_captured_command(
          "Compose Pull",
          command.clone(),
          run_directory.clone(),
          capture.clone(),
        )
        .instrument(span.clone())
        .await;
        log.sanitize(&replacers);
        Some(log)
      } else {
        None
      };
      #[cfg(not(target_os = "linux"))]
      let captured_log: Option<Log> = None;
      let log = if let Some(log) = captured_log {
        log
      } else {
        run_komodo_command_with_sanitization(
          "Compose Pull",
          command,
          CommandOptions::default().path(run_directory.as_path()),
          mode,
          &replacers,
        )
        .instrument(span)
        .await
        .expect("Compose pull command is not empty")
      };
      res.logs.push(log);
      if !all_logs_success(&res.logs) {
        return Ok(res);
      }
    }

    if stack.config.destroy_before_deploy
      // Also check if project name changed, which also requires taking down.
      || last_project_name != project_name
    {
      // Take down the existing compose stack.
      // This one tries to use the previously deployed service name, to ensure the right stack is taken down.
      compose_down(&last_project_name, &services, &mut res)
        .await
        .context("Failed to take down existing compose stack")?;
    }

    // Run compose up
    let extra_args = format_extra_args(&stack.config.extra_args);
    let command =
      format!("{compose_command} up -d{extra_args}{service_args}");
    let (command, _) = match maybe_wrap_command(
      command,
      &compose_cmd_wrapper,
      wrapper_include,
      "up",
    ) {
      Ok(result) => result,
      Err(log) => {
        res.logs.push(log);
        return Ok(res);
      }
    };

    let span = info_span!("ExecuteComposeUp");
    #[cfg(target_os = "linux")]
    let captured_log = if let Some(capture) = &capture {
      let mut log = run_captured_command(
        "Compose Up",
        command.clone(),
        run_directory.clone(),
        capture.clone(),
      )
      .instrument(span.clone())
      .await;
      log.sanitize(&replacers);
      Some(log)
    } else {
      None
    };
    #[cfg(not(target_os = "linux"))]
    let captured_log: Option<Log> = None;
    let log = if let Some(log) = captured_log {
      log
    } else {
      run_komodo_command_with_sanitization(
        "Compose Up",
        command,
        CommandOptions::default().path(run_directory.as_path()),
        KomodoCommandMode::Shell,
        &replacers,
      )
      .instrument(span)
      .await
      .expect("Compose up command is not empty")
    };

    res.deployed = log.success;
    res.logs.push(log);
    #[cfg(target_os = "linux")]
    if res.deployed
      && let Some(capture) = &capture
    {
      let mut evidence = capture.evidence.clone();
      evidence.deployment_proven = true;
      res.deployed_resolution = Some(evidence);
    }
    if res.deployed
      && expected_resolution.is_some()
      && res
        .deployed_resolution
        .as_ref()
        .is_none_or(|resolution| !resolution.deployment_proven)
    {
      res.logs.push(Log::simple(
        "Compose source tracking",
        "Deployment succeeded, but its source snapshot could not be verified. Automatic source-change comparisons are unavailable until a verified deployment.".into(),
      ));
    }

    if res.deployed && !stack.config.post_deploy.is_none() {
      let post_deploy_path =
        run_directory.join(&stack.config.post_deploy.path);
      let span = info_span!("ExecutePostDeploy");
      if let Some(log) = run_komodo_command_with_sanitization(
        "Post Deploy",
        &stack.config.post_deploy.command,
        CommandOptions::default().path(post_deploy_path.as_path()),
        if stack.config.post_deploy.shell_mode {
          KomodoCommandMode::Shell
        } else {
          KomodoCommandMode::Multiline
        },
        &replacers,
      )
      .instrument(span)
      .await
      {
        res.logs.push(log);
      };
    }

    Ok(res)
  }
}

#[cfg(target_os = "linux")]
async fn captured_model_matches(
  cli: &str,
  project: &str,
  roots: &[String],
  env_files: &[String],
  directory: &std::path::Path,
  capture: std::sync::Arc<crate::stack::resolve::DeploymentCapture>,
) -> bool {
  let original = config_command(
    cli,
    project,
    roots,
    env_files,
    ConfigFormat::Json,
  );
  let original = run_komodo_standard_command(
    "Original Compose model",
    original,
    CommandOptions::default()
      .path(directory)
      .env(&capture.environment)
      .clear_env(true)
      .output_limit(64 * 1024 * 1024),
  )
  .await;
  if !original.success {
    return false;
  }
  let captured_cli = format!(
    "{cli} --project-directory {}",
    escape(capture.compose.project_directory.to_string_lossy())
  );
  let captured_roots = capture
    .compose
    .roots
    .iter()
    .map(|path| path.to_string_lossy().into_owned())
    .collect::<Vec<_>>();
  let captured_env = capture
    .compose
    .env_files
    .iter()
    .map(|path| path.to_string_lossy().into_owned())
    .collect::<Vec<_>>();
  let captured = run_captured_command(
    "Captured Compose model",
    config_command(
      &captured_cli,
      project,
      &captured_roots,
      &captured_env,
      ConfigFormat::Json,
    ),
    directory.to_path_buf(),
    capture,
  )
  .await;
  if !captured.success {
    return false;
  }
  match (
    serde_json::from_str::<serde_json::Value>(&original.stdout),
    serde_json::from_str::<serde_json::Value>(&captured.stdout),
  ) {
    (Ok(original), Ok(captured)) => original == captured,
    _ => false,
  }
}

#[cfg(target_os = "linux")]
pub(crate) async fn run_captured_command(
  stage: &'static str,
  command: String,
  directory: PathBuf,
  capture: std::sync::Arc<crate::stack::resolve::DeploymentCapture>,
) -> Log {
  let cancel = tokio_util::sync::CancellationToken::new();
  let _cancel_on_drop = cancel.clone().drop_guard();
  // The task retains the descriptors while it cancels the command group.
  match tokio::spawn(async move {
    run_komodo_standard_command(
      stage,
      command,
      CommandOptions::default()
        .path(directory.as_path())
        .env(&capture.environment)
        .clear_env(true)
        .cancel(cancel)
        .output_limit(64 * 1024 * 1024),
    )
    .await
  })
  .await
  {
    Ok(log) => log,
    Err(error) => Log::error(
      stage,
      format!("Captured Compose command task failed: {error}"),
    ),
  }
}

async fn deployment_revision(
  stack: &komodo_client::entities::stack::Stack,
  directory: &std::path::Path,
  expected: &komodo_client::entities::stack::AcceptedComposeResolution,
) -> Option<Option<String>> {
  use komodo_client::entities::stack::ComposeResolutionSource;
  let (source_matches, revision) =
    match &expected.source_identity.request_identity.source {
      ComposeResolutionSource::Host { .. } => {
        (stack.config.files_on_host, None)
      }
      ComposeResolutionSource::Repository { .. } => {
        if stack.config.files_on_host {
          (false, None)
        } else {
          match git::get_commit_info(directory).await {
            Ok(commit) => (true, Some(commit.id)),
            Err(_) => {
              warn!("Unable to verify deployed Git revision");
              (false, None)
            }
          }
        }
      }
      ComposeResolutionSource::Ui => (
        !stack.config.files_on_host
          && stack.config.repo.is_empty()
          && stack.config.linked_repo.is_empty(),
        None,
      ),
    };
  if !source_matches {
    return None;
  }
  Some(revision)
}

async fn deployment_evidence(
  stack: &komodo_client::entities::stack::Stack,
  directory: &std::path::Path,
  env_files: &[String],
  expected: &komodo_client::entities::stack::AcceptedComposeResolution,
  replacers: &[(String, String)],
) -> Option<komodo_client::entities::stack::AcceptedComposeResolution>
{
  let revision =
    deployment_revision(stack, directory, expected).await?;
  match crate::stack::resolve::deployment_snapshot(
    stack,
    directory,
    env_files,
    expected,
    replacers,
    revision.as_deref(),
  ) {
    Ok(snapshot) => snapshot,
    Err(error) => {
      warn!(%error, "Unable to verify deployed Compose sources");
      None
    }
  }
}

//

impl Resolve<crate::api::Args> for ComposeExecution {
  #[instrument(
    "ComposeExecution",
    skip_all,
    fields(
      id = args.id.to_string(),
      core = args.core,
      project = self.project,
      command = self.command,
    )
  )]
  async fn resolve(
    self,
    args: &crate::api::Args,
  ) -> anyhow::Result<Log> {
    let ComposeExecution { project, command } = self;
    let docker_compose = docker_compose();
    let log = run_komodo_standard_command(
      "Compose Command",
      format!("{docker_compose} -p {project} {command}"),
      CommandOptions::default(),
    )
    .await;
    Ok(log)
  }
}

impl Resolve<crate::api::Args> for ComposeRestartObserved {
  async fn resolve(
    self,
    _: &crate::api::Args,
  ) -> anyhow::Result<ComposeRestartObservedResponse> {
    let ComposeRestartObserved {
      project,
      mut stack,
      repo,
      services,
      expected_resolution,
      mut replacers,
    } = self;
    let mut interpolator =
      Interpolator::new(None, &periphery_config().secrets);
    interpolator.interpolate_stack(&mut stack)?;
    replacers.extend(interpolator.secret_replacers);

    let directory = if stack.config.files_on_host {
      periphery_config()
        .stack_dir()
        .join(to_path_compatible_name(&stack.name))
        .join(&stack.config.run_directory)
    } else if let Some(repo) = &repo {
      periphery_config()
        .repo_dir()
        .join(to_path_compatible_name(&repo.name))
        .join(&repo.config.path)
        .join(&stack.config.run_directory)
    } else if !stack.config.repo.is_empty() {
      periphery_config()
        .stack_dir()
        .join(to_path_compatible_name(&stack.name))
        .join(&stack.config.clone_path)
        .join(&stack.config.run_directory)
    } else {
      periphery_config()
        .stack_dir()
        .join(to_path_compatible_name(&stack.name))
    };
    let generated = directory
      .join(&stack.config.env_file_path)
      .is_file()
      .then_some(stack.config.env_file_path.as_str());
    let env_files = ordered_env_files(
      generated,
      &stack.config.additional_env_files,
    );
    let command = format!(
      "{} -p {project} restart{}",
      docker_compose(),
      if services.is_empty() {
        String::new()
      } else {
        format!(" {}", services.join(" "))
      }
    );
    let expected = expected_resolution.clone();
    Ok(
      observed_restart(
        &expected_resolution,
        move || {
          let stack = stack.clone();
          let directory = directory.clone();
          let env_files = env_files.clone();
          let expected = expected.clone();
          let replacers = replacers.clone();
          async move {
            deployment_evidence(
              &stack, &directory, &env_files, &expected, &replacers,
            )
            .await
          }
        },
        move || async move {
          run_komodo_standard_command(
            "Compose Command",
            command,
            CommandOptions::default(),
          )
          .await
        },
      )
      .await,
    )
  }
}

pub(crate) async fn observed_restart<O, OF, R, RF>(
  expected: &komodo_client::entities::stack::AcceptedComposeResolution,
  mut observe: O,
  run: R,
) -> ComposeRestartObservedResponse
where
  O: FnMut() -> OF + Send,
  OF: std::future::Future<
      Output = Option<
        komodo_client::entities::stack::AcceptedComposeResolution,
      >,
    > + Send,
  R: FnOnce() -> RF + Send,
  RF: std::future::Future<Output = Log> + Send,
{
  let before = observe().await;
  if before.as_ref() != Some(expected) {
    return ComposeRestartObservedResponse {
        log: Log::error(
          "Compose source tracking",
          "Stack sources changed or could not be verified before restart. Refresh and retry.".into(),
        ),
        observed_resolution: None,
      };
  }
  let log = run().await;
  let after = if log.success { observe().await } else { None };
  ComposeRestartObservedResponse {
    log,
    observed_resolution: after
      .filter(|value| value.deployment_proven && value == expected),
  }
}

//

impl Resolve<crate::api::Args> for ComposeRun {
  #[instrument(
    "ComposeRun",
    skip_all,
    fields(
      id = args.id.to_string(),
      core = args.core,
      stack = self.stack.name,
      repo = self.repo.as_ref().map(|repo| &repo.name),
      service = &self.service
    )
  )]
  async fn resolve(
    self,
    args: &crate::api::Args,
  ) -> anyhow::Result<Log> {
    let ComposeRun {
      mut stack,
      repo,
      git_token,
      registry_token,
      mut replacers,
      service,
      command,
      no_tty,
      no_deps,
      detach,
      service_ports,
      env,
      workdir,
      user,
      entrypoint,
      pull,
    } = self;

    let mut interpolator =
      Interpolator::new(None, &periphery_config().secrets);
    interpolator
      .interpolate_stack(&mut stack)?
      .push_logs(&mut Vec::new());
    replacers.extend(interpolator.secret_replacers);

    let mut res = ComposeRunResponse::default();
    let (run_directory, env_file_path) = match write_stack(
      &stack,
      repo.as_ref(),
      git_token,
      replacers.clone(),
      &mut res,
      args,
    )
    .await
    {
      Ok(res) => res,
      Err(e) => {
        return Ok(Log::error(
          "Write Stack",
          format_serror(&e.into()),
        ));
      }
    };

    let run_directory = run_directory.canonicalize().with_context(||
      format!("Failed to validate run directory on host after stack write (canonicalize error), path={}", run_directory.to_string_lossy())
    )?;

    maybe_login_registry(&stack, registry_token, &mut Vec::new())
      .await;

    let docker_compose = docker_compose();

    let env_files = ordered_env_files(
      env_file_path,
      &stack.config.additional_env_files,
    );

    let project_name = stack.project_name(true);
    let compose_command = compose_command(
      docker_compose,
      &project_name,
      stack.compose_file_paths(),
      &env_files,
    );

    // Comes straight off the request and interpolated into a
    // command string which is handed to `bash -c`, so must be escaped.
    let service = escape(Cow::Borrowed(&service));

    // Parse wrapper configuration
    let compose_cmd_wrapper =
      parse_multiline_command(&stack.config.compose_cmd_wrapper);
    // If wrapper_include is empty but wrapper is set, use default ["up"] for backward compatibility
    static DEFAULT_INCLUDE: LazyLock<Vec<String>> =
      LazyLock::new(|| vec![String::from("up")]);
    let wrapper_include =
      if stack.config.compose_cmd_wrapper_include.is_empty()
        && !compose_cmd_wrapper.is_empty()
      {
        &DEFAULT_INCLUDE
      } else {
        &stack.config.compose_cmd_wrapper_include
      };

    if pull.unwrap_or_default() {
      let pull_command =
        format!("{compose_command} pull -- {service}");
      let (pull_command, wrapped) = match maybe_wrap_command(
        pull_command,
        &compose_cmd_wrapper,
        wrapper_include,
        "pull",
      ) {
        Ok(result) => result,
        Err(log) => return Ok(log),
      };
      let mode = if wrapped {
        KomodoCommandMode::Shell
      } else {
        KomodoCommandMode::Standard
      };
      let Some(pull_log) = run_komodo_command_with_sanitization(
        "Compose Pull",
        pull_command,
        CommandOptions::default().path(run_directory.as_path()),
        mode,
        &replacers,
      )
      .await
      else {
        unreachable!()
      };
      if !pull_log.success {
        return Ok(pull_log);
      }
    }

    let mut run_flags = String::from(" --rm");
    if detach.unwrap_or_default() {
      run_flags.push_str(" -d");
    }
    if no_tty.unwrap_or_default() {
      run_flags.push_str(" --no-tty");
    }
    if no_deps.unwrap_or_default() {
      run_flags.push_str(" --no-deps");
    }
    if service_ports.unwrap_or_default() {
      run_flags.push_str(" --service-ports");
    }
    if let Some(dir) = workdir.as_ref() {
      run_flags
        .push_str(&format!(" --workdir {}", escape(dir.into())));
    }
    if let Some(user) = user.as_ref() {
      run_flags.push_str(&format!(" --user {}", escape(user.into())));
    }
    if let Some(entrypoint) = entrypoint.as_ref() {
      run_flags.push_str(&format!(
        " --entrypoint {}",
        escape(entrypoint.into())
      ));
    }
    if let Some(env) = env {
      for (k, v) in env {
        // Escaped as a single KEY=VALUE token, which is what compose expects.
        run_flags.push_str(&format!(
          " -e {}",
          escape(format!("{k}={v}").into())
        ));
      }
    }

    let command_args = command
      .as_ref()
      .filter(|v| !v.is_empty())
      .map(|argv| {
        let joined = argv
          .iter()
          .map(|s| escape(s.into()).into_owned())
          .collect::<Vec<_>>()
          .join(" ");
        format!(" {joined}")
      })
      .unwrap_or_default();

    let run_command = format!(
      "{compose_command} run{run_flags} -- {service}{command_args}",
    );
    let (run_command, _) = match maybe_wrap_command(
      run_command,
      &compose_cmd_wrapper,
      wrapper_include,
      "run",
    ) {
      Ok(result) => result,
      Err(log) => return Ok(log),
    };

    let span = info_span!("RunComposeRun", run_command);
    let Some(log) = run_komodo_command_with_sanitization(
      "Compose Run",
      run_command,
      CommandOptions::default().path(run_directory.as_path()),
      KomodoCommandMode::Shell,
      &replacers,
    )
    .instrument(span)
    .await
    else {
      unreachable!()
    };

    Ok(log)
  }
}

/// Apply compose_cmd_wrapper to command if the subcommand is in wrapper_include list.
/// Returns Ok((command, wrapped)) where `wrapped` indicates if wrapper was applied.
/// Returns Err(Log) if wrapper is invalid (missing placeholder).
pub(crate) fn maybe_wrap_command(
  command: String,
  wrapper: &str,
  wrapper_include: &[String],
  subcommand: &str,
) -> Result<(String, bool), Log> {
  // Skip wrapping if wrapper is empty or subcommand is not in include list
  if wrapper.is_empty()
    || !wrapper_include.iter().any(|c| c == subcommand)
  {
    return Ok((command, false));
  }

  // Validate wrapper contains placeholder
  if !wrapper.contains("[[COMPOSE_COMMAND]]") {
    return Err(Log::error(
      "Compose Command Wrapper",
      "compose_cmd_wrapper is configured but does not contain [[COMPOSE_COMMAND]] placeholder. The placeholder is required to inject the compose command.".to_string(),
    ));
  }

  Ok((wrapper.replace("[[COMPOSE_COMMAND]]", &command), true))
}

#[instrument("ComposeDown", skip(res))]
async fn compose_down(
  project: &str,
  services: &[String],
  res: &mut DeployStackResponse,
) -> anyhow::Result<()> {
  let docker_compose = docker_compose();
  let service_args = if services.is_empty() {
    String::new()
  } else {
    // `--` so a service beginning with `-` is not parsed as a flag.
    format!(" -- {}", services.join(" "))
  };
  let log = run_komodo_standard_command(
    "Compose Down",
    format!("{docker_compose} -p {project} down{service_args}"),
    CommandOptions::default(),
  )
  .await;
  let success = log.success;
  res.logs.push(log);
  if !success {
    return Err(anyhow!(
      "Failed to bring down existing container(s) with docker compose down. Stopping run."
    ));
  }

  Ok(())
}

impl Resolve<crate::api::Args> for ResolveComposeStack {
  async fn resolve(
    self,
    args: &crate::api::Args,
  ) -> anyhow::Result<Self::Response> {
    use periphery_client::api::compose::ResolveComposeStackResponse;
    if let Err(error) = self.validate() {
      return Ok(ResolveComposeStackResponse::Failure {
        request_identity: None,
        error,
      });
    }
    Ok(
      crate::stack::resolve::resolve_sources(
        self,
        args.core.clone(),
        periphery_config(),
      )
      .await,
    )
  }
}

#[cfg(test)]
mod resolution_tests {
  use super::*;
  use crate::api::{Args, PeripheryRequest};
  use komodo_client::entities::stack::{
    AcceptedComposeResolution, ComposeResolutionErrorKind,
    ComposeResolutionSource, ComposeSourceIdentity,
    ObservedComposeSnapshot, ResolutionRequestIdentity, Stack,
  };

  #[tokio::test]
  async fn compose_include_restart_requires_stable_observed_sources()
  {
    use std::sync::{
      Arc,
      atomic::{AtomicUsize, Ordering},
    };
    let expected = AcceptedComposeResolution {
      deployment_proven: false,
      source_identity: ComposeSourceIdentity {
        request_identity: ResolutionRequestIdentity {
          stack_id: "stack".into(),
          config_generation: "generation".into(),
          source: ComposeResolutionSource::Host {
            server_id: "server".into(),
            run_directory: ".".into(),
          },
        },
        observed_snapshot: ObservedComposeSnapshot {
          complete: true,
          dependency_fingerprints: Vec::new(),
          commit_id: None,
          config_generation: None,
        },
      },
      dependencies: Vec::new(),
    };
    for (before, after, succeeds) in [
      (false, true, true),
      (true, false, true),
      (true, true, false),
      (true, true, true),
    ] {
      let observations = Arc::new(AtomicUsize::new(0));
      let executions = Arc::new(AtomicUsize::new(0));
      let observed = expected.clone();
      let count = observations.clone();
      let runs = executions.clone();
      let response = observed_restart(
        &expected,
        move || {
          let index = count.fetch_add(1, Ordering::SeqCst);
          let observed = observed.clone();
          async move {
            (if index == 0 { before } else { after })
              .then_some(observed)
          }
        },
        move || async move {
          runs.fetch_add(1, Ordering::SeqCst);
          if succeeds {
            Log::simple("restart", "ok".into())
          } else {
            Log::error("restart", "failed".into())
          }
        },
      )
      .await;
      assert_eq!(
        executions.load(Ordering::SeqCst),
        usize::from(before)
      );
      assert_eq!(response.log.success, before && succeeds);
      assert_eq!(
        response.observed_resolution.is_some(),
        before && after && succeeds && expected.deployment_proven
      );
    }
  }

  #[tokio::test]
  async fn compose_resolution_dispatch_rejects_invalid_ui_identity()
  -> anyhow::Result<()> {
    {
      let mut stack = Stack::default();
      stack.id = "a".repeat(24);
      stack.config.file_contents = "synthetic-secret".into();
      let request = ResolveComposeStack {
        request_identity: ResolutionRequestIdentity {
          stack_id: "another-stack".into(),
          config_generation: "generation".into(),
          source: ComposeResolutionSource::Ui,
        },
        stack,
        repo: None,
        git_token: Some("synthetic-secret".into()),
        replacers: Vec::new(),
      };
      let encoded = serde_json::json!({"type":"ResolveComposeStack","params":request});
      let request: PeripheryRequest =
        serde_json::from_value(encoded)?;
      assert!(!format!("{request:?}").contains("synthetic-secret"));
      let PeripheryRequest::ResolveComposeStack(request) = request
      else {
        panic!("Resolver request was not registered");
      };
      let response = request
        .resolve(&Args {
          core: "synthetic".into(),
          id: uuid::Uuid::new_v4(),
        })
        .await?;
      let ResolveComposeStackResponse::Failure {
        request_identity,
        error,
      } = response
      else {
        panic!(
          "Invalid requests must never produce a successful snapshot"
        );
      };
      assert!(request_identity.is_none());
      assert_eq!(
        error.category,
        ComposeResolutionErrorKind::InvalidIdentity
      );
    }
    Ok(())
  }
}
