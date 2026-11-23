use std::{collections::HashMap, time::Duration};

use anyhow::{Context, anyhow};
use command::{CommandOptions, run_komodo_standard_command};
use komodo_client::entities::stack::*;
use serde::{Deserialize, Serialize};

use crate::config::periphery_config;

pub fn docker_compose() -> &'static str {
  if periphery_config().legacy_compose_cli {
    "docker-compose"
  } else {
    "docker compose"
  }
}

pub async fn list_compose_projects()
-> anyhow::Result<Vec<ComposeProject>> {
  let docker_compose = docker_compose();
  let res = run_komodo_standard_command(
    "List Projects",
    format!("{docker_compose} ls --all --format json"),
    CommandOptions::default().timeout(Duration::from_secs(5)),
  )
  .await;

  if !res.success {
    return Err(anyhow!("{}", res.combined()).context(format!(
      "Failed to list compose projects using {docker_compose} ls"
    )));
  }

  let mut res =
    serde_json::from_str::<Vec<DockerComposeLsItem>>(&res.stdout)
      .with_context(|| res.stdout.clone())
      .with_context(|| {
        format!(
          "Failed to parse '{docker_compose} ls' response from json"
        )
      })?
      .into_iter()
      .filter(|item| !item.name.is_empty())
      .map(|item| ComposeProject {
        name: item.name,
        status: item.status,
        compose_files: item
          .config_files
          .split(',')
          .map(str::to_string)
          .collect(),
      })
      .collect::<Vec<_>>();

  res.sort_by(|a, b| {
    a.status.cmp(&b.status).then_with(|| a.name.cmp(&b.name))
  });

  Ok(res)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerComposeLsItem {
  #[serde(default, alias = "Name")]
  pub name: String,
  #[serde(alias = "Status")]
  pub status: Option<String>,
  /// Comma seperated list of paths
  #[serde(default, alias = "ConfigFiles")]
  pub config_files: String,
}

pub fn parse_compose_services(
  raw_config: &str,
  project_name: &str,
  services: &mut Vec<StackServiceNames>,
) -> anyhow::Result<()> {
  let compose = parse_compose_config(raw_config, ConfigFormat::Yaml)?;

  append_compose_services(compose, project_name, services);
  Ok(())
}

#[derive(Clone, Copy)]
pub(crate) enum ConfigFormat {
  Yaml,
  Json,
}

pub(crate) fn ordered_env_files(
  generated: Option<&str>,
  additional: &[AdditionalEnvFile],
) -> Vec<String> {
  additional
    .iter()
    .filter(|file| generated != Some(file.path.as_str()))
    .map(|file| file.path.clone())
    .chain(generated.map(str::to_string))
    .collect()
}

/// Render explicit roots only, with identical literal arguments in direct and wrapper-shell execution.
pub(crate) fn compose_command(
  cli: &str,
  project: &str,
  roots: &[String],
  env_files: &[String],
) -> String {
  let mut args = vec!["-p", project];
  for root in roots {
    args.extend(["-f", root]);
  }
  for file in env_files {
    args.extend(["--env-file", file]);
  }
  let args = args
    .iter()
    .map(|arg| shell_escape::escape((*arg).into()))
    .collect::<Vec<_>>()
    .join(" ");
  format!("{cli} {args}")
}

pub(crate) fn config_command(
  cli: &str,
  project: &str,
  roots: &[String],
  env_files: &[String],
  format: ConfigFormat,
) -> String {
  let base = compose_command(cli, project, roots, env_files);
  match format {
    ConfigFormat::Yaml => format!("{base} config"),
    ConfigFormat::Json => format!("{base} config --format json"),
  }
}

pub(crate) fn parse_compose_config(
  raw: &str,
  format: ConfigFormat,
) -> anyhow::Result<ComposeFile> {
  match format {
    ConfigFormat::Yaml => serde_yaml_ng::from_str(raw)
      .context("Failed to parse compose contents"),
    ConfigFormat::Json => {
      // Resolved models must declare services, unlike legacy source parsing.
      #[derive(Deserialize)]
      struct ConfigModel {
        services: HashMap<String, ComposeService>,
      }
      let model: ConfigModel = serde_json::from_str(raw)
        .context("Failed to parse resolved Compose model")?;
      Ok(ComposeFile {
        name: None,
        services: model.services,
      })
    }
  }
}

pub(crate) fn append_compose_services(
  compose: ComposeFile,
  project_name: &str,
  services: &mut Vec<StackServiceNames>,
) {
  for (
    service_name,
    ComposeService {
      container_name,
      deploy,
      image,
    },
  ) in compose.services
  {
    let image = image.unwrap_or_default();
    match deploy {
      Some(ComposeServiceDeploy {
        replicas: Some(replicas),
      }) if replicas > 1 => {
        for i in 1..1 + replicas {
          services.push(StackServiceNames {
            container_name: format!(
              "{project_name}-{service_name}-{i}"
            ),
            service_name: format!("{service_name}-{i}"),
            image: image.clone(),
            image_digest: None,
          });
        }
      }
      _ => {
        services.push(StackServiceNames {
          container_name: container_name.unwrap_or_else(|| {
            format!("{project_name}-{service_name}")
          }),
          service_name,
          image,
          image_digest: None,
        });
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use command::{run_shell_command, run_standard_command};
  use std::collections::BTreeMap;

  fn inventory(
    services: Vec<StackServiceNames>,
  ) -> BTreeMap<String, (String, String)> {
    services
      .into_iter()
      .map(|service| {
        (
          service.service_name,
          (service.container_name, service.image),
        )
      })
      .collect()
  }

  #[test]
  fn compose_include_config_normalization_preserves_existing_replica_behavior()
  -> anyhow::Result<()> {
    let model = serde_json::json!({"services":{
      "plain":{"image":"synthetic/plain"},
      "named":{"image":"synthetic/named","container_name":"explicit"},
      "scaled":{"image":"synthetic/scaled","deploy":{"replicas":2}},
      "zero":{"deploy":{"replicas":0}},
      "one":{"deploy":{"replicas":"1"}},
    }});
    let source = serde_yaml_ng::to_string(&model)?;
    let mut legacy = Vec::new();
    parse_compose_services(&source, "selected", &mut legacy)?;
    let compose =
      parse_compose_config(&model.to_string(), ConfigFormat::Json)?;
    let mut resolved = Vec::new();
    append_compose_services(compose, "selected", &mut resolved);
    let expected = BTreeMap::from([
      (
        "plain".into(),
        ("selected-plain".into(), "synthetic/plain".into()),
      ),
      (
        "named".into(),
        ("explicit".into(), "synthetic/named".into()),
      ),
      (
        "scaled-1".into(),
        ("selected-scaled-1".into(), "synthetic/scaled".into()),
      ),
      (
        "scaled-2".into(),
        ("selected-scaled-2".into(), "synthetic/scaled".into()),
      ),
      ("zero".into(), ("selected-zero".into(), String::new())),
      ("one".into(), ("selected-one".into(), String::new())),
    ]);
    assert_eq!(inventory(legacy), expected);
    assert_eq!(inventory(resolved), expected);
    assert!(
      parse_compose_config(
        r#"{"name":"missing-services"}"#,
        ConfigFormat::Json
      )
      .is_err()
    );
    let mut legacy = Vec::new();
    parse_compose_services(
      "name: missing-services",
      "selected",
      &mut legacy,
    )?;
    assert!(legacy.is_empty());
    Ok(())
  }

  #[tokio::test]
  async fn compose_include_config_arguments_preserve_roots_and_environment_precedence()
  -> anyhow::Result<()> {
    let stack = Stack::default();
    let additional =
      ["first.env", "generated.env", "last env", "first.env"].map(
        |path| AdditionalEnvFile {
          path: path.into(),
          track: false,
        },
      );
    for generated in [None, Some("generated.env")] {
      let env_files = ordered_env_files(generated, &additional);
      let expected_env = if generated.is_some() {
        vec!["first.env", "last env", "first.env", "generated.env"]
      } else {
        vec!["first.env", "generated.env", "last env", "first.env"]
      };
      for roots in [
        stack.compose_file_paths().to_vec(),
        vec![
          "override with space.yaml".into(),
          "root 'quoted'.yaml".into(),
        ],
      ] {
        for format in [ConfigFormat::Yaml, ConfigFormat::Json] {
          let command = config_command(
            "printf '%s\\n'",
            "selected",
            &roots,
            &env_files,
            format,
          );
          let mut expected = vec!["-p", "selected"];
          for root in &roots {
            expected.extend(["-f", root.as_str()]);
          }
          for env_file in &expected_env {
            expected.extend(["--env-file", env_file]);
          }
          expected.push("config");
          if matches!(format, ConfigFormat::Json) {
            expected.extend(["--format", "json"]);
          }
          for shell in [false, true] {
            let options = CommandOptions::default()
              .timeout(Duration::from_secs(5));
            let output = if shell {
              run_shell_command(&command, options).await
            } else {
              run_standard_command(&command, options).await
            };
            assert!(
              output.success(),
              "Argument capture failed: {}",
              output.stderr
            );
            assert_eq!(
              output.stdout.lines().collect::<Vec<_>>(),
              expected
            );
          }
        }
      }
    }
    Ok(())
  }

  #[test]
  #[ignore = "requires Docker Compose"]
  fn compose_include_cli_effective_model_parity_and_root_overrides()
  -> anyhow::Result<()> {
    let fixture = crate::stack::Fixture::new("nested")?;
    std::fs::write(
      fixture.root.join("override.yaml"),
      "services:\n  root:\n    image: synthetic/overridden\n",
    )?;
    for roots in [
      vec!["compose.yaml"],
      vec!["compose.yaml", "override.yaml"],
      vec!["override.yaml", "compose.yaml"],
    ] {
      let model = fixture.compose_model(&roots, &[])?;
      let mut services = Vec::new();
      parse_compose_services(
        &model.to_string(),
        "selected",
        &mut services,
      )?;
      let model =
        parse_compose_config(&model.to_string(), ConfigFormat::Json)?;
      let mut resolved = Vec::new();
      append_compose_services(model, "selected", &mut resolved);
      assert_eq!(services.len(), 3);
      assert_eq!(resolved.len(), 3);
      let services = inventory(services);
      assert_eq!(services.len(), 3);
      assert_eq!(
        services.keys().map(String::as_str).collect::<Vec<_>>(),
        ["leaf", "module", "root"]
      );
      assert_eq!(inventory(resolved), services);
      assert_eq!(
        services["root"].1,
        if roots.last() == Some(&"override.yaml") {
          "synthetic/overridden"
        } else {
          "conformance/root:synthetic"
        }
      );
    }
    std::fs::write(
      fixture.root.join("compose.yaml"),
      "services:\n  standalone:\n    image: ${IMAGE}\n    container_name: fixed-name\n",
    )?;
    std::fs::write(
      fixture.root.join("base.env"),
      "IMAGE=synthetic/base\n",
    )?;
    std::fs::write(
      fixture.root.join("generated.env"),
      "IMAGE=synthetic/generated\n",
    )?;
    let model = fixture.compose_model(
      &["compose.yaml"],
      &["base.env", "generated.env"],
    )?;
    let mut services = Vec::new();
    parse_compose_services(
      &model.to_string(),
      "selected",
      &mut services,
    )?;
    assert_eq!(
      inventory(services),
      BTreeMap::from([(
        "standalone".into(),
        ("fixed-name".into(), "synthetic/generated".into())
      ),])
    );
    Ok(())
  }
}
