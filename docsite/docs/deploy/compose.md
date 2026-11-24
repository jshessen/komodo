# Docker Compose

Komodo can deploy Docker Compose projects through the `Stack` resource.

## Configuration

```toml
[[stack]]
name = "my-stack"
[stack.config]
server = "server-prod"
run_directory = "/opt/stacks/my-stack"
file_paths = ["compose.yaml"]
git_account = "my-user"
repo = "myorg/stacks"
environment = """
DB_HOST = db.example.com
LOG_LEVEL = info
"""
```

### Config fields

| Field | Description | Default |
|---|---|---|
| `server` | The Server to deploy on. | — |
| `file_paths` | List of compose files. Supports composing multiple files via `docker compose -f ... -f ...`. | `[]` |
| `inline_files` | UI companion sources as `{ path, contents }` entries; these do not add Compose roots. | `[]` |
| `run_directory` | Working directory for compose commands. | — |
| `project_name` | Override the compose project name. Defaults to the Stack name. | Stack name |
| `environment` | Environment variables written to a `.env` file and passed via `--env-file`. Supports [variable interpolation](../configuration/variables.md). | `""` |
| `extra_args` | Additional flags passed to `docker compose up`. | `""` |
| `ignore_services` | Services to exclude from health checks (e.g. init containers that exit after startup). | `[]` |
| `git_provider` | Git provider domain. | `github.com` |
| `git_account` | Git provider account for private repos. | — |
| `repo` | Repository in `owner/repo` format. | — |
| `branch` | Branch to clone. | `main` |
| `auto_update` | Automatically redeploy when newer image digests are available. | `false` |
| `poll_for_updates` | Check for newer images and show an update indicator. | `false` |
| `send_alerts` | Send alerts on stack state changes. | `true` |
| `links` | Quick links displayed in the resource header. | `[]` |

## Defining Compose Files

Stacks support three ways to provide compose files:

1. **Write in the UI** — Komodo writes the files to the host at deploy time.
2. **Files on the host** — Point to existing files on the server.
3. **Git repo** — Komodo clones the repo onto the host to deploy. Changes are tracked in git and you can use [webhooks](../automate/webhooks.md) to auto-redeploy on push.

### Compose service discovery

For non-Swarm Host, Git, and UI stacks, service refresh follows local Compose `include`
dependencies. Keep `file_paths` as the ordered explicit roots; do not add included
files as extra roots. Git discovery uses a separate temporary checkout pinned to
the full revision selected by Core, without running repository or deployment hooks.
Host discovery reads the current on-disk environment and does not apply undeployed
changes to the Stack's `environment`.

If `compose_cmd_wrapper_include` contains `config`, the trusted
`compose_cmd_wrapper` also runs during background refresh. The default selection
is `up`, so it does not enable refresh wrapping. Wrapper filesystem/network side
effects remain the operator's responsibility.

No-include refresh preserves source-only parsing. Include resolution requires compatible
Core/Periphery versions and a Compose command that supports the configured includes;
it does not require user or network namespace creation. Git checkout inputs must remain
inside the discovery checkout; existing external Host paths remain allowed.

UI stacks retain `file_contents` as their primary root. Supply included files in
`inline_files` using unique normalized relative paths. Every explicit `file_paths`
root must have supplied contents. Absolute paths, traversal, symlinks, file/directory
collisions, `.git`, and collisions with the generated environment or ownership manifest
are rejected. The complete supplied tree is limited to 512 files and 32 MiB of text.
Primary and companion contents share variable/secret interpolation and its opt-out.
In UI Defined mode, use **Add Companion File** to add source contents and rename
their relative paths. Update the corresponding `include` references when renaming
or removing files. **Explicit Compose Roots** remains a separate ordered list.
Companion edits use the same save/unsaved-change workflow and write permissions
as the primary editor.

UI refresh uses a separate private temporary tree and never changes deployed input files.
Deployment writes files with restricted permissions and records only owned companion
paths in a private manifest. Removing a companion deletes only its previously owned file;
unrelated files are retained, and existing unowned companions are never overwritten.
Before deploy, pull, or run with companions, Core rechecks the additive discovery operation
so an older Periphery cannot silently ignore them. UI companions currently require a
Compose server target, not Swarm.

Compose may access remote includes during background refresh, as it can during deployment.
Remote include contents are not tracked as local dependencies, so source-based automatic
change decisions are unavailable when they are present. Unsupported syntax and resource
limits fail explicitly. No source fallback substitutes only explicit roots.

Compatibility upgrades must move Core and Periphery together. An older Periphery with
companions is rejected before deploy, pull, or run instead of silently deploying only
the primary root. Older Core versions cannot read persisted verified-deployment evidence;
restore a compatible database backup before downgrading Core. Swarm stacks remain on the
existing deployment path.

The trusted `compose_cmd_wrapper` runs for wrappers selected by
`compose_cmd_wrapper_include`; background discovery may therefore inherit wrapper
filesystem/network effects. The wrapper must contain `[[COMPOSE_COMMAND]]` exactly once
when selected. Discovery never runs deploy hooks or repository hooks and never uses an
active Git checkout.

A failed refresh clears latest service discovery, reports a safe error, and blocks
change-driven deployment and automatic update decisions without changing deployed state.
On Linux, supported full deployments use sealed copies of the Compose and
environment sources for both configuration and deployment. Evidence comes from the
same captured sources. Docker records temporary source paths in its Compose config-files
labels; those paths expire after the operation. Komodo retains the configured original
paths in the Stack configuration, but its Compose project listing and external tools
that use the labels may display paths they cannot reopen.

Verification currently excludes interpolation in Compose sources, inherited service
environment values, service `env_file`, `extends`, builds, configs, secrets, tracked
auxiliary files, remote includes, wrappers, selective services, custom `up` arguments,
post-deploy hooks, Compose environment controls, YAML tags or merges, unknown fields,
and no-include stacks with environment files. Manual deployment still works for these
cases, but it does not establish verified source evidence. Automatic source comparisons
fail explicitly until a verified deployment is available. Restart-only operations also
cannot establish verified evidence from before/after observations.

## Importing Existing Projects

To import a running compose project, create a Stack in Komodo with access to the same compose files and attach the correct Server. Komodo matches projects by compose project name — if the running project name differs from the Stack name, set a custom `project_name` in the config. Run `docker compose ls` on the host to find existing project names.

## Deploying to a Swarm

A Stack can target a **Swarm** instead of a single Server to deploy via `docker stack deploy`. See [Swarm](../swarm.md) for details.
