# Vault

[![Release](https://img.shields.io/github/v/release/abagile/tokyo3-vault?sort=semver&logo=Go&color=%23007D9C)](https://github.com/abagile/tokyo3-vault/releases)
[![Test](https://github.com/abagile/tokyo3-vault/actions/workflows/test.yml/badge.svg)](https://github.com/abagile/tokyo3-vault/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/abagile/tokyo3-vault.svg)](https://pkg.go.dev/github.com/abagile/tokyo3-vault)
[![Go Report Card](https://goreportcard.com/badge/github.com/abagile/tokyo3-vault)](https://goreportcard.com/report/github.com/abagile/tokyo3-vault)
[![codecov](https://codecov.io/gh/abagile/tokyo3-vault/branch/main/graph/badge.svg)](https://codecov.io/gh/abagile/tokyo3-vault)

A minimal self-hosted secret manager with versioning, audit logging, and `.env` file support. Secrets are encrypted at rest using per-secret data-encryption keys (DEK) wrapped by a master key (KEK) — either a local AES-256 key or AWS KMS.

## Contents

- [Installation](#installation)
- [Bootstrap](#bootstrap)
- [Configuration](#configuration)
- [Command Reference](#command-reference)
  - [Authentication](#authentication)
  - [Projects](#projects)
  - [Environments](#environments)
  - [Secrets](#secrets)
  - [Members](#members)
  - [Tokens](#tokens)
  - [Users](#users)
  - [Audit Log](#audit-log)
  - [Utilities](#utilities)
- [Permissions and Roles](#permissions-and-roles)
- [Machine Tokens](#machine-tokens)

---

## Installation

Requires Go 1.26 or later.

```sh
# CLI client
go install github.com/abagile/tokyo3-vault/cmd/vault@latest

# Server daemon
go install github.com/abagile/tokyo3-vault/cmd/vaultd@latest
```

Both binaries are installed to `$GOBIN` (default `$HOME/go/bin`). Make sure that directory is on your `$PATH`.

---

## Bootstrap

### 1. Choose a key provider

**Local master key (development / single-server)**

```sh
vault keygen
# outputs: a64characterhexstring0000000000000000000000000000000000000000000
```

Store this value as `VAULT_MASTER_KEY`. It encrypts every secret's data key — losing it means losing all secrets. Back it up securely.

**AWS KMS (recommended for production)**

Create a symmetric KMS key in your AWS account and note its key ID or ARN. No local key material to manage — AWS handles durability and rotation.

```sh
# Example ARN
arn:aws:kms:us-east-1:123456789012:key/mrk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Set `VAULT_KMS_KEY_ID` to the key ID, ARN, or alias. AWS credentials are loaded from the standard chain (env vars, IAM role, instance profile). `VAULT_MASTER_KEY` and `VAULT_KMS_KEY_ID` are mutually exclusive — set exactly one.

### 2. Start the server

**SQLite — local key (development):**

```sh
VAULT_MASTER_KEY=<key> VAULT_DB_PATH=vault.db vaultd
```

**PostgreSQL — KMS (production):**

```sh
VAULT_KMS_KEY_ID=<key-id-or-arn> VAULT_DATABASE_URL="postgres://user:pass@host/dbname" vaultd
```

The server listens on `:8080` by default. Set `VAULT_ADDR` to change this.

### 3. Create the first user

The first account created on a fresh server is automatically promoted to server admin.

```sh
vault signup --server http://localhost:8080
# prompts for email and password
```

Subsequent `vault signup` calls create regular member accounts.

### 4. Log in from the CLI

```sh
vault login --server http://localhost:8080
# prompts for email and password
# saves credentials to ~/.vault/config
```

---

## Configuration

### Server environment variables

**Key provider — exactly one must be set:**

| Variable | Description |
|---|---|
| `VAULT_MASTER_KEY` | 64-char hex key (32 bytes). Generate with `vault keygen`. Development only — store securely. |
| `VAULT_KMS_KEY_ID` | AWS KMS key ID, ARN, or alias (e.g. `alias/vault-prod`). Recommended for production. AWS credentials loaded from the standard chain. |

**Storage — exactly one must be set:**

| Variable | Default | Description |
|---|---|---|
| `VAULT_DATABASE_URL` | — | PostgreSQL DSN, e.g. `postgres://user:pass@host/db` |
| `VAULT_DB_PATH` | `vault.db` | SQLite file path |

**Optional:**

| Variable | Default | Description |
|---|---|---|
| `VAULT_ADDR` | `:8080` | TCP listen address |

### CLI configuration

| File | Location | Contents |
|---|---|---|
| Global config | `~/.vault/config` | Server URL and auth token (written by `vault login`) |
| Repo config | `.vault.toml` (CWD) | Default project and environment slugs (written by `vault projects link`) |

`.vault.toml` is looked up by walking up from the current directory, so any subdirectory of a linked directory inherits the project/env defaults.

---

## Command Reference

### Authentication

#### `vault login`

Authenticate and save credentials locally.

```sh
vault login [--server <url>]
```

Prompts for email and password. Saves the server URL and session token to `~/.vault/config`.

#### `vault signup`

Create a new account.

```sh
vault signup [--server <url>]
```

Prompts for email and password. The first account on a new server becomes server admin.

#### `vault logout`

Revoke the current session token and remove it from local config.

```sh
vault logout
```

---

### Projects

Projects are top-level namespaces that hold environments and secrets.

#### `vault projects list`

```sh
vault projects list
```

#### `vault projects create <name>`

```sh
vault projects create myapp
vault projects create "My App" --slug myapp
```

| Flag | Description |
|---|---|
| `--slug` | Custom URL slug (default: derived from name) |

#### `vault projects delete <slug>`

Deletes the project and all its environments and secrets. If `.vault.toml` in the current directory points to this project, it is removed automatically.

```sh
vault projects delete myapp
```

#### `vault projects link [project-slug]`

Write `.vault.toml` linking the current directory to a project and environment.

```sh
vault projects link myapp --env production
vault projects link --env staging   # keep current project, switch env
```

| Flag | Description |
|---|---|
| `--env` | Environment slug |

If `project-slug` is omitted, the project from the existing `.vault.toml` is reused, making environment switching easy.

#### `vault projects unlink`

Remove `.vault.toml` from the current directory.

```sh
vault projects unlink
```

---

### Environments

Environments live inside projects (e.g. `dev`, `staging`, `production`).

#### `vault envs list`

```sh
vault envs list [--project <slug>]
```

#### `vault envs create <name>`

```sh
vault envs create production [--project myapp] [--slug production]
```

| Flag | Description |
|---|---|
| `--project` | Project slug (default: from `.vault.toml`) |
| `--slug` | Custom slug |

#### `vault envs delete <env-slug>`

Deletes the environment and all its secrets. If `.vault.toml` points to this exact project+environment, it is removed automatically.

```sh
vault envs delete staging [--project myapp]
```

---

### Secrets

All secret commands default to the project and environment from `.vault.toml`. Override with `--project` and `--env`.

#### `vault secrets list`

List all secret keys (values are never shown).

```sh
vault secrets list
vault secrets list --project myapp --env production
```

Output: `KEY`, `VERSION`, `UPDATED`

#### `vault secrets get <KEY>`

Print a secret's current value to stdout.

```sh
vault secrets get DATABASE_URL
vault secrets get DATABASE_URL --project myapp --env production
```

#### `vault secrets set <KEY> <value>`

Create or update a secret.

```sh
vault secrets set DATABASE_URL "postgres://..."
vault secrets set API_KEY "$(cat secret.txt)"
```

Each update creates a new version. Previous versions can be listed and restored.

#### `vault secrets delete <KEY>`

Delete a secret and all its versions.

```sh
vault secrets delete OLD_KEY
```

#### `vault secrets versions <KEY>`

List all versions of a secret.

```sh
vault secrets versions DATABASE_URL
```

Output: `VER`, `ID`, `CREATED`

#### `vault secrets rollback <KEY> <version-id>`

Restore a secret to a previous version. Use `versions` to find the version ID.

```sh
vault secrets rollback DATABASE_URL 550e8400-e29b-41d4-a716-446655440000
```

#### `vault secrets import [KEY...]`

Copy secrets from another project+environment into the current one. Comments and insertion order are preserved.

```sh
# Copy all secrets from dev to current env (same project)
vault secrets import --from-env dev

# Copy specific keys only
vault secrets import --from-env dev DATABASE_URL REDIS_URL

# Cross-project copy
vault secrets import --from-project otherapp --from-env production
```

| Flag | Description |
|---|---|
| `--from-project` | Source project slug (default: current project) |
| `--from-env` | Source environment slug (required) |
| `--overwrite` | Overwrite existing secrets in destination |

#### `vault secrets upload [file]`

Parse a `.env` file and store each key as a secret. Comments and blank lines preceding each key are preserved and restored on download.

```sh
vault secrets upload .env
vault secrets upload .env --overwrite
cat .env | vault secrets upload -
vault secrets upload      # reads from stdin
```

| Flag | Description |
|---|---|
| `--overwrite` | Overwrite secrets that already exist |

#### `vault secrets download [file]`

Fetch all secrets and write them as a `.env` file, preserving insertion order and comments.

```sh
vault secrets download .env
vault secrets download .env --force   # overwrite if exists
vault secrets download                # print to stdout
vault secrets download - > .env
```

| Flag | Description |
|---|---|
| `--force` | Overwrite the output file if it already exists |

#### `vault run -- <command>`

Fetch all secrets and inject them as environment variables into a subprocess.

```sh
vault run -- npm start
vault run -- ./bin/server --port 8080
vault run --env production -- ./bin/migrate
```

Secrets override any existing environment variables with the same name. The child process replaces the vault process (Unix exec).

#### `vault export`

Print all secrets as shell `export` statements. Useful for sourcing into a shell session.

```sh
eval $(vault export)
source <(vault export)
vault export --env production > .env.local
```

---

### Members

Manage who has access to a project and at what role.

#### `vault members list <project-slug>`

```sh
vault members list myapp
```

Output: `USER ID`, `EMAIL`, `ROLE`, `ADDED`

#### `vault members add <project-slug>`

```sh
vault members add myapp --email alice@example.com --role editor
```

| Flag | Description |
|---|---|
| `--email` | User's email address (required) |
| `--role` | `viewer`, `editor`, or `owner` (default: `viewer`) |

Requires project owner role.

#### `vault members update <project-slug> <user-id>`

```sh
vault members update myapp <user-id> --role owner
```

| Flag | Description |
|---|---|
| `--role` | New role: `viewer`, `editor`, or `owner` |

Requires project owner role.

#### `vault members remove <project-slug> <user-id>`

```sh
vault members remove myapp <user-id>
```

Requires project owner role.

---

### Tokens

Machine tokens are long-lived credentials for CI/CD pipelines and automation. See [Machine Tokens](#machine-tokens) for details.

#### `vault tokens list`

```sh
vault tokens list
```

Output: `ID`, `NAME`, `PROJECT`, `EXPIRES`, `CREATED`

#### `vault tokens create <name>`

```sh
# Full-access token scoped to one env
vault tokens create deploy-prod --project myapp --env production

# Read-only token with expiry
vault tokens create ci-read --project myapp --env staging --read-only --expires-in 720h
```

| Flag | Description |
|---|---|
| `--project` | Scope to a project slug |
| `--env` | Scope to an environment within the project |
| `--read-only` | Prevent all write operations |
| `--expires-in` | TTL as Go duration (e.g. `24h`, `168h`, `30d`) |

The token value is displayed **once** at creation time. Copy it immediately — it cannot be retrieved later.

#### `vault tokens delete <id>`

Revoke a token immediately.

```sh
vault tokens delete <token-id>
```

---

### Users

Server-level user management. Requires server admin role.

#### `vault users list`

```sh
vault users list
```

Output: `ID`, `EMAIL`, `ROLE`, `CREATED`

#### `vault users create <email>`

```sh
vault users create bob@example.com
vault users create admin@example.com --role admin
```

| Flag | Description |
|---|---|
| `--role` | `member` or `admin` (default: `member`) |

Prompts for the new user's password.

#### `vault change-password`

Change the current user's password:

```sh
vault change-password
# prompts: current password, new password, confirm
```

Reset another user's password (admin only):

```sh
vault change-password --email bob@example.com
# prompts: new password, confirm
```

---

### Audit Log

The audit log records every significant action with actor, timestamp, and resource. Sensitive reads include a masked value preview (first 3 characters followed by `...`).

```sh
# Server admins: view all logs
vault audit

# Project owners: view logs for a specific project
vault audit --project myapp

# Filter by action
vault audit --project myapp --action secret.get

# Increase result limit (max 500)
vault audit --limit 200
```

| Flag | Description |
|---|---|
| `--project` | Filter by project slug (requires project owner role) |
| `--action` | Filter by action string (e.g. `secret.set`, `secret.get`) |
| `--limit` | Max entries to return, 1–500 (default: 50) |

Access rules:
- With `--project`: requires **owner** role on that project.
- Without `--project`: requires server **admin** role.

---

### Utilities

#### `vault keygen`

Generate a random master key for `VAULT_MASTER_KEY`.

```sh
vault keygen
# a64characterhexstring...
```

#### `vault version`

Print version, commit hash, and build time.

```sh
vault version
```

---

## Permissions and Roles

Vault uses a two-tier role system: server-level roles and project-level roles.

### Server-level roles

Assigned when a user account is created. The first signup on a new server is always `admin`.

| Role | Description |
|---|---|
| `admin` | Full access to all resources on the server. Implicit owner on every project. Can manage users, view all audit logs, and perform any project operation regardless of membership. |
| `member` | Regular user. Can create projects (becomes owner) and is limited to projects they are a member of. |

### Project-level roles

Assigned per-project via `vault members add/update`. Server admins bypass all project role checks.

| Role | List secrets | Read values | Write secrets | Manage members | View audit log |
|---|---|---|---|---|---|
| `viewer` | Yes | Yes | No | No | No |
| `editor` | Yes | Yes | Yes | No | No |
| `owner` | Yes | Yes | Yes | Yes | Yes |

"Write secrets" covers: `set`, `delete`, `rollback`, `import`, `upload`.

"Manage members" covers: `members add/update/remove`.

The user who creates a project is automatically its `owner`.

---

## Machine Tokens

Machine tokens are designed for non-interactive contexts such as CI/CD pipelines, deployment scripts, and automated tooling.

### Scope

A token can be scoped to a specific `project + environment` pair:

```sh
vault tokens create ci --project myapp --env production
```

A scoped token can only access secrets within that exact project and environment. It cannot create projects, manage users, or access other environments.

Tokens created without `--project`/`--env` are unscoped and can perform global operations (list projects, etc.) but are not suitable for secret access.

### Read-only mode

```sh
vault tokens create deployer --project myapp --env production --read-only
```

Read-only tokens can fetch secrets (`get`, `list`, `download`, `export`, `run`) but are rejected for any write operation (`set`, `delete`, `import`, `upload`, `rollback`).

### Expiry

```sh
vault tokens create temp --project myapp --env staging --expires-in 24h
```

Expired tokens are rejected at the server with a clear error. Common durations: `1h`, `24h`, `168h` (1 week), `720h` (30 days).

### Usage

Pass the token via the `VAULT_TOKEN` environment variable or store it in `~/.vault/config` by running `vault login` with the token as the password. In CI, inject it as a secret environment variable:

```sh
# GitHub Actions example
VAULT_TOKEN=${{ secrets.VAULT_TOKEN }} vault run -- ./deploy.sh
```
