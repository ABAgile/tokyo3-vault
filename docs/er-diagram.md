# Entity Relationship Diagram

> Source: [`internal/model/model.go`](../internal/model/model.go)

> **Note on `AUDIT_LOG`**: this entity lives in a physically separate audit database (see `AUDIT_DATABASE_URL` / `AUDIT_WRITE_DATABASE_URL`), not in the main vault DB. Its `actor_id`, `project_id`, and `env_id` columns are plain TEXT — there are no enforced foreign keys. Relationship arrows to PROJECT, ENVIRONMENT, and TOKEN are logical documentation only. Schema is managed by `internal/audit/migrations/` and applied by `vaultd audit-consumer` at startup.

```mermaid
erDiagram
    USER {
        string id         PK
        string email
        string role       "admin | member"
        time   created_at
    }
    TOKEN {
        string id         PK
        string user_id    FK "→ USER; nil = machine token without owner"
        string project_id FK "nil = unscoped"
        string env_id     FK "nil = unscoped"
        string name
        string token_hash
        bool   read_only
        time   expires_at
        time   created_at
    }
    CERT_PRINCIPAL {
        string id          PK
        string user_id     FK "owner"
        string project_id  FK "nil = any project"
        string env_id      FK "nil = any env"
        string spiffe_id   "URI SAN"
        string description
        bool   read_only
        time   expires_at
        time   created_at
    }
    PROJECT {
        string id            PK
        string name
        string slug
        bytes  encrypted_pek "wrapped by server KEK; nil until migrated"
        time   created_at
    }
    ENVIRONMENT {
        string id         PK
        string project_id FK
        string name
        string slug
        time   created_at
    }
    PROJECT_MEMBER {
        string project_id FK
        string user_id    FK
        string env_id     FK "nil = project-level; non-nil = env-scoped"
        string role       "viewer | editor | owner"
        time   created_at
    }
    SECRET {
        string id                  PK
        string project_id          FK
        string env_id              FK
        string key
        string comment             "text preceding key in .env"
        int    position            "insertion order"
        string current_version_id  FK "→ SECRET_VERSION; nullable"
        time   created_at
        time   updated_at
    }
    SECRET_VERSION {
        string id              PK
        string secret_id       FK
        bytes  encrypted_value
        bytes  encrypted_dek
        int    version
        string created_by      FK "→ TOKEN; nullable"
        time   created_at
    }
    AUDIT_LOG {
        string id         PK
        string action     "e.g. secret.set"
        string actor_id   "TOKEN id; no FK — separate audit DB"
        string project_id "PROJECT id; no FK — separate audit DB"
        string env_id     "ENVIRONMENT id; no FK — nullable"
        string resource   "nullable"
        string metadata   "free-form JSON; nullable"
        string ip         "nullable"
        time   created_at
    }
    DYNAMIC_BACKEND {
        string id                  PK
        string project_id          FK
        string env_id              FK
        string slug                "unique per project + env"
        string type                "e.g. postgresql"
        bytes  encrypted_config
        bytes  encrypted_config_dek
        int    default_ttl         "seconds"
        int    max_ttl             "seconds"
        time   created_at
        time   updated_at
    }
    DYNAMIC_ROLE {
        string id              PK
        string backend_id      FK
        string name
        string creation_tmpl
        string revocation_tmpl
        int    ttl             "nil = use backend default_ttl"
        time   created_at
    }
    DYNAMIC_LEASE {
        string id              PK
        string project_id      FK
        string env_id          FK
        string backend_id      FK "denorm — survives backend deletion"
        string role_id         FK "denorm — survives role deletion"
        string role_name       "snapshot at issuance"
        string username
        string revocation_tmpl "snapshot at issuance"
        time   expires_at
        time   revoked_at      "nil = active"
        string created_by      FK "→ TOKEN; nullable"
        time   created_at
    }

    USER             ||--o{ TOKEN           : "owns"
    USER             ||--o{ CERT_PRINCIPAL  : "registers"
    USER             ||--o{ PROJECT_MEMBER  : "is member"

    PROJECT          ||--o{ ENVIRONMENT     : "contains"
    PROJECT          ||--o{ PROJECT_MEMBER  : "has"
    PROJECT          ||--o{ SECRET          : "stores"
    PROJECT          ||--o{ DYNAMIC_BACKEND : "configures"
    PROJECT          ||--o{ DYNAMIC_LEASE   : "tracks"
    PROJECT          ||--o{ AUDIT_LOG       : "logged under (logical ref only)"
    ENVIRONMENT      ||--o{ AUDIT_LOG       : "scoped to (logical ref only)"
    PROJECT          }o--o{ TOKEN           : "scopes (optional)"
    PROJECT          }o--o{ CERT_PRINCIPAL  : "scopes (optional)"

    ENVIRONMENT      ||--o{ SECRET          : "stores"
    ENVIRONMENT      ||--o{ DYNAMIC_BACKEND : "configures"
    ENVIRONMENT      ||--o{ DYNAMIC_LEASE   : "tracks"
    ENVIRONMENT      }o--o{ PROJECT_MEMBER  : "scopes (optional)"
    ENVIRONMENT      }o--o{ TOKEN           : "scopes (optional)"
    ENVIRONMENT      }o--o{ CERT_PRINCIPAL  : "scopes (optional)"

    SECRET           ||--|{ SECRET_VERSION  : "has versions"
    SECRET           |o--o| SECRET_VERSION  : "current version"

    TOKEN            ||--o{ SECRET_VERSION  : "creates"
    TOKEN            ||--o{ DYNAMIC_LEASE   : "creates"
    TOKEN            ||--o{ AUDIT_LOG       : "actor in (logical ref only)"

    DYNAMIC_BACKEND  ||--|{ DYNAMIC_ROLE    : "defines"
    DYNAMIC_BACKEND  ||--o{ DYNAMIC_LEASE   : "issued via"
    DYNAMIC_ROLE     ||--o{ DYNAMIC_LEASE   : "template for"
```
