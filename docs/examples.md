## Basic Usage

Counts for the workspace, at the default `trust` level:

```yaml
collectors:
  modal:
    source: locktivity/epack-collector-modal@^0.1
    secrets:
      - MODAL_TOKEN_ID
      - MODAL_TOKEN_SECRET
```

## With Inventories

At `audit`, each count has its rows beside it:

```yaml
collectors:
  modal:
    source: locktivity/epack-collector-modal@^0.1
    config:
      level: audit
    secrets:
      - MODAL_TOKEN_ID
      - MODAL_TOKEN_SECRET
```

## Example Output

For a Team workspace read with a Manager's token, at the `trust` level, `artifacts/modal.details.json` holds:

```json
{
  "schema_version": "1.0.0",
  "collected_at": "2026-10-22T12:00:00Z",
  "collected_at_level": "trust",
  "workspace": {"id": "ac-0123456789abcdefghijkl", "name": "example-workspace"},
  "members": {
    "total_count": 3,
    "owner_count": 1,
    "manager_count": 1,
    "member_count": 1,
    "sign_in": {"github_count": 1, "google_count": 2, "saml_count": 0, "other_count": 0},
    "inactive_count": 2
  },
  "environments": {"total_count": 3, "restricted_count": 1},
  "service_users": {"total_count": 2, "never_used_count": 1},
  "proxy_auth_tokens": {"total_count": 2, "unscoped_count": 1},
  "secrets": {"total_count": 3, "never_used_count": 2},
  "apps": {
    "deployed_count": 3,
    "web_endpoint_count": 2,
    "unauthenticated_endpoint_count": 1,
    "scheduled_function_count": 1
  }
}
```

For the same workspace, `artifacts/modal.access-posture.json` holds:

```json
{
  "schema_version": "1.0.0",
  "collected_at": "2026-10-22T12:00:00Z",
  "provider": "modal",
  "system_type": "platform",
  "sign_in": {"sso_configured": false},
  "members": {
    "members_present": true,
    "sso_coverage_pct": 0,
    "local_members_present": true,
    "inactive_pct": 67
  },
  "admins": {
    "admins_present": true,
    "admin_share_pct": 67,
    "local_admins_present": true
  },
  "credentials": {
    "credentials_present": true,
    "rotation_overdue_pct": 25
  }
}
```

The workspace has service users, so `unrestricted_pct` and `write_access_pct` are left out with a `not_read` gap.

With a Member's token, `members` and `service_users` are absent and `artifacts/modal.collector-result.json` has a gap for each. The access-posture artifact leaves out `sign_in`, `members`, and `admins`, and the credential counts and percentages. Each has a `permission_denied` gap. At `audit`, the detailed artifact's gap on the members is:

```json
"gaps": [
  {
    "path": "artifacts/modal.details.json",
    "pointer": "/members",
    "status": "not_collected",
    "code": "permission_denied",
    "owner": "customer",
    "vendor_code": "PERMISSION_DENIED",
    "operation": "modal.members.list",
    "call": 2,
    "source": "internal/collector/members.go:25",
    "missing_permission": "Manager",
    "warning": "Reading members needs a token that belongs to the workspace's Owner or a Manager.",
    "detail": "modal.members.list: PERMISSION_DENIED: User example-member does not have manage access to workspace example-workspace. Contact your workspace administrator to update permissions."
  }
]
```

At `audit`, a restricted environment's row lists who holds a role in it:

```json
{
  "name": "prod",
  "default": false,
  "restricted": true,
  "created_at": "2026-10-02T12:00:00Z",
  "default_member_role": "no_access",
  "blocks_unauthenticated": true,
  "roles": [
    {"principal": "member@example.com", "kind": "member", "role": "viewer"},
    {"principal": "ci-deployer", "kind": "service_user", "role": "contributor"}
  ]
}
```

A deployed app's row:

```json
{
  "name": "public-api",
  "environment": "dev",
  "state": "deployed",
  "created_at": "2026-10-19T12:00:00Z",
  "web_endpoints": 1,
  "unauthenticated_endpoints": 1,
  "scheduled_functions": 0
}
```
