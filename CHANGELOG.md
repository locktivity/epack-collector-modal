# Changelog

## Unreleased

- The collector is built on Go 1.26.11.

## v0.2.1

- The collector is built on epack v0.10.5.
- `workspace.id` in `artifacts/modal.details.json` is written from the audit level. A trust run writes the workspace's name only. The schema marks the ID `audit` and keeps it required for the runs that write it.
- The collector result's `targets` says what the run was pointed at: the workspace the token belongs to, at `workspace` in `artifacts/modal.details.json`, and the environments the token can see, at `environments.inventory`. An environment the run could not read in full, or a list of environments it could not read, marks the environments incomplete.

## v0.2.0

- Each run writes `artifacts/modal.access-posture.json` in the `evidencepack/access-posture@v1` format. It is built from the members, service users, and proxy auth tokens the collector already reads, so the token needs no new permission.
- In `modal.access-posture.json`, a member who signs in through SAML SSO counts as an SSO member, and every other member as signing in without SSO. Modal's API does not report whether the workspace requires SSO, so a member who signs in with GitHub or Google counts even when it does. The Owner and the Managers are the admins. `sign_in.sso_configured` is true when any member signs in through SAML SSO.
- In `modal.access-posture.json`, the service users and proxy auth tokens are the machine credentials. A credential created more than 90 days ago counts as overdue for rotation. When a credential has no creation time, `rotation_overdue_credential_count` and `rotation_overdue_pct` are left out with a `partial` gap. In a workspace without service users, a proxy auth token that works in every environment counts as unrestricted, and no credential counts as having write access.
- In `modal.access-posture.json`, `unused_credential_count` and `unused_pct` count the service users never used or last used more than 90 days ago. Modal does not report when a proxy auth token was used, so both are left out with an `unsupported` gap in a workspace with one.
- In `modal.access-posture.json`, each value Modal does not report is left out of every run with an `unsupported` gap. That gap does not make a run partial. These values are:
  - `sign_in.sso_required`, `mfa_required` and `scim_enabled`
  - MFA coverage for members and admins who sign in without SSO
  - external members
  - credentials that never expire
  - `root` and `connected_apps`. Modal has no root account.
- In `modal.access-posture.json`, the unrestricted credentials and those with write access are left out with a `not_read` gap in a workspace with service users. A service user's access comes from its role in each environment, and the collector reads roles only in restricted environments, from the audit level. A `not_read` gap does not make a run partial.
- In `modal.access-posture.json`, the counts are written from the audit level. The `*_present` flags and the percentages are written at every level. A percentage over no members or no credentials is null.
- The collector accepts the `collect` config key, which lists `access-posture`, `details`, or both. Calls that only a left-out kind needs are skipped. Before, a run with any `collect` key failed with `config_invalid`.
- The build file and `--capabilities` list `evidencepack/access-posture@v1` as the kind of evidence the collector writes.
- The collector result lists `Manager` as the permission the `modal.members.list` operation needs, at every level. A `permission_denied` gap on the members names it as before.
- The collector result lists `Manager` as the permission the `modal.service_users.list` operation needs too. Modal refuses a Member's token for that list. A `permission_denied` gap on the service users, and on the credential values in `modal.access-posture.json`, now names it.
- The detailed artifact moves from `artifacts/modal.json` to `artifacts/modal.details.json`, and `collect` lists it as `details`.
- A service user with no role in a restricted environment is left out of that environment's `roles`. Modal lists such a service user with No Access.
- With epack v0.10.0, a collector result below the audit level leaves out the tenant and the call and step counts. Its operations gain `retried`, `status_codes` and `error_codes`, and its steps gain `any_failed`, at every level.
