# Community authentication

> **Release status:** The development extension implements the public `data360_auth_*` SQL functions, native token exchanges, and metadata-only session secret described here. Signed Community Extension publication and live-gated Salesforce packaging proof remain pending; a local development build must not be presented as a published community artifact.

## Intended audience and trust model

Community v1 is for a person running DuckDB locally on macOS, Linux, or Windows who can open a browser on the same computer. It uses a direct trust path:

```text
DuckDB extension -> Salesforce OAuth -> Salesforce Data 360
```

The extension is a public OAuth client. It uses Authorization Code with S256 PKCE and does **not** contain a client secret. Salesforce authenticates the user and the Salesforce organization controls app approval and Data 360 permissions.

A future `sowvi` provider has a different trust model:

```text
DuckDB extension -> governed Sowvi issuer -> short-lived, policy-bound capability
```

In that model Sowvi remains authoritative for grants, policy versions, revocation, query scope, limits, and accounting; Salesforce refresh credentials remain server-side. The Sowvi provider is **pending** and is not the community-v1 direct login.

## Availability at a glance

| Capability | Status |
|---|---|
| Read-only `data360_query(remote_sql, secret_name)` and bounded Arrow/JSON query transport | Implemented in the current development extension |
| External credential processes, Python, Salesforce CLI, and curl executable | Not used by the community runtime |
| S256 PKCE primitives and fixed-loopback components | Implemented and component-tested in the development extension |
| `data360_auth_start`, `data360_auth_status`, `data360_auth_complete`, `data360_auth_cancel` | Implemented and registered in the development extension |
| Native Salesforce code exchange and `/services/a360/token` exchange | Implemented; live-gated proof remains pending |
| Temporary metadata-only secret backed by process-memory credentials | Implemented in the development extension |
| `INSTALL data360 FROM community` signed artifact | Pending Community Extension publication |
| Governed/headless Sowvi provider and service-account provider | Future work |

## Salesforce administrator setup

An administrator must install or approve the packaged Salesforce External Client App (ECA), or configure an equivalent organization-approved public OAuth client. Before publication, the official ECA packaging and callback behavior must be proven with Salesforce; do not advertise an unverified client ID.

Configure the application as follows:

1. Enable OAuth Authorization Code flow.
2. Require PKCE and permit S256 only.
3. Register the callback **exactly** as `http://127.0.0.1:8910/oauth/callback`.
4. Treat the application as a public client: no client secret is supplied to DuckDB.
5. Grant only `api` and `cdp_query_api` for community v1. Do not grant or request `refresh_token`/`offline_access`.
6. Apply the organization's permitted-user/admin-approval policy.
7. Ensure My Domain, SSO, and the users' Data 360 permissions are configured. Users need access to the queried Data 360 objects and Query API; OAuth approval does not grant data access by itself.
8. Distribute the public client ID as non-secret application metadata. Never distribute a client secret.

The callback is fixed because Salesforce callback matching is exact. The extension binds `127.0.0.1:8910` before returning an authorization URL and must not silently choose another, unregistered port.

## Install and load

After the signed extension is published, the intended public installation is:

```sql
INSTALL data360 FROM community;
LOAD data360;
```

Until publication, use the repository's development build and load commands. A locally built unsigned artifact requires DuckDB's development-only unsigned-extension mode; that mode is not the public installation path. Community signing establishes artifact provenance and DuckDB compatibility, not a security review or Salesforce approval.

## Interactive login

The following SQL is the development extension contract.

```sql
-- 1. Start a process-local authorization session.
SELECT *
FROM data360_auth_start(
  'https://acme.my.salesforce.com',
  '<public-external-client-app-id>',
  'data360_prod'
);
```

The result contains a random process-local `auth_id`, an `authorization_url`, the fixed `callback_url`, an expiry, and status `PENDING_USER_ACTION`. The client ID is public metadata. The authorization URL can be copied to a browser on the **same computer**; it contains public routing values, a PKCE challenge, and random state, but no client secret, verifier, authorization code, or bearer token. Do not log or paste the full URL into tickets.

```sql
-- 2. Poll locally; this makes no provider request.
SELECT * FROM data360_auth_status('<auth_id>');

-- 3. After the browser redirects to localhost, finish the bounded exchanges.
SELECT * FROM data360_auth_complete('<auth_id>');
```

`data360_auth_status` reports only a safe state: `PENDING_USER_ACTION`, `CALLBACK_RECEIVED`, `AUTHORIZED`, `ACCESS_DENIED`, `EXPIRED`, `CANCELLED`, or `FAILED`. `data360_auth_complete` returns `PENDING_USER_ACTION` if no callback has arrived. Otherwise it validates the callback, exchanges the authorization code with Salesforce, exchanges the Salesforce access token at `/services/a360/token`, and creates/replaces the named temporary session secret.

```sql
-- 4. Query with the name, never with credential material.
SELECT *
FROM data360_query(
  'SELECT * FROM "My_Data_Lake_Object__dll" LIMIT 100',
  'data360_prod'
);

-- Optional: terminate an unfinished authorization session.
SELECT data360_auth_cancel('<auth_id>');
```

Cancellation, expiry, or completion closes the loopback listener. A query must never trigger a browser login automatically.

## Credential lifetime and privacy

Community v1 intentionally provides a temporary login:

- `state`, the PKCE verifier, authorization code, Salesforce access token, Data 360 capability, and validated tenant URL remain in process memory for the shortest practical lifetime.
- No refresh token is requested or stored.
- The intended DuckDB secret is temporary and non-serializable. It contains only an opaque session reference and non-sensitive provider metadata; credential bytes remain in a database-instance registry.
- Closing DuckDB, replacing the secret, cancelling authentication, or session expiry destroys the registry entry. A new DuckDB process requires a new browser approval.
- No operating-system credential store, encrypted credential file, credential subprocess, Python, Salesforce CLI, or shell-opened browser is part of community v1.
- Standard C++ storage does not justify a claim of guaranteed memory zeroization. The design minimizes copies, lifetime, and diagnostics instead.
- Query results cross TLS-verified HTTPS and are decoded into DuckDB vectors. This is not storage-level zero-copy.

Never put a token, authorization code, verifier, client secret, full authorization URL, provider response, or credential-bearing tenant URL in SQL, command-line arguments, environment variables, files, screenshots, logs, or support requests.

## Headless and remote systems

Direct loopback login is not a headless authentication flow. The browser must run on the host whose `127.0.0.1:8910` listener DuckDB opened. SSH port forwarding, containers, remote notebooks, browser automation, and copying the URL to a different computer are not supported community-v1 workarounds and can violate the callback and user-presence assumptions.

For automation, wait for the governed Sowvi HTTPS provider or an administrator-approved client-credentials provider with a reviewed host secret-injection boundary. Neither is currently available. Do not add an executable path, command template, shell interpolation, or client secret to SQL or an ordinary persistent DuckDB secret.

## Stable faults

The intended local fault contract is `fault_protocol_version = 1`. Expected states are returned as structured rows; invalid calls and internal failures use sanitized DuckDB exceptions. User-visible output must contain a stable code and safe guidance, never provider bodies or credential material.

| Code | Name | Operator action |
|---|---|---|
| `D360-AUTH-001` | `INVALID_LOGIN_ORIGIN` | Use the exact HTTPS Salesforce/My Domain origin. |
| `D360-AUTH-002` | `INVALID_CLIENT_ID` | Use the administrator-provided public ECA client ID. |
| `D360-AUTH-003` | `CALLBACK_PORT_UNAVAILABLE` | Free TCP port 8910 and retry; the extension cannot choose another port. |
| `D360-AUTH-004` | `CALLBACK_PROTOCOL_ERROR` | Restart login; do not replay or edit the callback. |
| `D360-AUTH-005` | `STATE_MISMATCH` | Cancel/restart login and investigate unexpected callback traffic. |
| `D360-AUTH-006` | `USER_DENIED` | Restart only if the user intends to approve access. |
| `D360-AUTH-007` | `SESSION_EXPIRED` | Start a new authorization session. |
| `D360-AUTH-008` | `NETWORK_UNAVAILABLE` | Check DNS/firewall connectivity and retry. |
| `D360-AUTH-009` | `TLS_FAILURE` | Fix trust/time/interception issues; never disable TLS verification. |
| `D360-AUTH-010` | `TOKEN_EXCHANGE_FAILED` | Restart login; ask the admin to verify ECA configuration. |
| `D360-AUTH-011` | `DATA360_EXCHANGE_FAILED` | Verify Data 360 enablement and user permissions. |
| `D360-AUTH-012` | `ORG_POLICY_DENIED` | Ask the Salesforce admin to approve the user/app. |
| `D360-AUTH-013` | `SECRET_NAME_INVALID` | Choose a valid, non-sensitive secret name. |
| `D360-AUTH-014` | `PERSISTENCE_FORBIDDEN` | Use the temporary session secret created by auth completion. |
| `D360-AUTH-015` | `AUTH_SESSION_NOT_FOUND` | Use an auth ID from this DuckDB process or restart login. |
| `D360-AUTH-016` | `AUTH_SESSION_LIMIT_REACHED` | Complete/cancel an active session, then retry. |
| `D360-AUTH-017` | `REAUTH_REQUIRED` | Start a new browser authorization; there is no refresh token. |
| `D360-AUTH-018` | `UNSUPPORTED_PLATFORM` | Use a platform published in the extension support matrix. |

## Troubleshooting

### The browser cannot reach the callback

Confirm the browser is on the same machine as DuckDB and that local firewall/security software permits DuckDB to listen on `127.0.0.1:8910`. Do not change the callback URL or expose the port on a public interface.

### `CALLBACK_PORT_UNAVAILABLE`

Find and stop the local process using TCP port 8910, or cancel another active Data 360 login. Retry `data360_auth_start`; do not select a random port because it is not the registered callback.

### Login succeeds in the browser but status remains pending

Check that Salesforce redirected to the exact callback path and that no proxy, container boundary, remote browser, or security product intercepted localhost. If the session expired, cancel it and start again. Share only the stable fault code with support.

### Salesforce denies access or Data 360 exchange fails

Ask the administrator to verify ECA installation/approval, `api` and `cdp_query_api` scopes, My Domain/SSO policy, Data 360 enablement, and object/query permissions. Do not paste Salesforce error descriptions or response bodies into support channels.

### Query returns `REAUTH_REQUIRED`

The short-lived capability expired or Salesforce returned an authentication failure. Start a new interactive login. Automatic renewal is intentionally unavailable because community v1 has no refresh token.

All HTTP 401 responses from Query API submission, status, metadata, and chunk requests map to the exact stable
`D360-AUTH-017 REAUTH_REQUIRED: Authorization is required` message without including the response body. HTTP 403
remains a generic query failure unless its bounded JSON body has the exact provider `errorCode`
`INVALID_SESSION_ID`, either as a top-level object or the sole object in an array. This conservative distinction
prevents policy and data-access denials such as `INSUFFICIENT_ACCESS` from being misreported as expired authorization.

### Development build has no `data360_auth_*` functions

The loaded artifact is stale or came from a build that predates community authentication integration. Rebuild the loadable extension, load that exact artifact, and verify the registered functions before troubleshooting Salesforce configuration.

## Continuous integration

The active monorepo workflow is [`.github/workflows/data360-community-auth.yml`](../../../.github/workflows/data360-community-auth.yml). It is path-filtered to this extension, runs release builds and tests on Linux x86_64, macOS arm64, and Windows x86_64 from this directory, exercises both SQLLogic suites, scans runtime source for prohibited executable/process dependencies, runs the redaction-bearing CTest suite, and runs a redacted repository secret scan with a checksum-verified standalone Gitleaks CLI that requires no organization license. It uploads each platform's loadable extension artifact. There is no nested workflow copy because GitHub only discovers workflows under the repository-root `.github/workflows/` directory.
