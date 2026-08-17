# DuckDB Data 360 extension — read-only Arrow connector

This directory contains the first native DuckDB extension slice for Salesforce Data 360 Query API V3.

## Current scope

Implemented and verified:

- a loadable DuckDB extension named `data360`;
- a read-only table-function registration, `data360_query(sql, secret_name)`;
- fail-closed named-secret lookup (credentials are never accepted as SQL literals);
- a transport-independent Query API V3 client contract;
- asynchronous polling and lazy, incrementally bounded result-chunk traversal;
- canonical HTTPS-origin validation for exact `*.c360a.salesforce.com` DNS hosts;
- request and overall timeouts;
- best-effort remote `DELETE` with an independent 250 ms native HTTPS deadline when a local query is cancelled or
  times out;
- fail-closed query-ID and chunk-path validation, cycle detection, and bounded chunk traversal;
- Arrow-ready scalar type mappings;
- sanitized errors and dependency-injected unit tests.
- S256 PKCE browser authorization through a fixed loopback callback;
- a temporary, non-serializable `oauth_pkce` secret backed by process-memory credentials;
- concrete TLS-verified HTTPS with redirects refused and bounded responses;
- Query API V3 submission-ID recovery from Salesforce response headers;
- authoritative precision/scale-driven DuckDB decimal binding;
- native Arrow transport for numbered Query API V3 result chunks, with direct Arrow-to-DuckDB vector output;
- lazy JSON fallback for the legacy direct-response shape;
- a bounded native Arrow IPC stream decoder and Arrow-to-DuckDB vector converter, verified against synthetic
  multi-batch and empty streams;
- live verification against the 32-row, 29-column synthetic Data 360 fixture.

Not yet implemented:

- production Sowvi control-plane capability issuance;
- signed Community Extension publication and live-gated Salesforce packaging proof;
- predicate/projection pushdown beyond SQL explicitly supplied to `data360_query`;
- bounded retry/backoff for proven transient and idempotent operations.

The live numbered Query API V3 path requests native Arrow stream chunks and converts them directly into DuckDB vectors.
The legacy direct-response shape retains its bounded lazy JSON fallback. Arrow compression is intentionally disabled and
compressed streams fail closed.
The decoder requires an exact `application/vnd.apache.arrow.stream` media type, validates the independent stream schema,
enforces a body cap before its owned input allocation, retains at most one record batch, emits vector-sized chunks, and
rejects truncation and trailing bytes with sanitized errors. A protocol EOS marker is accepted but not required: a clean
end-of-body immediately after a complete IPC message is also valid, matching the live provider stream.
DuckDB requires output names and types during binding. With no separate Data 360 describe endpoint currently wired,
bind submits the read-only query and retrieves only its authoritative metadata; it does not download result chunks.
Execution creates a fresh query during global scan initialization without downloading a result chunk. The single-threaded
scan fetches and validates one bounded Arrow response at a time, retaining only that response and one decoded record batch
while it fills DuckDB vectors. Legacy direct responses retain one bounded JSON chunk at a time.

## Security boundary

- Do not pass access tokens, refresh tokens, client secrets, or tenant URLs as SQL literals.
- Do not store production Salesforce credentials in ordinary persistent DuckDB secrets.
- Community authentication uses native HTTPS and Authorization Code with S256 PKCE. The extension is a public OAuth
  client, contains no client secret, and does not invoke a credential subprocess, Python, Salesforce CLI, or a curl
  executable.
- Credential bytes remain in a database-instance registry. The temporary named secret contains only an opaque session
  reference and non-sensitive provider metadata; it cannot be persisted or supplied directly through SQL.
- Sowvi remains authoritative for grants, policy versions, revocation, credential policy, and usage accounting.
- Data 360 executes SQL remotely and transfers results over HTTPS. This is not storage-level zero-copy.
- Every concrete `HttpTransport` must honor `follow_redirects=false`, enforce `timeout_ms` and
  `max_response_bytes`, use the already validated request URL without reparsing ambiguities, and never
  include Authorization headers, provider bodies, or request URLs in raised errors or logs.
- Automatic retry/backoff is not implemented. A future retry policy must be bounded,
  deadline-aware, cancellation-aware, limited to proven transient/idempotent operations, and covered by tests.

## Reproducible setup

The setup script pins DuckDB v1.5.5 and the extension build tooling by commit:

```bash
./scripts/setup.sh
```

## Build

```bash
make debug GEN=ninja \
  VCPKG_TOOLCHAIN_PATH="$PWD/vcpkg/scripts/buildsystems/vcpkg.cmake"
```

The manifest pins vcpkg baseline `94a541197763a4f449a1b91478df48c0584a6256`, nanoarrow `0.9.0` with its `ipc`
feature, and transitive FlatCC `0.6.3`. The local `vcpkg/` checkout and build cache are development artifacts and are
not source dependencies.

On macOS, the Makefile disables DuckDB's debug ASan runtime because it deadlocks during initialization on macOS 26, and sets the explicit native DuckDB platform. Other platforms retain DuckDB's normal debug configuration.

Loadable artifact:

```text
build/debug/extension/data360/data360.duckdb_extension
```

## Tests

```bash
# Transport, cancellation, timeout, tenant validation, cursor/chunk bounds, scan-adapter vectors, and type mappings
ctest --test-dir build/debug/extension/data360 --output-on-failure
build/debug/extension/data360/data360_unit_tests
build/debug/extension/data360/data360_scan_tests
build/debug/extension/data360/data360_arrow_ipc_tests

# DuckDB SQLLogic registration and fail-closed query/authentication behavior
build/debug/test/unittest test/sql/data360_query.test
build/debug/test/unittest test/sql/data360_auth.test

# Manual load proof
build/debug/duckdb -unsigned -csv -c \
  "LOAD 'build/debug/extension/data360/data360.duckdb_extension';
   SELECT function_type
   FROM duckdb_functions()
   WHERE function_name = 'data360_query';"
```

Expected registration result:

```text
function_type
table
```

## Development interactive query

Start an interactive authorization session, open the returned authorization URL in a browser on the same computer,
complete the callback, and query with the temporary secret name:

```sql
SELECT * FROM data360_auth_start(
    'https://your-org.my.salesforce.com',
    '<public-external-client-app-id>',
    'data360_dev'
);

SELECT * FROM data360_auth_status('<auth_id>');
SELECT * FROM data360_auth_complete('<auth_id>');

SELECT *
FROM data360_query(
    'SELECT * FROM Your_Data_Lake_Object__dll LIMIT 32',
    'data360_dev'
);
```

The callback is fixed at `http://127.0.0.1:8910/oauth/callback`. Authentication does not launch a browser or external
program. Persistent `data360` secrets and caller-created credential-bearing secrets are rejected. See
[`docs/community-authentication.md`](docs/community-authentication.md) for the complete contract and setup requirements.
