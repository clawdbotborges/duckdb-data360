# DuckDB Data 360 extension — read-only foundation

This directory contains the first native DuckDB extension slice for Salesforce Data 360 Query API V3.

## Current scope

Implemented and verified:

- a loadable DuckDB extension named `data360`;
- a read-only table-function registration, `data360_query(sql, secret_name)`;
- fail-closed named-secret lookup (credentials are never accepted as SQL literals);
- a transport-independent Query API V3 client contract;
- asynchronous polling and multi-chunk traversal;
- canonical HTTPS-origin validation for exact `*.c360a.salesforce.com` DNS hosts;
- request and overall timeouts;
- best-effort remote `DELETE` with a separate maximum 250 ms cleanup budget when a local query is cancelled
  or times out;
- fail-closed query-ID and chunk-path validation, cycle detection, and bounded chunk traversal;
- Arrow-ready scalar type mappings;
- sanitized errors and dependency-injected unit tests.

Not yet implemented in the native extension:

- the concrete HTTPS transport and Query API JSON/Arrow codecs;
- registration of a `data360` secret provider backed by a Sowvi capability/token broker;
- metadata-driven DuckDB output binding and Arrow-to-vector conversion;
- live remote execution from the table function.

Until those pieces are wired, a valid named secret intentionally returns a `NotImplementedException`. The table function must not be described as a complete live connector. Live OAuth, Query API V3, JSON, Arrow IPC, 32-row fixture, and refresh-token behavior are independently proven by `../salesforce-data360-fixture/scripts/data360_oauth_smoke.py`.

## Security boundary

- Do not pass access tokens, refresh tokens, client secrets, or tenant URLs as SQL literals.
- Do not store production Salesforce credentials in ordinary persistent DuckDB secrets.
- The eventual extension must resolve a short-lived, policy-bound capability from Sowvi's control plane or token broker.
- Sowvi remains authoritative for grants, policy versions, revocation, credential policy, and usage accounting.
- Data 360 executes SQL remotely and transfers Arrow results over HTTPS. This is not storage-level zero-copy.
- Every concrete `HttpTransport` must honor `follow_redirects=false`, enforce `timeout_ms` and
  `max_response_bytes`, use the already validated request URL without reparsing ambiguities, and never
  include Authorization headers, provider bodies, or request URLs in raised errors or logs.
- Automatic retry/backoff is not implemented in this foundation. A future retry policy must be bounded,
  deadline-aware, cancellation-aware, limited to proven transient/idempotent operations, and covered by tests.

## Reproducible setup

The setup script pins DuckDB v1.5.5 and the extension build tooling by commit:

```bash
./scripts/setup.sh
```

## Build

```bash
make debug GEN=ninja
```

On macOS, the Makefile disables DuckDB's debug ASan runtime because it deadlocks during initialization on macOS 26, and sets the explicit native DuckDB platform. Other platforms retain DuckDB's normal debug configuration.

Loadable artifact:

```text
build/debug/extension/data360/data360.duckdb_extension
```

## Tests

```bash
# Transport, cancellation, timeout, tenant validation, chunks, and type mappings
ctest --test-dir build/debug/extension/data360 --output-on-failure
build/debug/extension/data360/data360_unit_tests

# DuckDB SQLLogic registration and fail-closed behavior
build/debug/test/unittest test/sql/data360_query.test

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
