# DuckDB Data 360 extension — read-only JSON connector

This directory contains the first native DuckDB extension slice for Salesforce Data 360 Query API V3.

## Current scope

Implemented and verified:

- a loadable DuckDB extension named `data360`;
- a read-only table-function registration, `data360_query(sql, secret_name)`;
- fail-closed named-secret lookup (credentials are never accepted as SQL literals);
- a transport-independent Query API V3 client contract;
- asynchronous polling and lazy, incrementally bounded JSON-chunk traversal;
- canonical HTTPS-origin validation for exact `*.c360a.salesforce.com` DNS hosts;
- request and overall timeouts;
- best-effort remote `DELETE` with an independent 250 ms curl/process deadline when a local query is cancelled or
  times out; final operating-system process reaping occurs after that deadline and is not represented as a strict
  end-to-end wall-clock maximum;
- fail-closed query-ID and chunk-path validation, cycle detection, and bounded chunk traversal;
- Arrow-ready scalar type mappings;
- sanitized errors and dependency-injected unit tests.
- a temporary, non-serializable `data360` secret provider;
- a trusted process-local capability broker boundary;
- concrete TLS-verified HTTPS with redirects refused and bounded responses;
- Query API V3 submission-ID recovery from Salesforce response headers;
- metadata-driven DuckDB binding and one-chunk-at-a-time typed JSON-row vector output;
- a bounded native Arrow IPC stream decoder and Arrow-to-DuckDB vector converter, verified against synthetic
  multi-batch and empty streams;
- live verification against the 32-row, 29-column synthetic Data 360 fixture.

Not yet implemented:

- Query API transport wiring and live parity for the native Arrow decoder; the live table-function path remains on
  lazy JSON chunks;

- provider precision/scale-driven decimal binding; the current `numeric` alias maps conservatively to `DECIMAL(38,18)`;
- production Sowvi control-plane capability issuance (the current Python broker is development-local);
- predicate/projection pushdown beyond SQL explicitly supplied to `data360_query`;
- bounded retry/backoff for proven transient and idempotent operations.

The live connector currently uses Query API JSON chunks. The extension now contains a native nanoarrow-based decoder
and direct Arrow-to-DuckDB converter, but it is exercised only with deterministic synthetic IPC streams until transport
wiring and live parity are complete. Arrow compression is intentionally disabled and compressed streams fail closed.
The decoder requires an exact `application/vnd.apache.arrow.stream` media type, validates the independent stream schema,
enforces a body cap before its owned input allocation, retains at most one record batch, emits vector-sized chunks, and
rejects truncation and any bytes left after the protocol EOS marker with sanitized errors.
DuckDB requires output names and types during binding. With no separate Data 360 describe endpoint currently wired,
bind submits the read-only query and retrieves only its authoritative metadata; it does not download result chunks.
Execution creates a fresh query during global scan initialization without downloading a result chunk. The single-threaded
scan fetches and validates one non-empty bounded JSON chunk at a time, retaining only the current remote chunk while it
fills DuckDB vectors.

## Security boundary

- Do not pass access tokens, refresh tokens, client secrets, or tenant URLs as SQL literals.
- Do not store production Salesforce credentials in ordinary persistent DuckDB secrets.
- The development extension resolves a short-lived capability from a validated user-owned Python broker configured
  through `SOWVI_DATA360_BROKER_PATH`. SQL cannot select the broker. The broker is opened with `O_NOFOLLOW`, checked
  by descriptor, read through that descriptor, and supplied over stdin to the fixed root-owned `/usr/bin/python3`.
  Production must replace this bridge with a
  policy-bound Sowvi capability issuer.
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

## Development live query

Configure the broker path in the DuckDB process environment, create a temporary process secret containing only the
Salesforce login origin, and query with the secret name:

```sql
CREATE SECRET data360_dev (
    TYPE data360,
    PROVIDER process,
    LOGIN_URL 'https://your-org.my.salesforce.com'
);

SELECT *
FROM data360_query(
    'SELECT * FROM Your_Data_Lake_Object__dll LIMIT 32',
    'data360_dev'
);
```

Persistent `data360` secrets and SQL-supplied broker paths are rejected.
