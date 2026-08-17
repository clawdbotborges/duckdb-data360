# Third-Party Notices

This project depends on the following open-source components. Their license texts are preserved under `third_party/`:

| Component | Version/source | License location |
|---|---|---|
| Apache Arrow nanoarrow | 0.9.0 | `third_party/nanoarrow/LICENSE.txt` and `third_party/nanoarrow/NOTICE.txt` |
| FlatCC | 0.6.3 (transitive through nanoarrow IPC) | `third_party/flatcc/LICENSE` |
| curl/libcurl | resolved by pinned vcpkg baseline | `third_party/curl/LICENSE.txt` |
| OpenSSL | resolved by pinned vcpkg baseline | `third_party/openssl/LICENSE.txt` |
| zlib | resolved by pinned vcpkg baseline | `third_party/zlib/LICENSE.txt` |

The dependency graph and exact versions used for a build are controlled by `vcpkg.json` and its pinned `builtin-baseline`. DuckDB and DuckDB Extension CI Tools are development/build submodules and retain their own upstream licenses.
