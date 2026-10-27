# bazel-remote

sccache can store cache entries in a
[bazel-remote](https://github.com/buchgr/bazel-remote) HTTP cache.

bazel-remote's HTTP API is not WebDAV. Pointing `SCCACHE_WEBDAV_ENDPOINT` at a
bazel-remote instance will not work. Use this backend instead.

## How it works

sccache cache keys are already 64-character lowercase hex digests, which
bazel-remote accepts as action-cache keys. The serialized cache entry is stored
as a CAS blob under the SHA-256 of its bytes. An `ActionResult` in the action
cache points at that CAS digest.

No bazel-remote flags are required. In particular, leave
`--disable_http_ac_validation` unset; sccache uploads a valid `ActionResult`.

## Configuration

Set `SCCACHE_BAZEL_REMOTE_ENDPOINT` to the HTTP base URL of the server:

```bash
export SCCACHE_BAZEL_REMOTE_ENDPOINT=http://127.0.0.1:8080
```

Or in a config file:

```toml
[cache.bazel_remote]
endpoint = "http://127.0.0.1:8080"
```

Optional settings:

- `instance` / `SCCACHE_BAZEL_REMOTE_INSTANCE` — REAPI instance name used as a
  URL path prefix (for example `main` → `/main/ac/<key>`).
- `username` / `password` or `SCCACHE_BAZEL_REMOTE_USERNAME` /
  `SCCACHE_BAZEL_REMOTE_PASSWORD` — HTTP basic authentication.
- `rw_mode` / `SCCACHE_BAZEL_REMOTE_RW_MODE` — `READ_ONLY` or `READ_WRITE`
  (default).

In a multi-level chain, the backend name is `bazel-remote`.
