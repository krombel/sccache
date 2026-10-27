use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        // HTTP-based remote cache backends (excludes memcached and redis)
        any_http_remote: {
            any(
                feature = "azure",
                feature = "gcs",
                feature = "gha",
                feature = "s3",
                feature = "webdav",
                feature = "oss",
                feature = "cos"
            )
        },
        // Remote backends that use OpenDAL's Operator / RemoteStorage wrapper.
        any_opendal_remote: {
            any(
                any_http_remote,
                feature = "memcached",
                feature = "redis"
            )
        },
        // All remote cache backends (OpenDAL-backed plus direct HTTP).
        any_cache_remote: {
            any(
                any_opendal_remote,
                feature = "bazel-remote"
            )
        },
        // Distributed compilation features
        any_dist: {
            any(
                feature = "dist-client",
                feature = "dist-server"
            )
        }
    }
}
