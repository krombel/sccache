// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! HTTP cache backend for [bazel-remote](https://github.com/buchgr/bazel-remote).
//!
//! Entries are stored as CAS blobs keyed by the SHA-256 of their bytes. The
//! sccache blake3 cache key is stored in the action cache as an `ActionResult`
//! that points at that CAS digest.

use std::io::Cursor;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use reqwest::StatusCode;
use sha2::{Digest as Sha2Digest, Sha256};

use crate::cache::{Cache, CacheMode, CacheRead, CacheWrite, Storage};
use crate::errors::*;
use crate::util::new_reqwest_client_builder;

/// Always-present empty CAS blob; used for the read half of [`BazelRemoteCache::check`].
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Path used inside the ActionResult `OutputFile` that points at the CAS entry.
const ENTRY_PATH: &str = "sccache-entry";

/// Fixed CAS blob written during a read-write capability check.
const CHECK_BLOB: &[u8] = b"sccache-bazel-remote-check";

/// A cache that stores entries in a bazel-remote HTTP server.
pub struct BazelRemoteCache {
    client: reqwest::Client,
    endpoint: String,
    instance: String,
    username: Option<String>,
    password: Option<String>,
    rw_mode: CacheMode,
    basedirs: Vec<Vec<u8>>,
    skip_cache_check: bool,
}

impl BazelRemoteCache {
    pub fn build(
        endpoint: &str,
        instance: Option<&str>,
        username: Option<&str>,
        password: Option<&str>,
        rw_mode: CacheMode,
        basedirs: Vec<Vec<u8>>,
    ) -> Result<Self> {
        let instance = instance.unwrap_or("").trim_matches('/').to_owned();
        validate_instance(&instance)?;

        let endpoint = endpoint.trim_end_matches('/').to_owned();
        if endpoint.is_empty() {
            bail!("bazel-remote endpoint must not be empty");
        }

        let client = new_reqwest_client_builder()?.build()?;

        Ok(Self {
            client,
            endpoint,
            instance,
            username: username.map(str::to_owned).filter(|s| !s.is_empty()),
            password: password.map(str::to_owned).filter(|s| !s.is_empty()),
            rw_mode,
            basedirs,
            skip_cache_check: false,
        })
    }

    pub fn with_skip_cache_check(mut self, skip_cache_check: bool) -> Self {
        self.skip_cache_check = skip_cache_check;
        self
    }

    fn url(&self, kind: &str, hash: &str) -> String {
        if self.instance.is_empty() {
            format!("{}/{}/{}", self.endpoint, kind, hash)
        } else {
            format!("{}/{}/{}/{}", self.endpoint, self.instance, kind, hash)
        }
    }

    fn apply_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match (&self.username, &self.password) {
            (Some(user), Some(pass)) => req.basic_auth(user, Some(pass)),
            (Some(user), None) => req.basic_auth(user, None::<&str>),
            _ => req,
        }
    }

    async fn get_bytes(&self, kind: &str, hash: &str) -> Result<Option<Bytes>> {
        let url = self.url(kind, hash);
        let req = self
            .apply_auth(self.client.get(&url))
            .header(reqwest::header::ACCEPT_ENCODING, "identity");
        let resp = req.send().await.context("bazel-remote GET failed")?;
        match resp.status() {
            StatusCode::OK => {
                let bytes = resp.bytes().await.context("bazel-remote GET body")?;
                Ok(Some(bytes))
            }
            StatusCode::NOT_FOUND => Ok(None),
            status => {
                let body = resp.text().await.unwrap_or_default();
                bail!("bazel-remote GET {url} returned {status}: {body}")
            }
        }
    }

    async fn put_bytes(&self, kind: &str, hash: &str, data: Bytes) -> Result<()> {
        let url = self.url(kind, hash);
        let len = data.len();
        let req = self
            .apply_auth(self.client.put(&url))
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .header(reqwest::header::CONTENT_LENGTH, len.to_string())
            .body(data);
        let resp = req.send().await.context("bazel-remote PUT failed")?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("bazel-remote PUT {url} returned {status}: {body}")
        }
    }

    async fn fetch_entry(&self, key: &str) -> Result<Option<Bytes>> {
        validate_ac_key(key)?;
        let Some(ar_bytes) = self.get_bytes("ac", key).await? else {
            return Ok(None);
        };
        let digest = match decode_entry_digest(&ar_bytes) {
            Ok(d) => d,
            Err(e) => {
                warn!("bazel-remote: ignoring invalid ActionResult for {key}: {e:#}");
                return Ok(None);
            }
        };
        let Some(entry) = self.get_bytes("cas", &digest.hash).await? else {
            debug!(
                "bazel-remote: ActionResult for {key} points at missing CAS {}",
                digest.hash
            );
            return Ok(None);
        };
        if entry.len() as i64 != digest.size_bytes {
            warn!(
                "bazel-remote: CAS {} size mismatch: expected {}, got {}",
                digest.hash,
                digest.size_bytes,
                entry.len()
            );
            return Ok(None);
        }
        Ok(Some(entry))
    }
}

#[async_trait]
impl Storage for BazelRemoteCache {
    async fn get(&self, key: &str) -> Result<Cache> {
        Ok(self.get_with_raw(key).await?.0)
    }

    async fn get_with_raw(&self, key: &str) -> Result<(Cache, Option<Bytes>)> {
        match self.fetch_entry(key).await? {
            Some(data) => {
                let hit = CacheRead::from(Cursor::new(data.clone()))?;
                Ok((Cache::Hit(hit), Some(data)))
            }
            None => Ok((Cache::Miss, None)),
        }
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        let data = entry.finish()?;
        self.put_raw(key, data.into()).await
    }

    async fn get_raw(&self, key: &str) -> Result<Option<Bytes>> {
        self.fetch_entry(key).await
    }

    async fn put_raw(&self, key: &str, data: Bytes) -> Result<Duration> {
        if self.rw_mode == CacheMode::ReadOnly {
            bail!("storage is read-only");
        }
        validate_ac_key(key)?;
        let start = Instant::now();

        let hash = sha256_hex(&data);
        let size_bytes = data.len() as i64;
        self.put_bytes("cas", &hash, data).await?;

        let ar = encode_action_result(&Digest { hash, size_bytes });
        self.put_bytes("ac", key, Bytes::from(ar)).await?;

        Ok(start.elapsed())
    }

    async fn check(&self) -> Result<CacheMode> {
        if self.skip_cache_check {
            debug!(
                "bazel-remote storage check skipped; using configured cache mode: {:?}",
                self.rw_mode
            );
            return Ok(self.rw_mode);
        }

        // The empty CAS blob is always present on a real bazel-remote server.
        // A miss here usually means the endpoint or instance prefix is wrong.
        match self.get_bytes("cas", EMPTY_SHA256).await {
            Ok(Some(_)) => (),
            Ok(None) => bail!(
                "bazel-remote cache read check failed: empty CAS blob not found at {}",
                self.url("cas", EMPTY_SHA256)
            ),
            Err(e) => bail!("bazel-remote cache read check failed: {e:#}"),
        }

        if self.rw_mode == CacheMode::ReadOnly {
            return Ok(CacheMode::ReadOnly);
        }

        let hash = sha256_hex(CHECK_BLOB);
        let can_write = match self
            .put_bytes("cas", &hash, Bytes::from_static(CHECK_BLOB))
            .await
        {
            Ok(()) => true,
            Err(err) => {
                eprintln!("bazel-remote storage write check failed: {err:#}");
                false
            }
        };

        Ok(if can_write {
            CacheMode::ReadWrite
        } else {
            CacheMode::ReadOnly
        })
    }

    fn location(&self) -> String {
        if self.instance.is_empty() {
            format!("bazel-remote, endpoint: {}", self.endpoint)
        } else {
            format!(
                "bazel-remote, endpoint: {}, instance: {}",
                self.endpoint, self.instance
            )
        }
    }

    fn cache_type_name(&self) -> &'static str {
        "bazel-remote"
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    fn basedirs(&self) -> &[Vec<u8>] {
        &self.basedirs
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Digest {
    hash: String,
    size_bytes: i64,
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn validate_ac_key(key: &str) -> Result<()> {
    if is_hex64(key) {
        Ok(())
    } else {
        bail!("bazel-remote action-cache key must be 64 lowercase hex characters, got {key:?}")
    }
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn validate_instance(instance: &str) -> Result<()> {
    if instance.is_empty() {
        return Ok(());
    }
    for part in instance.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            bail!(
                "bazel-remote instance must not contain empty, '.' or '..' path segments: {instance:?}"
            );
        }
    }
    Ok(())
}

fn encode_action_result(digest: &Digest) -> Vec<u8> {
    let mut output_file = Vec::new();
    write_bytes_field(&mut output_file, 1, ENTRY_PATH.as_bytes());
    write_bytes_field(&mut output_file, 2, &encode_digest(digest));

    let mut ar = Vec::new();
    write_bytes_field(&mut ar, 2, &output_file);
    ar
}

fn encode_digest(digest: &Digest) -> Vec<u8> {
    let mut out = Vec::new();
    write_bytes_field(&mut out, 1, digest.hash.as_bytes());
    write_varint_field(&mut out, 2, digest.size_bytes as u64);
    out
}

fn decode_entry_digest(ar_bytes: &[u8]) -> Result<Digest> {
    let mut cursor = 0;
    while cursor < ar_bytes.len() {
        let (tag, next) = read_varint(ar_bytes, cursor)?;
        cursor = next;
        let field = (tag >> 3) as u32;
        let wire = (tag & 0x7) as u8;
        match (field, wire) {
            (2, 2) => {
                let (len, next) = read_varint(ar_bytes, cursor)?;
                cursor = next;
                let end = cursor
                    .checked_add(len as usize)
                    .context("ActionResult output_files length overflow")?;
                if end > ar_bytes.len() {
                    bail!("ActionResult output_files truncated");
                }
                let file = &ar_bytes[cursor..end];
                cursor = end;
                if let Some(digest) = decode_output_file(file)? {
                    return Ok(digest);
                }
            }
            (_, 0) => {
                let (_, next) = read_varint(ar_bytes, cursor)?;
                cursor = next;
            }
            (_, 1) => {
                cursor = cursor.checked_add(8).context("skipping fixed64 overflow")?;
            }
            (_, 2) => {
                let (len, next) = read_varint(ar_bytes, cursor)?;
                cursor = next
                    .checked_add(len as usize)
                    .context("skipping length-delimited overflow")?;
            }
            (_, 5) => {
                cursor = cursor.checked_add(4).context("skipping fixed32 overflow")?;
            }
            _ => bail!("unsupported protobuf wire type {wire} in ActionResult"),
        }
    }
    bail!("ActionResult has no {ENTRY_PATH} output file")
}

fn decode_output_file(bytes: &[u8]) -> Result<Option<Digest>> {
    let mut cursor = 0;
    let mut path: Option<&[u8]> = None;
    let mut digest: Option<Digest> = None;
    while cursor < bytes.len() {
        let (tag, next) = read_varint(bytes, cursor)?;
        cursor = next;
        let field = (tag >> 3) as u32;
        let wire = (tag & 0x7) as u8;
        match (field, wire) {
            (1, 2) => {
                let (len, next) = read_varint(bytes, cursor)?;
                cursor = next;
                let end = cursor + len as usize;
                if end > bytes.len() {
                    bail!("OutputFile path truncated");
                }
                path = Some(&bytes[cursor..end]);
                cursor = end;
            }
            (2, 2) => {
                let (len, next) = read_varint(bytes, cursor)?;
                cursor = next;
                let end = cursor + len as usize;
                if end > bytes.len() {
                    bail!("OutputFile digest truncated");
                }
                digest = Some(decode_digest(&bytes[cursor..end])?);
                cursor = end;
            }
            (_, 0) => {
                let (_, next) = read_varint(bytes, cursor)?;
                cursor = next;
            }
            (_, 1) => cursor += 8,
            (_, 2) => {
                let (len, next) = read_varint(bytes, cursor)?;
                cursor = next + len as usize;
            }
            (_, 5) => cursor += 4,
            _ => bail!("unsupported protobuf wire type {wire} in OutputFile"),
        }
    }
    if path == Some(ENTRY_PATH.as_bytes()) {
        digest
            .ok_or_else(|| anyhow!("OutputFile {ENTRY_PATH} missing digest"))
            .map(Some)
    } else {
        Ok(None)
    }
}

fn decode_digest(bytes: &[u8]) -> Result<Digest> {
    let mut cursor = 0;
    let mut hash = None;
    let mut size_bytes = None;
    while cursor < bytes.len() {
        let (tag, next) = read_varint(bytes, cursor)?;
        cursor = next;
        let field = (tag >> 3) as u32;
        let wire = (tag & 0x7) as u8;
        match (field, wire) {
            (1, 2) => {
                let (len, next) = read_varint(bytes, cursor)?;
                cursor = next;
                let end = cursor + len as usize;
                if end > bytes.len() {
                    bail!("Digest hash truncated");
                }
                hash = Some(
                    std::str::from_utf8(&bytes[cursor..end])
                        .context("Digest hash is not UTF-8")?
                        .to_owned(),
                );
                cursor = end;
            }
            (2, 0) => {
                let (v, next) = read_varint(bytes, cursor)?;
                cursor = next;
                size_bytes = Some(v as i64);
            }
            (_, 0) => {
                let (_, next) = read_varint(bytes, cursor)?;
                cursor = next;
            }
            (_, 1) => cursor += 8,
            (_, 2) => {
                let (len, next) = read_varint(bytes, cursor)?;
                cursor = next + len as usize;
            }
            (_, 5) => cursor += 4,
            _ => bail!("unsupported protobuf wire type {wire} in Digest"),
        }
    }
    let hash = hash.context("Digest missing hash")?;
    if !is_hex64(&hash) {
        bail!("Digest hash is not 64 lowercase hex characters: {hash:?}");
    }
    let size_bytes = size_bytes.context("Digest missing size_bytes")?;
    Ok(Digest { hash, size_bytes })
}

fn write_bytes_field(buf: &mut Vec<u8>, field: u32, value: &[u8]) {
    write_varint(buf, ((field as u64) << 3) | 2);
    write_varint(buf, value.len() as u64);
    buf.extend_from_slice(value);
}

fn write_varint_field(buf: &mut Vec<u8>, field: u32, value: u64) {
    write_varint(buf, (field as u64) << 3); // wire type 0 (varint)
    write_varint(buf, value);
}

fn write_varint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
            buf.push(byte);
        } else {
            buf.push(byte);
            break;
        }
    }
}

fn read_varint(buf: &[u8], mut cursor: usize) -> Result<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        if cursor >= buf.len() {
            bail!("truncated protobuf varint");
        }
        let byte = buf[cursor];
        cursor += 1;
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, cursor));
        }
        shift += 7;
        if shift >= 64 {
            bail!("protobuf varint too long");
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cache::CacheWrite;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn action_result_round_trip() {
        let digest = Digest {
            hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            size_bytes: 42,
        };
        let encoded = encode_action_result(&digest);
        assert_eq!(decode_entry_digest(&encoded).unwrap(), digest);
    }

    #[test]
    fn action_result_ignores_execution_metadata() {
        let digest = Digest {
            hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            size_bytes: 7,
        };
        let mut encoded = encode_action_result(&digest);
        // Append ActionResult.execution_metadata (field 9) as an empty message.
        write_bytes_field(&mut encoded, 9, b"");
        assert_eq!(decode_entry_digest(&encoded).unwrap(), digest);
    }

    #[test]
    fn validate_instance_rejects_dot_segments() {
        assert!(validate_instance("ok").is_ok());
        assert!(validate_instance("a/b").is_ok());
        assert!(validate_instance(".").is_err());
        assert!(validate_instance("..").is_err());
        assert!(validate_instance("a/../b").is_err());
        assert!(validate_instance("a/./b").is_err());
    }

    #[test]
    fn empty_sha256_matches_constant() {
        assert_eq!(sha256_hex(b""), EMPTY_SHA256);
    }

    struct MockServer {
        base_url: String,
        state: Arc<Mutex<MockState>>,
        _join: Option<thread::JoinHandle<()>>,
    }

    #[derive(Default)]
    struct MockState {
        cas: HashMap<String, Vec<u8>>,
        ac: HashMap<String, Vec<u8>>,
        read_only: bool,
        require_content_length: bool,
    }

    impl MockServer {
        fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let state = Arc::new(Mutex::new(MockState {
                require_content_length: true,
                ..Default::default()
            }));
            // Empty blob is always present, like bazel-remote.
            state
                .lock()
                .unwrap()
                .cas
                .insert(EMPTY_SHA256.to_owned(), Vec::new());

            let state_clone = Arc::clone(&state);
            let join = thread::spawn(move || {
                listener.set_nonblocking(false).unwrap();
                for stream in listener.incoming().flatten() {
                    let _ = handle_connection(stream, &state_clone);
                }
            });

            Self {
                base_url: format!("http://{addr}"),
                state,
                _join: Some(join),
            }
        }

        fn set_read_only(&self, read_only: bool) {
            self.state.lock().unwrap().read_only = read_only;
        }

        fn drop_cas(&self, hash: &str) {
            self.state.lock().unwrap().cas.remove(hash);
        }

        fn drop_empty_cas(&self) {
            self.drop_cas(EMPTY_SHA256);
        }
    }

    fn handle_connection(
        mut stream: std::net::TcpStream,
        state: &Arc<Mutex<MockState>>,
    ) -> std::io::Result<()> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = stream.read(&mut tmp)?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(header_end) = find_header_end(&buf) {
                let header = String::from_utf8_lossy(&buf[..header_end]).into_owned();
                let mut lines = header.split("\r\n");
                let request_line = lines.next().unwrap_or("");
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or("").to_owned();
                let path = parts.next().unwrap_or("").to_owned();

                let mut content_length: Option<usize> = None;
                for line in lines {
                    let lower = line.to_ascii_lowercase();
                    if let Some(v) = lower.strip_prefix("content-length:") {
                        content_length = v.trim().parse().ok();
                    }
                }

                let body_start = header_end + 4;
                let body_len = content_length.unwrap_or(0);
                while buf.len() < body_start + body_len {
                    let n = stream.read(&mut tmp)?;
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                let body = buf[body_start..body_start + body_len].to_vec();

                let response = dispatch(&method, &path, content_length, &body, state);
                stream.write_all(&response)?;
                return Ok(());
            }
        }
    }

    fn find_header_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n")
    }

    fn dispatch(
        method: &str,
        path: &str,
        content_length: Option<usize>,
        body: &[u8],
        state: &Arc<Mutex<MockState>>,
    ) -> Vec<u8> {
        let path = path.split('?').next().unwrap_or(path);
        let Some((kind, hash)) = parse_blob_path(path) else {
            return http_text(400, "bad path");
        };
        if !is_hex64(hash) {
            return http_text(400, "bad hash");
        }

        let mut st = state.lock().unwrap();
        match method {
            "GET" => {
                let map = if kind == "cas" { &st.cas } else { &st.ac };
                match map.get(hash) {
                    Some(data) => http_bytes(200, data),
                    None => http_text(404, "Not found"),
                }
            }
            "PUT" => {
                if st.read_only {
                    return http_text(401, "read-only");
                }
                if st.require_content_length && content_length.is_none() {
                    return http_text(400, "missing Content-Length");
                }
                if kind == "cas" {
                    let actual = sha256_hex(body);
                    if actual != hash {
                        return http_text(400, "hash mismatch");
                    }
                    st.cas.insert(hash.to_owned(), body.to_vec());
                    http_text(200, "ok")
                } else {
                    match decode_entry_digest(body) {
                        Ok(_) => {
                            // Mimic bazel-remote: rewrite the ActionResult with
                            // ExecutedActionMetadata (field 9) before storing.
                            let mut stored = body.to_vec();
                            write_bytes_field(&mut stored, 9, b"");
                            st.ac.insert(hash.to_owned(), stored);
                            http_text(200, "ok")
                        }
                        Err(e) => http_text(400, &format!("invalid ActionResult: {e:#}")),
                    }
                }
            }
            "HEAD" => {
                let map = if kind == "cas" { &st.cas } else { &st.ac };
                if map.contains_key(hash) {
                    http_text(200, "")
                } else {
                    http_text(404, "Not found")
                }
            }
            _ => http_text(405, "method not allowed"),
        }
    }

    fn parse_blob_path(path: &str) -> Option<(&str, &str)> {
        let path = path.trim_start_matches('/');
        let parts: Vec<&str> = path.split('/').collect();
        match parts.as_slice() {
            [kind, hash] if *kind == "ac" || *kind == "cas" => Some((*kind, *hash)),
            [_, kind, hash] if *kind == "ac" || *kind == "cas" => Some((*kind, *hash)),
            _ => None,
        }
    }

    fn http_text(status: u16, body: &str) -> Vec<u8> {
        http_bytes(status, body.as_bytes())
    }

    fn http_bytes(status: u16, body: &[u8]) -> Vec<u8> {
        let reason = match status {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            405 => "Method Not Allowed",
            _ => "Error",
        };
        let mut out = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn sample_key() -> &'static str {
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }

    #[test]
    fn put_get_round_trip() {
        let server = MockServer::start();
        let cache = BazelRemoteCache::build(
            &server.base_url,
            None,
            None,
            None,
            CacheMode::ReadWrite,
            Vec::new(),
        )
        .unwrap();
        let rt = runtime();

        let entry = CacheWrite::new();
        let data = entry.finish().unwrap();
        rt.block_on(cache.put_raw(sample_key(), Bytes::from(data.clone())))
            .unwrap();

        let (result, raw) = rt.block_on(cache.get_with_raw(sample_key())).unwrap();
        assert!(matches!(result, Cache::Hit(_)));
        assert_eq!(raw.unwrap().as_ref(), data.as_slice());
    }

    #[test]
    fn miss_on_missing_action_result() {
        let server = MockServer::start();
        let cache = BazelRemoteCache::build(
            &server.base_url,
            None,
            None,
            None,
            CacheMode::ReadWrite,
            Vec::new(),
        )
        .unwrap();
        let rt = runtime();
        let (result, raw) = rt.block_on(cache.get_with_raw(sample_key())).unwrap();
        assert!(matches!(result, Cache::Miss));
        assert!(raw.is_none());
    }

    #[test]
    fn miss_on_dangling_cas() {
        let server = MockServer::start();
        let cache = BazelRemoteCache::build(
            &server.base_url,
            None,
            None,
            None,
            CacheMode::ReadWrite,
            Vec::new(),
        )
        .unwrap();
        let rt = runtime();

        let data = CacheWrite::new().finish().unwrap();
        let cas_hash = sha256_hex(&data);
        rt.block_on(cache.put_raw(sample_key(), Bytes::from(data)))
            .unwrap();
        server.drop_cas(&cas_hash);

        let (result, _) = rt.block_on(cache.get_with_raw(sample_key())).unwrap();
        assert!(matches!(result, Cache::Miss));
    }

    #[test]
    fn read_only_rejects_puts() {
        let server = MockServer::start();
        let cache = BazelRemoteCache::build(
            &server.base_url,
            None,
            None,
            None,
            CacheMode::ReadOnly,
            Vec::new(),
        )
        .unwrap();
        let rt = runtime();
        let err = rt
            .block_on(cache.put_raw(sample_key(), Bytes::from_static(b"x")))
            .unwrap_err();
        assert!(err.to_string().contains("read-only"));
    }

    #[test]
    fn check_detects_read_only_server() {
        let server = MockServer::start();
        server.set_read_only(true);
        let cache = BazelRemoteCache::build(
            &server.base_url,
            None,
            None,
            None,
            CacheMode::ReadWrite,
            Vec::new(),
        )
        .unwrap();
        let rt = runtime();
        assert_eq!(rt.block_on(cache.check()).unwrap(), CacheMode::ReadOnly);
    }

    #[test]
    fn check_read_write_ok() {
        let server = MockServer::start();
        let cache = BazelRemoteCache::build(
            &server.base_url,
            None,
            None,
            None,
            CacheMode::ReadWrite,
            Vec::new(),
        )
        .unwrap();
        let rt = runtime();
        assert_eq!(rt.block_on(cache.check()).unwrap(), CacheMode::ReadWrite);
    }

    #[test]
    fn check_fails_when_empty_cas_missing() {
        let server = MockServer::start();
        server.drop_empty_cas();
        let cache = BazelRemoteCache::build(
            &server.base_url,
            None,
            None,
            None,
            CacheMode::ReadWrite,
            Vec::new(),
        )
        .unwrap();
        let rt = runtime();
        let err = rt.block_on(cache.check()).unwrap_err();
        assert!(
            err.to_string().contains("empty CAS blob not found"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn skip_cache_check_uses_configured_mode() {
        let cache = BazelRemoteCache::build(
            "http://127.0.0.1:1",
            None,
            None,
            None,
            CacheMode::ReadOnly,
            Vec::new(),
        )
        .unwrap()
        .with_skip_cache_check(true);
        let rt = runtime();
        assert_eq!(rt.block_on(cache.check()).unwrap(), CacheMode::ReadOnly);
    }

    #[test]
    fn instance_prefix_round_trip() {
        let server = MockServer::start();
        let cache = BazelRemoteCache::build(
            &server.base_url,
            Some("main"),
            None,
            None,
            CacheMode::ReadWrite,
            Vec::new(),
        )
        .unwrap();
        let rt = runtime();
        let data = CacheWrite::new().finish().unwrap();
        rt.block_on(cache.put_raw(sample_key(), Bytes::from(data.clone())))
            .unwrap();
        let raw = rt.block_on(cache.get_raw(sample_key())).unwrap().unwrap();
        assert_eq!(raw.as_ref(), data.as_slice());
    }

    #[test]
    fn rejects_non_hex_key() {
        let server = MockServer::start();
        let cache = BazelRemoteCache::build(
            &server.base_url,
            None,
            None,
            None,
            CacheMode::ReadWrite,
            Vec::new(),
        )
        .unwrap();
        let rt = runtime();
        let err = rt
            .block_on(cache.put_raw("not-a-hash", Bytes::from_static(b"x")))
            .unwrap_err();
        assert!(err.to_string().contains("64 lowercase hex"));
    }
}
