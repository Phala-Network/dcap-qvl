//! HTTP client abstraction used by [`crate::collateral`].
//!
//! The `HttpClient` trait keeps `reqwest` (and its types / version) out
//! of this crate's public API surface. The default-path constructors
//! ([`with_default_http`](crate::collateral::CollateralClient::<crate::configs::DefaultConfig>::with_default_http),
//! [`from_env`](crate::collateral::CollateralClient::<crate::configs::DefaultConfig>::from_env))
//! still use `reqwest` internally, but no public function signature
//! mentions `reqwest::Client` — so a future `reqwest` major bump is an
//! internal change, not a breaking one for downstream callers.
//!
//! Callers that need a custom HTTP stack (different TLS config,
//! workspace-pinned `reqwest` major, non-`reqwest` transport, wasm host
//! fetch, …) implement [`HttpClient`] on their own type and pass it to
//! [`CollateralClient::new`](crate::collateral::CollateralClient::new).
//!
//! The trait is deliberately narrow — it covers only what
//! [`crate::collateral`] needs: a `GET`, plus access to status, named
//! headers, and the response body.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use anyhow::Result;

/// Owned HTTP response.
///
/// Bodies are buffered into memory: the PCCS endpoints used by this crate
/// return small payloads (≤ a few hundred KiB), so streaming is not worth
/// the abstraction cost.
pub struct HttpResponse {
    /// HTTP status code (e.g. `200`).
    pub status: u16,
    /// Response headers. Use [`HttpResponse::header`] for
    /// case-insensitive lookups; the field itself imposes no
    /// case-normalization invariant on implementations.
    pub headers: BTreeMap<String, String>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Case-insensitive header lookup. O(n) over header count — header
    /// counts are small (typically < 20), so a linear scan is cheaper
    /// than imposing a normalization invariant on every implementation.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// `true` if [`status`](Self::status) is in `200..300`.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Decode the body as UTF-8.
    pub fn text(&self) -> Result<&str> {
        Ok(core::str::from_utf8(&self.body)?)
    }
}

/// HTTP transport used by [`CollateralClient`](crate::collateral::CollateralClient).
///
/// Implementations only need to support `GET`; the crate buffers
/// responses in memory (see [`HttpResponse`]).
///
/// The `async fn` here intentionally has no `Send` bound. Auto-traits
/// propagate through monomorphization, so callers using a `Send` impl
/// still get `Send` futures automatically; callers on single-threaded
/// runtimes don't pay the `Send` bound they don't need.
#[allow(async_fn_in_trait)]
pub trait HttpClient {
    /// Issue a GET request and buffer the full response.
    async fn get(&self, url: &str) -> Result<HttpResponse>;
}

/// Opaque `reqwest`-backed [`HttpClient`] adapter.
///
/// The type name is `pub` only so it can sit as the default `H` on
/// [`CollateralClient`](crate::collateral::CollateralClient); the inner
/// `reqwest::Client` and the constructor are crate-private. Callers
/// obtain a value only indirectly via
/// [`with_default_http`](crate::collateral::CollateralClient::<crate::configs::DefaultConfig>::with_default_http)
/// /
/// [`from_env`](crate::collateral::CollateralClient::<crate::configs::DefaultConfig>::from_env)
/// and treat it as an opaque token — `reqwest::Client` does not appear
/// in any public signature, so a future `reqwest` major bump is an
/// internal change.
#[cfg(feature = "reqwest")]
#[derive(Clone)]
pub struct ReqwestHttp(reqwest::Client);

#[cfg(feature = "reqwest")]
impl ReqwestHttp {
    pub(crate) fn new(client: reqwest::Client) -> Self {
        Self(client)
    }
}

/// Delays before each retry of a transient failure. The number of entries is
/// the retry budget, so a GET makes at most `RETRY_BACKOFF.len() + 1` attempts.
#[cfg(feature = "reqwest")]
const RETRY_BACKOFF: [core::time::Duration; 2] = [
    core::time::Duration::from_millis(200),
    core::time::Duration::from_millis(500),
];

/// `true` for failures a fresh attempt can plausibly fix: connect errors,
/// a request that failed on a stale pooled connection, or a body cut off
/// mid-transfer. Timeouts are not retried: an attempt that timed out already
/// spent the client's whole request timeout, and retrying would multiply the
/// caller's wait. Header parsing and other local errors are not retried either.
#[cfg(feature = "reqwest")]
fn is_transient(err: &anyhow::Error) -> bool {
    let Some(e) = err.downcast_ref::<reqwest::Error>() else {
        return false;
    };
    if e.is_timeout() {
        return false;
    }
    // `is_connect` does not exist on wasm32 (no connection layer).
    #[cfg(not(target_arch = "wasm32"))]
    if e.is_connect() {
        return true;
    }
    e.is_request() || e.is_body()
}

#[cfg(feature = "reqwest")]
async fn backoff_sleep(delay: core::time::Duration) {
    // No async timer is available on wasm32; retry immediately there.
    #[cfg(not(target_arch = "wasm32"))]
    tokio::time::sleep(delay).await;
    #[cfg(target_arch = "wasm32")]
    let _ = delay;
}

/// Retries transient failures (see [`is_transient`]) and HTTP 5xx responses
/// with [`RETRY_BACKOFF`]. 4xx responses and non-transient errors are returned
/// immediately. After the last attempt the final outcome is returned as is, so
/// a persistent 5xx still reaches the caller as a response.
///
/// A long-lived client can reuse an idle pooled connection that an
/// intermediary already dropped; the request then fails on send, and a retry
/// on a fresh connection succeeds.
#[cfg(feature = "reqwest")]
impl HttpClient for ReqwestHttp {
    async fn get(&self, url: &str) -> Result<HttpResponse> {
        for delay in RETRY_BACKOFF {
            match self.get_once(url).await {
                Ok(resp) if resp.status < 500 => return Ok(resp),
                Ok(resp) => log::warn!("GET {url} returned HTTP {}, retrying", resp.status),
                Err(err) if is_transient(&err) => log::warn!("GET {url} failed, retrying: {err}"),
                Err(err) => return Err(err),
            }
            backoff_sleep(delay).await;
        }
        self.get_once(url).await
    }
}

#[cfg(feature = "reqwest")]
impl ReqwestHttp {
    async fn get_once(&self, url: &str) -> Result<HttpResponse> {
        let resp = self.0.get(url).send().await?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(name, value)| {
                let v = value
                    .to_str()
                    .map_err(|e| anyhow::anyhow!("Header {name} has non-ASCII value: {e}"))?;
                Ok::<_, anyhow::Error>((name.as_str().to_string(), v.to_string()))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let body = resp.bytes().await?.to_vec();
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

// `set_linger(0)` is how the tests make the server send a TCP RST; the
// deprecation only warns about blocking on drop, which is irrelevant here.
#[cfg(all(test, feature = "reqwest"))]
#[allow(
    deprecated,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// What the test server does with one incoming connection.
    #[derive(Clone, Copy)]
    enum Reply {
        /// Accept, then abort the connection with a TCP RST.
        Reset,
        /// Answer with the given status and close the connection.
        Status(u16),
    }

    /// Spawn a local server that handles one request per connection and
    /// picks its reply from `replies[n]` for the n-th connection (the last
    /// entry repeats). Returns the base URL and the connection counter.
    async fn spawn_server(replies: Vec<Reply>) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let n = counter.fetch_add(1, Ordering::SeqCst);
                let reply = replies[n.min(replies.len() - 1)];
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                match reply {
                    Reply::Reset => {
                        stream.set_linger(Some(Duration::ZERO)).unwrap();
                        drop(stream);
                    }
                    Reply::Status(code) => {
                        let resp = format!(
                            "HTTP/1.1 {code} X\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    }
                }
            }
        });
        (url, hits)
    }

    use core::time::Duration;

    fn http() -> ReqwestHttp {
        ReqwestHttp::new(reqwest::Client::new())
    }

    #[tokio::test]
    async fn get_retries_after_connection_reset() {
        let (url, hits) = spawn_server(vec![Reply::Reset, Reply::Status(200)]).await;
        let resp = http().get(&url).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn get_retries_after_server_error() {
        let (url, hits) = spawn_server(vec![Reply::Status(503), Reply::Status(200)]).await;
        let resp = http().get(&url).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn get_does_not_retry_client_error() {
        for code in [400, 404] {
            let (url, hits) = spawn_server(vec![Reply::Status(code)]).await;
            let resp = http().get(&url).await.unwrap();
            assert_eq!(resp.status, code);
            assert_eq!(hits.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn get_gives_up_after_three_attempts_on_persistent_server_error() {
        let (url, hits) = spawn_server(vec![Reply::Status(503)]).await;
        let resp = http().get(&url).await.unwrap();
        assert_eq!(resp.status, 503);
        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn get_gives_up_after_three_attempts_on_persistent_reset() {
        let (url, hits) = spawn_server(vec![Reply::Reset]).await;
        assert!(http().get(&url).await.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }
}
