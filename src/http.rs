//! HTTP client abstraction used by [`crate::collateral`].
//!
//! `dcap-qvl` ships a default [`HttpClient`] impl for [`reqwest::Client`]
//! when `feature = "reqwest"` is enabled. The trait lets downstream users
//! avoid taking a *direct* dependency on `reqwest` (and the resulting
//! version / type coupling on the public API boundary): they can
//! implement [`HttpClient`] on their own type — backed by a different
//! HTTP stack, a host-provided fetch on wasm, etc. — and pass an
//! instance to
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
/// (e.g. the built-in [`reqwest::Client`] adapter) get `Send` futures
/// automatically; callers on single-threaded runtimes don't pay the
/// `Send` bound they don't need.
#[allow(async_fn_in_trait)]
pub trait HttpClient {
    /// Issue a GET request and buffer the full response.
    async fn get(&self, url: &str) -> Result<HttpResponse>;
}

#[cfg(feature = "reqwest")]
impl HttpClient for reqwest::Client {
    async fn get(&self, url: &str) -> Result<HttpResponse> {
        let resp = reqwest::Client::get(self, url).send().await?;
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
