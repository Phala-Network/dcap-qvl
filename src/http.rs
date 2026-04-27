//! HTTP client abstraction used by [`crate::collateral`].
//!
//! `dcap-qvl` ships a default [`HttpClient`] impl on [`reqwest::Client`]
//! (gated by `feature = "reqwest"`). Downstream users who can't depend on
//! `reqwest` (e.g. workspaces with their own HTTP stack, or wasm targets
//! using a host-provided fetch) can implement [`HttpClient`] on their own
//! type and pass an instance to
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
    /// Response headers. Names MUST be stored lower-cased so
    /// [`HttpResponse::header`] can perform case-insensitive lookups
    /// without re-walking the map. Implementations are responsible for
    /// lower-casing on insertion.
    pub headers: BTreeMap<String, String>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Case-insensitive header lookup.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
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
        let mut headers = BTreeMap::new();
        for (name, value) in resp.headers() {
            if let Ok(v) = value.to_str() {
                headers.insert(name.as_str().to_ascii_lowercase(), v.to_string());
            }
        }
        let body = resp.bytes().await?.to_vec();
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}
