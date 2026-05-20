use thiserror::Error;

/// Error type returned by every public binding function.
///
/// The variants distinguish the broad failure category so callers can branch
/// on them in Kotlin/Swift; the inner message preserves the full anyhow chain
/// for human-readable diagnostics.
#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum DcapError {
    /// The quote, collateral, or PEM input could not be parsed.
    #[error("parse error: {0}")]
    Parse(String),

    /// Verification failed (signature, certificate chain, TCB, or QE identity).
    #[error("verification failed: {0}")]
    Verify(String),
}

impl DcapError {
    pub(crate) fn from_anyhow(e: anyhow::Error) -> Self {
        DcapError::Verify(format_error_chain(&e))
    }
}

fn format_error_chain(e: &anyhow::Error) -> String {
    let mut msg = e.to_string();
    let mut source = e.source();
    while let Some(err) = source {
        msg.push_str(": ");
        msg.push_str(&err.to_string());
        source = err.source();
    }
    msg
}
