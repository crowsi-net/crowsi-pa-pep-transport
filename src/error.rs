use crate::digest;

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("local PEP exchange did not return a definitive signed receipt")]
pub struct WireFailure {
    evidence_digest: String,
}

impl WireFailure {
    /// Creates a disclosure-safe evidence reference from local failure material.
    #[must_use]
    pub fn from_evidence(context: &str, material: &[u8]) -> Self {
        Self {
            evidence_digest: digest::evidence(context, material),
        }
    }

    #[must_use]
    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }
}
