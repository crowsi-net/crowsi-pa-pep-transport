use crowsi_enforcement_point::{
    EnforcementPoint, EnforcementReceiptV2, PepExecutionLeaseV2, Result as PepResult,
};

use crate::WireFailure;

pub trait LocalPepWire {
    /// Exchanges one versioned JSON request over an authenticated local channel.
    ///
    /// # Errors
    ///
    /// Returns disclosure-safe evidence when no definitive response is available.
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, WireFailure>;
}

pub trait PepExecutor {
    /// Executes the PEP-side lease after local wire decoding.
    ///
    /// # Errors
    ///
    /// Returns a PEP validation, trust, ledger, signer, or provider failure.
    fn execute(&self, lease: &PepExecutionLeaseV2) -> PepResult<EnforcementReceiptV2>;
}

impl PepExecutor for EnforcementPoint {
    fn execute(&self, lease: &PepExecutionLeaseV2) -> PepResult<EnforcementReceiptV2> {
        EnforcementPoint::execute(self, lease)
    }
}
