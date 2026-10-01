use crowsi_control_contracts::{EnforcementReceiptV2, PepExecutionLeaseV2, Validate};
use crowsi_policy_administrator::{EnforcementPointV2, PepExecutionUncertainV2};

use crate::{
    LocalPepWire, WireFailure, binding,
    model::{
        MAX_WIRE_BYTES, REQUEST_SCHEMA_V1, RESPONSE_SCHEMA_V1, RequestEnvelope, ResponseEnvelope,
    },
};

pub struct PepV2Transport<W> {
    wire: W,
}

impl<W> PepV2Transport<W> {
    #[must_use]
    pub const fn new(wire: W) -> Self {
        Self { wire }
    }

    #[must_use]
    pub fn into_inner(self) -> W {
        self.wire
    }
}

impl<W: LocalPepWire> EnforcementPointV2 for PepV2Transport<W> {
    fn compare_and_swap(
        &mut self,
        lease: &PepExecutionLeaseV2,
    ) -> Result<EnforcementReceiptV2, PepExecutionUncertainV2> {
        let request = RequestEnvelope {
            schema: REQUEST_SCHEMA_V1.into(),
            request_id: lease.command.jti.clone(),
            lease,
        };
        let encoded = serde_json::to_vec(&request)
            .map_err(|error| uncertain("request-json", error.to_string().as_bytes()))?;
        if encoded.len() > MAX_WIRE_BYTES {
            return Err(uncertain("request-size", &encoded.len().to_be_bytes()));
        }
        let response = self
            .wire
            .exchange(&encoded)
            .map_err(|error| from_failure(&error))?;
        if response.len() > MAX_WIRE_BYTES {
            return Err(uncertain("response-size", &response.len().to_be_bytes()));
        }
        let envelope: ResponseEnvelope<EnforcementReceiptV2> = serde_json::from_slice(&response)
            .map_err(|error| uncertain("response-json", error.to_string().as_bytes()))?;
        if envelope.schema != RESPONSE_SCHEMA_V1
            || envelope.request_id != lease.command.jti
            || envelope.receipt.validate().is_err()
            || !binding::exact(lease, &envelope.receipt)
        {
            return Err(uncertain("response-binding", &response));
        }
        Ok(envelope.receipt)
    }
}

fn from_failure(value: &WireFailure) -> PepExecutionUncertainV2 {
    PepExecutionUncertainV2::new(value.evidence_digest())
        .expect("WireFailure always contains a valid SHA-256 evidence digest")
}

fn uncertain(context: &str, material: &[u8]) -> PepExecutionUncertainV2 {
    from_failure(&WireFailure::from_evidence(context, material))
}
