use crowsi_enforcement_point::PepExecutionLeaseV2;

use crate::{
    LocalPepWire, PepExecutor, WireFailure,
    model::{
        MAX_WIRE_BYTES, REQUEST_SCHEMA_V1, RESPONSE_SCHEMA_V1, RequestEnvelope, ResponseEnvelope,
    },
};

pub struct LocalPepEndpoint<E> {
    executor: E,
}

impl<E> LocalPepEndpoint<E> {
    #[must_use]
    pub const fn new(executor: E) -> Self {
        Self { executor }
    }

    #[must_use]
    pub fn into_inner(self) -> E {
        self.executor
    }
}

impl<E: PepExecutor> LocalPepWire for LocalPepEndpoint<E> {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, WireFailure> {
        if request.len() > MAX_WIRE_BYTES {
            return Err(failure("request-size", &request.len().to_be_bytes()));
        }
        let envelope: RequestEnvelope<PepExecutionLeaseV2> = serde_json::from_slice(request)
            .map_err(|error| failure("request-json", error.to_string().as_bytes()))?;
        if envelope.schema != REQUEST_SCHEMA_V1 || envelope.request_id != envelope.lease.command.jti
        {
            return Err(failure("request-binding", request));
        }
        let receipt = self
            .executor
            .execute(&envelope.lease)
            .map_err(|error| failure("pep-execution", error.to_string().as_bytes()))?;
        let response = ResponseEnvelope {
            schema: RESPONSE_SCHEMA_V1.into(),
            request_id: envelope.request_id,
            receipt,
        };
        let encoded = serde_json::to_vec(&response)
            .map_err(|error| failure("response-json", error.to_string().as_bytes()))?;
        if encoded.len() > MAX_WIRE_BYTES {
            Err(failure("response-size", &encoded.len().to_be_bytes()))
        } else {
            Ok(encoded)
        }
    }
}

fn failure(context: &str, material: &[u8]) -> WireFailure {
    WireFailure::from_evidence(context, material)
}
