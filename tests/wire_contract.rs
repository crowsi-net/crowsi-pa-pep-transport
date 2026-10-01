use crowsi_control_contracts::PepExecutionLeaseV2;
use crowsi_pa_pep_transport::{EnforcementPointV2, LocalPepWire, PepV2Transport, WireFailure};

struct StaticWire(Vec<u8>);

impl LocalPepWire for StaticWire {
    fn exchange(&mut self, _request: &[u8]) -> Result<Vec<u8>, WireFailure> {
        Ok(self.0.clone())
    }
}

#[test]
fn response_spliced_to_another_request_is_uncertain() {
    let lease = lease();
    let response = serde_json::json!({
        "schema": "crowsi://pa-pep-transport/response/v1",
        "request_id": "jti.command.v2.other",
        "receipt": serde_json::from_str::<serde_json::Value>(include_str!(
            "../../crowsi-enforcement-point/fixtures/enforcement-receipt-v2.sample.json"
        )).expect("receipt")
    });
    let mut transport =
        PepV2Transport::new(StaticWire(serde_json::to_vec(&response).expect("JSON")));

    let failure = transport
        .compare_and_swap(&lease)
        .expect_err("cross-request response");

    assert!(failure.evidence_digest().starts_with("sha256:"));
}

#[test]
fn wire_envelope_schemas_are_closed_and_versioned() {
    for (source, identifier) in [
        (
            include_str!("../schemas/pa-pep-request-v1.schema.json"),
            "crowsi://pa-pep-transport/request/v1",
        ),
        (
            include_str!("../schemas/pa-pep-response-v1.schema.json"),
            "crowsi://pa-pep-transport/response/v1",
        ),
    ] {
        let schema: serde_json::Value = serde_json::from_str(source).expect("schema");
        assert_eq!(schema["$id"], identifier);
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["required"].as_array().expect("required").len(),
            schema["properties"].as_object().expect("properties").len()
        );
    }
}

#[test]
fn oversized_local_frame_fails_before_json_decoding() {
    use crowsi_pa_pep_transport::LocalPepEndpoint;

    struct Unreachable;
    impl crowsi_pa_pep_transport::PepExecutor for Unreachable {
        fn execute(
            &self,
            _lease: &crowsi_enforcement_point::PepExecutionLeaseV2,
        ) -> crowsi_enforcement_point::Result<crowsi_enforcement_point::EnforcementReceiptV2>
        {
            panic!("oversized input must not reach PEP");
        }
    }
    let mut endpoint = LocalPepEndpoint::new(Unreachable);
    let failure = endpoint
        .exchange(&vec![b' '; 65_537])
        .expect_err("bounded frame");
    assert!(failure.evidence_digest().starts_with("sha256:"));
}

fn lease() -> PepExecutionLeaseV2 {
    serde_json::from_str(include_str!(
        "../../crowsi-policy-administrator/fixtures/conformance/v1/pep-execution-lease-v2.json"
    ))
    .expect("PA lease")
}
