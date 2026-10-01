#[path = "../../crowsi-policy-administrator/tests/support/mod.rs"]
mod pa_support;
mod support;

use crowsi_control_contracts::EnforcementOutcome;
use crowsi_enforcement_point::ResourceState;
use crowsi_pa_pep_transport::{
    EnforcementPointV2, LocalPepEndpoint, LocalPepWire, PepExecutor, PepV2Transport,
};
use pa_support::V2Fixture;
use support::{FixedTimePep, TestReceiptSigner, configured_pep};

#[test]
fn pa_reservation_crosses_json_pep_wire_and_receipt_returns_to_pa() {
    let fixture = V2Fixture::new().expect("PA fixture");
    let mut administrator = fixture.administrator().expect("PA");
    administrator
        .reserve_v2(&fixture.reservation())
        .expect("durable reservation");
    let lease = administrator
        .begin_execution_v2(&fixture.command.jti)
        .expect("actual PA lease");
    let pep = configured_pep(&fixture);
    let endpoint = LocalPepEndpoint::new(FixedTimePep(pep));
    let mut transport = PepV2Transport::new(endpoint);

    let receipt = transport.compare_and_swap(&lease).expect("signed receipt");
    let status = administrator
        .record_receipt_v2(&receipt)
        .expect("durable PA receipt");

    assert_eq!(receipt.outcome, EnforcementOutcome::Applied);
    assert_eq!(receipt.command_jti, lease.command.jti);
    assert_eq!(receipt.command_digest, lease.command_digest);
    assert_eq!(receipt.fence_epoch, lease.command.fence_epoch);
    assert_eq!(receipt.binding, lease.command.binding);
    assert!(receipt.authorization_consumed);
    assert_eq!(status.state, "applied");
    assert_eq!(status.outcome.as_deref(), Some("applied"));
}

#[test]
fn local_endpoint_rejects_an_unknown_request_field() {
    let fixture = V2Fixture::new().expect("PA fixture");
    let mut endpoint = LocalPepEndpoint::new(FixedTimePep(configured_pep(&fixture)));
    let mut value = serde_json::json!({
        "schema": "crowsi://pa-pep-transport/request/v1",
        "request_id": "jti.command.v2.1",
        "lease": serde_json::from_str::<serde_json::Value>(include_str!(
            "../../crowsi-policy-administrator/fixtures/conformance/v1/pep-execution-lease-v2.json"
        )).expect("lease")
    });
    value["unexpected"] = serde_json::json!(true);

    let failure = endpoint
        .exchange(&serde_json::to_vec(&value).expect("JSON"))
        .expect_err("closed request");

    assert!(failure.evidence_digest().starts_with("sha256:"));
}

#[test]
fn production_surface_has_no_software_receipt_signer() {
    fn assert_executor<T: PepExecutor>() {}
    assert_executor::<FixedTimePep>();
    let source = concat!(
        include_str!("../src/lib.rs"),
        include_str!("../src/binding.rs"),
        include_str!("../src/client.rs"),
        include_str!("../src/digest.rs"),
        include_str!("../src/endpoint.rs"),
        include_str!("../src/error.rs"),
        include_str!("../src/model.rs"),
        include_str!("../src/port.rs")
    );
    assert!(!source.contains("SigningKey"));
    assert!(!source.contains("from_seed"));
    assert!(!source.contains("private_key"));
    let _ = TestReceiptSigner::from_seed("receipt.control.1", [9; 32]);
    let _ = ResourceState::Connected;
}
