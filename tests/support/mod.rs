use std::sync::Arc;

use crate::pa_support::V2Fixture;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_enforcement_point::{
    EnforcementPoint, MemoryProvider, PepError, PepExecutionLeaseV2, PepLedger, ReceiptSigningPort,
    ResourceRecord, ResourceState, Result as PepResult, TrustedCommandKey, TrustedReceiptKey,
};
use ed25519_dalek::{Signer, SigningKey};

pub struct TestReceiptSigner {
    key_id: String,
    key: SigningKey,
}

impl TestReceiptSigner {
    pub fn from_seed(key_id: &str, seed: [u8; 32]) -> Self {
        Self {
            key_id: key_id.into(),
            key: SigningKey::from_bytes(&seed),
        }
    }

    fn verifying_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

impl ReceiptSigningPort for TestReceiptSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign_digest(&self, digest: &str) -> PepResult<String> {
        let bytes = decode_digest(digest)?;
        Ok(URL_SAFE_NO_PAD.encode(self.key.sign(&bytes).to_bytes()))
    }
}

pub struct FixedTimePep(pub EnforcementPoint);

impl crowsi_pa_pep_transport::PepExecutor for FixedTimePep {
    fn execute(
        &self,
        lease: &PepExecutionLeaseV2,
    ) -> PepResult<crowsi_enforcement_point::EnforcementReceiptV2> {
        self.0
            .execute_at_for_test(lease, "2026-07-29T00:02:00.000Z")
    }
}

pub fn configured_pep(fixture: &V2Fixture) -> EnforcementPoint {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../crowsi-policy-administrator/fixtures/conformance/v1/pep-command-trust-manifest-v1.json"
    ))
    .expect("public trust manifest");
    let verifier = &manifest["command_verifier"];
    assert_eq!(manifest["security_domain"], fixture.command.security_domain);
    assert_eq!(manifest["deployment_id"], fixture.command.deployment_id);
    assert_eq!(verifier["key_id"], fixture.command.signed.key_id);
    let command_key_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(verifier["public_key"].as_str().expect("public key"))
        .expect("base64url public key")
        .try_into()
        .expect("Ed25519 public key");
    let provider = Arc::new(MemoryProvider::new());
    provider
        .register(ResourceRecord {
            security_domain: fixture.command.security_domain.clone(),
            deployment_id: fixture.command.deployment_id.clone(),
            resource_uri: fixture.command.target_id.clone(),
            provider: fixture.command.provider.clone(),
            kind: crowsi_enforcement_point::ProviderKind::Incus,
            resource_version: fixture.command.expected_resource_version.clone(),
            latest_fence: fixture.command.previous_fence_epoch,
            state: ResourceState::Connected,
        })
        .expect("resource");
    let signer = Arc::new(TestReceiptSigner::from_seed("receipt.control.1", [9; 32]));
    let receipt_key =
        TrustedReceiptKey::new("receipt.control.1", signer.verifying_key()).expect("receipt key");
    let command_key = TrustedCommandKey::new(
        verifier["key_id"].as_str().expect("key id"),
        command_key_bytes,
        manifest["security_domain"]
            .as_str()
            .expect("security domain"),
        manifest["deployment_id"].as_str().expect("deployment"),
    )
    .expect("command key");
    EnforcementPoint::new(
        PepLedger::open_in_memory().expect("ledger"),
        provider,
        command_key,
        signer,
        receipt_key,
    )
    .expect("PEP")
}

fn decode_digest(value: &str) -> PepResult<[u8; 32]> {
    let hex = value.strip_prefix("sha256:").ok_or(PepError::Signature)?;
    if hex.len() != 64 {
        return Err(PepError::Signature);
    }
    let mut bytes = [0_u8; 32];
    for (index, target) in bytes.iter_mut().enumerate() {
        *target = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| PepError::Signature)?;
    }
    Ok(bytes)
}
