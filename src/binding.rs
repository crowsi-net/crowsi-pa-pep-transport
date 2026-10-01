use crowsi_control_contracts::{EnforcementReceiptV2, PepExecutionLeaseV2};

pub(crate) fn exact(lease: &PepExecutionLeaseV2, receipt: &EnforcementReceiptV2) -> bool {
    let command = &lease.command;
    receipt.command_jti == command.jti
        && receipt.command_digest == lease.command_digest
        && receipt.security_domain == command.security_domain
        && receipt.deployment_id == command.deployment_id
        && receipt.incident_id == command.incident_id
        && receipt.target_id == command.target_id
        && receipt.release_reservation_id == command.release_reservation_id
        && receipt.fence_epoch == command.fence_epoch
        && receipt.binding == command.binding
        && receipt.provider == command.provider
        && receipt.expected_resource_version == command.expected_resource_version
        && receipt.authorization_consumed
}
