# crowsi-pa-pep-transport interface reference

Use the [usage guide](getting-started.md) for the first steps. This reference preserves the current interface details and operational limits. Run command examples from the repository root, after preparing the exact declared dependencies and registered configuration.

## Flow

1. The PA durably reserves and begins one v2 execution lease.
2. `PepV2Transport` places that lease in the closed request-v1 JSON envelope.
3. An authenticated `LocalPepWire` carries the bytes to `LocalPepEndpoint`.
4. The endpoint decodes the PEP's independently released lease type.
5. The PEP verifies its public PA trust manifest, fences, applies provider CAS,
   and delegates receipt signing to its external signing port.
6. The endpoint returns the signed receipt in response-v1 JSON.
7. The transport enforces exact lease/receipt binding.
8. The PA verifies the independently pinned receipt key and durably records the
   receipt.

The integration test performs the entire
`reserve_v2 → begin_execution_v2 → JSON → PEP → JSON → record_receipt_v2`
sequence. The PA and PEP use their separate Rust wire models, so the test
detects schema drift that a shared in-memory type would hide.

## Production boundary

`LocalPepWire` is deliberately transport-agnostic. A production implementation
must authenticate the local peer, constrain the endpoint path and permissions,
bound message sizes and deadlines, and treat disconnects as outcome-unknown.
The provided `LocalPepEndpoint` is an in-process composition adapter; it makes
no socket, network, provider, or credential calls by itself.

The library contains no private key and no software signer. The PEP's
`ReceiptSigningPort` remains the only receipt-signing boundary and must
terminate at an HSM, TPM, or credential broker in production. Test-only
signing material stays under `tests/`.

The two transport envelopes are versioned and closed:

- `crowsi://pa-pep-transport/request/v1`
- `crowsi://pa-pep-transport/response/v1`

Unknown fields, schema versions, request bindings, malformed payloads, and
cross-command responses fail closed to PA `PepExecutionUncertainV2` evidence.
