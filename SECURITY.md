# Security boundary

This repository composes two security components; it does not collapse their
trust stores, ledgers, clocks, or signing authorities.

## Required production properties

- The PA owns authorization reservation, dispatch state, receipt verification,
  and durable completion.
- The PEP owns command verification, trusted execution time, monotonic fences,
  provider CAS, and external receipt signing.
- The PEP command key and PA receipt key are separately pinned public keys.
- The local transport authenticates both peers and rejects filesystem links,
  permissive endpoints, oversized frames, timeouts, and trailing frames.
- A disconnect or invalid response becomes outcome-unknown. It is never retried
  with a newly issued authorization until reconciliation determines the result.
- Neither request nor response logs may contain subject identifiers, target
  URIs, signatures, credentials, raw provider responses, or private material.

`WireFailure` hashes local failure material under a domain separator and
returns only that digest to the PA. It is an audit correlation reference, not
proof that enforcement occurred.

## Receipt handling

The transport validates the closed receipt shape and exact request binding, but
does not replace PA trust verification. A caller must pass the returned receipt
to `PolicyAdministrator::record_receipt_v2` (or use `execute_v2`) before
considering it definitive. The PA verifies the receipt signature and all
stored command fields before advancing durable state.

The test signer is conformance-only. Production code exposes no software
signer, seed, or private-key constructor.

Report suspected boundary bypasses privately with redacted schema identifiers,
evidence digests, and fence state. Do not attach credentials or customer data.

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
