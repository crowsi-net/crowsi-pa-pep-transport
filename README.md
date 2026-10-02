# crowsi-pa-pep-transport

Connect a policy administrator to an enforcement point through a validated control exchange.

## What you can do

- Carry the declared administration/enforcement envelopes.
- Apply bounded transport checks.

## Current scope

The deployment supplies peer trust and authorized endpoints. Transport delivery does not grant an operation.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

Install Rust 1.97 or newer and make the declared dependencies available. Use the configured private registry when a dependency is not distributed publicly. Run from this repository:

```sh
cargo test --locked
```

## Documentation and source

[Interface reference](docs/interface-reference.md)

[Usage guide](docs/getting-started.md)

[Schemas](schemas) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
