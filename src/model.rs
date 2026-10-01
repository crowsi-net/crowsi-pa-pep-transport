use serde::{Deserialize, Serialize};

pub const REQUEST_SCHEMA_V1: &str = "crowsi://pa-pep-transport/request/v1";
pub const RESPONSE_SCHEMA_V1: &str = "crowsi://pa-pep-transport/response/v1";
pub const MAX_WIRE_BYTES: usize = 65_536;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestEnvelope<T> {
    pub schema: String,
    pub request_id: String,
    pub lease: T,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResponseEnvelope<T> {
    pub schema: String,
    pub request_id: String,
    pub receipt: T,
}
