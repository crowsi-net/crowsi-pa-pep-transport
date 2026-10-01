use sha2::{Digest, Sha256};

pub(crate) fn evidence(context: &str, material: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"crowsi-pa-pep-transport-evidence-v1\0");
    hasher.update(context.as_bytes());
    hasher.update([0]);
    hasher.update(material);
    format!("sha256:{:x}", hasher.finalize())
}
