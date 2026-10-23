use crate::detection::{DetectionEngine, DetectionReport};
use crate::engine::{ScanConfig, ScanEngine, SignatureDatabase};
use crate::rules::{RuleBundle, RuleDisposition, RuleEngine, RulePolicy};
use crate::similarity::{SimilarityEngine, SimilarityProfile, MIN_SKETCH_BYTES, SKETCH_SIZE};
use crate::updater::{
    verify_update, ActiveUpdate, SignedUpdateEnvelope, UpdateError, UpdateStore, MAX_ENVELOPE_BYTES,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

pub const DEFINITION_SCHEMA_VERSION: u32 = 2;
pub const COMPACT_DEFINITION_SCHEMA_VERSION: u32 = 3;

pub const MAX_DEFINITION_BUNDLE_BYTES: usize = 16 * 1024 * 1024;

pub const MAX_DEFINITION_PAYLOAD_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_COMPACT_SHA256_SIGNATURES: usize = 8_000_000;
pub const MAX_EXACT_SIGNATURES: usize = 100_000;
pub const MAX_YARA_BUNDLES: usize = 64;
pub const MAX_YARA_SOURCE_BYTES: usize = 1024 * 1024;
pub const MAX_TOTAL_YARA_SOURCE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_RULE_POLICIES: usize = 8_192;
pub const MAX_SIMILARITY_PROFILES: usize = 512;
pub const MAX_PROVENANCE_RECORDS: usize = 64;

const MAX_BUNDLE_ID_BYTES: usize = 128;
const MAX_THREAT_NAME_BYTES: usize = 160;
const MAX_FAMILY_BYTES: usize = 96;
const MAX_NAMESPACE_BYTES: usize = 64;
const MAX_RULE_IDENTIFIER_BYTES: usize = 128;
const MAX_DESCRIPTION_BYTES: usize = 512;
const BUILTIN_NAMESPACE: &str = "blackshard_builtin";
const COMPACT_PAYLOAD_MAGIC: &[u8; 16] = b"BLACKSHARD-CDB3\0";
const COMPACT_PAYLOAD_PREFIX_BYTES: usize = 16 + 4 + 8;
const TRUSTED_PUBLIC_KEY_HEX: Option<&str> = option_env!("BLACKSHARD_DEFINITION_PUBLIC_KEY_HEX");

pub fn configured_trusted_public_key() -> Result<Option<[u8; 32]>, String> {
    let Some(encoded) = TRUSTED_PUBLIC_KEY_HEX else {
        return Ok(None);
    };
    if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(
            "BLACKSHARD_DEFINITION_PUBLIC_KEY_HEX must be exactly 64 hexadecimal characters"
                .to_owned(),
        );
    }
    let decoded = hex::decode(encoded)
        .map_err(|error| format!("definition public key is malformed: {error}"))?;
    let key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| "definition public key has the wrong length".to_owned())?;
    if key.iter().all(|byte| *byte == 0) {
        return Err("definition public key must not be all zeroes".to_owned());
    }
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .map_err(|error| format!("definition public key is not a valid Ed25519 key: {error}"))?;
    Ok(Some(key))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DefinitionBundle {
    pub schema_version: u32,
    pub bundle_id: String,
    pub exact_sha256: Vec<ExactHashDefinition>,
    pub yara_bundles: Vec<DefinitionRuleBundle>,
    #[serde(default)]
    pub similarity_profiles: Vec<DefinitionSimilarityProfile>,
    #[serde(default)]
    pub sources: Vec<DefinitionProvenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExactHashDefinition {
    pub sha256: String,
    pub threat_name: String,
    pub family: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DefinitionRuleBundle {
    pub namespace: String,
    pub source: String,
    pub policies: Vec<DefinitionRulePolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DefinitionRulePolicy {
    pub identifier: String,

    pub disposition: RuleDisposition,
    pub risk_score: u8,
    pub threat_name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DefinitionSimilarityProfile {
    pub identifier: String,
    pub threat_name: String,
    pub family: Option<String>,
    pub minimum_file_size: u64,
    pub maximum_file_size: u64,
    pub minimum_similarity_basis_points: u16,

    pub sketch: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DefinitionProvenance {
    pub provider: String,
    pub source_url: String,
    pub retrieved_at: DateTime<Utc>,
    pub content_sha256: String,
    pub license: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CompactDefinitionHeader {
    schema_version: u32,
    bundle: DefinitionBundle,
    compact_sha256: CompactHashHeader,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CompactHashHeader {
    count: u64,
    threat_name: String,
    family: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DefinitionPayload {
    pub bundle: DefinitionBundle,
    pub compact_sha256: Vec<[u8; 32]>,
    pub compact_threat_name: Option<String>,
    pub compact_family: Option<String>,
}

impl DefinitionPayload {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DefinitionError> {
        if !bytes.starts_with(COMPACT_PAYLOAD_MAGIC) {
            return Ok(Self {
                bundle: DefinitionBundle::from_json(bytes)?,
                compact_sha256: Vec::new(),
                compact_threat_name: None,
                compact_family: None,
            });
        }
        if bytes.len() > MAX_DEFINITION_PAYLOAD_BYTES {
            return Err(DefinitionError::BundleTooLarge {
                actual: bytes.len(),
                maximum: MAX_DEFINITION_PAYLOAD_BYTES,
            });
        }
        if bytes.len() < COMPACT_PAYLOAD_PREFIX_BYTES {
            return Err(DefinitionError::Serialization(
                "compact payload prefix is truncated".to_owned(),
            ));
        }

        let header_length =
            u32::from_be_bytes(bytes[16..20].try_into().expect("fixed header slice")) as usize;
        let count_u64 = u64::from_be_bytes(bytes[20..28].try_into().expect("fixed count slice"));
        let count = usize::try_from(count_u64).map_err(|_| DefinitionError::LimitExceeded {
            field: "compact_sha256".to_owned(),
            actual: usize::MAX,
            maximum: MAX_COMPACT_SHA256_SIGNATURES,
        })?;
        if count > MAX_COMPACT_SHA256_SIGNATURES {
            return Err(DefinitionError::LimitExceeded {
                field: "compact_sha256".to_owned(),
                actual: count,
                maximum: MAX_COMPACT_SHA256_SIGNATURES,
            });
        }
        if header_length > MAX_DEFINITION_BUNDLE_BYTES {
            return Err(DefinitionError::BundleTooLarge {
                actual: header_length,
                maximum: MAX_DEFINITION_BUNDLE_BYTES,
            });
        }
        let digest_bytes = count.checked_mul(32).ok_or_else(|| {
            DefinitionError::Serialization("compact digest length overflowed".to_owned())
        })?;
        let expected_length = COMPACT_PAYLOAD_PREFIX_BYTES
            .checked_add(header_length)
            .and_then(|value| value.checked_add(digest_bytes))
            .ok_or_else(|| {
                DefinitionError::Serialization("compact payload length overflowed".to_owned())
            })?;
        if bytes.len() != expected_length {
            return Err(DefinitionError::Serialization(format!(
                "compact payload length is {}, expected {expected_length}",
                bytes.len()
            )));
        }

        let header_end = COMPACT_PAYLOAD_PREFIX_BYTES + header_length;
        let header: CompactDefinitionHeader =
            serde_json::from_slice(&bytes[COMPACT_PAYLOAD_PREFIX_BYTES..header_end])
                .map_err(|error| DefinitionError::Serialization(error.to_string()))?;
        if header.schema_version != COMPACT_DEFINITION_SCHEMA_VERSION {
            return Err(DefinitionError::UnsupportedSchema {
                found: header.schema_version,
            });
        }
        if header.compact_sha256.count != count_u64 {
            return Err(DefinitionError::InvalidField {
                field: "compact_sha256.count".to_owned(),
                reason: "header count does not match the binary record count".to_owned(),
            });
        }
        header.bundle.validate()?;
        validate_text(
            "compact_sha256.threat_name",
            &header.compact_sha256.threat_name,
            MAX_THREAT_NAME_BYTES,
        )?;
        if let Some(family) = &header.compact_sha256.family {
            validate_text("compact_sha256.family", family, MAX_FAMILY_BYTES)?;
        }
        if count == 0 {
            return Err(DefinitionError::InvalidField {
                field: "compact_sha256".to_owned(),
                reason: "compact corpus must not be empty".to_owned(),
            });
        }

        let mut digests = Vec::with_capacity(count);
        for &chunk in bytes[header_end..].as_chunks::<32>().0 {
            digests.push(chunk);
        }
        if digests.windows(2).any(|window| window[0] >= window[1]) {
            return Err(DefinitionError::InvalidField {
                field: "compact_sha256".to_owned(),
                reason: "digests must be strictly sorted and unique".to_owned(),
            });
        }

        Ok(Self {
            bundle: header.bundle,
            compact_sha256: digests,
            compact_threat_name: Some(header.compact_sha256.threat_name),
            compact_family: header.compact_sha256.family,
        })
    }

    pub fn to_compact_bytes(
        bundle: DefinitionBundle,
        digests: Vec<[u8; 32]>,
        threat_name: String,
        family: Option<String>,
    ) -> Result<Vec<u8>, DefinitionError> {
        bundle.validate()?;
        if digests.is_empty() || digests.len() > MAX_COMPACT_SHA256_SIGNATURES {
            return Err(DefinitionError::LimitExceeded {
                field: "compact_sha256".to_owned(),
                actual: digests.len(),
                maximum: MAX_COMPACT_SHA256_SIGNATURES,
            });
        }
        if digests.windows(2).any(|window| window[0] >= window[1]) {
            return Err(DefinitionError::InvalidField {
                field: "compact_sha256".to_owned(),
                reason: "digests must be strictly sorted and unique".to_owned(),
            });
        }
        validate_text(
            "compact_sha256.threat_name",
            &threat_name,
            MAX_THREAT_NAME_BYTES,
        )?;
        if let Some(value) = &family {
            validate_text("compact_sha256.family", value, MAX_FAMILY_BYTES)?;
        }

        let header = CompactDefinitionHeader {
            schema_version: COMPACT_DEFINITION_SCHEMA_VERSION,
            compact_sha256: CompactHashHeader {
                count: digests.len() as u64,
                threat_name,
                family,
            },
            bundle,
        };
        let header_bytes = serde_json::to_vec(&header)
            .map_err(|error| DefinitionError::Serialization(error.to_string()))?;
        if header_bytes.len() > MAX_DEFINITION_BUNDLE_BYTES {
            return Err(DefinitionError::BundleTooLarge {
                actual: header_bytes.len(),
                maximum: MAX_DEFINITION_BUNDLE_BYTES,
            });
        }
        let capacity =
            COMPACT_PAYLOAD_PREFIX_BYTES + header_bytes.len() + digests.len().saturating_mul(32);
        if capacity > MAX_DEFINITION_PAYLOAD_BYTES {
            return Err(DefinitionError::BundleTooLarge {
                actual: capacity,
                maximum: MAX_DEFINITION_PAYLOAD_BYTES,
            });
        }
        let mut payload = Vec::with_capacity(capacity);
        payload.extend_from_slice(COMPACT_PAYLOAD_MAGIC);
        payload.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(&(digests.len() as u64).to_be_bytes());
        payload.extend_from_slice(&header_bytes);
        for digest in digests {
            payload.extend_from_slice(&digest);
        }
        Ok(payload)
    }
}

impl DefinitionBundle {
    pub fn from_json(bytes: &[u8]) -> Result<Self, DefinitionError> {
        if bytes.len() > MAX_DEFINITION_BUNDLE_BYTES {
            return Err(DefinitionError::BundleTooLarge {
                actual: bytes.len(),
                maximum: MAX_DEFINITION_BUNDLE_BYTES,
            });
        }
        let bundle: Self = serde_json::from_slice(bytes)
            .map_err(|error| DefinitionError::Serialization(error.to_string()))?;
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn to_json(&self) -> Result<Vec<u8>, DefinitionError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| DefinitionError::Serialization(error.to_string()))?;
        if bytes.len() > MAX_DEFINITION_BUNDLE_BYTES {
            return Err(DefinitionError::BundleTooLarge {
                actual: bytes.len(),
                maximum: MAX_DEFINITION_BUNDLE_BYTES,
            });
        }
        Ok(bytes)
    }

    pub fn validate(&self) -> Result<(), DefinitionError> {
        if self.schema_version != DEFINITION_SCHEMA_VERSION {
            return Err(DefinitionError::UnsupportedSchema {
                found: self.schema_version,
            });
        }
        validate_token("bundle_id", &self.bundle_id, MAX_BUNDLE_ID_BYTES, b"._-")?;
        check_count(
            "exact_sha256",
            self.exact_sha256.len(),
            MAX_EXACT_SIGNATURES,
        )?;
        check_count("yara_bundles", self.yara_bundles.len(), MAX_YARA_BUNDLES)?;
        check_count(
            "similarity_profiles",
            self.similarity_profiles.len(),
            MAX_SIMILARITY_PROFILES,
        )?;
        check_count("sources", self.sources.len(), MAX_PROVENANCE_RECORDS)?;
        if self.exact_sha256.is_empty()
            && self.yara_bundles.is_empty()
            && self.similarity_profiles.is_empty()
        {
            return Err(DefinitionError::InvalidField {
                field: "bundle".to_owned(),
                reason: "at least one exact, YARA, or similarity detection record is required"
                    .to_owned(),
            });
        }

        let mut provenance = HashSet::with_capacity(self.sources.len());
        for (source_index, source) in self.sources.iter().enumerate() {
            let field = format!("sources[{source_index}]");
            validate_token(&format!("{field}.provider"), &source.provider, 96, b"._-")?;
            let parsed_url =
                url::Url::parse(&source.source_url).map_err(|_| DefinitionError::InvalidField {
                    field: format!("{field}.source_url"),
                    reason: "source URL must be an absolute HTTPS URL".to_owned(),
                })?;
            if parsed_url.scheme() != "https"
                || parsed_url.host_str().is_none()
                || !parsed_url.username().is_empty()
                || parsed_url.password().is_some()
                || parsed_url.fragment().is_some()
            {
                return Err(DefinitionError::InvalidField {
                    field: format!("{field}.source_url"),
                    reason: "source URL must use HTTPS and contain no credentials or fragment"
                        .to_owned(),
                });
            }
            validate_sha256(&source.content_sha256).map_err(|reason| {
                DefinitionError::InvalidField {
                    field: format!("{field}.content_sha256"),
                    reason,
                }
            })?;
            validate_text(&format!("{field}.license"), &source.license, 256)?;
            let identity = format!(
                "{}\0{}\0{}",
                source.provider, source.source_url, source.content_sha256
            );
            if !provenance.insert(identity) {
                return Err(DefinitionError::Duplicate {
                    field: "sources.provider/source_url/content_sha256".to_owned(),
                    value: source.source_url.clone(),
                });
            }
        }

        let mut profile_identifiers = HashSet::with_capacity(self.similarity_profiles.len());
        for (profile_index, profile) in self.similarity_profiles.iter().enumerate() {
            let field = format!("similarity_profiles[{profile_index}]");
            validate_identifier(
                &format!("{field}.identifier"),
                &profile.identifier,
                MAX_RULE_IDENTIFIER_BYTES,
                false,
            )?;
            if !profile_identifiers.insert(profile.identifier.clone()) {
                return Err(DefinitionError::Duplicate {
                    field: "similarity_profiles.identifier".to_owned(),
                    value: profile.identifier.clone(),
                });
            }
            validate_text(
                &format!("{field}.threat_name"),
                &profile.threat_name,
                MAX_THREAT_NAME_BYTES,
            )?;
            if let Some(family) = &profile.family {
                validate_text(&format!("{field}.family"), family, MAX_FAMILY_BYTES)?;
            }
            if profile.minimum_file_size < MIN_SKETCH_BYTES as u64
                || profile.maximum_file_size < profile.minimum_file_size
                || profile.maximum_file_size > 64 * 1024 * 1024
            {
                return Err(DefinitionError::InvalidField {
                    field: format!("{field}.file_size"),
                    reason: "size bounds must be ordered and remain within 4 KiB through 64 MiB"
                        .to_owned(),
                });
            }
            if !(8_500..=10_000).contains(&profile.minimum_similarity_basis_points) {
                return Err(DefinitionError::InvalidField {
                    field: format!("{field}.minimum_similarity_basis_points"),
                    reason: "similarity threshold must be 8500 through 10000 basis points"
                        .to_owned(),
                });
            }
            if profile.sketch.len() != SKETCH_SIZE {
                return Err(DefinitionError::InvalidField {
                    field: format!("{field}.sketch"),
                    reason: format!("sketch must contain exactly {SKETCH_SIZE} values"),
                });
            }
            let mut previous = None;
            for value in &profile.sketch {
                if value.len() != 16
                    || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
                    || value.bytes().any(|byte| byte.is_ascii_uppercase())
                {
                    return Err(DefinitionError::InvalidField {
                        field: format!("{field}.sketch"),
                        reason: "sketch values must be lower-case 16-digit hexadecimal".to_owned(),
                    });
                }
                let parsed =
                    u64::from_str_radix(value, 16).map_err(|_| DefinitionError::InvalidField {
                        field: format!("{field}.sketch"),
                        reason: "sketch contains an invalid integer".to_owned(),
                    })?;
                if previous.is_some_and(|prior| prior >= parsed) {
                    return Err(DefinitionError::InvalidField {
                        field: format!("{field}.sketch"),
                        reason: "sketch values must be strictly increasing".to_owned(),
                    });
                }
                previous = Some(parsed);
            }
        }

        let mut digests = HashSet::with_capacity(self.exact_sha256.len());
        for (index, signature) in self.exact_sha256.iter().enumerate() {
            let field = format!("exact_sha256[{index}]");
            validate_sha256(&signature.sha256).map_err(|reason| DefinitionError::InvalidField {
                field: format!("{field}.sha256"),
                reason,
            })?;
            let normalized = signature.sha256.to_ascii_lowercase();
            if !digests.insert(normalized) {
                return Err(DefinitionError::Duplicate {
                    field: "exact_sha256.sha256".to_owned(),
                    value: signature.sha256.clone(),
                });
            }
            validate_text(
                &format!("{field}.threat_name"),
                &signature.threat_name,
                MAX_THREAT_NAME_BYTES,
            )?;
            if let Some(family) = &signature.family {
                validate_text(&format!("{field}.family"), family, MAX_FAMILY_BYTES)?;
            }
        }

        let mut namespaces = HashSet::with_capacity(self.yara_bundles.len());
        let mut total_source_bytes = 0usize;
        let mut total_policies = 0usize;
        for (bundle_index, bundle) in self.yara_bundles.iter().enumerate() {
            let field = format!("yara_bundles[{bundle_index}]");
            validate_identifier(
                &format!("{field}.namespace"),
                &bundle.namespace,
                MAX_NAMESPACE_BYTES,
                true,
            )?;
            if bundle.namespace == BUILTIN_NAMESPACE {
                return Err(DefinitionError::InvalidField {
                    field: format!("{field}.namespace"),
                    reason: "the built-in namespace is reserved".to_owned(),
                });
            }
            if !namespaces.insert(bundle.namespace.clone()) {
                return Err(DefinitionError::Duplicate {
                    field: "yara_bundles.namespace".to_owned(),
                    value: bundle.namespace.clone(),
                });
            }
            if bundle.source.is_empty() {
                return Err(DefinitionError::InvalidField {
                    field: format!("{field}.source"),
                    reason: "source must not be empty".to_owned(),
                });
            }
            if bundle.source.as_bytes().contains(&0) {
                return Err(DefinitionError::InvalidField {
                    field: format!("{field}.source"),
                    reason: "source must not contain NUL bytes".to_owned(),
                });
            }
            if bundle.source.len() > MAX_YARA_SOURCE_BYTES {
                return Err(DefinitionError::LimitExceeded {
                    field: format!("{field}.source_bytes"),
                    actual: bundle.source.len(),
                    maximum: MAX_YARA_SOURCE_BYTES,
                });
            }
            total_source_bytes = total_source_bytes
                .checked_add(bundle.source.len())
                .ok_or_else(|| DefinitionError::LimitExceeded {
                    field: "total_yara_source_bytes".to_owned(),
                    actual: usize::MAX,
                    maximum: MAX_TOTAL_YARA_SOURCE_BYTES,
                })?;
            if total_source_bytes > MAX_TOTAL_YARA_SOURCE_BYTES {
                return Err(DefinitionError::LimitExceeded {
                    field: "total_yara_source_bytes".to_owned(),
                    actual: total_source_bytes,
                    maximum: MAX_TOTAL_YARA_SOURCE_BYTES,
                });
            }
            total_policies = total_policies
                .checked_add(bundle.policies.len())
                .ok_or_else(|| DefinitionError::LimitExceeded {
                    field: "total_rule_policies".to_owned(),
                    actual: usize::MAX,
                    maximum: MAX_RULE_POLICIES,
                })?;
            if total_policies > MAX_RULE_POLICIES {
                return Err(DefinitionError::LimitExceeded {
                    field: "total_rule_policies".to_owned(),
                    actual: total_policies,
                    maximum: MAX_RULE_POLICIES,
                });
            }

            let mut policy_identifiers = HashSet::with_capacity(bundle.policies.len());
            for (policy_index, policy) in bundle.policies.iter().enumerate() {
                let policy_field = format!("{field}.policies[{policy_index}]");
                validate_identifier(
                    &format!("{policy_field}.identifier"),
                    &policy.identifier,
                    MAX_RULE_IDENTIFIER_BYTES,
                    false,
                )?;
                if !policy_identifiers.insert(policy.identifier.clone()) {
                    return Err(DefinitionError::Duplicate {
                        field: format!("{field}.policies.identifier"),
                        value: policy.identifier.clone(),
                    });
                }
                validate_text(
                    &format!("{policy_field}.threat_name"),
                    &policy.threat_name,
                    MAX_THREAT_NAME_BYTES,
                )?;
                validate_text(
                    &format!("{policy_field}.description"),
                    &policy.description,
                    MAX_DESCRIPTION_BYTES,
                )?;
                validate_policy_score(policy, &policy_field)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum DefinitionError {
    BundleTooLarge {
        actual: usize,
        maximum: usize,
    },
    UnsupportedSchema {
        found: u32,
    },
    Serialization(String),
    InvalidField {
        field: String,
        reason: String,
    },
    LimitExceeded {
        field: String,
        actual: usize,
        maximum: usize,
    },
    Duplicate {
        field: String,
        value: String,
    },
    Storage {
        path: PathBuf,
        source: io::Error,
    },
    Compilation(String),
}

impl fmt::Display for DefinitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BundleTooLarge { actual, maximum } => write!(
                formatter,
                "definition bundle is {actual} bytes, exceeding the {maximum}-byte limit"
            ),
            Self::UnsupportedSchema { found } => {
                write!(formatter, "unsupported definition schema version {found}")
            }
            Self::Serialization(reason) => {
                write!(formatter, "definition JSON is invalid: {reason}")
            }
            Self::InvalidField { field, reason } => {
                write!(formatter, "invalid definition field {field}: {reason}")
            }
            Self::LimitExceeded {
                field,
                actual,
                maximum,
            } => write!(
                formatter,
                "definition field {field} has {actual} items/bytes, exceeding {maximum}"
            ),
            Self::Duplicate { field, value } => {
                write!(formatter, "duplicate definition {field}: {value}")
            }
            Self::Storage { path, source } => {
                write!(formatter, "could not read {}: {source}", path.display())
            }
            Self::Compilation(reason) => {
                write!(formatter, "definition compilation failed: {reason}")
            }
        }
    }
}

impl std::error::Error for DefinitionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinitionCandidate {
    Current,
    LastKnownGood,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinitionIssueStage {
    PointerState,
    Storage,
    Authentication,
    Validation,
    Compilation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefinitionLoadIssue {
    pub candidate: DefinitionCandidate,
    pub stage: DefinitionIssueStage,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefinitionSource {
    BuiltIn,
    Current {
        sequence: u64,
        version: String,
        bundle_id: String,
        expires_at: DateTime<Utc>,
    },
    LastKnownGood {
        sequence: u64,
        version: String,
        bundle_id: String,
        expires_at: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefinitionRuntimeFreshness {
    BuiltIn,
    Fresh { expires_at: DateTime<Utc> },
    Expired { expired_at: DateTime<Utc> },
}

impl DefinitionSource {
    pub fn expires_at(&self) -> Option<&DateTime<Utc>> {
        match self {
            Self::BuiltIn => None,
            Self::Current { expires_at, .. } | Self::LastKnownGood { expires_at, .. } => {
                Some(expires_at)
            }
        }
    }

    pub fn runtime_freshness(&self, now: DateTime<Utc>) -> DefinitionRuntimeFreshness {
        match self.expires_at() {
            None => DefinitionRuntimeFreshness::BuiltIn,
            Some(expires_at) if *expires_at <= now => DefinitionRuntimeFreshness::Expired {
                expired_at: *expires_at,
            },
            Some(expires_at) => DefinitionRuntimeFreshness::Fresh {
                expires_at: *expires_at,
            },
        }
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        matches!(
            self.runtime_freshness(now),
            DefinitionRuntimeFreshness::Expired { .. }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefinitionMatchRateLimits {
    pub window_samples: usize,
    pub minimum_samples: usize,
    pub maximum_match_rate_basis_points: u16,
}

impl Default for DefinitionMatchRateLimits {
    fn default() -> Self {
        Self {
            window_samples: 1_024,
            minimum_samples: 128,
            maximum_match_rate_basis_points: 2_500,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinitionMatchRateState {
    Monitoring { samples: usize, matches: usize },
    Healthy { samples: usize, matches: usize },
    Tripped { samples: usize, matches: usize },
}

pub struct DefinitionMatchRateCircuitBreaker {
    limits: DefinitionMatchRateLimits,
    observations: VecDeque<bool>,
    matches: usize,
    tripped: bool,
}

impl Default for DefinitionMatchRateCircuitBreaker {
    fn default() -> Self {
        Self::new(DefinitionMatchRateLimits::default())
            .expect("the built-in definition match-rate limits are valid")
    }
}

impl DefinitionMatchRateCircuitBreaker {
    pub fn new(limits: DefinitionMatchRateLimits) -> Result<Self, DefinitionError> {
        if limits.window_samples == 0
            || limits.window_samples > 65_536
            || limits.minimum_samples == 0
            || limits.minimum_samples > limits.window_samples
            || limits.maximum_match_rate_basis_points > 10_000
        {
            return Err(DefinitionError::InvalidField {
                field: "definition_match_rate_limits".to_owned(),
                reason: "window must be 1..=65536, minimum must fit the window, and rate must be 0..=10000 basis points".to_owned(),
            });
        }
        Ok(Self {
            limits,
            observations: VecDeque::with_capacity(limits.window_samples),
            matches: 0,
            tripped: false,
        })
    }

    pub fn observe(&mut self, report: &DetectionReport) -> DefinitionMatchRateState {
        let external_match = report
            .rule_matches
            .iter()
            .any(|matched| matched.namespace != BUILTIN_NAMESPACE);
        self.observe_external_match(external_match)
    }

    pub fn observe_external_match(&mut self, external_match: bool) -> DefinitionMatchRateState {
        if self.observations.len() == self.limits.window_samples
            && self.observations.pop_front() == Some(true)
        {
            self.matches -= 1;
        }
        self.observations.push_back(external_match);
        self.matches += usize::from(external_match);

        if !self.tripped && self.observations.len() >= self.limits.minimum_samples {
            self.tripped = self.matches * 10_000
                > self.observations.len()
                    * usize::from(self.limits.maximum_match_rate_basis_points);
        }
        self.state()
    }

    pub fn state(&self) -> DefinitionMatchRateState {
        if self.tripped {
            DefinitionMatchRateState::Tripped {
                samples: self.observations.len(),
                matches: self.matches,
            }
        } else if self.observations.len() < self.limits.minimum_samples {
            DefinitionMatchRateState::Monitoring {
                samples: self.observations.len(),
                matches: self.matches,
            }
        } else {
            DefinitionMatchRateState::Healthy {
                samples: self.observations.len(),
                matches: self.matches,
            }
        }
    }

    pub fn is_tripped(&self) -> bool {
        self.tripped
    }

    pub fn reset_for_new_sequence(&mut self) {
        self.observations.clear();
        self.matches = 0;
        self.tripped = false;
    }
}

pub struct DefinitionLoadOutcome {
    pub engine: DetectionEngine,
    pub source: DefinitionSource,
    pub issues: Vec<DefinitionLoadIssue>,
}

impl DefinitionLoadOutcome {
    pub fn runtime_freshness(&self, now: DateTime<Utc>) -> DefinitionRuntimeFreshness {
        self.source.runtime_freshness(now)
    }
}

#[derive(Debug, Clone)]
pub struct DefinitionStore {
    updates: UpdateStore,
}

impl DefinitionStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, UpdateError> {
        Ok(Self {
            updates: UpdateStore::new(root, MAX_DEFINITION_PAYLOAD_BYTES as u64)?,
        })
    }

    pub fn program_data() -> Result<Self, UpdateError> {
        Self::new(Self::program_data_path())
    }

    pub fn program_data_path() -> PathBuf {
        std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("blackshard")
            .join("Definitions")
    }

    pub fn update_store(&self) -> &UpdateStore {
        &self.updates
    }

    pub fn load(
        &self,
        now: DateTime<Utc>,
        trusted_public_key: &[u8; 32],
        scan_config: ScanConfig,
    ) -> Result<DefinitionLoadOutcome, DefinitionError> {
        let mut issues = Vec::new();

        for candidate in [
            DefinitionCandidate::Current,
            DefinitionCandidate::LastKnownGood,
        ] {
            let active = match candidate {
                DefinitionCandidate::Current => self.updates.current(),
                DefinitionCandidate::LastKnownGood => self.updates.last_known_good(),
            };
            let active = match active {
                Ok(Some(active)) => active,
                Ok(None) => continue,
                Err(error) => {
                    issues.push(DefinitionLoadIssue {
                        candidate,
                        stage: DefinitionIssueStage::PointerState,
                        message: error.to_string(),
                    });
                    continue;
                }
            };

            match load_active_candidate(
                &active,
                candidate,
                now,
                trusted_public_key,
                scan_config.clone(),
            ) {
                Ok((engine, bundle_id)) => {
                    let source = match candidate {
                        DefinitionCandidate::Current => DefinitionSource::Current {
                            sequence: active.sequence,
                            version: active.version,
                            bundle_id,
                            expires_at: active.expires_at,
                        },
                        DefinitionCandidate::LastKnownGood => DefinitionSource::LastKnownGood {
                            sequence: active.sequence,
                            version: active.version,
                            bundle_id,
                            expires_at: active.expires_at,
                        },
                    };
                    return Ok(DefinitionLoadOutcome {
                        engine,
                        source,
                        issues,
                    });
                }
                Err(failure) => issues.push(DefinitionLoadIssue {
                    candidate,
                    stage: failure.stage,
                    message: failure.message,
                }),
            }
        }

        let engine = build_builtin_engine(scan_config)?;
        Ok(DefinitionLoadOutcome {
            engine,
            source: DefinitionSource::BuiltIn,
            issues,
        })
    }

    pub fn load_with_defaults(
        &self,
        now: DateTime<Utc>,
        trusted_public_key: &[u8; 32],
    ) -> Result<DefinitionLoadOutcome, DefinitionError> {
        self.load(now, trusted_public_key, ScanConfig::default())
    }
}

struct CandidateFailure {
    stage: DefinitionIssueStage,
    message: String,
}

impl CandidateFailure {
    fn new(stage: DefinitionIssueStage, message: impl Into<String>) -> Self {
        Self {
            stage,
            message: message.into(),
        }
    }
}

fn load_active_candidate(
    active: &ActiveUpdate,
    _candidate: DefinitionCandidate,
    now: DateTime<Utc>,
    trusted_public_key: &[u8; 32],
    scan_config: ScanConfig,
) -> Result<(DetectionEngine, String), CandidateFailure> {
    let payload = read_bounded_regular(&active.payload_path, MAX_DEFINITION_PAYLOAD_BYTES)
        .map_err(|error| CandidateFailure::new(DefinitionIssueStage::Storage, error.to_string()))?;
    let envelope_bytes = read_bounded_regular(&active.envelope_path, MAX_ENVELOPE_BYTES)
        .map_err(|error| CandidateFailure::new(DefinitionIssueStage::Storage, error.to_string()))?;
    let envelope = SignedUpdateEnvelope::from_json(&envelope_bytes).map_err(|error| {
        CandidateFailure::new(DefinitionIssueStage::Authentication, error.to_string())
    })?;

    let installed_before_candidate = active.sequence.saturating_sub(1);
    let verify_at = |at: DateTime<Utc>| {
        verify_update(
            &envelope,
            &payload,
            installed_before_candidate,
            at,
            MAX_DEFINITION_PAYLOAD_BYTES as u64,
            trusted_public_key,
        )
    };
    // The expiry limits how long a bundle may be *installed*, so an attacker cannot hold a
    // machine on a stale feed by replaying one. A bundle already installed and authenticated is
    // another matter: once it expires, its signatures are still worth far more than the small
    // built-in set, so an offline machine keeps using it (and reports it as expired) until a newer
    // bundle arrives. Everything else is still checked: signature, sequence, size and digest.
    let verified = match verify_at(now) {
        Err(UpdateError::Expired { expired_at }) => {
            let just_before = expired_at - chrono::Duration::seconds(1);
            verify_at(just_before)
        }
        other => other,
    }
    .map_err(|error| {
        CandidateFailure::new(DefinitionIssueStage::Authentication, error.to_string())
    })?;

    if verified.manifest.sequence != active.sequence
        || verified.manifest.version != active.version
        || verified.manifest.expires_at != active.expires_at
        || !verified
            .manifest
            .payload_sha256
            .eq_ignore_ascii_case(&active.payload_sha256)
    {
        return Err(CandidateFailure::new(
            DefinitionIssueStage::Authentication,
            "activation pointer does not match its signed manifest",
        ));
    }

    let definitions = DefinitionPayload::from_bytes(&payload).map_err(|error| {
        CandidateFailure::new(DefinitionIssueStage::Validation, error.to_string())
    })?;
    let bundle_id = definitions.bundle.bundle_id.clone();
    let engine = build_authenticated_engine(definitions, scan_config).map_err(|error| {
        CandidateFailure::new(DefinitionIssueStage::Compilation, error.to_string())
    })?;
    Ok((engine, bundle_id))
}

fn build_builtin_engine(scan_config: ScanConfig) -> Result<DetectionEngine, DefinitionError> {
    let static_engine = ScanEngine::new(scan_config, SignatureDatabase::default())
        .map_err(|error| DefinitionError::Compilation(error.to_string()))?;
    let rules = RuleEngine::builtin().map_err(DefinitionError::Compilation)?;
    Ok(DetectionEngine::new(static_engine, rules))
}

fn build_authenticated_engine(
    definitions: DefinitionPayload,
    scan_config: ScanConfig,
) -> Result<DetectionEngine, DefinitionError> {
    let DefinitionPayload {
        bundle,
        compact_sha256,
        compact_threat_name,
        compact_family,
    } = definitions;

    bundle.validate()?;

    let similarity_profiles = bundle
        .similarity_profiles
        .into_iter()
        .map(|profile| {
            let sketch = profile
                .sketch
                .iter()
                .map(|value| u64::from_str_radix(value, 16).expect("validated similarity sketch"))
                .collect::<Vec<_>>()
                .try_into()
                .expect("validated similarity sketch length");
            SimilarityProfile {
                identifier: profile.identifier,
                threat_name: profile.threat_name,
                family: profile.family,
                minimum_file_size: profile.minimum_file_size,
                maximum_file_size: profile.maximum_file_size,
                minimum_similarity_basis_points: profile.minimum_similarity_basis_points,
                sketch,
            }
        })
        .collect::<Vec<_>>();
    let similarity =
        SimilarityEngine::new(similarity_profiles).map_err(DefinitionError::Compilation)?;

    let mut signatures = SignatureDatabase::default();
    for signature in bundle.exact_sha256 {
        let replaced = signatures
            .insert_sha256_hex(&signature.sha256, signature.threat_name, signature.family)
            .map_err(|error| DefinitionError::InvalidField {
                field: "exact_sha256.sha256".to_owned(),
                reason: error.to_string(),
            })?;
        if replaced.is_some() {
            return Err(DefinitionError::Duplicate {
                field: "exact_sha256.sha256 (including built-ins)".to_owned(),
                value: signature.sha256,
            });
        }
    }
    if !compact_sha256.is_empty() {
        signatures
            .replace_compact_sha256(
                compact_sha256,
                compact_threat_name.expect("validated compact signature name"),
                compact_family,
            )
            .map_err(|error| DefinitionError::InvalidField {
                field: "compact_sha256".to_owned(),
                reason: error.to_string(),
            })?;
    }

    let rule_bundles = bundle
        .yara_bundles
        .into_iter()
        .map(|bundle| RuleBundle {
            namespace: bundle.namespace,
            source: bundle.source,
            policies: bundle
                .policies
                .into_iter()
                .map(|policy| RulePolicy {
                    identifier: policy.identifier,
                    disposition: policy.disposition,
                    risk_score: policy.risk_score,
                    threat_name: policy.threat_name,
                    description: policy.description,
                })
                .collect(),
        })
        .collect::<Vec<_>>();

    let static_engine = ScanEngine::new(scan_config, signatures)
        .map_err(|error| DefinitionError::Compilation(error.to_string()))?;
    let rules = RuleEngine::compile(&rule_bundles).map_err(DefinitionError::Compilation)?;
    Ok(DetectionEngine::new(static_engine, rules).with_similarity(similarity))
}

fn validate_policy_score(
    policy: &DefinitionRulePolicy,
    field: &str,
) -> Result<(), DefinitionError> {
    let valid = match policy.disposition {
        RuleDisposition::Informational => policy.risk_score <= 25,
        RuleDisposition::Suspicious => (1..=99).contains(&policy.risk_score),
        RuleDisposition::Malicious => (95..=100).contains(&policy.risk_score),
    };
    if valid {
        return Ok(());
    }
    let expected = match policy.disposition {
        RuleDisposition::Informational => "0 through 25 for informational rules",
        RuleDisposition::Suspicious => "1 through 99 for suspicious rules",
        RuleDisposition::Malicious => "95 through 100 for malicious rules",
    };
    Err(DefinitionError::InvalidField {
        field: format!("{field}.risk_score"),
        reason: format!("expected {expected}"),
    })
}

fn validate_sha256(value: &str) -> Result<(), String> {
    if value.len() != 64 {
        return Err("SHA-256 must contain exactly 64 hexadecimal characters".to_owned());
    }
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("SHA-256 contains a non-hexadecimal character".to_owned());
    }
    Ok(())
}

fn validate_text(field: &str, value: &str, maximum: usize) -> Result<(), DefinitionError> {
    if value.is_empty() || value.len() > maximum {
        return Err(DefinitionError::InvalidField {
            field: field.to_owned(),
            reason: format!("must contain 1 through {maximum} UTF-8 bytes"),
        });
    }
    if value.trim() != value {
        return Err(DefinitionError::InvalidField {
            field: field.to_owned(),
            reason: "leading or trailing whitespace is not allowed".to_owned(),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(DefinitionError::InvalidField {
            field: field.to_owned(),
            reason: "control characters are not allowed".to_owned(),
        });
    }
    Ok(())
}

fn validate_token(
    field: &str,
    value: &str,
    maximum: usize,
    punctuation: &[u8],
) -> Result<(), DefinitionError> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || punctuation.contains(&byte))
    {
        return Err(DefinitionError::InvalidField {
            field: field.to_owned(),
            reason: format!(
                "must contain 1 through {maximum} ASCII letters, digits, or approved punctuation"
            ),
        });
    }
    Ok(())
}

fn validate_identifier(
    field: &str,
    value: &str,
    maximum: usize,
    allow_hyphen: bool,
) -> Result<(), DefinitionError> {
    if value.is_empty() || value.len() > maximum {
        return Err(DefinitionError::InvalidField {
            field: field.to_owned(),
            reason: format!("must contain 1 through {maximum} ASCII bytes"),
        });
    }
    let mut bytes = value.bytes();
    let first = bytes.next().expect("non-empty checked above");
    if !(first.is_ascii_alphabetic() || first == b'_')
        || !bytes.all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'_' || (allow_hyphen && byte == b'-')
        })
    {
        return Err(DefinitionError::InvalidField {
            field: field.to_owned(),
            reason: if allow_hyphen {
                "must start with a letter/underscore and contain only ASCII letters, digits, underscores, or hyphens".to_owned()
            } else {
                "must be a valid YARA identifier".to_owned()
            },
        });
    }
    Ok(())
}

fn check_count(field: &str, actual: usize, maximum: usize) -> Result<(), DefinitionError> {
    if actual > maximum {
        return Err(DefinitionError::LimitExceeded {
            field: field.to_owned(),
            actual,
            maximum,
        });
    }
    Ok(())
}

fn read_bounded_regular(path: &Path, maximum: usize) -> Result<Vec<u8>, DefinitionError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| DefinitionError::Storage {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DefinitionError::Storage {
            path: path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                "candidate is not a regular, non-symlink file",
            ),
        });
    }
    if metadata.len() > maximum as u64 {
        return Err(DefinitionError::BundleTooLarge {
            actual: usize::try_from(metadata.len()).unwrap_or(usize::MAX),
            maximum,
        });
    }

    let file = File::open(path).map_err(|source| DefinitionError::Storage {
        path: path.to_path_buf(),
        source,
    })?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| DefinitionError::Storage {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() > maximum {
        return Err(DefinitionError::BundleTooLarge {
            actual: bytes.len(),
            maximum,
        });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::DetectionVerdict;
    use crate::similarity::compute_sketch;
    use crate::updater::{SignedUpdateEnvelope, UpdateManifest, UPDATE_SCHEMA_VERSION};
    use chrono::TimeZone;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    fn now() -> DateTime<Utc> {
        Utc.timestamp_opt(1_800_000_000, 0).single().unwrap()
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x2d; 32])
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn exact_signature(bytes: &[u8], name: &str) -> ExactHashDefinition {
        ExactHashDefinition {
            sha256: sha256_hex(bytes),
            threat_name: name.to_owned(),
            family: Some("Test".to_owned()),
        }
    }

    fn exact_bundle(id: &str, target: &[u8]) -> DefinitionBundle {
        DefinitionBundle {
            schema_version: DEFINITION_SCHEMA_VERSION,
            bundle_id: id.to_owned(),
            exact_sha256: vec![exact_signature(target, "Test.External.Exact")],
            yara_bundles: Vec::new(),
            similarity_profiles: Vec::new(),
            sources: Vec::new(),
        }
    }

    fn similarity_bundle(id: &str, target: &[u8]) -> DefinitionBundle {
        let sketch = compute_sketch(target).unwrap();
        DefinitionBundle {
            schema_version: DEFINITION_SCHEMA_VERSION,
            bundle_id: id.to_owned(),
            exact_sha256: Vec::new(),
            yara_bundles: Vec::new(),
            similarity_profiles: vec![DefinitionSimilarityProfile {
                identifier: "test_family_profile".to_owned(),
                threat_name: "Test.Similarity.Family".to_owned(),
                family: Some("TestFamily".to_owned()),
                minimum_file_size: target.len() as u64,
                maximum_file_size: target.len() as u64,
                minimum_similarity_basis_points: 9_000,
                sketch: sketch.iter().map(|value| format!("{value:016x}")).collect(),
            }],
            sources: Vec::new(),
        }
    }

    fn similarity_sample(seed: u64) -> Vec<u8> {
        let mut state = seed;
        let mut target = Vec::with_capacity(32 * 1024);
        for _ in 0..target.capacity() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            target.push(state as u8);
        }
        target[0..2].copy_from_slice(b"MZ");
        target
    }

    fn yara_bundle(id: &str, disposition: Option<RuleDisposition>) -> DefinitionBundle {
        let identifier = "External_Marker";
        DefinitionBundle {
            schema_version: DEFINITION_SCHEMA_VERSION,
            bundle_id: id.to_owned(),
            exact_sha256: Vec::new(),
            yara_bundles: vec![DefinitionRuleBundle {
                namespace: "blackshard_release".to_owned(),
                source: format!(
                    r#"rule {identifier} {{
                        strings:
                            $marker = "blackshard-external-marker"
                        condition:
                            $marker
                    }}"#
                ),
                policies: disposition
                    .map(|disposition| DefinitionRulePolicy {
                        identifier: identifier.to_owned(),
                        disposition,
                        risk_score: match disposition {
                            RuleDisposition::Informational => 10,
                            RuleDisposition::Suspicious => 70,
                            RuleDisposition::Malicious => 100,
                        },
                        threat_name: "Test.External.Yara".to_owned(),
                        description: "unit-test external marker".to_owned(),
                    })
                    .into_iter()
                    .collect(),
            }],
            similarity_profiles: Vec::new(),
            sources: Vec::new(),
        }
    }

    fn envelope(sequence: u64, payload: &[u8]) -> SignedUpdateEnvelope {
        let key = signing_key();
        let manifest = UpdateManifest {
            schema_version: UPDATE_SCHEMA_VERSION,
            product: crate::updater::UPDATE_PRODUCT_ID.to_owned(),
            channel: crate::updater::UPDATE_CHANNEL.to_owned(),
            sequence,
            version: format!("2027.1.{sequence}"),
            issued_at: now(),
            expires_at: now() + chrono::Duration::days(7),
            payload_url: format!("https://updates.blackshard.dev/definitions/{sequence}.json"),
            payload_size: payload.len() as u64,
            payload_sha256: sha256_hex(payload),
        };
        let signature = key.sign(&manifest.signing_bytes().unwrap());
        SignedUpdateEnvelope {
            manifest,
            signature_ed25519: hex::encode(signature.to_bytes()),
        }
    }

    fn stage(store: &DefinitionStore, sequence: u64, bundle: &DefinitionBundle) -> ActiveUpdate {
        let payload = bundle.to_json().unwrap();
        store
            .update_store()
            .stage_and_activate(
                &envelope(sequence, &payload),
                &payload,
                now(),
                &signing_key().verifying_key().to_bytes(),
            )
            .unwrap()
    }

    #[test]
    fn strict_json_rejects_unknown_fields_schema_and_oversize() {
        let valid = exact_bundle("release-1", b"target");
        assert_eq!(
            DefinitionBundle::from_json(&valid.to_json().unwrap()).unwrap(),
            valid
        );

        let mut unknown = serde_json::to_value(&valid).unwrap();
        unknown["future_behavior"] = serde_json::json!(true);
        assert!(matches!(
            DefinitionBundle::from_json(&serde_json::to_vec(&unknown).unwrap()),
            Err(DefinitionError::Serialization(_))
        ));

        let mut unsupported = valid;
        unsupported.schema_version += 1;
        assert!(matches!(
            unsupported.validate(),
            Err(DefinitionError::UnsupportedSchema { .. })
        ));

        let oversized = vec![b' '; MAX_DEFINITION_BUNDLE_BYTES + 1];
        assert!(matches!(
            DefinitionBundle::from_json(&oversized),
            Err(DefinitionError::BundleTooLarge { .. })
        ));
    }

    #[test]
    fn compact_payload_round_trips_and_loads_through_signed_store() {
        let target = b"historical compact malware fixture";
        let digest: [u8; 32] = Sha256::digest(target).into();
        let bundle = exact_bundle("compact-1", b"separate labelled fixture");
        let payload = DefinitionPayload::to_compact_bytes(
            bundle,
            vec![digest],
            "MalwareBazaar.Historical".to_owned(),
            None,
        )
        .unwrap();
        let parsed = DefinitionPayload::from_bytes(&payload).unwrap();
        assert_eq!(parsed.compact_sha256, vec![digest]);

        let directory = tempfile::tempdir().unwrap();
        let store = DefinitionStore::new(directory.path()).unwrap();
        store
            .update_store()
            .stage_and_activate(
                &envelope(1, &payload),
                &payload,
                now(),
                &signing_key().verifying_key().to_bytes(),
            )
            .unwrap();
        let loaded = store
            .load_with_defaults(now(), &signing_key().verifying_key().to_bytes())
            .unwrap();
        let report = loaded.engine.scan_bytes(target);
        assert_eq!(report.verdict, DetectionVerdict::Malicious);
        assert!(!report.should_quarantine());
        assert!(report.should_block());
        assert!(report
            .static_report
            .expect("static report")
            .evidence
            .iter()
            .any(|evidence| evidence.description.contains("MalwareBazaar.Historical")));
    }

    #[test]
    fn compact_payload_rejects_truncation_and_unsorted_digests() {
        let bundle = exact_bundle("compact-invalid", b"labelled");
        let mut payload = DefinitionPayload::to_compact_bytes(
            bundle,
            vec![[0x10; 32], [0x20; 32]],
            "MalwareBazaar.Historical".to_owned(),
            None,
        )
        .unwrap();
        assert!(DefinitionPayload::from_bytes(&payload[..payload.len() - 1]).is_err());

        let digest_start = payload.len() - 64;
        payload[digest_start..].rotate_left(32);
        assert!(matches!(
            DefinitionPayload::from_bytes(&payload),
            Err(DefinitionError::InvalidField { .. })
        ));
    }

    #[test]
    fn rejects_bad_and_duplicate_hashes() {
        let mut bundle = exact_bundle("release-1", b"target");
        bundle.exact_sha256[0].sha256 = "not-a-digest".to_owned();
        assert!(matches!(
            bundle.validate(),
            Err(DefinitionError::InvalidField { .. })
        ));

        let mut bundle = exact_bundle("release-2", b"target");
        let mut duplicate = bundle.exact_sha256[0].clone();
        duplicate.sha256.make_ascii_uppercase();
        bundle.exact_sha256.push(duplicate);
        assert!(matches!(
            bundle.validate(),
            Err(DefinitionError::Duplicate { .. })
        ));
    }

    #[test]
    fn rejects_reserved_namespaces_duplicate_policy_and_unsafe_scores() {
        let mut bundle = yara_bundle("rules-1", Some(RuleDisposition::Malicious));
        bundle.yara_bundles[0].namespace = BUILTIN_NAMESPACE.to_owned();
        assert!(matches!(
            bundle.validate(),
            Err(DefinitionError::InvalidField { .. })
        ));

        let mut bundle = yara_bundle("rules-2", Some(RuleDisposition::Malicious));
        let duplicate = bundle.yara_bundles[0].policies[0].clone();
        bundle.yara_bundles[0].policies.push(duplicate);
        assert!(matches!(
            bundle.validate(),
            Err(DefinitionError::Duplicate { .. })
        ));

        let mut bundle = yara_bundle("rules-3", Some(RuleDisposition::Malicious));
        bundle.yara_bundles[0].policies[0].risk_score = 50;
        assert!(matches!(
            bundle.validate(),
            Err(DefinitionError::InvalidField { .. })
        ));
    }

    #[test]
    fn count_and_source_limits_are_enforced_before_compilation() {
        let mut bundle = exact_bundle("limits", b"target");
        bundle.yara_bundles = (0..=MAX_YARA_BUNDLES)
            .map(|index| DefinitionRuleBundle {
                namespace: format!("ns_{index}"),
                source: "rule x { condition: false }".to_owned(),
                policies: Vec::new(),
            })
            .collect();
        assert!(matches!(
            bundle.validate(),
            Err(DefinitionError::LimitExceeded { .. })
        ));

        let mut bundle = yara_bundle("source-limit", None);
        bundle.yara_bundles[0].source = "x".repeat(MAX_YARA_SOURCE_BYTES + 1);
        assert!(matches!(
            bundle.validate(),
            Err(DefinitionError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn authenticated_exact_hash_is_malicious() {
        let directory = tempfile::tempdir().unwrap();
        let store = DefinitionStore::new(directory.path()).unwrap();
        let target = b"known external malware test payload";
        stage(&store, 1, &exact_bundle("exact-1", target));

        let outcome = store
            .load_with_defaults(now(), &signing_key().verifying_key().to_bytes())
            .unwrap();
        assert!(matches!(
            outcome.source,
            DefinitionSource::Current { sequence: 1, .. }
        ));
        assert!(outcome.issues.is_empty());
        let report = outcome.engine.scan_bytes(target);
        assert_eq!(report.verdict, DetectionVerdict::Malicious);
        assert!(report.should_quarantine());
    }

    #[test]
    fn unclassified_rule_defaults_to_suspicious_not_quarantine() {
        let directory = tempfile::tempdir().unwrap();
        let store = DefinitionStore::new(directory.path()).unwrap();
        stage(&store, 1, &yara_bundle("rules-1", None));

        let outcome = store
            .load_with_defaults(now(), &signing_key().verifying_key().to_bytes())
            .unwrap();
        let report = outcome
            .engine
            .scan_bytes(b"prefix blackshard-external-marker suffix");
        assert_eq!(report.verdict, DetectionVerdict::Suspicious);
        assert!(!report.should_quarantine());
    }

    #[test]
    fn externally_defined_yara_is_alert_only_even_when_labelled_malicious() {
        let directory = tempfile::tempdir().unwrap();
        let store = DefinitionStore::new(directory.path()).unwrap();
        stage(
            &store,
            1,
            &yara_bundle("rules-malicious", Some(RuleDisposition::Malicious)),
        );

        let outcome = store
            .load_with_defaults(now(), &signing_key().verifying_key().to_bytes())
            .unwrap();
        let report = outcome.engine.scan_bytes(b"blackshard-external-marker");
        assert_eq!(report.verdict, DetectionVerdict::Malicious);
        assert!(!report.should_quarantine());
        assert!(!report.should_block());
        assert!(!report.automatic_quarantine_eligible);
        assert_eq!(report.threat_name.as_deref(), Some("Test.External.Yara"));
    }

    #[test]
    fn runtime_expiry_is_rechecked_without_reloading() {
        let source = DefinitionSource::Current {
            sequence: 7,
            version: "test".to_owned(),
            bundle_id: "test".to_owned(),
            expires_at: now() + chrono::Duration::minutes(5),
        };
        assert!(!source.is_expired_at(now()));
        assert!(matches!(
            source.runtime_freshness(now()),
            DefinitionRuntimeFreshness::Fresh { .. }
        ));
        assert!(source.is_expired_at(now() + chrono::Duration::minutes(5)));
        assert!(matches!(
            DefinitionSource::BuiltIn.runtime_freshness(now()),
            DefinitionRuntimeFreshness::BuiltIn
        ));
    }

    #[test]
    fn an_installed_bundle_stays_in_use_after_it_expires() {
        let directory = tempfile::tempdir().unwrap();
        let store = DefinitionStore::new(directory.path()).unwrap();
        stage(
            &store,
            1,
            &yara_bundle("kept-rule", Some(RuleDisposition::Suspicious)),
        );
        let key = signing_key().verifying_key().to_bytes();

        // Well past the 7-day expiry the test envelopes carry.
        let later = now() + chrono::Duration::days(30);
        let outcome = store.load_with_defaults(later, &key).unwrap();
        assert!(matches!(outcome.source, DefinitionSource::Current { .. }));
        assert!(outcome.source.is_expired_at(later));
        assert!(outcome
            .engine
            .scan_bytes(b"blackshard-external-marker")
            .rule_matches
            .iter()
            .any(|matched| matched.identifier == "External_Marker"));
    }

    #[test]
    fn external_rule_match_rate_breaker_latches_until_new_sequence() {
        let directory = tempfile::tempdir().unwrap();
        let store = DefinitionStore::new(directory.path()).unwrap();
        stage(
            &store,
            1,
            &yara_bundle("broad-rule", Some(RuleDisposition::Suspicious)),
        );
        let outcome = store
            .load_with_defaults(now(), &signing_key().verifying_key().to_bytes())
            .unwrap();
        let matched = outcome.engine.scan_bytes(b"blackshard-external-marker");
        let clean = outcome.engine.scan_bytes(b"ordinary text");
        let mut breaker = DefinitionMatchRateCircuitBreaker::new(DefinitionMatchRateLimits {
            window_samples: 4,
            minimum_samples: 4,
            maximum_match_rate_basis_points: 2_500,
        })
        .unwrap();
        breaker.observe(&matched);
        breaker.observe(&matched);
        breaker.observe(&clean);
        assert!(matches!(
            breaker.observe(&clean),
            DefinitionMatchRateState::Tripped {
                samples: 4,
                matches: 2
            }
        ));
        assert!(matches!(
            breaker.observe(&clean),
            DefinitionMatchRateState::Tripped { .. }
        ));
        breaker.reset_for_new_sequence();
        assert!(matches!(
            breaker.state(),
            DefinitionMatchRateState::Monitoring {
                samples: 0,
                matches: 0
            }
        ));
    }

    #[test]
    fn corrupt_current_payload_falls_back_to_reauthenticated_lkg() {
        let directory = tempfile::tempdir().unwrap();
        let store = DefinitionStore::new(directory.path()).unwrap();
        let previous_target = b"last-known-good target";
        stage(&store, 10, &exact_bundle("lkg-10", previous_target));
        let current = stage(&store, 11, &exact_bundle("current-11", b"current target"));
        fs::write(&current.payload_path, b"locally tampered bytes").unwrap();

        let outcome = store
            .load_with_defaults(now(), &signing_key().verifying_key().to_bytes())
            .unwrap();
        assert!(matches!(
            outcome.source,
            DefinitionSource::LastKnownGood { sequence: 10, .. }
        ));
        assert_eq!(outcome.issues.len(), 1);
        assert_eq!(outcome.issues[0].candidate, DefinitionCandidate::Current);
        assert_eq!(
            outcome.issues[0].stage,
            DefinitionIssueStage::Authentication
        );
        assert_eq!(
            outcome.engine.scan_bytes(previous_target).verdict,
            DetectionVerdict::Malicious
        );
    }

    #[test]
    fn authenticated_similarity_is_advisory_and_never_destructive() {
        let target = similarity_sample(0x1234_5678_9abc_def0);
        let directory = tempfile::tempdir().unwrap();
        let store = DefinitionStore::new(directory.path()).unwrap();
        stage(&store, 30, &similarity_bundle("similarity-30", &target));
        let outcome = store
            .load_with_defaults(now(), &signing_key().verifying_key().to_bytes())
            .unwrap();
        let report = outcome.engine.scan_bytes(&target);
        assert_eq!(report.similarity_matches.len(), 1);
        assert_eq!(report.verdict, DetectionVerdict::Suspicious);
        assert!(!report.should_block());
        assert!(!report.should_quarantine());
    }

    #[test]
    fn similarity_profile_rejects_low_thresholds_and_unsorted_sketches() {
        let target = similarity_sample(0xfedc_ba98_7654_3210);
        let mut bundle = similarity_bundle("invalid-similarity", &target);
        bundle.similarity_profiles[0].minimum_similarity_basis_points = 8_499;
        assert!(bundle.validate().is_err());
        bundle.similarity_profiles[0].minimum_similarity_basis_points = 9_000;
        bundle.similarity_profiles[0].sketch.swap(0, 1);
        assert!(bundle.validate().is_err());
    }

    #[test]
    fn invalid_signature_key_falls_back_to_builtins_and_reports_failure() {
        let directory = tempfile::tempdir().unwrap();
        let store = DefinitionStore::new(directory.path()).unwrap();
        let target = b"must remain clean without publisher authentication";
        stage(&store, 1, &exact_bundle("untrusted", target));
        let wrong_key = SigningKey::from_bytes(&[0x99; 32]);

        let outcome = store
            .load_with_defaults(now(), &wrong_key.verifying_key().to_bytes())
            .unwrap();
        assert_eq!(outcome.source, DefinitionSource::BuiltIn);
        assert_eq!(outcome.issues.len(), 1);
        assert_eq!(
            outcome.issues[0].stage,
            DefinitionIssueStage::Authentication
        );
        assert_eq!(
            outcome.engine.scan_bytes(target).verdict,
            DetectionVerdict::Clean
        );
    }

    #[test]
    fn compilation_failure_falls_back_to_lkg() {
        let directory = tempfile::tempdir().unwrap();
        let store = DefinitionStore::new(directory.path()).unwrap();
        let target = b"compiler fallback target";
        stage(&store, 20, &exact_bundle("lkg-20", target));
        let mut broken = yara_bundle("broken-21", None);
        broken.yara_bundles[0].source = "rule broken { condition: }".to_owned();
        stage(&store, 21, &broken);

        let outcome = store
            .load_with_defaults(now(), &signing_key().verifying_key().to_bytes())
            .unwrap();
        assert!(matches!(
            outcome.source,
            DefinitionSource::LastKnownGood { sequence: 20, .. }
        ));
        assert_eq!(outcome.issues.len(), 1);
        assert_eq!(outcome.issues[0].stage, DefinitionIssueStage::Compilation);
        assert_eq!(
            outcome.engine.scan_bytes(target).verdict,
            DetectionVerdict::Malicious
        );
    }

    #[test]
    fn empty_store_uses_builtins_without_a_false_error() {
        let directory = tempfile::tempdir().unwrap();
        let store = DefinitionStore::new(directory.path()).unwrap();
        let outcome = store
            .load_with_defaults(now(), &signing_key().verifying_key().to_bytes())
            .unwrap();
        assert_eq!(outcome.source, DefinitionSource::BuiltIn);
        assert!(outcome.issues.is_empty());
    }
}
