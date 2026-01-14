//! Protocol definitions and API configuration types
//!
//! This module defines the data structures for configuring AWS API calls
//! in a data-driven way, allowing operations to be defined in JSON config
//! rather than hard-coded in Rust.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// AWS API protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApiProtocol {
    /// EC2/IAM style: Action=X&Version=Y as query params, XML response
    Query,
    /// JSON-RPC style with X-Amz-Target header
    Json,
    /// REST with JSON body (Lambda, EKS)
    RestJson,
    /// REST with XML body (S3, Route53)
    RestXml,
}

impl Default for ApiProtocol {
    fn default() -> Self {
        ApiProtocol::Query
    }
}

/// Pagination configuration for API calls
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PaginationConfig {
    /// Parameter name for input token (e.g., "NextToken", "Marker")
    #[serde(default)]
    pub input_token: Option<String>,
    /// Path to extract output token from response
    #[serde(default)]
    pub output_token: Option<String>,
    /// Parameter name for max results
    #[serde(default)]
    pub max_results_param: Option<String>,
    /// Default max results value
    #[serde(default)]
    pub max_results: Option<u32>,
}

/// Configuration for a single API operation
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ApiConfig {
    /// Protocol to use for this API call
    #[serde(default)]
    pub protocol: ApiProtocol,

    /// Action name (for Query/JSON protocols, e.g., "DescribeInstances")
    #[serde(default)]
    pub action: Option<String>,

    /// HTTP method (for REST protocols: GET, POST, DELETE, etc.)
    #[serde(default)]
    pub method: Option<String>,

    /// URL path template (for REST protocols, e.g., "/2015-03-31/functions")
    /// Supports placeholders like {function_name}
    #[serde(default)]
    pub path: Option<String>,

    /// Path to extract items from the response (JSON pointer format)
    /// For XML: after xml_to_json conversion
    /// e.g., "/DescribeInstancesResponse/reservationSet/item/instancesSet/item"
    #[serde(default)]
    pub response_root: Option<String>,

    /// For nested responses, path to get to the items array within response_root
    /// Used when items are wrapped in another object
    #[serde(default)]
    pub items_path: Option<String>,

    /// Static parameters to always include in the request
    #[serde(default)]
    pub static_params: HashMap<String, Value>,

    /// Pagination configuration
    #[serde(default)]
    pub pagination: Option<PaginationConfig>,

    /// Pre-request hooks (e.g., "resolve_s3_bucket_region")
    #[serde(default)]
    pub pre_hooks: Vec<String>,

    /// Whether this is a composite operation requiring multiple API calls
    #[serde(default)]
    pub composite: bool,

    /// For composite operations, the sequence of operations
    #[serde(default)]
    pub operations: Vec<CompositeOperation>,
}

/// A single operation in a composite API call
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CompositeOperation {
    /// Action name for this step
    pub action: String,
    /// Store result in this variable name
    #[serde(default)]
    pub store_as: Option<String>,
    /// Input parameters (can reference previous results with $variable)
    #[serde(default)]
    pub input: HashMap<String, Value>,
}

/// Field mapping from raw API response to normalized output
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FieldMapping {
    /// Source path in the API response (JSON pointer format)
    /// e.g., "/instanceId" or "/instanceState/name"
    pub source: String,

    /// Default value if source is null/missing
    #[serde(default)]
    pub default: Option<String>,

    /// Optional transformation to apply
    /// Supported: "tags_to_map", "format_bytes", "format_epoch_millis", "bool_to_yes_no"
    #[serde(default)]
    pub transform: Option<String>,

    /// For array fields, path within each array item
    #[serde(default)]
    pub array_item_path: Option<String>,
}

impl Default for FieldMapping {
    fn default() -> Self {
        Self {
            source: String::new(),
            default: Some("-".to_string()),
            transform: None,
            array_item_path: None,
        }
    }
}

/// Result from parsing an API response
#[derive(Debug, Clone)]
pub struct ParsedResponse {
    /// The parsed items
    pub items: Vec<Value>,
    /// Next page token if pagination is available
    pub next_token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_protocol_deserialize() {
        let json = r#""query""#;
        let protocol: ApiProtocol = serde_json::from_str(json).unwrap();
        assert_eq!(protocol, ApiProtocol::Query);

        let json = r#""json""#;
        let protocol: ApiProtocol = serde_json::from_str(json).unwrap();
        assert_eq!(protocol, ApiProtocol::Json);

        let json = r#""rest-json""#;
        let protocol: ApiProtocol = serde_json::from_str(json).unwrap();
        assert_eq!(protocol, ApiProtocol::RestJson);

        let json = r#""rest-xml""#;
        let protocol: ApiProtocol = serde_json::from_str(json).unwrap();
        assert_eq!(protocol, ApiProtocol::RestXml);
    }

    #[test]
    fn test_field_mapping_deserialize() {
        let json = r#"{"source": "/instanceId"}"#;
        let mapping: FieldMapping = serde_json::from_str(json).unwrap();
        assert_eq!(mapping.source, "/instanceId");
        assert_eq!(mapping.default, None);

        let json = r#"{"source": "/ipAddress", "default": "-"}"#;
        let mapping: FieldMapping = serde_json::from_str(json).unwrap();
        assert_eq!(mapping.source, "/ipAddress");
        assert_eq!(mapping.default, Some("-".to_string()));
    }

    #[test]
    fn test_api_config_deserialize() {
        let json = r#"{
            "protocol": "query",
            "action": "DescribeInstances",
            "response_root": "/DescribeInstancesResponse/reservationSet"
        }"#;
        let config: ApiConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.protocol, ApiProtocol::Query);
        assert_eq!(config.action, Some("DescribeInstances".to_string()));
    }
}
