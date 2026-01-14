//! Data-Driven SDK Dispatcher
//!
//! This module provides a new implementation of the SDK dispatcher that uses
//! configuration from JSON files instead of hard-coded match statements.
//!
//! The goal is to eventually replace the monolithic sdk_dispatch.rs with this
//! generic, data-driven approach.

use super::field_mapper::build_response;
use super::handlers::get_protocol_handler;
use super::protocol::ApiProtocol;
use super::registry::get_resource;
use crate::aws::client::AwsClients;
use anyhow::{anyhow, Result};
use serde_json::Value;

/// Invoke an AWS API using the data-driven configuration
///
/// This function reads the API configuration from the resource definition
/// and uses the appropriate protocol handler to execute the request.
///
/// # Arguments
/// * `resource_key` - The resource key (e.g., "ec2-instances", "lambda-functions")
/// * `clients` - AWS clients container
/// * `params` - Request parameters (filters, pagination token, etc.)
///
/// # Returns
/// A JSON value with the response in normalized format
pub async fn invoke_data_driven(
    resource_key: &str,
    clients: &AwsClients,
    params: &Value,
) -> Result<Value> {
    // Get resource definition
    let resource_def =
        get_resource(resource_key).ok_or_else(|| anyhow!("Unknown resource: {}", resource_key))?;

    // Check if this resource uses data-driven dispatch
    let api_config = resource_def
        .api_config
        .as_ref()
        .ok_or_else(|| anyhow!("Resource {} does not have api_config", resource_key))?;

    // Get the appropriate protocol handler
    let handler = get_protocol_handler(api_config.protocol);

    // Use service_name override from api_config if specified, otherwise use resource's service
    let service = api_config
        .service_name
        .as_deref()
        .unwrap_or(&resource_def.service);

    // Execute the API call and parse response
    let parsed = handler
        .invoke(
            clients,
            service,
            api_config,
            params,
            &resource_def.field_mappings,
        )
        .await?;

    // Build the final response
    Ok(build_response(
        parsed.items,
        &resource_def.response_path,
        parsed.next_token,
    ))
}

/// Check if a resource supports data-driven dispatch
pub fn supports_data_driven(resource_key: &str) -> bool {
    get_resource(resource_key)
        .map(|r| r.uses_data_driven_dispatch())
        .unwrap_or(false)
}

/// Get the protocol type for a resource (if using data-driven dispatch)
pub fn get_resource_protocol(resource_key: &str) -> Option<ApiProtocol> {
    get_resource(resource_key)
        .and_then(|r| r.api_config.as_ref())
        .map(|c| c.protocol)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supports_data_driven_returns_false_for_legacy() {
        // Legacy resources without api_config should return false
        let result = supports_data_driven("nonexistent-resource");
        assert!(!result);
    }

    #[test]
    fn test_dynamodb_tables_uses_data_driven() {
        // DynamoDB tables should use data-driven dispatch after migration
        let result = supports_data_driven("dynamodb-tables");
        assert!(result, "DynamoDB tables should use data-driven dispatch");
    }

    #[test]
    fn test_ec2_instances_uses_data_driven() {
        // EC2 instances now use data-driven dispatch
        let result = supports_data_driven("ec2-instances");
        assert!(result, "EC2 instances should use data-driven dispatch");
    }

    #[test]
    fn test_lambda_functions_uses_data_driven() {
        // Lambda functions should use data-driven dispatch after migration
        let result = supports_data_driven("lambda-functions");
        assert!(result, "Lambda functions should use data-driven dispatch");
    }

    #[test]
    fn test_secretsmanager_uses_data_driven() {
        // Secrets Manager should use data-driven dispatch after migration
        let result = supports_data_driven("secretsmanager-secrets");
        assert!(result, "Secrets Manager should use data-driven dispatch");
    }

    #[test]
    fn test_ssm_parameters_uses_data_driven() {
        let result = supports_data_driven("ssm-parameters");
        assert!(result, "SSM parameters should use data-driven dispatch");
    }

    #[test]
    fn test_ecr_repositories_uses_data_driven() {
        let result = supports_data_driven("ecr-repositories");
        assert!(result, "ECR repositories should use data-driven dispatch");
    }

    #[test]
    fn test_acm_certificates_uses_data_driven() {
        let result = supports_data_driven("acm-certificates");
        assert!(result, "ACM certificates should use data-driven dispatch");
    }

    #[test]
    fn test_eventbridge_rules_uses_data_driven() {
        let result = supports_data_driven("eventbridge-rules");
        assert!(result, "EventBridge rules should use data-driven dispatch");
    }

    #[test]
    fn test_eventbridge_buses_uses_data_driven() {
        let result = supports_data_driven("eventbridge-buses");
        assert!(result, "EventBridge buses should use data-driven dispatch");
    }

    #[test]
    fn test_cloudwatch_log_groups_uses_data_driven() {
        let result = supports_data_driven("cloudwatch-log-groups");
        assert!(
            result,
            "CloudWatch log groups should use data-driven dispatch"
        );
    }

    #[test]
    fn test_cloudwatch_log_streams_uses_data_driven() {
        let result = supports_data_driven("cloudwatch-log-streams");
        assert!(
            result,
            "CloudWatch log streams should use data-driven dispatch"
        );
    }
}
