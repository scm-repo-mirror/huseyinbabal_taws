//! Lightweight AWS HTTP Client with SigV4 signing
//!
//! Replaces 55 AWS SDK crates with a single HTTP client

use anyhow::{anyhow, Result};
use reqwest::Client;
use aws_sigv4::http_request::{sign, SigningSettings, SignableRequest, SignableBody};
use aws_sigv4::sign::v4::SigningParams;
use aws_smithy_runtime_api::client::identity::Identity;
use std::time::SystemTime;
use std::collections::HashMap;

use super::credentials::Credentials;

/// AWS Service definition
#[derive(Debug, Clone)]
pub struct ServiceDefinition {
    /// Service signing name (e.g., "ec2", "sts", "elasticloadbalancing")
    pub signing_name: &'static str,
    /// Service endpoint prefix (e.g., "ec2", "sts", "elasticloadbalancing")
    pub endpoint_prefix: &'static str,
    /// API version (e.g., "2016-11-15" for EC2)
    pub api_version: &'static str,
    /// Protocol: "query", "json", "rest-json", "rest-xml"
    #[allow(dead_code)]
    pub protocol: Protocol,
    /// Target prefix for JSON protocol (e.g., "AWSCognitoIdentityProviderService")
    pub target_prefix: Option<&'static str>,
    /// Whether this is a global service (uses us-east-1)
    pub is_global: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Protocol {
    /// EC2/IAM style: Action=X&Version=Y as query params
    Query,
    /// JSON-RPC style with X-Amz-Target header
    Json,
    /// REST with JSON body
    RestJson,
    /// REST with XML body (S3)
    RestXml,
}

/// Service definitions for all 30 supported services
pub fn get_service(name: &str) -> Option<ServiceDefinition> {
    match name {
        "ec2" => Some(ServiceDefinition {
            signing_name: "ec2",
            endpoint_prefix: "ec2",
            api_version: "2016-11-15",
            protocol: Protocol::Query,
            target_prefix: None,
            is_global: false,
        }),
        "s3" => Some(ServiceDefinition {
            signing_name: "s3",
            endpoint_prefix: "s3",
            api_version: "2006-03-01",
            protocol: Protocol::RestXml,
            target_prefix: None,
            is_global: false,
        }),
        "iam" => Some(ServiceDefinition {
            signing_name: "iam",
            endpoint_prefix: "iam",
            api_version: "2010-05-08",
            protocol: Protocol::Query,
            target_prefix: None,
            is_global: true,
        }),
        "lambda" => Some(ServiceDefinition {
            signing_name: "lambda",
            endpoint_prefix: "lambda",
            api_version: "2015-03-31",
            protocol: Protocol::RestJson,
            target_prefix: None,
            is_global: false,
        }),
        "rds" => Some(ServiceDefinition {
            signing_name: "rds",
            endpoint_prefix: "rds",
            api_version: "2014-10-31",
            protocol: Protocol::Query,
            target_prefix: None,
            is_global: false,
        }),
        "dynamodb" => Some(ServiceDefinition {
            signing_name: "dynamodb",
            endpoint_prefix: "dynamodb",
            api_version: "2012-08-10",
            protocol: Protocol::Json,
            target_prefix: Some("DynamoDB_20120810"),
            is_global: false,
        }),
        "ecs" => Some(ServiceDefinition {
            signing_name: "ecs",
            endpoint_prefix: "ecs",
            api_version: "2014-11-13",
            protocol: Protocol::Json,
            target_prefix: Some("AmazonEC2ContainerServiceV20141113"),
            is_global: false,
        }),
        "eks" => Some(ServiceDefinition {
            signing_name: "eks",
            endpoint_prefix: "eks",
            api_version: "2017-11-01",
            protocol: Protocol::RestJson,
            target_prefix: None,
            is_global: false,
        }),
        "cloudformation" => Some(ServiceDefinition {
            signing_name: "cloudformation",
            endpoint_prefix: "cloudformation",
            api_version: "2010-05-15",
            protocol: Protocol::Query,
            target_prefix: None,
            is_global: false,
        }),
        "cloudwatchlogs" | "logs" => Some(ServiceDefinition {
            signing_name: "logs",
            endpoint_prefix: "logs",
            api_version: "2014-03-28",
            protocol: Protocol::Json,
            target_prefix: Some("Logs_20140328"),
            is_global: false,
        }),
        "sqs" => Some(ServiceDefinition {
            signing_name: "sqs",
            endpoint_prefix: "sqs",
            api_version: "2012-11-05",
            protocol: Protocol::Query,
            target_prefix: None,
            is_global: false,
        }),
        "sns" => Some(ServiceDefinition {
            signing_name: "sns",
            endpoint_prefix: "sns",
            api_version: "2010-03-31",
            protocol: Protocol::Query,
            target_prefix: None,
            is_global: false,
        }),
        "secretsmanager" => Some(ServiceDefinition {
            signing_name: "secretsmanager",
            endpoint_prefix: "secretsmanager",
            api_version: "2017-10-17",
            protocol: Protocol::Json,
            target_prefix: Some("secretsmanager"),
            is_global: false,
        }),
        "ssm" => Some(ServiceDefinition {
            signing_name: "ssm",
            endpoint_prefix: "ssm",
            api_version: "2014-11-06",
            protocol: Protocol::Json,
            target_prefix: Some("AmazonSSM"),
            is_global: false,
        }),
        "route53" => Some(ServiceDefinition {
            signing_name: "route53",
            endpoint_prefix: "route53",
            api_version: "2013-04-01",
            protocol: Protocol::RestXml,
            target_prefix: None,
            is_global: true,
        }),
        "apigateway" => Some(ServiceDefinition {
            signing_name: "apigateway",
            endpoint_prefix: "apigateway",
            api_version: "2015-07-09",
            protocol: Protocol::RestJson,
            target_prefix: None,
            is_global: false,
        }),
        "sts" => Some(ServiceDefinition {
            signing_name: "sts",
            endpoint_prefix: "sts",
            api_version: "2011-06-15",
            protocol: Protocol::Query,
            target_prefix: None,
            is_global: false,
        }),
        "ecr" => Some(ServiceDefinition {
            signing_name: "ecr",
            endpoint_prefix: "api.ecr",
            api_version: "2015-09-21",
            protocol: Protocol::Json,
            target_prefix: Some("AmazonEC2ContainerRegistry_V20150921"),
            is_global: false,
        }),
        "kms" => Some(ServiceDefinition {
            signing_name: "kms",
            endpoint_prefix: "kms",
            api_version: "2014-11-01",
            protocol: Protocol::Json,
            target_prefix: Some("TrentService"),
            is_global: false,
        }),
        "elasticache" => Some(ServiceDefinition {
            signing_name: "elasticache",
            endpoint_prefix: "elasticache",
            api_version: "2015-02-02",
            protocol: Protocol::Query,
            target_prefix: None,
            is_global: false,
        }),
        "cloudfront" => Some(ServiceDefinition {
            signing_name: "cloudfront",
            endpoint_prefix: "cloudfront",
            api_version: "2020-05-31",
            protocol: Protocol::RestXml,
            target_prefix: None,
            is_global: true,
        }),
        "acm" => Some(ServiceDefinition {
            signing_name: "acm",
            endpoint_prefix: "acm",
            api_version: "2015-12-08",
            protocol: Protocol::Json,
            target_prefix: Some("CertificateManager"),
            is_global: false,
        }),
        "eventbridge" | "events" => Some(ServiceDefinition {
            signing_name: "events",
            endpoint_prefix: "events",
            api_version: "2015-10-07",
            protocol: Protocol::Json,
            target_prefix: Some("AWSEvents"),
            is_global: false,
        }),
        "codepipeline" => Some(ServiceDefinition {
            signing_name: "codepipeline",
            endpoint_prefix: "codepipeline",
            api_version: "2015-07-09",
            protocol: Protocol::Json,
            target_prefix: Some("CodePipeline_20150709"),
            is_global: false,
        }),
        "codebuild" => Some(ServiceDefinition {
            signing_name: "codebuild",
            endpoint_prefix: "codebuild",
            api_version: "2016-10-06",
            protocol: Protocol::Json,
            target_prefix: Some("CodeBuild_20161006"),
            is_global: false,
        }),
        "cognitoidentityprovider" | "cognito-idp" => Some(ServiceDefinition {
            signing_name: "cognito-idp",
            endpoint_prefix: "cognito-idp",
            api_version: "2016-04-18",
            protocol: Protocol::Json,
            target_prefix: Some("AWSCognitoIdentityProviderService"),
            is_global: false,
        }),
        "cloudtrail" => Some(ServiceDefinition {
            signing_name: "cloudtrail",
            endpoint_prefix: "cloudtrail",
            api_version: "2013-11-01",
            protocol: Protocol::Json,
            target_prefix: Some("com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101"),
            is_global: false,
        }),
        "autoscaling" => Some(ServiceDefinition {
            signing_name: "autoscaling",
            endpoint_prefix: "autoscaling",
            api_version: "2011-01-01",
            protocol: Protocol::Query,
            target_prefix: None,
            is_global: false,
        }),
        "elasticloadbalancing" | "elb" | "elbv2" => Some(ServiceDefinition {
            signing_name: "elasticloadbalancing",
            endpoint_prefix: "elasticloadbalancing",
            api_version: "2015-12-01",
            protocol: Protocol::Query,
            target_prefix: None,
            is_global: false,
        }),
        "athena" => Some(ServiceDefinition {
            signing_name: "athena",
            endpoint_prefix: "athena",
            api_version: "2017-05-18",
            protocol: Protocol::Json,
            target_prefix: Some("AmazonAthena"),
            is_global: false,
        }),
        _ => None,
    }
}

/// AWS HTTP Client
pub struct AwsHttpClient {
    http_client: Client,
    credentials: Credentials,
    region: String,
}

impl AwsHttpClient {
    /// Create a new AWS HTTP client
    pub fn new(credentials: Credentials, region: &str) -> Self {
        Self {
            http_client: Client::new(),
            credentials,
            region: region.to_string(),
        }
    }

    /// Update region
    pub fn set_region(&mut self, region: &str) {
        self.region = region.to_string();
    }

    /// Update credentials
    pub fn set_credentials(&mut self, credentials: Credentials) {
        self.credentials = credentials;
    }

    /// Get the endpoint URL for a service
    fn get_endpoint(&self, service: &ServiceDefinition) -> String {
        let region = if service.is_global {
            "us-east-1"
        } else {
            &self.region
        };

        // Special case for S3
        if service.signing_name == "s3" {
            return format!("https://s3.{}.amazonaws.com", region);
        }

        // Special case for global services
        if service.is_global {
            match service.signing_name {
                "iam" => return "https://iam.amazonaws.com".to_string(),
                "route53" => return "https://route53.amazonaws.com".to_string(),
                "cloudfront" => return "https://cloudfront.amazonaws.com".to_string(),
                _ => {}
            }
        }

        format!("https://{}.{}.amazonaws.com", service.endpoint_prefix, region)
    }

    /// Make a Query protocol request (EC2, IAM, RDS, etc.)
    pub async fn query_request(
        &self,
        service_name: &str,
        action: &str,
        params: &[(&str, &str)],
    ) -> Result<String> {
        let service = get_service(service_name)
            .ok_or_else(|| anyhow!("Unknown service: {}", service_name))?;

        let endpoint = self.get_endpoint(&service);
        
        // Build query string
        let mut query_params: Vec<(String, String)> = vec![
            ("Action".to_string(), action.to_string()),
            ("Version".to_string(), service.api_version.to_string()),
        ];
        for (k, v) in params {
            query_params.push((k.to_string(), v.to_string()));
        }

        let query_string: String = query_params
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let url = format!("{}/?{}", endpoint, query_string);
        let body = "";

        self.signed_request(&service, "POST", &url, body, None).await
    }

    /// Make a JSON protocol request (DynamoDB, ECS, Logs, etc.)
    pub async fn json_request(
        &self,
        service_name: &str,
        target: &str,
        body: &str,
    ) -> Result<String> {
        let service = get_service(service_name)
            .ok_or_else(|| anyhow!("Unknown service: {}", service_name))?;

        let endpoint = self.get_endpoint(&service);
        let url = format!("{}/", endpoint);

        let target_header = format!(
            "{}.{}",
            service.target_prefix.unwrap_or(service.signing_name),
            target
        );

        let mut headers = HashMap::new();
        headers.insert("X-Amz-Target".to_string(), target_header);
        headers.insert("Content-Type".to_string(), "application/x-amz-json-1.1".to_string());

        self.signed_request(&service, "POST", &url, body, Some(headers)).await
    }

    /// Make a REST-JSON request (Lambda, API Gateway, EKS, etc.)
    pub async fn rest_json_request(
        &self,
        service_name: &str,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<String> {
        let service = get_service(service_name)
            .ok_or_else(|| anyhow!("Unknown service: {}", service_name))?;

        let endpoint = self.get_endpoint(&service);
        let url = format!("{}{}", endpoint, path);

        let mut headers = HashMap::new();
        if body.is_some() {
            headers.insert("Content-Type".to_string(), "application/json".to_string());
        }

        self.signed_request(&service, method, &url, body.unwrap_or(""), Some(headers)).await
    }

    /// Make a REST-XML request (S3, Route53, CloudFront)
    pub async fn rest_xml_request(
        &self,
        service_name: &str,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<String> {
        let service = get_service(service_name)
            .ok_or_else(|| anyhow!("Unknown service: {}", service_name))?;

        let endpoint = self.get_endpoint(&service);
        let url = format!("{}{}", endpoint, path);

        self.signed_request(&service, method, &url, body.unwrap_or(""), None).await
    }

    /// Make a signed request
    async fn signed_request(
        &self,
        service: &ServiceDefinition,
        method: &str,
        url: &str,
        body: &str,
        extra_headers: Option<HashMap<String, String>>,
    ) -> Result<String> {
        let region = if service.is_global {
            "us-east-1"
        } else {
            &self.region
        };

        // Parse URL
        let parsed_url = url::Url::parse(url)?;
        let host = parsed_url.host_str().ok_or_else(|| anyhow!("Invalid URL"))?;
        let path_and_query = if let Some(query) = parsed_url.query() {
            format!("{}?{}", parsed_url.path(), query)
        } else {
            parsed_url.path().to_string()
        };

        // Build headers
        let mut headers = vec![
            ("host".to_string(), host.to_string()),
        ];
        
        if let Some(extra) = &extra_headers {
            for (k, v) in extra {
                headers.push((k.to_lowercase(), v.clone()));
            }
        }

        // Create identity for signing
        let creds = aws_credential_types::Credentials::new(
            &self.credentials.access_key_id,
            &self.credentials.secret_access_key,
            self.credentials.session_token.clone(),
            None,
            "taws",
        );
        let identity: Identity = creds.into();
        
        // Create signing params
        let signing_params = SigningParams::builder()
            .identity(&identity)
            .region(region)
            .name(service.signing_name)
            .time(SystemTime::now())
            .settings(SigningSettings::default())
            .build()?
            .into();

        // Create signable request
        let signable_body = if body.is_empty() {
            SignableBody::Bytes(&[])
        } else {
            SignableBody::Bytes(body.as_bytes())
        };

        let signable_request = SignableRequest::new(
            method,
            &path_and_query,
            headers.iter().map(|(k, v)| (k.as_str(), v.as_str())),
            signable_body,
        )?;

        // Sign the request
        let (signing_instructions, _signature) = sign(signable_request, &signing_params)?.into_parts();

        // Build the actual request
        let mut request = match method {
            "GET" => self.http_client.get(url),
            "POST" => self.http_client.post(url),
            "PUT" => self.http_client.put(url),
            "DELETE" => self.http_client.delete(url),
            "PATCH" => self.http_client.patch(url),
            _ => return Err(anyhow!("Unsupported HTTP method: {}", method)),
        };

        // Apply signing headers
        for (name, value) in signing_instructions.headers() {
            request = request.header(name.to_string(), value.to_string());
        }

        // Apply extra headers
        if let Some(extra) = extra_headers {
            for (k, v) in extra {
                request = request.header(&k, &v);
            }
        }

        // Set body if present
        if !body.is_empty() {
            request = request.body(body.to_string());
        }

        // Send request
        let response = request.send().await?;
        let status = response.status();
        let text = response.text().await?;

        if !status.is_success() {
            return Err(anyhow!("AWS request failed ({}): {}", status, text));
        }

        Ok(text)
    }
}

/// Parse XML response to JSON (simplified)
pub fn xml_to_json(xml: &str) -> Result<serde_json::Value> {
    // Simple XML to JSON conversion for AWS responses
    // This is a simplified parser - AWS responses have predictable structures
    
    use serde_json::{Value, Map};
    
    fn parse_element(content: &str) -> Value {
        let content = content.trim();
        
        // Check if it looks like XML
        if !content.starts_with('<') {
            // It's a text value
            return Value::String(content.to_string());
        }
        
        let mut result = Map::new();
        let mut pos = 0;
        
        while pos < content.len() {
            // Find next tag
            let Some(tag_start) = content[pos..].find('<') else { break };
            let tag_start = pos + tag_start;
            
            // Skip closing tags and special tags
            if content[tag_start..].starts_with("</") || 
               content[tag_start..].starts_with("<?") ||
               content[tag_start..].starts_with("<!") {
                pos = tag_start + 1;
                if let Some(end) = content[pos..].find('>') {
                    pos = pos + end + 1;
                }
                continue;
            }
            
            let Some(tag_end) = content[tag_start..].find('>') else { break };
            let tag_end = tag_start + tag_end;
            
            // Extract tag name (handle attributes)
            let tag_content = &content[tag_start+1..tag_end];
            let tag_name = tag_content.split_whitespace().next().unwrap_or(tag_content);
            
            // Self-closing tag?
            if tag_content.ends_with('/') {
                result.insert(tag_name.trim_end_matches('/').to_string(), Value::Null);
                pos = tag_end + 1;
                continue;
            }
            
            // Find closing tag
            let close_tag = format!("</{}>", tag_name);
            let Some(close_pos) = content[tag_end..].find(&close_tag) else { 
                pos = tag_end + 1;
                continue;
            };
            let close_pos = tag_end + close_pos;
            
            // Get inner content
            let inner = &content[tag_end+1..close_pos];
            let value = parse_element(inner);
            
            // Handle duplicate keys (convert to array)
            if let Some(existing) = result.get_mut(tag_name) {
                match existing {
                    Value::Array(arr) => arr.push(value),
                    _ => {
                        let old = existing.take();
                        *existing = Value::Array(vec![old, value]);
                    }
                }
            } else {
                result.insert(tag_name.to_string(), value);
            }
            
            pos = close_pos + close_tag.len();
        }
        
        if result.is_empty() && !content.starts_with('<') {
            Value::String(content.to_string())
        } else {
            Value::Object(result)
        }
    }
    
    Ok(parse_element(xml))
}
