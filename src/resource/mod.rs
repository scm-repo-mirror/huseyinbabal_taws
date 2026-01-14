mod fetcher;
mod registry;
pub mod sdk_dispatch;

// New data-driven dispatch modules
pub mod field_mapper;
pub mod handlers;
pub mod path_extractor;
pub mod protocol;

// New dispatcher that uses config-driven approach
mod data_driven_dispatch;

pub use fetcher::{extract_json_value, fetch_resources, fetch_resources_paginated, ResourceFilter};
pub use registry::*;
pub use sdk_dispatch::{describe_resource, execute_action, format_log_timestamp, invoke_sdk};
