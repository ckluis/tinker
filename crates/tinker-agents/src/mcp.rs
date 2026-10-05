//! MCP-shaped read surface: protocol-compatible, policy-identical.
//!
//! The protocol is replaceable (MCP-compatible server; SDK/HTTP expose
//! the same compiler) — policy, lineage, and action semantics are not.
//! Every tool here routes through the semantic pipeline, so MCP reads
//! see exactly what the virtual files show: no parallel redaction logic.
//!
//! Read-only by default. Writes use typed mutation tools (the action
//! registry) — never arbitrary resource replacement.

use tinker_core::{Result, TenantContext, TinkerError};
use uuid::Uuid;

use crate::budgets::ExpansionBudget;
use crate::cache::TransformCache;
use crate::expand::ExpansionEngine;
use crate::profiles::ProfileEngine;
use crate::transforms::TransformEngine;
use crate::vfile::VirtualFileReader;

/// One MCP tool descriptor (tools/list).
#[derive(Debug, Clone, serde::Serialize)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    /// JSON Schema for the tool's arguments (required by MCP clients).
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

/// MCP resource descriptor (resources/list).
#[derive(Debug, Clone, serde::Serialize)]
pub struct McpResource {
    pub uri: String,
    pub name: String,
}

pub struct McpServer<'a> {
    engine: &'a TransformEngine,
    cache: &'a TransformCache,
    profiles: &'a ProfileEngine,
    expansion: ExpansionEngine<'a>,
}

impl<'a> McpServer<'a> {
    pub fn new(
        engine: &'a TransformEngine,
        cache: &'a TransformCache,
        profiles: &'a ProfileEngine,
        expansion: ExpansionEngine<'a>,
    ) -> Self {
        Self {
            engine,
            cache,
            profiles,
            expansion,
        }
    }

    /// tools/list: the closed read-tool set. Read tools derive from
    /// object/query metadata — the model never gets a generic console.
    pub fn tools_list() -> Vec<McpTool> {
        vec![
            McpTool {
                name: "read_virtual_file".into(),
                description: "Read an authorized virtual file projection at a /tinker/... path"
                    .into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Virtual file path (/tinker/<object>/<record>/index.md)"
                        },
                        "attachment": {
                            "type": "string",
                            "description": "Agent attachment name for attachment-scoped reads (optional)"
                        }
                    },
                    "required": ["path"]
                }),
            },
            McpTool {
                name: "expand_context".into(),
                description: "Budgeted graph expansion from a root record along declared edges"
                    .into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "profile": { "type": "string" },
                        "root_object": { "type": "string" },
                        "root_record": { "type": "string", "description": "Root record UUID" },
                        "budget": { "type": "object" },
                        "attachment": {
                            "type": "string",
                            "description": "Agent attachment name (optional; required for this tool)"
                        }
                    },
                    "required": ["profile", "root_object", "root_record"]
                }),
            },
            McpTool {
                name: "describe_profile".into(),
                description: "Describe the active context profile for a key".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "profile": { "type": "string" }
                    },
                    "required": ["profile"]
                }),
            },
        ]
    }

    /// resources/list: virtual-file resources are addressed as
    /// tinker://{object}/{record}/index.md.
    pub fn resources_list() -> Vec<McpResource> {
        vec![McpResource {
            uri: "tinker://{object}/{record}/index.md".into(),
            name: "Virtual file (authorized projection)".into(),
        }]
    }

    /// tools/call dispatcher. Unknown tools fail closed — the tool set is
    /// generated server-side, never from model output.
    pub async fn tools_call(
        &self,
        ctx: &TenantContext,
        tool: &str,
        args: serde_json::Value,
        attachment_id: Option<Uuid>,
    ) -> Result<serde_json::Value> {
        match tool {
            "read_virtual_file" => {
                let path = args.get("path").and_then(|p| p.as_str()).ok_or_else(|| {
                    TinkerError::Validation("read_virtual_file needs path".into())
                })?;
                let reader = VirtualFileReader::new(self.engine, self.cache);
                let md = reader.read(ctx, path, attachment_id).await?;
                Ok(serde_json::json!({"path": path, "markdown": md}))
            }
            "expand_context" => {
                let attachment = attachment_id.ok_or_else(|| {
                    TinkerError::Forbidden("expand_context needs an agent attachment".into())
                })?;
                let profile_key =
                    args.get("profile")
                        .and_then(|p| p.as_str())
                        .ok_or_else(|| {
                            TinkerError::Validation("expand_context needs profile".into())
                        })?;
                let root_object = args
                    .get("root_object")
                    .and_then(|p| p.as_str())
                    .ok_or_else(|| {
                        TinkerError::Validation("expand_context needs root_object".into())
                    })?;
                let root_record = args
                    .get("root_record")
                    .and_then(|p| p.as_str())
                    .and_then(|s| Uuid::parse_str(s).ok())
                    .ok_or_else(|| {
                        TinkerError::Validation("expand_context needs root_record uuid".into())
                    })?;
                let budget = ExpansionBudget::from_json(
                    args.get("budget").unwrap_or(&serde_json::Value::Null),
                );
                let profile = self.profiles.active(ctx, profile_key).await?;
                let (files, manifest) = self
                    .expansion
                    .expand(ctx, attachment, &profile, root_object, root_record, &budget)
                    .await?;
                Ok(serde_json::json!({
                    "files": files,
                    "manifest": {
                        "id": manifest.id,
                        "records": manifest.records,
                        "tokens": manifest.tokens,
                        "depth_reached": manifest.depth_reached,
                        "traversed": manifest.traversed.len(),
                        "truncated": manifest.truncated.len(),
                    },
                }))
            }
            "describe_profile" => {
                let key = args
                    .get("profile")
                    .and_then(|p| p.as_str())
                    .ok_or_else(|| {
                        TinkerError::Validation("describe_profile needs profile".into())
                    })?;
                let p = self.profiles.active(ctx, key).await?;
                Ok(serde_json::json!({
                    "key": p.profile_key, "version": p.version,
                    "status": p.status, "definition": p.definition,
                }))
            }
            other => Err(TinkerError::Forbidden(format!("unknown tool {other}"))),
        }
    }

    /// resources/read: tinker://{object}/{record}/index.md — the same
    /// compiler as the virtual files, with structured citations beside
    /// text.
    pub async fn resources_read(
        &self,
        ctx: &TenantContext,
        uri: &str,
        attachment_id: Option<Uuid>,
    ) -> Result<serde_json::Value> {
        let path = uri
            .strip_prefix("tinker://")
            .ok_or_else(|| TinkerError::Validation(format!("bad resource uri: {uri}")))?;
        let vpath = format!("/tinker/{path}");
        let reader = VirtualFileReader::new(self.engine, self.cache);
        let md = reader.read(ctx, &vpath, attachment_id).await?;
        Ok(serde_json::json!({
            "uri": uri,
            "mimeType": "text/markdown",
            "text": md,
            "citations": [{"uri": uri, "via": "semantic-pipeline"}],
        }))
    }
}
