//! Platform-scope communications ontology: `comm_channel`, `comm_thread`,
//! `comm_message`.
//!
//! Defined through the owner handle (tenants can never define platform
//! objects — M0 proved the rejection), converging idempotently on
//! reinstall like the M3 pack installer. The objects materialize as real
//! tables `data.comm_channel` / `data.comm_thread` / `data.comm_message`
//! with typed columns; the ontology's RLS keeps every row tenant-scoped.

use std::collections::HashMap;
use tinker_core::Result;
use tinker_ontology::{FieldDef, FieldType, ObjectDef, Ontology, Scope};
use uuid::Uuid;

pub const CHANNEL_SLUG: &str = "comm_channel";
pub const THREAD_SLUG: &str = "comm_thread";
pub const MESSAGE_SLUG: &str = "comm_message";

/// Object ids plus the physical `data.*` table names, resolved once at
/// install so the write path never re-describes per row.
#[derive(Debug, Clone)]
pub struct InstalledComms {
    pub objects: HashMap<String, Uuid>,
    pub channel_id: Uuid,
    pub thread_id: Uuid,
    pub message_id: Uuid,
    pub channel_table: String,
    pub thread_table: String,
    pub message_table: String,
}

pub struct CommsInstaller {
    ontology: Ontology,
}

impl CommsInstaller {
    pub fn new(ontology: Ontology) -> Self {
        Self { ontology }
    }

    /// Install the comms objects and fields. Serialized against
    /// concurrent installs: the body is check-then-create on global
    /// slugs, which races without the session lock (two installers can
    /// both observe a missing slug and both attempt the define).
    pub async fn install(&self) -> Result<InstalledComms> {
        let lock = self.ontology.install_lock("tinker-comms-install").await?;
        let result = self.install_inner().await;
        lock.release().await?;
        result
    }

    async fn install_inner(&self) -> Result<InstalledComms> {
        let mut objects = HashMap::new();
        for (slug, name, label) in [
            (CHANNEL_SLUG, "Channel", "Communication channel"),
            (THREAD_SLUG, "Thread", "Conversation thread"),
            (MESSAGE_SLUG, "Message", "Thread message"),
        ] {
            let meta = match self.ontology.platform_object_by_slug(slug).await? {
                Some(existing) => existing,
                None => {
                    self.ontology
                        .define_platform_object(&ObjectDef {
                            name: name.into(),
                            api_slug: slug.into(),
                            label: label.into(),
                            scope: Scope::Platform,
                            pack_id: Some("tinker-comms".into()),
                            pack_version: Some("1".into()),
                        })
                        .await?
                }
            };
            objects.insert(slug.to_string(), meta.id);
        }
        let channel_id = objects[CHANNEL_SLUG];
        let thread_id = objects[THREAD_SLUG];
        let message_id = objects[MESSAGE_SLUG];

        self.ensure_fields(
            channel_id,
            vec![
                field("name", "Name", FieldType::Text, true),
                select_field("kind", "Kind", &["channel", "shared_inbox"], true),
            ],
        )
        .await?;
        self.ensure_fields(
            thread_id,
            vec![
                field("subject", "Subject", FieldType::Text, true),
                FieldDef {
                    validation: Default::default(),
                    preset: None,
                    max_pii_class: "restricted".to_string(),
                    name: "channel".into(),
                    api_name: "channel".into(),
                    label: "Channel".into(),
                    field_type: FieldType::Relation {
                        target_object_id: channel_id,
                    },
                    options: serde_json::Value::Null,
                    required: true,
                },
                select_field("status", "Status", &["open", "pending", "resolved"], true),
            ],
        )
        .await?;
        self.ensure_fields(
            message_id,
            vec![
                FieldDef {
                    validation: Default::default(),
                    preset: None,
                    max_pii_class: "restricted".to_string(),
                    name: "thread".into(),
                    api_name: "thread".into(),
                    label: "Thread".into(),
                    field_type: FieldType::Relation {
                        target_object_id: thread_id,
                    },
                    options: serde_json::Value::Null,
                    required: true,
                },
                field("author_actor_id", "Author actor", FieldType::Text, true),
                field("body", "Body", FieldType::RichText, true),
            ],
        )
        .await?;

        Ok(InstalledComms {
            objects,
            channel_id,
            thread_id,
            message_id,
            channel_table: format!("data.{CHANNEL_SLUG}"),
            thread_table: format!("data.{THREAD_SLUG}"),
            message_table: format!("data.{MESSAGE_SLUG}"),
        })
    }

    async fn ensure_fields(&self, object_id: Uuid, fields: Vec<FieldDef>) -> Result<()> {
        let existing = self.ontology.platform_field_api_names(object_id).await?;
        for f in fields {
            if existing.iter().any(|n| n == &f.api_name) {
                continue; // converge, don't duplicate
            }
            self.ontology.add_platform_field(object_id, &f).await?;
        }
        Ok(())
    }
}

fn field(api_name: &str, label: &str, field_type: FieldType, required: bool) -> FieldDef {
    FieldDef {
        validation: Default::default(),
        preset: None,
        max_pii_class: "restricted".to_string(),
        name: api_name.into(),
        api_name: api_name.into(),
        label: label.into(),
        field_type,
        options: serde_json::Value::Null,
        required,
    }
}

fn select_field(api_name: &str, label: &str, options: &[&str], required: bool) -> FieldDef {
    FieldDef {
        validation: Default::default(),
        preset: None,
        max_pii_class: "restricted".to_string(),
        name: api_name.into(),
        api_name: api_name.into(),
        label: label.into(),
        field_type: FieldType::Select,
        options: serde_json::json!({ "options": options }),
        required,
    }
}
