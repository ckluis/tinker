//! Portfolio packs (PRD M3): declarative, installable bundles of objects,
//! fields, relations, and apps.
//!
//! A pack is a TOML document: objects with typed fields (relations name
//! their target by slug), plus app definitions whose rt-grid queries use
//! `from_slug` where the object id will go. The [`PackInstaller`] is the
//! platform-authorized path — it holds the owner database handle and is
//! constructed by the binary/CLI, never by a tenant HTTP handler.
//!
//! Install is two phases: [`PackInstaller::install_objects`] creates the
//! shared platform tables (two passes: objects first, then fields so
//! relations can resolve by slug); [`PackInstaller::install_app`] creates
//! the app inside one organization's workspace, rewrites `from_slug` to
//! the real object ids, and publishes.

use std::collections::HashMap;

use serde::Deserialize;
use tinker_apps::{AppDefinition, AppRegistry, AppTokens};
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_ontology::{FieldDef, FieldType, ObjectDef, Ontology, PlatformFieldRow, Scope};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
pub struct PackDefinition {
    pub pack: PackMeta,
    #[serde(default)]
    pub objects: Vec<PackObject>,
    #[serde(default)]
    pub apps: Vec<PackApp>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PackMeta {
    pub id: String,
    pub version: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PackObject {
    pub name: String,
    pub api_slug: String,
    pub label: String,
    #[serde(default)]
    pub fields: Vec<PackField>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PackField {
    pub name: String,
    pub api_name: String,
    pub label: String,
    pub field_type: String,
    /// For `select`: the allowed options.
    #[serde(default)]
    pub options: Vec<String>,
    /// For `relation`: the target object's `api_slug` within this pack.
    #[serde(default)]
    pub relation_target: Option<String>,
    #[serde(default)]
    pub required: bool,
    /// Vault-backed field (docs/pii-sensitive-fields.md). Fixed at first
    /// install: a reinstall that disagrees is drift and fails closed.
    #[serde(default)]
    pub sensitive: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PackApp {
    pub slug: String,
    pub name: String,
    pub definition: AppDefinition,
}

/// Object ids by api_slug, from a pack install.
#[derive(Debug, Clone, Default)]
pub struct InstalledPack {
    pub objects: HashMap<String, Uuid>,
}

/// What installing an app produced: the app id plus the portable
/// component ids that were rewritten from slugs to object ids.
#[derive(Debug, Clone, Default)]
pub struct InstalledApp {
    pub app_id: Uuid,
    pub slug: String,
    /// component id -> installed object id for every rewritten `from_slug`.
    pub object_ids: HashMap<String, Uuid>,
}

impl PackDefinition {
    pub fn from_toml(text: &str) -> Result<Self> {
        toml::from_str(text).map_err(|e| TinkerError::Validation(format!("bad pack toml: {e}")))
    }
}

/// The signature of a lost check-then-create race against a concurrent
/// installer. Two shapes:
/// - raw `TinkerError::Db` 23505 (unique violation), e.g. a field insert
///   that raced under the DDL lock;
/// - `TinkerError::Validation("object slug already exists: ...")`, which is
///   how `define_object_inner` reports the 23505 on the slug unique index
///   (and 42P07 on the physical table). The message contract is pinned by
///   `concurrent_cross_pack_slug_collision_converges` — if the ontology
///   ever rewords it, that test fails and this predicate must follow.
fn is_concurrent_create_race(e: &TinkerError) -> bool {
    match e {
        TinkerError::Db(sqlx::Error::Database(dbe)) => dbe.code().as_deref() == Some("23505"),
        TinkerError::Validation(m) => m.starts_with("object slug already exists: "),
        _ => false,
    }
}

/// Platform-authorized pack installer. Construct it with the owner
/// ontology handle; it never touches tenant-scoped APIs for DDL.
pub struct PackInstaller {
    ontology: Ontology,
    apps: AppRegistry,
}

impl PackInstaller {
    pub fn new(ontology: Ontology, apps: AppRegistry) -> Self {
        Self { ontology, apps }
    }

    /// Install the pack's objects as platform objects (two passes: objects,
    /// then fields so relations resolve by slug). Idempotent per slug: a
    /// re-install resolves existing platform objects instead of forking
    /// tables or failing on duplicates, and reconciles drift: missing pack
    /// fields are re-added, drifted field metadata (name/label/required/
    /// options) is restored to the declared values, and a type-drifted pack
    /// field fails closed — reinstall never rewrites a physical column.
    /// Fields on the object that the pack does not declare are left alone;
    /// removing them would be destructive.
    ///
    /// Evolution-aware by construction: evolved fields live on
    /// per-organization extension tables, never in `ontology_fields`, so
    /// reinstall cannot see or clobber them.
    ///
    /// Serialized per pack via the install lock: the passes are
    /// check-then-create on slugs, which races without the lock (two
    /// installers can both observe a missing slug and both attempt the
    /// define). Installs of disjoint packs proceed concurrently; the
    /// loser of a genuine cross-pack slug race re-resolves per object in
    /// pass 1 (a failed define implies the winner committed), and keeps
    /// one whole-pass retry as a backstop for field-level races — either
    /// way it converges through the idempotent resolve-existing path.
    pub async fn install_objects(&self, pack: &PackDefinition) -> Result<InstalledPack> {
        let lock = self
            .ontology
            .install_lock(&Self::install_lock_key(&pack.pack.id))
            .await?;
        let result = self.install_objects_inner(pack).await;
        let result = match result {
            Err(e) if is_concurrent_create_race(&e) => {
                // Cross-pack slug race: the winner committed between our
                // check and our create. One retry converges via the
                // idempotent re-read; a second failure is returned as-is
                // (something genuinely unexpected, not a race).
                self.install_objects_inner(pack).await
            }
            other => other,
        };
        lock.release().await?;
        result
    }

    /// Advisory-lock key for a pack's install. Per-pack (not global), so
    /// concurrent installs of disjoint packs proceed in parallel while
    /// installs of the same pack still serialize on check-then-create.
    pub fn install_lock_key(pack_id: &str) -> String {
        format!("tinker-pack-install:{pack_id}")
    }

    async fn install_objects_inner(&self, pack: &PackDefinition) -> Result<InstalledPack> {
        let mut installed = InstalledPack::default();
        // Pass 1: objects. Per-object check-then-create with re-resolve on
        // a lost race: a failed define implies the winner committed, so the
        // next resolve finds it. This converges no matter how many objects
        // in the pack collide (a single whole-pass retry could not: it
        // would spend its one retry on the first collision and die on the
        // second).
        for obj in &pack.objects {
            let def = ObjectDef {
                name: obj.name.clone(),
                api_slug: obj.api_slug.clone(),
                label: obj.label.clone(),
                scope: Scope::Platform,
                pack_id: Some(pack.pack.id.clone()),
                pack_version: Some(pack.pack.version.clone()),
            };
            let meta = loop {
                match self.ontology.platform_object_by_slug(&obj.api_slug).await? {
                    Some(existing) => break existing,
                    None => match self.ontology.define_platform_object(&def).await {
                        Ok(meta) => break meta,
                        Err(e) if is_concurrent_create_race(&e) => continue,
                        Err(e) => return Err(e),
                    },
                }
            };
            installed.objects.insert(obj.api_slug.clone(), meta.id);
        }
        // Pass 2: fields (relations resolve against pass 1), in two phases
        // so a type-drifted field fails closed BEFORE anything is written.
        for obj in &pack.objects {
            let object_id = installed.objects[&obj.api_slug];
            let rows = self.ontology.platform_field_rows(object_id).await?;
            // Phase A (verify): every present pack field must still carry
            // its declared physical type. A mismatch is operator drift that
            // reinstall must never silently rewrite (column rewrite = data
            // loss): fail closed with the field and both types named.
            for f in &obj.fields {
                if let Some(row) = rows.iter().find(|r| r.api_name == f.api_name) {
                    let declared = pack_field_type(f, &installed)?;
                    check_no_type_drift(&obj.api_slug, f, &declared, row)?;
                }
            }
            // Phase B (execute): re-add missing pack fields (restores
            // dropped fields); restore drifted metadata on present ones.
            // Fields the pack does not declare are left alone — removing
            // them would be destructive.
            for f in &obj.fields {
                let options = pack_field_options(f);
                match rows.iter().find(|r| r.api_name == f.api_name) {
                    None => {
                        let field_type = pack_field_type(f, &installed)?;
                        self.ontology
                            .add_platform_field(
                                object_id,
                                &FieldDef {
                                    validation: Default::default(),
                                    preset: None,
                                    max_pii_class: "restricted".to_string(),
                                    sensitive: f.sensitive,
                                    name: f.name.clone(),
                                    api_name: f.api_name.clone(),
                                    label: f.label.clone(),
                                    field_type,
                                    options,
                                    required: f.required,
                                },
                            )
                            .await?;
                    }
                    Some(row) => {
                        // The physical column differs (UUID ref vs value),
                        // so a flipped flag is not a metadata repair.
                        let declared =
                            f.sensitive || matches!(f.field_type.as_str(), "email" | "phone");
                        if row.sensitive != declared {
                            return Err(TinkerError::Validation(format!(
                                "pack field '{}' drifted: declared sensitive={} but installed \
                                 sensitive={}; reinstall refuses to rewrite the column",
                                f.api_name, declared, row.sensitive
                            )));
                        }
                        if row.name != f.name
                            || row.label != f.label
                            || row.required != f.required
                            || row.options_json != options
                        {
                            self.ontology
                                .update_platform_field_metadata(
                                    object_id,
                                    &f.api_name,
                                    &f.name,
                                    &f.label,
                                    f.required,
                                    &options,
                                )
                                .await?;
                        }
                    }
                }
            }
        }
        Ok(installed)
    }

    /// Install one of the pack's apps into an organization's workspace:
    /// create, rewrite `from_slug` query refs to installed object ids,
    /// save a draft, and publish it.
    pub async fn install_app(
        &self,
        ctx: &TenantContext,
        workspace_id: Uuid,
        pack: &PackDefinition,
        installed: &InstalledPack,
        app_slug: &str,
    ) -> Result<InstalledApp> {
        let pack_app = pack
            .apps
            .iter()
            .find(|a| a.slug == app_slug)
            .ok_or_else(|| TinkerError::NotFound(format!("pack app {app_slug}")))?;
        let app_id = self
            .apps
            .create_app(
                ctx.organization_id.0,
                workspace_id,
                ctx.actor_id,
                &pack_app.slug,
                &pack_app.name,
            )
            .await?;
        let mut definition = pack_app.definition.clone();
        let object_ids = rewrite_from_slugs(&mut definition, installed)?;
        let version = self
            .apps
            .save_draft(
                ctx.organization_id.0,
                ctx.actor_id,
                app_id,
                &definition,
                &AppTokens {
                    brand: String::new(),
                    accent: String::new(),
                },
            )
            .await?;
        self.apps
            .publish(ctx.organization_id.0, ctx.actor_id, app_id, version)
            .await?;
        Ok(InstalledApp {
            app_id,
            slug: pack_app.slug.clone(),
            object_ids,
        })
    }
}

/// Declared options JSON for a pack field: `{"options": [...]}` for
/// selects, null otherwise — the shape `add_platform_field` stores.
fn pack_field_options(f: &PackField) -> serde_json::Value {
    if f.field_type == "select" {
        serde_json::json!({ "options": f.options })
    } else {
        serde_json::Value::Null
    }
}

fn describe_field_type(ft: &FieldType) -> String {
    match ft {
        FieldType::Relation { target_object_id } => {
            format!("relation -> {target_object_id}")
        }
        other => other.kind_name().to_string(),
    }
}

/// Fail closed when a present pack field's installed type no longer matches
/// the declaration. Reinstall restores metadata and re-adds dropped fields,
/// but it never rewrites a physical column: that is destructive, and the
/// operator must resolve the drift deliberately.
fn check_no_type_drift(
    object_slug: &str,
    f: &PackField,
    declared: &FieldType,
    row: &PlatformFieldRow,
) -> Result<()> {
    let kind_ok = declared.kind_name() == row.field_type;
    let target_ok = match declared {
        FieldType::Relation { target_object_id } => {
            row.relation_target_id == Some(*target_object_id)
        }
        _ => true,
    };
    if kind_ok && target_ok {
        return Ok(());
    }
    let installed_desc = match row.relation_target_id {
        Some(t) => format!("{} -> {t}", row.field_type),
        None => row.field_type.clone(),
    };
    Err(TinkerError::Validation(format!(
        "pack field '{}' on object '{}' drifted: declared {} but installed field is {}; \
         reinstall refuses to rewrite the column — resolve the drift manually",
        f.api_name,
        object_slug,
        describe_field_type(declared),
        installed_desc,
    )))
}

fn pack_field_type(f: &PackField, installed: &InstalledPack) -> Result<FieldType> {
    match f.field_type.as_str() {
        "text" => Ok(FieldType::Text),
        "richtext" => Ok(FieldType::RichText),
        "number" => Ok(FieldType::Number),
        "date" => Ok(FieldType::Date),
        "datetime" => Ok(FieldType::DateTime),
        "boolean" => Ok(FieldType::Boolean),
        "currency" => Ok(FieldType::Currency),
        "email" => Ok(FieldType::Email),
        "phone" => Ok(FieldType::Phone),
        "url" => Ok(FieldType::Url),
        "file" => Ok(FieldType::File),
        "select" => Ok(FieldType::Select),
        "multiselect" => Ok(FieldType::MultiSelect),
        "relation" => {
            let target_slug = f.relation_target.as_deref().ok_or_else(|| {
                TinkerError::Validation(format!(
                    "relation field {} needs relation_target",
                    f.api_name
                ))
            })?;
            let target_object_id = installed.objects.get(target_slug).ok_or_else(|| {
                TinkerError::Validation(format!("unknown relation target: {target_slug}"))
            })?;
            Ok(FieldType::Relation {
                target_object_id: *target_object_id,
            })
        }
        other => Err(TinkerError::Validation(format!(
            "unknown field type: {other}"
        ))),
    }
}

/// Rewrite `props.query.from_slug` to `props.query.from` (the installed
/// object id) on every rt-grid component. The pack stays portable; the
/// installed app is concrete.
fn rewrite_from_slugs(
    definition: &mut AppDefinition,
    installed: &InstalledPack,
) -> Result<HashMap<String, Uuid>> {
    let mut rewritten = HashMap::new();
    for component in &mut definition.components {
        let Some(query) = component.props.get_mut("query") else {
            continue;
        };
        let Some(slug) = query.get("from_slug").and_then(|v| v.as_str()) else {
            continue;
        };
        let object_id = installed.objects.get(slug).ok_or_else(|| {
            TinkerError::Validation(format!("query references unknown pack object: {slug}"))
        })?;
        let map = query.as_object_mut().ok_or_else(|| {
            TinkerError::Validation("rt-grid query props must be an object".into())
        })?;
        map.remove("from_slug");
        map.insert(
            "from".to_string(),
            serde_json::Value::String(object_id.to_string()),
        );
        rewritten.insert(component.id.clone(), *object_id);
    }
    Ok(rewritten)
}
