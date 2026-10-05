//! Governed email templates (item 36, M5 launch scope).
//!
//! - [`TemplateStore`]: CRUD + versioning over `email_templates` /
//!   `email_template_versions`. Org-scoped with RLS; versions are
//!   immutable (an update inserts a new version row and bumps
//!   `current_version`); names are unique per org (case-insensitive).
//! - [`render`]: the minimal safe template engine — variable
//!   substitution (`{{ user.name }}`), conditionals
//!   (`{% if x %}...{% elif y %}...{% else %}...{% endif %}`), and loops
//!   (`{% for item in items %}...{% endfor %}`). Nothing else.
//! - [`TemplateSender`]: renders a template and sends it through the M5
//!   [`EmailProvider`][crate::delivery::EmailProvider] trait.
//!
//! ## Why the engine cannot escape its sandbox
//!
//! The engine is deliberately NOT a general-purpose template language
//! (no Handlebars, no Jinja, no embedded scripting). Its safety is
//! structural, not a blocklist:
//!
//! 1. **No expression grammar.** Tag payloads are one of exactly three
//!    shapes: a dotted variable path (`{{ a.b.c }}`), an `if`/`elif`
//!    guard (a dotted path), or a `for x in list` header (two dotted
//!    paths and one bare identifier). There is no syntax for function
//!    calls, operators, filters, method invocation, string literals
//!    with escapes, or sub-expressions — the parser rejects anything
//!    else with [`RenderError::BadTag`]. A template author cannot *write*
//!    an escape because the language has no words for one.
//! 2. **Data-only lookup.** Paths resolve against the caller-supplied
//!    JSON context object and nothing else. There are no globals, no
//!    builtins, no environment access, no includes/extends, no access
//!    to the filesystem, network, or process. Lookup indexes
//!    `serde_json::Value` maps/arrays — there is no method dispatch, no
//!    prototype chain, no `__proto__`/`constructor` semantics: those are
//!    just inert map keys that resolve to nothing.
//! 3. **Fail-closed on missing data.** An unresolvable path is
//!    [`RenderError::MissingVariable`], not an empty string — a
//!    security-sensitive send never silently drops a field.
//! 4. **Bounded execution.** Loops are capped at 10,000 iterations and
//!    total output at 1,000,000 chars ([`RenderError::LimitExceeded`]);
//!    a malicious or pathological template cannot loop forever or
//!    memory-bomb the renderer.
//! 5. **Output escaping.** Substituted values are HTML-escaped by
//!    default, so a context value containing markup renders inert.
//!
//! ## Cross-org safety
//!
//! Template rows are tenant-scoped (RLS); [`TemplateStore::get`] under
//! org B's context cannot see org A's templates (NotFound, no oracle).
//! Rendering reads only the caller-provided `context` JSON — the engine
//! performs zero database reads, so a render can never pull another
//! org's data.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use uuid::Uuid;

use crate::delivery::{EmailProvider, ProviderError, SendReceipt, SendRequest};

/// Max loop iterations per `{% for %}` (DoS bound).
const MAX_LOOP_ITERS: usize = 10_000;
/// Max rendered output chars (DoS bound).
const MAX_OUTPUT_CHARS: usize = 1_000_000;

// ---------------------------------------------------------------------------
// Template store
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TemplateSummary {
    pub id: Uuid,
    pub name: String,
    pub current_version: i32,
    pub status: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct TemplateVersion {
    pub template_id: Uuid,
    pub name: String,
    pub version: i32,
    pub subject: String,
    pub body: String,
    pub status: String,
}

pub struct TemplateStore {
    core: CoreDb,
}

fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > 120 {
        return false;
    }
    let first_ok = b[0].is_ascii_alphanumeric();
    first_ok
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'.' || *c == b'_' || *c == b'-')
}

impl TemplateStore {
    pub fn new(core: CoreDb) -> Self {
        Self { core }
    }

    fn check_fields(name: &str, subject: &str, body: &str) -> Result<()> {
        if !valid_name(name) {
            return Err(TinkerError::Validation(
                "template name must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$".into(),
            ));
        }
        if subject.is_empty() || subject.len() > 500 {
            return Err(TinkerError::Validation(
                "template subject must be 1-500 chars".into(),
            ));
        }
        if body.is_empty() || body.len() > 100_000 {
            return Err(TinkerError::Validation(
                "template body must be 1-100000 chars".into(),
            ));
        }
        Ok(())
    }

    /// Create a template at version 1. Name collisions (per org,
    /// case-insensitive) fail with a generic message.
    pub async fn create(
        &self,
        ctx: &TenantContext,
        name: &str,
        subject: &str,
        body: &str,
    ) -> Result<TemplateSummary> {
        Self::check_fields(name, subject, body)?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO email_templates
                 (organization_id, name, created_by)
             VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(ctx.organization_id.0)
        .bind(name)
        .bind(ctx.actor_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            if e.as_database_error()
                .and_then(|d| d.code())
                .is_some_and(|c| c == "23505")
            {
                TinkerError::Validation("template name unavailable".into())
            } else {
                TinkerError::Db(e)
            }
        })?;
        sqlx::query(
            "INSERT INTO email_template_versions
                 (template_id, organization_id, version, subject, body, created_by)
             VALUES ($1, $2, 1, $3, $4, $5)",
        )
        .bind(id)
        .bind(ctx.organization_id.0)
        .bind(subject)
        .bind(body)
        .bind(ctx.actor_id)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await?;
        let mut tx2 = self.core.tenant_tx(ctx).await?;
        let summary = self
            .summary_for(&mut tx2, ctx, id)
            .await?
            .ok_or_else(|| TinkerError::Internal("template vanished after create".into()))?;
        tx2.commit().await?;
        Ok(summary)
    }

    async fn summary_for(
        &self,
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        ctx: &TenantContext,
        template_id: Uuid,
    ) -> Result<Option<TemplateSummary>> {
        let row: Option<(Uuid, String, i32, String, DateTime<Utc>)> = sqlx::query_as(
            "SELECT id, name, current_version, status, updated_at FROM email_templates
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(template_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(TinkerError::Db)?;
        Ok(row.map(
            |(id, name, current_version, status, updated_at)| TemplateSummary {
                id,
                name,
                current_version,
                status,
                updated_at,
            },
        ))
    }

    async fn version_row(
        &self,
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        ctx: &TenantContext,
        template_id: Uuid,
        version: i32,
    ) -> Result<Option<TemplateVersion>> {
        let row: Option<(Uuid, String, i32, String, String, String)> = sqlx::query_as(
            "SELECT v.template_id, t.name, v.version, v.subject, v.body, t.status
             FROM email_template_versions v
             JOIN email_templates t ON t.id = v.template_id
             WHERE v.organization_id = $1 AND v.template_id = $2 AND v.version = $3",
        )
        .bind(ctx.organization_id.0)
        .bind(template_id)
        .bind(version)
        .fetch_optional(&mut **tx)
        .await
        .map_err(TinkerError::Db)?;
        Ok(row.map(
            |(template_id, name, version, subject, body, status)| TemplateVersion {
                template_id,
                name,
                version,
                subject,
                body,
                status,
            },
        ))
    }

    /// Update = new immutable version. Archived templates cannot be
    /// updated (unarchive is not a v1 operation — create a new template).
    pub async fn update(
        &self,
        ctx: &TenantContext,
        template_id: Uuid,
        subject: &str,
        body: &str,
    ) -> Result<TemplateSummary> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let summary = self
            .summary_for(&mut tx, ctx, template_id)
            .await?
            .ok_or_else(|| TinkerError::NotFound("template".into()))?;
        if summary.status != "active" {
            return Err(TinkerError::Validation("template is archived".into()));
        }
        Self::check_fields(&summary.name, subject, body)?;
        let next = summary.current_version + 1;
        sqlx::query(
            "INSERT INTO email_template_versions
                 (template_id, organization_id, version, subject, body, created_by)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(template_id)
        .bind(ctx.organization_id.0)
        .bind(next)
        .bind(subject)
        .bind(body)
        .bind(ctx.actor_id)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        sqlx::query(
            "UPDATE email_templates
             SET current_version = $3, updated_at = now()
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(template_id)
        .bind(next)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await?;
        Ok(TemplateSummary {
            current_version: next,
            ..summary
        })
    }

    /// Current version of an ACTIVE template by name. Archived or
    /// foreign-org templates resolve to NotFound (no oracle).
    pub async fn get(&self, ctx: &TenantContext, name: &str) -> Result<TemplateVersion> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM email_templates
             WHERE organization_id = $1 AND lower(name) = lower($2) AND status = 'active'",
        )
        .bind(ctx.organization_id.0)
        .bind(name)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let id = id.ok_or_else(|| TinkerError::NotFound("template".into()))?;
        let summary = self
            .summary_for(&mut tx, ctx, id)
            .await?
            .ok_or_else(|| TinkerError::NotFound("template".into()))?;
        let v = self
            .version_row(&mut tx, ctx, id, summary.current_version)
            .await?
            .ok_or_else(|| TinkerError::Internal("template version row missing".into()))?;
        tx.commit().await?;
        Ok(v)
    }

    /// Any version of a template by id (includes archived; still
    /// tenant-scoped).
    pub async fn get_by_id(
        &self,
        ctx: &TenantContext,
        template_id: Uuid,
    ) -> Result<TemplateVersion> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let summary = self
            .summary_for(&mut tx, ctx, template_id)
            .await?
            .ok_or_else(|| TinkerError::NotFound("template".into()))?;
        let v = self
            .version_row(&mut tx, ctx, template_id, summary.current_version)
            .await?
            .ok_or_else(|| TinkerError::Internal("template version row missing".into()))?;
        tx.commit().await?;
        Ok(v)
    }

    pub async fn get_version(
        &self,
        ctx: &TenantContext,
        template_id: Uuid,
        version: i32,
    ) -> Result<TemplateVersion> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let v = self
            .version_row(&mut tx, ctx, template_id, version)
            .await?
            .ok_or_else(|| TinkerError::NotFound("template version".into()))?;
        tx.commit().await?;
        Ok(v)
    }

    pub async fn list(&self, ctx: &TenantContext) -> Result<Vec<TemplateSummary>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<(Uuid, String, i32, String, DateTime<Utc>)> = sqlx::query_as(
            "SELECT id, name, current_version, status, updated_at FROM email_templates
             WHERE organization_id = $1 ORDER BY name",
        )
        .bind(ctx.organization_id.0)
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await?;
        Ok(rows
            .into_iter()
            .map(
                |(id, name, current_version, status, updated_at)| TemplateSummary {
                    id,
                    name,
                    current_version,
                    status,
                    updated_at,
                },
            )
            .collect())
    }

    pub async fn archive(&self, ctx: &TenantContext, template_id: Uuid) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let n = sqlx::query(
            "UPDATE email_templates SET status = 'archived', updated_at = now()
             WHERE organization_id = $1 AND id = $2 AND status = 'active'",
        )
        .bind(ctx.organization_id.0)
        .bind(template_id)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?
        .rows_affected();
        tx.commit().await?;
        if n == 0 {
            return Err(TinkerError::NotFound("template".into()));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Minimal safe template engine

/// Engine-local result: parse/render failures are [`RenderError`],
/// not [`TinkerError`].
type EngineResult<T> = std::result::Result<T, RenderError>;
// ---------------------------------------------------------------------------

/// Render failure. Every variant is fail-closed: a template that does
/// not parse or does not resolve renders NOTHING (the caller gets the
/// error, never partial output).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RenderError {
    #[error("unclosed tag")]
    UnclosedTag,
    #[error("bad tag: {0}")]
    BadTag(String),
    #[error("missing variable: {0}")]
    MissingVariable(String),
    #[error("render limit exceeded")]
    LimitExceeded,
    #[error("context must be a JSON object")]
    BadContext,
}

#[derive(Debug)]
enum Node {
    Text(String),
    Var(Vec<String>),
    If {
        cond: Vec<String>,
        then: Vec<Node>,
        elifs: Vec<(Vec<String>, Vec<Node>)>,
        els: Vec<Node>,
    },
    For {
        var: String,
        list: Vec<String>,
        body: Vec<Node>,
    },
}

fn is_ident(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

fn parse_path(s: &str) -> EngineResult<Vec<String>> {
    let s = s.trim();
    if s.is_empty() {
        return Err(RenderError::BadTag("empty variable".into()));
    }
    let segs: Vec<String> = s.split('.').map(str::to_string).collect();
    if segs.iter().all(|p| is_ident(p)) {
        Ok(segs)
    } else {
        Err(RenderError::BadTag(format!("bad variable path: {s}")))
    }
}

struct Parser<'a> {
    src: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn rest(&self) -> &'a str {
        &self.src[self.pos..]
    }

    /// Parse nodes until EOF or one of `terminators` (the first
    /// whitespace-delimited keyword of the tag). Returns the matched
    /// terminator's FULL inner tag text, still positioned at its `{%`.
    fn parse_block(&mut self, terminators: &[&str]) -> EngineResult<(Vec<Node>, Option<String>)> {
        let mut nodes = Vec::new();
        loop {
            let rest = self.rest();
            let var_at = rest.find("{{");
            let tag_at = rest.find("{%");
            let next = match (var_at, tag_at) {
                (Some(v), Some(t)) => Some(v.min(t)),
                (Some(v), None) => Some(v),
                (None, Some(t)) => Some(t),
                (None, None) => None,
            };
            let Some(rel) = next else {
                if !rest.is_empty() {
                    nodes.push(Node::Text(rest.to_string()));
                    self.pos = self.src.len();
                }
                return Ok((nodes, None));
            };
            if rel > 0 {
                nodes.push(Node::Text(rest[..rel].to_string()));
                self.pos += rel;
            }
            let rest = self.rest();
            if rest.starts_with("{{") {
                // Search for the closer AFTER the opener: `{{}` must not
                // match its own braces (that sliced `[2..1]` and panicked).
                let end = close_after_opener(rest, "}}")?;
                let inner = &rest[2..end];
                nodes.push(Node::Var(parse_path(inner)?));
                self.pos += end + 2;
            } else {
                // Starts with "{%" (the min() above guarantees one of them).
                let end = close_after_opener(rest, "%}")?;
                let inner = rest[2..end].trim().to_string();
                let kw = inner.split_whitespace().next().unwrap_or("");
                if terminators.contains(&kw) {
                    return Ok((nodes, Some(inner)));
                }
                self.pos += end + 2;
                match kw {
                    "if" => nodes.push(self.parse_if(&inner)?),
                    "for" => nodes.push(self.parse_for(&inner)?),
                    _ => return Err(RenderError::BadTag(inner)),
                }
            }
        }
    }

    /// Consume the tag the parser is currently positioned at (through
    /// its `%}`).
    fn consume_tag(&mut self) -> EngineResult<()> {
        let idx = close_after_opener(self.rest(), "%}")?;
        self.pos += idx + 2;
        Ok(())
    }

    fn parse_if(&mut self, inner: &str) -> EngineResult<Node> {
        let cond = parse_path(inner["if".len()..].trim())?;
        let (then, term) = self.parse_block(&["elif", "else", "endif"])?;
        let mut term = term.ok_or(RenderError::UnclosedTag)?;
        self.consume_tag()?;
        let mut elifs = Vec::new();
        let mut els = Vec::new();
        loop {
            let kw = term.split_whitespace().next().unwrap_or("");
            match kw {
                "elif" => {
                    let econd = parse_path(term["elif".len()..].trim())?;
                    let (body, t) = self.parse_block(&["elif", "else", "endif"])?;
                    elifs.push((econd, body));
                    term = t.ok_or(RenderError::UnclosedTag)?;
                    self.consume_tag()?;
                }
                "else" => {
                    let (body, t) = self.parse_block(&["endif"])?;
                    let t = t.ok_or(RenderError::UnclosedTag)?;
                    if t.split_whitespace().next() != Some("endif") {
                        return Err(RenderError::UnclosedTag);
                    }
                    self.consume_tag()?;
                    els = body;
                    break;
                }
                "endif" => break,
                _ => return Err(RenderError::BadTag(term)),
            }
        }
        Ok(Node::If {
            cond,
            then,
            elifs,
            els,
        })
    }

    fn parse_for(&mut self, inner: &str) -> EngineResult<Node> {
        let rest = inner["for".len()..].trim();
        let (var, list) = rest
            .split_once(" in ")
            .ok_or_else(|| RenderError::BadTag(inner.to_string()))?;
        let var = var.trim();
        if !is_ident(var) {
            return Err(RenderError::BadTag(inner.to_string()));
        }
        let list = parse_path(list.trim())?;
        let (body, term) = self.parse_block(&["endfor"])?;
        let term = term.ok_or(RenderError::UnclosedTag)?;
        if term.split_whitespace().next() != Some("endfor") {
            return Err(RenderError::BadTag(term));
        }
        self.consume_tag()?;
        Ok(Node::For {
            var: var.to_string(),
            list,
            body,
        })
    }
}

fn parse_template(src: &str) -> EngineResult<Vec<Node>> {
    let mut p = Parser { src, pos: 0 };
    let (nodes, term) = p.parse_block(&[])?;
    if term.is_some() {
        return Err(RenderError::BadTag("stray terminator".into()));
    }
    Ok(nodes)
}

struct Scope<'a> {
    root: &'a Value,
    frames: Vec<HashMap<String, Value>>,
}

fn lookup(scope: &Scope<'_>, path: &[String]) -> Option<Value> {
    let first = &path[0];
    let mut cur: Option<Value> = None;
    for frame in scope.frames.iter().rev() {
        if let Some(v) = frame.get(first) {
            cur = Some(v.clone());
            break;
        }
    }
    if cur.is_none() {
        cur = scope.root.get(first).cloned();
    }
    let mut cur = cur?;
    for seg in &path[1..] {
        match &cur {
            Value::Object(m) => cur = m.get(seg)?.clone(),
            Value::Array(a) => {
                let i: usize = seg.parse().ok()?;
                cur = a.get(i)?.clone();
            }
            _ => return None,
        }
    }
    Some(cur)
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(v).unwrap_or_default(),
    }
}

struct Renderer<'a> {
    scope: Scope<'a>,
    out: String,
}

impl Renderer<'_> {
    fn push_str(&mut self, s: &str) -> EngineResult<()> {
        if self.out.len() + s.len() > MAX_OUTPUT_CHARS {
            return Err(RenderError::LimitExceeded);
        }
        self.out.push_str(s);
        Ok(())
    }

    fn render_nodes(&mut self, nodes: &[Node]) -> EngineResult<()> {
        for n in nodes {
            match n {
                Node::Text(t) => self.push_str(t)?,
                Node::Var(path) => {
                    let v = lookup(&self.scope, path)
                        .ok_or_else(|| RenderError::MissingVariable(path.join(".")))?;
                    let s = escape_html(&value_to_string(&v));
                    self.push_str(&s)?;
                }
                Node::If {
                    cond,
                    then,
                    elifs,
                    els,
                } => {
                    let c = lookup(&self.scope, cond)
                        .ok_or_else(|| RenderError::MissingVariable(cond.join(".")))?;
                    if truthy(&c) {
                        self.render_nodes(then)?;
                    } else {
                        let mut done = false;
                        for (econd, body) in elifs {
                            let e = lookup(&self.scope, econd)
                                .ok_or_else(|| RenderError::MissingVariable(econd.join(".")))?;
                            if truthy(&e) {
                                self.render_nodes(body)?;
                                done = true;
                                break;
                            }
                        }
                        if !done {
                            self.render_nodes(els)?;
                        }
                    }
                }
                Node::For { var, list, body } => {
                    let l = lookup(&self.scope, list)
                        .ok_or_else(|| RenderError::MissingVariable(list.join(".")))?;
                    let arr = match l {
                        Value::Array(a) => a,
                        _ => {
                            return Err(RenderError::BadTag(format!(
                                "for target is not a list: {}",
                                list.join(".")
                            )));
                        }
                    };
                    if arr.len() > MAX_LOOP_ITERS {
                        return Err(RenderError::LimitExceeded);
                    }
                    for item in arr {
                        let mut frame = HashMap::new();
                        frame.insert(var.clone(), item);
                        self.scope.frames.push(frame);
                        let r = self.render_nodes(body);
                        self.scope.frames.pop();
                        r?;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Render `template` against a JSON object `context`.
///
/// See the module docs for the sandbox argument. Fails closed: any
/// malformed tag, missing variable, non-list loop target, or limit
/// breach returns an error and produces no output.
pub fn render(template: &str, context: &Value) -> EngineResult<String> {
    if !context.is_object() {
        return Err(RenderError::BadContext);
    }
    let nodes = parse_template(template)?;
    let mut r = Renderer {
        scope: Scope {
            root: context,
            frames: Vec::new(),
        },
        out: String::new(),
    };
    r.render_nodes(&nodes)?;
    Ok(r.out)
}

// ---------------------------------------------------------------------------
// Template send (reuses the M5 provider trait)
// ---------------------------------------------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Renders a template and sends it through an M5 [`EmailProvider`].
/// Template lookup is tenant-scoped, so a render under org B's context
/// can never see org A's templates; rendering itself performs no DB
/// reads, so it cannot leak cross-org data by construction.
pub struct TemplateSender<P> {
    provider: P,
    templates: TemplateStore,
}

impl<P: EmailProvider> TemplateSender<P> {
    pub fn new(provider: P, core: CoreDb) -> Self {
        Self {
            provider,
            templates: TemplateStore::new(core),
        }
    }

    pub fn store(&self) -> &TemplateStore {
        &self.templates
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    /// Render `template_name` (active version) with `context` and send
    /// to `to_actor`. The idempotency key is deterministic over
    /// (template, version, context), so a retried send dedupes at the
    /// provider instead of double-sending.
    pub async fn send(
        &self,
        ctx: &TenantContext,
        template_name: &str,
        to_actor: Uuid,
        context: &Value,
    ) -> Result<SendReceipt> {
        let t = self.templates.get(ctx, template_name).await?;
        let subject = render(&t.subject, context)
            .map_err(|e| TinkerError::Validation(format!("template subject render: {e}")))?;
        let body = render(&t.body, context)
            .map_err(|e| TinkerError::Validation(format!("template body render: {e}")))?;
        let ctx_json = serde_json::to_string(context).map_err(TinkerError::Serde)?;
        let key = format!(
            "template:{}:v{}:{}",
            t.name,
            t.version,
            sha256_hex(ctx_json.as_bytes())
        );
        self.provider
            .send(&SendRequest {
                idempotency_key: key,
                to_actor,
                to_address: None,
                subject,
                body,
            })
            .await
            .map_err(|e| match e {
                ProviderError::Transient(s) => {
                    TinkerError::Internal(format!("transient provider error: {s}"))
                }
                ProviderError::Permanent(s) => {
                    TinkerError::Internal(format!("permanent provider error: {s}"))
                }
                ProviderError::CrashSimulated => {
                    TinkerError::Internal("simulated provider crash".into())
                }
            })
    }
}

/// Byte offset of `closer` in `rest`, searching only past the 2-byte
/// opener (`{{` / `{%`) that `rest` starts with. A closer overlapping the
/// opener (`{%}`) is not a closer: the tag is unclosed.
fn close_after_opener(rest: &str, closer: &str) -> EngineResult<usize> {
    rest.get(2..)
        .and_then(|after| after.find(closer))
        .map(|i| i + 2)
        .ok_or(RenderError::UnclosedTag)
}

#[cfg(test)]
mod engine_tests {
    use super::*;
    use serde_json::json;

    fn ctx() -> Value {
        json!({
            "user": {"name": "Ada", "tags": ["a", "b"]},
            "count": 3,
            "empty": "",
            "items": [{"n": "x"}, {"n": "y"}],
        })
    }

    #[test]
    fn vars_and_escaping() {
        let out = render("Hi {{ user.name }}!", &ctx()).unwrap();
        assert_eq!(out, "Hi Ada!");
        let evil = json!({"v": "<script>alert(1)</script>"});
        let out = render("{{ v }}", &evil).unwrap();
        assert_eq!(out, "&lt;script&gt;alert(1)&lt;/script&gt;");
    }

    #[test]
    fn closer_overlapping_opener_is_unclosed_not_a_panic() {
        // `{%}` once sliced `rest[2..1]` and panicked the request task.
        for src in ["{%}", "x {%}", "{%}%}", "{{}", "{% if user.name %}{%}"] {
            assert!(render(src, &ctx()).is_err(), "{src:?} must fail closed");
        }
        assert_eq!(render("{%}", &ctx()), Err(RenderError::UnclosedTag));
        assert_eq!(render("{{}", &ctx()), Err(RenderError::UnclosedTag));
    }

    #[test]
    fn missing_variable_fails_closed() {
        assert_eq!(
            render("{{ nope }}", &ctx()),
            Err(RenderError::MissingVariable("nope".into()))
        );
        assert_eq!(
            render("{{ user.nope }}", &ctx()),
            Err(RenderError::MissingVariable("user.nope".into()))
        );
    }

    #[test]
    fn conditionals() {
        let t = "{% if user.name %}yes{% else %}no{% endif %}";
        assert_eq!(render(t, &ctx()).unwrap(), "yes");
        let t = "{% if empty %}yes{% elif user.name %}elif{% else %}no{% endif %}";
        assert_eq!(render(t, &ctx()).unwrap(), "elif");
        let t = "{% if empty %}yes{% else %}no{% endif %}";
        assert_eq!(render(t, &ctx()).unwrap(), "no");
    }

    #[test]
    fn loops() {
        let out = render("{% for i in items %}[{{ i.n }}]{% endfor %}", &ctx()).unwrap();
        assert_eq!(out, "[x][y]");
        // Loop var shadows nothing outside; missing list fails closed.
        assert!(render("{% for i in nope %}x{% endfor %}", &ctx()).is_err());
        assert!(render("{% for i in user.name %}x{% endfor %}", &ctx()).is_err());
    }

    #[test]
    fn malicious_templates_are_inert() {
        // No function calls, no expressions, no attribute smuggling.
        for bad in [
            "{{ (function(){})() }}",
            "{{ a; drop table }}",
            "{{ __proto__.polluted }}",
            "{% include \"evil\" %}",
            "{% for x in [1,2] %}{% endfor %}",
            "{{ user.name | upper }}",
            "{% if 1 == 1 %}yes{% endif %}",
            "{{ `whoami` }}",
        ] {
            let r = render(bad, &ctx());
            assert!(r.is_err(), "expected inert/error for {bad:?}, got {r:?}");
        }
        // Unknown dunder-ish keys are just missing variables (inert).
        assert_eq!(
            render("{{ constructor }}", &ctx()),
            Err(RenderError::MissingVariable("constructor".into()))
        );
    }

    #[test]
    fn unclosed_and_stray_tags_fail() {
        assert_eq!(
            render("{{ user.name", &ctx()),
            Err(RenderError::UnclosedTag)
        );
        assert_eq!(render("{% if x %}y", &ctx()), Err(RenderError::UnclosedTag));
        assert_eq!(
            render("{% if user.name %}y{% endif %}{% endif %}", &ctx()),
            Err(RenderError::BadTag("endif".into()))
        );
    }

    #[test]
    fn output_limit_binds() {
        let big: Vec<Value> = (0..20_000).map(|i| json!({"n": i})).collect();
        let c = json!({"items": big});
        // 20k iterations > MAX_LOOP_ITERS.
        assert_eq!(
            render("{% for i in items %}x{% endfor %}", &c),
            Err(RenderError::LimitExceeded)
        );
    }

    #[test]
    fn non_object_context_rejected() {
        assert_eq!(render("hi", &json!([1, 2])), Err(RenderError::BadContext));
    }
}
