//! @-mentions: extraction, tenant-scoped resolution, notification routing.
//!
//! `post_message` extracts `@handle` tokens from the body, resolves them
//! against the **caller's organization roster only**, and routes a
//! `"mention"` notification per resolved actor through
//! [`NotificationRouter`]. Security properties:
//!
//! - Resolution is a single tenant-scoped query
//!   (`organization_id = $1 AND handle = ANY($2)`): a handle that exists
//!   only in another org resolves to nothing — no cross-org handle
//!   oracle, no error leak, no notification.
//! - Unknown handles produce no notification and no error: the post
//!   succeeds identically whether or not a handle exists.
//! - Self-mentions never notify.
//! - Payloads carry ids and opaque refs only — no PII, no bodies — per
//!   the notify module contract.
//!
//! Honest limits: no mention autocomplete API; no email/push delivery
//! beyond the existing router modes (immediate/digest/off/quiet-hours).

use chrono::{DateTime, Utc};
use tinker_core::handles::normalize_handle;
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use tinker_durable::DurableRuntime;
use uuid::Uuid;

use crate::delivery::DeliveryWorker;
use crate::notify::{NotificationItem, NotificationRouter, RoutingOutcome};

/// The notification kind routed for a mention. The router treats kind as
/// an opaque string; no router change was needed.
pub const MENTION_KIND: &str = "mention";

fn is_handle_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}

/// Extract mention handles from a message body.
///
/// Rules:
/// - `@` starts a mention when it is at the start of the body or
///   preceded by a non-handle character (so `a@b.com` is not a mention),
///   and is followed by at least one handle character.
/// - The token is the maximal run of handle characters `[A-Za-z0-9._-]`;
///   trailing `.`/`-` are stripped (a stored handle never ends in one).
/// - Tokens are normalized with [`normalize_handle`]; results are
///   deduplicated preserving first-appearance order.
pub fn extract_handles(body: &str) -> Vec<String> {
    let chars: Vec<char> = body.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let is_mention_start = chars[i] == '@'
            && (i == 0 || !is_handle_char(chars[i - 1]))
            && i + 1 < chars.len()
            && is_handle_char(chars[i + 1]);
        if is_mention_start {
            let mut j = i + 1;
            while j < chars.len() && is_handle_char(chars[j]) {
                j += 1;
            }
            let token: String = chars[i + 1..j].iter().collect();
            // Strip trailing separators BEFORE normalization: "@." must
            // not normalize to the "actor" fallback and mention someone.
            let token = token.trim_end_matches(['.', '-']);
            if !token.is_empty() {
                let handle = normalize_handle(token);
                if !out.contains(&handle) {
                    out.push(handle);
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

/// Resolve handles against the caller's organization roster only.
///
/// Returns the actor ids whose handle matches, in no particular order.
/// Unknown handles resolve to nothing — this is what makes mentions
/// oracle-free across tenants.
pub async fn resolve_handles(
    core: &CoreDb,
    ctx: &TenantContext,
    handles: &[String],
) -> Result<Vec<Uuid>> {
    if handles.is_empty() {
        return Ok(Vec::new());
    }
    let mut tx = core.tenant_tx(ctx).await?;
    let ids: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM actors WHERE organization_id = $1 AND handle = ANY($2)")
            .bind(ctx.organization_id.0)
            .bind(handles)
            .fetch_all(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
    tx.commit().await?;
    Ok(ids)
}

/// The router + worker pair `post_message` uses to route mentions.
/// Construct per request (cheap: both are handle wrappers) or once and
/// share — both inner types are `Clone`.
#[derive(Clone)]
pub struct MentionNotifier {
    router: NotificationRouter,
    worker: DeliveryWorker,
}

impl MentionNotifier {
    pub fn new(router: NotificationRouter, worker: DeliveryWorker) -> Self {
        Self { router, worker }
    }

    /// Production wiring: a router over `core` plus a durable-backed
    /// delivery worker with no PII projector (mention payloads carry ids
    /// only, so no projection is needed).
    pub fn production(core: &CoreDb, owner: sqlx::PgPool) -> Self {
        let durable = DurableRuntime::new(core.clone(), owner);
        Self::new(
            NotificationRouter::new(core.clone()),
            DeliveryWorker::new(core.clone(), durable, None),
        )
    }

    /// Extract, resolve, and route mentions for a posted message.
    /// Returns one [`RoutingOutcome`] per notified actor. Self-mentions
    /// are skipped; unknown or foreign handles resolve to nothing.
    pub async fn notify_mentions(
        &self,
        core: &CoreDb,
        ctx: &TenantContext,
        message_id: Uuid,
        author_actor_id: Uuid,
        body: &str,
    ) -> Result<Vec<RoutingOutcome>> {
        let handles = extract_handles(body);
        let ids = resolve_handles(core, ctx, &handles).await?;
        let now: DateTime<Utc> = Utc::now();
        let mut outcomes = Vec::new();
        for id in ids {
            if id == author_actor_id {
                continue;
            }
            let outcome = self
                .router
                .route(
                    ctx,
                    &self.worker,
                    id,
                    NotificationItem {
                        kind: MENTION_KIND.to_string(),
                        ref_id: message_id,
                    },
                    now,
                )
                .await?;
            outcomes.push(outcome);
        }
        Ok(outcomes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extraction_edge_cases() {
        // Boundaries.
        assert_eq!(extract_handles("@bob hi"), vec!["bob"]);
        assert_eq!(extract_handles("hi @bob"), vec!["bob"]);
        assert_eq!(extract_handles("@bob"), vec!["bob"]);
        // Punctuation.
        assert_eq!(extract_handles("hi @bob!"), vec!["bob"]);
        assert_eq!(extract_handles("(@bob), [@carol];"), vec!["bob", "carol"]);
        assert_eq!(
            extract_handles("see @bob.smith-x_y."),
            vec!["bob.smith-x_y"]
        );
        // Not mentions.
        assert_eq!(extract_handles("mail a@b.com"), Vec::<String>::new());
        assert_eq!(extract_handles("lone @ sign"), Vec::<String>::new());
        assert_eq!(extract_handles("@."), Vec::<String>::new());
        assert_eq!(extract_handles("@-"), Vec::<String>::new());
        // Repeated mentions dedupe, first-appearance order kept.
        assert_eq!(
            extract_handles("@bob and @carol then @bob"),
            vec!["bob", "carol"]
        );
        // Case normalizes; mention at offset after newline.
        assert_eq!(extract_handles("hi\n@Bob hi"), vec!["bob"]);
        // A mention-looking token that normalizes to empty-ish is skipped.
        assert_eq!(extract_handles("@@bob"), vec!["bob"]);
    }
}
