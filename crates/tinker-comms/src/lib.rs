//! M5: native work and communications as ontology objects.
//!
//! `comm_channel`, `comm_thread`, and `comm_message` are platform-scope
//! ontology objects — real tables with typed columns, defined through the
//! owner handle by [`CommsInstaller`] (the same path the M3 pack installer
//! uses). Chat is a view over the messages dataset; email/notification
//! delivery runs through the transactional [`delivery`](DeliveryWorker)
//! outbox with durable, idempotent provider sends.
//!
//! Security posture, per the PRD's communications plane:
//! - Tenant scope decides whether a record exists (RLS on every table,
//!   composite tenant keys). Sibling ids resolve to NotFound, never
//!   Forbidden — no existence oracle.
//! - The semantic access layer (field grants, per actor) decides which
//!   field values a card shows. One card template, no role branches: a
//!   hidden field renders as [`MASKED`].
//! - Realtime envelopes carry ids only ([`tinker_live::Signal`]); each
//!   subscriber re-reads through its own tenant context and grants.
//! - PII plaintext never enters core rows. Outbox payloads hold opaque
//!   vault refs; the worker resolves them cross-plane at send time.
//! - Identity disclosure is an explicit, versioned, revocable act. Viewers
//!   without disclosure see a stable handle, never a display name.

pub mod crossplane;
pub mod delivery;
pub mod disclose;
pub mod inbound;
pub mod install;
pub mod mentions;
pub mod notify;
pub mod search;
pub mod templates;
pub mod unfurl;
pub mod write;

pub use crossplane::{
    find_valid_grant, grant_cross_plane_access, list_grant_uses, list_grants, log_grant_use,
    revoke_cross_plane_access, CrossPlaneGrant, GrantSummary, GrantUse,
};
pub use delivery::{
    DeliveryWorker, EmailProvider, FakeEmailProvider, FakeMode, SendReceipt, SendRequest,
};
pub use disclose::{is_disclosed, set_disclosure};
pub use inbound::{
    derive_org_key, fetch_message_attachment, receive_email, register_inbound_address,
    verify_signature, InboundAttachmentPayload, InboundConfig, InboundDeps, InboundEmailPayload,
    ReceiveOutcome,
};
pub use install::{CommsInstaller, InstalledComms};
pub use mentions::{extract_handles, resolve_handles, MentionNotifier, MENTION_KIND};
pub use notify::{NotificationItem, NotificationRouter, PrefsInput, RoutingOutcome};
pub use search::{MessageSearch, MessageSearchHit};
pub use templates::{
    render, RenderError, TemplateSender, TemplateStore, TemplateSummary, TemplateVersion,
};
pub use unfurl::{ThreadCard, UnfurlRenderer, MASKED};
pub use write::CommsWriter;

use std::sync::Arc;
use tinker_db::CoreDb;
use tinker_live::SignalBus;
use tinker_ontology::Ontology;

/// The M5 communications handle kept on the web [`AppState`][tinker_web].
///
/// Constructed synchronously; [`Comms::install`] performs the (idempotent)
/// platform-object DDL and must be awaited once at startup before the
/// comms routes serve traffic — handlers fail closed with 503 until then.
pub struct Comms {
    core: CoreDb,
    ontology: Ontology,
    signals: SignalBus,
    installed: tokio::sync::RwLock<Option<InstalledComms>>,
}

impl Comms {
    pub fn new(core: CoreDb, ontology: Ontology, signals: SignalBus) -> Self {
        Self {
            core,
            ontology,
            signals,
            installed: tokio::sync::RwLock::new(None),
        }
    }

    /// Idempotent: re-running converges on the existing objects/fields.
    pub async fn install(&self) -> tinker_core::Result<InstalledComms> {
        let installer = CommsInstaller::new(self.ontology.clone());
        let installed = installer.install().await?;
        *self.installed.write().await = Some(installed.clone());
        Ok(installed)
    }

    pub fn writer(&self) -> CommsWriter {
        CommsWriter::new(
            self.core.clone(),
            self.ontology.clone(),
            self.signals.clone(),
        )
    }

    pub fn renderer(&self) -> UnfurlRenderer {
        UnfurlRenderer::new(self.core.clone(), self.ontology.clone())
    }

    /// Permission-aware message search over `backend` (item 32). The
    /// backend is passed in (not stored) so callers choose native vs TIN;
    /// the search itself is tenant-scoped with projection-masked
    /// snippets — see [`MessageSearch`].
    pub fn message_search(
        &self,
        backend: std::sync::Arc<dyn tinker_search::SearchBackend>,
    ) -> MessageSearch {
        MessageSearch::new(self.core.clone(), self.ontology.clone(), backend)
    }

    pub async fn installed(&self) -> Option<InstalledComms> {
        self.installed.read().await.clone()
    }
}

pub type SharedComms = Arc<Comms>;
