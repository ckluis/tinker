//! Installer lock scope: the install advisory lock is per-pack, so
//! concurrent installs of disjoint packs proceed in parallel while
//! installs of the same pack still serialize on check-then-create.

use std::time::Duration;
use tinker_apps::AppRegistry;
use tinker_db::{CoreDb, OwnerDb};
use tinker_ontology::Ontology;
use tinker_packs::{PackDefinition, PackInstaller};

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

async fn setup() -> (PackInstaller, Ontology, sqlx::PgPool) {
    let tenant_pool = sqlx::PgPool::connect(&env("TINKER_CORE_URL"))
        .await
        .unwrap();
    let owner_pool = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    let ontology = Ontology::new(CoreDb(tenant_pool.clone()), OwnerDb(owner_pool.clone()));
    let installer = PackInstaller::new(ontology.clone(), AppRegistry::new(tenant_pool));
    (installer, ontology, owner_pool)
}

/// Wait until some session is observably blocked waiting for an advisory
/// lock — i.e. the spawned installer has reached `pg_advisory_lock` and
/// is queued behind our held key. No sleep-guessing, no vacuous pass.
async fn wait_for_lock_waiter(owner: &sqlx::PgPool, timeout: Duration) {
    let start = std::time::Instant::now();
    loop {
        let (n,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted",
        )
        .fetch_one(owner)
        .await
        .unwrap();
        if n >= 1 {
            return;
        }
        if start.elapsed() > timeout {
            panic!("timed out waiting for the installer to block on its lock");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A minimal one-object pack. The slug carries a random suffix because
/// platform slugs are global and persist in the shared test database.
fn test_pack(pack_id: &str) -> PackDefinition {
    let rand: String = uuid::Uuid::now_v7().simple().to_string()[..12].to_string();
    let slug = format!("lock_scope_{}_{}", pack_id.replace('-', "_"), rand);
    let toml = format!(
        "[pack]\nid = \"{pack_id}\"\nversion = \"1.0.0\"\nname = \"LockScope\"\n\n\
         [[objects]]\nname = \"Lock Widget\"\napi_slug = \"{slug}\"\nlabel = \"Lock Widget\"\n\n\
         [[objects.fields]]\nname = \"name\"\napi_name = \"name\"\nlabel = \"Name\"\nfield_type = \"text\"\n"
    );
    PackDefinition::from_toml(&toml).unwrap()
}

/// No global serialization: hold the legacy global lock key for the whole
/// test. If installs ever serialize globally again, pack B's install hangs
/// here until the timeout fails the test. Deterministic — no timing.
#[tokio::test]
async fn disjoint_pack_installs_do_not_serialize() {
    let (installer, ontology, _) = setup().await;
    let pack_b = test_pack("lock-scope-b");

    let legacy = ontology.install_lock("tinker-pack-install").await.unwrap();
    let installed_b =
        tokio::time::timeout(Duration::from_secs(15), installer.install_objects(&pack_b))
            .await
            .expect("disjoint pack install must not wait on a global install lock")
            .unwrap();
    legacy.release().await.unwrap();

    let slug_b = pack_b.objects[0].api_slug.clone();
    assert!(
        installed_b.objects.contains_key(&slug_b),
        "pack B installed its object while the legacy global lock was held"
    );
}

/// The lock is actually taken, and per-pack: with pack A's per-pack key
/// held, pack A's own install blocks in the lock (observed waiting in
/// pg_locks — never dropped mid-wait); releasing the key lets it through.
#[tokio::test]
async fn install_lock_is_per_pack() {
    let (installer, ontology, owner_pool) = setup().await;
    let installer = std::sync::Arc::new(installer);
    let pack_a = test_pack("lock-scope-a");
    let slug_a = pack_a.objects[0].api_slug.clone();

    let lock_a = ontology
        .install_lock(&PackInstaller::install_lock_key(&pack_a.pack.id))
        .await
        .unwrap();
    let inst = installer.clone();
    let handle = tokio::spawn(async move { inst.install_objects(&pack_a).await });

    wait_for_lock_waiter(&owner_pool, Duration::from_secs(10)).await;
    assert!(
        !handle.is_finished(),
        "pack A's install must block on its own per-pack lock"
    );
    lock_a.release().await.unwrap();

    let installed_a = handle.await.expect("install task survived").unwrap();
    assert!(
        installed_a.objects.contains_key(&slug_a),
        "pack A installs once its lock is released"
    );
}

/// Same-pack installs still serialize and converge: two concurrent
/// installs of one pack both succeed on the same platform object.
#[tokio::test]
async fn same_pack_installs_serialize_and_converge() {
    let (installer, _, _) = setup().await;
    let installer = std::sync::Arc::new(installer);
    let pack = test_pack("lock-scope-same");

    let (r1, r2) = tokio::join!(
        installer.install_objects(&pack),
        installer.install_objects(&pack),
    );
    let i1 = r1.unwrap();
    let i2 = r2.unwrap();
    let slug = pack.objects[0].api_slug.clone();
    assert_eq!(
        i1.objects[&slug], i2.objects[&slug],
        "concurrent installs of the same pack converge on one object"
    );
}
