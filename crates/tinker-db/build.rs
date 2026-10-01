fn main() {
    // sqlx::migrate! embeds migration files at compile time, but cargo
    // does not track the migrations directory as a dependency — adding a
    // new .sql file does NOT trigger a rebuild, so the `migrate` example
    // (and any test binary) can silently embed a stale set. These
    // directives make the migration files first-class build inputs.
    println!("cargo:rerun-if-changed=migrations/core");
    println!("cargo:rerun-if-changed=migrations/pii");
}
