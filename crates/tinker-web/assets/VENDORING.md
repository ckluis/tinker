# Vendored frontend assets

PRD rule: vendored JS/CSS, no CDN. These files are served by the Tinker
binary itself from `/assets/*`.

- `datastar.js` — DataStar v1.0.0-beta.11, ESM browser bundle
  (`/dist/datastar.js`), downloaded 2026-09-24 from
  https://cdn.jsdelivr.net/npm/@starfederation/datastar@1.0.0-beta.11/dist/datastar.js
  (40,026 bytes). Loaded as `<script type="module">`. Re-vendor on upgrade;
  record the version here.
- `tinker.js` — first-party custom elements (`rt-text`, `rt-stat`,
  `rt-select`, `rt-grid`, `rt-form`). MIT, ours.
- `tinker.css` — first-party styles. MIT, ours.
