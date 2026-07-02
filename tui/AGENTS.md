# tui-rust/ — `neuralice-tui` (ratatui terminal dashboard)

> Nearest-file precedence: this file governs the `neuralice-tui` crate under
> `tui-rust/`. Repo-wide rules: root [`../AGENTS.md`](../AGENTS.md). The
> general Rust style/test conventions in [`../icecore/AGENTS.md`](../icecore/AGENTS.md)
> apply here too (inline `format!`, exhaustive `match`, RPITIT over
> `#[async_trait]`, `*_tests.rs` sibling files, modules < 500 LoC, deep-equals
> tests, be patient with Rust commands). This file adds the **ratatui/TUI**
> specifics.

`neuralice-tui` is the on-appliance **terminal dashboard** (ratatui 0.29 +
crossterm 0.28). It is **active in production** — shipped as
`/opt/neuralice/bin/neuralice-tui` and run by `neuralice-tui.service` on the
appliance. It is a **standalone crate**, not part of the `icecore/` Cargo
workspace.

> Note: the separate Go `tui/` directory is **legacy / not deployed** — do
> not extend it; `neuralice-tui` is the live TUI.

## Build / test

```bash
cd tui-rust
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
```

Run `cargo fmt` after edits. Keep `app.rs` focused on orchestration — push
new screens/widgets into `src/ui/` modules rather than growing `app.rs`.

## ratatui styling conventions

Prefer ratatui's **Stylize** helpers over constructing `Style`/`Span::styled`
by hand:

- Plain span: `"text".into()`. Styled: `"text".dim()`, `.bold()`, `.cyan()`,
  `.green()`, `.italic()`, `.underlined()`, etc.
- **Do not hardcode `.white()`** — use the default foreground (no color).
- **Computed** styles (value known only at runtime): `Span::styled(...)` or
  `Span::from(text).set_style(style)` is fine.
- Build lines with `vec![…].into()` when the target type is obvious; use
  `Line::from(vec![…])` / `Span::from(text)` only when inference is ambiguous
  (e.g. `Paragraph::new`, `Cell::from`) or `.into()` would need extra type
  annotations. Don't add type annotations solely to satisfy `.into()`.
- Chain helpers for readability: `url.cyan().underlined()`.
- **Compactness**: prefer the form that stays on one line after `rustfmt`; if
  only one of `Line::from(vec![…])` / `vec![…].into()` avoids wrapping, choose
  it. Don't churn between equivalent forms (`Span::styled` ↔ `set_style`,
  `Line::from` ↔ `.into()`) without a real readability/functional gain —
  follow file-local conventions.

## Theme & colors

Centralize colors in `src/ui/theme.rs`; reference the theme rather than
hardcoding colors in widgets, so the dark-first palette stays consistent.

## Text wrapping

- `textwrap::wrap` for plain strings.
- For a ratatui `Line`, use the crate's wrapping helpers (e.g. word-wrap)
  rather than custom logic; use `initial_indent` / `subsequent_indent`
  options for indented wrapped lines instead of hand-rolling.

## Snapshot tests (insta)

Any change to **user-visible rendered output** (new or changed widget/screen)
should carry `insta` snapshot coverage so UI diffs are reviewable. If the
crate doesn't yet use `insta`, adding it for new UI is the preferred path
(`cargo install --locked cargo-insta`; review `*.snap.new`, then
`cargo insta accept -p neuralice-tui`). Otherwise assert rendered `Buffer`
content with deep-equals.

## What this dashboard shows

Mirror the compliance/operability surface: appliance/service health, network
profile (Local/Update/Nomad), mTLS/pairing/posture status, model/policy/
version metadata, and local audit status — the operator's at-a-glance view of
the sovereign appliance. Never imply logs leave the appliance.
