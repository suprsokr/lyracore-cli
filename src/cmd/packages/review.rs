//! The trust review: a deterministic, read-only inventory of what a candidate Package would add to
//! the realm.
//!
//! It answers one question — "what does installing this register?" — and it answers it the way the
//! server's own build does. `module/build.rs` discovers a Package by text-scanning
//! `packages/<name>/src/**` for three marker macros on a comment- and string-stripped copy of each
//! file, so a commented-out marker registers nothing. This module ports that scan, because a review
//! that counted markers the build ignores (or missed ones it registers) would describe a different
//! install than the one about to happen.
//!
//! Hook event names are checked against the checkout's `datascripts/runtime-scripts/events.json`,
//! the same file `module/build.rs` embeds, so the review carries no event list of its own that can
//! go stale. When that file is missing or malformed, the review reports the event names as
//! unverified rather than guessing.
//!
//! It is an INVENTORY, not a verdict. Tables and reducers are `#[table]`/`#[reducer]` attributes,
//! which the SpacetimeDB macros act on rather than the build script — they are counted here because
//! they are what the Package adds to the schema, which is what an operator is being asked to trust.
//! Everything else in the Rust is code that runs inside the module with full database access, and
//! the report says so.
//!
//! Runtime Scripts ARE counted from a generated Script Artifact when one exists, with `scripts/`
//! sources as the pre-build fallback. Package Deltas are counted from `data/.generated/`; their
//! claim tables decide which Import Families the review names.
//!
//! DUPLICATION, ON PURPOSE: `strip_comments_and_strings` and the three marker matchers are a port
//! of `module/build.rs`, which lives in the server repository and is not a dependency of this CLI.
//! The tests below pin the behaviour the port exists for — an inert commented-out marker, and
//! marker syntax quoted inside a doc example.

use super::{
    artifact,
    tree::{self, EntryKind},
};
use crate::project::ProjectLayout;
use crate::{Error, Result};
use std::path::Path;

/// The Module's hook catalogue: the `game_hook!` event names `module/build.rs` accepts, read from
/// the checkout's `datascripts/runtime-scripts/events.json`.
///
/// A `game_hook!` naming an event outside the catalogue fails the server build. Reading the file
/// the build reads keeps the review's annotation true for the checkout it describes, whatever the
/// CLI's own pin date.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookCatalogue {
    /// Event names from the checkout, in file order.
    Loaded(Vec<String>),
    /// The file could not be read. The review reports hook event names as unverified, never as
    /// accepted or refused.
    Unverifiable {
        /// What stopped the read, for the review to print.
        reason: String,
    },
}

impl HookCatalogue {
    /// Read the catalogue from `project`'s checkout. A missing or malformed file is not an error:
    /// the review still describes the Package, and its hooks row says the event names are
    /// unverified.
    pub fn load(project: &ProjectLayout) -> Self {
        let text = match std::fs::read_to_string(project.runtime_scripts_dir().join("events.json"))
        {
            Ok(text) => text,
            Err(error) => {
                return Self::Unverifiable {
                    reason: format!(
                        "datascripts/runtime-scripts/events.json could not be read ({error})"
                    ),
                }
            }
        };
        match serde_json::from_str::<Vec<HookEventRow>>(&text) {
            Ok(rows) => Self::Loaded(rows.into_iter().map(|row| row.event).collect()),
            Err(error) => Self::Unverifiable {
                reason: format!("datascripts/runtime-scripts/events.json is malformed ({error})"),
            },
        }
    }

    /// Whether the build accepts `event`, or `None` when the catalogue could not be read.
    fn accepts(&self, event: &str) -> Option<bool> {
        match self {
            Self::Loaded(events) => Some(events.iter().any(|known| known == event)),
            Self::Unverifiable { .. } => None,
        }
    }

    /// Why the catalogue is unverifiable, when it is.
    fn unverifiable_reason(&self) -> Option<&str> {
        match self {
            Self::Loaded(_) => None,
            Self::Unverifiable { reason } => Some(reason),
        }
    }
}

/// One catalogue row. `module/build.rs` deserializes the whole row and refuses the build on a
/// missing field; the review needs only the event name.
#[derive(serde::Deserialize)]
struct HookEventRow {
    event: String,
}

/// What a candidate Package would register, and how much unclassified Rust comes with it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustReview {
    /// Table accessor names from SpacetimeDB 2.x's required `#[table(accessor = ...)]`.
    pub tables: Vec<String>,
    /// Function names carrying `#[reducer]`.
    pub reducers: Vec<String>,
    /// `game_hook!(EVENT, fn NAME)` — event and handler.
    pub hooks: Vec<(String, String)>,
    /// Why the hook event names could not be checked against the checkout's hook catalogue, when it
    /// was absent or malformed. `render` prints the reason beside the hooks row.
    pub hooks_unverified: Option<String>,
    /// `game_tick_pass!(fn NAME)` — passes the core scheduler runs every tick.
    pub tick_passes: Vec<String>,
    /// `character_owned!(kind, fn NAME)` — per-character sweeps and cross-shard transport arms.
    pub character_owned: Vec<String>,
    /// Directory names under `client/addons/`.
    pub addons: Vec<String>,
    /// Files under `client/mpq/` — each one shadows a stock client file.
    pub client_overrides: usize,
    /// Runtime Scripts this Package would run, by artifact name or pre-build source file.
    pub runtime_scripts: Vec<String>,
    /// Package-local Datascripts run by the author during `packages build`.
    pub datascripts: Vec<String>,
    /// Physical generated Package Delta artifacts.
    pub package_delta_count: usize,
    /// Generated Package Deltas grouped by Import Family.
    pub package_deltas: Vec<(String, usize)>,
    pub rust_files: usize,
    pub rust_lines: usize,
}

impl TrustReview {
    /// Scan `package_dir` against `hook_catalogue`. Reads; never writes, never runs anything.
    pub fn scan(package_dir: &Path, hook_catalogue: &HookCatalogue) -> Result<Self> {
        let mut review = Self {
            hooks_unverified: hook_catalogue.unverifiable_reason().map(str::to_string),
            ..Self::default()
        };
        let entries = tree::collect(package_dir)?;

        let rust_files: Vec<_> = entries
            .iter()
            .filter(|entry| {
                entry.kind == EntryKind::File
                    && entry.relative.starts_with("src")
                    && entry.relative.extension().map(|ext| ext == "rs") == Some(true)
            })
            .collect();
        review.rust_files = rust_files.len();
        for entry in rust_files {
            let raw = std::fs::read_to_string(&entry.path).map_err(|error| {
                Error::Usage(format!(
                    "cannot read Rust source {} for the trust review: {error}. Nothing was copied.",
                    entry.path.display()
                ))
            })?;
            review.rust_lines += raw.lines().count();
            review.scan_source(&strip_comments_and_strings(&raw), hook_catalogue);
        }

        review.addons = entries
            .iter()
            .filter(|entry| {
                entry.kind == EntryKind::Directory
                    && entry.relative.parent() == Some(Path::new("client/addons"))
            })
            .map(|entry| {
                entry
                    .relative
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        review.addons.sort();
        review.client_overrides = entries
            .iter()
            .filter(|entry| {
                entry.kind == EntryKind::File && entry.relative.starts_with("client/mpq")
            })
            .count();

        let mut source_scripts: Vec<String> = entries
            .iter()
            .filter(|entry| {
                entry.kind == EntryKind::File
                    && entry.relative.parent() == Some(Path::new("scripts"))
                    && entry
                        .relative
                        .extension()
                        .is_some_and(|ext| ext == "ts" || ext == "lua")
            })
            .map(|entry| {
                entry
                    .relative
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        source_scripts.sort();

        review.datascripts = entries
            .iter()
            .filter(|entry| {
                entry.kind == EntryKind::File
                    && entry.relative.parent() == Some(Path::new("datascripts"))
                    && entry.relative.extension().is_some_and(|ext| ext == "ts")
            })
            .map(|entry| entry.relative.to_string_lossy().into_owned())
            .collect();
        review.datascripts.sort();

        let generated = artifact::summarize_package_artifacts(package_dir)?;
        review.runtime_scripts = if generated.has_script_artifact {
            generated.runtime_scripts
        } else {
            source_scripts
        };
        review.package_delta_count = generated.package_delta_count;
        review.package_deltas = generated.package_delta_families;

        Ok(review)
    }

    fn scan_source(&mut self, content: &str, hook_catalogue: &HookCatalogue) {
        for head in attribute_heads(content, "table") {
            let accessor = balanced(head.trim_start())
                .and_then(|args| top_level_named_ident(&args, "accessor"))
                .unwrap_or_else(|| {
                    "(invalid table: missing required `accessor = name`)".to_string()
                });
            self.tables.push(accessor);
        }
        for head in attribute_heads(content, "reducer") {
            self.reducers.push(following_fn_name(head));
        }
        for head in marker_heads(content, "game_hook!") {
            if let Some((event, name)) = match_hook(head) {
                let event = match hook_catalogue.accepts(&event) {
                    Some(true) => event,
                    Some(false) => format!("{event} (unknown event — the server build refuses it)"),
                    None => format!("{event} (event name unverified)"),
                };
                self.hooks.push((event, name));
            }
        }
        for head in marker_heads(content, "game_tick_pass!") {
            if let Some(name) = head.strip_prefix('(').and_then(match_fn_name) {
                self.tick_passes.push(name);
            }
        }
        for head in marker_heads(content, "character_owned!") {
            if let Some(name) = match_character_owned(head) {
                self.character_owned.push(name);
            }
        }
        self.tables.sort();
        self.reducers.sort();
        self.hooks.sort();
        self.tick_passes.sort();
        self.character_owned.sort();
    }

    /// Whether the inventory contains no registered behavior or authoring scripts.
    pub fn registers_nothing(&self) -> bool {
        self.tables.is_empty()
            && self.reducers.is_empty()
            && self.hooks.is_empty()
            && self.tick_passes.is_empty()
            && self.character_owned.is_empty()
            && self.addons.is_empty()
            && self.client_overrides == 0
            && self.runtime_scripts.is_empty()
            && self.datascripts.is_empty()
            && self.package_delta_count == 0
    }

    /// The full block `packages add` prints before it asks.
    pub fn render(&self, source: &Path) -> String {
        let hooks: Vec<String> = self
            .hooks
            .iter()
            .map(|(event, name)| format!("{event} -> {name}"))
            .collect();
        let mut out = format!(
            "trust review — deterministic scan of {}\n",
            source.display()
        );
        out.push_str(&row("tables", self.tables.len(), &self.tables));
        out.push_str(&row("reducers", self.reducers.len(), &self.reducers));
        out.push_str(&row("hooks", self.hooks.len(), &hooks));
        if !self.hooks.is_empty() {
            if let Some(reason) = &self.hooks_unverified {
                out.push_str(&format!("  {:<18} {reason}\n", "hook catalogue"));
            }
        }
        out.push_str(&row(
            "tick passes",
            self.tick_passes.len(),
            &self.tick_passes,
        ));
        out.push_str(&row(
            "character-owned",
            self.character_owned.len(),
            &self.character_owned,
        ));
        out.push_str(&row("addons", self.addons.len(), &self.addons));
        out.push_str(&row("client overrides", self.client_overrides, &[]));
        out.push_str(&package_delta_row(
            self.package_delta_count,
            &self.package_deltas,
        ));
        out.push_str(&row(
            "runtime scripts",
            self.runtime_scripts.len(),
            &self.runtime_scripts,
        ));
        out.push_str(&row(
            "datascripts",
            self.datascripts.len(),
            &self.datascripts,
        ));
        if !self.datascripts.is_empty() {
            out.push_str("  Datascripts are trusted code run on your machine by packages build.\n");
        }
        out.push_str(&format!(
            "  trusted Rust       {} file(s), {} line(s)\n",
            self.rust_files, self.rust_lines
        ));
        out.push_str(
            "\nThe rows above are what the build registers. Everything else in those Rust files is \
             TRUSTED\nCODE: it runs inside the module with full access to every table in the \
             database, and no row\nhere bounds it. This is an inventory, not a security guarantee. \
             Read the source first.\n",
        );
        out
    }

    /// The one-line content-kind summary `packages list` shows per Package.
    pub fn kinds_summary(&self) -> String {
        let mut parts = Vec::new();
        if self.package_delta_count > 0 {
            let suffix = if self.package_delta_count == 1 {
                ""
            } else {
                "s"
            };
            parts.push(format!(
                "{} package delta{suffix}",
                self.package_delta_count
            ));
        }
        for (label, count) in [
            ("tables", self.tables.len()),
            ("reducers", self.reducers.len()),
            ("hooks", self.hooks.len()),
            ("tick passes", self.tick_passes.len()),
            ("character-owned", self.character_owned.len()),
            ("addons", self.addons.len()),
            ("client overrides", self.client_overrides),
            ("runtime scripts", self.runtime_scripts.len()),
            ("datascripts", self.datascripts.len()),
        ] {
            if count > 0 {
                parts.push(format!("{count} {label}"));
            }
        }
        if self.rust_files > 0 {
            parts.push(format!("{} Rust file(s)", self.rust_files));
        }
        if parts.is_empty() {
            "(nothing detected)".to_string()
        } else {
            parts.join(", ")
        }
    }
}

fn package_delta_row(count: usize, families: &[(String, usize)]) -> String {
    if count == 0 {
        return "  package deltas     none\n".to_string();
    }
    let details: Vec<String> = families
        .iter()
        .map(|(family, count)| format!("{family}: {count}"))
        .collect();
    row("package deltas", count, &details)
}

fn row(label: &str, count: usize, names: &[String]) -> String {
    let detail = if names.is_empty() {
        String::new()
    } else {
        format!("  {}", names.join(", "))
    };
    format!("  {label:<18} {count}{detail}\n")
}

// ---- the marker scan, ported from module/build.rs ---------------------------------------------

/// Every occurrence of `marker`, as the left-trimmed text that follows it.
fn marker_heads<'a>(content: &'a str, marker: &str) -> Vec<&'a str> {
    let mut heads = Vec::new();
    let mut from = 0usize;
    while let Some(index) = content[from..].find(marker) {
        let head_start = from + index + marker.len();
        heads.push(content[head_start..].trim_start());
        from = head_start;
    }
    heads
}

/// Every `#[<attr>` / `#[spacetimedb::<attr>` occurrence, as the text that follows the name.
fn attribute_heads<'a>(content: &'a str, attr: &str) -> Vec<&'a str> {
    let mut heads = Vec::new();
    for prefix in [format!("#[{attr}"), format!("#[spacetimedb::{attr}")] {
        let mut from = 0usize;
        while let Some(index) = content[from..].find(&prefix) {
            let head_start = from + index + prefix.len();
            // `#[tables]` must not match `#[table`. The next character ends the attribute name.
            if !content[head_start..].starts_with(|c: char| c.is_alphanumeric() || c == '_') {
                heads.push(&content[head_start..]);
            }
            from = head_start;
        }
    }
    heads
}

fn balanced(head: &str) -> Option<String> {
    let inner = head.strip_prefix('(')?;
    let mut depth = 1usize;
    for (index, c) in inner.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(inner[..index].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

/// A top-level `key = identifier` argument. Nested `index(...)`/`scheduled(...)` options can carry
/// their own `accessor` tokens, so commas and equals signs inside delimiters must not be mistaken
/// for the table's required accessor.
fn top_level_named_ident(args: &str, key: &str) -> Option<String> {
    let mut round = 0usize;
    let mut square = 0usize;
    let mut curly = 0usize;
    let mut start = 0usize;
    for (index, c) in args
        .char_indices()
        .chain(std::iter::once((args.len(), ',')))
    {
        match c {
            '(' => round += 1,
            ')' => round = round.saturating_sub(1),
            '[' => square += 1,
            ']' => square = square.saturating_sub(1),
            '{' => curly += 1,
            '}' => curly = curly.saturating_sub(1),
            ',' if round == 0 && square == 0 && curly == 0 => {
                let part = &args[start..index];
                if let Some((left, right)) = part.split_once('=') {
                    if left.trim() == key {
                        let right = right.trim();
                        let ident = read_ident(right)?;
                        let tail = &right[ident.len()..];
                        if tail.trim().is_empty() {
                            return Some(ident);
                        }
                    }
                }
                start = index + c.len_utf8();
            }
            _ => {}
        }
    }
    None
}

/// The first `fn NAME` after an attribute — the item it applies to, past any further attributes.
fn following_fn_name(head: &str) -> String {
    let mut rest = head;
    while let Some(index) = rest.find("fn ") {
        let after = &rest[index + 3..];
        if let Some(name) = read_ident(after) {
            return name;
        }
        rest = after;
    }
    "(unnamed)".to_string()
}

/// `game_hook!` head: `(EVENT, fn NAME(...`.
fn match_hook(head: &str) -> Option<(String, String)> {
    let rest = head.strip_prefix('(')?.trim_start();
    let end = rest.find(|c: char| !(c.is_alphanumeric() || c == '_'))?;
    if end == 0 {
        return None;
    }
    let event = rest[..end].to_string();
    let rest = rest[end..].trim_start().strip_prefix(',')?;
    Some((event, match_fn_name(rest)?))
}

/// `character_owned!` head: `(KIND, fn NAME(...` for the four known kinds.
fn match_character_owned(head: &str) -> Option<String> {
    for kind in ["delete", "restamp", "transfer", "not_transported"] {
        if let Some(rest) = head.strip_prefix(format!("({kind},").as_str()) {
            if let Some(name) = match_fn_name(rest) {
                return Some(format!("{kind}: {name}"));
            }
        }
    }
    None
}

/// Optional whitespace, `fn NAME`, then `(` — the marker's own parameter list.
fn match_fn_name(rest: &str) -> Option<String> {
    let rest = rest.trim_start().strip_prefix("fn ")?.trim_start();
    let end = rest.find(|c: char| !(c.is_alphanumeric() || c == '_'))?;
    if end == 0 || !rest[end..].trim_start().starts_with('(') {
        return None;
    }
    Some(rest[..end].to_string())
}

fn read_ident(text: &str) -> Option<String> {
    let text = text.trim_start();
    let end = text
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(text.len());
    (end > 0).then(|| text[..end].to_string())
}

/// Blank out comments (line and nested block), string literals (plain, byte, raw) and char
/// literals, preserving newlines and character positions — so the scan sees only real code.
///
/// The port of `module/build.rs`'s function of the same name. Lifetimes (`'a`) survive; only a
/// real char literal is blanked.
fn strip_comments_and_strings(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let mut out: Vec<char> = Vec::with_capacity(b.len());
    let blank = |c: char| if c == '\n' { '\n' } else { ' ' };
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        if c == '/' && b.get(i + 1) == Some(&'/') {
            while i < b.len() && b[i] != '\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }
        if c == '/' && b.get(i + 1) == Some(&'*') {
            let mut depth = 0usize;
            while i < b.len() {
                if b[i] == '/' && b.get(i + 1) == Some(&'*') {
                    depth += 1;
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                } else if b[i] == '*' && b.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    out.push(blank(b[i]));
                    i += 1;
                }
            }
            continue;
        }
        // A raw string only when `r`/`br` starts a token, so `for` and `attr` never trigger it.
        let prev_is_ident = i > 0 && (b[i - 1].is_alphanumeric() || b[i - 1] == '_');
        if !prev_is_ident && (c == 'r' || (c == 'b' && b.get(i + 1) == Some(&'r'))) {
            let r_at = if c == 'b' { i + 1 } else { i };
            let mut j = r_at + 1;
            while b.get(j) == Some(&'#') {
                j += 1;
            }
            if b.get(j) == Some(&'"') {
                let hashes = j - (r_at + 1);
                for c in &b[i..=j] {
                    out.push(blank(*c));
                }
                i = j + 1;
                'raw: while i < b.len() {
                    if b[i] == '"' {
                        let mut h = 0usize;
                        while h < hashes && b.get(i + 1 + h) == Some(&'#') {
                            h += 1;
                        }
                        if h == hashes {
                            for c in &b[i..=(i + hashes)] {
                                out.push(blank(*c));
                            }
                            i += hashes + 1;
                            break 'raw;
                        }
                    }
                    out.push(blank(b[i]));
                    i += 1;
                }
                continue;
            }
        }
        if c == '"' || (!prev_is_ident && c == 'b' && b.get(i + 1) == Some(&'"')) {
            if c == 'b' {
                out.push(' ');
                i += 1;
            }
            out.push(' ');
            i += 1;
            while i < b.len() {
                if b[i] == '\\' {
                    out.push(' ');
                    if i + 1 < b.len() {
                        out.push(blank(b[i + 1]));
                    }
                    i += 2;
                    continue;
                }
                if b[i] == '"' {
                    out.push(' ');
                    i += 1;
                    break;
                }
                out.push(blank(b[i]));
                i += 1;
            }
            continue;
        }
        if c == '\'' {
            let is_char_lit = match b.get(i + 1) {
                Some('\\') => true,
                Some(_) => b.get(i + 2) == Some(&'\''),
                None => false,
            };
            if is_char_lit {
                out.push(' ');
                i += 1;
                if b.get(i) == Some(&'\\') {
                    out.push(' ');
                    i += 1;
                    if i < b.len() {
                        out.push(blank(b[i]));
                        i += 1;
                    }
                    while i < b.len() && b[i] != '\'' {
                        out.push(blank(b[i]));
                        i += 1;
                    }
                } else {
                    out.push(blank(b[i]));
                    i += 1;
                }
                if b.get(i) == Some(&'\'') {
                    out.push(' ');
                    i += 1;
                }
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn package(files: &[(&str, &str)]) -> TempDir {
        let tmp = TempDir::new().unwrap();
        for (relative, content) in files {
            let path = tmp.path().join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
        tmp
    }

    /// The catalogue a checkout naming `events` would produce. A test that declares no hook still
    /// passes one, because `scan` always takes the catalogue.
    fn catalogue(events: &[&str]) -> HookCatalogue {
        HookCatalogue::Loaded(events.iter().map(|event| (*event).to_string()).collect())
    }

    fn spell_delta(package: &str) -> String {
        format!(
            r#"{{"version":1,"package":"{package}","source_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","claims":[{{"table":"game_spell","key":{{"spell_id":133}},"operation":"update","fields":{{"cooldown_ms":{{"type":"u32","value":1500}}}}}}]}}"#
        )
    }

    fn mixed_family_delta(package: &str) -> String {
        format!(
            r#"{{"version":1,"package":"{package}","source_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","claims":[{{"table":"game_spell","key":{{"spell_id":133}},"operation":"update","fields":{{"cooldown_ms":{{"type":"u32","value":1500}}}}}},{{"table":"game_item_template","key":{{"entry":25}},"operation":"update","fields":{{"name":{{"type":"string","value":"Worn Shortsword"}}}}}}]}}"#
        )
    }

    fn two_script_artifact(package: &str) -> String {
        format!(
            r#"{{"kind":"script","version":1,"package":"{package}","source_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","scripts":[{{"script_id":100002,"name":"example.goodbye","event":"on_logout","priority":0,"enabled":true,"source":"return"}},{{"script_id":100001,"name":"example.greet","event":"on_login","priority":0,"enabled":true,"source":"return"}}]}}"#
        )
    }

    #[test]
    fn the_review_names_what_the_build_would_register() {
        let tmp = package(&[(
            "src/mod.rs",
            "#[spacetimedb::table(accessor = pkg_greeter_log, public)]\n\
             pub struct GreeterLog { pub id: u64 }\n\
             #[spacetimedb::reducer]\n\
             pub fn pkg_greeter_reset(ctx: &ReducerContext) {}\n\
             game_hook!(on_login, fn greet(ctx, payload) { });\n\
             game_tick_pass!(fn sweep_greetings(ctx) { });\n\
             character_owned!(delete, fn sweep_delete_pkg_greeter_log(ctx, guid) { });\n",
        )]);

        let review = TrustReview::scan(tmp.path(), &catalogue(&["on_login"])).unwrap();

        assert_eq!(review.tables, ["pkg_greeter_log"]);
        assert_eq!(review.reducers, ["pkg_greeter_reset"]);
        assert_eq!(
            review.hooks,
            [("on_login".to_string(), "greet".to_string())]
        );
        assert_eq!(review.tick_passes, ["sweep_greetings"]);
        assert_eq!(
            review.character_owned,
            ["delete: sweep_delete_pkg_greeter_log"]
        );
        assert_eq!(review.rust_files, 1);
    }

    #[test]
    fn tables_use_the_pinned_spacetimedb_two_x_accessor_syntax() {
        let tmp = package(&[(
            "src/mod.rs",
            "#[table(accessor = one)]\n\
             pub struct One { pub id: u64 }\n\
             #[spacetimedb::table(\n\
                 index(name = by_id, btree(columns = [id])),\n\
                 name = \"canonical_two\",\n\
                 accessor = two,\n\
             )]\n\
             pub struct Two { pub id: u64 }\n\
             #[table]\n\
             pub struct Missing { pub id: u64 }\n\
             #[table(name = legacy)]\n\
             pub struct Legacy { pub id: u64 }\n",
        )]);

        let review = TrustReview::scan(tmp.path(), &catalogue(&[])).unwrap();

        assert_eq!(
            review.tables,
            [
                "(invalid table: missing required `accessor = name`)",
                "(invalid table: missing required `accessor = name`)",
                "one",
                "two",
            ]
        );
    }

    #[test]
    fn a_commented_out_or_quoted_marker_registers_nothing() {
        // The property the ported stripper exists for: the server build ignores both of these, so
        // a review that counted them would describe an install that never happens.
        let tmp = package(&[(
            "src/mod.rs",
            "// game_hook!(on_login, fn commented(ctx, payload) { });\n\
             /// Example: `game_tick_pass!(fn documented(ctx) { })`\n\
             /* character_owned!(delete, fn blocked(ctx, guid) { }); */\n\
             const EXAMPLE: &str = \"game_hook!(on_death, fn quoted(ctx, payload) { });\";\n\
             game_hook!(on_login, fn real(ctx, payload) { });\n",
        )]);

        let review = TrustReview::scan(tmp.path(), &catalogue(&["on_login"])).unwrap();

        assert_eq!(review.hooks, [("on_login".to_string(), "real".to_string())]);
        assert!(review.tick_passes.is_empty(), "{review:?}");
        assert!(review.character_owned.is_empty(), "{review:?}");
    }

    #[test]
    fn non_utf8_rust_is_refused_instead_of_rendered_as_empty_trusted_code() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("src")).unwrap();
        std::fs::write(tmp.path().join("src/mod.rs"), [0xff, 0xfe]).unwrap();

        let error = TrustReview::scan(tmp.path(), &catalogue(&[])).unwrap_err();

        assert!(
            error.to_string().contains("cannot read Rust source"),
            "{error}"
        );
    }

    #[test]
    fn a_hook_naming_an_event_the_build_refuses_is_reported_not_counted_as_ordinary() {
        let tmp = package(&[(
            "src/mod.rs",
            "game_hook!(on_teatime, fn brew(ctx, payload) { });\n",
        )]);

        let review = TrustReview::scan(tmp.path(), &catalogue(&["on_login"])).unwrap();

        assert_eq!(review.hooks.len(), 1);
        assert!(review.hooks[0].0.contains("unknown event"), "{review:?}");
    }

    #[test]
    fn client_content_is_counted_from_the_two_channels_the_packer_reads() {
        let tmp = package(&[
            ("client/addons/Greeter/Greeter.lua", "-- hi\n"),
            ("client/addons/Greeter/Greeter.toc", "## Interface: 11200\n"),
            ("client/addons/Bagger/Bagger.lua", "-- bags\n"),
            (
                "client/mpq/Interface/FrameXML/ChatFrame.lua",
                "-- override\n",
            ),
        ]);

        let review = TrustReview::scan(tmp.path(), &catalogue(&[])).unwrap();

        // Addons are DIRECTORIES; overrides are individual files that shadow stock ones.
        assert_eq!(review.addons, ["Bagger", "Greeter"]);
        assert_eq!(review.client_overrides, 1);
        assert_eq!(review.rust_files, 0);
    }

    #[test]
    fn the_rendered_review_states_that_unclassified_rust_is_trusted_code() {
        let tmp = package(&[("src/mod.rs", "pub fn helper() {}\n")]);
        let review = TrustReview::scan(tmp.path(), &catalogue(&[])).unwrap();

        let text = review.render(tmp.path());

        assert!(text.contains("TRUSTED"), "{text}");
        assert!(text.contains("not a security guarantee"), "{text}");
        assert!(text.contains("package deltas     none"), "{text}");
        assert!(!text.contains("nothing in this checkout reads"), "{text}");
        assert!(text.contains("runtime scripts"), "{text}");
        assert!(review.registers_nothing(), "{review:?}");
    }

    /// Runtime Scripts run ON THE REALM once the Package is built, so a candidate carrying them
    /// must never be reviewed as if it carried none.
    #[test]
    fn runtime_script_sources_are_named_in_the_review() {
        let tmp = package(&[
            ("scripts/ember_echo.ts", "// @event on_login\n"),
            ("scripts/bonus.lua", "-- @event on_login\n"),
            ("scripts/README.md", "not a script\n"),
        ]);

        let review = TrustReview::scan(tmp.path(), &catalogue(&[])).unwrap();

        assert_eq!(review.runtime_scripts, ["bonus.lua", "ember_echo.ts"]);
        assert!(!review.registers_nothing(), "{review:?}");
        let text = review.render(tmp.path());
        assert!(text.contains("ember_echo.ts"), "{text}");
        assert!(
            review.kinds_summary().contains("2 runtime scripts"),
            "{review:?}"
        );
    }

    #[test]
    fn package_local_datascripts_are_named_before_installation() {
        let tmp = package(&[
            ("datascripts/welcome.ts", "// a Datascript\n"),
            ("datascripts/README.md", "not a script\n"),
        ]);
        let review = TrustReview::scan(tmp.path(), &catalogue(&[])).unwrap();
        assert_eq!(review.datascripts, ["datascripts/welcome.ts"]);
        assert!(!review.registers_nothing());
        assert!(review.kinds_summary().contains("1 datascripts"));
        assert!(review.render(tmp.path()).contains("run on your machine"));
    }

    #[test]
    fn a_prebuilt_script_artifact_is_counted_without_script_sources() {
        let tmp = package(&[(
            "data/.generated/runtime.json",
            &two_script_artifact("example.prebuilt"),
        )]);

        let review = TrustReview::scan(tmp.path(), &catalogue(&[])).unwrap();

        assert_eq!(review.runtime_scripts, ["example.goodbye", "example.greet"]);
        assert!(!review.registers_nothing(), "{review:?}");
        let text = review.render(tmp.path());
        assert!(text.contains("runtime scripts    2"), "{text}");
        assert!(text.contains("example.goodbye, example.greet"), "{text}");
        assert!(
            review.kinds_summary().contains("2 runtime scripts"),
            "{review:?}"
        );
    }

    #[test]
    fn generated_package_deltas_are_counted_by_import_family() {
        let tmp = TempDir::new().unwrap();
        let candidate = tmp.path().join("candidate");
        let delta_path = candidate.join("data/.generated/spell.json");
        std::fs::create_dir_all(delta_path.parent().unwrap()).unwrap();
        std::fs::write(delta_path, spell_delta("example.fire_nova")).unwrap();
        std::fs::write(
            candidate.join("data/.generated/README.md"),
            "generated artifacts live here\n",
        )
        .unwrap();
        let sibling = tmp.path().join("unrelated/data/.generated");
        std::fs::create_dir_all(&sibling).unwrap();
        std::fs::write(sibling.join("broken.json"), r#"{"version":9}"#).unwrap();

        let review = TrustReview::scan(&candidate, &catalogue(&[])).unwrap();

        assert_eq!(review.package_delta_count, 1);
        assert_eq!(review.package_deltas, [("spell".to_string(), 1)]);
        assert!(!review.registers_nothing(), "{review:?}");
        let text = review.render(&candidate);
        assert!(text.contains("package deltas"), "{text}");
        assert!(text.contains("1  spell: 1"), "{text}");
        assert!(
            review.kinds_summary().contains("1 package delta"),
            "{review:?}"
        );
    }

    #[test]
    fn a_mixed_package_delta_is_counted_in_each_import_family() {
        let tmp = package(&[(
            "data/.generated/catalogues.json",
            &mixed_family_delta("example.mixed"),
        )]);

        let review = TrustReview::scan(tmp.path(), &catalogue(&[])).unwrap();

        let text = review.render(tmp.path());

        assert_eq!(
            review.package_deltas,
            [("items".to_string(), 1), ("spell".to_string(), 1)]
        );
        assert_eq!(review.package_delta_count, 1);
        assert!(text.contains("package deltas     1"), "{text}");
        assert!(text.contains("items: 1, spell: 1"), "{text}");
        assert!(
            review.kinds_summary().contains("1 package delta"),
            "{review:?}"
        );
    }

    #[test]
    fn a_malformed_generated_artifact_is_refused_by_the_package_delta_reader() {
        let tmp = package(&[("data/.generated/broken.json", r#"{"version":9}"#)]);

        let error = TrustReview::scan(tmp.path(), &catalogue(&[])).unwrap_err();

        assert!(error.to_string().contains("broken.json"), "{error}");
    }

    #[test]
    fn a_non_utf8_generated_artifact_refusal_names_its_file() {
        let tmp = TempDir::new().unwrap();
        let candidate = tmp.path().join("candidate");
        let artifact = candidate.join("data/.generated/non-utf8.json");
        std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        std::fs::write(&artifact, [0xff]).unwrap();

        let error = TrustReview::scan(&candidate, &catalogue(&[])).unwrap_err();

        assert!(error.to_string().contains("non-utf8.json"), "{error}");
        assert!(error.to_string().contains("UTF-8"), "{error}");
    }

    #[test]
    fn the_scan_is_deterministic_over_the_same_tree() {
        let tmp = package(&[
            ("src/mod.rs", "pub mod a;\npub mod b;\n"),
            ("src/a.rs", "game_hook!(on_kill, fn one(ctx, p) { });\n"),
            ("src/b.rs", "game_hook!(on_kill, fn two(ctx, p) { });\n"),
        ]);

        let first = TrustReview::scan(tmp.path(), &catalogue(&["on_kill"])).unwrap();
        let second = TrustReview::scan(tmp.path(), &catalogue(&["on_kill"])).unwrap();

        assert_eq!(first, second);
        assert_eq!(
            first.hooks,
            [
                ("on_kill".to_string(), "one".to_string()),
                ("on_kill".to_string(), "two".to_string())
            ]
        );
    }

    /// The defect the checkout read exists for: a pinned CLI carried its own event list, so events
    /// a newer checkout accepts were annotated as refused by the build.
    #[test]
    fn a_hook_event_the_checkout_lists_is_treated_as_known() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[workspace]\n").unwrap();
        let events = tmp.path().join("datascripts/runtime-scripts/events.json");
        std::fs::create_dir_all(events.parent().unwrap()).unwrap();
        std::fs::write(&events, r#"[{"event":"on_cast_finished"}]"#).unwrap();
        let package_dir = tmp.path().join("packages/sample");
        std::fs::create_dir_all(package_dir.join("src")).unwrap();
        std::fs::write(
            package_dir.join("src/mod.rs"),
            "game_hook!(on_cast_finished, fn cast_finished(ctx, p) { });\n",
        )
        .unwrap();
        let project = ProjectLayout::from_root(tmp.path()).unwrap();

        let review = TrustReview::scan(&package_dir, &HookCatalogue::load(&project)).unwrap();

        assert_eq!(
            review.hooks,
            [("on_cast_finished".to_string(), "cast_finished".to_string())]
        );
        let text = review.render(&package_dir);
        assert!(!text.contains("unknown event"), "{text}");
        assert!(!text.contains("unverified"), "{text}");
    }

    #[test]
    fn a_checkout_with_no_hook_catalogue_reports_event_names_unverified() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[workspace]\n").unwrap();
        let package_dir = tmp.path().join("packages/sample");
        std::fs::create_dir_all(package_dir.join("src")).unwrap();
        std::fs::write(
            package_dir.join("src/mod.rs"),
            "game_hook!(on_cast_finished, fn cast_finished(ctx, p) { });\n",
        )
        .unwrap();
        let project = ProjectLayout::from_root(tmp.path()).unwrap();

        let review = TrustReview::scan(&package_dir, &HookCatalogue::load(&project)).unwrap();

        assert_eq!(review.hooks.len(), 1);
        assert!(
            review.hooks[0].0.contains("event name unverified"),
            "{review:?}"
        );
        assert!(!review.hooks[0].0.contains("refuses"), "{review:?}");
        let text = review.render(&package_dir);
        assert!(text.contains("hook catalogue"), "{text}");
        assert!(text.contains("could not be read"), "{text}");
    }

    #[test]
    fn a_malformed_hook_catalogue_reports_event_names_unverified() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[workspace]\n").unwrap();
        let events = tmp.path().join("datascripts/runtime-scripts/events.json");
        std::fs::create_dir_all(events.parent().unwrap()).unwrap();
        std::fs::write(&events, "not json").unwrap();
        let package_dir = tmp.path().join("packages/sample");
        std::fs::create_dir_all(package_dir.join("src")).unwrap();
        std::fs::write(
            package_dir.join("src/mod.rs"),
            "game_hook!(on_login, fn greet(ctx, p) { });\n",
        )
        .unwrap();
        let project = ProjectLayout::from_root(tmp.path()).unwrap();

        let review = TrustReview::scan(&package_dir, &HookCatalogue::load(&project)).unwrap();

        assert!(
            review.hooks[0].0.contains("event name unverified"),
            "{review:?}"
        );
        let text = review.render(&package_dir);
        assert!(text.contains("is malformed"), "{text}");
    }
}
