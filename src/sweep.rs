//! Two passes over the target's own text, run after the scanners: comment markers (`TODO`,
//! `FIXME`, `HACK`, `XXX`, `bypass`…) and the inline comments that silence a scanner
//! (`nosemgrep`, `bearer:disable`, `trivy:ignore`, `luacheck:`, `lgtm[`…). Both are plain
//! case-insensitive searches with word boundaries — no regex engine, no dependency — and
//! report the file, the line and the column of every hit.
//!
//! Neither pass runs by default: `--comments` turns the markers on, and `--suppressions
//! report` (or `ignore`) the suppression comments.

use std::path::Path;

use crate::detect::SKIPPED_DIRS;
use crate::model::{Finding, Severity, SkippedPath};
use crate::scanners::{TEXT_CAP, cap};

/// What to do with the comments that silence a scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Suppressions {
    /// Let each scanner apply them; a finding it still reports stays flagged `suppressed`.
    #[default]
    Honour,
    /// Honour them, and report every suppression comment as a finding of its own.
    Report,
    /// Disable them where the scanner allows it (Semgrep, `CodeQL`) and report every
    /// suppression comment; the others' comments are reported too.
    Ignore,
}

/// Name of the markers pass in the report.
pub const COMMENTS: &str = "comments";
/// Name of the suppression-comments pass in the report.
pub const SUPPRESSIONS: &str = "suppressions";
/// Files larger than this are skipped (minified bundles, data).
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// A comment marker: the spelling searched for (lower case; a space matches space, `-` or
/// `_`) and the rule it is reported under.
pub const MARKERS: &[(&str, &str)] = &[
    ("todo", "todo"),
    ("to do", "todo"),
    ("fixme", "fixme"),
    ("fix me", "fixme"),
    ("tofix", "fixme"),
    ("to fix", "fixme"),
    ("hack", "hack"),
    ("bypass", "bypass"),
    ("xxx", "xxx"),
    ("kludge", "kludge"),
    ("workaround", "workaround"),
];

/// Which files a suppression comment is looked for in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Where {
    /// Any text file.
    Any,
    /// Only files with one of these extensions.
    Only(&'static [&'static str]),
    /// Not in prose (Markdown, text…), where the word is ordinary.
    NotProse,
}

/// A scanner's inline suppression comment: the tool, the spelling (lower case), whether the
/// spelling must end at a word boundary, and where it is looked for.
#[derive(Debug)]
pub struct Suppression {
    /// The scanner it silences (`semgrep`, `bearer`… or `other` for tools sast3uh does not
    /// drive but that are common in code bases).
    pub tool: &'static str,
    /// What is searched for, lower case.
    pub marker: &'static str,
    /// `true` when a letter or digit right after the marker makes it another word.
    pub bounded: bool,
    at: Where,
}

const PROSE: &[&str] = &["md", "markdown", "txt", "rst", "adoc", "asciidoc", "org"];
/// Files no marker is looked for in: translation catalogues (`msgid "To do"`, Spanish
/// `todo`), compiled catalogues, lockfiles.
const NOT_CODE: &[&str] = &["po", "pot", "mo", "lock"];

/// Every suppression comment known, most specific spelling first.
pub const SUPPRESSION_MARKERS: &[Suppression] = &[
    // Semgrep: `nosemgrep` or `nosem`, optionally `: rule-id`, on the line or the one above.
    Suppression {
        tool: "semgrep",
        marker: "nosemgrep",
        bounded: true,
        at: Where::Any,
    },
    Suppression {
        tool: "semgrep",
        marker: "nosem",
        bounded: true,
        at: Where::Any,
    },
    // Bearer: `bearer:disable rule_id` on the line above.
    Suppression {
        tool: "bearer",
        marker: "bearer:disable",
        bounded: false,
        at: Where::Any,
    },
    // Trivy: `trivy:ignore:AVD-…` (and the tfsec spelling it inherited) on the line above.
    Suppression {
        tool: "trivy",
        marker: "trivy:ignore",
        bounded: false,
        at: Where::Any,
    },
    Suppression {
        tool: "trivy",
        marker: "tfsec:ignore",
        bounded: false,
        at: Where::Any,
    },
    // Luacheck: `-- luacheck: ignore`, `no unused`, `push`/`pop`, `globals`… (Lua only).
    Suppression {
        tool: "luacheck",
        marker: "luacheck:",
        bounded: false,
        at: Where::Only(&["lua", "luau", "rockspec"]),
    },
    // CodeQL: `lgtm[query-id]` / `lgtm` and `codeql[query-id]` on the alert's line.
    Suppression {
        tool: "codeql",
        marker: "codeql[",
        bounded: false,
        at: Where::Any,
    },
    Suppression {
        tool: "codeql",
        marker: "lgtm",
        bounded: true,
        at: Where::NotProse,
    },
    // Common in code bases, outside the scanners sast3uh drives.
    Suppression {
        tool: "other",
        marker: "nosec",
        bounded: true,
        at: Where::NotProse,
    },
    Suppression {
        tool: "other",
        marker: "nosonar",
        bounded: true,
        at: Where::Any,
    },
    Suppression {
        tool: "other",
        marker: "gitleaks:allow",
        bounded: false,
        at: Where::Any,
    },
    Suppression {
        tool: "other",
        marker: "checkov:skip",
        bounded: false,
        at: Where::Any,
    },
    Suppression {
        tool: "other",
        marker: "allowlist secret",
        bounded: false,
        at: Where::Any,
    },
    Suppression {
        tool: "other",
        marker: "trufflehog:ignore",
        bounded: false,
        at: Where::Any,
    },
    Suppression {
        tool: "other",
        marker: "noqa",
        bounded: true,
        at: Where::NotProse,
    },
    Suppression {
        tool: "other",
        marker: "nolint",
        bounded: true,
        at: Where::NotProse,
    },
];

/// What a pass found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Swept {
    /// One per hit.
    pub findings: Vec<Finding>,
    /// Text files read.
    pub scanned_files: usize,
    /// Files not read, and why.
    pub skipped_paths: Vec<SkippedPath>,
    /// `true` when the walk stopped at the file cap.
    pub truncated: bool,
}

/// One pattern of a [`Matcher`].
#[derive(Debug, Clone, Copy)]
struct Pattern {
    /// Lower-case bytes to find.
    bytes: &'static [u8],
    /// A space in `bytes` also matches `-` and `_`.
    flexible_space: bool,
    /// The byte after the match must not be a word character.
    bounded_after: bool,
}

/// Finds a set of patterns in a lower-cased line in one pass: a 256-entry table says which
/// patterns can start at a byte, so a byte that starts none costs one lookup.
#[derive(Debug)]
struct Matcher {
    patterns: Vec<Pattern>,
    table: [u32; 256],
}

impl Matcher {
    fn new(patterns: Vec<Pattern>) -> Self {
        debug_assert!(patterns.len() <= 32, "the table holds 32 patterns");
        let mut table = [0u32; 256];
        for (index, pattern) in patterns.iter().enumerate() {
            if let Some(first) = pattern.bytes.first()
                && let Some(slot) = table.get_mut(usize::from(*first))
            {
                *slot |= 1u32 << index;
            }
        }
        Matcher { patterns, table }
    }

    /// Every `(pattern index, byte offset)` hit in `lower`, in offset order, patterns
    /// outside `allowed` (a bit per pattern) left out.
    fn scan(&self, lower: &[u8], allowed: u32) -> Vec<(usize, usize)> {
        let mut hits = Vec::new();
        for (at, byte) in lower.iter().enumerate() {
            let mut mask = self.table.get(usize::from(*byte)).copied().unwrap_or(0) & allowed;
            if mask == 0 || !boundary_before(lower, at) {
                continue;
            }
            while mask != 0 {
                let index = mask.trailing_zeros() as usize;
                mask &= mask - 1;
                let Some(pattern) = self.patterns.get(index) else {
                    continue;
                };
                if matches_at(lower, at, pattern) {
                    hits.push((index, at));
                }
            }
        }
        hits
    }
}

fn matches_at(lower: &[u8], at: usize, pattern: &Pattern) -> bool {
    let end = at + pattern.bytes.len();
    let Some(window) = lower.get(at..end) else {
        return false;
    };
    let same = window.iter().zip(pattern.bytes).all(|(c, k)| {
        c == k || (pattern.flexible_space && *k == b' ' && matches!(c, b'-' | b'_' | b' '))
    });
    same && (!pattern.bounded_after || boundary_after(lower, end))
}

fn markers_matcher() -> Matcher {
    Matcher::new(
        MARKERS
            .iter()
            .map(|(keyword, _)| Pattern {
                bytes: keyword.as_bytes(),
                flexible_space: true,
                bounded_after: true,
            })
            .collect(),
    )
}

fn suppressions_matcher() -> Matcher {
    Matcher::new(
        SUPPRESSION_MARKERS
            .iter()
            .map(|s| Pattern {
                bytes: s.marker.as_bytes(),
                flexible_space: false,
                bounded_after: s.bounded,
            })
            .collect(),
    )
}

/// The suppression patterns that apply to a file with this extension (lower case).
fn allowed_suppressions(extension: &str) -> u32 {
    SUPPRESSION_MARKERS
        .iter()
        .enumerate()
        .filter(|(_, s)| match s.at {
            Where::Any => true,
            Where::Only(extensions) => extensions.contains(&extension),
            Where::NotProse => !PROSE.contains(&extension),
        })
        .fold(0u32, |mask, (index, _)| mask | (1u32 << index))
}

/// Both passes over `root` in one walk, each file read once: the markers when `comments`,
/// the suppression comments when `suppressions`.
#[must_use]
pub fn run(root: &Path, max_files: usize, comments: bool, suppressions: bool) -> (Swept, Swept) {
    let markers = markers_matcher();
    let silencers = suppressions_matcher();
    let mut found_comments = Swept::default();
    let mut found_suppressions = Swept::default();
    let mut lower = Vec::new();
    let walked = walk(root, max_files, &mut |path, text| {
        let extension = path
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let allowed = allowed_suppressions(&extension);
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        // A minified bundle is somebody else's code, on one line.
        let code = !NOT_CODE.contains(&extension.as_str()) && !name.contains(".min.");
        let comments = comments && code;
        let allowed = if code { allowed } else { 0 };
        for (index, line) in text.lines().enumerate() {
            let number = u32::try_from(index).unwrap_or(u32::MAX).saturating_add(1);
            lower.clear();
            lower.extend(line.bytes().map(|b| b.to_ascii_lowercase()));
            if comments && let Some(&(index, at)) = markers.scan(&lower, u32::MAX).first() {
                found_comments
                    .findings
                    .push(marker_finding(path, number, line, at, index));
            }
            if suppressions && allowed != 0 {
                let mut seen: Vec<&str> = Vec::new();
                for (index, at) in silencers.scan(&lower, allowed) {
                    let Some(s) = SUPPRESSION_MARKERS.get(index) else {
                        continue;
                    };
                    if seen.contains(&s.tool) {
                        continue;
                    }
                    seen.push(s.tool);
                    found_suppressions
                        .findings
                        .push(suppression_finding(path, number, line, at, s));
                }
            }
        }
    });
    for swept in [&mut found_comments, &mut found_suppressions] {
        swept.scanned_files = walked.scanned_files;
        swept.skipped_paths.clone_from(&walked.skipped_paths);
        swept.truncated = walked.truncated;
    }
    (found_comments, found_suppressions)
}

/// The markers pass over `root`.
#[must_use]
pub fn comments(root: &Path, max_files: usize) -> Swept {
    run(root, max_files, true, false).0
}

/// The suppression-comments pass over `root`.
#[must_use]
pub fn suppressions(root: &Path, max_files: usize) -> Swept {
    run(root, max_files, false, true).1
}

fn marker_finding(path: &Path, number: u32, line: &str, at: usize, index: usize) -> Finding {
    let (keyword, rule) = MARKERS.get(index).copied().unwrap_or(("", "marker"));
    let mut finding = Finding::new(
        COMMENTS,
        rule,
        Severity::Info,
        format!("{} comment", rule.to_ascii_uppercase()),
        cap(line.trim(), TEXT_CAP),
        path.to_path_buf(),
    );
    finding.line = Some(number);
    finding.column = Some(column_of(line, at));
    finding.snippet = Some(cap(line.trim_end(), TEXT_CAP));
    finding.categories.push("comment".to_owned());
    finding
        .extra
        .insert("marker".to_owned(), keyword.to_owned());
    finding
}

fn suppression_finding(
    path: &Path,
    number: u32,
    line: &str,
    at: usize,
    s: &Suppression,
) -> Finding {
    let after = line.get(at + s.marker.len()..).unwrap_or_default();
    let mut finding = Finding::new(
        SUPPRESSIONS,
        s.tool,
        Severity::Low,
        format!(
            "{} suppression comment ({})",
            s.tool,
            s.marker.trim_end_matches(['[', ':'])
        ),
        cap(line.trim(), TEXT_CAP),
        path.to_path_buf(),
    );
    finding.line = Some(number);
    finding.column = Some(column_of(line, at));
    finding.snippet = Some(cap(line.trim_end(), TEXT_CAP));
    finding.categories.push("suppression".to_owned());
    finding.tags.push(s.tool.to_owned());
    finding
        .extra
        .insert("marker".to_owned(), s.marker.to_owned());
    let rules = after
        .trim_start_matches([':', '[', '=', ' ', '\t'])
        .trim_end_matches([']', ' ', '\t', '\r'])
        .trim();
    if !rules.is_empty() {
        finding.extra.insert("argument".to_owned(), cap(rules, 200));
    }
    finding
}

/// `keyword` as a whole word in `line`, case-insensitively, a space in the keyword matching
/// space, `-` or `_`; the 1-based column of the hit.
#[must_use]
pub fn find_word(line: &str, keyword: &str) -> Option<u32> {
    let lower: Vec<u8> = line.bytes().map(|b| b.to_ascii_lowercase()).collect();
    let matcher = Matcher::new(vec![Pattern {
        bytes: Box::leak(keyword.to_ascii_lowercase().into_boxed_str()).as_bytes(),
        flexible_space: true,
        bounded_after: true,
    }]);
    matcher
        .scan(&lower, u32::MAX)
        .first()
        .map(|(_, at)| column_of(line, *at))
}

fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn boundary_before(bytes: &[u8], at: usize) -> bool {
    at == 0
        || at
            .checked_sub(1)
            .and_then(|i| bytes.get(i))
            .is_none_or(|b| !is_word(*b))
}

fn boundary_after(bytes: &[u8], end: usize) -> bool {
    bytes.get(end).is_none_or(|b| !is_word(*b))
}

fn column_of(line: &str, byte_offset: usize) -> u32 {
    u32::try_from(line.get(..byte_offset).unwrap_or_default().chars().count())
        .unwrap_or(u32::MAX)
        .saturating_add(1)
}

/// What a walk saw, findings apart.
#[derive(Debug, Default)]
struct Walked {
    scanned_files: usize,
    skipped_paths: Vec<SkippedPath>,
    truncated: bool,
}

/// Walk `root` like the detector does (no symlink, no build or VCS directory), read each text
/// file once and hand it to `each` with its relative path.
fn walk(root: &Path, max_files: usize, each: &mut dyn FnMut(&Path, &str)) -> Walked {
    let mut walked = Walked::default();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if file_type.is_dir() {
                if !SKIPPED_DIRS.contains(&name.as_str()) {
                    stack.push(path);
                }
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            if walked.scanned_files + walked.skipped_paths.len() >= max_files {
                walked.truncated = true;
                return walked;
            }
            let relative = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
            match read_text(&path) {
                Ok(text) => {
                    walked.scanned_files += 1;
                    each(&relative, &text);
                }
                Err(reason) => walked.skipped_paths.push(SkippedPath {
                    path: relative.to_string_lossy().into_owned(),
                    reason,
                }),
            }
        }
    }
    walked
}

/// The file as text, unless it is too large or binary.
fn read_text(path: &Path) -> Result<String, String> {
    let size = std::fs::metadata(path).map_err(|e| e.to_string())?.len();
    if size > MAX_FILE_BYTES {
        return Err(format!(
            "larger than {} MiB",
            MAX_FILE_BYTES / (1024 * 1024)
        ));
    }
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    if bytes.iter().take(8192).any(|b| *b == 0) {
        return Err("binary".to_owned());
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, content) in files {
            let path = dir.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
        dir
    }

    #[test]
    fn words_are_found_whole_case_insensitively_with_flexible_separators() {
        assert_eq!(find_word("// TODO: later", "todo"), Some(4));
        assert_eq!(find_word("x = 1  # to do", "to do"), Some(10));
        assert_eq!(find_word("# to-do list", "to do"), Some(3));
        assert_eq!(find_word("# to_do", "to do"), Some(3));
        assert_eq!(
            find_word("todos = []", "todo"),
            None,
            "part of a longer word"
        );
        assert_eq!(find_word("hackathon()", "hack"), None);
        assert_eq!(find_word("debug = 0xxx", "xxx"), None);
        assert_eq!(find_word("bypassAuth = true", "bypass"), None);
        assert_eq!(find_word("// BYPASS auth here", "bypass"), Some(4));
        assert_eq!(
            find_word("do not todo_me", "todo"),
            None,
            "underscore is a word char"
        );
        assert_eq!(
            find_word("é TODO", "todo"),
            Some(3),
            "columns count characters"
        );
        assert_eq!(find_word("", "todo"), None);
        assert_eq!(find_word("to", "todo"), None);
    }

    #[test]
    fn markers_pass_reports_one_finding_per_line_with_file_line_and_column() {
        let dir = tree(&[
            (
                "src/a.rs",
                "fn main() {\n    // TODO: handle errors\n    let x = 1; // HACK hack\n}\n",
            ),
            (
                "b.py",
                "# FIXME\n# fix me too\nprint('to fix this')\nbypass = 1\n# nothing\n",
            ),
            ("c.txt", "xxx\n"),
            ("node_modules/d.js", "// TODO ignored\n"),
            ("bin.dat", "TODO\0binary\n"),
            ("locales/es_ES.po", "msgid \"To do\"\nmsgstr \"todo\"\n"),
            ("public/lib/app.min.js", "/* TODO minified */x=1\n"),
            ("Cargo.lock", "# TODO\n"),
        ]);
        let swept = comments(dir.path(), 1000);
        assert_eq!(swept.scanned_files, 6);
        assert_eq!(swept.skipped_paths.len(), 1);
        assert_eq!(swept.skipped_paths[0].reason, "binary");
        let hits: Vec<(String, u32, &str)> = swept
            .findings
            .iter()
            .map(|f| {
                (
                    f.path.to_string_lossy().into_owned(),
                    f.line.unwrap(),
                    f.rule_id.as_str(),
                )
            })
            .collect();
        assert_eq!(
            hits,
            vec![
                ("b.py".to_owned(), 1, "fixme"),
                ("b.py".to_owned(), 2, "fixme"),
                ("b.py".to_owned(), 3, "fixme"),
                ("b.py".to_owned(), 4, "bypass"),
                ("c.txt".to_owned(), 1, "xxx"),
                ("src/a.rs".to_owned(), 2, "todo"),
                ("src/a.rs".to_owned(), 3, "hack"),
            ]
        );
        let todo = &swept.findings[5];
        assert_eq!(todo.tool, COMMENTS);
        assert_eq!(todo.title, "TODO comment");
        assert_eq!(todo.message, "// TODO: handle errors");
        assert_eq!(todo.column, Some(8));
        assert_eq!(todo.severity, Severity::Info);
        assert_eq!(todo.extra.get("marker").map(String::as_str), Some("todo"));
        assert!(swept.findings.iter().all(|f| f.snippet.is_some()));
        assert_eq!(
            swept.findings[3].message, "bypass = 1",
            "a whole word is a hit wherever it is: the snippet tells comment from code"
        );
    }

    #[test]
    fn suppression_pass_knows_every_scanner_and_keeps_the_argument() {
        let dir = tree(&[
            (
                "a.py",
                "eval(x)  # nosemgrep: python.lang.security.audit.eval-detected\nos.system(c)  # nosec B605\nimport x  # noqa: F401\n",
            ),
            (
                "b.rb",
                "# bearer:disable ruby_lang_logger\nlogger.info(user.password)\n",
            ),
            ("Dockerfile", "#trivy:ignore:AVD-DS-0026\nFROM alpine\n"),
            (
                "main.tf",
                "#tfsec:ignore:aws-s3-enable-logging\nresource \"aws_s3_bucket\" \"b\" {}\n",
            ),
            (
                "c.lua",
                "local x = 1 -- luacheck: ignore 211\n-- luacheck: no unused\n",
            ),
            (
                "d.js",
                "res.send(q) // lgtm[js/reflected-xss]\nres.send(r) // codeql[js/reflected-xss]\nres.send(s) // lgtm\n",
            ),
            ("e.go", "x := f() // nolint:gosec\n"),
            ("f.java", "String p = \"x\"; // NOSONAR\n"),
            (
                "g.yml",
                "key: AKIA # gitleaks:allow\n  # checkov:skip=CKV_AWS_1: reason\n",
            ),
            ("h.txt", "This LGTM, nosec is a word here\n"),
            ("i.md", "luacheck: ignore is not for prose\n"),
            ("j.py", "nosemantics = 1\nnoqa_list = []\n"),
            ("k.po", "msgid \"nosemgrep\"\n"),
        ]);
        let swept = suppressions(dir.path(), 1000);
        let hits: Vec<(String, u32, String, Option<String>)> = swept
            .findings
            .iter()
            .map(|f| {
                (
                    f.path.to_string_lossy().into_owned(),
                    f.line.unwrap(),
                    f.rule_id.clone(),
                    f.extra.get("argument").cloned(),
                )
            })
            .collect();
        let expect = |file: &str, line: u32, tool: &str, arg: Option<&str>| {
            assert!(
                hits.contains(&(
                    file.to_owned(),
                    line,
                    tool.to_owned(),
                    arg.map(str::to_owned)
                )),
                "missing {file}:{line} {tool} {arg:?} in {hits:?}"
            );
        };
        expect(
            "a.py",
            1,
            "semgrep",
            Some("python.lang.security.audit.eval-detected"),
        );
        expect("a.py", 2, "other", Some("B605"));
        expect("a.py", 3, "other", Some("F401"));
        expect("b.rb", 1, "bearer", Some("ruby_lang_logger"));
        expect("Dockerfile", 1, "trivy", Some("AVD-DS-0026"));
        expect("main.tf", 1, "trivy", Some("aws-s3-enable-logging"));
        expect("c.lua", 1, "luacheck", Some("ignore 211"));
        expect("c.lua", 2, "luacheck", Some("no unused"));
        expect("d.js", 1, "codeql", Some("js/reflected-xss"));
        expect("d.js", 2, "codeql", Some("js/reflected-xss"));
        expect("d.js", 3, "codeql", None);
        expect("e.go", 1, "other", Some("gosec"));
        expect("f.java", 1, "other", None);
        expect("g.yml", 1, "other", None);
        expect("g.yml", 2, "other", Some("CKV_AWS_1: reason"));
        assert_eq!(hits.len(), 15, "{hits:?}");
        assert!(
            !hits
                .iter()
                .any(|h| matches!(h.0.as_str(), "h.txt" | "i.md" | "j.py" | "k.po"))
        );
        let first = &swept.findings[0];
        assert_eq!(first.tool, SUPPRESSIONS);
        assert_eq!(first.severity, Severity::Low);
        assert_eq!(first.categories, vec!["suppression".to_owned()]);
        assert!(
            first.title.ends_with("suppression comment (trivy:ignore)"),
            "{}",
            first.title
        );
        assert_eq!(first.column, Some(2));
    }

    #[test]
    fn one_walk_serves_both_passes_and_a_long_line_is_cheap() {
        let long = format!("{} // TODO at the end # nosec\n", "x".repeat(3_000_000));
        let dir = tree(&[("big.js", &long), ("a.py", "# fixme\n")]);
        let started = std::time::Instant::now();
        let (comments, suppressions) = run(dir.path(), 1000, true, true);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(comments.scanned_files, 2);
        assert_eq!(suppressions.scanned_files, 2);
        assert_eq!(comments.findings.len(), 2);
        assert_eq!(suppressions.findings.len(), 1);
        assert_eq!(comments.findings[1].column, Some(3_000_005));
        let (none, also_none) = run(dir.path(), 1000, false, false);
        assert!(none.findings.is_empty() && also_none.findings.is_empty());
        assert_eq!(none.scanned_files, 2);
    }

    #[test]
    fn large_files_are_skipped_and_the_walk_is_capped() {
        let dir = tree(&[
            ("a.txt", "TODO\n"),
            ("b.txt", "TODO\n"),
            ("c.txt", "TODO\n"),
        ]);
        let big = dir.path().join("big.txt");
        let file = std::fs::File::create(&big).unwrap();
        file.set_len(MAX_FILE_BYTES + 1).unwrap();
        let swept = comments(dir.path(), 1000);
        assert_eq!(swept.scanned_files, 3);
        assert_eq!(swept.skipped_paths.len(), 1);
        assert!(swept.skipped_paths[0].reason.starts_with("larger than"));
        let capped = comments(dir.path(), 2);
        assert!(capped.truncated);
        assert_eq!(capped.scanned_files, 2);
        assert_eq!(comments(&dir.path().join("missing"), 10), Swept::default());
    }
}
