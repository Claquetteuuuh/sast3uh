//! What a target holds — languages and notable files — from file names alone, so the
//! pipeline can pick the rule packs that matter without reading a single file.
//!
//! The walk skips what no scanner should look at (VCS metadata, dependency trees, build
//! output), never follows symbolic links, and stops at a file cap so a huge monorepo cannot
//! turn detection into the slow part.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

/// A language Semgrep (or another scanner) can analyse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(missing_docs)]
pub enum Language {
    Apex,
    Bash,
    C,
    Cpp,
    CSharp,
    Clojure,
    Dart,
    Dockerfile,
    Elixir,
    Go,
    Html,
    Java,
    JavaScript,
    Json,
    Jsonnet,
    Julia,
    Kotlin,
    Lua,
    Ocaml,
    Php,
    Python,
    R,
    Ruby,
    Rust,
    Scala,
    Solidity,
    Swift,
    Terraform,
    TypeScript,
    Yaml,
}

impl Language {
    /// The identifier Semgrep uses for the language.
    pub fn semgrep_id(self) -> &'static str {
        match self {
            Language::Apex => "apex",
            Language::Bash => "bash",
            Language::C => "c",
            Language::Cpp => "cpp",
            Language::CSharp => "csharp",
            Language::Clojure => "clojure",
            Language::Dart => "dart",
            Language::Dockerfile => "dockerfile",
            Language::Elixir => "elixir",
            Language::Go => "go",
            Language::Html => "html",
            Language::Java => "java",
            Language::JavaScript => "javascript",
            Language::Json => "json",
            Language::Jsonnet => "jsonnet",
            Language::Julia => "julia",
            Language::Kotlin => "kotlin",
            Language::Lua => "lua",
            Language::Ocaml => "ocaml",
            Language::Php => "php",
            Language::Python => "python",
            Language::R => "r",
            Language::Ruby => "ruby",
            Language::Rust => "rust",
            Language::Scala => "scala",
            Language::Solidity => "solidity",
            Language::Swift => "swift",
            Language::Terraform => "terraform",
            Language::TypeScript => "typescript",
            Language::Yaml => "yaml",
        }
    }

    /// The language of a file, from its name.
    pub fn of_file(name: &str) -> Option<Self> {
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "dockerfile" | "containerfile" => return Some(Language::Dockerfile),
            "gemfile" | "rakefile" | "guardfile" | "podfile" => return Some(Language::Ruby),
            "makefile" => return None,
            _ => {}
        }
        if lower.starts_with("dockerfile.") || lower.ends_with(".dockerfile") {
            return Some(Language::Dockerfile);
        }
        let ext = lower.rsplit('.').next().filter(|e| e.len() < lower.len())?;
        Some(match ext {
            "cls" | "trigger" => Language::Apex,
            "sh" | "bash" | "zsh" | "ksh" => Language::Bash,
            "c" | "h" => Language::C,
            "cc" | "cpp" | "cxx" | "c++" | "hpp" | "hh" | "hxx" | "h++" => Language::Cpp,
            "cs" => Language::CSharp,
            "clj" | "cljs" | "cljc" | "edn" => Language::Clojure,
            "dart" => Language::Dart,
            "ex" | "exs" => Language::Elixir,
            "go" => Language::Go,
            "html" | "htm" | "xhtml" => Language::Html,
            "java" => Language::Java,
            "js" | "jsx" | "mjs" | "cjs" | "vue" | "svelte" => Language::JavaScript,
            "json" | "jsonc" | "json5" => Language::Json,
            "jsonnet" | "libsonnet" => Language::Jsonnet,
            "jl" => Language::Julia,
            "kt" | "kts" => Language::Kotlin,
            "lua" => Language::Lua,
            "ml" | "mli" => Language::Ocaml,
            "php" | "phtml" | "php5" | "php7" | "phps" => Language::Php,
            "py" | "pyi" | "pyw" => Language::Python,
            "r" | "rmd" => Language::R,
            "rb" | "erb" | "rake" | "gemspec" => Language::Ruby,
            "rs" => Language::Rust,
            "scala" | "sc" => Language::Scala,
            "sol" => Language::Solidity,
            "swift" => Language::Swift,
            "tf" | "tfvars" | "hcl" => Language::Terraform,
            "ts" | "tsx" | "mts" | "cts" => Language::TypeScript,
            "yml" | "yaml" => Language::Yaml,
            _ => return None,
        })
    }
}

/// A notable file or layout that calls for a specific rule pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Marker {
    /// `.github/workflows/*.yml`.
    GithubActions,
    /// `.gitlab-ci.yml`.
    GitlabCi,
    /// `docker-compose*.yml` / `compose.yml`.
    DockerCompose,
    /// A dependency lockfile or manifest (supply-chain rules).
    Lockfile,
    /// `nginx.conf` or a file under an `nginx` directory.
    Nginx,
    /// A Kubernetes manifest directory (`k8s`, `kubernetes`, `manifests`, `charts`, `helm`).
    Kubernetes,
    /// A `.luacheckrc` (the project configures Luacheck itself).
    Luacheckrc,
    /// An AI agent skill or instruction file (`SKILL.md`, `.cursorrules`, `CLAUDE.md`…).
    AgentSkill,
}

impl Marker {
    /// The marker a file carries, from its relative path, if any.
    pub fn of_path(relative: &str) -> Option<Self> {
        let lower = relative.replace('\\', "/").to_ascii_lowercase();
        let name = lower.rsplit('/').next().unwrap_or(&lower);
        let in_dir = |dir: &str| lower.split('/').rev().skip(1).any(|part| part == dir);
        if lower.starts_with(".github/workflows/") && is_yaml(name) {
            return Some(Marker::GithubActions);
        }
        if name == ".gitlab-ci.yml" {
            return Some(Marker::GitlabCi);
        }
        if (name.starts_with("docker-compose") || name.starts_with("compose.")) && is_yaml(name) {
            return Some(Marker::DockerCompose);
        }
        if matches!(
            name,
            "package-lock.json"
                | "yarn.lock"
                | "pnpm-lock.yaml"
                | "package.json"
                | "requirements.txt"
                | "pipfile.lock"
                | "poetry.lock"
                | "uv.lock"
                | "go.sum"
                | "go.mod"
                | "gemfile.lock"
                | "cargo.lock"
                | "composer.lock"
                | "pom.xml"
                | "build.gradle"
                | "build.gradle.kts"
                | "packages.lock.json"
                | "pubspec.lock"
                | "mix.lock"
        ) || name.starts_with("requirements") && has_ext(name, "txt")
        {
            return Some(Marker::Lockfile);
        }
        if name == "nginx.conf" || (has_ext(name, "conf") && in_dir("nginx")) {
            return Some(Marker::Nginx);
        }
        if is_yaml(name)
            && [
                "k8s",
                "kubernetes",
                "manifests",
                "charts",
                "helm",
                "templates",
            ]
            .iter()
            .any(|d| in_dir(d))
        {
            return Some(Marker::Kubernetes);
        }
        if name == ".luacheckrc" {
            return Some(Marker::Luacheckrc);
        }
        if name == "skill.md"
            || name == ".cursorrules"
            || name == "claude.md"
            || name == "agents.md"
            || name == "gemini.md"
            || lower.contains("/.claude/")
            || lower.contains("/.cursor/")
        {
            return Some(Marker::AgentSkill);
        }
        None
    }
}

fn has_ext(name: &str, ext: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

fn is_yaml(name: &str) -> bool {
    has_ext(name, "yml") || has_ext(name, "yaml")
}

/// What was found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detected {
    /// Files per language.
    pub languages: BTreeMap<Language, usize>,
    /// Notable files.
    pub markers: BTreeSet<Marker>,
    /// Files looked at (directories excluded).
    pub files_seen: usize,
    /// `true` when the walk stopped at the file cap.
    pub truncated: bool,
}

impl Detected {
    /// The languages, most files first.
    pub fn languages_by_weight(&self) -> Vec<Language> {
        let mut langs: Vec<(Language, usize)> =
            self.languages.iter().map(|(l, n)| (*l, *n)).collect();
        langs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        langs.into_iter().map(|(l, _)| l).collect()
    }

    /// One line for the log: `javascript (3), python (1), yaml (2) · github-actions, lockfile`.
    pub fn summary(&self) -> String {
        let mut counts: Vec<(Language, usize)> =
            self.languages.iter().map(|(l, n)| (*l, *n)).collect();
        counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let langs: Vec<String> = counts
            .iter()
            .map(|(l, n)| format!("{} ({n})", l.semgrep_id()))
            .collect();
        let markers: Vec<String> = self
            .markers
            .iter()
            .map(|m| {
                serde_json::to_value(m)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default()
            })
            .collect();
        let mut out = if langs.is_empty() {
            "no recognised language".to_owned()
        } else {
            langs.join(", ")
        };
        if !markers.is_empty() {
            out.push_str(" · ");
            out.push_str(&markers.join(", "));
        }
        if self.truncated {
            out.push_str(" · (walk truncated)");
        }
        out
    }
}

/// Directories no scanner should look into.
const SKIPPED_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "target",
    "vendor",
    "dist",
    "build",
    "out",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    ".cache",
    ".mise",
    ".idea",
    ".vscode",
    "coverage",
    ".next",
    ".nuxt",
    ".terraform",
    "Pods",
    "DerivedData",
    ".gradle",
    "bower_components",
    ".yarn",
    ".pnpm-store",
];

/// Default cap on files looked at.
pub const DEFAULT_MAX_FILES: usize = 200_000;

/// Walk `root` and report what it holds.
pub fn detect(root: &Path, max_files: usize) -> Detected {
    let mut found = Detected::default();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
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
            if found.files_seen >= max_files {
                found.truncated = true;
                return found;
            }
            found.files_seen += 1;
            if let Some(language) = Language::of_file(&name) {
                *found.languages.entry(language).or_insert(0) += 1;
            }
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            if let Some(marker) = Marker::of_path(&relative) {
                found.markers.insert(marker);
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(root: &Path, relative: &str) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"x").unwrap();
    }

    #[test]
    fn languages_come_from_extensions_and_special_names() {
        assert_eq!(Language::of_file("app.js"), Some(Language::JavaScript));
        assert_eq!(Language::of_file("App.TSX"), Some(Language::TypeScript));
        assert_eq!(Language::of_file("main.lua"), Some(Language::Lua));
        assert_eq!(Language::of_file("Dockerfile"), Some(Language::Dockerfile));
        assert_eq!(
            Language::of_file("Dockerfile.prod"),
            Some(Language::Dockerfile)
        );
        assert_eq!(Language::of_file("Gemfile"), Some(Language::Ruby));
        assert_eq!(Language::of_file("main.tf"), Some(Language::Terraform));
        assert_eq!(Language::of_file("deploy.yaml"), Some(Language::Yaml));
        assert_eq!(Language::of_file("README.md"), None);
        assert_eq!(Language::of_file("Makefile"), None);
        assert_eq!(Language::of_file("noext"), None);
        assert_eq!(
            Language::of_file(".bashrc"),
            None,
            "a dot file has no extension"
        );
        assert_eq!(Language::Cpp.semgrep_id(), "cpp");
        assert_eq!(Language::CSharp.semgrep_id(), "csharp");
    }

    #[test]
    fn markers_come_from_paths() {
        assert_eq!(
            Marker::of_path(".github/workflows/ci.yml"),
            Some(Marker::GithubActions)
        );
        assert_eq!(Marker::of_path(".github/dependabot.yml"), None);
        assert_eq!(Marker::of_path(".gitlab-ci.yml"), Some(Marker::GitlabCi));
        assert_eq!(
            Marker::of_path("docker-compose.prod.yml"),
            Some(Marker::DockerCompose)
        );
        assert_eq!(Marker::of_path("compose.yaml"), Some(Marker::DockerCompose));
        assert_eq!(Marker::of_path("package-lock.json"), Some(Marker::Lockfile));
        assert_eq!(
            Marker::of_path("api/requirements-dev.txt"),
            Some(Marker::Lockfile)
        );
        assert_eq!(Marker::of_path("Cargo.lock"), Some(Marker::Lockfile));
        assert_eq!(
            Marker::of_path("deploy/nginx/site.conf"),
            Some(Marker::Nginx)
        );
        assert_eq!(Marker::of_path("nginx.conf"), Some(Marker::Nginx));
        assert_eq!(Marker::of_path("other/site.conf"), None);
        assert_eq!(
            Marker::of_path("k8s/deployment.yaml"),
            Some(Marker::Kubernetes)
        );
        assert_eq!(
            Marker::of_path("charts/app/templates/svc.yaml"),
            Some(Marker::Kubernetes)
        );
        assert_eq!(Marker::of_path("config/app.yaml"), None);
        assert_eq!(Marker::of_path(".luacheckrc"), Some(Marker::Luacheckrc));
        assert_eq!(
            Marker::of_path("skills/deploy/SKILL.md"),
            Some(Marker::AgentSkill)
        );
        assert_eq!(Marker::of_path("CLAUDE.md"), Some(Marker::AgentSkill));
        assert_eq!(Marker::of_path("src/main.rs"), None);
    }

    #[test]
    fn detect_walks_counts_and_skips_dependency_trees() {
        let dir = tempfile::tempdir().unwrap();
        for f in [
            "src/app.js",
            "src/lib.ts",
            "src/app.py",
            "lua/main.lua",
            ".github/workflows/ci.yml",
            "package-lock.json",
            "Dockerfile",
            "README.md",
        ] {
            touch(dir.path(), f);
        }
        touch(dir.path(), "node_modules/left-pad/index.js");
        touch(dir.path(), ".git/hooks/pre-commit.sh");
        touch(dir.path(), "target/debug/build.rs");
        let found = detect(dir.path(), DEFAULT_MAX_FILES);
        assert_eq!(
            found.languages[&Language::JavaScript],
            1,
            "node_modules is skipped"
        );
        assert_eq!(found.languages[&Language::TypeScript], 1);
        assert_eq!(found.languages[&Language::Python], 1);
        assert_eq!(found.languages[&Language::Lua], 1);
        assert_eq!(found.languages[&Language::Yaml], 1);
        assert_eq!(found.languages[&Language::Dockerfile], 1);
        assert_eq!(found.languages[&Language::Json], 1);
        assert!(
            !found.languages.contains_key(&Language::Rust),
            "target/ is skipped"
        );
        assert!(
            !found.languages.contains_key(&Language::Bash),
            ".git/ is skipped"
        );
        assert_eq!(
            found.markers,
            BTreeSet::from([Marker::GithubActions, Marker::Lockfile])
        );
        assert_eq!(found.files_seen, 8);
        assert!(!found.truncated);
        assert!(
            found.summary().contains("javascript (1)"),
            "{}",
            found.summary()
        );
        assert!(
            found.summary().contains("github-actions, lockfile"),
            "{}",
            found.summary()
        );
    }

    #[test]
    fn detect_stops_at_the_cap_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..5 {
            touch(dir.path(), &format!("f{i}.py"));
        }
        let found = detect(dir.path(), 3);
        assert!(found.truncated);
        assert_eq!(found.files_seen, 3);
        assert!(found.summary().ends_with("(walk truncated)"));
    }

    #[cfg(unix)]
    #[test]
    fn detect_never_follows_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        touch(outside.path(), "secret.rb");
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret.rb"), dir.path().join("file.rb"))
            .unwrap();
        let found = detect(dir.path(), DEFAULT_MAX_FILES);
        assert!(found.languages.is_empty(), "{found:?}");
        assert_eq!(found.files_seen, 0);
    }

    #[test]
    fn an_empty_or_missing_directory_detects_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(detect(dir.path(), 10), Detected::default());
        assert_eq!(detect(&dir.path().join("missing"), 10), Detected::default());
        assert_eq!(Detected::default().summary(), "no recognised language");
    }

    #[test]
    fn languages_by_weight_orders_by_file_count_then_name() {
        let mut found = Detected::default();
        found.languages.insert(Language::Python, 2);
        found.languages.insert(Language::JavaScript, 5);
        found.languages.insert(Language::Go, 2);
        assert_eq!(
            found.languages_by_weight(),
            vec![Language::JavaScript, Language::Go, Language::Python]
        );
    }
}
