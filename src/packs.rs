//! The Semgrep rule packs worth running, and which of them a target calls for.
//!
//! The catalogue was measured against the registry (`https://semgrep.dev/api/registry/rulesets`
//! and `https://semgrep.dev/c/p/<name>`) on 2026-11-02, anonymously — what the OSS engine can
//! actually download. Every official pack (author Semgrep, r2c, GitLab, Trail of Bits, 0xdea)
//! was downloaded and counted; the ones left out are either **empty without a Pro login**
//! (`elixir`, `nextjs`, `nestjs`, `php-laravel`, `lockfiles`, `cpp-audit`, `cpp-alpha-*`,
//! `csharp-interfile`, `mobile-open-redirect`, `scala-alpha`, `secrets-default`,
//! `semgrep-secrets*`, `shadow-ai-pro`, `security-headers`, `agent-skills`, `vuln-finding`),
//! **meta or test packs** (`semgrep-rule-lints`, `semgrep-rule-ci`, `semgrep-misconfigurations`,
//! `test*`, `auto`), **strict subsets** of a pack already listed (`r2c-security-audit` =
//! `security-audit`, `typescript` = `javascript`, `dockerfile` = `docker`, `gitlab-eslint` =
//! `eslint`, `deepsemgrep`/`default-v2` ⊂ `default`, `minusworld.ruby-on-rails-xss` =
//! `ruby-on-rails-xss`, `helper_scripts.insecure-transport-jsnode` =
//! `colleend.insecure-transport-nodejs`, `r2c-ci` = `ci`), or **style-only**
//! (`r2c-best-practices`).
//!
//! Semgrep deduplicates a rule that several packs share, so overlapping packs cost download
//! time, never duplicate findings; selecting by language keeps that time down.

use crate::detect::{Detected, Language, Marker};

/// How much noise is acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum Profile {
    /// Security rules only: the curated packs, the OWASP/CWE lists, secrets, injections.
    Security,
    /// Everything that is not pure style: adds the audit-oriented, community and correctness
    /// packs. More findings, more to triage. The default.
    Exhaustive,
}

/// What a pack is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Kind {
    Universal,
    Secrets,
    Injection,
    Language,
    Framework,
    Infra,
    Ci,
    SupplyChain,
    Ai,
    Correctness,
    Audit,
    Community,
}

/// A Semgrep registry pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pack {
    /// Registry name, without the `p/` prefix.
    pub name: &'static str,
    /// What it is for.
    pub kind: Kind,
    /// The least noisy profile that includes it.
    pub profile: Profile,
    /// Languages that call for it; empty with empty `markers` means always.
    pub languages: &'static [Language],
    /// Notable files that call for it.
    pub markers: &'static [Marker],
    /// Rules measured on 2026-11-02 (information only; the registry moves).
    pub measured_rules: u32,
    /// One line on what it brings.
    pub note: &'static str,
}

impl Pack {
    /// The `--config` value.
    pub fn config(&self) -> String {
        format!("p/{}", self.name)
    }

    /// `true` when the target calls for this pack.
    pub fn applies(&self, detected: &Detected) -> bool {
        if self.languages.is_empty() && self.markers.is_empty() {
            return true;
        }
        self.languages
            .iter()
            .any(|l| detected.languages.contains_key(l))
            || self.markers.iter().any(|m| detected.markers.contains(m))
    }
}

use Language::{
    Apex, Bash, C, CSharp, Cpp, Dockerfile, Go, Html, Java, JavaScript, Kotlin, Ocaml, Php, Python,
    Ruby, Rust, Scala, Swift, Terraform, TypeScript, Yaml,
};
use Marker::{AgentSkill, DockerCompose, GithubActions, GitlabCi, Kubernetes, Lockfile};

const JS: &[Language] = &[JavaScript, TypeScript, Html];
const JVM: &[Language] = &[Java, Kotlin, Scala];
const ALWAYS: &[Language] = &[];
const NO_MARKER: &[Marker] = &[];

macro_rules! pack {
    ($name:literal, $kind:ident, $profile:ident, $langs:expr, $markers:expr, $rules:literal, $note:literal) => {
        Pack {
            name: $name,
            kind: Kind::$kind,
            profile: Profile::$profile,
            languages: $langs,
            markers: $markers,
            measured_rules: $rules,
            note: $note,
        }
    };
}

/// The catalogue, in the order packs are passed to Semgrep.
pub const CATALOG: &[Pack] = &[
    // ── Always: the curated multi-language sets ─────────────────────
    pack!(
        "default",
        Universal,
        Security,
        ALWAYS,
        NO_MARKER,
        1074,
        "Semgrep's curated default: the broadest security set"
    ),
    pack!(
        "security-audit",
        Audit,
        Security,
        ALWAYS,
        NO_MARKER,
        225,
        "security issues that need a human review"
    ),
    pack!(
        "owasp-top-ten",
        Universal,
        Security,
        ALWAYS,
        NO_MARKER,
        560,
        "mapped to the OWASP Top 10"
    ),
    pack!(
        "cwe-top-25",
        Universal,
        Security,
        ALWAYS,
        NO_MARKER,
        216,
        "mapped to the CWE Top 25"
    ),
    pack!(
        "gitlab",
        Universal,
        Security,
        ALWAYS,
        NO_MARKER,
        544,
        "GitLab's SAST rules (gosec, flawfinder, findsecbugs… ports)"
    ),
    pack!(
        "trailofbits",
        Universal,
        Security,
        ALWAYS,
        NO_MARKER,
        120,
        "Trail of Bits' rules"
    ),
    pack!(
        "r2c",
        Universal,
        Security,
        ALWAYS,
        NO_MARKER,
        75,
        "the original r2c default set"
    ),
    pack!(
        "ci",
        Universal,
        Security,
        ALWAYS,
        NO_MARKER,
        160,
        "high-confidence rules safe to block a CI on"
    ),
    pack!(
        "comment",
        Universal,
        Exhaustive,
        ALWAYS,
        NO_MARKER,
        140,
        "lower-confidence rules meant for review comments"
    ),
    pack!(
        "audit-poc-20221019",
        Audit,
        Exhaustive,
        ALWAYS,
        NO_MARKER,
        271,
        "auditor-oriented: crypto, injection, auth"
    ),
    pack!(
        "developer-poc-20221019",
        Audit,
        Exhaustive,
        ALWAYS,
        NO_MARKER,
        60,
        "developer-oriented counterpart"
    ),
    pack!(
        "guardian-default",
        Universal,
        Exhaustive,
        ALWAYS,
        NO_MARKER,
        332,
        "fast-scan set for AI-generated code"
    ),
    pack!(
        "replit-community",
        Community,
        Exhaustive,
        ALWAYS,
        NO_MARKER,
        563,
        "Replit community pack (python, js/ts, regex)"
    ),
    pack!(
        "r2c-bug-scan",
        Correctness,
        Exhaustive,
        ALWAYS,
        NO_MARKER,
        44,
        "logic bugs, not security"
    ),
    // ── Secrets ─────────────────────────────────────────────────────
    pack!(
        "secrets",
        Secrets,
        Security,
        ALWAYS,
        NO_MARKER,
        52,
        "credentials in code"
    ),
    pack!(
        "gitleaks",
        Secrets,
        Security,
        ALWAYS,
        NO_MARKER,
        175,
        "gitleaks' secret patterns, ported"
    ),
    // ── Vulnerability classes across languages ──────────────────────
    pack!(
        "jwt",
        Injection,
        Security,
        ALWAYS,
        NO_MARKER,
        16,
        "JWT mistakes"
    ),
    pack!(
        "sql-injection",
        Injection,
        Security,
        ALWAYS,
        NO_MARKER,
        47,
        "SQL injection"
    ),
    pack!(
        "xss",
        Injection,
        Security,
        ALWAYS,
        NO_MARKER,
        35,
        "cross-site scripting"
    ),
    pack!(
        "minusworld.omni-xss",
        Injection,
        Security,
        ALWAYS,
        NO_MARKER,
        55,
        "secure defaults against XSS"
    ),
    pack!(
        "command-injection",
        Injection,
        Security,
        ALWAYS,
        NO_MARKER,
        31,
        "OS command injection"
    ),
    pack!(
        "colleend.insecure-transport-omni",
        Injection,
        Security,
        ALWAYS,
        NO_MARKER,
        53,
        "plain-text transport"
    ),
    // ── Supply chain ────────────────────────────────────────────────
    pack!(
        "supply-chain",
        SupplyChain,
        Security,
        ALWAYS,
        NO_MARKER,
        1,
        "trojan-source and friends"
    ),
    pack!(
        "package-managers",
        SupplyChain,
        Security,
        ALWAYS,
        &[Lockfile],
        11,
        "package-manager configuration hardening"
    ),
    // ── AI / agents ─────────────────────────────────────────────────
    pack!(
        "shadow-ai",
        Ai,
        Security,
        &[Python, JavaScript, TypeScript],
        NO_MARKER,
        144,
        "LLM usage in the code base"
    ),
    pack!(
        "ai-best-practices",
        Ai,
        Security,
        &[Python, Bash],
        &[AgentSkill],
        27,
        "AI-powered application security"
    ),
    pack!(
        "mcp",
        Ai,
        Security,
        &[Python],
        &[AgentSkill],
        6,
        "Model Context Protocol implementations"
    ),
    // ── Python ──────────────────────────────────────────────────────
    pack!(
        "python",
        Language,
        Security,
        &[Python],
        NO_MARKER,
        151,
        "Python default"
    ),
    pack!(
        "django",
        Framework,
        Security,
        &[Python],
        NO_MARKER,
        28,
        "Django"
    ),
    pack!(
        "minusworld.django-xss",
        Framework,
        Security,
        &[Python],
        NO_MARKER,
        12,
        "Django XSS defaults"
    ),
    pack!(
        "flask",
        Framework,
        Security,
        &[Python],
        NO_MARKER,
        18,
        "Flask"
    ),
    pack!(
        "fastapi",
        Framework,
        Security,
        &[Python],
        NO_MARKER,
        1,
        "FastAPI"
    ),
    pack!(
        "minusworld.r2c-python-ci",
        Language,
        Security,
        &[Python],
        NO_MARKER,
        39,
        "high-confidence Python"
    ),
    pack!(
        "python-alpha-ci",
        Language,
        Exhaustive,
        &[Python],
        NO_MARKER,
        21,
        "alpha Python rules"
    ),
    // ── JavaScript / TypeScript ─────────────────────────────────────
    pack!(
        "javascript",
        Language,
        Security,
        JS,
        NO_MARKER,
        74,
        "JavaScript/TypeScript default"
    ),
    pack!("nodejs", Framework, Security, JS, NO_MARKER, 36, "Node.js"),
    pack!(
        "expressjs",
        Framework,
        Security,
        JS,
        NO_MARKER,
        71,
        "Express"
    ),
    pack!(
        "minusworld.express-xss",
        Framework,
        Security,
        JS,
        NO_MARKER,
        10,
        "Express XSS defaults"
    ),
    pack!("hapi", Framework, Security, JS, NO_MARKER, 34, "hapi"),
    pack!("koa", Framework, Security, JS, NO_MARKER, 34, "Koa"),
    pack!("react", Framework, Security, JS, NO_MARKER, 4, "React"),
    pack!(
        "react-best-practices",
        Framework,
        Exhaustive,
        JS,
        NO_MARKER,
        13,
        "React smells (mostly style)"
    ),
    pack!(
        "electron-desktop-app",
        Framework,
        Security,
        JS,
        NO_MARKER,
        10,
        "Electron"
    ),
    pack!(
        "eslint",
        Language,
        Security,
        JS,
        NO_MARKER,
        12,
        "eslint-plugin-security, ported"
    ),
    pack!(
        "minusworld.r2c-javascript-ci",
        Language,
        Security,
        JS,
        NO_MARKER,
        16,
        "high-confidence JavaScript"
    ),
    pack!(
        "colleend.insecure-transport-nodejs",
        Framework,
        Security,
        JS,
        NO_MARKER,
        8,
        "Node.js plain-text transport"
    ),
    // ── JVM ─────────────────────────────────────────────────────────
    pack!(
        "java",
        Language,
        Security,
        &[Java],
        NO_MARKER,
        60,
        "Java default"
    ),
    pack!(
        "findsecbugs",
        Language,
        Security,
        JVM,
        NO_MARKER,
        285,
        "FindSecBugs, ported (Java, Scala, Kotlin)"
    ),
    pack!(
        "mschwager.java-security-rules",
        Language,
        Security,
        &[Java],
        NO_MARKER,
        59,
        "r2c Java security rules"
    ),
    pack!(
        "minusworld.r2c-java-ci",
        Language,
        Security,
        &[Java],
        NO_MARKER,
        16,
        "high-confidence Java"
    ),
    pack!(
        "colleend.insecure-transport-javastdlib",
        Framework,
        Security,
        &[Java],
        NO_MARKER,
        11,
        "Java stdlib plain-text transport"
    ),
    pack!(
        "colleend.insecure-transport-javaspring",
        Framework,
        Security,
        &[Java],
        NO_MARKER,
        3,
        "Spring plain-text transport"
    ),
    pack!(
        "minusworld.java-httpservlet-jsp-xss",
        Framework,
        Security,
        &[Java],
        NO_MARKER,
        4,
        "Servlet/JSP XSS defaults"
    ),
    pack!(
        "kotlin",
        Language,
        Security,
        &[Kotlin],
        NO_MARKER,
        10,
        "Kotlin default"
    ),
    pack!(
        "scala",
        Language,
        Security,
        &[Scala],
        NO_MARKER,
        12,
        "Scala default"
    ),
    pack!(
        "play",
        Framework,
        Security,
        &[Scala],
        NO_MARKER,
        23,
        "Play framework"
    ),
    // ── Go ──────────────────────────────────────────────────────────
    pack!(
        "golang",
        Language,
        Security,
        &[Go],
        NO_MARKER,
        42,
        "Go default"
    ),
    pack!(
        "minusworld.r2c-go-ci",
        Language,
        Security,
        &[Go],
        NO_MARKER,
        19,
        "high-confidence Go"
    ),
    pack!(
        "minusworld.go-std-xss",
        Framework,
        Security,
        &[Go],
        NO_MARKER,
        5,
        "Go stdlib XSS defaults"
    ),
    // ── Ruby ────────────────────────────────────────────────────────
    pack!(
        "ruby",
        Language,
        Security,
        &[Ruby],
        NO_MARKER,
        45,
        "Ruby default"
    ),
    pack!(
        "brakeman",
        Framework,
        Security,
        &[Ruby],
        NO_MARKER,
        19,
        "Brakeman, ported (Rails)"
    ),
    pack!(
        "ruby-on-rails-xss",
        Framework,
        Security,
        &[Ruby],
        NO_MARKER,
        14,
        "Rails XSS defaults"
    ),
    // ── PHP ─────────────────────────────────────────────────────────
    pack!(
        "php",
        Language,
        Security,
        &[Php],
        NO_MARKER,
        24,
        "PHP default"
    ),
    pack!(
        "phpcs-security-audit",
        Language,
        Security,
        &[Php],
        NO_MARKER,
        9,
        "phpcs-security-audit, ported"
    ),
    pack!(
        "wordpress",
        Framework,
        Security,
        &[Php],
        NO_MARKER,
        12,
        "WordPress audit (WPScan port)"
    ),
    // ── C# ──────────────────────────────────────────────────────────
    pack!(
        "csharp",
        Language,
        Security,
        &[CSharp],
        NO_MARKER,
        27,
        "C# default"
    ),
    pack!(
        "security-code-scan",
        Language,
        Security,
        &[CSharp],
        NO_MARKER,
        20,
        "Security Code Scan, ported"
    ),
    // ── C / C++ ─────────────────────────────────────────────────────
    pack!(
        "c",
        Language,
        Security,
        &[C, Cpp],
        NO_MARKER,
        2,
        "C default"
    ),
    pack!(
        "flawfinder",
        Language,
        Security,
        &[C, Cpp],
        NO_MARKER,
        64,
        "Flawfinder, ported"
    ),
    pack!(
        "0xdea",
        Language,
        Security,
        &[C, Cpp],
        NO_MARKER,
        49,
        "vulnerability-research rules for C/C++"
    ),
    pack!(
        "helper_scripts.c",
        Language,
        Security,
        &[C, Cpp],
        NO_MARKER,
        15,
        "r2c C rules"
    ),
    // ── Others ──────────────────────────────────────────────────────
    pack!(
        "rust",
        Language,
        Security,
        &[Rust],
        NO_MARKER,
        11,
        "Rust (audit-oriented)"
    ),
    pack!(
        "swift",
        Language,
        Security,
        &[Swift],
        NO_MARKER,
        2,
        "Swift default"
    ),
    pack!(
        "ocaml",
        Correctness,
        Exhaustive,
        &[Ocaml],
        NO_MARKER,
        28,
        "OCaml (best practice, correctness)"
    ),
    pack!(
        "apex",
        Language,
        Security,
        &[Apex],
        NO_MARKER,
        22,
        "Apex default"
    ),
    // ── Infrastructure and CI ───────────────────────────────────────
    pack!(
        "terraform",
        Infra,
        Security,
        &[Terraform],
        NO_MARKER,
        63,
        "Terraform default"
    ),
    pack!(
        "docker",
        Infra,
        Security,
        &[Dockerfile],
        NO_MARKER,
        7,
        "Hadolint rules, ported"
    ),
    pack!(
        "docker-compose",
        Infra,
        Security,
        &[Yaml],
        &[DockerCompose],
        6,
        "docker-compose configuration"
    ),
    pack!(
        "kubernetes",
        Infra,
        Security,
        &[Yaml],
        &[Kubernetes],
        11,
        "Kubernetes manifests"
    ),
    pack!(
        "github-actions",
        Ci,
        Security,
        ALWAYS,
        &[GithubActions],
        12,
        "GitHub Actions workflows"
    ),
    pack!(
        "semgrep-misconfigurations",
        Ci,
        Exhaustive,
        ALWAYS,
        &[GithubActions, GitlabCi],
        1,
        "Semgrep misconfigured in CI"
    ),
];

/// The packs `detected` calls for under `profile`, in catalogue order.
pub fn select(detected: &Detected, profile: Profile) -> Vec<&'static Pack> {
    CATALOG
        .iter()
        .filter(|p| p.profile <= profile && p.applies(detected))
        .collect()
}

/// The `--config` values for [`select`].
pub fn configs(detected: &Detected, profile: Profile) -> Vec<String> {
    select(detected, profile)
        .iter()
        .map(|p| p.config())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn detected(langs: &[Language], markers: &[Marker]) -> Detected {
        let mut d = Detected::default();
        for l in langs {
            d.languages.insert(*l, 1);
        }
        d.markers = markers.iter().copied().collect();
        d
    }

    #[test]
    fn catalogue_names_are_unique_and_registry_shaped() {
        let mut seen = BTreeSet::new();
        for pack in CATALOG {
            assert!(seen.insert(pack.name), "duplicate {}", pack.name);
            assert!(
                pack.name.chars().all(|c| c.is_ascii_lowercase()
                    || c.is_ascii_digit()
                    || matches!(c, '-' | '_' | '.')),
                "{}",
                pack.name
            );
            assert!(!pack.note.is_empty());
            assert_eq!(pack.config(), format!("p/{}", pack.name));
        }
        assert!(CATALOG.len() >= 70, "{}", CATALOG.len());
    }

    #[test]
    fn an_empty_target_gets_the_universal_packs_only() {
        let names: Vec<&str> = select(&Detected::default(), Profile::Security)
            .iter()
            .map(|p| p.name)
            .collect();
        assert!(names.contains(&"default"));
        assert!(names.contains(&"gitlab"));
        assert!(names.contains(&"gitleaks"));
        assert!(names.contains(&"sql-injection"));
        assert!(!names.contains(&"python"));
        assert!(!names.contains(&"github-actions"));
        assert!(!names.contains(&"comment"), "exhaustive only");
        assert!(!names.contains(&"replit-community"));
    }

    #[test]
    fn languages_and_markers_add_their_packs() {
        let d = detected(&[JavaScript, Python, Yaml], &[GithubActions, Lockfile]);
        let names: Vec<&str> = select(&d, Profile::Exhaustive)
            .iter()
            .map(|p| p.name)
            .collect();
        for expected in [
            "javascript",
            "expressjs",
            "nodejs",
            "python",
            "django",
            "flask",
            "shadow-ai",
            "kubernetes",
            "docker-compose",
            "github-actions",
            "package-managers",
            "comment",
            "replit-community",
            "python-alpha-ci",
            "react-best-practices",
        ] {
            assert!(
                names.contains(&expected),
                "{expected} missing from {names:?}"
            );
        }
        for absent in [
            "golang",
            "java",
            "findsecbugs",
            "ruby",
            "php",
            "terraform",
            "docker",
            "rust",
            "ocaml",
        ] {
            assert!(
                !names.contains(&absent),
                "{absent} should not be selected: {names:?}"
            );
        }
        let order: Vec<usize> = names
            .iter()
            .map(|n| CATALOG.iter().position(|p| p.name == *n).unwrap())
            .collect();
        assert!(
            order.windows(2).all(|w| w[0] < w[1]),
            "catalogue order is kept"
        );
    }

    #[test]
    fn the_security_profile_is_a_subset_of_exhaustive() {
        let d = detected(&[Python, JavaScript, Go, Java, Ocaml], &[GithubActions]);
        let security: BTreeSet<&str> = select(&d, Profile::Security)
            .iter()
            .map(|p| p.name)
            .collect();
        let exhaustive: BTreeSet<&str> = select(&d, Profile::Exhaustive)
            .iter()
            .map(|p| p.name)
            .collect();
        assert!(security.is_subset(&exhaustive));
        assert!(exhaustive.len() > security.len());
        assert!(exhaustive.contains("ocaml") && !security.contains("ocaml"));
        assert!(Profile::Security < Profile::Exhaustive);
    }

    #[test]
    fn jvm_and_c_families_share_packs() {
        let kotlin: Vec<&str> = select(&detected(&[Kotlin], &[]), Profile::Security)
            .iter()
            .map(|p| p.name)
            .collect();
        assert!(
            kotlin.contains(&"kotlin")
                && kotlin.contains(&"findsecbugs")
                && !kotlin.contains(&"java")
        );
        let cpp: Vec<&str> = select(&detected(&[Cpp], &[]), Profile::Security)
            .iter()
            .map(|p| p.name)
            .collect();
        assert!(cpp.contains(&"flawfinder") && cpp.contains(&"0xdea") && cpp.contains(&"c"));
        let configs = configs(&detected(&[Rust], &[]), Profile::Security);
        assert!(configs.contains(&"p/rust".to_owned()));
        assert!(configs.iter().all(|c| c.starts_with("p/")));
    }
}
