//! Loose semantic versions: enough to compare what a tool prints with what upstream released.

use std::fmt;

/// `major.minor.patch`; pre-release and build suffixes are ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    /// Major.
    pub major: u64,
    /// Minor.
    pub minor: u64,
    /// Patch (0 when absent).
    pub patch: u64,
}

impl Version {
    /// Build a version.
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Version {
            major,
            minor,
            patch,
        }
    }

    /// Find the first `N.N[.N]` token in free-form text, such as `bearer version 2.1.1, build
    /// 600e55…`, `Luacheck: 1.2.0` or `v1.183.0`.
    pub fn parse(text: &str) -> Option<Self> {
        text.split(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '(' || c == ')')
            .find_map(Self::parse_token)
    }

    fn parse_token(token: &str) -> Option<Self> {
        let token = token.trim_start_matches(['v', 'V']);
        // Drop a pre-release / build suffix: 1.2.3-rc1, 1.2.3+build.
        let core = token.split(['-', '+']).next()?;
        let mut parts = core.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = match parts.next() {
            None => 0,
            Some(p) => p
                .trim_end_matches(|c: char| !c.is_ascii_digit())
                .parse()
                .ok()?,
        };
        if parts.next().is_some() {
            return None;
        }
        Some(Version {
            major,
            minor,
            patch,
        })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_tools_version_banners() {
        assert_eq!(
            Version::parse("bearer version 2.1.1, build 600e551c56e61c063e425190d49fe0a960103a48"),
            Some(Version::new(2, 1, 1))
        );
        assert_eq!(Version::parse("1.163.0\n"), Some(Version::new(1, 163, 0)));
        assert_eq!(
            Version::parse("Luacheck: 1.2.0\nLua: PUC-Rio Lua 5.4\nArgparse: 0.7.1"),
            Some(Version::new(1, 2, 0))
        );
        assert_eq!(Version::parse("v1.183.0"), Some(Version::new(1, 183, 0)));
    }

    #[test]
    fn skips_the_bearer_update_nag_that_precedes_the_banner() {
        let text = "You are running an outdated version of Bearer CLI, v2.1.3 is now available.\n\
                    bearer version 2.1.1, build 600e551c";
        // The first version-looking token wins: callers that need the installed one must look
        // at the line that carries it (see the Bearer adapter).
        assert_eq!(Version::parse(text), Some(Version::new(2, 1, 3)));
    }

    #[test]
    fn two_part_versions_and_suffixes() {
        assert_eq!(Version::parse("5.4"), Some(Version::new(5, 4, 0)));
        assert_eq!(Version::parse("1.2.3-rc1"), Some(Version::new(1, 2, 3)));
        assert_eq!(Version::parse("1.2.3+build.7"), Some(Version::new(1, 2, 3)));
        assert_eq!(Version::parse("(1.2.3)"), Some(Version::new(1, 2, 3)));
    }

    #[test]
    fn rejects_text_without_a_version() {
        assert_eq!(Version::parse("no version here"), None);
        assert_eq!(Version::parse(""), None);
        assert_eq!(Version::parse("1"), None);
        assert_eq!(Version::parse("1.2.3.4"), None);
        assert_eq!(Version::parse("a.b.c"), None);
    }

    #[test]
    fn orders_numerically_not_lexically() {
        assert!(Version::new(1, 163, 0) < Version::new(1, 183, 0));
        assert!(Version::new(1, 9, 0) < Version::new(1, 10, 0));
        assert!(Version::new(2, 0, 0) > Version::new(1, 999, 999));
        assert_eq!(Version::new(1, 2, 3).to_string(), "1.2.3");
    }
}
