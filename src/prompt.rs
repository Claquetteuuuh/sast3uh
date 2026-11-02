//! Yes/no questions to the person running the tool.

use std::io::{BufRead, IsTerminal, Write};

/// Something that can answer a yes/no question.
pub trait Prompter {
    /// Ask `question`; `true` means yes.
    fn confirm(&mut self, question: &str) -> bool;
}

/// Asks on the terminal. When standard input or standard error is not a terminal (CI, a
/// pipe), the answer is always no: a non-interactive run never changes the machine.
#[derive(Debug, Default)]
pub struct TerminalPrompter;

impl Prompter for TerminalPrompter {
    fn confirm(&mut self, question: &str) -> bool {
        let stdin = std::io::stdin();
        let mut stderr = std::io::stderr();
        if !stdin.is_terminal() || !stderr.is_terminal() {
            return false;
        }
        let _ = write!(stderr, "{question} [y/N] ");
        let _ = stderr.flush();
        let mut answer = String::new();
        match stdin.lock().read_line(&mut answer) {
            Ok(0) | Err(_) => false,
            Ok(_) => is_yes(&answer),
        }
    }
}

/// A fixed answer.
#[derive(Debug, Clone, Copy)]
pub struct FixedAnswer(pub bool);

impl Prompter for FixedAnswer {
    fn confirm(&mut self, _question: &str) -> bool {
        self.0
    }
}

/// `y`, `yes`, `o`, `oui` — case-insensitive, surrounding whitespace ignored.
pub fn is_yes(answer: &str) -> bool {
    matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes" | "o" | "oui"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_yes_in_both_languages() {
        for yes in ["y", "Y", "yes", "YES ", " oui\n", "o"] {
            assert!(is_yes(yes), "{yes:?}");
        }
        for no in ["", "n", "no", "non", "yeah", "\n"] {
            assert!(!is_yes(no), "{no:?}");
        }
    }

    #[test]
    fn fixed_answers_are_fixed() {
        assert!(FixedAnswer(true).confirm("?"));
        assert!(!FixedAnswer(false).confirm("?"));
    }

    #[test]
    fn the_terminal_prompter_says_no_without_a_terminal() {
        // Under `cargo test` stdin is not a terminal.
        if !std::io::stdin().is_terminal() {
            assert!(!TerminalPrompter.confirm("update?"));
        }
    }
}
