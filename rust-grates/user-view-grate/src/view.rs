//! What one user sees of a file, and how what they write goes back into it.
//!
//! A view works line by line. A line is *visible* if it matches one of the `keep` patterns (or
//! there are none) and none of the `drop` patterns. Visible lines then pass through the `replace`
//! rules in order. Everything is done on bytes, so a file need not be valid UTF-8.

use std::borrow::Cow;

use regex::bytes::{Regex, RegexBuilder};

#[derive(Debug)]
pub struct CompiledView {
    keep: Vec<Regex>,
    drop: Vec<Regex>,
    replace: Vec<(Regex, Vec<u8>)>,
    pub writable: bool,
}

/// Why a user's edit was not merged into the real file.
#[derive(Debug, PartialEq, Eq)]
pub enum MergeError {
    /// Line `line` (counted from 1) of what the user wrote is not one they are allowed to see,
    /// so it is not one they may write either.
    NotOwnLine { line: usize },
}

fn compile(pattern: &str) -> Result<Regex, String> {
    RegexBuilder::new(pattern)
        // `.`, `\w`, `\d` and friends match bytes, so no input is rejected or skipped for its
        // encoding.
        .unicode(false)
        .build()
        .map_err(|e| format!("bad pattern {pattern:?}: {e}"))
}

/// A line without its trailing newline.
fn body(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\n").unwrap_or(line)
}

impl CompiledView {
    pub fn new(
        keep: &[String],
        drop: &[String],
        replace: &[(String, String)],
        writable: bool,
    ) -> Result<Self, String> {
        Ok(CompiledView {
            keep: keep.iter().map(|p| compile(p)).collect::<Result<_, _>>()?,
            drop: drop.iter().map(|p| compile(p)).collect::<Result<_, _>>()?,
            replace: replace
                .iter()
                .map(|(p, r)| Ok((compile(p)?, r.as_bytes().to_vec())))
                .collect::<Result<_, String>>()?,
            writable,
        })
    }

    /// Whether the user may see `line` (given without its newline).
    pub fn visible(&self, line: &[u8]) -> bool {
        (self.keep.is_empty() || self.keep.iter().any(|r| r.is_match(line)))
            && !self.drop.iter().any(|r| r.is_match(line))
    }

    /// The user's view of `raw`.
    pub fn render(&self, raw: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for line in raw.split_inclusive(|&b| b == b'\n') {
            let text = body(line);
            if !self.visible(text) {
                continue;
            }
            let mut text = Cow::Borrowed(text);
            for (pattern, replacement) in &self.replace {
                // Only a rule that matched allocates a new line.
                let rewritten = match pattern.replace_all(&text, &replacement[..]) {
                    Cow::Borrowed(_) => None,
                    Cow::Owned(new) => Some(new),
                };
                if let Some(new) = rewritten {
                    text = Cow::Owned(new);
                }
            }
            out.extend_from_slice(&text);
            if line.ends_with(b"\n") {
                out.push(b'\n');
            }
        }
        out
    }

    /// `raw` with the user's lines replaced by `edited`, the view as the user left it.
    ///
    /// Every line of `edited` must itself be visible to the user: someone who sees only lines
    /// starting `alice:` can write only such lines. Lines the user cannot see are kept exactly as
    /// they are, in place. The first visible line of `raw` is replaced by the first line of
    /// `edited`, the second by the second, and so on; extra lines of `edited` go after the last
    /// visible line (at the end of the file if there was none), and visible lines left over are
    /// removed.
    pub fn merge(&self, raw: &[u8], edited: &[u8]) -> Result<Vec<u8>, MergeError> {
        let new_lines: Vec<&[u8]> = edited.split_inclusive(|&b| b == b'\n').collect();
        for (i, line) in new_lines.iter().enumerate() {
            if !self.visible(body(line)) {
                return Err(MergeError::NotOwnLine { line: i + 1 });
            }
        }

        let mut new_lines = new_lines.into_iter();
        let mut out: Vec<&[u8]> = Vec::new();
        // Where lines of `edited` that have no line to replace are inserted.
        let mut extra_at = None;
        for line in raw.split_inclusive(|&b| b == b'\n') {
            if self.visible(body(line)) {
                if let Some(new) = new_lines.next() {
                    out.push(new);
                }
                extra_at = Some(out.len());
            } else {
                out.push(line);
            }
        }
        let at = extra_at.unwrap_or(out.len());
        out.splice(at..at, new_lines);

        // A line that is no longer last needs its newline; the last line ends the way the file
        // did.
        let ends_with_newline = raw.ends_with(b"\n");
        let mut merged = Vec::with_capacity(raw.len() + edited.len() + 1);
        let last = out.len().saturating_sub(1);
        for (i, line) in out.iter().enumerate() {
            merged.extend_from_slice(line);
            if !line.ends_with(b"\n") && (i < last || ends_with_newline) {
                merged.push(b'\n');
            }
        }
        Ok(merged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(keep: &[&str], drop: &[&str], replace: &[(&str, &str)]) -> CompiledView {
        let s = |v: &[&str]| v.iter().map(|p| p.to_string()).collect::<Vec<_>>();
        let r: Vec<(String, String)> = replace
            .iter()
            .map(|(p, r)| (p.to_string(), r.to_string()))
            .collect();
        CompiledView::new(&s(keep), &s(drop), &r, replace.is_empty()).unwrap()
    }

    const SHADOW: &[u8] = b"root:$6$r00t:19000:0:99999:7:::\n\
alice:$6$aaaa:19500:0:99999:7:::\n\
bob:$6$bbbb:19600:0:99999:7:::\n";

    #[test]
    fn keep_shows_only_matching_lines() {
        let v = view(&["^alice:"], &[], &[]);
        assert_eq!(v.render(SHADOW), b"alice:$6$aaaa:19500:0:99999:7:::\n");
        assert_eq!(view(&["^nobody:"], &[], &[]).render(SHADOW), b"");
    }

    #[test]
    fn keep_patterns_are_alternatives_and_drop_wins() {
        let v = view(&["^alice:", "^bob:"], &["bbbb"], &[]);
        assert_eq!(v.render(SHADOW), b"alice:$6$aaaa:19500:0:99999:7:::\n");
        // With no keep pattern every line is visible unless dropped.
        let v = view(&[], &["^root:"], &[]);
        assert!(!v.render(SHADOW).starts_with(b"root"));
        assert_eq!(v.render(SHADOW).split(|&b| b == b'\n').count(), 3);
    }

    #[test]
    fn replace_rewrites_visible_lines_in_order() {
        let log = b"pay user=alice card=4111-1111-1111-1111 ok\nlogin user=bob\n";
        let v = view(
            &[],
            &[],
            &[
                (r"\b(\d{4})-\d{4}-\d{4}-(\d{4})\b", "$1-****-****-$2"),
                (r"user=\w+", "user=?"),
            ],
        );
        assert_eq!(
            v.render(log),
            b"pay user=? card=4111-****-****-1111 ok\nlogin user=?\n"
        );
    }

    #[test]
    fn replace_can_delete_and_last_line_keeps_its_ending() {
        let v = view(&[], &[], &[("secret=\\S+ ?", "")]);
        assert_eq!(v.render(b"a secret=x b\nc secret=y"), b"a b\nc ");
    }

    #[test]
    fn bytes_that_are_not_utf8_pass_through() {
        let v = view(&["^a"], &[], &[("x.z", "-")]);
        assert_eq!(v.render(b"a\xff x\xfez\nb\xff\n"), b"a\xff -\n");
    }

    #[test]
    fn merge_replaces_own_line_in_place() {
        let v = view(&["^alice:"], &[], &[]);
        let merged = v.merge(SHADOW, b"alice:$6$NEW:20000:0:99999:7:::\n").unwrap();
        assert_eq!(
            merged,
            b"root:$6$r00t:19000:0:99999:7:::\n\
alice:$6$NEW:20000:0:99999:7:::\n\
bob:$6$bbbb:19600:0:99999:7:::\n"
        );
        // Unchanged view, unchanged file.
        assert_eq!(v.merge(SHADOW, &v.render(SHADOW)).unwrap(), SHADOW);
    }

    #[test]
    fn merge_refuses_lines_the_user_could_not_see() {
        let v = view(&["^alice:"], &[], &[]);
        assert_eq!(
            v.merge(SHADOW, b"alice:x\nroot::0:0:::::\n"),
            Err(MergeError::NotOwnLine { line: 2 })
        );
        // A blank line is not an `alice:` line either.
        assert_eq!(
            v.merge(SHADOW, b"alice:x\n\n"),
            Err(MergeError::NotOwnLine { line: 2 })
        );
    }

    #[test]
    fn merge_adds_and_removes_lines() {
        let v = view(&["^alice:"], &[], &[]);
        // Two lines for one: the extra goes right after the user's last line.
        assert_eq!(
            v.merge(SHADOW, b"alice:1\nalice:2\n").unwrap(),
            b"root:$6$r00t:19000:0:99999:7:::\nalice:1\nalice:2\nbob:$6$bbbb:19600:0:99999:7:::\n"
        );
        // An empty view removes the user's lines and nothing else.
        assert_eq!(
            v.merge(SHADOW, b"").unwrap(),
            b"root:$6$r00t:19000:0:99999:7:::\nbob:$6$bbbb:19600:0:99999:7:::\n"
        );
        // A user with no line yet gets theirs appended.
        let carol = view(&["^carol:"], &[], &[]);
        assert!(carol.merge(SHADOW, b"carol:1\n").unwrap().ends_with(b":::\ncarol:1\n"));
    }

    #[test]
    fn merge_fixes_up_newlines() {
        let v = view(&["^a"], &[], &[]);
        // The edit has no final newline but lands mid-file.
        assert_eq!(v.merge(b"a1\nb\n", b"a2").unwrap(), b"a2\nb\n");
        // The last line ends the way the user wrote it when the file had no final newline.
        assert_eq!(v.merge(b"b\na1", b"a2\n").unwrap(), b"b\na2\n");
        assert_eq!(v.merge(b"b\na1", b"a2").unwrap(), b"b\na2");
        // A line appended after an unterminated last line starts on its own line.
        assert_eq!(v.merge(b"b", b"a2").unwrap(), b"b\na2");
        assert_eq!(v.merge(b"", b"a2").unwrap(), b"a2");
    }
}
