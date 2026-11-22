//! The policy file: which files have views, and what each user sees of them.
//!
//! ```text
//! # uid -> name, used when a cage is identified by its effective uid
//! [users]
//! 0    = root
//! 1000 = alice
//!
//! [file /etc/shadow]
//! user root
//!   raw
//! user *
//!   keep ^{user}:
//!   write
//!
//! [file /var/log/payments.log]
//! user auditor
//!   raw
//! user support, oncall
//!   replace \b(\d{4})-\d{4}-\d{4}-(\d{4})\b => $1-****-****-$2
//! user *
//!   keep \buser={user}\b
//!   replace card=\S+ => card=[redacted]
//! ```
//!
//! Under a `[file PATH]` header, each `user` line starts a block for the users it names. The first
//! block that names the calling user decides what that user gets; a user no block names is denied.
//! A file with no `[file]` section is not touched at all.

use std::collections::BTreeMap;

use crate::view::CompiledView;

/// Who a cage is, as far as the policy is concerned.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Identity {
    pub name: String,
    pub uid: Option<u32>,
}

/// What one `user` block grants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Grant {
    /// The real file, unchanged.
    Raw,
    /// No access.
    Deny,
    /// A filtered and rewritten copy.
    View(ViewSpec),
}

/// A view before `{user}` and `{uid}` are filled in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ViewSpec {
    pub keep: Vec<String>,
    pub drop: Vec<String>,
    pub replace: Vec<(String, String)>,
    pub writable: bool,
}

#[derive(Clone, Debug)]
pub struct UserBlock {
    /// User names, numeric uids, or `*`.
    pub users: Vec<String>,
    pub grant: Grant,
}

#[derive(Clone, Debug)]
pub struct FileRule {
    pub path: String,
    pub blocks: Vec<UserBlock>,
}

#[derive(Clone, Debug, Default)]
pub struct Policy {
    pub users: BTreeMap<u32, String>,
    pub files: Vec<FileRule>,
}

impl Policy {
    pub fn parse(text: &str) -> Result<Policy, String> {
        Parser::default().run(text)
    }

    /// The identity for an effective uid: its name from `[users]`, or the number itself.
    pub fn identity_for_uid(&self, uid: u32) -> Identity {
        let name = self
            .users
            .get(&uid)
            .cloned()
            .unwrap_or_else(|| uid.to_string());
        Identity {
            name,
            uid: Some(uid),
        }
    }

    /// The identity for a name given on the command line.
    pub fn identity_for_name(&self, name: &str) -> Identity {
        let uid = self
            .users
            .iter()
            .find(|(_, n)| n.as_str() == name)
            .map(|(uid, _)| *uid);
        Identity {
            name: name.to_string(),
            uid,
        }
    }
}

impl FileRule {
    /// The grant of the first block that names `who`. A user no block names is denied.
    pub fn grant_for(&self, who: &Identity) -> (usize, &Grant) {
        for (i, block) in self.blocks.iter().enumerate() {
            if block.users.iter().any(|u| user_matches(u, who)) {
                return (i, &block.grant);
            }
        }
        (usize::MAX, &Grant::Deny)
    }
}

fn user_matches(entry: &str, who: &Identity) -> bool {
    if entry == "*" || entry == who.name {
        return true;
    }
    match (entry.parse::<u32>(), who.uid) {
        (Ok(n), Some(uid)) => n == uid,
        _ => false,
    }
}

impl ViewSpec {
    /// Fill in the placeholders for `who` and compile the patterns.
    pub fn compile(&self, who: &Identity) -> Result<CompiledView, String> {
        let uid = who.uid.map(|u| u.to_string()).unwrap_or_default();
        let in_pattern = |s: &str| {
            s.replace("{user}", &regex::escape(&who.name))
                .replace("{uid}", &uid)
        };
        // In a replacement `$` starts a group reference, so a name is inserted with `$` doubled.
        let in_replacement = |s: &str| {
            s.replace("{user}", &who.name.replace('$', "$$"))
                .replace("{uid}", &uid)
        };
        CompiledView::new(
            &self.keep.iter().map(|p| in_pattern(p)).collect::<Vec<_>>(),
            &self.drop.iter().map(|p| in_pattern(p)).collect::<Vec<_>>(),
            &self
                .replace
                .iter()
                .map(|(p, r)| (in_pattern(p), in_replacement(r)))
                .collect::<Vec<_>>(),
            self.writable,
        )
    }
}

#[derive(Default)]
struct Parser {
    policy: Policy,
    section: Section,
    /// The `user` block being filled, with the directives seen so far.
    block: Option<PendingBlock>,
}

#[derive(Default, PartialEq)]
enum Section {
    #[default]
    None,
    Users,
    File,
}

struct PendingBlock {
    users: Vec<String>,
    /// Line of the `user` header, for error messages.
    line: usize,
    raw: bool,
    deny: bool,
    readonly: bool,
    view: ViewSpec,
}

impl Parser {
    fn run(mut self, text: &str) -> Result<Policy, String> {
        for (i, line) in text.lines().enumerate() {
            let n = i + 1;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            self.line(line).map_err(|e| format!("line {n}: {e}"))?;
            if let Some(block) = &mut self.block {
                if block.line == 0 {
                    block.line = n;
                }
            }
        }
        self.end_block()?;
        for file in &self.policy.files {
            if file.blocks.is_empty() {
                return Err(format!("[file {}] has no user blocks", file.path));
            }
        }
        Ok(self.policy)
    }

    fn line(&mut self, line: &str) -> Result<(), String> {
        if let Some(header) = line.strip_prefix('[') {
            let header = header
                .strip_suffix(']')
                .ok_or("section header is missing its closing ]")?
                .trim();
            self.end_block()?;
            if header == "users" {
                self.section = Section::Users;
            } else if let Some(path) = header.strip_prefix("file ") {
                let path = path.trim();
                if !path.starts_with('/') {
                    return Err(format!("file path must be absolute: {path}"));
                }
                if self.policy.files.iter().any(|f| f.path == path) {
                    return Err(format!("more than one [file {path}] section"));
                }
                self.policy.files.push(FileRule {
                    path: path.to_string(),
                    blocks: Vec::new(),
                });
                self.section = Section::File;
            } else {
                return Err(format!("unknown section [{header}]"));
            }
            return Ok(());
        }

        match self.section {
            Section::None => Err("expected [users] or [file PATH] before this line".into()),
            Section::Users => {
                let (uid, name) = line.split_once('=').ok_or("expected UID = NAME")?;
                let uid: u32 = uid
                    .trim()
                    .parse()
                    .map_err(|_| format!("not a uid: {}", uid.trim()))?;
                let name = name.trim();
                if name.is_empty() || name == "*" || name.parse::<u32>().is_ok() {
                    return Err(format!("not a usable user name: {name:?}"));
                }
                if self.policy.users.insert(uid, name.to_string()).is_some() {
                    return Err(format!("uid {uid} is listed twice"));
                }
                Ok(())
            }
            Section::File => self.file_line(line),
        }
    }

    fn file_line(&mut self, line: &str) -> Result<(), String> {
        let (word, rest) = match line.split_once(char::is_whitespace) {
            Some((w, r)) => (w, r.trim()),
            None => (line, ""),
        };

        if word == "user" {
            self.end_block()?;
            let users: Vec<String> = rest
                .split(',')
                .map(|u| u.trim().to_string())
                .filter(|u| !u.is_empty())
                .collect();
            if users.is_empty() {
                return Err("`user` needs a name, a uid, or *".into());
            }
            self.block = Some(PendingBlock {
                users,
                line: 0,
                raw: false,
                deny: false,
                readonly: false,
                view: ViewSpec::default(),
            });
            return Ok(());
        }

        let block = self
            .block
            .as_mut()
            .ok_or("expected a `user` line before this directive")?;
        let need_pattern = |what: &str| -> Result<String, String> {
            if rest.is_empty() {
                Err(format!("`{what}` needs a pattern"))
            } else {
                Ok(rest.to_string())
            }
        };
        let no_argument = |what: &str| -> Result<(), String> {
            if rest.is_empty() {
                Ok(())
            } else {
                Err(format!("`{what}` takes no argument"))
            }
        };
        match word {
            "raw" => {
                no_argument("raw")?;
                block.raw = true;
            }
            "deny" => {
                no_argument("deny")?;
                block.deny = true;
            }
            "readonly" => {
                no_argument("readonly")?;
                block.readonly = true;
            }
            "write" => {
                no_argument("write")?;
                block.view.writable = true;
            }
            "keep" => block.view.keep.push(need_pattern("keep")?),
            "drop" => block.view.drop.push(need_pattern("drop")?),
            "replace" => {
                // `PATTERN => REPLACEMENT`; an empty replacement deletes the match.
                let (pattern, replacement) = match rest.rsplit_once(" => ") {
                    Some((p, r)) => (p.trim(), r.trim()),
                    None => match rest.strip_suffix(" =>") {
                        Some(p) => (p.trim(), ""),
                        None => return Err("expected `replace PATTERN => REPLACEMENT`".into()),
                    },
                };
                if pattern.is_empty() {
                    return Err("`replace` needs a pattern".into());
                }
                block
                    .view
                    .replace
                    .push((pattern.to_string(), replacement.to_string()));
            }
            other => return Err(format!("unknown directive `{other}`")),
        }
        Ok(())
    }

    fn end_block(&mut self) -> Result<(), String> {
        let Some(block) = self.block.take() else {
            return Ok(());
        };
        let at = format!("user block at line {}", block.line);
        let v = &block.view;
        let has_view = !v.keep.is_empty() || !v.drop.is_empty() || !v.replace.is_empty();
        let grant = if block.raw || block.deny {
            if (block.raw && block.deny) || has_view || v.writable || block.readonly {
                return Err(format!("{at}: `raw` and `deny` stand alone"));
            }
            if block.raw { Grant::Raw } else { Grant::Deny }
        } else {
            if !has_view && !v.writable && !block.readonly {
                return Err(format!(
                    "{at}: no directives (use raw, deny, readonly, keep, drop, replace or write)"
                ));
            }
            if block.readonly && v.writable {
                return Err(format!("{at}: both `readonly` and `write`"));
            }
            if v.writable && !v.replace.is_empty() {
                // What the user writes replaces their lines in the real file. Text that `replace`
                // rewrote on the way out cannot be put back.
                return Err(format!("{at}: `write` cannot be combined with `replace`"));
            }
            // Catch a bad pattern when the policy loads, not at the first open.
            let probe = Identity {
                name: "user".into(),
                uid: Some(0),
            };
            v.compile(&probe).map_err(|e| format!("{at}: {e}"))?;
            Grant::View(v.clone())
        };
        let file = self
            .policy
            .files
            .last_mut()
            .expect("a user block is always inside a [file] section");
        file.blocks.push(UserBlock {
            users: block.users,
            grant,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHADOW: &str = "
# comment
[users]
0 = root
1000 = alice

[file /etc/shadow]
user root
  raw
user mallory
  deny
user *
  keep ^{user}:
  write

[file /var/log/pay.log]
user support, 2000
  replace \\b(\\d{4})-\\d{4}-(\\d{4})\\b => $1-****-$2
  replace secret =>
user guest
  readonly
";

    fn id(name: &str, uid: Option<u32>) -> Identity {
        Identity {
            name: name.into(),
            uid,
        }
    }

    #[test]
    fn parses_users_and_files() {
        let p = Policy::parse(SHADOW).unwrap();
        assert_eq!(p.users.get(&1000).map(String::as_str), Some("alice"));
        assert_eq!(p.files.len(), 2);
        assert_eq!(p.files[0].path, "/etc/shadow");
        assert_eq!(p.files[0].blocks.len(), 3);
        assert_eq!(p.files[1].blocks[0].users, vec!["support", "2000"]);
    }

    #[test]
    fn first_matching_block_wins_and_unknown_users_are_denied() {
        let p = Policy::parse(SHADOW).unwrap();
        let shadow = &p.files[0];
        assert_eq!(shadow.grant_for(&id("root", Some(0))).1, &Grant::Raw);
        assert_eq!(shadow.grant_for(&id("mallory", None)).1, &Grant::Deny);
        assert!(matches!(
            shadow.grant_for(&id("alice", Some(1000))).1,
            Grant::View(v) if v.writable && v.keep == ["^{user}:"]
        ));

        let log = &p.files[1];
        // Named by uid.
        assert!(matches!(
            log.grant_for(&id("2000", Some(2000))).1,
            Grant::View(_)
        ));
        assert_eq!(log.grant_for(&id("bob", Some(7))).1, &Grant::Deny);
    }

    #[test]
    fn identities() {
        let p = Policy::parse(SHADOW).unwrap();
        assert_eq!(p.identity_for_uid(1000), id("alice", Some(1000)));
        assert_eq!(p.identity_for_uid(42), id("42", Some(42)));
        assert_eq!(p.identity_for_name("alice"), id("alice", Some(1000)));
        assert_eq!(p.identity_for_name("carol"), id("carol", None));
    }

    #[test]
    fn replace_forms() {
        let p = Policy::parse(SHADOW).unwrap();
        let Grant::View(v) = &p.files[1].blocks[0].grant else {
            panic!()
        };
        assert_eq!(v.replace[0].1, "$1-****-$2");
        assert_eq!(v.replace[1], ("secret".to_string(), String::new()));
    }

    #[test]
    fn user_name_is_escaped_in_patterns() {
        let spec = ViewSpec {
            keep: vec!["^{user}:".into()],
            ..Default::default()
        };
        // A name is matched as text, so `.` in it does not match any character.
        let view = spec.compile(&id("a.b", None)).unwrap();
        assert!(view.visible(b"a.b:x"));
        assert!(!view.visible(b"axb:x"));
    }

    /// The policy and fixtures of the grate's own test suite (`test/`), rendered for the users
    /// those tests run as. `test/uvg_redact_test.c` expects exactly this text.
    #[test]
    fn test_suite_policy_and_fixtures() {
        let p = Policy::parse(include_str!("../test/uvg_test.conf")).unwrap();
        let render = |path: &str, who: &Identity, raw: &[u8]| -> Vec<u8> {
            let rule = p.files.iter().find(|f| f.path == path).unwrap();
            match rule.grant_for(who).1 {
                Grant::View(spec) => spec.compile(who).unwrap().render(raw),
                other => panic!("{path}: {other:?}"),
            }
        };
        let support = id("support", None);

        let log = render(
            "/uvg_payments.log",
            &support,
            include_bytes!("../test/uvg_payments.log"),
        );
        assert_eq!(
            String::from_utf8(log).unwrap(),
            "2026-11-20T10:00:01 INFO charge user=alice card=4111-****-****-1111 amount=12.50 token=[redacted]\n\
             2026-11-20T10:00:03 INFO refund user=bob card=5500-****-****-0004 amount=3.00 token=[redacted]\n\
             2026-11-20T10:00:04 WARN declined user=carol card=3400-****-****-0009\n"
        );

        let invoices = render(
            "/uvg_invoices.csv",
            &support,
            include_bytes!("../test/uvg_invoices.csv"),
        );
        assert_eq!(
            String::from_utf8(invoices).unwrap(),
            "id,-,amount,-\n1001,-,1200.00,-\n1002,-,89.90,-\n"
        );

        let shadow = include_bytes!("../test/uvg_shadow");
        assert_eq!(
            render("/uvg_shadow", &id("alice", None), shadow),
            b"alice:$6$alicesalt$alicehash:19500:0:99999:7:::\n"
        );
        let by_uid = render(
            "/uvg_uid",
            &p.identity_for_uid(4000002),
            include_bytes!("../test/uvg_uid"),
        );
        assert_eq!(by_uid, b"4000002:a line for uid 4000002\n");

        let grant = |path: &str, who: &Identity| {
            let rule = p.files.iter().find(|f| f.path == path).unwrap();
            rule.grant_for(who).1.clone()
        };
        assert_eq!(grant("/uvg_secret", &support), Grant::Deny);
        assert_eq!(grant("/uvg_audit.log", &support), Grant::Deny);
        assert_eq!(grant("/uvg_shadow", &id("root", None)), Grant::Raw);
        assert!(matches!(grant("/uvg_notes", &support), Grant::View(v) if !v.writable));
    }

    #[test]
    fn rejects_bad_policies() {
        let bad = [
            ("keep x", "expected [users] or [file PATH]"),
            ("[file rel/path]\nuser *\nraw", "must be absolute"),
            ("[file /a]\nkeep x", "expected a `user` line"),
            ("[file /a]\nuser *", "no directives"),
            ("[file /a]\nuser *\nraw\nkeep x", "stand alone"),
            (
                "[file /a]\nuser *\nwrite\nreplace a => b",
                "cannot be combined",
            ),
            ("[file /a]\nuser *\nkeep (", "user block at line 2"),
            ("[file /a]\nuser *\nfrobnicate", "unknown directive"),
            ("[file /a]", "has no user blocks"),
            ("[file /a]\nuser *\nraw\n[file /a]\nuser *\nraw", "more than one"),
            ("[users]\nabc = x", "not a uid"),
            ("[users]\n1 = 2", "not a usable user name"),
            ("[file /a]\nuser *\nreplace a", "expected `replace"),
            ("[file /a]\nuser *\nreadonly\nwrite", "both"),
        ];
        for (text, want) in bad {
            let err = Policy::parse(text).unwrap_err();
            assert!(err.contains(want), "{text:?}: got {err:?}, want {want:?}");
        }
    }
}
