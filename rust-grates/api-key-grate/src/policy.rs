//! The policy file: which keys there are, where each comes from, and where each may go.
//!
//! ```text
//! [key openai]
//! file /run/keys/openai        # the key is this file's content
//! env OPENAI_API_KEY           # the program finds the placeholder here
//! allow 162.159.140.245:443    # the placeholder becomes the key on the way here
//! allow 10.0.0.0/8:*
//! allow [2606:4700::]/32:443
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// An address a key may be sent to: a network and a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dest {
    net: IpAddr,
    prefix: u8,
    /// `None`: any port.
    port: Option<u16>,
}

/// An IPv4 address written as IPv6 (`::ffff:1.2.3.4`) is that IPv4 address.
fn canonical(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => addr,
        },
        v4 => v4,
    }
}

fn masked(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(a) => {
            let mask = u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask))
        }
        IpAddr::V6(a) => {
            let mask = u128::MAX.checked_shl(128 - prefix as u32).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask))
        }
    }
}

impl Dest {
    /// `ADDRESS[/BITS]:PORT`, with an IPv6 address in brackets and `*` for any port.
    pub fn parse(text: &str) -> Result<Dest, String> {
        let form = "expected ADDRESS:PORT, ADDRESS/BITS:PORT or [IPV6]:PORT";
        let (addr_text, rest) = match text.strip_prefix('[') {
            Some(inner) => inner.split_once(']').ok_or(form)?,
            None => text.split_at(text.find(['/', ':']).unwrap_or(text.len())),
        };
        let addr: IpAddr = addr_text.parse().map_err(|_| {
            format!("`{addr_text}` is not an IP address (host names are not resolved)")
        })?;
        if addr.is_ipv6() && !text.starts_with('[') {
            return Err(form.into());
        }
        let (bits_text, port_text) = match rest.strip_prefix('/') {
            Some(rest) => {
                let (bits, port) = rest.split_once(':').ok_or(form)?;
                (Some(bits), port)
            }
            None => (None, rest.strip_prefix(':').ok_or(form)?),
        };
        let width = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match bits_text {
            Some(bits) => bits
                .parse::<u8>()
                .ok()
                .filter(|b| *b <= width)
                .ok_or(format!("`/{bits}` is not a prefix length up to {width}"))?,
            None => width,
        };
        let port = match port_text {
            "*" => None,
            p => Some(
                p.parse::<u16>()
                    .ok()
                    .filter(|p| *p != 0)
                    .ok_or(format!("`{p}` is not a port (1-65535, or * for any)"))?,
            ),
        };
        let addr = if prefix == width {
            canonical(addr)
        } else {
            addr
        };
        let prefix = if addr.is_ipv4() {
            prefix.min(32)
        } else {
            prefix
        };
        Ok(Dest {
            net: masked(addr, prefix),
            prefix,
            port,
        })
    }

    pub fn matches(&self, addr: IpAddr, port: u16) -> bool {
        let addr = canonical(addr);
        if addr.is_ipv4() != self.net.is_ipv4() {
            return false;
        }
        masked(addr, self.prefix) == self.net && self.port.is_none_or(|p| p == port)
    }
}

/// The address and port in a `sockaddr_in` or `sockaddr_in6`. `None` for any other family.
pub fn parse_sockaddr(bytes: &[u8]) -> Option<(IpAddr, u16)> {
    let family = u16::from_ne_bytes(bytes.get(0..2)?.try_into().ok()?);
    let port = u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?);
    match family {
        AF_INET => {
            let a: [u8; 4] = bytes.get(4..8)?.try_into().ok()?;
            Some((IpAddr::V4(Ipv4Addr::from(a)), port))
        }
        AF_INET6 => {
            let a: [u8; 16] = bytes.get(8..24)?.try_into().ok()?;
            Some((canonical(IpAddr::V6(Ipv6Addr::from(a))), port))
        }
        _ => None,
    }
}

/// One `[key NAME]` section.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyRule {
    pub name: String,
    /// The file holding the key. Without one the key is taken from the environment.
    pub file: Option<String>,
    /// Variables the program is started with, set to the placeholder. When there is no `file`,
    /// the first is also where the grate finds the key.
    pub env: Vec<String>,
    pub allow: Vec<Dest>,
}

impl KeyRule {
    pub fn allows(&self, addr: IpAddr, port: u16) -> bool {
        self.allow.iter().any(|d| d.matches(addr, port))
    }
}

#[derive(Debug, Default)]
pub struct Policy {
    pub keys: Vec<KeyRule>,
}

fn is_name(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn is_env_name(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

impl Policy {
    pub fn parse(text: &str) -> Result<Policy, String> {
        let mut policy = Policy::default();
        for (number, raw) in text.lines().enumerate() {
            let at = |msg: String| format!("line {}: {msg}", number + 1);
            // A comment is a line starting with #, or the rest of a line after " #".
            let line = raw
                .split(" #")
                .next()
                .unwrap_or("")
                .split("\t#")
                .next()
                .unwrap_or("");
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(header) = line.strip_prefix('[') {
                let name = header
                    .strip_suffix(']')
                    .and_then(|h| h.trim().strip_prefix("key"))
                    .map(str::trim)
                    .filter(|n| is_name(n))
                    .ok_or_else(|| at("expected [key NAME]".into()))?;
                if policy.keys.iter().any(|k| k.name == name) {
                    return Err(at(format!("key {name} is defined twice")));
                }
                policy.keys.push(KeyRule {
                    name: name.to_string(),
                    file: None,
                    env: Vec::new(),
                    allow: Vec::new(),
                });
                continue;
            }

            let (word, value) = match line.split_once(char::is_whitespace) {
                Some((word, value)) => (word, value.trim()),
                None => (line, ""),
            };
            // Every use is checked against the keys before this one as well as this one.
            let (earlier, key) = match policy.keys.split_last_mut() {
                Some((key, earlier)) => (earlier, key),
                None => return Err(at("expected [key NAME] first".into())),
            };
            match word {
                "file" => {
                    if !value.starts_with('/') {
                        return Err(at("file needs an absolute path".into()));
                    }
                    if key.file.is_some() {
                        return Err(at(format!("key {} already has a file", key.name)));
                    }
                    if earlier.iter().any(|k| k.file.as_deref() == Some(value)) {
                        return Err(at(format!("{value} is already another key's file")));
                    }
                    key.file = Some(value.to_string());
                }
                "env" => {
                    if !is_env_name(value) {
                        return Err(at(format!("`{value}` is not a variable name")));
                    }
                    if earlier
                        .iter()
                        .chain([&*key])
                        .any(|k| k.env.iter().any(|e| e == value))
                    {
                        return Err(at(format!("{value} is used twice")));
                    }
                    key.env.push(value.to_string());
                }
                "allow" => key.allow.push(Dest::parse(value).map_err(at)?),
                other => return Err(at(format!("unknown directive `{other}`"))),
            }
        }

        if policy.keys.is_empty() {
            return Err("no [key NAME] section".into());
        }
        for key in &policy.keys {
            if key.file.is_none() && key.env.is_empty() {
                return Err(format!(
                    "key {}: needs `file PATH` or `env NAME` to say where the key is",
                    key.name
                ));
            }
            if key.allow.is_empty() {
                return Err(format!(
                    "key {}: needs at least one `allow ADDRESS:PORT`",
                    key.name
                ));
            }
        }
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn destinations() {
        let one = Dest::parse("127.0.0.1:8080").unwrap();
        assert!(one.matches(v4(127, 0, 0, 1), 8080));
        assert!(!one.matches(v4(127, 0, 0, 1), 8081));
        assert!(!one.matches(v4(127, 0, 0, 2), 8080));

        let net = Dest::parse("10.1.2.3/8:*").unwrap();
        assert!(net.matches(v4(10, 200, 0, 9), 1));
        assert!(net.matches(v4(10, 0, 0, 0), 65535));
        assert!(!net.matches(v4(11, 0, 0, 0), 443));

        let all = Dest::parse("0.0.0.0/0:443").unwrap();
        assert!(all.matches(v4(8, 8, 8, 8), 443));
        assert!(!all.matches("::1".parse().unwrap(), 443));

        let six = Dest::parse("[2606:4700::]/32:443").unwrap();
        assert!(six.matches("2606:4700:1::5".parse().unwrap(), 443));
        assert!(!six.matches("2606:4701::5".parse().unwrap(), 443));
        assert!(
            Dest::parse("[::1]:80")
                .unwrap()
                .matches("::1".parse().unwrap(), 80)
        );
    }

    #[test]
    fn an_ipv4_address_inside_ipv6_is_that_ipv4_address() {
        let rule = Dest::parse("192.0.2.7:443").unwrap();
        assert!(rule.matches("::ffff:192.0.2.7".parse().unwrap(), 443));
        let rule = Dest::parse("[::ffff:192.0.2.7]:443").unwrap();
        assert!(rule.matches(v4(192, 0, 2, 7), 443));
    }

    #[test]
    fn bad_destinations() {
        for bad in [
            "",
            "127.0.0.1",
            "127.0.0.1:",
            "127.0.0.1:0",
            "127.0.0.1:70000",
            "127.0.0.1/33:80",
            "api.example.com:443",
            "::1:80",
            "[::1]",
            "[::1]/129:80",
            "[::1:80",
        ] {
            assert!(Dest::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn socket_addresses() {
        let mut v4_bytes = vec![2, 0, 0x1f, 0x90, 127, 0, 0, 1];
        v4_bytes.extend([0; 8]);
        assert_eq!(parse_sockaddr(&v4_bytes), Some((v4(127, 0, 0, 1), 8080)));

        let mut v6_bytes = vec![10, 0, 0x01, 0xbb, 0, 0, 0, 0];
        v6_bytes.extend(Ipv6Addr::LOCALHOST.octets());
        v6_bytes.extend([0; 4]);
        assert_eq!(
            parse_sockaddr(&v6_bytes),
            Some((IpAddr::V6(Ipv6Addr::LOCALHOST), 443))
        );

        // AF_UNIX, AF_UNSPEC and anything cut short are not addresses a key can go to.
        assert_eq!(parse_sockaddr(&[1, 0, b'/', b't', b'm', b'p', 0, 0]), None);
        assert_eq!(parse_sockaddr(&[0, 0, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(parse_sockaddr(&[2, 0, 0x1f]), None);
        assert_eq!(parse_sockaddr(&v6_bytes[..20]), None);
    }

    #[test]
    fn a_policy() {
        let policy = Policy::parse(
            "# keys for the agent\n\
             [key openai]\n\
             file /run/keys/openai   # read at start\n\
             env OPENAI_API_KEY\n\
             allow 162.159.140.245:443\n\
             allow 10.0.0.0/8:*\n\
             \n\
             [ key github ]\n\
             env GITHUB_TOKEN\n\
             env GH_TOKEN\n\
             allow 140.82.112.0/20:443\n",
        )
        .unwrap();
        assert_eq!(policy.keys.len(), 2);
        let openai = &policy.keys[0];
        assert_eq!(openai.name, "openai");
        assert_eq!(openai.file.as_deref(), Some("/run/keys/openai"));
        assert_eq!(openai.env, ["OPENAI_API_KEY"]);
        assert!(openai.allows(v4(10, 9, 8, 7), 22));
        assert!(!openai.allows(v4(140, 82, 112, 3), 443));
        let github = &policy.keys[1];
        assert_eq!(github.file, None);
        assert_eq!(github.env, ["GITHUB_TOKEN", "GH_TOKEN"]);
        assert!(github.allows(v4(140, 82, 121, 3), 443));
    }

    #[test]
    fn bad_policies() {
        for (bad, why) in [
            ("", "no [key"),
            ("file /k\n", "[key NAME] first"),
            ("[secret a]\n", "expected [key NAME]"),
            ("[key a b]\n", "expected [key NAME]"),
            (
                "[key a]\nallow 1.2.3.4:5\n",
                "needs `file PATH` or `env NAME`",
            ),
            ("[key a]\nenv A\n", "at least one `allow"),
            ("[key a]\nfile k\nallow 1.2.3.4:5\n", "absolute path"),
            (
                "[key a]\nfile /k\nfile /j\nallow 1.2.3.4:5\n",
                "already has a file",
            ),
            ("[key a]\nenv 1A\nallow 1.2.3.4:5\n", "not a variable name"),
            ("[key a]\nenv A\nenv A\nallow 1.2.3.4:5\n", "used twice"),
            ("[key a]\nenv A\nallow host:5\n", "not an IP address"),
            (
                "[key a]\nenv A\nallow 1.2.3.4:5\nsend 1\n",
                "unknown directive",
            ),
            (
                "[key a]\nenv A\nallow 1.2.3.4:5\n[key a]\nenv B\nallow 1.2.3.4:5\n",
                "defined twice",
            ),
            (
                "[key a]\nenv A\nallow 1.2.3.4:5\n[key b]\nenv A\nallow 1.2.3.4:5\n",
                "used twice",
            ),
            (
                "[key a]\nfile /k\nallow 1.2.3.4:5\n[key b]\nfile /k\nallow 1.2.3.4:5\n",
                "already another key's file",
            ),
        ] {
            let err = Policy::parse(bad).unwrap_err();
            assert!(err.contains(why), "{bad:?}: {err}");
        }
        assert!(
            Policy::parse("[key a]\nenv A\nallow 1.2.3.4:5\nbogus\n")
                .unwrap_err()
                .starts_with("line 4:")
        );
    }
}
