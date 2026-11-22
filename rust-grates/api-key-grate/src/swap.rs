//! Keys, their placeholders, and trading one for the other in a stream of bytes.
//!
//! A placeholder has the same length as its key, so trading them never moves or resizes
//! anything: a byte count the program was told is the byte count that went out, and a
//! `Content-Length` written for the placeholder is right for the key.
//!
//! Going out, a placeholder becomes the key ([`Outbound`]). Coming in, the key becomes the
//! placeholder ([`Inbound`]). The two directions fail in different ways and are built
//! differently for it: a placeholder that is missed goes out as a placeholder, which is
//! harmless, but a key that is missed has been read by the program.

/// How many leading characters of a key its placeholder keeps.
pub const KEEP: usize = 4;
pub const MIN_KEY: usize = 16;
pub const MAX_KEY: usize = 4096;
/// A placeholder needs at least this many random characters to be one of a kind.
pub const MIN_RANDOM: usize = 12;

pub struct Secret {
    pub name: String,
    key: Vec<u8>,
    placeholder: Vec<u8>,
    /// For each prefix of the key, the length of its longest proper prefix that is also its
    /// suffix (the Knuth-Morris-Pratt table).
    fail: Vec<usize>,
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the key.
        write!(f, "Secret({})", self.name)
    }
}

fn randomized(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

impl Secret {
    /// Make the placeholder for `key`. `below(n)` returns a uniform random number under `n`.
    ///
    /// The placeholder keeps the key's first [`KEEP`] characters and its shape: a letter stays a
    /// letter of the same case, a digit a digit, and anything else stays as it is. Code that
    /// checks what a key looks like accepts it.
    pub fn new(
        name: &str,
        key: &[u8],
        mut below: impl FnMut(u32) -> u32,
    ) -> Result<Secret, String> {
        if key.len() < MIN_KEY || key.len() > MAX_KEY {
            return Err(format!(
                "a key is {MIN_KEY} to {MAX_KEY} characters, this one is {}",
                key.len()
            ));
        }
        if !key.iter().all(u8::is_ascii_graphic) {
            return Err("a key is printable ASCII with no spaces".into());
        }
        if key[KEEP..].iter().filter(|b| randomized(**b)).count() < MIN_RANDOM {
            return Err(format!(
                "a key needs {MIN_RANDOM} letters or digits after its first {KEEP} characters"
            ));
        }

        let mut placeholder = key.to_vec();
        while placeholder == key {
            for (p, k) in placeholder[KEEP..].iter_mut().zip(&key[KEEP..]) {
                *p = match k {
                    b'0'..=b'9' => b'0' + below(10) as u8,
                    b'a'..=b'z' => b'a' + below(26) as u8,
                    b'A'..=b'Z' => b'A' + below(26) as u8,
                    other => *other,
                };
            }
        }

        let mut fail = vec![0; key.len()];
        let mut k = 0;
        for i in 1..key.len() {
            while k > 0 && key[i] != key[k] {
                k = fail[k - 1];
            }
            if key[i] == key[k] {
                k += 1;
            }
            fail[i] = k;
        }

        Ok(Secret {
            name: name.to_string(),
            key: key.to_vec(),
            placeholder,
            fail,
        })
    }

    pub fn placeholder(&self) -> &[u8] {
        &self.placeholder
    }

    pub fn len(&self) -> usize {
        self.key.len()
    }
}

/// The key in a key file or an environment variable: the content without its line ending.
pub fn key_text(content: &[u8]) -> &[u8] {
    let content = content.strip_suffix(b"\n").unwrap_or(content);
    content.strip_suffix(b"\r").unwrap_or(content)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// A stretch of outgoing data where a placeholder was replaced by its key.
#[derive(Debug, Clone, PartialEq)]
pub struct Region {
    /// Where in the data the stretch starts.
    pos: usize,
    secret: usize,
    /// Which byte of the secret is at `pos`: not 0 when the secret started in an earlier write.
    from: usize,
}

/// One connection's outgoing direction.
#[derive(Debug, Default)]
pub struct Outbound {
    /// A key that was cut off by a short write: (secret, how much of it went out). The program
    /// will send the rest of the placeholder next, and the rest of the key goes in its place.
    carry: Option<(usize, usize)>,
}

impl Outbound {
    /// Replace, in `data`, the placeholder of every secret in `active` by its key. `data` is
    /// what the program wants to send next. Returns what was replaced, for [`Outbound::sent`].
    ///
    /// A placeholder is recognized only when it lies whole within one call's data (or continues
    /// one cut off by a short write). One that the program splits over two writes goes out
    /// unchanged.
    pub fn rewrite(&self, secrets: &[Secret], active: &[usize], data: &mut [u8]) -> Vec<Region> {
        let mut regions = Vec::new();
        let mut start = 0;
        if let Some((secret, from)) = self.carry {
            let rest = &secrets[secret].placeholder[from..];
            let n = rest.len().min(data.len());
            if active.contains(&secret) && n > 0 && data[..n] == rest[..n] {
                regions.push(Region {
                    pos: 0,
                    secret,
                    from,
                });
                start = n;
            }
        }
        for &secret in active {
            let placeholder = &secrets[secret].placeholder;
            let mut at = start;
            while let Some(found) = data.get(at..).and_then(|d| find(d, placeholder)) {
                regions.push(Region {
                    pos: at + found,
                    secret,
                    from: 0,
                });
                at += found + placeholder.len();
            }
        }
        // Placeholders are found in what the program sent, so one cannot be made by replacing
        // another. Two that overlap (they are random, so they do not) keep only the first.
        regions.sort_by_key(|r| r.pos);
        let mut end = 0;
        regions.retain(|r| {
            let keep = r.pos >= end;
            if keep {
                end = r.pos + secrets[r.secret].len() - r.from;
            }
            keep
        });
        for r in &regions {
            let key = &secrets[r.secret].key[r.from..];
            let n = key.len().min(data.len() - r.pos);
            data[r.pos..r.pos + n].copy_from_slice(&key[..n]);
        }
        regions
    }

    /// The first `n` bytes of the data last rewritten went out.
    pub fn sent(&mut self, secrets: &[Secret], regions: &[Region], n: usize) {
        if n == 0 {
            // Nothing moved: whatever was cut off still is.
            return;
        }
        self.carry = regions.iter().find_map(|r| {
            let end = r.pos + secrets[r.secret].len() - r.from;
            (r.pos < n && n < end).then(|| (r.secret, r.from + n - r.pos))
        });
    }

    /// How many bytes to leave off the end of `chunk` so that it does not end partway through a
    /// placeholder. For data sent in pieces, when more follows this chunk.
    pub fn trim(secrets: &[Secret], active: &[usize], chunk: &[u8]) -> usize {
        active
            .iter()
            .map(|&s| {
                let placeholder = &secrets[s].placeholder;
                let longest = (placeholder.len() - 1).min(chunk.len());
                (1..=longest)
                    .rev()
                    .find(|&n| chunk.ends_with(&placeholder[..n]))
                    .unwrap_or(0)
            })
            .max()
            .unwrap_or(0)
    }
}

/// One connection's incoming direction: for each secret, how much of its key the stream
/// currently ends with.
#[derive(Debug, Clone, Default)]
pub struct Inbound {
    matched: Vec<usize>,
}

impl Inbound {
    /// Replace every key in `data`, the next bytes of the stream, by its placeholder.
    ///
    /// A key can arrive split over two reads, and the first part cannot be held back until the
    /// second arrives: a reply that merely ends with the first letters of a key would never be
    /// delivered. So when data ends with the start of a key, that start is delivered as the
    /// start of the placeholder at once. If the key then continues, so does the placeholder,
    /// and the program has seen none of it. If it does not continue, a few bytes of the reply
    /// read as placeholder instead of what was sent; with [`KEEP`] characters shared, that takes
    /// a reply ending in a longer start of the key than that, which only something sending
    /// the key itself does.
    pub fn redact(&mut self, secrets: &[Secret], data: &mut [u8]) {
        self.matched.resize(secrets.len(), 0);
        let raw = data.to_vec();
        for (secret, k) in secrets.iter().zip(&mut self.matched) {
            let (key, len) = (&secret.key, secret.key.len());
            let cover = |data: &mut [u8], end: usize, matched: usize| {
                // The last `matched` bytes up to `end` are the first `matched` of the key.
                let shown = matched.min(end);
                data[end - shown..end]
                    .copy_from_slice(&secret.placeholder[matched - shown..matched]);
            };
            for (i, &b) in raw.iter().enumerate() {
                while *k > 0 && (*k == len || key[*k] != b) {
                    *k = secret.fail[*k - 1];
                }
                if key[*k] == b {
                    *k += 1;
                }
                if *k == len {
                    cover(data, i + 1, len);
                }
            }
            if *k < len {
                cover(data, raw.len(), *k);
            }
        }
    }
}

/// `data` with every key replaced by its placeholder: what a program may see of a file.
pub fn hide(secrets: &[Secret], data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    Inbound::default().redact(secrets, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"sk-test-4f9a8B7c6D5e4F3a2b1c0d9e";

    /// A small deterministic generator, so tests do not depend on a source of randomness.
    struct Rng(u64);
    impl Rng {
        fn below(&mut self, n: u32) -> u32 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % n as u64) as u32
        }
    }

    fn secret(name: &str, key: &[u8], seed: u64) -> Secret {
        let mut rng = Rng(seed);
        Secret::new(name, key, |n| rng.below(n)).unwrap()
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        find(haystack, needle).is_some()
    }

    #[test]
    fn placeholder_keeps_length_start_and_shape() {
        let s = secret("demo", KEY, 7);
        let p = s.placeholder();
        assert_eq!(p.len(), KEY.len());
        assert_eq!(p[..KEEP], KEY[..KEEP]);
        assert_ne!(p, KEY);
        for (a, b) in p.iter().zip(KEY) {
            assert_eq!(a.is_ascii_digit(), b.is_ascii_digit());
            assert_eq!(a.is_ascii_lowercase(), b.is_ascii_lowercase());
            assert_eq!(a.is_ascii_uppercase(), b.is_ascii_uppercase());
            if !b.is_ascii_alphanumeric() {
                assert_eq!(a, b);
            }
        }
        // Another draw gives another placeholder.
        assert_ne!(secret("demo", KEY, 8).placeholder(), p);
        assert_eq!(format!("{s:?}"), "Secret(demo)");
    }

    #[test]
    fn keys_that_cannot_be_hidden_are_refused() {
        let mut rng = Rng(1);
        let mut make = |key: &[u8]| Secret::new("k", key, |n| rng.below(n)).map(|_| ());
        assert!(make(b"short").is_err());
        assert!(make(b"has a space in it, long enough").is_err());
        assert!(make(b"line\nbreak-in-the-middle-0123456789").is_err());
        assert!(make(b"abcd------------------x").is_err());
        assert!(make(&vec![b'a'; MAX_KEY + 1]).is_err());
        assert!(make(b"0123456789abcdef").is_ok());
    }

    #[test]
    fn key_text_drops_one_line_ending() {
        assert_eq!(key_text(b"abc\n"), b"abc");
        assert_eq!(key_text(b"abc\r\n"), b"abc");
        assert_eq!(key_text(b"abc"), b"abc");
        assert_eq!(key_text(b"abc\n\n"), b"abc\n");
    }

    #[test]
    fn outbound_puts_the_key_where_the_placeholder_is() {
        let secrets = [
            secret("a", KEY, 3),
            secret("b", b"ghp_0123456789abcdefABCDEF", 4),
        ];
        let (pa, pb) = (
            secrets[0].placeholder().to_vec(),
            secrets[1].placeholder().to_vec(),
        );
        let mut data = [
            b"Authorization: Bearer ",
            &pa[..],
            b"\r\nX-Other: ",
            &pb[..],
            b" ",
            &pa[..],
        ]
        .concat();
        let before = data.len();

        // Only the secrets this connection may carry are replaced.
        let out = Outbound::default();
        let regions = out.rewrite(&secrets, &[0], &mut data);
        assert_eq!(regions.len(), 2);
        assert_eq!(data.len(), before);
        assert_eq!(
            data,
            [
                b"Authorization: Bearer ",
                KEY,
                b"\r\nX-Other: ",
                &pb[..],
                b" ",
                KEY
            ]
            .concat()
        );

        // Nothing to replace, nothing changed.
        let mut plain = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        assert!(out.rewrite(&secrets, &[0, 1], &mut plain).is_empty());
        assert_eq!(plain, b"GET / HTTP/1.1\r\n\r\n");
        // A placeholder cut short is not one.
        let mut cut = pa[..pa.len() - 1].to_vec();
        assert!(out.rewrite(&secrets, &[0], &mut cut).is_empty());
        assert_eq!(cut, pa[..pa.len() - 1]);
    }

    #[test]
    fn a_short_write_inside_a_key_is_finished_by_the_next_writes() {
        let secrets = [secret("a", KEY, 3)];
        let p = secrets[0].placeholder().to_vec();
        let message = [b"token=", &p[..], b"&x=1"].concat();
        let want = [b"token=", KEY, b"&x=1"].concat();

        // Whatever the size of each write, what goes out in the end is the message with the key.
        for step in 1..message.len() {
            let mut out = Outbound::default();
            let mut wire = Vec::new();
            let mut done = 0;
            while done < message.len() {
                // The program offers everything it has left; only `step` bytes are taken.
                let mut data = message[done..].to_vec();
                let regions = out.rewrite(&secrets, &[0], &mut data);
                let n = step.min(data.len());
                wire.extend_from_slice(&data[..n]);
                out.sent(&secrets, &regions, n);
                done += n;
            }
            assert_eq!(wire, want, "step {step}");
        }
    }

    #[test]
    fn a_cut_off_key_is_not_continued_by_other_data() {
        let secrets = [secret("a", KEY, 3)];
        let p = secrets[0].placeholder().to_vec();
        let mut out = Outbound::default();

        let mut data = p.clone();
        let regions = out.rewrite(&secrets, &[0], &mut data);
        out.sent(&secrets, &regions, 10);
        assert_eq!(out.carry, Some((0, 10)));

        // A write that sent nothing leaves things as they were.
        let mut again = p[10..].to_vec();
        let regions = out.rewrite(&secrets, &[0], &mut again);
        assert_eq!(again, KEY[10..]);
        out.sent(&secrets, &regions, 0);
        assert_eq!(out.carry, Some((0, 10)));

        // The program sends something else instead: it goes out as it is.
        let mut other = b"something else entirely".to_vec();
        let regions = out.rewrite(&secrets, &[0], &mut other);
        assert!(regions.is_empty());
        assert_eq!(other, b"something else entirely");
        out.sent(&secrets, &regions, other.len());
        assert_eq!(out.carry, None);
    }

    #[test]
    fn trim_keeps_a_placeholder_out_of_two_chunks() {
        let secrets = [secret("a", KEY, 3)];
        let p = secrets[0].placeholder().to_vec();
        assert_eq!(Outbound::trim(&secrets, &[0], b"nothing here"), 0);
        let chunk = [b"body ", &p[..9]].concat();
        assert_eq!(Outbound::trim(&secrets, &[0], &chunk), 9);
        // A whole placeholder at the end is not partway through one.
        let chunk = [b"body ", &p[..]].concat();
        assert_eq!(Outbound::trim(&secrets, &[0], &chunk), 0);
        assert_eq!(Outbound::trim(&secrets, &[], &p[..9]), 0);
    }

    #[test]
    fn inbound_hides_the_key() {
        let secrets = [
            secret("a", KEY, 3),
            secret("b", b"ghp_0123456789abcdefABCDEF", 4),
        ];
        let (pa, pb) = (secrets[0].placeholder(), secrets[1].placeholder());
        let reply = [
            b"you sent ",
            KEY,
            b" and ",
            &secrets[1].key[..],
            b", twice: ",
            KEY,
            KEY,
        ]
        .concat();
        let want = [b"you sent ", pa, b" and ", pb, b", twice: ", pa, pa].concat();
        assert_eq!(hide(&secrets, &reply), want);
        assert_eq!(hide(&secrets, b"nothing to hide"), b"nothing to hide");
    }

    #[test]
    fn inbound_hides_a_key_however_the_reads_fall() {
        let secrets = [secret("a", KEY, 3)];
        let p = secrets[0].placeholder();
        let reply = [b"HTTP/1.1 200 OK\r\n\r\nkey=", KEY, b";", KEY, b" end"].concat();
        let want = [b"HTTP/1.1 200 OK\r\n\r\nkey=", p, b";", p, b" end"].concat();

        // Two reads, split at every place.
        for cut in 0..=reply.len() {
            let mut inbound = Inbound::default();
            let (mut a, mut b) = (reply[..cut].to_vec(), reply[cut..].to_vec());
            inbound.redact(&secrets, &mut a);
            inbound.redact(&secrets, &mut b);
            assert_eq!([a, b].concat(), want, "cut at {cut}");
        }
        // Reads of every fixed size, down to one byte at a time.
        for size in 1..reply.len() {
            let mut inbound = Inbound::default();
            let mut seen = Vec::new();
            for chunk in reply.chunks(size) {
                let mut chunk = chunk.to_vec();
                inbound.redact(&secrets, &mut chunk);
                seen.extend(chunk);
            }
            // Each read handed over its part of this, so none handed over part of a key.
            assert_eq!(seen, want, "size {size}");
        }
    }

    #[test]
    fn a_reply_ending_like_a_key_reads_as_the_placeholder_there() {
        let secrets = [secret("a", KEY, 3)];
        let p = secrets[0].placeholder();
        let mut inbound = Inbound::default();

        // Ending with no more of the key than a placeholder keeps changes nothing.
        let mut short = [b"id: ", &KEY[..KEEP]].concat();
        inbound.redact(&secrets, &mut short);
        assert_eq!(short, [b"id: ", &KEY[..KEEP]].concat());
        let mut next = b" and more".to_vec();
        inbound.redact(&secrets, &mut next);
        assert_eq!(next, b" and more");

        // Ending with more of it reads as that much of the placeholder, key or not.
        let mut long = [b"id: ", &KEY[..10]].concat();
        inbound.redact(&secrets, &mut long);
        assert_eq!(long, [b"id: ", &p[..10]].concat());
        let mut next = b"... (masked)".to_vec();
        inbound.redact(&secrets, &mut next);
        assert_eq!(next, b"... (masked)");
    }

    #[test]
    fn peeking_at_data_does_not_count_as_reading_it() {
        let secrets = [secret("a", KEY, 3)];
        let p = secrets[0].placeholder();
        let mut inbound = Inbound::default();
        let mut first = KEY[..12].to_vec();
        inbound.redact(&secrets, &mut first);

        // A look at what comes next, on a copy of the state...
        let mut peeked = KEY[12..].to_vec();
        inbound.clone().redact(&secrets, &mut peeked);
        assert_eq!(peeked, p[12..]);
        // ...and then the read itself gives the same.
        let mut read = KEY[12..].to_vec();
        inbound.redact(&secrets, &mut read);
        assert_eq!(read, p[12..]);
    }

    #[test]
    fn a_key_that_repeats_itself_is_never_let_through() {
        // The key's start is also its middle, so a stream can match it in two ways at once.
        let key = b"abababababababababababab0123456789xy";
        let secrets = [secret("r", key, 5)];
        let stream = [
            b"ab".repeat(9),
            key.to_vec(),
            b"abab".to_vec(),
            key.to_vec(),
        ]
        .concat();
        for size in 1..stream.len() {
            let mut inbound = Inbound::default();
            let mut seen = Vec::new();
            for chunk in stream.chunks(size) {
                let mut chunk = chunk.to_vec();
                inbound.redact(&secrets, &mut chunk);
                seen.extend(chunk);
            }
            assert_eq!(seen.len(), stream.len());
            assert!(!contains(&seen, &key[..]), "size {size}");
            // Nor its distinctive end, which only the key itself has.
            assert!(!contains(&seen, b"0123456789xy"), "size {size}");
        }
    }

    #[test]
    fn random_streams_in_random_reads_never_show_a_key() {
        let secrets = [
            secret("a", KEY, 3),
            secret("b", b"ghp_0123456789abcdefABCDEF", 4),
        ];
        let mut rng = Rng(0x9e3779b97f4a7c15);
        for _ in 0..300 {
            // A stream of noise, keys, and keys cut short.
            let mut stream = Vec::new();
            for _ in 0..rng.below(8) + 1 {
                let key = &secrets[rng.below(2) as usize].key;
                match rng.below(4) {
                    0 => stream.extend((0..rng.below(20)).map(|_| b' ' + rng.below(90) as u8)),
                    1 => stream.extend_from_slice(&key[..rng.below(key.len() as u32) as usize]),
                    _ => stream.extend_from_slice(key),
                }
            }
            let mut inbound = Inbound::default();
            let mut seen = Vec::new();
            let mut rest = &stream[..];
            while !rest.is_empty() {
                let n = (rng.below(12) as usize + 1).min(rest.len());
                let mut chunk = rest[..n].to_vec();
                inbound.redact(&secrets, &mut chunk);
                seen.extend(chunk);
                rest = &rest[n..];
            }
            assert_eq!(seen.len(), stream.len());
            for s in &secrets {
                assert!(
                    !contains(&seen, &s.key),
                    "{:?}",
                    String::from_utf8_lossy(&stream)
                );
            }
        }
    }
}
