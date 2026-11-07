//! `.dockerignore` with Docker's semantics (moby/patternmatcher): patterns are cleaned paths relative to the context;
//! `*` and `?` stay within one path segment, `**` spans any number of segments, `[...]` is a character class, `\`
//! escapes; a later pattern wins and `!` re-includes; a path is excluded when it or one of its parent directories
//! matches. The Docker CLI applies these before sending the context; so does the agent.

pub struct Ignore {
    patterns: Vec<Pattern>,
}

struct Pattern {
    exclusion: bool,
    tokens: Vec<Token>,
}

#[derive(Debug)]
enum Token {
    Lit(u8),
    /// `?`: one byte other than `/`.
    One,
    /// `*`: any run of bytes without `/`.
    Star,
    /// `**` followed by more pattern: any number of whole segments, including none.
    Segments,
    /// `**` at the end: anything.
    Rest,
    Class {
        negated: bool,
        ranges: Vec<(u8, u8)>,
    },
}

impl Ignore {
    pub fn parse(text: &str) -> Ignore {
        let patterns = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter_map(|l| {
                let (exclusion, p) = match l.strip_prefix('!') {
                    Some(rest) => (true, rest.trim()),
                    None => (false, l),
                };
                let cleaned = clean(p);
                let cleaned = cleaned.strip_prefix('/').filter(|r| !r.is_empty()).unwrap_or(&cleaned);
                (!cleaned.is_empty()).then(|| Pattern { exclusion, tokens: compile(cleaned.as_bytes()) })
            })
            .collect();
        Ignore { patterns }
    }

    /// Whether `path` (relative to the context, `/`-separated, no leading `./`) is left out of the context.
    pub fn excludes(&self, path: &str) -> bool {
        let parents: Vec<&str> = {
            let mut v = Vec::new();
            let mut i = 0;
            while let Some(j) = path[i..].find('/') {
                v.push(&path[..i + j]);
                i += j + 1;
            }
            v
        };
        let mut excluded = false;
        for p in &self.patterns {
            let hit = matches(&p.tokens, path.as_bytes()) || parents.iter().any(|d| matches(&p.tokens, d.as_bytes()));
            if hit {
                excluded = !p.exclusion;
            }
        }
        excluded
    }
}

/// `filepath.Clean` for `/`-separated paths: no empty or `.` segments, `..` folded where possible.
pub fn clean(p: &str) -> String {
    let rooted = p.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." if out.last().is_some_and(|s| *s != "..") => {
                out.pop();
            }
            ".." if rooted => {}
            s => out.push(s),
        }
    }
    let body = out.join("/");
    match (rooted, body.is_empty()) {
        (true, _) => format!("/{body}"),
        (false, true) => ".".into(),
        (false, false) => body,
    }
}

fn compile(p: &[u8]) -> Vec<Token> {
    let mut t = Vec::new();
    let mut i = 0;
    while i < p.len() {
        match p[i] {
            b'*' if p.get(i + 1) == Some(&b'*') => {
                i += 2;
                // `**/` is the same as `**`.
                if p.get(i) == Some(&b'/') {
                    i += 1;
                }
                t.push(if i >= p.len() { Token::Rest } else { Token::Segments });
                continue;
            }
            b'*' => t.push(Token::Star),
            b'?' => t.push(Token::One),
            b'\\' if i + 1 < p.len() => {
                i += 1;
                t.push(Token::Lit(p[i]));
            }
            b'[' => {
                if let Some((tok, next)) = class(p, i + 1) {
                    t.push(tok);
                    i = next;
                    continue;
                }
                t.push(Token::Lit(b'['));
            }
            c => t.push(Token::Lit(c)),
        }
        i += 1;
    }
    t
}

/// A `[...]` class starting after the `[`; None when it is not closed (then `[` is literal).
fn class(p: &[u8], mut i: usize) -> Option<(Token, usize)> {
    let negated = p.get(i) == Some(&b'^');
    if negated {
        i += 1;
    }
    let mut ranges = Vec::new();
    let mut first = true;
    while i < p.len() {
        let mut c = p[i];
        if c == b']' && !first {
            return Some((Token::Class { negated, ranges }, i + 1));
        }
        first = false;
        if c == b'\\' && i + 1 < p.len() {
            i += 1;
            c = p[i];
        }
        if p.get(i + 1) == Some(&b'-') && p.get(i + 2).is_some_and(|&e| e != b']') {
            let mut end = p[i + 2];
            let mut skip = 3;
            if end == b'\\' && i + 3 < p.len() {
                end = p[i + 3];
                skip = 4;
            }
            ranges.push((c, end));
            i += skip;
        } else {
            ranges.push((c, c));
            i += 1;
        }
    }
    None
}

fn matches(t: &[Token], s: &[u8]) -> bool {
    let Some((first, rest)) = t.split_first() else { return s.is_empty() };
    match first {
        Token::Lit(c) => s.first() == Some(c) && matches(rest, &s[1..]),
        Token::One => s.first().is_some_and(|&b| b != b'/') && matches(rest, &s[1..]),
        Token::Class { negated, ranges } => {
            s.first().is_some_and(|&b| ranges.iter().any(|&(a, z)| a <= b && b <= z) != *negated)
                && matches(rest, &s[1..])
        }
        Token::Star => {
            let mut k = 0;
            loop {
                if matches(rest, &s[k..]) {
                    return true;
                }
                if k == s.len() || s[k] == b'/' {
                    return false;
                }
                k += 1;
            }
        }
        Token::Segments => matches(rest, s) || (0..s.len()).any(|k| s[k] == b'/' && matches(rest, &s[k + 1..])),
        Token::Rest => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_semantics() {
        let ig = Ignore::parse(
            "# comment\n\nnode_modules\n/dist/\n*.log\n!keep.log\n**/*.tmp\ndocs/**\n!docs/README.md\nsecret?.txt\n[ab].bin\n",
        );
        // A directory pattern excludes everything below it.
        assert!(ig.excludes("node_modules"));
        assert!(ig.excludes("node_modules/x/y.js"));
        // Patterns are anchored at the context root.
        assert!(!ig.excludes("src/node_modules/a.js"));
        assert!(ig.excludes("dist/app.js"));
        // `*` does not cross `/`.
        assert!(ig.excludes("app.log"));
        assert!(!ig.excludes("logs/app.log"));
        // The last matching pattern wins.
        assert!(!ig.excludes("keep.log"));
        // `**` spans any depth, including none.
        assert!(ig.excludes("a.tmp"));
        assert!(ig.excludes("a/b/c.tmp"));
        assert!(ig.excludes("docs/guide/x.md"));
        assert!(!ig.excludes("docs/README.md"));
        assert!(ig.excludes("secret1.txt"));
        assert!(!ig.excludes("secret12.txt"));
        assert!(ig.excludes("a.bin"));
        assert!(!ig.excludes("c.bin"));
        assert!(!ig.excludes("src/main.rs"));
    }

    #[test]
    fn negated_class_escape_and_cleaning() {
        let ig = Ignore::parse("./build//out\n[^x]y\nliteral\\*\n");
        assert!(ig.excludes("build/out/a"));
        assert!(ig.excludes("ay"));
        assert!(!ig.excludes("xy"));
        assert!(ig.excludes("literal*"));
        assert!(!ig.excludes("literalx"));
        assert_eq!(clean("a/./b/../c/"), "a/c");
        assert_eq!(clean("../a"), "../a");
        assert_eq!(clean("/../a"), "/a");
        assert_eq!(clean(""), ".");
    }

    #[test]
    fn exclude_everything_then_reinclude() {
        let ig = Ignore::parse("*\n!src\n!Dockerfile\n");
        assert!(ig.excludes("README.md"));
        assert!(!ig.excludes("Dockerfile"));
        // `src` itself re-included; files inside match `*` only through the parent, which is re-included last.
        assert!(!ig.excludes("src/main.rs"));
    }
}
