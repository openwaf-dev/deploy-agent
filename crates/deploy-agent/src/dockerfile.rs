//! Declares build arguments in a Dockerfile. Docker hands a `--build-arg` only to the stages that declare it with
//! `ARG NAME`, so variables meant for the build (`NEXT_PUBLIC_*` and the like) would otherwise never reach it: an
//! `ARG NAME` line goes after every `FROM` whose stage does not declare `NAME` yet.
//!
//! Lines are read as BuildKit's parser reads them: the `# escape=` parser directive, comment lines, line continuations
//! (comment and blank lines inside one do not end it) and the heredocs of `RUN`, `COPY` and `ADD`, whose bodies hold
//! no instructions. Everything but the inserted lines stays byte for byte.

/// A Dockerfile with `ARG` lines inserted.
#[derive(Debug, PartialEq)]
pub struct Declared {
    pub text: String,
    /// The names declared at least once, in the order given.
    pub args: Vec<String>,
    /// `ARG` lines inserted.
    pub lines: usize,
    /// `FROM` instructions that got at least one.
    pub stages: usize,
}

struct Stage<'a> {
    /// Where the lines go (the end of the `FROM`'s last physical line, before its line ending) and the line ending
    /// they start with; none when the instruction runs into the end of the file inside a continuation.
    at: Option<(usize, &'a str)>,
    declared: Vec<String>,
}

/// Inserts `ARG <name>` after every `FROM` for each name (`[A-Za-z_][A-Za-z0-9_]*`, others are skipped) its stage does
/// not declare. `ARG`s before the first `FROM` are global and declare nothing in a stage. None when nothing changes.
pub fn declare_args(text: &str, names: &[&str]) -> Option<Declared> {
    let mut wanted: Vec<&str> = Vec::new();
    for &n in names {
        if valid_name(n) && !wanted.contains(&n) {
            wanted.push(n);
        }
    }
    if wanted.is_empty() {
        return None;
    }
    let mut lines = Vec::new();
    let mut offset = 0;
    for l in text.split_inclusive('\n') {
        lines.push((offset, l));
        offset += l.len();
    }
    let content = |i: usize| {
        let l = lines[i].1.trim_end_matches(['\r', '\n']);
        if i == 0 { l.strip_prefix('\u{feff}').unwrap_or(l) } else { l }
    };
    let file_eol = match lines.first() {
        Some((_, l)) if l.ends_with("\r\n") => "\r\n",
        _ => "\n",
    };
    let escape = escape_directive((0..lines.len()).map(content));

    let mut stages: Vec<Stage> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let first = content(i);
        i += 1;
        if is_comment(first) {
            continue;
        }
        let (rest, mut ended) = trim_continuation(first.trim_start(), escape);
        if ended && rest.is_empty() {
            continue;
        }
        let mut line = rest.to_string();
        let mut last = i - 1;
        while !ended && i < lines.len() {
            let next = content(i);
            i += 1;
            if is_comment(next) || next.trim_start().is_empty() {
                continue;
            }
            let (rest, e) = trim_continuation(next, escape);
            line.push_str(rest);
            ended = e;
            last = i - 1;
        }
        let trimmed = line.trim_matches(is_space);
        let (keyword, args) = trimmed.split_once(is_space).unwrap_or((trimmed, ""));
        match keyword.to_ascii_lowercase().as_str() {
            "from" => {
                let (start, l) = lines[last];
                let at = if !ended {
                    None
                } else if l.ends_with("\r\n") {
                    Some((start + l.len() - 2, "\r\n"))
                } else if l.ends_with('\n') {
                    Some((start + l.len() - 1, "\n"))
                } else {
                    Some((start + l.len(), file_eol))
                };
                stages.push(Stage { at, declared: Vec::new() });
            }
            "arg" => {
                if let Some(s) = stages.last_mut() {
                    for w in words(args, escape, true) {
                        let name = w.split('=').next().unwrap_or_default();
                        s.declared.push(name.to_string());
                    }
                }
            }
            "run" | "copy" | "add" if line.contains("<<") => {
                for (name, chomp) in words(&line, '\\', true).iter().filter_map(|w| heredoc(w)) {
                    while i < lines.len() {
                        let body = lines[i].1.trim_end_matches(['\r', '\n']);
                        i += 1;
                        let body = if chomp { body.trim_start_matches('\t') } else { body };
                        if body == name {
                            break;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut declared = Declared { text: String::new(), args: Vec::new(), lines: 0, stages: 0 };
    for s in &stages {
        let Some((at, eol)) = s.at else { continue };
        let missing: Vec<&str> = wanted.iter().copied().filter(|n| !s.declared.iter().any(|d| d == n)).collect();
        if missing.is_empty() {
            continue;
        }
        out.push_str(&text[copied..at]);
        copied = at;
        for n in missing {
            out.push_str(eol);
            out.push_str("ARG ");
            out.push_str(n);
            declared.lines += 1;
            if !declared.args.iter().any(|a| a == n) {
                declared.args.push(n.to_string());
            }
        }
        declared.stages += 1;
    }
    if declared.lines == 0 {
        return None;
    }
    out.push_str(&text[copied..]);
    declared.args.sort_by_key(|a| wanted.iter().position(|w| w == a));
    declared.text = out;
    Some(declared)
}

fn valid_name(n: &str) -> bool {
    let mut b = n.bytes();
    b.next().is_some_and(|c| c.is_ascii_alphabetic() || c == b'_') && b.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\u{b}' | '\u{c}' | '\r')
}

fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with('#')
}

/// The escape character set by the parser directives at the top of the file (`\` by default). Directives stop at the
/// first line that is not one of the known ones.
fn escape_directive<'a>(lines: impl Iterator<Item = &'a str>) -> char {
    let mut escape = '\\';
    for l in lines {
        let Some((key, value)) = l.trim_start().strip_prefix('#').and_then(|d| d.split_once('=')) else { break };
        let (key, value) = (key.trim(), value.trim());
        let key_ok =
            key.starts_with(|c: char| c.is_ascii_alphabetic()) && key.chars().all(|c| c.is_ascii_alphanumeric());
        if !key_ok || value.is_empty() {
            break;
        }
        match key.to_ascii_lowercase().as_str() {
            "escape" if value == "`" => escape = '`',
            "escape" if value == "\\" => escape = '\\',
            "escape" | "syntax" | "check" => {}
            _ => break,
        }
    }
    escape
}

/// The line without its trailing escape character (and the blanks after it), and whether the instruction ends there.
fn trim_continuation(line: &str, escape: char) -> (&str, bool) {
    match line.trim_end_matches([' ', '\t']).strip_suffix(escape) {
        Some(rest) => (rest, false),
        None => (line, true),
    }
}

/// Splits on unquoted whitespace, honouring single and double quotes and the escape character. `raw` keeps the quotes
/// and escape characters in the words; otherwise they are removed.
fn words(s: &str, escape: char, raw: bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut quote = None;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if quote.is_none() && c.is_whitespace() {
            if in_word {
                out.push(std::mem::take(&mut word));
                in_word = false;
            }
            continue;
        }
        in_word = true;
        let escapes = quote.is_none() || quote == Some('"');
        if Some(c) == quote {
            quote = None;
            if raw {
                word.push(c);
            }
        } else if quote.is_none() && (c == '\'' || c == '"') {
            quote = Some(c);
            if raw {
                word.push(c);
            }
        } else if escapes && c == escape {
            if raw {
                word.push(c);
            }
            if let Some(n) = chars.next() {
                word.push(n);
            }
        } else {
            word.push(c);
        }
    }
    if in_word {
        out.push(word);
    }
    out
}

/// The terminator of a heredoc word (`<<EOF`, `<<-EOF`, `<<"EOF"`, `<<'EOF'`) and whether leading tabs are stripped
/// before comparing (`<<-`). A file descriptor before `<<` makes it a redirection, as in BuildKit.
fn heredoc(word: &str) -> Option<(String, bool)> {
    let rest = word.strip_prefix("<<")?;
    let (chomp, rest) = match rest.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, rest),
    };
    if rest.contains('<') {
        return None;
    }
    let mut name = words(rest, '\\', false);
    if name.len() != 1 || name[0].is_empty() {
        return None;
    }
    Some((name.remove(0), chomp))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declare(text: &str, names: &[&str]) -> Option<String> {
        let d = declare_args(text, names)?;
        assert_eq!(declare_args(&d.text, names), None, "idempotent on {:?}", d.text);
        Some(d.text)
    }

    #[test]
    fn every_stage_gets_the_missing_names() {
        let text = "ARG NODE=22\nFROM node:${NODE} AS deps\nRUN npm ci\n\nFROM --platform=$BUILDPLATFORM node AS build\nARG NEXT_PUBLIC_A=1 OTHER\nRUN next build\nfrom nginx\nCOPY --from=build /app/out /usr/share/nginx/html\n";
        let d = declare_args(text, &["NEXT_PUBLIC_A", "NEXT_PUBLIC_B", "NEXT_PUBLIC_A"]).unwrap();
        assert_eq!(
            d.text,
            "ARG NODE=22\nFROM node:${NODE} AS deps\nARG NEXT_PUBLIC_A\nARG NEXT_PUBLIC_B\nRUN npm ci\n\nFROM --platform=$BUILDPLATFORM node AS build\nARG NEXT_PUBLIC_B\nARG NEXT_PUBLIC_A=1 OTHER\nRUN next build\nfrom nginx\nARG NEXT_PUBLIC_A\nARG NEXT_PUBLIC_B\nCOPY --from=build /app/out /usr/share/nginx/html\n"
        );
        assert_eq!((d.args, d.lines, d.stages), (vec!["NEXT_PUBLIC_A".into(), "NEXT_PUBLIC_B".into()], 5, 3));
        assert_eq!(declare_args(&d.text, &["NEXT_PUBLIC_A", "NEXT_PUBLIC_B"]), None);
    }

    #[test]
    fn a_global_arg_declares_nothing_in_a_stage() {
        assert_eq!(
            declare("ARG A=1\nFROM alpine\nRUN echo $A\n", &["A"]).unwrap(),
            "ARG A=1\nFROM alpine\nARG A\nRUN echo $A\n"
        );
    }

    #[test]
    fn existing_declarations_count_in_any_form_but_only_in_their_stage() {
        let text = "FROM a AS one\nRUN x\n  arg B=\"x y\" A\nFROM b\nARG C='1 2'\n";
        assert_eq!(
            declare(text, &["A", "B", "C"]).unwrap(),
            "FROM a AS one\nARG C\nRUN x\n  arg B=\"x y\" A\nFROM b\nARG A\nARG B\nARG C='1 2'\n"
        );
        assert_eq!(declare("FROM a\nARG A\n", &["A"]), None);
    }

    #[test]
    fn comments_are_not_instructions() {
        let text = "# FROM x\nFROM a\n  # FROM y\nRUN z\n";
        assert_eq!(declare(text, &["A"]).unwrap(), "# FROM x\nFROM a\nARG A\n  # FROM y\nRUN z\n");
    }

    #[test]
    fn a_continued_from_gets_the_lines_after_its_last_physical_line() {
        let text = "FROM \\\n  # the base\n\n  node:22 \\  \n  AS build\nRUN x\n";
        assert_eq!(
            declare(text, &["A"]).unwrap(),
            "FROM \\\n  # the base\n\n  node:22 \\  \n  AS build\nARG A\nRUN x\n"
        );
        // A continuation still open at the end of the file gets nothing: the line would join the instruction.
        assert_eq!(declare_args("FROM a \\\n# c\n", &["A"]), None);
        // A continued line that starts with FROM belongs to the instruction before it.
        assert_eq!(declare("RUN a \\\n  FROM b\nFROM c\n", &["A"]).unwrap(), "RUN a \\\n  FROM b\nFROM c\nARG A\n");
    }

    #[test]
    fn the_escape_directive_changes_the_continuation_character() {
        let text = "# syntax=docker/dockerfile:1\n# escape=`\nFROM mcr.microsoft.com/windows `\n  AS build\nRUN dir c:\\\nFROM b\n";
        assert_eq!(
            declare(text, &["A"]).unwrap(),
            "# syntax=docker/dockerfile:1\n# escape=`\nFROM mcr.microsoft.com/windows `\n  AS build\nARG A\nRUN dir c:\\\nFROM b\nARG A\n"
        );
        // Directives stop at the first other line: this one is a comment.
        let text = "FROM a \\\n  AS b\n# escape=`\n";
        assert_eq!(declare(text, &["A"]).unwrap(), "FROM a \\\n  AS b\nARG A\n# escape=`\n");
    }

    #[test]
    fn heredoc_bodies_are_skipped() {
        let text = "FROM a\nRUN <<EOF cat - <<-'END' > /f\nFROM nope\nEOF\nFROM still nope\n\tEND\nCOPY <<\"X\" /x\nFROM nope\nX\nRUN 2<<NOT echo\nFROM b\n";
        assert_eq!(
            declare(text, &["A"]).unwrap(),
            "FROM a\nARG A\nRUN <<EOF cat - <<-'END' > /f\nFROM nope\nEOF\nFROM still nope\n\tEND\nCOPY <<\"X\" /x\nFROM nope\nX\nRUN 2<<NOT echo\nFROM b\nARG A\n"
        );
    }

    #[test]
    fn line_endings_are_kept() {
        assert_eq!(declare("FROM a\r\nRUN x\r\n", &["A", "B"]).unwrap(), "FROM a\r\nARG A\r\nARG B\r\nRUN x\r\n");
        assert_eq!(declare("FROM a\r\nFROM b", &["A"]).unwrap(), "FROM a\r\nARG A\r\nFROM b\r\nARG A");
        assert_eq!(declare("FROM a", &["A"]).unwrap(), "FROM a\nARG A");
        assert_eq!(declare("\u{feff}FROM a\n", &["A"]).unwrap(), "\u{feff}FROM a\nARG A\n");
    }

    #[test]
    fn only_valid_names_and_some_names_change_anything() {
        assert_eq!(declare("FROM a\n", &["1A", "A-B", "", "A B", "_ok9"]).unwrap(), "FROM a\nARG _ok9\n");
        assert_eq!(declare_args("FROM a\n", &["A-B"]), None);
        assert_eq!(declare_args("FROM a\n", &[]), None);
        assert_eq!(declare_args("RUN x\n", &["A"]), None);
        assert_eq!(declare_args("", &["A"]), None);
    }
}
