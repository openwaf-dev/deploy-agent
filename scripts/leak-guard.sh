#!/usr/bin/env bash
# leak-guard.sh [dir] — refuses (exit 1) when a file of an OpenWAF open-source repository carries something
# that must stay private. Scans the files git would publish (tracked and untracked, minus .gitignore) or, outside a
# git repository, every regular file; binary files are skipped. Prints file:line and the rule, never the match.
#
# Built-in rules: IPv4 addresses other than loopback and the documentation ranges (192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24), real-format secrets (ows_ + 43 characters) and site keys other than the test ones, private keys,
# and e-mail addresses outside openwaf.dev and the example domains.
#
# LEAK_DENYLIST_FILE adds a private denylist: one extended regular expression per line (a leading "i:" makes it
# case-insensitive; "#" starts a comment). It is kept out of the repository (the CI reads it from a secret); hits are
# reported by line number of the denylist only.
#
# Lines can be exempted in .leak-guard-allow (path<TAB>ERE matched against the line), for reviewed false positives.
set -euo pipefail
dir=${1:-.}
cd "$dir"

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  files=$(git ls-files -co --exclude-standard)
else
  files=$(find . -type f -not -path './.git/*' | sed 's|^\./||')
fi
files=$(printf '%s\n' "$files" | grep -v -E '^(\.leak-guard-allow)$' | while IFS= read -r f; do [ -f "$f" ] && printf '%s\n' "$f"; done || true)
[ -n "$files" ] || { echo "leak-guard: no files under $dir" >&2; exit 2; }

findings=$(mktemp)
trap 'rm -f "$findings"' EXIT
allowed() { # allowed <file> <line text>
  [ -f .leak-guard-allow ] || return 1
  local path re
  while IFS=$'\t' read -r path re; do
    case $path in '' | '#'*) continue ;; esac
    [ "$path" = "$1" ] && printf '%s\n' "$2" | grep -qE -- "$re" && return 0
  done <.leak-guard-allow
  return 1
}
report() { # report <rule> <file:line:text…> lines on stdin
  local rule=$1 loc file rest line
  while IFS= read -r loc; do
    file=${loc%%:*}; rest=${loc#*:}; line=${rest%%:*}
    allowed "$file" "${rest#*:}" && continue
    printf '%s:%s: %s\n' "$file" "$line" "$rule" | tee -a "$findings"
  done
}
scan() { # scan <rule> <grep options…> -- pattern
  local rule=$1; shift
  printf '%s\n' "$files" | tr '\n' '\0' | xargs -0 grep -HnI "$@" 2>/dev/null | report "$rule" || true
}

# IPv4: everything but loopback, 0.0.0.0 and the documentation ranges.
printf '%s\n' "$files" | tr '\n' '\0' | xargs -0 grep -HnIoE '(^|[^0-9.])[0-9]{1,3}(\.[0-9]{1,3}){3}([^0-9.]|$)' 2>/dev/null |
  sed -E 's/^([^:]*:[0-9]+:)[^0-9]*([0-9.]+).*$/\1\2/' |
  grep -vE ':(127\.[0-9.]+|0\.0\.0\.0|192\.0\.2\.[0-9]+|198\.51\.100\.[0-9]+|203\.0\.113\.[0-9]+)$' | report "IPv4 address outside the documentation ranges" || true
scan "secret in real format (ows_…)" -E -- 'ows_[A-Za-z0-9_-]{43}'
printf '%s\n' "$files" | tr '\n' '\0' | xargs -0 grep -HnIoE 'owk_[A-Za-z0-9_-]{12,}' 2>/dev/null |
  grep -vE ':owk_(test_(pass|fail|interactive)|YOUR_SITE_KEY)$' | report "site key that is not a test key" || true
scan "private key" -E -- '-----BEGIN [A-Z ]*PRIVATE KEY-----'
printf '%s\n' "$files" | tr '\n' '\0' | xargs -0 grep -HnIoE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' 2>/dev/null |
  grep -vE '@((www\.)?openwaf\.dev|example\.(com|org|net)|[a-z0-9.-]+\.example|[a-z0-9.-]+\.test)$' |
  grep -vE ':[^:@]+@[0-9]+\.[0-9]' | report "e-mail address outside openwaf.dev and the example domains" || true

if [ -n "${LEAK_DENYLIST_FILE:-}" ]; then
  [ -r "$LEAK_DENYLIST_FILE" ] || { echo "leak-guard: LEAK_DENYLIST_FILE not readable" >&2; exit 2; }
  n=0
  while IFS= read -r re || [ -n "$re" ]; do
    n=$((n + 1))
    case $re in '' | '#'*) continue ;; esac
    if [ "${re#i:}" != "$re" ]; then scan "private denylist line $n" -i -E -- "${re#i:}"; else scan "private denylist line $n" -E -- "$re"; fi
  done <"$LEAK_DENYLIST_FILE"
  echo "leak-guard: private denylist applied ($n lines)"
else
  echo "leak-guard: no private denylist (LEAK_DENYLIST_FILE unset): built-in rules only"
fi

hits=$(wc -l <"$findings" | tr -d ' ')
if [ "$hits" -gt 0 ]; then
  echo "leak-guard: $hits finding(s): refused" >&2
  exit 1
fi
echo "leak-guard: clean ($(printf '%s\n' "$files" | wc -l | tr -d ' ') files)"
