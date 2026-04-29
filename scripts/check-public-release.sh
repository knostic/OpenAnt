#!/usr/bin/env bash
# Pre-push verification for public release branches.
#
# Run from anywhere inside the repo, while checked out on the release branch
# you are about to push to `public`. Exits non-zero if any check fails so
# callers (humans, hooks, CI) can gate on it.
#
# Encodes the checks from docs/internal/release-to-public.md step 6, plus:
#   - race guard against public/master moving since the branch was cut
#   - gitleaks secret scan (warns if not installed)
#
# Usage:
#   scripts/check-public-release.sh              # fetch remotes, run all checks
#   scripts/check-public-release.sh --no-fetch   # skip git fetch (offline / CI)
#   scripts/check-public-release.sh --no-build   # skip Go build smoke test
#   scripts/check-public-release.sh --post-merge # verify a fresh public clone
#                                                # (skips branch + race guards;
#                                                #  implies --no-fetch)
#
# Pattern files (read from repo root):
#   .publish-exclude            — regexes for forbidden tracked paths
#   .publish-forbidden-strings  — case-insensitive substrings forbidden in content

set -uo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "fatal: not inside a git repository" >&2
  exit 2
}
cd "$REPO_ROOT"

NO_FETCH=0
NO_BUILD=0
POST_MERGE=0
for arg in "$@"; do
  case "$arg" in
    --no-fetch) NO_FETCH=1 ;;
    --no-build) NO_BUILD=1 ;;
    --post-merge) POST_MERGE=1; NO_FETCH=1 ;;
    -h|--help)
      sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "unknown arg: $arg" >&2
      echo "use --help for usage" >&2
      exit 2
      ;;
  esac
done

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

pass() { printf '  PASS  %s\n' "$1"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { printf '  FAIL  %s\n' "$1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
warn() { printf '  WARN  %s\n' "$1"; WARN_COUNT=$((WARN_COUNT + 1)); }
section() { printf '\n== %s ==\n' "$1"; }

read_patterns() {
  # Strip comments + blank lines from a pattern file. $1 = path.
  sed -E 's/[[:space:]]*#.*$//; /^[[:space:]]*$/d' "$1"
}

# ---------- Setup ----------

section "Setup"

if [ "$NO_FETCH" = "0" ]; then
  if git remote get-url public >/dev/null 2>&1; then
    if git fetch --quiet origin && git fetch --quiet public; then
      pass "fetched origin and public"
    else
      fail "git fetch failed — check network / remote auth"
    fi
  else
    fail "remote 'public' missing — run: git remote add public git@github.com:knostic/OpenAnt.git"
  fi
else
  pass "skipped fetch (--no-fetch)"
fi

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$POST_MERGE" = "1" ]; then
  pass "post-merge mode (branch + race guards skipped) — branch: $CURRENT_BRANCH"
else
  case "$CURRENT_BRANCH" in
    master|main|HEAD)
      fail "on '$CURRENT_BRANCH' — release checks must run on a release branch (e.g. release/<name>)"
      ;;
    *)
      pass "on release branch: $CURRENT_BRANCH"
      ;;
  esac

  section "Race guard vs public/master"

  if git rev-parse --verify --quiet refs/remotes/public/master >/dev/null; then
    AHEAD=$(git log --oneline public/master ^HEAD 2>/dev/null)
    if [ -n "$AHEAD" ]; then
      fail "public/master has commits not reachable from $CURRENT_BRANCH:"
      printf '%s\n' "$AHEAD" | sed 's/^/        /'
      echo "        rebase onto public/master before releasing"
    else
      pass "public/master fully reachable from $CURRENT_BRANCH"
    fi
  else
    fail "public/master ref not found — fetch the public remote"
  fi
fi

# ---------- Forbidden paths ----------

section "Internal-only paths"

EXCLUDE_FILE="$REPO_ROOT/.publish-exclude"
if [ ! -f "$EXCLUDE_FILE" ]; then
  fail ".publish-exclude not found at repo root"
else
  any_path_failure=0
  ALL_TRACKED=$(git ls-files)
  while IFS= read -r pattern; do
    [ -z "$pattern" ] && continue
    matches=$(printf '%s\n' "$ALL_TRACKED" | grep -E -- "$pattern" || true)
    if [ -n "$matches" ]; then
      fail "tracked files match forbidden pattern '$pattern':"
      printf '%s\n' "$matches" | sed 's/^/        /'
      any_path_failure=1
    fi
  done < <(read_patterns "$EXCLUDE_FILE")
  if [ "$any_path_failure" = "0" ]; then
    pass "no tracked files match .publish-exclude"
  fi
fi

# ---------- Forbidden strings ----------

section "Forbidden strings in content"

FORBID_FILE="$REPO_ROOT/.publish-forbidden-strings"
if [ ! -f "$FORBID_FILE" ]; then
  fail ".publish-forbidden-strings not found at repo root"
else
  any_string_failure=0
  # Exclude the pattern files themselves (they legitimately contain the patterns)
  # plus anything already flagged by the path check.
  GREP_PATHSPECS=(
    ':(exclude).publish-exclude'
    ':(exclude).publish-forbidden-strings'
    ':(exclude)docs/internal'
    ':(exclude)scripts/check-public-release.sh'
  )
  while IFS= read -r needle; do
    [ -z "$needle" ] && continue
    if matches=$(git grep -i -F -n -e "$needle" -- "${GREP_PATHSPECS[@]}" 2>/dev/null); then
      fail "forbidden string '$needle' found:"
      printf '%s\n' "$matches" | sed 's/^/        /'
      any_string_failure=1
    fi
  done < <(read_patterns "$FORBID_FILE")
  if [ "$any_string_failure" = "0" ]; then
    pass "no forbidden strings found"
  fi
fi

# ---------- Secret scan ----------

section "Secret scan (gitleaks)"

if command -v gitleaks >/dev/null 2>&1; then
  # Scan ONLY the tracked content of HEAD — excludes untracked / gitignored
  # files (notably node_modules) so the scan reflects what would land on public.
  GL_DIR=$(mktemp -d)
  GL_OUT=$(mktemp)
  if git archive HEAD | tar -x -C "$GL_DIR"; then
    if NO_COLOR=1 gitleaks detect --source "$GL_DIR" --no-banner --redact --no-git >"$GL_OUT" 2>&1; then
      pass "gitleaks: no secrets detected in tracked content"
    else
      fail "gitleaks detected potential secrets:"
      sed 's/^/        /' "$GL_OUT"
    fi
  else
    fail "git archive HEAD failed — cannot run gitleaks scan"
  fi
  rm -rf "$GL_DIR" "$GL_OUT"
else
  warn "gitleaks not installed — install via 'brew install gitleaks' for secret scanning"
fi

# ---------- Build smoke test ----------

section "Build smoke test"

if [ "$NO_BUILD" = "1" ]; then
  pass "skipped build (--no-build)"
elif [ -d apps/openant-cli ]; then
  BUILD_OUT=$(mktemp)
  if (cd apps/openant-cli && go build ./... >"$BUILD_OUT" 2>&1); then
    pass "apps/openant-cli builds cleanly"
  else
    fail "apps/openant-cli build failed:"
    sed 's/^/        /' "$BUILD_OUT"
  fi
  rm -f "$BUILD_OUT"
else
  fail "apps/openant-cli not found — adjust check-public-release.sh"
fi

# ---------- Summary ----------

section "Summary"
printf '  %d passed, %d failed, %d warnings\n' "$PASS_COUNT" "$FAIL_COUNT" "$WARN_COUNT"

if [ "$FAIL_COUNT" -gt 0 ]; then
  echo ""
  echo "FAILED — fix issues above before pushing to public."
  exit 1
fi

echo ""
echo "OK — release branch is clean. Safe to push."
exit 0
