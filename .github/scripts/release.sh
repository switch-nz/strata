#!/usr/bin/env bash
# Cut the tag and GitHub release for the version in engine/version.py.
#
# Idempotent: does nothing if the tag already exists. Refuses (non-zero) if
# CHANGELOG.md has no dated "## [X.Y.Z] - YYYY-MM-DD" section for the version,
# so a release is never published without its notes.
#
#   SHA      commit to tag (default: HEAD)
#   DRY_RUN  set to anything to print what would happen and change nothing
set -euo pipefail

version=$(sed -n 's/^__version__ = "\([0-9][0-9.]*\)".*/\1/p' engine/version.py)
[ -n "$version" ] || { echo "cannot read __version__ from engine/version.py" >&2; exit 1; }
tag="v$version"
sha="${SHA:-$(git rev-parse HEAD)}"

if git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1 \
   || git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  echo "$tag already exists; nothing to release."
  exit 0
fi

notes=$(mktemp)
awk -v v="$version" '
  $0 ~ "^## \\[" v "\\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$" { on = 1; found = 1; next }
  on && /^## \[/ { exit }
  on { print }
  END { exit found ? 0 : 1 }
' CHANGELOG.md > "$notes" || {
  echo "CHANGELOG.md has no dated '## [$version] - YYYY-MM-DD' section; not releasing." >&2
  exit 1
}
# Trim leading and trailing blank lines.
sed -i -e '/./,$!d' "$notes"
sed -i -e :a -e '/^\n*$/{$d;N;ba' -e '}' "$notes"
[ -s "$notes" ] || { echo "the $version changelog section is empty; not releasing." >&2; exit 1; }

echo "Releasing $tag at $sha ($(wc -l < "$notes") lines of notes)."
if [ -n "${DRY_RUN:-}" ]; then
  echo "--- notes ---"; cat "$notes"; echo "--- (dry run: no tag, no release) ---"
  exit 0
fi

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git tag -a "$tag" "$sha" -m "Strata $version"
git push origin "$tag"
gh release create "$tag" --verify-tag --title "Strata $version" --notes-file "$notes"

# Attach the native crypto sidecars (built by CI) to the release just made.
# Non-fatal: the release is already published, and the job can be run again
# by hand: gh workflow run ci.yml --ref "$tag" -f tag="$tag"
gh workflow run ci.yml --ref "$tag" -f tag="$tag"   || echo "::warning::could not dispatch the sidecar build for $tag"
