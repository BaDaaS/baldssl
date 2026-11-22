#!/usr/bin/env bash
#
# Downloads the test fixtures archive of a baldssl-fixtures release, checks
# its SHA-256, and unpacks it into a directory. Does nothing when the
# directory already holds that release (its .tag file names it).
#
# Usage:
#   scripts/fetch-fixtures.sh <tag> <sha256> <directory>
#

set -euo pipefail

if [[ "$#" -ne 3 ]]; then
    echo "usage: $0 <tag> <sha256> <directory>" >&2
    exit 2
fi
tag=$1
expected=$2
dir=$3
name="baldssl-fixtures-$tag.tar.gz"
url="https://github.com/BaDaaS/baldssl-fixtures/releases/download/$tag/$name"

if [[ -f "$dir/.tag" && "$(cat "$dir/.tag")" == "$tag" ]]; then
    exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "fetching fixtures $tag"
curl -fsSL --retry 3 -o "$work/$name" "$url"
if command -v sha256sum >/dev/null; then
    actual=$(sha256sum "$work/$name" | cut -d' ' -f1)
else
    actual=$(shasum -a 256 "$work/$name" | cut -d' ' -f1)
fi
if [[ "$actual" != "$expected" ]]; then
    echo "fixtures $tag: SHA-256 $actual, expected $expected" >&2
    exit 1
fi

mkdir -p "$work/unpacked"
tar -xzf "$work/$name" -C "$work/unpacked" --strip-components=1
echo "$tag" >"$work/unpacked/.tag"
rm -rf "$dir"
mkdir -p "$(dirname "$dir")"
mv "$work/unpacked" "$dir"
