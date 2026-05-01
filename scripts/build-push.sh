#!/usr/bin/env bash
set -euo pipefail

# Build the eedom production image and push to GHCR.
# For self-hosted runner (sambou@192.168.0.210) or any host with GHCR access.
#
# Usage:
#   bash scripts/build-push.sh                   # build + push latest
#   bash scripts/build-push.sh v0.2.11           # build + push with version tag
#   REGISTRY=ghcr.io/gitrdunhq/eedom bash scripts/build-push.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="${1:-}"
REGISTRY="${REGISTRY:-ghcr.io/gitrdunhq/eedom}"
ARCH="amd64"
SHA=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "unknown")

if command -v podman &>/dev/null; then
    ENGINE=podman
elif command -v docker &>/dev/null; then
    ENGINE=docker
else
    echo "ERROR: Neither podman nor docker found" >&2
    exit 1
fi

TAGS=("-t" "${REGISTRY}:latest" "-t" "${REGISTRY}:${SHA}")
[[ -n "$VERSION" ]] && TAGS+=("-t" "${REGISTRY}:${VERSION}")

echo "Engine: $ENGINE | Registry: $REGISTRY | SHA: ${SHA:0:12}"

# Build
if [[ "$ENGINE" == "podman" ]]; then
    sed 's/--security=insecure //g' "$REPO_ROOT/Dockerfile" \
      | $ENGINE build \
          --platform "linux/$ARCH" \
          "${TAGS[@]}" \
          -f - "$REPO_ROOT"
else
    BUILDER="eedom-builder"
    if ! docker buildx inspect "$BUILDER" &>/dev/null; then
        docker buildx create --name "$BUILDER" --driver docker-container \
            --buildkitd-flags '--allow-insecure-entitlement security.insecure' --use
    fi
    docker buildx build \
        --builder "$BUILDER" \
        --allow security.insecure \
        --load \
        --platform "linux/$ARCH" \
        "${TAGS[@]}" \
        "$REPO_ROOT"
fi

echo "Built: ${REGISTRY}:latest (${SHA:0:12})"

# Push
echo "Pushing to GHCR..."
$ENGINE push "${REGISTRY}:latest"
$ENGINE push "${REGISTRY}:${SHA}"
[[ -n "$VERSION" ]] && $ENGINE push "${REGISTRY}:${VERSION}"

echo "Pushed: ${REGISTRY}:latest, :${SHA:0:12}${VERSION:+, :$VERSION}"
