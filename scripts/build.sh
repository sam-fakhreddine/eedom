#!/usr/bin/env bash
set -euo pipefail

# Build the eedom production container image.
# Auto-detects podman vs docker and applies the right flags.
#
# Usage:
#   bash scripts/build.sh              # default: linux/amd64
#   bash scripts/build.sh arm64        # explicit arch
#   bash scripts/build.sh amd64 --no-cache

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ARCH="${1:-amd64}"; shift 2>/dev/null || true
EXTRA_ARGS=("$@")
IMAGE="eedom:${ARCH}"

if command -v podman &>/dev/null; then
    ENGINE=podman
elif command -v docker &>/dev/null; then
    ENGINE=docker
else
    echo "ERROR: Neither podman nor docker found" >&2
    exit 1
fi

echo "Engine: $ENGINE | Platform: linux/$ARCH | Image: $IMAGE"

if [[ "$ENGINE" == "podman" ]]; then
    # Podman: strip --security=insecure from RUN directives (not needed, not supported)
    sed 's/--security=insecure //g' "$REPO_ROOT/Dockerfile" \
      | $ENGINE build \
          --platform "linux/$ARCH" \
          -t "$IMAGE" \
          -t eedom:latest \
          "${EXTRA_ARGS[@]}" \
          -f - "$REPO_ROOT"
else
    # Docker: needs buildx with insecure entitlement for uv tokio workaround
    BUILDER="eedom-builder"
    if ! docker buildx inspect "$BUILDER" &>/dev/null; then
        echo "Creating buildx builder '$BUILDER' with insecure entitlements..."
        docker buildx create --name "$BUILDER" --driver docker-container \
            --buildkitd-flags '--allow-insecure-entitlement security.insecure' --use
    fi
    docker buildx build \
        --builder "$BUILDER" \
        --allow security.insecure \
        --load \
        --platform "linux/$ARCH" \
        -t "$IMAGE" \
        -t eedom:latest \
        "${EXTRA_ARGS[@]}" \
        "$REPO_ROOT"
fi

echo "Built: $IMAGE"
$ENGINE run --rm --platform "linux/$ARCH" --entrypoint "" "$IMAGE" eedom --version 2>&1 | tail -1
