#!/usr/bin/env bash
set -Eeuo pipefail

# ZEN Control source bundle creator
#
# Run from the root of the ZEN Control repository, e.g.:
#   cd ~/mikrotik-control
#   ./bundle-zen-starter.sh
#
# Creates a source-only starter bundle suitable for attaching to a new
# ChatGPT conversation. Runtime data, secrets, databases, logs, backups,
# certificates and caches are deliberately excluded.

PROJECT_NAME="${PROJECT_NAME:-zen-control}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-$PWD}"
BUNDLE_BASENAME="${PROJECT_NAME}-starter-${STAMP}"
STAGE="$(mktemp -d)"
STAGE_ROOT="${STAGE}/${BUNDLE_BASENAME}"
ARCHIVE="${OUT_DIR}/${BUNDLE_BASENAME}.tar.gz"
MANIFEST="${OUT_DIR}/${BUNDLE_BASENAME}.manifest.txt"
SHA_FILE="${ARCHIVE}.sha256"

cleanup() {
    rm -rf "${STAGE}"
}
trap cleanup EXIT

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

echo "ZEN Control starter bundle"
echo "Source : $PWD"
echo "Output : $ARCHIVE"
echo

[[ -f "docker-compose.yml" ]] || fail "docker-compose.yml not found. Run this from the ZEN Control repository root."
[[ -d "app" ]] || fail "app/ not found. Run this from the ZEN Control repository root."
[[ -d "tests" ]] || fail "tests/ not found. Run this from the ZEN Control repository root."

mkdir -p "${STAGE_ROOT}"

# Refuse obvious secret-like files if they would otherwise be copied.
# This is belt-and-braces; the rsync excludes below should already omit them.
SECRET_PATTERNS=(
    ".env"
    "*.pem"
    "*.key"
    "*.p12"
    "*.pfx"
    "id_rsa"
    "id_ed25519"
)

EXCLUDES=(
    "--exclude=.git/"
    "--exclude=.env"
    "--exclude=.env.*"
    "--exclude=!.env.example"
    "--exclude=data/"
    "--exclude=postgres-data/"
    "--exclude=pgdata/"
    "--exclude=backups/"
    "--exclude=backup/"
    "--exclude=logs/"
    "--exclude=log/"
    "--exclude=diagnostics/"
    "--exclude=exports/"
    "--exclude=pcap/"
    "--exclude=pcaps/"
    "--exclude=node_modules/"
    "--exclude=dist/"
    "--exclude=build/"
    "--exclude=.venv/"
    "--exclude=venv/"
    "--exclude=__pycache__/"
    "--exclude=.pytest_cache/"
    "--exclude=.mypy_cache/"
    "--exclude=.ruff_cache/"
    "--exclude=.coverage"
    "--exclude=coverage.xml"
    "--exclude=htmlcov/"
    "--exclude=*.sqlite"
    "--exclude=*.sqlite3"
    "--exclude=*.db"
    "--exclude=*.db-shm"
    "--exclude=*.db-wal"
    "--exclude=*.log"
    "--exclude=*.pcap"
    "--exclude=*.pcapng"
    "--exclude=*.pem"
    "--exclude=*.key"
    "--exclude=*.p12"
    "--exclude=*.pfx"
    "--exclude=id_rsa"
    "--exclude=id_ed25519"
    "--exclude=*.crt"
    "--exclude=*.cer"
    "--exclude=*.der"
    "--exclude=*.secrets"
    "--exclude=secrets/"
    "--exclude=certs/"
    "--exclude=certificates/"
    "--exclude=.DS_Store"
    "--exclude=${BUNDLE_BASENAME}.tar.gz"
    "--exclude=${BUNDLE_BASENAME}.manifest.txt"
    "--exclude=${BUNDLE_BASENAME}.tar.gz.sha256"
)

# Prefer rsync because it gives us reliable include/exclude semantics.
if command -v rsync >/dev/null 2>&1; then
    rsync -a \
        "${EXCLUDES[@]}" \
        ./ "${STAGE_ROOT}/"
else
    echo "rsync not found; using tar fallback."

    TAR_EXCLUDES=(
        "--exclude=.git"
        "--exclude=.env"
        "--exclude=.env.*"
        "--exclude=data"
        "--exclude=postgres-data"
        "--exclude=pgdata"
        "--exclude=backups"
        "--exclude=backup"
        "--exclude=logs"
        "--exclude=log"
        "--exclude=diagnostics"
        "--exclude=exports"
        "--exclude=pcap"
        "--exclude=pcaps"
        "--exclude=node_modules"
        "--exclude=dist"
        "--exclude=build"
        "--exclude=.venv"
        "--exclude=venv"
        "--exclude=__pycache__"
        "--exclude=.pytest_cache"
        "--exclude=.mypy_cache"
        "--exclude=.ruff_cache"
        "--exclude=.coverage"
        "--exclude=coverage.xml"
        "--exclude=htmlcov"
        "--exclude=*.sqlite"
        "--exclude=*.sqlite3"
        "--exclude=*.db"
        "--exclude=*.db-shm"
        "--exclude=*.db-wal"
        "--exclude=*.log"
        "--exclude=*.pcap"
        "--exclude=*.pcapng"
        "--exclude=*.pem"
        "--exclude=*.key"
        "--exclude=*.p12"
        "--exclude=*.pfx"
        "--exclude=id_rsa"
        "--exclude=id_ed25519"
        "--exclude=*.crt"
        "--exclude=*.cer"
        "--exclude=*.der"
        "--exclude=*.secrets"
        "--exclude=secrets"
        "--exclude=certs"
        "--exclude=certificates"
        "--exclude=.DS_Store"
    )

    tar -cf - "${TAR_EXCLUDES[@]}" . | tar -xf - -C "${STAGE_ROOT}"
fi

# .env.example is safe/useful and should be retained if present.
if [[ -f ".env.example" ]]; then
    cp -a ".env.example" "${STAGE_ROOT}/.env.example"
fi

# Add the handoff if it is beside this script or already in the repo root.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "$PWD/ZEN_HANDOFF.md" ]]; then
    cp -a "$PWD/ZEN_HANDOFF.md" "${STAGE_ROOT}/ZEN_HANDOFF.md"
elif [[ -f "${SCRIPT_DIR}/ZEN_HANDOFF.md" ]]; then
    cp -a "${SCRIPT_DIR}/ZEN_HANDOFF.md" "${STAGE_ROOT}/ZEN_HANDOFF.md"
else
    cat > "${STAGE_ROOT}/BUNDLE_NOTE.txt" <<'EOF'
ZEN_HANDOFF.md was not found beside bundle-zen-starter.sh or in the repository.
Attach the handoff document separately to the new conversation.
EOF
fi

# Add a small deterministic bundle-info file.
{
    echo "bundle_name=${BUNDLE_BASENAME}"
    echo "created_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "source_directory=$PWD"
    if [[ -f "README.md" ]]; then
        VERSION_LINE="$(grep -Eim1 '(^|[^0-9])v?0\.[0-9]+(\.[0-9]+)?([^0-9]|$)|release' README.md || true)"
        [[ -n "${VERSION_LINE}" ]] && echo "readme_version_hint=${VERSION_LINE}"
    fi
    echo "security_note=source-only bundle; runtime/private data excluded"
} > "${STAGE_ROOT}/ZEN_BUNDLE_INFO.txt"

# Final secret sanity check. This intentionally errs on the side of caution.
BAD_FILES="$(
    find "${STAGE_ROOT}" -type f \( \
        -name '.env' -o \
        -name '*.pem' -o \
        -name '*.key' -o \
        -name '*.p12' -o \
        -name '*.pfx' -o \
        -name 'id_rsa' -o \
        -name 'id_ed25519' -o \
        -name '*.sqlite' -o \
        -name '*.sqlite3' -o \
        -name '*.db' -o \
        -name '*.pcap' -o \
        -name '*.pcapng' \
    \) -print
)"

if [[ -n "${BAD_FILES}" ]]; then
    echo "Refusing to create bundle because excluded/private file types remain:" >&2
    echo "${BAD_FILES}" >&2
    exit 1
fi

# Generate a file manifest inside the bundle.
(
    cd "${STAGE_ROOT}"
    find . -type f -printf '%P\n' | LC_ALL=C sort
) > "${STAGE_ROOT}/ZEN_FILE_MANIFEST.txt"

# Also keep an external manifest with hashes for integrity/debugging.
(
    cd "${STAGE_ROOT}"
    while IFS= read -r file; do
        sha256sum "$file"
    done < <(find . -type f -printf '%P\n' | LC_ALL=C sort)
) > "${MANIFEST}"

# Create deterministic-ish archive ownership metadata.
tar \
    --sort=name \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    -czf "${ARCHIVE}" \
    -C "${STAGE}" \
    "${BUNDLE_BASENAME}"

sha256sum "${ARCHIVE}" > "${SHA_FILE}"

echo
echo "Bundle created successfully:"
echo "  ${ARCHIVE}"
echo
echo "Integrity:"
cat "${SHA_FILE}"
echo
echo "Manifest:"
echo "  ${MANIFEST}"
echo
echo "Files in bundle:"
tar -tzf "${ARCHIVE}" | wc -l
echo
echo "Before uploading to a new chat, optionally inspect with:"
echo "  tar -tzf '${ARCHIVE}' | less"
echo
echo "Recommended:"
echo "  attach '${ARCHIVE}'"
echo "  attach 'ZEN_HANDOFF.md'"
echo "  then paste the New-chat starter prompt from the handoff"
