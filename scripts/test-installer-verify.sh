#!/usr/bin/env bash
# test-installer-verify.sh — CI test vector for the installer trust chain.
#
# Guards the verify mechanism install.sh relies on (ssh-keygen -Y verify over the
# signed aggregate manifest) and the trust-anchor constants. Uses a THROWAWAY test
# key — never the release key. The day someone touches the allowed_signers pin, the
# namespace, the rollback floor, or reintroduces a weaker fallback, this test says so.
#
# Runs offline (no network): generates a key, a known manifest and signature locally.
#   scripts/test-installer-verify.sh
set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SH="$SCRIPTS_DIR/install.sh"
PASS=0; FAIL=0
ok()   { printf '  ok   %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  FAIL %s\n' "$1" >&2; FAIL=$((FAIL+1)); }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }

[ -f "$INSTALL_SH" ] || { echo "FAIL: install.sh not found at $INSTALL_SH" >&2; exit 1; }
command -v ssh-keygen >/dev/null 2>&1 || { echo "FAIL: ssh-keygen required" >&2; exit 1; }

# Pull the constants from install.sh so the test stays in sync with the installer.
NS="$(sed -n 's/^RCHAT_SIGN_NAMESPACE="\([^"]*\)".*/\1/p' "$INSTALL_SH")"
FLOOR="$(sed -n 's/^RCHAT_MIN_VERSION="\([^"]*\)".*/\1/p' "$INSTALL_SH")"
[ -n "$NS" ] || { echo "FAIL: could not read RCHAT_SIGN_NAMESPACE from install.sh" >&2; exit 1; }
[ -n "$FLOOR" ] || { echo "FAIL: could not read RCHAT_MIN_VERSION from install.sh" >&2; exit 1; }
echo "namespace=$NS floor=$FLOOR"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
KEY="$WORK/testkey"; MAN="$WORK/SHA256SUMS.txt"; SIG="$MAN.sig"; AS="$WORK/allowed_signers"

ssh-keygen -t ed25519 -f "$KEY" -N "" -C "$NS" -q
printf '%s %s\n' "$NS" "$(ssh-keygen -y -f "$KEY")" > "$AS"
# A second throwaway key, used by the e2e "signed by a different key" case below.
ssh-keygen -t ed25519 -f "$WORK/otherkey" -N "" -q

# Known manifest: version header (covered by the signature) + one artifact line.
ART_HASH="$(printf 'test-binary-bytes' | shasum -a 256 | awk '{print $1}')"
{
    printf '# rchat-release signed manifest\n'
    printf '# version: %s\n' "$FLOOR"
    printf '%s  rchat-server-macos-universal\n' "$ART_HASH"
} > "$MAN"

echo "── signature verify (the exact command install.sh uses) ──"
ssh-keygen -Y sign -f "$KEY" -n "$NS" "$MAN" 2>/dev/null
check "known key + manifest + signature verifies green" \
    'ssh-keygen -Y verify -f "$AS" -I "$NS" -n "$NS" -s "$SIG" < "$MAN" >/dev/null 2>&1'

cp "$MAN" "$WORK/good.man"
printf 'tampered\n' >> "$MAN"
check "tampered manifest is a HARD failure" \
    '! ssh-keygen -Y verify -f "$AS" -I "$NS" -n "$NS" -s "$SIG" < "$MAN" >/dev/null 2>&1'
cp "$WORK/good.man" "$MAN"

check "wrong namespace is a HARD failure" \
    '! ssh-keygen -Y verify -f "$AS" -I "$NS" -n "not-$NS" -s "$SIG" < "$MAN" >/dev/null 2>&1'
check "missing signature is a HARD failure" \
    '! ssh-keygen -Y verify -f "$AS" -I "$NS" -n "$NS" -s "$WORK/absent.sig" < "$MAN" >/dev/null 2>&1'

echo "── manifest parsing (version floor + artifact lookup) ──"
MVER="$(grep -m1 '^# version: ' "$MAN" | awk '{print $3}')"
check "version header parses to the floor value" '[ "$MVER" = "$FLOOR" ]'
LOOKUP="$(awk -v n="rchat-server-macos-universal" '$2==n{print $1}' "$MAN")"
check "artifact line lookup returns the manifest hash" '[ "$LOOKUP" = "$ART_HASH" ]'
check "absent artifact lookup is empty (installer refuses)" \
    '[ -z "$(awk -v n="rchat-server-not-present" '\''$2==n{print $1}'\'' "$MAN")" ]'

# version_lt: numeric dot compare (mirrors install.sh).
version_lt() {
    vlt_rest=${1#*.}
    vlt_a1=${1%%.*}; vlt_a2=${vlt_rest%%.*}; vlt_a3=${vlt_rest#*.}
    vlt_rest=${2#*.}
    vlt_b1=${2%%.*}; vlt_b2=${vlt_rest%%.*}; vlt_b3=${vlt_rest#*.}
    [ "$vlt_a1" -lt "$vlt_b1" ] && return 0
    [ "$vlt_a1" -gt "$vlt_b1" ] && return 1
    [ "$vlt_a2" -lt "$vlt_b2" ] && return 0
    [ "$vlt_a2" -gt "$vlt_b2" ] && return 1
    [ "$vlt_a3" -lt "$vlt_b3" ] && return 0
    return 1
}
echo "── rollback floor compare ──"
# These literals exercise version_lt semantics only; they are independent of
# the current $FLOOR value and must not be "helpfully" derived from it.
check "2.0.9 < 2.1.0 (older refused)" 'version_lt 2.0.9 2.1.0'
check "2.1.0 == 2.1.0 not below (accepted)" '! version_lt 2.1.0 2.1.0'
check "2.2.0 > 2.1.0 not below (accepted)" '! version_lt 2.2.0 2.1.0'
check "1.9.9 < 2.0.0 (older refused)" 'version_lt 1.9.9 2.0.0'

echo "── install.sh design invariants (no weaker fallback, anchors compiled in) ──"
check "compiled-in allowed_signers anchor present" 'grep -q "^RCHAT_ALLOWED_SIGNERS=" "$INSTALL_SH"'
check "compiled-in rollback floor present" 'grep -q "^RCHAT_MIN_VERSION=" "$INSTALL_SH"'
check "verify_manifest fetches the signed manifest" 'grep -q "SHA256SUMS.txt.sig" "$INSTALL_SH"'
check "verify_manifest uses ssh-keygen -Y verify" 'grep -q "ssh-keygen -Y verify" "$INSTALL_SH"'
# The binary download must NOT fetch a per-artifact .sha256 from the download host.
check "no per-artifact .sha256 fetch fallback" '! grep -q "\$ART\.sha256" "$INSTALL_SH"'
check "verify_manifest is wired before downloads" 'grep -q "^    verify_manifest || die" "$INSTALL_SH"'
# The shipped anchor LINE must carry the real release key, never the placeholder
# (install.sh also contains the placeholder string in its fail-closed detector —
# that one stays; only the RCHAT_ALLOWED_SIGNERS assignment is pinned here).
check "real install.sh anchor line is not the placeholder" \
    '! grep "^RCHAT_ALLOWED_SIGNERS=" "$INSTALL_SH" | grep -q "REPLACE_WITH_RELEASE_PUBKEY"'
# ...and "not the placeholder" is not enough: that check accepts ANY real key,
# and every e2e case below injects its own anchor, so a PR swapping
# RCHAT_ALLOWED_SIGNERS for a different real key would go green. Pin the derived
# fingerprint instead of the key text, so the test breaks if either the key
# material or the identity changes. A legitimate rotation edits this constant
# and install.sh's anchor in the same PR — the visible two-file change a
# reviewer must notice. (In the PR lane this restores the invariant the release
# lane's anchor-custody guard enforces.)
EXPECTED_FP="SHA256:Rk40bozYxBNd4VOYY6kmZ9HiF+F5T8fY3yfAyGWA5bU"
ANCHOR_KEY="$(sed -n "s/^RCHAT_ALLOWED_SIGNERS='[^ ]* \(ssh-ed25519 [A-Za-z0-9+/=]*\).*/\1/p" "$INSTALL_SH")"
printf '%s\n' "$ANCHOR_KEY" > "$WORK/anchor.pub"
check "shipped anchor is the rchat-release key ($EXPECTED_FP)" \
    '[ "$(ssh-keygen -lf "$WORK/anchor.pub" | awk "{print \$2}")" = "$EXPECTED_FP" ]'

echo "── verify_manifest end-to-end (install.sh's OWN code, local file:// origin) ──"
# Exercise the shipped verify_manifest, not a re-implementation (the version_lt
# mirror above can drift; these cases run the real function).
VFUNCS="$WORK/verify-funcs.sh"
{
    sed -n '/^say()/p;/^verr()/p' "$INSTALL_SH"
    sed -n '/^version_lt()/,/^}/p' "$INSTALL_SH"
    sed -n '/^verify_manifest()/,/^}/p' "$INSTALL_SH"
} > "$VFUNCS"
grep -q 'verify_manifest()' "$VFUNCS" || { echo "FAIL: could not extract verify_manifest from install.sh" >&2; exit 1; }
# Completeness guard: the sed range above ends at the first column-0 '}', which
# today is the function's end; a nested block or a heredoc containing one would
# truncate the extraction silently. Assert it reached the function's last known
# statement so a truncated function fails here, not inside the e2e cases.
grep -q 'VERIFIED_MANIFEST="\$vm_mfile"' "$VFUNCS" || { echo "FAIL: verify_manifest extraction truncated (missing tail)" >&2; exit 1; }
GOOD_ANCHOR="$NS $(ssh-keygen -y -f "$KEY")"
# run_verify <manifest-version> <requested-version> [signing-key] [anchor] [tamper]
# Signs a manifest locally, lays it out as file://$WORK/e2e/<req>/, and runs the
# real verify_manifest in a subshell. get() is the file:// stand-in for the
# pinned-https downloader install.sh defines in main.
run_verify() {
    local mver="$1" req="$2" skey="${3:-$KEY}" anchor="${4:-$GOOD_ANCHOR}" tamper="${5:-}"
    local dir="$WORK/e2e/$req"
    mkdir -p "$dir"
    {
        printf '# rchat-release signed manifest\n'
        printf '# version: %s\n' "$mver"
        printf '%s  rchat-server-macos-universal\n' "$ART_HASH"
    } > "$dir/SHA256SUMS.txt"
    rm -f "$dir/SHA256SUMS.txt.sig"  # cases reuse dirs; never let ssh-keygen prompt or leave a stale sig
    ssh-keygen -Y sign -f "$skey" -n "$NS" "$dir/SHA256SUMS.txt" 2>/dev/null
    [ -z "$tamper" ] || printf 'tampered\n' >> "$dir/SHA256SUMS.txt"
    (
        REL="file://$dir"
        VERSION="$req"
        DRY=0
        RCHAT_MIN_VERSION="$FLOOR"
        RCHAT_SIGN_NAMESPACE="$NS"
        RCHAT_ALLOWED_SIGNERS="$anchor"
        VERIFIED_MANIFEST=""
        TMP="$WORK/e2e-tmp"; mkdir -p "$TMP"
        get() { src="${1#file://}"; cp "$src" "$2"; }
        # shellcheck disable=SC1090
        source "$VFUNCS"
        verify_manifest
    ) >/dev/null 2>&1
}
# This is the ONLY case that requires success; every case after it asserts
# `! run_verify …`, so any failure — including a broken harness — would count
# as a pass for them. Do not remove the positive case: it is what fails when
# the harness breaks, and it carries the whole negative suite.
check "e2e: valid sig + version == requested == floor -> accepted" \
    'run_verify "$FLOOR" "$FLOOR"'
check "e2e: SIGNED suffixed version above floor (2.1.1-rc1) -> hard fail" \
    '! run_verify "2.1.1-rc1" "2.1.1-rc1"'
check "e2e: SIGNED suffixed version below floor (2.0.9-rc1) -> hard fail" \
    '! run_verify "2.0.9-rc1" "2.0.9-rc1"'
check "e2e: signed manifest for a DIFFERENT release (1.9.9 vs $FLOOR) -> hard fail" \
    '! run_verify "1.9.9" "$FLOOR"'
check "e2e: strict below-floor version (2.0.9) -> hard fail" \
    '! run_verify "2.0.9" "2.0.9"'
check "e2e: tampered manifest after signing -> hard fail" \
    '! run_verify "$FLOOR" "$FLOOR" "$KEY" "$GOOD_ANCHOR" tamper'
check "e2e: placeholder anchor -> hard fail" \
    '! run_verify "$FLOOR" "$FLOOR" "$KEY" "$NS ssh-ed25519 AAAA_REPLACE_WITH_RELEASE_PUBKEY rchat-release"'
check "e2e: signature by a different key -> hard fail" \
    '! run_verify "$FLOOR" "$FLOOR" "$WORK/otherkey"'

echo ""
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "installer-verify test vector: ALL GREEN"
