#!/bin/sh
# rChat relay installer (POSIX sh).
#
#   curl -fsSL https://raw.githubusercontent.com/PDG-Global/rchat-core/<tag>/scripts/install.sh -o install.sh
#   sudo sh install.sh
#   sudo sh install.sh --version 2.1.0 --dry-run
#
# Downloads the rchat-server binary for this platform and installs it. Every
# downloaded file is verified against the SIGNED aggregate manifest
# (SHA256SUMS.txt + SHA256SUMS.txt.sig, OpenSSH ed25519, verified with
# ssh-keygen -Y verify against the release public key compiled into this
# script). There is no fallback to a per-artifact .sha256 from the download
# host: a degraded path is exactly the attacker's next move, so absent or
# invalid signature, missing version header, or a version below the compiled
# rollback floor are all hard failures. The script never overwrites an
# existing config, relay identity key or service file, and it never writes a
# config or a key. The whole script is one function called on the last line,
# so a truncated download runs nothing.
#
# Options: --version V  --gnu  --dry-run  --prefix DIR  --base-url URL
# Exit codes: 0 ok; 1 unsupported platform or bad option; 2 download failure;
#             3 verification failure (bad signature, checksum mismatch, or a
#             version below the rollback floor);
#             4 install-stage failure (mkdir, install, user creation);
#             130 interrupted.

set -eu
PATH="$PATH:/usr/sbin:/sbin"

# -- Release trust anchors (compiled into this tagged installer, NOT fetched
#    from the download host) --
# The release public key (allowed_signers format) and the rollback floor are
# baked in here at tag time, so write access to the download host cannot move
# them. RELEASE PUBKEY: the public half of the rChat release signing key. The
# secret half is held in release custody. Rotating = new key + a new anchor
# here, in a new release; RCHAT_MIN_VERSION below already keeps older
# manifests out.
RCHAT_ALLOWED_SIGNERS='rchat-release ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJT7YB8nsEtovRSnq4lD/CdXpCVr2+lozwBBV24/qbjM rchat-release'
RCHAT_SIGN_NAMESPACE="rchat-release"
# Rollback floor: minimum acceptable release version. Bump at tag time
# (same ceremony as the release version). A genuinely signed OLD release
# served by a compromised download host is refused because its signed
# manifest version is below this floor.
RCHAT_MIN_VERSION="2.1.1"
VERIFIED_MANIFEST=""

TMP=""
NEWBIN=""

cleanup() {
    [ -z "$NEWBIN" ] || rm -f "$NEWBIN"
    [ -z "$TMP" ] || rm -rf "$TMP"
}

die() { code=$1; shift; echo "install.sh: $*" >&2; exit "$code"; }
say() { echo "==> $*"; }
verr() { echo "install.sh: $*" >&2; }
run() { "$@" || die 4 "failed: $*"; }

# Rollback floor: numeric dot-version compare — true if a < b (e.g. 2.0.9 < 2.1.0).
# Both arguments are strict X.Y.Z (verify_manifest rejects anything else).
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

# Fetch + verify the signed aggregate manifest ONCE, before any download is
# trusted. Fail closed: absent/invalid manifest or signature, missing or
# pre-8.0 OpenSSH, an unfilled release pubkey, or a version below the floor
# are all HARD failures. There is NO fallback to a per-artifact .sha256 from
# the download host. Uses get() (the pinned-https downloader set up in main)
# and the version/paths resolved there. Returns 0 with VERIFIED_MANIFEST set,
# or 1 after explaining on stderr.
verify_manifest() {
    if [ "$DRY" = 1 ]; then
        say "dry run: would fetch and verify the signed release manifest for $VERSION"
        return 0
    fi

    # The verifier must be a known quantity on the box: OpenSSH >= 8.0 (ed25519 -Y).
    if ! command -v ssh-keygen >/dev/null 2>&1; then
        verr "ssh-keygen not found."
        verr "rChat verifies the release manifest with OpenSSH (ssh-keygen -Y verify, needs OpenSSH >= 8.0)."
        verr "Install OpenSSH and retry. Refusing to install unverified."
        return 1
    fi
    vm_sshver=$(ssh -V 2>&1 | sed -n 's/^OpenSSH_\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
    if [ -n "$vm_sshver" ] && [ "${vm_sshver%%.*}" -lt 8 ]; then
        verr "OpenSSH $vm_sshver is too old (need >= 8.0 for ssh-keygen -Y verify)."
        verr "Upgrade OpenSSH and retry. Refusing to install unverified."
        return 1
    fi

    # Compiled-in trust anchor must be filled (fail closed on a placeholder build).
    case "$RCHAT_ALLOWED_SIGNERS" in
        *REPLACE_WITH_RELEASE_PUBKEY*)
            verr "This installer was built without the rChat release public key."
            verr "Refusing to install unverified. Use an official tagged installer from r-chat.net."
            return 1 ;;
    esac

    vm_mfile="$TMP/SHA256SUMS.txt"; vm_sfile="$TMP/SHA256SUMS.txt.sig"; vm_asfile="$TMP/allowed_signers"

    if ! get "$REL/SHA256SUMS.txt" "$vm_mfile"; then
        verr "Could not fetch the signed manifest for $VERSION."
        verr "Looked for: $REL/SHA256SUMS.txt"
        verr "Refusing to install without a verified manifest (no fallback). Retry or check the download host."
        return 1
    fi
    if ! get "$REL/SHA256SUMS.txt.sig" "$vm_sfile"; then
        verr "Could not fetch the manifest signature for $VERSION."
        verr "Refusing to install without a verified manifest (no fallback)."
        return 1
    fi

    printf '%s\n' "$RCHAT_ALLOWED_SIGNERS" > "$vm_asfile"
    if ! ssh-keygen -Y verify -f "$vm_asfile" -I "$RCHAT_SIGN_NAMESPACE" -n "$RCHAT_SIGN_NAMESPACE" -s "$vm_sfile" < "$vm_mfile" >/dev/null 2>&1; then
        verr "Manifest signature verification FAILED for $VERSION."
        verr "The release manifest is not signed by the rChat release key. Refusing to install."
        verr "(Hard failure — there is no weaker fallback check.)"
        return 1
    fi
    say "manifest signature verified ($RCHAT_SIGN_NAMESPACE)"

    # Rollback floor: the signed manifest carries its version; refuse any
    # version below the floor baked into this tagged installer.
    vm_mver=$(grep -m1 '^# version: ' "$vm_mfile" | awk '{print $3}')
    if [ -z "$vm_mver" ]; then
        verr "Signed manifest carries no version header — cannot check the rollback floor. Refusing."
        return 1
    fi
    # Strict release version: X.Y.Z only. A suffixed version (e.g. 2.1.0-rc1)
    # must not reach version_lt's numeric tests.
    if ! printf '%s\n' "$vm_mver" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        verr "Manifest version '$vm_mver' is not a strict X.Y.Z release version. Refusing."
        return 1
    fi
    # The signed manifest must name the release we asked for: VERSION comes
    # from the download host, so a valid signature for a different release is
    # not a pass.
    if [ "$vm_mver" != "$VERSION" ]; then
        verr "Manifest version $vm_mver does not match the requested release $VERSION. Refusing."
        return 1
    fi
    if version_lt "$vm_mver" "$RCHAT_MIN_VERSION"; then
        verr "Manifest version $vm_mver is below the minimum $RCHAT_MIN_VERSION baked into this installer."
        verr "Refusing a possible rollback to an older release. Use a current installer from r-chat.net."
        return 1
    fi
    VERIFIED_MANIFEST="$vm_mfile"
    say "manifest version $vm_mver accepted (floor $RCHAT_MIN_VERSION)"
    return 0
}

# Hash of an artifact from the verified manifest (empty if not listed).
manifest_hash() {
    awk -v n="$1" '$2==n{print $1}' "$VERIFIED_MANIFEST"
}

usage() {
    echo "Usage: install.sh [--version V] [--gnu] [--dry-run] [--prefix DIR] [--base-url URL]"
}

main() {
    BASE_URL="https://assets.r-chat.net"
    EXPLICIT_BASE=0
    PREFIX="/"
    VERSION=""
    GNU=0
    DRY=0

    while [ $# -gt 0 ]; do
        case "$1" in
            --version) [ $# -ge 2 ] || die 1 "--version needs a value"; VERSION=$2; shift 2 ;;
            --gnu) GNU=1; shift ;;
            --dry-run) DRY=1; shift ;;
            --prefix) [ $# -ge 2 ] || die 1 "--prefix needs a value"; PREFIX=$2; shift 2 ;;
            --base-url) [ $# -ge 2 ] || die 1 "--base-url needs a value"; BASE_URL=$2; EXPLICIT_BASE=1; shift 2 ;;
            -h|--help) usage; exit 0 ;;
            *) usage >&2; die 1 "unknown option: $1" ;;
        esac
    done

    BASE_URL=${BASE_URL%/}
    ROOT=${PREFIX%/}   # "" for "/", so "$ROOT/usr/..." works for both

    # https only. Plain http is allowed only for a base URL given explicitly.
    PROTO="=https"
    case "$BASE_URL" in
        https://*) ;;
        http://*)
            [ "$EXPLICIT_BASE" = 1 ] || die 1 "refusing a non-https base URL"
            PROTO="=http,https" ;;
        *) die 1 "base URL must start with https://" ;;
    esac

    OS=${RCHAT_INSTALL_OS:-$(uname -s)}
    ARCH=${RCHAT_INSTALL_ARCH:-$(uname -m)}

    SERVICE=""
    case "$OS" in
        Linux)
            SERVICE=systemd
            case "$ARCH" in
                x86_64|amd64)
                    if [ "$GNU" = 1 ]; then ART=rchat-server-x86_64-linux-gnu; else ART=rchat-server-x86_64-linux-static; fi ;;
                aarch64|arm64)
                    if [ "$GNU" = 1 ]; then ART=rchat-server-aarch64-linux-gnu; else ART=rchat-server-aarch64-linux-static; fi ;;
                armv7l) ART=rchat-server-armv7-linux ;;
                riscv64) ART=rchat-server-riscv64gc-linux-gnu ;;
                *) die 1 "unsupported platform: $OS/$ARCH" ;;
            esac ;;
        FreeBSD)
            SERVICE=rc
            case "$ARCH" in
                amd64|x86_64) ART=rchat-server-x86_64-freebsd ;;
                *) die 1 "unsupported platform: $OS/$ARCH" ;;
            esac ;;
        Darwin)
            SERVICE=launchd
            ART=rchat-server-macos-universal ;;
        *) die 1 "unsupported platform: $OS/$ARCH" ;;
    esac

    # Downloader (curl preferred; fetch cannot pin redirects to https).
    if command -v curl >/dev/null 2>&1; then
        get() { curl -fsSL --proto "$PROTO" --proto-redir "$PROTO" --tlsv1.2 -o "$2" "$1"; }
    elif command -v fetch >/dev/null 2>&1; then
        get() { fetch -qo "$2" "$1"; }
    else
        die 2 "neither curl nor fetch found"
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        hash_of() { sha256sum "$1" | cut -d' ' -f1; }
    elif command -v shasum >/dev/null 2>&1; then
        hash_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
    elif command -v sha256 >/dev/null 2>&1; then
        hash_of() { sha256 -q "$1"; }
    else
        die 2 "no sha256 tool found (sha256sum, shasum or sha256)"
    fi

    TMP=$(mktemp -d "${TMPDIR:-/tmp}/rchat-install.XXXXXX") || die 2 "cannot create a temporary directory"
    trap cleanup EXIT
    trap 'exit 130' HUP INT TERM

    if [ -z "$VERSION" ]; then
        get "$BASE_URL/VERSION" "$TMP/VERSION" || die 2 "cannot download $BASE_URL/VERSION"
        VERSION=$(tr -d ' \r\n\t' < "$TMP/VERSION")
    fi
    case "$VERSION" in
        ""|[!0-9]*|*[!0-9A-Za-z._-]*|*..*) die 2 "invalid version: $VERSION" ;;
    esac

    BIN_DIR="$ROOT/usr/local/bin"
    REL="$BASE_URL/$VERSION"
    SVC_SRC=""; SVC_DST=""; SVC_MODE=0644; SVC_ALT1=""; SVC_ALT2=""
    case "$SERVICE" in
        systemd)
            CONF_DIR="$ROOT/etc/rchat"; STATE_DIR="$ROOT/var/lib/rchat"; STATE_MODE=0700
            SVC_SRC=rchat-server.service
            SVC_DST="$ROOT/etc/systemd/system/rchat-server.service"
            SVC_ALT1="$ROOT/lib/systemd/system/rchat-server.service"
            SVC_ALT2="$ROOT/usr/lib/systemd/system/rchat-server.service" ;;
        rc)
            CONF_DIR="$ROOT/usr/local/etc/rchat"; STATE_DIR="$ROOT/var/db/rchat"; STATE_MODE=0700
            SVC_SRC=rchat.rc; SVC_DST="$ROOT/usr/local/etc/rc.d/rchat"; SVC_MODE=0555 ;;
        *)
            CONF_DIR="$ROOT/usr/local/etc/rchat"; STATE_DIR="" ;;
    esac
    LOG_DIR=""
    [ "$SERVICE" = rc ] && LOG_DIR="$ROOT/var/log/rchat"

    say "rchat-server $VERSION for $OS/$ARCH ($ART)"

    if [ "$DRY" = 1 ]; then
        say "dry run: nothing is downloaded or installed"
        say "would fetch and verify the signed release manifest $REL/SHA256SUMS.txt (+ .sig)"
        say "would download $REL/$ART and verify it against the signed manifest"
        say "would install it to $BIN_DIR/rchat-server (0755, atomic)"
        [ -z "$SVC_SRC" ] || say "would install $REL/$SVC_SRC to $SVC_DST ($SVC_MODE), verified against the signed manifest, unless a unit exists"
        [ "$ROOT" != "" ] || [ -z "$STATE_DIR" ] || say "would create the rchat user if missing"
        say "would create $CONF_DIR${STATE_DIR:+, $STATE_DIR}${LOG_DIR:+, $LOG_DIR} (no config or key is written)"
        [ "$SERVICE" != launchd ] || say "would print launchd guidance (no service file is installed)"
        exit 0
    fi

    # Verify the signed release manifest once, before any download is trusted.
    verify_manifest || die 3 "release manifest verification failed; nothing was installed"

    say "downloading"
    get "$REL/$ART" "$TMP/$ART" || die 2 "cannot download $REL/$ART"

    # Verify against the SIGNED manifest (verified once above), never a
    # per-artifact .sha256 fetched from the download host. No fallback.
    WANT=$(manifest_hash "$ART")
    [ -n "$WANT" ] || die 3 "$ART is not listed in the signed manifest; refusing to install"
    GOT=$(hash_of "$TMP/$ART" | tr 'A-F' 'a-f')
    if [ "$WANT" != "$GOT" ]; then
        die 3 "checksum mismatch for $ART; nothing was installed"
    fi
    say "sha256 verified against the signed manifest"

    # Fetch the service file before touching the prefix.
    UNIT_EXISTS=0
    if [ -n "$SVC_SRC" ]; then
        for u in "$SVC_DST" "$SVC_ALT1" "$SVC_ALT2"; do
            if [ -n "$u" ] && [ -e "$u" ]; then UNIT_EXISTS=1; say "kept existing $u"; break; fi
        done
    fi
    SVC_OK=0
    if [ -n "$SVC_SRC" ] && [ "$UNIT_EXISTS" = 0 ]; then
        if get "$REL/$SVC_SRC" "$TMP/$SVC_SRC"; then
            # The service file is installed; it must verify against the same
            # signed manifest as the binary.
            SWANT=$(manifest_hash "$SVC_SRC")
            [ -n "$SWANT" ] || die 3 "$SVC_SRC is not listed in the signed manifest; refusing to install it"
            SGOT=$(hash_of "$TMP/$SVC_SRC" | tr 'A-F' 'a-f')
            [ "$SWANT" = "$SGOT" ] || die 3 "checksum mismatch for $SVC_SRC; nothing was installed"
            SVC_OK=1
        else
            say "warning: cannot download $SVC_SRC; skipping the service file"
        fi
    fi

    # The service user, state and log directories come first, so a failure
    # leaves nothing half-installed. Only a real install (PREFIX=/) creates the
    # user and chowns; under a prefix, or when no user tool exists, the
    # commands are printed.
    MANUAL=""
    REAL_USER=0
    if [ -n "$STATE_DIR" ]; then
        if [ "$ROOT" = "" ]; then
            REAL_USER=1
            if [ "$SERVICE" = rc ]; then
                pw usershow rchat >/dev/null 2>&1 || { run pw useradd rchat -d /var/db/rchat -s /usr/sbin/nologin -c "rChat relay" -w no; say "created the rchat user"; }
            elif ! id rchat >/dev/null 2>&1; then
                NOLOGIN=/bin/false
                for sh_ in /usr/sbin/nologin /sbin/nologin /bin/false; do
                    if [ -x "$sh_" ]; then NOLOGIN=$sh_; break; fi
                done
                if command -v useradd >/dev/null 2>&1; then
                    run useradd --system --user-group --home-dir /var/lib/rchat --no-create-home --shell "$NOLOGIN" --comment "rChat relay" rchat
                    say "created the rchat user"
                elif command -v adduser >/dev/null 2>&1 && command -v addgroup >/dev/null 2>&1; then
                    run addgroup -S rchat
                    run adduser -S -D -H -h /var/lib/rchat -s "$NOLOGIN" -G rchat rchat
                    say "created the rchat user"
                else
                    REAL_USER=0
                    say "warning: no useradd or adduser found; create the rchat user yourself"
                fi
            fi
        fi
        if [ "$REAL_USER" = 1 ]; then
            run install -d -o rchat -g rchat -m "$STATE_MODE" "$STATE_DIR"
            [ -z "$LOG_DIR" ] || run install -d -o rchat -g rchat -m 0750 "$LOG_DIR"
        else
            run mkdir -p "$STATE_DIR"
            [ -z "$LOG_DIR" ] || run mkdir -p "$LOG_DIR"
            MANUAL="  0. Create the rchat user on the target host (useradd --system --user-group rchat, or pw useradd), then run
       install -d -o rchat -g rchat -m $STATE_MODE /${STATE_DIR#"$ROOT"/}${LOG_DIR:+
       install -d -o rchat -g rchat -m 0750 /${LOG_DIR#"$ROOT"/}}
       install -d -o root -g rchat -m 0750 /${CONF_DIR#"$ROOT"/}"
        fi
    fi
    if [ ! -d "$CONF_DIR" ]; then
        if [ "$REAL_USER" = 1 ]; then run install -d -m 0750 -o root -g rchat "$CONF_DIR"; else run mkdir -p "$CONF_DIR"; fi
        say "created $CONF_DIR"
    fi

    HAD_BIN=0
    [ ! -e "$BIN_DIR/rchat-server" ] || HAD_BIN=1
    run mkdir -p "$BIN_DIR"
    NEWBIN="$BIN_DIR/.rchat-server.new.$$"
    run install -m 0755 "$TMP/$ART" "$NEWBIN"
    run mv -f "$NEWBIN" "$BIN_DIR/rchat-server"
    NEWBIN=""
    say "installed $BIN_DIR/rchat-server"

    if [ "$SVC_OK" = 1 ]; then
        run mkdir -p "$(dirname "$SVC_DST")"
        run install -m "$SVC_MODE" "$TMP/$SVC_SRC" "$SVC_DST"
        say "installed $SVC_DST"
    fi

    # The invite holds the relay's secret WebSocket path: this script only
    # prints the command, so the invite never lands in an install log.
    INVITE_NOTE="Anyone with this invite can reach your relay. They can't read messages."
    echo
    echo "rchat-server $VERSION is installed. Next steps:"
    [ -z "$MANUAL" ] || echo "$MANUAL"
    echo "  1. Copy the config template from https://docs.r-chat.net to $CONF_DIR/server.toml and edit it,
    then chmod 0640 it (the rchat group must be able to read it)."
    case "$SERVICE" in
        systemd)
            echo "     Under [server] set: relay_identity_path = \"/var/lib/rchat/relay_identity.key\""
            echo "     Under [server.acme] set: cache_dir = \"/var/lib/rchat/acme\""
            echo "  2. Create the relay identity key as the service user, once (it refuses to overwrite one):"
            echo "       sudo -u rchat /usr/local/bin/rchat-server --config /etc/rchat/server.toml --init-relay-identity"
            echo "  3. Give this relay its own decoy website (what a browser or probe sees), as the service user:"
            echo "       sudo -u rchat /usr/local/bin/rchat-server --config /etc/rchat/server.toml --render-decoy /var/lib/rchat/decoy --host your.domain.example"
            echo "     then under [server.decoy] set: root = \"/var/lib/rchat/decoy\""
            echo "  4. systemctl daemon-reload && systemctl enable --now rchat-server"
            echo "  5. Invite people: with host = \"your.domain.example\" under [server.decoy], print the invite"
            echo "     (a link and a QR code that set up rChat for this relay) as the service user:"
            echo "       sudo -u rchat /usr/local/bin/rchat-server --config /etc/rchat/server.toml --print-invite"
            echo "     $INVITE_NOTE" ;;
        rc)
            echo "     Under [server] set: relay_identity_path = \"/var/db/rchat/relay_identity.key\""
            echo "     Under [server.acme] set: cache_dir = \"/var/db/rchat/acme\""
            echo "  2. Create the relay identity key as the service user, once (it refuses to overwrite one):"
            echo "       su -m rchat -c '/usr/local/bin/rchat-server --config /usr/local/etc/rchat/server.toml --init-relay-identity'"
            echo "  3. Give this relay its own decoy website (what a browser or probe sees), as the service user:"
            echo "       su -m rchat -c '/usr/local/bin/rchat-server --config /usr/local/etc/rchat/server.toml --render-decoy /var/db/rchat/decoy --host your.domain.example'"
            echo "     then under [server.decoy] set: root = \"/var/db/rchat/decoy\""
            echo "  4. sysrc rchat_enable=YES && service rchat start"
            echo "  5. Invite people: with host = \"your.domain.example\" under [server.decoy], print the invite"
            echo "     (a link and a QR code that set up rChat for this relay) as the service user:"
            echo "       su -m rchat -c '/usr/local/bin/rchat-server --config /usr/local/etc/rchat/server.toml --print-invite'"
            echo "     $INVITE_NOTE" ;;
        launchd)
            echo "  2. macOS installs the binary only. Run the relay under launchd with a plist of your own"
            echo "     that starts: $BIN_DIR/rchat-server --config $CONF_DIR/server.toml"
            echo "  3. Invite people: with host = \"your.domain.example\" under [server.decoy], print the invite"
            echo "     (a link and a QR code that set up rChat for this relay):"
            echo "       /${BIN_DIR#"$ROOT"/}/rchat-server --config /${CONF_DIR#"$ROOT"/}/server.toml --print-invite"
            echo "     $INVITE_NOTE" ;;
    esac
    if [ "$HAD_BIN" = 1 ]; then
        case "$SERVICE" in
            systemd) echo "A previous binary was replaced: systemctl restart rchat-server to run $VERSION." ;;
            rc) echo "A previous binary was replaced: service rchat restart to run $VERSION." ;;
            *) echo "A previous binary was replaced: restart the relay to run $VERSION." ;;
        esac
    fi
}

main "$@"
