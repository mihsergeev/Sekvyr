#!/bin/sh
# Run only inside the dedicated Alpine 3.24 target-platform BuildKit stage.
set -eu
umask 077

fail() { printf '%s\n' "$1" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail 'SQLite builder must run as root in its isolated stage'
[ ! -L /tmp/signing ] || fail 'Signing mount must not be a symlink'
awk '$5 == "/tmp/signing" { for (i=6; i<=NF; i++) if ($i == "-" && $(i+1) == "tmpfs") ok=1 } END { exit !ok }' \
	/proc/self/mountinfo || fail 'A dedicated BuildKit tmpfs mount at /tmp/signing is required'
case "$(cat /etc/alpine-release)" in 3.24.*) ;; *) fail 'Alpine 3.24 builder required';; esac
arch=$(apk --print-arch)
case "$arch" in x86_64|aarch64) ;; *) fail 'Unsupported SQLite artifact architecture';; esac
case "${SOURCE_DATE_EPOCH:-}" in ''|*[!0-9]*) fail 'Explicit numeric SOURCE_DATE_EPOCH is required';; esac
[ "$SOURCE_DATE_EPOCH" -gt 0 ] || fail 'Positive SOURCE_DATE_EPOCH is required'
export SOURCE_DATE_EPOCH

source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ -f "$source_dir/APKBUILD" ] || fail 'APKBUILD missing'
[ ! -e /out ] || [ -d /out ] && [ ! -L /out ] || fail 'Invalid output directory'
mkdir -p /out
[ -z "$(ls -A /out)" ] || fail 'Output directory must be empty'
[ -z "$(ls -A /tmp/signing)" ] || fail 'Signing tmpfs must be empty'

# All signing material, HOME and abuild user configuration live on this tmpfs.
export HOME=/tmp/signing/home
export ABUILD_USERDIR=/tmp/signing/abuild
export ABUILD_USERCONF=/tmp/signing/abuild/abuild.conf
export PACKAGER='Sekvyr Project <maintainer@sekvyr.invalid>'
export PACKAGER_PRIVKEY=/tmp/signing/sekvyr-sqlite-build.rsa
export PACKAGER_PUBKEY=/tmp/signing/sekvyr-sqlite-build.rsa.pub
mkdir -p "$HOME" "$ABUILD_USERDIR" /tmp/signing/verify-keys
openssl genrsa -out "$PACKAGER_PRIVKEY" 4096
openssl rsa -in "$PACKAGER_PRIVKEY" -pubout -out "$PACKAGER_PUBKEY" 2>/dev/null
install -m644 "$PACKAGER_PUBKEY" /tmp/signing/verify-keys/sekvyr-sqlite-build.rsa.pub
# Abuild verifies new APKs while creating its index. Trust only this RUN's key.
export APK='apk --no-network --keys-dir /tmp/signing/verify-keys'
printf '%s\n' 'PACKAGER="Sekvyr Project <maintainer@sekvyr.invalid>"' \
	'PACKAGER_PRIVKEY="/tmp/signing/sekvyr-sqlite-build.rsa"' \
	'PACKAGER_PUBKEY="/tmp/signing/sekvyr-sqlite-build.rsa.pub"' > "$ABUILD_USERCONF"

# A fresh work directory prevents reuse of packages signed by another invocation.
work=$(mktemp -d /tmp/sqlite-build.XXXXXX)
mkdir -p "$work/sekvyr/sqlite" "$work/packages" "$work/distfiles"
cp "$source_dir/APKBUILD" "$work/sekvyr/sqlite/APKBUILD"
cd "$work/sekvyr/sqlite"
# Dependencies are installed in the preceding builder layer. No -r or sudo here.
# -d suppresses abuild's dependency installation/check; it does not skip hashes.
abuild -F -d -m -P "$work/packages" -s "$work/distfiles"
artifact="$work/packages/sekvyr/$arch/sqlite-libs-3.54.1-r0.apk"
[ -f "$artifact" ] || fail 'Expected SQLite library APK was not produced'
apk --no-network --keys-dir /tmp/signing/verify-keys verify "$artifact"
# Same signature-key basename, but different key material: lookup must succeed
# and cryptographic authentication must fail. Both extra keys stay on tmpfs.
mkdir /tmp/signing/wrong-keys
openssl genrsa -out /tmp/signing/wrong-signing.rsa 4096
openssl rsa -in /tmp/signing/wrong-signing.rsa -pubout \
	-out /tmp/signing/wrong-keys/sekvyr-sqlite-build.rsa.pub 2>/dev/null
if apk --no-network --keys-dir /tmp/signing/wrong-keys verify "$artifact" >/dev/null 2>&1; then
	fail 'APK verification accepted the wrong signing key'
fi
# Corrupt a private-to-this-RUN copy; never export a damaged artifact.
python - "$artifact" /tmp/signing/corrupted.apk <<'PY'
import sys
from pathlib import Path

content = bytearray(Path(sys.argv[1]).read_bytes())
if len(content) < 64:
    raise SystemExit("APK too small for integrity test")
content[len(content) // 2] ^= 1
Path(sys.argv[2]).write_bytes(content)
PY
if apk --no-network --keys-dir /tmp/signing/verify-keys verify /tmp/signing/corrupted.apk >/dev/null 2>&1; then
	fail 'APK verification accepted corrupted package bytes'
fi
install -m644 "$artifact" /out/sqlite-libs-3.54.1-r0.apk
install -m644 "$PACKAGER_PUBKEY" /out/sekvyr-sqlite-build.rsa.pub
{
	printf 'package=sqlite-libs-3.54.1-r0\narchitecture=%s\nsource_date_epoch=%s\n' "$arch" "$SOURCE_DATE_EPOCH"
	printf 'source_id=2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76\n'
	printf 'abuild='; abuild -V
	printf 'apk='; apk --version
	printf 'compiler='; cc -dumpfullversion
} > /out/build-info.txt
chmod 644 /out/build-info.txt
cd /out
sha256sum sqlite-libs-3.54.1-r0.apk sekvyr-sqlite-build.rsa.pub build-info.txt > SHA256SUMS
chmod 644 SHA256SUMS
# Private key/config disappear when the RUN tmpfs is unmounted, including on error.
