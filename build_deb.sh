#!/data/data/com.termux/files/usr/bin/bash
# Build the VirtualSU Termux (aarch64) deb.
#
# The package is still named "afake-su" internally, so only the produced
# archive is branded VirtualSU.  The payload is self-branded: the binary ships
# as "vsu", with "vsud" for the daemon.  It deliberately does NOT provide su or
# sudo, so it never collides with termux-tools' su or the sudo package and
# needs no dpkg-divert.  Payload:
#
#   bin/vsu               the proot-embedded su (self-contained)
#   bin/vsud              the privilege anchor daemon (vsu --vsud)
#   bin/{rish,rishq}      Shizuku bridge
#   bin/{rish_shizuku.dex,facts.dex}
#   lib/afake-su/libiconv.so, libncursesw.so.6.5   runtime libs for the shell
#
# The binary already embeds the two .so files and the dex assets and writes
# them at session start, so the deb copies are belt-and-suspenders: they are
# installed under lib/afake-su/ (never lib/, which Termux's libiconv/ncurses
# packages own) and never overwrite a system file.
set -eu
umask 022

cd "$(dirname "$0")"
ROOT="$(pwd)"
PKG=afake-su
VER="${VIRTUALSU_VERSION:-2.0}"
ARCH=aarch64
PREFIXDIR="data/data/com.termux/files/usr"
STAGE="$ROOT/build/deb/stage"
OUT="$ROOT/dist"
NAME="VirtualSU_${VER}_${ARCH}.deb"
SYS=/data/data/com.termux/files/usr

[ -f src/fakesu.elf ] || { echo "build src/fakesu.elf first" >&2; exit 1; }
for a in rish rishq rish_shizuku.dex dex/facts.dex; do
	[ -f "$a" ] || { echo "missing $a" >&2; exit 1; }
done

rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" "$STAGE/$PREFIXDIR/bin" "$STAGE/$PREFIXDIR/lib/afake-su"

# control: keep the package name, stamp the VirtualSU release version and home.
sed -e "s/^Version: .*/Version: $VER/" \
    -e "s#^Homepage: .*#Homepage: https://github.com/httpspycharmhelpers/VirtualSU#" \
    packaging/debian/control > "$STAGE/DEBIAN/control"
for s in preinst postinst prerm postrm; do
	cp packaging/debian/"$s" "$STAGE/DEBIAN/$s"
	chmod 755 "$STAGE/DEBIAN/$s"
done

B="$STAGE/$PREFIXDIR/bin"
cp -f src/fakesu.elf "$B/vsu"
chmod 755 "$B/vsu"

cp -f rish "$B/rish";   chmod 755 "$B/rish"
cp -f rishq "$B/rishq"; chmod 755 "$B/rishq"
cp -f rish_shizuku.dex "$B/rish_shizuku.dex"; chmod 644 "$B/rish_shizuku.dex"
cp -f dex/facts.dex "$B/facts.dex";           chmod 644 "$B/facts.dex"

cp -f packaging/vsud "$B/vsud"; chmod 755 "$B/vsud"

for so in libiconv.so libncursesw.so.6.5; do
	cp -f "$SYS/lib/$so" "$STAGE/$PREFIXDIR/lib/afake-su/$so"
	chmod 755 "$STAGE/$PREFIXDIR/lib/afake-su/$so"
done

mkdir -p "$OUT"
if dpkg-deb --help 2>&1 | grep -q -- '--root-owner-group'; then
	dpkg-deb --build --root-owner-group "$STAGE" "$OUT/$NAME"
else
	fakeroot dpkg-deb --build "$STAGE" "$OUT/$NAME"
fi

echo
echo "== built $OUT/$NAME =="
dpkg-deb -I "$OUT/$NAME"
echo "== payload =="
dpkg-deb -c "$OUT/$NAME" | awk '{print $1, $2, $6}'
