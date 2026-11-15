#!/data/data/com.termux/files/usr/bin/bash
# Deploy aFakeSU as termux's su (rish/rishq -> fakesu.elf, uid 2000).
set -u

STAGE=/sdcard/termux
DEST=/data/local/tmp/termux
SU=/data/data/com.termux/files/usr/bin/su
RISHQ=/data/data/com.termux/files/usr/bin/rishq
PREFIX_BIN=/data/data/com.termux/files/usr/bin

echo "[*] probe rish..."
if ! timeout 20 rish -c ': ' 2>/dev/null; then
	echo "[!!] rish/Shizuku not connected. Start Shizuku, authorize Termux,"
	echo "     then re-run. (battery optimization may block the link)"
	exit 1
fi

echo "[*] stage fakesu.elf via rish -> $DEST"
rish -c "mkdir -p '$DEST' && cp -f '$STAGE/fakesu.elf' '$DEST/fakesu.elf' && chmod 755 '$DEST/fakesu.elf'" || {
	echo "[!!] rish stage failed"; exit 1; }

echo "[*] install rishq = $RISHQ"
cp -f "$HOME/aFakeSU/rishq" "$RISHQ" && chmod 755 "$RISHQ"

if [ -e "$SU" ]; then
	cp -f "$SU" "$SU.bak" && echo "[*] backed up old su -> $SU.bak"
fi

echo "[*] install wrapper $SU"
cat > "$SU" <<EOF
#!/data/data/com.termux/files/usr/bin/bash
set -u
EXE=$DEST/fakesu.elf
args=""
for arg in "\$@"; do
    args="\$args '\$arg'"
done
exec rishq "\$EXE\$args" 20
EOF
chmod 755 "$SU"

echo "[*] done. try: su -c 'id'   (or just  su)"
echo "    note: every su call needs Shizuku alive at boot"