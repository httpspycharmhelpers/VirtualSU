#!/data/data/com.termux/files/usr/bin/bash
# One source of truth: every deployed copy must report the same version, and
# the build's own version is the reference.  This exists because four copies
# had drifted -- a stale 1.8M binary from 08-21 at the repo root, and
# /sdcard/termux/fakesu.elf, which afake-su actually execs and which was
# never updated, so users kept seeing a version string that had not changed
# in days while src/fakesu.elf was already correct.
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/src/fakesu.elf"
RISH="$ROOT/src/.aFakeSU/rish"
[ -x "$RISH" ] || RISH="$ROOT/rish"
WANT="$("$SRC" -v)"
[ -n "$WANT" ] || { echo "build has no version" >&2; exit 1; }
rc=0
for dest in "$ROOT/afake-su.elf" "$ROOT/../fakesu.elf" \
            "/data/local/tmp/su.elf" "/sdcard/termux/fakesu.elf" \
            "/data/data/com.termux/files/usr/bin/fakesu.elf"; do
	cp -f "$SRC" "$dest" 2>/dev/null || { printf '%-52s COPY FAILED\n' "$dest"; rc=1; continue; }
	# mode 644/755, never 660: an sdcard copy left non-executable is what
	# made afake-su return nothing at all.
	chmod 0755 "$dest" 2>/dev/null
	# /data/local/tmp and /sdcard are mounted noexec for Termux, so a copy
	# there can only be run through rish (which is also how afake-su invokes
	# it).  Verify it the same way, or the check would report a false
	# mismatch on the one path that matters most.
	got="$("$dest" -v 2>/dev/null)"
	if [ -z "$got" ] && [ -x "$RISH" ]; then
		got="$("$RISH" -c "$dest -v" 2>/dev/null | tr -d '\r' | head -1)"
	fi
	[ -n "$got" ] || got='<cannot exec>' 
	if [ "$got" = "$WANT" ]; then
		printf '%-52s ok\n' "$dest"
	else
		printf '%-52s MISMATCH (%s)\n' "$dest" "$got"
		rc=1
	fi
done
exit $rc
