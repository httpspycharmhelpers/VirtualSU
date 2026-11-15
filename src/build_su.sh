#!/data/data/com.termux/files/usr/bin/bash
set -u

cd "$(dirname "$0")"
ROOT="$(pwd)"
PT="$ROOT/proot-termux"
TP="$ROOT/third_party"
BLD="$ROOT/build"
BASH_BIN="$ROOT/bash-5.3/bash"

mkdir -p "$BLD"

CC="clang"
COMMON="-O2 -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -DARG_MAX=131072"
PT_CFLAGS="$COMMON -DVERSION=\"5.1.0\" -DWITH_LIBANDROID_SHMEM -I$PT/src -I$PT"

echo "== talloc.o =="
$CC -c $COMMON \
    -DTALLOC_BUILD_VERSION_MAJOR=2 -DTALLOC_BUILD_VERSION_MINOR=4 -DTALLOC_BUILD_VERSION_RELEASE=3 \
    -I"$TP" -I"$TP/talloc-2.4.3" \
    "$TP/talloc-2.4.3/talloc.c" -o "$BLD/talloc.o" || exit 1

echo "== shmem.o =="
$CC -c $COMMON -I"$TP/libandroid-shmem-0.7" \
    "$TP/libandroid-shmem-0.7/shmem.c" -o "$BLD/shmem.o" || exit 1

echo "== cli.o (PROOT_EMBEDDED) =="
$CC -c $PT_CFLAGS -DPROOT_EMBEDDED \
    "$PT/src/cli/cli.c" -o "$BLD/cli.o" || exit 1

echo "== bash_data.o (objcopy) =="
cp "$BASH_BIN" "$BLD/bash.bin"
(cd "$BLD" && objcopy -I binary -O elf64-littleaarch64 -B aarch64 \
    --rename-section .data=.rodata,alloc,load,readonly,data,contents \
    bash.bin bash.bin.o) || exit 1

echo "== embedded libs (libiconv / libncursesw) =="
for lib in libiconv.so libncursesw.so.6.5; do
    cp "/data/data/com.termux/files/usr/lib/$lib" "$BLD/$lib"
    (cd "$BLD" && objcopy -I binary -O elf64-littleaarch64 -B aarch64 \
        --rename-section .data=.rodata,alloc,load,readonly,data,contents \
        "$lib" "$lib.o") || exit 1
done

# facts.dex, rishq and rish are tiny (7K + 2.4K + 1.4K) and all three are
# located by path at runtime.  Embedding them makes the binary self-contained:
# no deb payload and no "install the helpers next to the binary" step, which is
# what silently broke before -- the dex lives under dex/ in the source tree and
# was never on any of the search paths.
#
# The whole bridge has to travel together.  rishq resolves its launcher as
# "$D/rish", and rish in turn resolves "rish_shizuku.dex" next to itself and
# exits when it is missing.  Both failures surface as the same unhelpful
# "read: invalid file descriptor" on RISH[0], because in each case the coproc
# child dies before the read loop starts.  rish_shizuku.dex is 58K, which the
# 3.3M binary can carry without complaint.
echo "== embedded assets (facts.dex / rishq) =="
for asset in facts.dex rishq rish rish_shizuku.dex; do
    src=""
    for cand in "$ROOT/../dex/$asset" "$ROOT/../$asset" "$ROOT/$asset" \
               "/data/data/com.termux/files/usr/share/afake-su/$asset"; do
        if [ -f "$cand" ]; then src="$cand"; break; fi
    done
    if [ -z "$src" ]; then
        echo "!! missing $asset -- run dex/build_dex.sh first" >&2
        exit 1
    fi
    # -f after an explicit rm: a previous run may have left these 0400 (the
    # dex arrives that way from the source tree), and cp then fails to
    # truncate the old copy.  The failure used to be invisible -- the cp had
    # no error check and the objcopy below happily re-wrapped whatever stale
    # $asset.o was already in build/, so an edited facts.dex was silently not
    # embedded and the build still reported success.
    rm -f "$BLD/$asset" "$BLD/$asset.o"
    cp -f "$src" "$BLD/$asset" || exit 1
    (cd "$BLD" && objcopy -I binary -O elf64-littleaarch64 -B aarch64 \
        --rename-section .data=.rodata,alloc,load,readonly,data,contents \
        "$asset" "$asset.o") || exit 1
done

echo "== su.o =="
$CC -c $COMMON -I"$PT" -I"$PT/src" \
    "$ROOT/su.c" -o "$BLD/su.o" || exit 1

# Vsud lives in its own translation unit: it is a separate long-lived process
# with its own lifecycle, and su.c is already long enough.  It only needs the
# libc/termux side, so it is deliberately built without the PRoot include
# path -- that keeps the daemon from depending on tracee internals it has no
# business touching.
echo "== vsud.o =="
$CC -c $COMMON "$ROOT/vsud.c" -o "$BLD/vsud.o" || exit 1

# Every proot source file is compiled here, from the tree, on every build.
#
# This used to be a per-file affair: build_su.sh grew one explicit rule per
# edited file (enter.o, then fake_id0.o) because the link step below globs
# whatever .o files are lying around in proot-termux/src.  Anything without its
# own rule was silently linked in stale -- an edit to event.c compiled clean,
# reported success, and did nothing at all.  Two of the three bugs fixed in
# this script were found only after noticing the .o was older than the .c.
#
# So: compile all of it, and keep only the prebuilt objects that have no .c to
# rebuild from (the loader assembly).
PT_BUILD="$BLD/pt"
rm -rf "$PT_BUILD"
mkdir -p "$PT_BUILD"

PT_OBJS=""
while IFS= read -r f; do
	rel="${f#"$PT/src/"}"
	case "$rel" in
	# cli.c is built above into $BLD/cli.o with the same flags.
	cli/cli.c) continue ;;
	# Standalone loader tool, never linked into the binary.
	loader/loader.c) continue ;;
	# Dot-prefixed files are standalone probes with their own main()
	# (.check_process_vm.c, .check_seccomp_filter.c); they have never
	# been linked and must not start being.
	.*) continue ;;
	esac
	o="$PT_BUILD/${rel//\//_}.o"
	$CC -c $PT_CFLAGS -DPROOT_EMBEDDED "$f" -o "$o" || exit 1
	PT_OBJS="$PT_OBJS $o"
done < <(find "$PT/src" -name '*.c' | sort)

# Assembly-only objects: no .c exists, so they stay as they are.  Anything that
# *does* have a .c was just rebuilt above, so linking the tree's copy too would
# be a duplicate-symbol error -- which is exactly the signal that a source file
# is being compiled twice, not that the tree is clean.
PREBUILT=""
while IFS= read -r f; do
	case "$f" in
		*cli.o|*loader/loader.o|*loader/assembly.o|*loader-m32.o|*loader-m32-wrapped.o|*assembly-m32.o|*test_embed.o) continue ;;
	esac
	[ -f "${f%.o}.c" ] && continue
	PREBUILT="$PREBUILT $f"
done < <(find "$PT/src" -name "*.o" | sort)

echo "== link =="
$CC -o "$ROOT/fakesu.elf" \
    "$BLD/cli.o" $PT_OBJS $PREBUILT \
    "$BLD/talloc.o" "$BLD/shmem.o" "$BLD/su.o" "$BLD/vsud.o" "$BLD/bash.bin.o" \
    "$BLD/libiconv.so.o" "$BLD/libncursesw.so.6.5.o" \
    "$BLD/facts.dex.o" "$BLD/rishq.o" "$BLD/rish.o" "$BLD/rish_shizuku.dex.o" \
    -Wl,-z,noexecstack -llog || exit 1

echo "== done: $ROOT/fakesu.elf =="
file "$ROOT/fakesu.elf"

# Deliberately NOT copied to /sdcard.  This used to end with a write to
# /sdcard/termux/fakesu.elf, the same reach the handoff warns about for
# deploy_sync.sh: building is a local operation and has no business touching
# shared storage, where it can land on top of unrelated files.  Deploying is
# deploy_sync.sh's job and nothing else.

SCRIPT_DIR="$ROOT/.."
cat > "$SCRIPT_DIR/afake-su" << 'SCRIPT'
#!/data/data/com.termux/files/usr/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
args=""
for arg in "$@"; do
    args="$args '$arg'"
done
"$SCRIPT_DIR/rish" -c "/data/data/com.termux/files/usr/bin/fakesu.elf $args "
SCRIPT
chmod +x "$SCRIPT_DIR/afake-su"
echo "== generated: $SCRIPT_DIR/afake-su =="