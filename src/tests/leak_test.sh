#!/data/data/com.termux/files/usr/bin/bash
# Leak / lifecycle regression tests for the fake-root session.
# Kept in a script file on purpose: when these patterns live in the caller's
# own command line, every /proc scan matches the scanner.

cd "$(dirname "$0")/.." || exit 1
BIN=./fakesu.elf

[ -x "$BIN" ] || { echo "no $BIN here (run from src/tests)"; exit 1; }

# Never touch ourselves or our ancestors.
SELF=$$
SKIP="$SELF"
p=$SELF
for _ in 1 2 3 4; do
	p=$(awk '{print $4}' "/proc/$p/stat" 2>/dev/null) || break
	[ -z "$p" ] || [ "$p" = "0" ] && break
	SKIP="$SKIP $p"
done

comm_of() { tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null; }
state_of() { awk '{print $3}' "/proc/$1/stat" 2>/dev/null; }
ppid_of() { awk '{print $4}' "/proc/$1/stat" 2>/dev/null; }

# Live processes that descend from $1 (the su pid), by ppid chain.
descendants() {
	local root=$1 d p
	for d in /proc/[0-9]*; do
		p=${d#/proc/}
		[ "$p" = "$root" ] && continue
		# walk up
		local q=$p i=0
		while [ $i -lt 6 ]; do
			q=$(ppid_of $q)
			[ -z "$q" ] && break
			[ "$q" = "$root" ] && { echo "$p"; break; }
			[ "$q" = "1" ] && break
			i=$((i+1))
		done
	done
}

strays() {
	# anything left that looks like our guest: a sh, or a sleep we started
	local d p n=0
	for d in /proc/[0-9]*; do
		p=${d#/proc/}
		case " $SKIP " in *" $p "*) continue;; esac
		local c
		c=$(comm_of "$p")
		case "$c" in
			*"sleep 301"*) n=$((n+1));;
			*/system/bin/sh*|*"/bin/sh -c ls"*) n=$((n+1));;
		esac
	done
	echo $n
}

report() { echo "  strays=$(strays)"; }

echo "### baseline"
echo "  strays=$(strays)"

# ---------------------------------------------------------------- SIGTERM
echo "### C: SIGTERM to su"
$BIN -c 'sleep 301' >/dev/null 2>&1 </dev/null &
SU=$!
sleep 4
before=$(descendants $SU | tr '\n' ' ')
echo "  su=$SU descendants=[$before]"
kill -TERM $SU 2>/dev/null
wait $SU 2>/dev/null
rc=$?
sleep 2
echo "  su rc=$rc  su_alive=$([ -d /proc/$SU ] && echo yes || echo no)"
report

# ------------------------------------------------------- SIGKILL, 1 proc
echo "### B: SIGKILL to su, single-process guest"
$BIN -c 'sleep 301' >/dev/null 2>&1 </dev/null &
SU=$!
sleep 4
before=$(descendants $SU | tr '\n' ' ')
echo "  su=$SU descendants=[$before]"
kill -9 $SU 2>/dev/null
wait $SU 2>/dev/null
sleep 2
alive=""
for p in $before; do [ -d "/proc/$p" ] && alive="$alive $p"; done
echo "  leaked=[$alive]"
report

# ------------------------------------------------------ SIGKILL, pipeline
echo "### B2: SIGKILL to su, multi-process guest (pipeline + sleep)"
$BIN -c 'sh -c "ls -1 /etc | wc -l; sleep 301"' >/dev/null 2>&1 </dev/null &
SU=$!
sleep 6
before=$(descendants $SU | tr '\n' ' ')
echo "  su=$SU descendants=[$before]"
kill -9 $SU 2>/dev/null
wait $SU 2>/dev/null
sleep 3
alive=""
for p in $before; do [ -d "/proc/$p" ] && alive="$alive $p($(state_of $p))"; done
echo "  leaked=[$alive]"
report

echo "### final"
report
