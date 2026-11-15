#!/data/data/com.termux/files/usr/bin/bash
# Regression tests for the supervisor fork: exit-status forwarding and ^C.
cd "$(dirname "$0")/.." || exit 1
BIN=$PWD/fakesu.elf

echo "### 退出码转发"
for code in 0 1 42 127; do
	"$BIN" -c "exit $code" >/dev/null 2>&1 </dev/null
	echo "  guest exit $code -> su exit $?"
done

echo "### guest 自杀时的状态"
"$BIN" -c 'kill -TERM $$' >/dev/null 2>&1 </dev/null
echo "  guest SIGTERM -> su exit $?  (期望 143)"
"$BIN" -c 'kill -9 $$' >/dev/null 2>&1 </dev/null
echo "  guest SIGKILL -> su exit $?  (期望 137)"
"$BIN" -c 'nosuchcommand_xyz' >/dev/null 2>&1 </dev/null
echo "  guest 命令不存在 -> su exit $?  (期望 127)"

echo "### ^C 只发给 su 时，会话必须存活"
# The guest has to actually block: with </dev/null a `read` returns EOF at once
# and the session is already over before the signal is sent.
"$BIN" -c 'sleep 30; echo GUEST_FINISHED' >~/tmp/work/sigint.out 2>&1 </dev/null &
SU=$!
sleep 4
guest_before=$(awk '{print $4}' "/proc/$SU/stat" 2>/dev/null)
echo "  su=$SU 其子进程=$guest_before state=$(awk '{print $3}' /proc/$guest_before/stat 2>/dev/null)"
kill -INT $SU 2>/dev/null
sleep 2
su_alive=no; [ -d /proc/$SU ] && su_alive=yes
guest_alive=no; [ -d /proc/$guest_before ] && guest_alive=yes
echo "  发 SIGINT 给 su 后: su_alive=$su_alive guest_alive=$guest_alive  (都应为 yes)"
kill -TERM $SU 2>/dev/null
wait $SU 2>/dev/null
sleep 2
echo "  收尾: 输出=$(tr '\n' ' ' < ~/tmp/work/sigint.out 2>/dev/null)  (应为空，guest 未跑完)"

echo "### -i pty 路径仍可用"
if command -v script >/dev/null 2>&1; then
	echo "  pty_ok" | timeout -s KILL 30 "$BIN" -i >~/tmp/work/pty.out 2>&1
	echo "  rc=$? 输出=$(tr -d '\r' < ~/tmp/work/pty.out | grep -c . ) 行"
else
	echo "  (无 script 工具，跳过)"
fi

echo "### 基本功能未回归"
"$BIN" -c 'echo "id=$(id -u):$(id -g) etc=$(ls /etc|wc -l) ctx=$(cat /proc/self/attr/current)"' >~/tmp/work/basic.out 2>&1 </dev/null
echo "  rc=$? -> $(cat ~/tmp/work/basic.out)"
