#!/data/data/com.termux/files/usr/bin/bash
# 把 Facts.java 编成裸 dex。刻意不引用任何 android.* 类(全靠反射),
# 因此不需要 android.jar,也不受 Android 版本间签名差异影响。
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
rm -rf "$D/out" "$D/facts.dex"
mkdir -p "$D/out"
javac -source 8 -target 8 -nowarn -d "$D/out" "$D/src/afakesu/facts/Facts.java" 2>&1 | grep -v 'bootstrap class path' || true
d8 --release --min-api 29 --output "$D/out" $(find "$D/out" -name '*.class')
mv "$D/out/classes.dex" "$D/facts.dex"
echo "产物: $D/facts.dex ($(stat -c %s "$D/facts.dex") 字节)"
