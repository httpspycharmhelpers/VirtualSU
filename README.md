# VirtualSU

面向 **非 root 设备** 的虚拟 root 沙箱。它在用户态为一条命令伪造出一份一致、可信的「root 视角」——文件系统、uid/gid、附加组、capability、系统属性、SELinux 标签、`/proc` 视图——让依赖 root 的脚本、检测脚本、安装/打包流程在本机跑通，而**不触碰内核**。

它不是 root 实现，也不绕过内核：SELinux 强制、DAC 检查、进程的真实 uid 全部不变。所谓「root」是**告诉命令什么**，并把这些说法拼成一套自洽的叙事。把可信代码指进来，你得到的是一个沙箱，不是提权。

与 KernelSU / Magisk 的区别：本项目不模仿它们的实现，最大的特点是在 **SELinux / syscall 层做拦截与伪造**，且不隐藏自身。配套的 Vsud 守护进程把每次会话的祖先从调用者 shell 换成 root 身份的守护进程，让「谁在跑 root」这件事在进程树上也成立。

> 源码构建产物名为 `fakesu.elf`；发布的 deb 把它安装为 **`vsu`**，守护进程入口为 **`vsud`**。本机对任何**名为 `su` 的 ELF** 会拒绝执行（EPERM），所以主二进制刻意不叫 `su`。项目名 / 发布包名统一为 **VirtualSU**。

## 快速开始

两种入口，行为一致：

**Termux（app uid 启动）**

```sh
~/aFakeSU/src/fakesu.elf -c 'id; id -Z'      # 从源码直接跑
vsu -c 'id; id -Z'                            # 安装 deb 后（命令名 vsu）
vsud                                          # 常驻守护进程（一般无需手动跑）
```

**rish（uid 2000 / Shizuku）**

```sh
rish -c "/data/local/tmp/fakesu.elf -c 'id; id -Z'"
```

两条路径都会自动：从设备真实数据里采集 uid/组/属性/SELinux 策略（经 Shizuku 桥接，失败则退回内置默认值），再为命令搭建会话。

## 命令

### `vsu` / `fakesu.elf`（本体）

```
vsu [选项] [-] [user [argument...]]
```

| 选项 | 作用 |
|------|------|
| `-c, --command CMD` | 把 `CMD` 交给会话 shell 执行 |
| `-l, --login` | 作为登录 shell 启动 |
| `-s, --shell SH` | 用 `SH` 代替默认 `/system/bin/sh` |
| `-p, --preserve-environment` | 原样保留环境变量 |
| `-u, --user UID` | 以指定 UID 运行 |
| `-g, --group GID` | 指定主组 |
| `-G, --supp-group GID` | 追加附加组（未给 `-g` 时第一个兼作主组） |
| `-Z CONTEXT` | 指定上报的 SELinux 上下文（任意语法合法域，`untrusted_app` 等自动补 MLS） |
| `-C, --caps SPEC` | 会话持有的 capability：`all` / `none` / `NAME[,NAME...]`，`-NAME` 表示从全集里去掉 |
| `-d, --drop-cap` | 丢弃全部 capability（含 bounding set） |
| `-t, --target PID` | 进入 PID 的 mount namespace |
| `-M, -m, -mm, --mount-master` | 强制在全局 mount namespace 运行 |
| `-i, --interactive` | 强制以调用者 uid 弹出提示 |
| `-v, --version` / `-V` | 打印版本 / 版本号后退出 |
| `-h, --help` | 帮助 |
| `--require-existing-domain` | `-Z` 时校验上下文确实存在于当前策略（默认不校验） |

### `vsud`（守护进程）

`vsud` 就是 `vsu --vsud`：按 uid 一份的常驻守护进程，会话由它 fork 出（详见「架构」）。首个 `vsu` 调用会自动拉起它，通常不必手动执行。

> 发布包**不提供 `su` / `sudo`**，因此不会与 termux-tools 的 `su` 或 sudo 包冲突，也不需要 `dpkg-divert`。

## 策略管理

虚拟 root 若把 root 交给任何调用者，就既容易被识破、也不像真实实现，所以按 uid 维护一张策略表：

| 命令 | 作用 |
|------|------|
| `vsu --policy-list` | 列出已存策略 |
| `vsu --policy-set UID allow\|deny\|restrict\|query` | 设置某 uid 的策略 |
| `vsu --policy-remove UID` | 删除（回到 `query`） |
| `vsu --root-access prompt\|disabled\|adb-only\|apps-only` | 全局 root 授权模式 |
| `vsu --multiuser owner-managed\|owner-only\|global` | 多用户模式 |

## 我们劫持了什么

全部在用户态完成，靠 proot 的 syscall 拦截（ptrace/seccomp）与包装器改写结果：

- **uid / gid / 附加组**：`id`、`getuid/getgid/getgroups`、`/proc/<pid>/status`。
- **capability**：`/proc/<pid>/status` 的 `Cap*` 行、`capget`。
- **SELinux**：`id -Z`、`ls -Z`、`ps -Z`、`getenforce`、`/proc/<pid>/attr/*`，以及 `getxattr/listxattr` 的 `security.selinux`。默认 uid 0 → `u:r:virtu_su:s0`，其余按 AID 表映射，`-Z` 可覆盖为任意合法域。
- **系统属性**：`getprop / setprop / resetprop` 包装器，键值持久化在 `<workdir>/.props`。
- **分区写**：`/system`、`/vendor`、`/product`、`/odm`、`/` 的写操作重定向到 `<workdir>/ov/`，`stat` 仍报 `root:root` 与真实 mode/size。
- **mount**：接受并记忆 `-o remount,rw/ro`，`mount` 输出按需改写。
- **chcon / restorecon**：写入的标签按**规范化后的绝对路径**存进 `<workdir>/.xattrs/`，`ls -Z` 据此显示（相对/绝对写法指向同一文件时命中同一条）；未覆盖路径与非覆盖查询走真实 xattr。
- **/proc 视图**：`status`、`cmdline`、`comm`、`maps`、`attr`。
- **身份边界**：只有 Vsud 及其子树是 `root` + `virtu_su`；设备其余进程与文件对象保留**真实**身份，祖先与无关进程不被伪造。

## 架构

- **Vsud**：按 uid 一份的常驻守护进程（抽象 Unix socket `afake_su_vsud.<uid>`）。会话由它 fork 出，因此 guest 的祖先是 root 身份的守护进程，而不是调用者 shell；调用 `vsu` 的那个 shell 在进程树里仍是真实的 `untrusted_app`/`shell`。
- **会话**：客户端把 argv/env/stdio（可含 pty）经 `SCM_RIGHTS` 交给守护进程，守护进程再 `exec` 本二进制并去掉 `--vsud-session` 标记，走完整 su 流程。守护进程不可用时自动就地回退（`VSUD_NO_DAEMON=1` 可强制）。
- **采集桥**：`rish` + `rish_shizuku.dex`（Shizuku）在设备上采集真实 uid/组/属性/SELinux 策略并缓存到 `<workdir>`。

## 打包 / 发布

发布包为 Termux（aarch64）deb，包内包含：

- `vsu`（proot 静态内嵌的主二进制，即 `fakesu.elf` 改名）
- `vsud`（守护进程入口，即 `vsu --vsud`）
- `rish`、`rishq`、`rish_shizuku.dex`、`facts.dex`（采集桥）
- `libiconv.so`、`libncursesw.so.6.5`（嵌入 shell 所需的运行库）

包内**不含 `su` / `sudo`**，安装不触碰 termux-tools 的 `su` 与 sudo 包，卸载也无需恢复任何文件。产物文件名带 **VirtualSU** 与版本号（如 `VirtualSU_2.0_aarch64.deb`）。

## 构建

```sh
cd src && ./build_su.sh        # 全量编译 proot + su.c + vsud.c，链接出 fakesu.elf
```

构建脚本会从零编译 proot-termux 的全部 `.c`（不依赖残留 `.o`），并嵌入 `bash`、两个 `.so`、以及 `dex/` 下的采集资产。

## 已知限制

- **不是提权**：内核级 uid 0、真实 SELinux transition、真实父进程死亡语义都拿不到。深度检测（magisk 级）仍可识破。
- 名为 `su` 的 **ELF** 在本机会被拒绝执行（EPERM），这也是发布包把主二进制命名为 `vsu` 的原因；其余名字（`vsu`、`fakesu.elf` 等）可执行。
- 覆盖层**不**覆盖 `/data`；目录读操作保持真实 inode。
- rish/uid 2000 读不到 Termux 私有目录，部署需经共享存储中转。
- `/proc/version`、`/proc/sys/kernel/*`、`/proc/1` 在会话内可能仍被真实 SELinux + `hidepid` 拒绝。
