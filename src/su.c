
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "proot-termux/src/cli/cli.h"
#include "proot-termux/src/cli/note.h"
extern const unsigned char _binary_bash_bin_start[];
extern const unsigned char _binary_bash_bin_end[];
#define EMBEDDED_BASH_SIZE ((size_t)(_binary_bash_bin_end - _binary_bash_bin_start))
extern const unsigned char _binary_libiconv_so_start[];
extern const unsigned char _binary_libiconv_so_end[];
extern const unsigned char _binary_libncursesw_so_6_5_start[];
extern const unsigned char _binary_libncursesw_so_6_5_end[];
#define VERSION_STR "2c6adbc6:AFAKESU"
#define VERSION_CODE "27000"
#define DEFAULT_SHELL "/system/bin/sh"
#define ANDROID_PATH "/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin"
/* Guest-visible mirror of <workdir>/bin (the getprop/mount/chcon wrappers).
 * It must NOT expose the Termux path in $PATH or `which`, so the host
 * workdir/bin is bound here and this clean path is what the session sees. */
#define GUEST_BIN_DIR "/data/local/tmp/.su/bin"
#define GUEST_PATH GUEST_BIN_DIR ":/sbin:/system/sbin:/system/bin:/system/xbin:/vendor/bin"
#define INT_MAX_VALUE 2147483647
#define WORK_DIR_NAME ".tmp"
#define CACHE_DIR_NAME ".aFakeSU"
#define REAL_FILE "real_uids.txt"
#define RISHQ_NAME "rishq"
#define FACTS_DEX_NAME "facts.dex"
#define APP_PROCESS "/system/bin/app_process"
static char g_self_exe[PATH_MAX];
static char g_self_dir[PATH_MAX];
char g_work_dir[PATH_MAX];
/* A second, location-independent place to look for (and keep) the L0
 * caches.  g_work_dir is derived from the running binary's own path, and
 * the same binary is installed at more than one path (/data/local/tmp and
 * the Termux prefix), so the caches harvested by one copy are invisible to
 * the other: .ugroups went unread and /proc/self/status came back with an
 * empty Groups line.  Readers try the workdir first, then this. */
char g_alt_cache[PATH_MAX];
char g_proot_argv0[64];
int g_proot_argv0_fix = 0;
static const char *g_fake_name = "sh";
/* Export of the fake comm name for the proot side (proc.c/enter.c) so
 * /proc/<pid>/status "Name:" matches /system/bin/sh, not the real
 * Termux interpreter. */
char g_fake_comm[64] = "sh";
static char *g_cmd = NULL;
static size_t g_cmd_cap = 0, g_cmd_len = 0;
static const char *g_grp = NULL;
/* Android's SUPP_GROUPS_MAX is 32; leave headroom for a device with a
 * longer declared list. */
#define SUPP_GID_MAX 64
static const char **g_suppg = NULL;
static size_t g_suppg_cnt = 0;

static const char *g_tgt = NULL;
static const char *g_shell = DEFAULT_SHELL;
static bool g_login = false;
static bool g_preserve = false;
static bool g_mount = false;
/* -i: force a pseudo-terminal even with -c.  -d: drop every Linux
 * capability for the session, so a capability probe sees an unprivileged
 * root rather than a fully capable one. */
static bool g_interactive = false;
/* Not static: proot's enter.c rewrites /proc/<pid>/status on every read and
 * needs the same flag, otherwise --drop-cap changes the file we generate
 * but not the one the session actually reads. */
int g_drop_cap = false;
/* Set from -i and consumed by build_and_run_proot(). */
static bool force_pty = false;

/*
 * Per-UID root policy, mirroring Magisk's su policy table.
 * Magisk does not hand root to every caller.  Each requesting app UID gets
 * its own policy, the caller is identified by the UID of the process asking
 * for su, and the policy decides between four answers:
 *
 *   ALLOW     run the session as requested
 *   DENY      refuse outright, exactly like Magisk's "deny" prompt choice
 *   QUERY     no stored decision: ask.  Without a manager app to prompt,
 *              Magisk denies, and so do we.
 *   RESTRICT  allow, but force drop_cap, so the session is a root with an
 *             empty capability set
 *
 * RESTRICT is why the capability handling is not just a -d flag: Magisk
 * turns drop_cap on by itself when the policy says restrict.
 */
enum su_policy { SU_POLICY_ALLOW, SU_POLICY_DENY, SU_POLICY_QUERY, SU_POLICY_RESTRICT };

/* Global root access modes, matching Magisk's RootAccess setting. */
enum root_access { ROOT_ACCESS_PROMPT, ROOT_ACCESS_DISABLED,
		   ROOT_ACCESS_ADB_ONLY, ROOT_ACCESS_APPS_ONLY };
static enum root_access g_root_access = ROOT_ACCESS_PROMPT;

/* Multiuser modes, matching Magisk's MultiuserMode. */
enum multiuser_mode { MULTIUSER_OWNER_MANAGED, MULTIUSER_OWNER_ONLY,
		      MULTIUSER_GLOBAL };
static enum multiuser_mode g_multiuser = MULTIUSER_OWNER_MANAGED;

/* The UID of whoever invoked su; the policy lookup keys off this. */
static long g_caller_uid = -1;
static const char **g_pos = NULL;
static size_t g_pos_cnt = 0;
static long g_uid = -1;
static long g_gid = -1;
const char *g_selinux_ctx = NULL;

static bool valid_uint_str(const char *s, long *out);
static const char *aid_name_for_uid(long uid, char *name, size_t namesz);
/*
 * Persisted property overrides.  Real root flips read-only props with
 * resetprop/setprop (ro.debuggable, ro.build.*, ro.product.*, ...); a
 * fake root owns a store that shadows the real property service for every
 * process under the session's PATH (getprop/resetprop/setprop first).
 */
static void emit_prop_wrappers(const char *ctx_path)
{
	const char *wd = g_work_dir[0] != '\0' ? g_work_dir : "/data/local/tmp/termux";
	char st[PATH_MAX];
	char p[PATH_MAX];
	snprintf(st, sizeof(st), "%s/.props", wd);

	snprintf(p, sizeof(p), "%s/getprop", ctx_path);
	FILE *f = fopen(p, "w");
	if (f) {
		fprintf(f,
			"#!/system/bin/sh\n"
			"P=\"%s\"\n"
			"[ -f \"$P\" ] || exec /system/bin/getprop \"$@\"\n"
			"if [ \"$#\" -eq 0 ] || [ \"$1\" = \"-p\" ]; then\n"
			"  while IFS='=' read -r k v; do echo \"[$k]: [$v]\"; done < \"$P\"\n"
			"  exit 0\n"
			"fi\n"
			"while IFS='=' read -r k v; do\n"
			"  [ \"$k\" = \"$1\" ] && { echo \"$v\"; exit 0; }\n"
			"done < \"$P\"\n"
			"exec /system/bin/getprop \"$@\"\n",
			st);
		fclose(f);
		chmod(p, 0755);
	}

	static const char *names[] = { "setprop", "resetprop" };
	size_t i;
	for (i = 0; i < 2; i++) {
		snprintf(p, sizeof(p), "%s/%s", ctx_path, names[i]);
		f = fopen(p, "w");
		if (f) {
			fprintf(f,
				"#!/system/bin/sh\n"
				"P=\"%s\"\n"
				"W=\"%s\"\n"
				"name=\"\"; val=\"\"; args=0; del=0\n"
				"for a in \"$@\"; do\n"
				"  case \"$a\" in\n"
				"    -d|--delete) del=1 ;;\n"
				"    -p|--persistent) : ;;\n"
				"    -*) : ;;\n"
				"    *) args=$((args+1))\n"
				"       [ $args -eq 1 ] && name=\"$a\"\n"
				"       [ $args -eq 2 ] && val=\"$a\" ;;\n"
				"  esac\n"
				"done\n"
				"M=\"$W/.propsmod\"\n"
				"if [ $del -eq 1 ] && [ -n \"$name\" ]; then\n"
				"  [ -f \"$P\" ] && sed -i \"/^$name=/d\" \"$P\"\n"
				"  [ -f \"$M\" ] && sed -i \"/^$name$/d\" \"$M\"\n"
				"  exit 0\n"
				"fi\n"
				"if [ $args -ge 2 ] && [ -n \"$name\" ]; then\n"
				"  [ -f \"$P\" ] && sed -i \"/^$name=/d\" \"$P\"\n"
				"  echo \"$name=$val\" >> \"$P\"\n"
				"  mkdir -p \"$W\"\n"
				"  [ -f \"$M\" ] && sed -i \"/^$name$/d\" \"$M\"\n"
				"  echo \"$name\" >> \"$M\"\n"
				"  exit 0\n"
				"fi\n"
				"if [ $args -eq 1 ] && [ -n \"$name\" ] && [ -f \"$P\" ]; then\n"
				"  while IFS='=' read -r k v; do\n"
				"    [ \"$k\" = \"$name\" ] && { echo \"$v\"; exit 0; }\n"
				"  done < \"$P\"\n"
				"fi\n"
				"exec /system/bin/%s \"$@\"\n",
				st, wd, names[i]);
			fclose(f);
			chmod(p, 0755);
		}
	}
}
static void emit_mount_wrapper(const char *ctx_path)
{
	char p[PATH_MAX];
	snprintf(p, sizeof(p), "%s/mount", ctx_path);
	FILE *f = fopen(p, "w");
	if (!f)
		return;
	fprintf(f,
		"#!/system/bin/sh\n"
		"W=\"%s\"\n"
		"mkdir -p \"$W/.mnt\"\n"
		"if echo \" $* \" | grep -q 'remount'; then\n"
		"  rw=0; ro=0\n"
		"  echo \" $* \" | grep -qE '(^|,)rw(,|$)' && rw=1\n"
		"  echo \" $* \" | grep -qE '(^|,)ro(,|$)' && ro=1\n"
		"  tgt=\n"
		"  for a in \"$@\"; do\n"
		"    case \"$a\" in\n"
		"      -o|-t|*remount*|rw|ro|bind|rbind|none|ext4|f2fs|erofs) : ;;\n"
		"      *) tgt=\"$a\" ;;\n"
		"    esac\n"
		"  done\n"
		"  [ -n \"$tgt\" ] || tgt=/ \n"
		"  comp=$(echo \"$tgt\" | sed 's#^/*##; s#/.*$##')\n"
		"  [ -n \"$comp\" ] || comp=root\n"
		"  if [ $rw -eq 1 ] && [ $ro -eq 0 ]; then\n"
		"    echo 1 > \"$W/.mnt/$comp\"\n"
		"  elif [ $ro -eq 1 ]; then\n"
		"    rm -f \"$W/.mnt/$comp\"\n"
		"  fi\n"
		"  /system/bin/mount \"$@\" >/dev/null 2>&1\n"
		"  exit 0\n"
		"fi\n"
		"exec /system/bin/mount \"$@\"\n",
		g_work_dir[0] != '\0' ? g_work_dir : "/data/local/tmp/termux");
	fclose(f);
	chmod(p, 0755);
}

/*
 * chcon/restorecon: real root rewrites security.selinux labels; a fake
 * root records them into <workdir>/.xattrs/<path-with-'%'> which
 * enter.c replays for getxattr/lgetxattr (ls -Z) while the real
 * syscall keeps failing with EPERM.
 */
static void emit_chcon_wrappers(const char *ctx_path)
{
	char xd[PATH_MAX];
	char p[PATH_MAX];
	snprintf(xd, sizeof(xd), "%s/.xattrs", g_work_dir);

	snprintf(p, sizeof(p), "%s/chcon", ctx_path);
	FILE *f = fopen(p, "w");
	if (f) {
		fprintf(f,
			"#!/system/bin/sh\n"
			"X=\"%s\"\n"
			"mkdir -p \"$X\"\n"
			"ctx=; opts=1\n"
			"for a in \"$@\"; do\n"
			"  case \"$a\" in\n"
			"    -*) : ;;\n"
			"    *) if [ -z \"$ctx\" ]; then ctx=\"$a\"; else\n"
			"         k=$(echo \"$a\" | sed 's#/#%%#g')\n"
			"         case \"$k\" in %%*) k=${k#%%} ;; esac\n"
			"         echo \"$ctx\" > \"$X/$k\"\n"
			"       fi ;;\n"
			"  esac\n"
			"done\n"
			"/system/bin/chcon \"$@\" >/dev/null 2>&1\n"
			"exit 0\n",
			xd);
		fclose(f);
		chmod(p, 0755);
	}

	snprintf(p, sizeof(p), "%s/restorecon", ctx_path);
	f = fopen(p, "w");
	if (f) {
		fprintf(f,
			"#!/system/bin/sh\n"
			"X=\"%s\"\n"
			"for a in \"$@\"; do\n"
			"  case \"$a\" in\n"
			"    -*) : ;;\n"
			"    *) k=$(echo \"$a\" | sed 's#/#%%#g')\n"
			"       case \"$k\" in %%*) k=${k#%%} ;; esac\n"
			"       rm -f \"$X/$k\" ;;\n"
			"  esac\n"
			"done\n"
			"/system/bin/restorecon \"$@\" >/dev/null 2>&1\n"
			"exit 0\n",
			xd);
		fclose(f);
		chmod(p, 0755);
	}
}

static void print_help(FILE *f)
{
	fprintf(f,
		"FakeSU\n"
		"\n"
		"Usage: fakesu [options] [-] [user [argument...]]\n"
		"\n"
		"Options:\n"
		"  -c, --command COMMAND         Pass COMMAND to the invoked shell\n"
		"  -i, --interactive             Force pseudo-terminal allocation when using -c\n"
		"  -g, --group GROUP             Specify the primary group\n"
		"  -G, --supp-group GROUP        Specify a supplementary group.\n"
		"                                The first specified supplementary group is also used\n"
		"                                as a primary group if the option -g is not specified.\n"
		"  -Z, --context CONTEXT         Change SELinux context\n"
		"  -t, --target PID              PID to take mount namespace from\n"
		"  -d, --drop-cap                Drop all Linux capabilities\n"
		"  -h, --help                    Display this help message and exit\n"
		"  -, -l, --login                Pretend the shell to be a login shell\n"
		"  -m, -p,\n"
		"  --preserve-environment        Preserve the entire environment\n"
		"  -s, --shell SHELL             Use SHELL instead of the default /system/bin/sh\n"
		"  -v, --version                 Display version number and exit\n"
		"  -V                            Display version code and exit\n"
		"  -mm, -M,\n"
		"  --mount-master                Force run in the global mount namespace\n"
		"\n"
		"  -t and -mm are accepted for command-line compatibility.  A fake root\n"
		"  runs unprivileged, so it cannot really join another process's mount\n"
		"  namespace; both options report that and continue in the current one.\n"
		"\n");
}
static void usage_err(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	fputc('\n', stderr);
	print_help(stderr);
	exit(2);
}
static void invalid_gid(const char *s)
{
	fprintf(stderr, "Invalid GID: %s\n", s);
	print_help(stderr);
	exit(1);
}
static void invalid_pid(const char *s)
{
	fprintf(stderr, "Invalid PID: %s\n", s);
	print_help(stderr);
	exit(1);
}
static const char *const AID_USERS =
	"root:0\n"
	"daemon:1\n"
	"bin:2\n"
	"sys:3\n"
	"system:1000\n"
	"radio:1001\n"
	"bluetooth:1002\n"
	"graphics:1003\n"
	"input:1004\n"
	"audio:1005\n"
	"camera:1006\n"
	"log:1007\n"
	"compass:1008\n"
	"mount:1009\n"
	"wifi:1010\n"
	"adb:1011\n"
	"install:1012\n"
	"media:1013\n"
	"dhcp:1014\n"
	"sdcard_rw:1015\n"
	"vpn:1016\n"
	"keystore:1017\n"
	"usb:1018\n"
	"drm:1019\n"
	"mdnsr:1020\n"
	"gps:1021\n"
	"media_rw:1023\n"
	"mtp:1024\n"
	"drmrpc:1026\n"
	"nfc:1027\n"
	"sdcard_r:1028\n"
	"clat:1029\n"
	"loop_radio:1030\n"
	"mediadrm:1031\n"
	"package_info:1032\n"
	"sdcard_pics:1033\n"
	"sdcard_av:1034\n"
	"sdcard_all:1035\n"
	"logd:1036\n"
	"shared_relro:1037\n"
	"dbus:1038\n"
	"tlsdate:1039\n"
	"mediaex:1040\n"
	"audioserver:1041\n"
	"metrics_coll:1042\n"
	"metricsd:1043\n"
	"webserv:1044\n"
	"debuggerd:1045\n"
	"mediacodec:1046\n"
	"cameraserver:1047\n"
	"firewall:1048\n"
	"trunks:1049\n"
	"nvram:1050\n"
	"dns:1051\n"
	"dns_tether:1052\n"
	"webview_zygote:1053\n"
	"vehicle_network:1054\n"
	"media_audio:1055\n"
	"media_video:1056\n"
	"media_image:1057\n"
	"tombstoned:1058\n"
	"media_obb:1059\n"
	"ese:1060\n"
	"ota_update:1061\n"
	"automotive_evs:1062\n"
	"lowpan:1063\n"
	"hsm:1064\n"
	"reserved_disk:1065\n"
	"statsd:1066\n"
	"incidentd:1067\n"
	"secure_element:1068\n"
	"lmkd:1069\n"
	"llkd:1070\n"
	"iorapd:1071\n"
	"gpu_service:1072\n"
	"network_stack:1073\n"
	"gsid:1074\n"
	"fsverity_cert:1075\n"
	"credstore:1076\n"
	"external_storage:1077\n"
	"ext_data_rw:1078\n"
	"ext_obb_rw:1079\n"
	"context_hub:1080\n"
	"virtualizationservice:1081\n"
	"artd:1082\n"
	"uwb:1083\n"
	"thread_network:1084\n"
	"diced:1085\n"
	"dmesgd:1086\n"
	"jc_weaver:1087\n"
	"jc_strongbox:1088\n"
	"jc_identitycred:1089\n"
	"sdk_sandbox:1090\n"
	"security_log_writer:1091\n"
	"prng_seeder:1092\n"
	"uprobestsats:1093\n"
	"cros_ec:1094\n"
	"mmd:1095\n"
	"shell:2000\n"
	"cache:2001\n"
	"diag:2002\n"
	"net_bt_admin:3001\n"
	"net_bt:3002\n"
	"inet:3003\n"
	"net_raw:3004\n"
	"net_admin:3005\n"
	"net_bw_stats:3006\n"
	"net_bw_acct:3007\n"
	"readproc:3009\n"
	"wakelock:3010\n"
	"uhid:3011\n"
	"readtracefs:3012\n"
	"virtualmachine:3013\n"
	"everybody:9997\n"
	"misc:9998\n"
	"nobody:9999";
static const char *const AID_GAPS =
	"oem_3000:3000\n"
	"oem_3008:3008\n"
	"oem_3020:3020";
static const struct { const char *user; const char *ctx; } AID_SELINUX_CTX[] = {
	/* uid 1000-2000: AOSP seapp_contexts + daemon domains */
	{ "root", "u:r:kernel:s0" },
	{ "system", "u:r:system_app:s0" },
	{ "radio", "u:r:radio:s0" },
	/* The device policy says "user=bluetooth seinfo=platform domain=bluetooth";
	 * the old mtk_hal_bluetooth label was a guess that no seapp rule
	 * backs. */
	{ "bluetooth", "u:r:bluetooth:s0" },
	{ "wifi", "u:r:wificond:s0" },
	{ "media", "u:r:mediametrics:s0" },
	{ "keystore", "u:r:keystore:s0" },
	{ "drm", "u:r:drm:s0" },
	{ "gps", "u:r:mnld:s0" },
	{ "shell", "u:r:shell:s0" },
	{ "log", "u:r:logd:s0" },
	{ "logd", "u:r:logd:s0" },
	{ "graphics", "u:r:surfaceflinger:s0" },
	{ "camera", "u:r:cameraserver:s0" },
	{ "input", "u:r:input:s0" },
	{ "audio", "u:r:audioserver:s0" },
	{ "vpn", "u:r:vpn:s0" },
	{ "install", "u:r:installd:s0" },
	{ "mount", "u:r:vold:s0" },
	{ "vold", "u:r:vold:s0" },
	{ "adb", "u:r:adbd:s0" },
	{ "dhcp", "u:r:dhcp:s0" },
	{ "nfc", "u:r:nfc:s0" },
	{ "secure_element", "u:r:secure_element:s0" },
	{ "webview_zygote", "u:r:webview_zygote:s0" },
	{ "mtp", "u:r:mtp:s0" },
	{ "clat", "u:r:clatd:s0" },
	{ "mediadrm", "u:r:mediadrm:s0" },
	{ "shared_relro", "u:r:shared_relro:s0" },
	{ "net_admin", "u:r:network_stack:s0" },
	{ "network_stack", "u:r:network_stack:s0" },
	{ "net_bt_admin", "u:r:bluetooth:s0" },
	{ "net_bt", "u:r:bluetooth:s0" },
	{ "net_bt_stack", "u:r:bluetooth:s0" },
	{ "audioserver", "u:r:audioserver:s0" },
	{ "cameraserver", "u:r:cameraserver:s0" },
	{ "debuggerd", "u:r:debuggerd:s0" },
	{ "nobody", "u:r:nobody:s0" },
};
/* Real daemon/app domains that init/zygote/device genuinely reachable ones,
 * allowed as the only valid domain namespace for an injected -Z/--context. */
static const char *const SELINUX_KNOWN_EXTRA_CTX[] = {
	"u:r:system_server:s0", "u:r:init:s0", "u:r:system_init:s0",
	"u:r:zygote:s0", "u:r:surfaceflinger:s0", "u:r:servicemanager:s0",
	"u:r:netd:s0", "u:r:vold:s0", "u:r:installd:s0", "u:r:adbd:s0",
	"u:r:untrusted_app:s0", "u:r:platform_app:s0", "u:r:priv_app:s0",
	"u:r:isolated_app:s0", "u:r:su:s0", "u:r:ksu:s0",
};
static void selinux_ctx_reject(const char *in)
{
	fprintf(stderr,
		"su: security context `%s' names a domain that does not exist on this device; refusing\n",
		in);
	exit(1);
}
static int selinux_ctx_known(const char *ctx)
{
	size_t i;
	if (ctx == NULL)
		return 0;
	char base[128];
	const char *mls = strstr(ctx, ":s0:c");
	if (mls != NULL) {
		size_t n = (size_t)(mls - ctx) + 3;
		if (n >= sizeof(base))
			return 0;
		memcpy(base, ctx, n);
		base[n] = '\0';
		ctx = base;
	}
	for (i = 0; i < sizeof(AID_SELINUX_CTX)/sizeof(AID_SELINUX_CTX[0]); i++)
		if (strcmp(AID_SELINUX_CTX[i].ctx, ctx) == 0)
			return 1;
	for (i = 0; i < sizeof(SELINUX_KNOWN_EXTRA_CTX)/sizeof(SELINUX_KNOWN_EXTRA_CTX[0]); i++)
		if (strcmp(SELINUX_KNOWN_EXTRA_CTX[i], ctx) == 0)
			return 1;
	/* The untrusted_app_NN family is chosen by the device policy from
	 * minTargetSdkVersion, and the numbers are device specific -- 30/29/27/25
	 * here.  Accept any of them: a hardcoded list made an explicit
	 * -Z u:r:untrusted_app_30:s0 fail with "domain does not exist" while
	 * the default path produced exactly that context.  Being a little
	 * permissive here costs nothing, because the per-uid check in
	 * selinux_ctx_gate_uid() is what actually narrows -Z. */
	if (strncmp(ctx, "u:r:untrusted_app_", 18) == 0) {
		const char *p = ctx + 18;
		if (*p >= '0' && *p <= '9') {
			while (*p >= '0' && *p <= '9')
				p++;
			return strcmp(p, ":s0") == 0;
		}
	}
	return 0;
}
/* Accept a full u:r:<domain>:s0 string or a bare known name (e.g. "shell",
 * "radio"), normalize it, and hard-fail if the domain is not one this device
 * could actually carry.  Rejects any non-sepolicy character (no "/", spaces,
 * newlines) so the ctx file can never be corrupted via injection. */
/* ---- per-uid observed SELinux domains -------------------------------
 *
 * The policy file gives one domain per AID, but that is not the whole
 * truth on this device: uid 1002 is declared user=bluetooth while every
 * process on it runs in mtk_hal_bluetooth, and uid 1000 alone hosts 63
 * different domains.  What a process can actually wear is the set of
 * labels observed for that uid, so -Z is checked against that set: a
 * context outside it is refused the way real su refuses a bad context
 * (message on stderr, non-zero exit) instead of being silently taken.
 *
 * Source is "ps -A -o LABEL,UID" -- the default USER column is a name,
 * not a uid, so the name would have to be resolved backwards.  Harvested
 * once per process; a uid with no live process has no set, and then the
 * domain-exists check alone decides, as before.
 */
static bool valid_uint_str(const char *s, long *out);
static int run_capture_argv_list(char **argv, char **out, size_t *outlen);

#define UID_DOM_MAX 8192
typedef struct { long uid; char dom[64]; int n; } uid_dom_t;
static uid_dom_t g_uid_doms[UID_DOM_MAX];
static int g_uid_doms_n;
static bool g_uid_doms_done;

static void selinux_ctx_domain(const char *ctx, char *out, size_t cap)
{
	const char *p = ctx;
	int colons = 0;
	while (*p != '\0' && colons < 2) {
		if (*p == ':') {
			colons++;
			if (colons == 2) { p++; break; }
		}
		p++;
	}
	snprintf(out, cap, "%s", p);
	char *c = strchr(out, ':');
	if (c != NULL)
		*c = '\0';
}

static void uid_doms_load(void)
{
	if (g_uid_doms_done)
		return;
	g_uid_doms_done = true;
	char *av[] = { (char *)"/system/bin/ps", (char *)"-A", (char *)"-o",
		(char *)"LABEL,UID", NULL };
	char *out = NULL;
	size_t outlen = 0;
	if (run_capture_argv_list(av, &out, &outlen) != 0 || out == NULL)
		return;
	char *copy = strdup(out);
	free(out);
	if (copy == NULL)
		return;
	char *save = NULL;
	for (char *line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		if (strncmp(line, "u:r:", 4) != 0)
			continue;
		char *ps = NULL;
		char *lab = strtok_r(line, " \t", &ps);
		char *uidstr = strtok_r(NULL, " \t", &ps);
		long uid;
		if (lab == NULL || uidstr == NULL || !valid_uint_str(uidstr, &uid))
			continue;
		char dom[64];
		selinux_ctx_domain(lab, dom, sizeof(dom));
		if (dom[0] == '\0')
			continue;
		int i;
		for (i = 0; i < g_uid_doms_n; i++)
			if (g_uid_doms[i].uid == uid && strcmp(g_uid_doms[i].dom, dom) == 0) {
				g_uid_doms[i].n++;
				break;
			}
		if (i < g_uid_doms_n || g_uid_doms_n >= UID_DOM_MAX)
			continue;
		g_uid_doms[g_uid_doms_n].uid = uid;
		snprintf(g_uid_doms[g_uid_doms_n].dom, sizeof(g_uid_doms[g_uid_doms_n].dom),
			"%s", dom);
		g_uid_doms[g_uid_doms_n].n = 1;
		g_uid_doms_n++;
	}
	free(copy);
}

/* The per-uid check cannot live in selinux_ctx_norm_validate(): -Z is
 * validated while parsing, and g_uid is still -1 then (it is only fixed
 * up once the whole command line has been read), so the gate would never
 * see a uid and would let everything through.  It runs after the uid is
 * final, next to where the default context is chosen. */
static void selinux_ctx_gate_uid(const char *ctx)
{
	if (g_uid < 0 || ctx == NULL || ctx[0] == '\0')
		return;
	uid_doms_load();
	char dom[64];
	selinux_ctx_domain(ctx, dom, sizeof(dom));
	bool have_uid = false, ok = false;
	for (int i = 0; i < g_uid_doms_n; i++)
		if (g_uid_doms[i].uid == g_uid) {
			have_uid = true;
			if (strcmp(g_uid_doms[i].dom, dom) == 0) {
				ok = true;
				break;
			}
		}
	if (!have_uid || ok)
		return;
	fprintf(stderr, "su: uid %ld does not run in `%s'; refusing\n", g_uid, dom);
	fprintf(stderr, "su: uid %ld runs in", g_uid);
	for (int i = 0; i < g_uid_doms_n; i++)
		if (g_uid_doms[i].uid == g_uid)
			fprintf(stderr, " %s", g_uid_doms[i].dom);
	fprintf(stderr, "\n");
	exit(1);
}

static const char *selinux_ctx_norm_validate(const char *in)
{
	static char norm[128];
	const char *ctx = in;
	size_t i;
	if (in == NULL || in[0] == '\0') {
		fprintf(stderr, "su: empty security context\n");
		exit(1);
	}
	if (strncmp(in, "u:r:", 4) != 0) {
		for (i = 0; i < sizeof(AID_SELINUX_CTX)/sizeof(AID_SELINUX_CTX[0]); i++)
			if (strcmp(AID_SELINUX_CTX[i].user, in) == 0) {
				ctx = AID_SELINUX_CTX[i].ctx;
				break;
			}
		if (strncmp(ctx, "u:r:", 4) != 0) {
			/* a bare domain name: only usable if it maps to a known ctx */
			static char bare[128];
			if (snprintf(bare, sizeof(bare), "u:r:%s:s0", in) >= (int)sizeof(bare))
				selinux_ctx_reject(in);
			if (!selinux_ctx_known(bare))
				selinux_ctx_reject(in);
			ctx = bare;
		}
	}
	for (i = 0; ctx[i] != '\0'; i++) {
		char c = ctx[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		      || (c >= '0' && c <= '9') || c == '_' || c == ':' || c == ','))
			selinux_ctx_reject(in);
		if (i >= sizeof(norm) - 2)
			selinux_ctx_reject(in);
	}
	if (!selinux_ctx_known(ctx))
		selinux_ctx_reject(in);
	snprintf(norm, sizeof(norm), "%s", ctx);
	return norm;
}
static bool valid_uint_str(const char *s, long *out);
/* When the Shizuku bridge is not up, every harvest attempt blocks until
 * the binder times out.  Two harvests then made a plain "su 0 -c id -Z"
 * miss its own deadline, and the command failed outright even though the
 * compiled-in baseline made the answer available without any harvest at
 * all.  One failed attempt disables the rest for this process. */
static int rishq_broken = 0;

static int rishq_query(const char *cmd, char **out, size_t *outlen);
static int facts_query(const char *mode, const char *arg, char **out, size_t *outlen);
static int run_capture_argv_list(char **argv, char **out, size_t *outlen);
static const char *aid_merged_table(void);
static const char *const g_usermap_name = ".usermap";
/* Look up "name:uid" lines in a merged table; return true when row found. */
static bool aid_table_has_uid(const char *table, long uid)
{
	if (table == NULL)
		return false;
	char *copy = strdup(table);
	if (copy == NULL)
		return false;
	bool res = false;
	char *save = NULL;
	for (char *line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		char *colon = strchr(line, ':');
		long v;
		if (colon && valid_uint_str(colon + 1, &v) && v == uid) {
			res = true;
			break;
		}
	}
	free(copy);
	return res;
}
/* Append the oem_# auto-named ranges AOSP reserves (2900-2999 vendor,
 * 5000-5999 second oem range): every value in these ranges exists as a
 * resolvable user/group name on real devices. */
static void aid_append_oem_range(char *merged, size_t cap, size_t *n, int lo, int hi)
{
	for (int u = lo; u <= hi; u++) {
		size_t left = cap - *n;
		if (left < 24)
			break;
		int w = snprintf(merged + *n, left, "oem_%d:%d\n", u, u);
		if (w < 0)
			break;
		*n += (size_t)w;
	}
}
/* Full, searchable identity table = static AID_USERS + the OEM/gap names
 * + the auto-named oem ranges + the real user list fetched from the device
 * itself via rishq (kept in workdir/.usermap).  This is what "su <user>"
 * resolves names against, so every user the vendor actually exposes
 * (incl. the 3000-series) has a uid<->name mapping instead of silently
 * collapsing into root. */
static const char *aid_merged_table(void)
{
	static char merged[65536];
	static bool built = false;
	if (!built) {
		built = true;
		size_t n = 0;
		const char *tables[2] = { AID_USERS, AID_GAPS };
		for (int ti = 0; ti < 2 && n < sizeof(merged) - 2; ti++) {
			char *copy = strdup(tables[ti]);
			if (copy == NULL)
				continue;
			char *save = NULL;
			for (char *line = strtok_r(copy, "\n", &save); line && n < sizeof(merged) - 2;
			     line = strtok_r(NULL, "\n", &save)) {
				size_t l = strlen(line);
				if (n + l + 2 >= sizeof(merged))
					break;
				memcpy(merged + n, line, l);
				n += l;
				merged[n++] = '\n';
			}
			free(copy);
		}
		/* Process.FIRST_OEM_APP_UID..LAST_OEM_APP_UID.  The previous
	 * 2900-2999 / 5000-5999 were not the OEM range at all: 5000-5999 sits
	 * inside the named AID block, so auto-naming it oem_# shadowed real
	 * AID names, and the actual OEM range got no name and no domain. */
		aid_append_oem_range(merged, sizeof(merged), &n, 29000, 29999);
		/* Merge the device's real users (uid unknown to the static
		 * table): e.g. vendor-only AIDs running on this box. */
		char path[PATH_MAX];
		snprintf(path, sizeof(path), "%s/%s", g_work_dir, g_usermap_name);
		FILE *f = fopen(path, "r");
		if (f) {
			char line[256];
			while (f && n < sizeof(merged) - 2 && fgets(line, sizeof(line), f)) {
				char *sp = strchr(line, ' ');
				if (!sp)
					continue;
				*sp = '\0';
				char *end;
				long u = strtol(sp + 1, &end, 10);
				if (end == sp + 1 || u < 1000 || u >= 200000)
					continue;
				size_t nl = strlen(line);
				while (nl > 0 && (line[nl - 1] == '\n' || line[nl - 1] == '\r'))
					line[--nl] = '\0';
				if (nl == 0 || strchr(line, ':') || strchr(line, ' '))
					continue;
				if (aid_table_has_uid(merged, u))
					continue;
				if (n + nl + 16 >= sizeof(merged))
					continue;
				memcpy(merged + n, line, nl);
				n += nl;
				merged[n++] = ':';
				size_t digs = snprintf(merged + n, sizeof(merged) - n, "%ld\n", u);
				n += digs;
			}
			fclose(f);
		}
		merged[n] = '\0';
	}
	return merged;
}
/* Fetch the device's real uid<->name list through rishq (the shell-level
 * bridge), persist it to workdir/.usermap, and refresh it once an hour so
 * vendor-specific users discovered by later runs keep the tables warm
 * without hammering shizuku on every invocation. */
static void aid_real_patch(void)
{
	if (g_work_dir[0] == '\0')
		return;
	char path[PATH_MAX], tmp[PATH_MAX];
	snprintf(path, sizeof(path), "%s/%s", g_work_dir, g_usermap_name);
	snprintf(tmp, sizeof(tmp), "%s/%s.tmp", g_work_dir, g_usermap_name);
	struct stat st;
	if (stat(path, &st) == 0 && st.st_size > 0
	    && time(NULL) - st.st_mtime < 3600)
		return;
	char *out = NULL;
	size_t outlen = 0;
	if (rishq_query("ps -A -o USER= -o UID= 2>/dev/null", &out, &outlen) != 0) {
		free(out);
		return;
	}
	FILE *f = fopen(tmp, "w");
	if (!f) {
		free(out);
		return;
	}
	int written = 0;
	if (out != NULL) {
		char *save = NULL;
		for (char *line = strtok_r(out, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
			char *sp = strchr(line, ' ');
			if (!sp)
				continue;
			*sp = '\0';
			char *end;
			errno = 0;
			long u = strtol(sp + 1, &end, 10);
			if (end == sp + 1 || errno)
				continue;
			char *ep = end;
			while (*ep == ' ')
				ep++;
			if (*ep != '\0' && *ep != '\n' && *ep != '\r')
				continue;
			if (line[0] == '\0')
				continue;
			fprintf(f, "%s %ld\n", line, u);
			written++;
		}
	}
	if (written == 0)
		fprintf(f, "root 0\n");
	fclose(f);
	rename(tmp, path);
	free(out);
}

/* The supplementary-group lookup for a single uid lives in the session
 * setup path (see the "No explicit -g/-s given" block in main), because
 * it needs PackageManager and the session's own uid, neither of which
 * exists at harvest time. */
static const char *aid_name_for_uid(long uid, char *name, size_t namesz)
{
	char *table = strdup(aid_merged_table());
	if (table == NULL)
		return NULL;
	char *save = NULL;
	const char *res = NULL;
	for (char *line = strtok_r(table, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		char *colon = strchr(line, ':');
		if (colon == NULL)
			continue;
		long v;
		if (valid_uint_str(colon + 1, &v) && v == uid) {
			size_t n = (size_t)(colon - line);
			if (n >= namesz)
				n = namesz - 1;
			memcpy(name, line, n);
			name[n] = '\0';
			res = name;
			break;
		}
	}
	free(table);
	return res;
}
static int run_cmd_capture_argv(const char *path, const char *arg1, const char *arg2, char **out, size_t *outlen);
/* L0 tables are device facts.  They change only when the user installs or
 * removes a package, so a long TTL is right: a short one would re-run the
 * 15s rishq cold start often enough to be felt, and would make the
 * harvested answer depend on when it was taken. */
#define SEAPP_MAX_AGE 86400
#define APPTAB_MAX_AGE 21600

/* ---------------- L0: device-harvested app / SELinux tables ----------------
 *
 * These are device facts, not session facts, so they are harvested once
 * through rishq and then replayed verbatim.  Recomputing them per session
 * is what makes a sandbox give itself away: two runs of the same command
 * must produce byte-identical answers, and anything derived from a live
 * /proc (pids, random tokens, timestamps) does not.
 *
 * The domain name an app runs in is decided by the device's own policy
 * file, /system/etc/selinux/plat_seapp_contexts, which the app domain
 * cannot read but rishq can.  It is keyed on minTargetSdkVersion, not on
 * an arbitrary per-device index, which is why untrusted_app_27 must never
 * be hardcoded: on another device, or for an app with a different target
 * SDK, the same suffix maps differently or not at all.
 */
#define SEAPP_FILE ".seapp"
#define APPTAB_FILE ".apptab"

/* "minSdk=<n> domain=<name>" per applicable user=_app rule. */
struct seapp_rule {
	long min_sdk;
	char domain[64];
};

static const char *seapp_path(void)
{
	static char p[PATH_MAX];
	snprintf(p, sizeof(p), "%s/%s", g_work_dir, SEAPP_FILE);
	return p;
}

static const char *apptab_path(void)
{
	static char p[PATH_MAX];
	snprintf(p, sizeof(p), "%s/%s", g_work_dir, APPTAB_FILE);
	return p;
}

static bool l0_fresh(const char *path, unsigned max_age);

/* An app's MCS categories are fully determined by its app id, so they are
 * computed rather than harvested:
 *
 *     n    = appid - 10000
 *     cat1 = n % 256
 *     cat2 = 256 + n / 256
 *
 * This is Android's own encoding -- the 16-bit app offset split into a low
 * and a high byte, with the high byte lifted by 256 to clear the reserved
 * low categories -- and it was verified against 60 live contexts on this
 * device (uid 10282 -> c26,c257; 10368 -> c112,c257; 10380 -> c124,c257;
 * 10241 -> c241,c256; 10162 -> c162,c256; 10276 -> c20,c257) plus 41
 * platform/priv contexts that carry the fixed c512,c768 instead.
 *
 * Reading them off a running process with `ps -A -Z` also works, but it
 * costs a 700-line harvest, a persistent .appctx file, and a lookup that
 * silently fails for any app not currently running.  Computing it removes
 * all three. */
static void mcs_for_app_id(long app_id, char *out, size_t cap)
{
	long n = app_id - 10000;
	if (n < 0)
		n = 0;
	snprintf(out, cap, ":c%ld,c%ld,c512,c768", n % 256, 256 + n / 256);
}


static bool l0_fresh(const char *path, unsigned max_age)
{
	struct stat st;
	if (stat(path, &st) != 0)
		return false;
	return (time(NULL) - st.st_mtime) < (time_t)max_age;
}

/* Pull plat_seapp_contexts and keep only the user=_app rules that name a
 * domain, as "<minSdk> <domain>" lines. */
/* Store the device's own app rules verbatim.  Earlier this file was reduced
 * to just "minTargetSdkVersion domain" pairs, which made the domain of a
 * system app impossible to decide: those rules are selected by seinfo,
 * isPrivApp and name, none of which survived.  The whole file is 24 lines,
 * so keeping it intact costs nothing and keeps the resolution faithful. */
static void harvest_seapp_rules(void)
{
	if (l0_fresh(seapp_path(), SEAPP_MAX_AGE))
		return;
	char *out = NULL;
	size_t outlen = 0;
	if (rishq_query("cat /system/etc/selinux/plat_seapp_contexts 2>/dev/null",
			&out, &outlen) != 0 || out == NULL) {
		free(out);
		return;
	}
	FILE *f = fopen(seapp_path(), "w");
	if (f == NULL) {
		free(out);
		return;
	}
	char *save = NULL;
	for (char *line = strtok_r(out, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		if (strstr(line, "user=_app") == NULL)
			continue;
		if (strstr(line, "isSystemServer=true") != NULL)
			continue;
		if (strstr(line, " domain=") == NULL)
			continue;
		fprintf(f, "%s\n", line);
	}
	fclose(f);
	free(out);
}
/* uid -> package name index, from pm list packages -U.
 *
 * This deliberately does not scrape "dumpsys package packages".  That
 * output is 34k lines on this device, and parsing it for one package's
 * targetSdk meant decoding a format that repeats the same package header
 * in its Dexopt and Queries sub-sections -- which is how com.termux came
 * out recorded as targetSdk 29 and a system app, and bin.mt.plus as 31
 * instead of 28.  The index is 400 lines of a fixed "package:NAME uid:N"
 * shape, and the per-package facts are fetched one package at a time and
 * cached here, so a lookup costs one small query the first time and none
 * afterwards. */
static void harvest_app_table(void)
{
	if (l0_fresh(apptab_path(), APPTAB_MAX_AGE))
		return;
	char *out = NULL;
	size_t outlen = 0;
	/* One call, one whole table.  The dex asks PackageManager for every
	 * installed package at once instead of scraping "pm list packages -U"
	 * and then paying a "dumpsys package <name>" round trip per entry --
	 * that per-package walk is what used to mis-attribute targetSdk, and
	 * it needed the Shizuku bridge alive for the whole harvest.  Running
	 * as our own uid needs no permission and no bridge at all. */
	if (facts_query("--user", "0", &out, &outlen) != 0 || out == NULL) {
		free(out);
		return;
	}
	FILE *f = fopen(apptab_path(), "w");
	if (f == NULL) {
		free(out);
		return;
	}
	char *save = NULL;
	for (char *line = strtok_r(out, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		/* FACT<TAB>uid<TAB>user<TAB>name<TAB>tsdk<TAB>sys<TAB>priv<TAB>path */
		long uid, user, ts;
		int isys, ipriv;
		char name[160];
		if (sscanf(line, "FACT\t%ld\t%ld\t%159[^\t]\t%ld\t%d\t%d",
				&uid, &user, name, &ts, &isys, &ipriv) != 6)
			continue;
		if (uid < 0 || name[0] == '-')
			continue;
		/* isSystem comes from FLAG_SYSTEM, which is what the runtime's own
		 * app-domain selection reads.  A path test cannot tell the 51
		 * preinstalled packages on this device that live under /data/app
		 * from genuine user apps. */
		fprintf(f, "%ld %s %ld %s %s\n", uid, name, ts,
			isys ? "system" : "user", ipriv ? "priv" : "unpriv");
	}
	fclose(f);
	free(out);
}

/* Android picks the rule with the highest minTargetSdkVersion that the
 * app still satisfies, exactly as the runtime does. */
/* Standard AOSP app rules, compiled in.
 *
 * Every device fact we resolve a context from used to be scraped over
 * Shizuku into a file, which made the whole facility depend on that bridge
 * staying alive: with Shizuku down the rule table was empty and every app
 * fell back to the catch-all domain.  This is the unmodified AOSP rule set
 * for app contexts, so a device whose own plat_seapp_contexts cannot be
 * read still gets the right answer for the overwhelming majority of apps.
 * When the real file is available it wins, because it carries the vendor
 * rules this cannot know about. */
static const char aosp_seapp_baseline[] =
	"user=_app seinfo=platform name=com.android.traceur domain=traceur_app type=app_data_file levelFrom=all\n"
	"user=_app isPrivApp=true name=com.android.remoteprovisioner domain=remote_prov_app type=app_data_file levelFrom=all\n"
	"user=_app seinfo=platform isPrivApp=true name=com.android.permissioncontroller domain=permissioncontroller_app type=privapp_data_file levelFrom=all\n"
	"user=_app isPrivApp=true name=com.google.android.permissioncontroller domain=permissioncontroller_app type=privapp_data_file levelFrom=all\n"
	"user=_app seinfo=media isPrivApp=true name=com.android.providers.media.module domain=mediaprovider_app type=privapp_data_file levelFrom=all\n"
	"user=_app isPrivApp=true name=com.google.android.providers.media.module domain=mediaprovider_app type=privapp_data_file levelFrom=all\n"
	"user=_app isPrivApp=true name=com.android.vzwomatrigger domain=vzwomatrigger_app type=privapp_data_file levelFrom=all\n"
	"user=_app isPrivApp=true name=com.google.android.gms domain=gmscore_app type=privapp_data_file levelFrom=user\n"
	"user=_app isPrivApp=true name=com.google.android.gms.* domain=gmscore_app type=privapp_data_file levelFrom=user\n"
	"user=_app isPrivApp=true name=com.google.android.gms:* domain=gmscore_app type=privapp_data_file levelFrom=user\n"
	"user=_app isPrivApp=true name=com.google.android.gsf domain=gmscore_app type=privapp_data_file levelFrom=user\n"
	"user=_app seinfo=app_zygote domain=app_zygote levelFrom=user\n"
	"user=_app seinfo=media domain=mediaprovider type=app_data_file levelFrom=user\n"
	"user=_app seinfo=platform domain=platform_app type=app_data_file levelFrom=user\n"
	"user=_app isEphemeralApp=true domain=ephemeral_app type=app_data_file levelFrom=all\n"
	"user=_app isPrivApp=true domain=priv_app type=privapp_data_file levelFrom=user\n"
	"user=_app minTargetSdkVersion=32 domain=untrusted_app type=app_data_file levelFrom=all\n"
	"user=_app minTargetSdkVersion=30 domain=untrusted_app_30 type=app_data_file levelFrom=all\n"
	"user=_app minTargetSdkVersion=29 domain=untrusted_app_29 type=app_data_file levelFrom=all\n"
	"user=_app minTargetSdkVersion=28 domain=untrusted_app_27 type=app_data_file levelFrom=all\n"
	"user=_app minTargetSdkVersion=26 domain=untrusted_app_27 type=app_data_file levelFrom=user\n"
	"user=_app domain=untrusted_app_25 type=app_data_file levelFrom=user\n";

/* The device's own rules when they can be read, the compiled-in AOSP set
 * otherwise. */
static char *seapp_rules_text(void)
{
	FILE *f = fopen(seapp_path(), "r");
	if (f != NULL) {
		long sz = -1;
		if (fseek(f, 0, SEEK_END) == 0)
			sz = ftell(f);
		if (sz > 0 && sz < (1 << 20)) {
			rewind(f);
			char *buf = malloc((size_t)sz + 1);
			if (buf != NULL) {
				size_t got = fread(buf, 1, (size_t)sz, f);
				fclose(f);
				buf[got] = '\0';
				if (strstr(buf, " domain=") != NULL)
					return buf;
				free(buf);
				return strdup(aosp_seapp_baseline);
			}
		}
		fclose(f);
	}
	return strdup(aosp_seapp_baseline);
}

/* seapp_contexts name selectors use "*" and, on older policies, ":" as
 * wildcards, so a plain strcmp would miss com.google.android.gms.*. */
static bool seapp_name_matches(const char *pattern, const char *name)
{
	if (strchr(pattern, '*') == NULL && strchr(pattern, ':') == NULL)
		return strcmp(pattern, name) == 0;
	const char *p = pattern, *n = name, *star = NULL, *retry = NULL;
	while (*n != '\0') {
		if (*p == '*' || *p == ':') {
			star = p++;
			retry = n;
		} else if (*p == *n) {
			p++;
			n++;
		} else if (star != NULL) {
			p = star + 1;
			n = ++retry;
		} else {
			return false;
		}
	}
	while (*p == '*' || *p == ':')
		p++;
	return *p == '\0';
}

/* Which of the policy's seinfo buckets a package falls in.  seinfo is
 * really the signing key, which dumpsys will not tell us, so this keys off
 * what is observable: the media providers carry the media key, and the rest
 * of the system image carries the platform key. */
static void package_seinfo(const char *pkg, int is_system, int is_priv,
		char *out, size_t cap)
{
	if (pkg != NULL && (strncmp(pkg, "com.android.providers.media", 26) == 0
			|| strncmp(pkg, "com.google.android.providers.media", 35) == 0))
		snprintf(out, cap, "media");
	else
		/* AOSP has no "system_app" app domain: plat_seapp_contexts gives
		 * every app off /system the platform_app domain, which is the
		 * label the device was observed to use for them.  is_system
		 * therefore has to reach seinfo=platform, or a system app drops
		 * through to the minTargetSdkVersion ladder and is reported as
		 * untrusted_app_*.  is_priv is included for the same reason --
		 * a privileged app is platform-signed by definition. */
		snprintf(out, cap, "%s", (is_system || is_priv) ? "platform" : "");
}

/* Resolve one package's domain the way the platform does: walk the rules in
 * file order and take the first that matches.  The order is load-bearing --
 * the minTargetSdkVersion rules run from strictest to loosest, so first
 * match is what keeps a targetSdk 28 app out of the catch-all
 * untrusted_app_25 that sits below it.
 *
 * Returns the domain and reports whether the matched rule isolates per app
 * (levelFrom=all), which is what decides computed versus fixed categories. */
static const char *seapp_lookup(const char *pkg, long target_sdk, int is_priv,
		int is_system, int *level_from_all)
{
	static char dom[64];
	char seinfo[32];
	dom[0] = '\0';
	*level_from_all = 0;
	package_seinfo(pkg, is_system, is_priv, seinfo, sizeof(seinfo));

	char *text = seapp_rules_text();
	if (text == NULL)
		return NULL;
	int best_score = -1;
	char *save = NULL;
	for (char *line = strtok_r(text, "\n", &save); line;
			line = strtok_r(NULL, "\n", &save)) {
		const char *d = strstr(line, " domain=");
		if (d == NULL)
			continue;
		d += 8;
		char cand[64];
		int k = 0;
		while (d[k] && !isspace((unsigned char)d[k]) && k < (int)sizeof(cand) - 1) {
			cand[k] = d[k];
			k++;
		}
		cand[k] = '\0';
		if (k == 0)
			continue;

		const char *nm = strstr(line, " name=");
		if (nm != NULL) {
			char pat[128];
			const char *s = nm + 6;
			int j = 0;
			while (*s && !isspace((unsigned char)*s) && j < (int)sizeof(pat) - 1)
				pat[j++] = *s++;
			pat[j] = '\0';
			if (pkg == NULL || !seapp_name_matches(pat, pkg))
				continue;
		}
		if (strstr(line, "isPrivApp=true") != NULL && !is_priv)
			continue;
		if (strstr(line, "isPrivApp=false") != NULL && is_priv)
			continue;
		if (strstr(line, "fromRunAs=true") != NULL)
			continue;
		if (strstr(line, "isEphemeralApp=true") != NULL)
			continue;
		const char *si = strstr(line, " seinfo=");
		if (si != NULL) {
			char want[32];
			const char *s = si + 8;
			int j = 0;
			while (*s && !isspace((unsigned char)*s) && j < (int)sizeof(want) - 1)
				want[j++] = *s++;
			want[j] = '\0';
			if (strcmp(want, seinfo) != 0)
				continue;
		}
		const char *ts = strstr(line, " minTargetSdkVersion=");
		if (ts != NULL && target_sdk < atol(ts + 21))
			continue;

		/* Prefer the most specific rule that matches.  Plain first-match
		 * gets this wrong: com.android.providers.media.module matches
		 * both "seinfo=media domain=mediaprovider" and the four-selector
		 * rule naming it, and the device gives the latter.  Counting
		 * selectors reproduces that, while leaving the minTargetSdkVersion
		 * ladder to file order, which is what it relies on. */
		int score = 0;
		for (const char *k = line; (k = strstr(k, "=")) != NULL; k++)
			if (k == line || isspace((unsigned char)k[-1]))
				score++;
		if (score <= best_score)
			continue;
		best_score = score;
		snprintf(dom, sizeof(dom), "%s", cand);
		*level_from_all = strstr(line, "levelFrom=all") != NULL;
	}
	free(text);
	return dom[0] != '\0' ? dom : NULL;
}

/* Rewrite one index line with its detail filled in, so the next session
 * resolves the same uid without another query. */
static void apptab_cache_detail(long uid, const char *name, long tsdk,
		int is_system, int is_priv)
{
	FILE *f = fopen(apptab_path(), "r");
	if (f == NULL)
		return;
	/* The temporary must sit beside the target: a rename across
	 * filesystems fails, and /data/local/tmp is not writable by an app
	 * uid, so the first version silently cached nothing. */
	char tmp[PATH_MAX];
	snprintf(tmp, sizeof(tmp), "%s.tmp", apptab_path());
	FILE *w = fopen(tmp, "w");
	if (w == NULL) {
		fclose(f);
		return;
	}
	char line[320];
	while (fgets(line, sizeof(line), f) != NULL) {
		long u, ts;
		char nm[160], sys_s[16], priv_s[16];
		if (sscanf(line, "%ld %159s %ld %15s %15s", &u, nm, &ts,
				sys_s, priv_s) == 5 && u == uid && ts <= 0) {
			fprintf(w, "%ld %s %ld %s %s\n", uid, name, tsdk,
				is_system ? "system" : "user",
				is_priv ? "priv" : "plain");
			continue;
		}
		fputs(line, w);
	}
	fclose(f);
	fclose(w);
	rename(tmp, apptab_path());
}

/* Fetch one package's targetSdk, system flag and privileged flag.  A
 * single-package dump is a few hundred lines with exactly one package
 * header, so there is nothing to disambiguate. */
static void apptab_fetch_detail(const char *name, long uid, long *tsdk,
		int *is_system, int *is_priv)
{
	char cmd[256];
	snprintf(cmd, sizeof(cmd), "dumpsys package %s 2>/dev/null", name);
	char *out = NULL;
	size_t outlen = 0;
	if (rishq_query(cmd, &out, &outlen) != 0 || out == NULL) {
		free(out);
		return;
	}
	*tsdk = 0;
	*is_system = 0;
	*is_priv = 0;
	int have_path = 0;
	char codepath[256] = { 0 };
	char *save = NULL;
	for (char *line = strtok_r(out, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		long u;
		if (sscanf(line, " userId=%ld", &u) == 1)
			have_path = u == uid ? have_path : -1;
		if (sscanf(line, " codePath=%255s", codepath) == 1)
			have_path = 1;
		const char *ts = strstr(line, "targetSdk=");
		if (ts != NULL)
			*tsdk = atol(ts + 10);
		if (strstr(line, "pkgFlags=[") != NULL && have_path == 0)
			*is_system = strstr(line, " SYSTEM ") != NULL;
	}
	/* Everything under /data is installed by the user and everything
	 * else lives in the read-only system image, so the path settles it
	 * even when dumpsys omits the flags line.  Verified against the
	 * device: no package in /data/app is a system app. */
	*is_system = have_path > 0 && strncmp(codepath, "/data/", 6) != 0;
	*is_priv = strstr(codepath, "priv-app") != NULL;
	free(out);
}

static bool apptab_lookup(long uid, long *target_sdk, int *is_system,
		char *package_name, size_t name_cap, int *is_priv_app)
{
	long app_id = uid % 100000;
	/* Ask the dex directly.
	 *
	 * The cached table was never usable: this process runs as uid 2000
	 * under rish, which cannot create files in the app's private
	 * directory, so every harvest silently wrote nothing and the table
	 * stayed absent.  The lookup that matters is for exactly one uid per
	 * session, so there is nothing to amortise here -- a single binder
	 * query replaces the file, the staleness check and the rewrite. */
	{
		char ubuf[16];
		snprintf(ubuf, sizeof(ubuf), "%ld", uid);
		char *out = NULL;
		size_t outlen = 0;
		if (facts_query("--uid", ubuf, &out, &outlen) == 0 && out != NULL) {
			long u, user, ts;
			int isys, ipriv;
			char name[160];
			if (sscanf(out, "FACT\t%ld\t%ld\t%159[^\t]\t%ld\t%d\t%d",
					&u, &user, name, &ts, &isys, &ipriv) == 6
			    && u % 100000 == app_id && name[0] != '-') {
				snprintf(package_name, name_cap, "%s", name);
				*target_sdk = ts;
				*is_system = isys;
				*is_priv_app = ipriv;
				free(out);
				return true;
			}
		}
		free(out);
	}
	FILE *f = fopen(apptab_path(), "r");
	if (f == NULL)
		return false;
	char line[320];
	bool found = false;
	long u, ts;
	char name[160], sys_s[16], priv_s[16];
	while (fgets(line, sizeof(line), f) != NULL) {
		if (sscanf(line, "%ld %159s %ld %15s %15s", &u, name, &ts,
				sys_s, priv_s) != 5)
			continue;
		if (u % 100000 != app_id)
			continue;
		snprintf(package_name, name_cap, "%s", name);
		*is_priv_app = strcmp(priv_s, "priv") == 0;
		*is_system = strcmp(sys_s, "system") == 0;
		if (ts <= 0) {
			apptab_fetch_detail(name, u, &ts, is_system, is_priv_app);
			*target_sdk = ts;
			fclose(f);
			apptab_cache_detail(u, name, ts, *is_system, *is_priv_app);
			return true;
		}
		*target_sdk = ts;
		found = true;
		break;
	}
	fclose(f);
	return found;
}


/* Domains that isolate each app get the computed per-app pair; every
 * shared-level domain observed on a real device (platform_app, priv_app,
 * gmscore_app, mediaprovider) carries the same fixed c512,c768 instead. */
static void mcs_categories_for_domain(const char *dom, long app_id,
		char *out, size_t cap)
{
	if (dom != NULL && strncmp(dom, "untrusted_app", 13) == 0) {
		long n = app_id - 10000;
		if (n < 0)
			n = 0;
		snprintf(out, cap, ":c%ld,c%ld,c512,c768", n % 256, 256 + n / 256);
		return;
	}
	snprintf(out, cap, ":c512,c768");
}


/* Full context for a non-root app uid: the domain comes from the device's
 * own policy keyed on the app's real target SDK, the categories are
 * computed from the app id.  Nothing here is harvested per app, so the
 * answer is identical whether or not the app is currently running. */
static const char *selinux_ctx_for_app_uid(long uid)
{
	static char ctx[192];
	ctx[0] = '\0';
	long app_id = uid % 100000;
	/* Shared platform uids keep their own domains and are not app
	 * contexts at all; the caller resolves those by name. */
	if (app_id == 1000 || app_id == 1001 || app_id == 1002
	    || (app_id >= 2000 && app_id <= 2999) || (app_id >= 3000 && app_id <= 3999)
	    || (app_id >= 5000 && app_id <= 5999))
		return NULL;
	/* Isolated processes (Process.FIRST_ISOLATED_UID..LAST_ISOLATED_UID)
	 * own no installed package, so the package table cannot describe them
	 * and they came back with no context.  The policy has a domain for
	 * them -- this device had six of them running in isolated_app -- and
	 * it is levelFrom=user, so the categories are the fixed pair.
	 *
	 * The OEM app range (29000-29999) is deliberately NOT given oem_app
	 * here: no oem_app process exists on this device and the loaded policy
	 * cannot be read to confirm the domain is even defined, and inventing
	 * a label the policy does not have leaves the session with no context
	 * at all.  That range still needs its name mapping (fixed above), but
	 * its context is a known open item. */
	if (app_id >= 99000 && app_id <= 99999) {
		snprintf(ctx, sizeof(ctx), "u:r:isolated_app:s0:c512,c768");
		return ctx;
	}
	/* SDK sandbox uids (Process.FIRST_SDK_SANDBOX_UID..LAST_SDK_SANDBOX_UID)
	 * are user=_sdksandbox in the policy, and that rule is levelFrom=all --
	 * so unlike the shared-level domains above, the categories are the
	 * per-app computation.  They sit below the app range and used to be
	 * resolved as ordinary apps. */
	if (app_id >= 20000 && app_id <= 28999) {
		char mcs[128];
		mcs_for_app_id(app_id, mcs, sizeof(mcs));
		snprintf(ctx, sizeof(ctx), "u:r:sdk_sandbox:s0%s", mcs);
		return ctx;
	}
	harvest_seapp_rules();
	harvest_app_table();

	long target_sdk = 0;
	int is_system = 0, is_priv = 0, level_all = 0;
	char pkbuf[128] = { 0 };
	const char *dom = NULL;
	if (apptab_lookup(uid, &target_sdk, &is_system, pkbuf, sizeof(pkbuf), &is_priv))
		dom = seapp_lookup(pkbuf, target_sdk, is_priv, is_system, &level_all);
	if (dom == NULL) {
		/* No package owns this uid, or the harvest failed.  Use the
		 * untrusted domain the device assigns to ordinary apps rather
		 * than guessing a name of our own. */
		int la = 0;
		dom = seapp_lookup(NULL, 0, 0, 0, &la);
		if (dom == NULL)
			return NULL;
		level_all = la;
	}
	char mcs[128];
	if (level_all)
		mcs_for_app_id(app_id, mcs, sizeof(mcs));
	else
		snprintf(mcs, sizeof(mcs), ":c512,c768");
	snprintf(ctx, sizeof(ctx), "u:r:%s:s0%s", dom, mcs);
	return ctx;
}

static const char *selinux_ctx_for_user(const char *user)
{
	/* A per-app uid must be resolved before the numeric form is turned
	 * into an AID_USERS name: once the name exists, "10402" is
	 * indistinguishable from any other account name, and the app's real
	 * domain would never be looked up. */
	if (user != NULL && isdigit((unsigned char)user[0])) {
		long u;
		if (valid_uint_str(user, &u) && u >= 10000) {
			const char *appctx = selinux_ctx_for_app_uid(u);
			if (appctx != NULL && appctx[0] != '\0')
				return appctx;
		}
	}
	/* resolve name like uid/gid resolution does: numeric -> AID_USERS name */
	const char *name = user;
	char namebuf[64];
	if (name != NULL && name[0] != '\0' && isdigit((unsigned char)name[0])) {
		long u;
		if (valid_uint_str(name, &u) && aid_name_for_uid(u, namebuf, sizeof(namebuf)))
			name = namebuf;
	}
	/* KernelSU is the reference here, and its root sessions run in
	 * u:r:ksu:s0 -- that string is hardcoded in ksud itself.  Note this
	 * is NOT the u:r:su:s0 constant that appears in KernelSU's Natives.kt:
	 * that one is only the *default value an App Profile starts from*, not
	 * the domain a real su session lands in.  Getting this wrong is exactly
	 * the kind of tell we are trying to avoid, since u:r:su:s0 is the old
	 * Magisk domain and reads as "old Magisk" rather than "KernelSU".
	 * kernel:s0 would be worse still -- that is init's domain, shared with
	 * the rest of uid 0's 24 observed domains. */
	if (name == NULL || name[0] == '\0' || strcmp(name, "root") == 0)
		return "u:r:ksu:s0";
	if (strcmp(name, "shell") == 0)
		return "u:r:shell:s0";

	/* real-time context list: scan ps -Z -A for the target user */
	char exact_ctx[96];
	snprintf(exact_ctx, sizeof(exact_ctx), "u:r:%s:s0", name);
	static char g_ctx_buf[128];
	g_ctx_buf[0] = '\0';
	char *out = NULL;
	size_t outlen = 0;
	if (run_cmd_capture_argv("/system/bin/ps", "-Z", "-A", &out, &outlen) == 0 && out != NULL) {
		char *copy = strdup(out);
		free(out);
		if (copy != NULL) {
			const char *pref = NULL;
			char *lsave = NULL;
			for (char *line = strtok_r(copy, "\n", &lsave); line; line = strtok_r(NULL, "\n", &lsave)) {
				if (strncmp(line, "u:r:", 4) != 0)
					continue;
				char *psave = NULL;
				char *label = strtok_r(line, " ", &psave);
				char *uname = strtok_r(NULL, " ", &psave);
				if (label == NULL || uname == NULL)
					continue;
				if (strcmp(uname, name) != 0)
					continue;
				if (strcmp(label, exact_ctx) == 0) {
					snprintf(g_ctx_buf, sizeof(g_ctx_buf), "%s", label);
					break;
				}
			}
			/* Nothing else is acceptable here.  An earlier version fell
			 * back to the first "u:r:" line of ps when no process
			 * matched, which handed every unrecognised app the label of
			 * an unrelated running process -- right often enough to
			 * look like it was working.  Only an exact match counts. */
			free(copy);
			if (g_ctx_buf[0] != '\0')
				return g_ctx_buf;
		}
	}
	/* fallback: static table */
	for (size_t i = 0; i < sizeof(AID_SELINUX_CTX)/sizeof(AID_SELINUX_CTX[0]); i++)
		if (strcmp(AID_SELINUX_CTX[i].user, name) == 0)
			return AID_SELINUX_CTX[i].ctx;
	return "u:r:shell:s0";
}
static bool valid_uint_str(const char *s, long *out)
{
	size_t len = strlen(s);
	if (len < 1 || len > 10)
		return false;
	for (size_t i = 0; i < len; i++) {
		if (!isdigit((unsigned char)s[i]))
			return false;
	}
	errno = 0;
	char *end;
	long v = strtol(s, &end, 10);
	if (errno || *end != '\0' || v < 0 || v > INT_MAX_VALUE)
		return false;
	if (out)
		*out = v;
	return true;
}
static void xstrcat_grow(char **buf, size_t *cap, size_t *len, const char *s, size_t n)
{
	if (*buf == NULL) {
		*cap = 1024;
		*buf = malloc(*cap);
		if (*buf == NULL) {
			perror("malloc");
			exit(1);
		}
	}
	while (*len + n + 1 > *cap) {
		*cap *= 2;
		*buf = realloc(*buf, *cap);
		if (*buf == NULL) {
			perror("realloc");
			exit(1);
		}
	}
	memcpy(*buf + *len, s, n);
	*len += n;
	(*buf)[*len] = '\0';
}
static void cmd_set_value(const char *val)
{
	size_t n = strlen(val);
	xstrcat_grow(&g_cmd, &g_cmd_cap, &g_cmd_len, val, n);
}
static void cmd_append_arg(const char *arg)
{
	size_t n = strlen(arg);
	xstrcat_grow(&g_cmd, &g_cmd_cap, &g_cmd_len, " ", 1);
	xstrcat_grow(&g_cmd, &g_cmd_cap, &g_cmd_len, arg, n);
}
static bool is_enoexec(const char *p)
{
	int fd = open(p, O_RDONLY);
	if (fd < 0)
		return true;
	unsigned char hdr[4];
	ssize_t n = read(fd, hdr, sizeof(hdr));
	close(fd);
	if (n <= 0)
		return true;
	if (n >= 4 && hdr[0] == 0x7f && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F')
		return false;
	if (hdr[0] == '#' && hdr[1] == '!') {
		char line[512];
		FILE *f = fopen(p, "r");
		if (!f)
			return true;
		if (fgets(line, sizeof(line), f) == NULL) {
			fclose(f);
			return true;
		}
		fclose(f);
		if (line[0] != '#' || line[1] != '!')
			return true;
		char *ip = line + 2;
		while (*ip == ' ' || *ip == '\t')
			ip++;
		char *end = ip;
		while (*end && *end != ' ' && *end != '\t' && *end != '\n' && *end != '\r')
			end++;
		if (end == ip)
			return true;
		*end = '\0';
		struct stat st;
		if (stat(ip, &st) == 0)
			return false;
		return true;
	}
	return true;
}
static int shell_validate(const char *s)
{
	if (s == NULL || s[0] == '\0') {
		fprintf(stderr, "Cannot execute : No such file or directory\n");
		return 1;
	}
	if (strchr(s, '/') != NULL) {
		struct stat st;
		if (stat(s, &st) != 0) {
			fprintf(stderr, "Cannot execute %s: No such file or directory\n", s);
			return 1;
		}
		if (S_ISDIR(st.st_mode)) {
			fprintf(stderr, "Cannot execute %s: Permission denied\n", s);
			return 1;
		}
		if (access(s, X_OK) != 0) {
			fprintf(stderr, "Cannot execute %s: Permission denied\n", s);
			return 1;
		}
		if (is_enoexec(s))
			return 2;
		return 0;
	}
	bool found = false;
	const char *err = "No such file or directory";
	char *path = strdup(ANDROID_PATH);
	char *save = NULL;
	for (char *d = strtok_r(path, ":", &save); d; d = strtok_r(NULL, ":", &save)) {
		char full[PATH_MAX];
		snprintf(full, sizeof(full), "%s/%s", d, s);
		struct stat st;
		if (stat(full, &st) == 0) {
			found = true;
			if (!S_ISDIR(st.st_mode) && access(full, X_OK) == 0) {
				free(path);
				if (is_enoexec(full))
					return 2;
				return 0;
			}
		}
	}
	free(path);
	if (found)
		err = "Permission denied";
	fprintf(stderr, "Cannot execute %s: %s\n", s, err);
	return 1;
}
static int run_cmd_capture_argv(const char *path, const char *arg1, const char *arg2, char **out, size_t *outlen);
static int run_cmd_capture(const char *path, const char *arg, char **out, size_t *outlen)
{
	return run_cmd_capture_argv(path, arg, NULL, out, outlen);
}
/* Same capture, but for a command with an arbitrary argument list.  The
 * two-argument form above cannot express the app_process invocation the
 * facts dex needs. */
static int run_capture_argv_list(char **argv, char **out, size_t *outlen)
{
	int pipefd[2];
	if (pipe(pipefd) != 0)
		return -1;
	pid_t pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}
	if (pid == 0) {
		dup2(pipefd[1], STDOUT_FILENO);
		close(pipefd[0]);
		close(pipefd[1]);
		execv(argv[0], argv);
		_exit(127);
	}
	close(pipefd[1]);
	size_t cap = 8192, len = 0;
	char *buf = malloc(cap);
	if (!buf) {
		close(pipefd[0]);
		return -1;
	}
	for (;;) {
		if (len + 4096 + 1 > cap) {
			cap *= 2;
			char *nb = realloc(buf, cap);
			if (!nb) {
				free(buf);
				close(pipefd[0]);
				return -1;
			}
			buf = nb;
		}
		ssize_t n = read(pipefd[0], buf + len, cap - len - 1);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (n == 0)
			break;
		len += (size_t)n;
	}
	buf[len] = '\0';
	close(pipefd[0]);
	int status = 0;
	waitpid(pid, &status, 0);
	*out = buf;
	*outlen = len;
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -1;
	return 0;
}

static int run_cmd_capture_argv(const char *path, const char *arg1, const char *arg2, char **out, size_t *outlen)
{
	int pipefd[2];
	if (pipe(pipefd) != 0)
		return -1;
	pid_t pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}
	if (pid == 0) {
		dup2(pipefd[1], STDOUT_FILENO);
		close(pipefd[0]);
		close(pipefd[1]);
		if (arg2)
			execl(path, path, arg1, arg2, (char *)NULL);
		else
			execl(path, path, arg1, (char *)NULL);
		_exit(127);
	}
	close(pipefd[1]);
	size_t cap = 8192, len = 0;
	char *buf = malloc(cap);
	if (!buf) {
		close(pipefd[0]);
		return -1;
	}
	for (;;) {
		if (len + 4096 + 1 > cap) {
			cap *= 2;
			char *nb = realloc(buf, cap);
			if (!nb) {
				free(buf);
				close(pipefd[0]);
				return -1;
			}
			buf = nb;
		}
		ssize_t n = read(pipefd[0], buf + len, cap - len - 1);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (n == 0)
			break;
		len += (size_t)n;
	}
	close(pipefd[0]);
	buf[len] = '\0';
	int status = 0;
	waitpid(pid, &status, 0);
	*out = buf;
	*outlen = len;
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -1;
	return 0;
}
/* Load the facts dex in a plain app_process and read what it prints.
 *
 * The dex talks to the package service over binder as our own uid, so this
 * needs no Shizuku, no shell privilege and no permission, and it cannot
 * destabilise the host the way the scraped harvest did.  Only a hard failure
 * trips the breaker; an empty table is a legitimate answer. */
static int facts_broken = 0;
static int facts_query(const char *mode, const char *arg, char **out, size_t *outlen)
{
	if (facts_broken)
		return -1;
	char dex[PATH_MAX];
	/* Normally the dex sits next to this binary, which is where the
	 * package installs it.  Some deployments run the binary out of a
	 * directory that only permits overwriting existing files, so the
	 * private work directory is tried as well. */
	/* dex/ is where the source tree keeps it, and the packaged install
	 * drops it next to the binary; neither of the two runtime work
	 * directories holds it, so the lookup returned empty and every uid
	 * silently resolved to "no such package". */
	const char *dirs[4];
	dirs[0] = g_self_dir;
	dirs[1] = g_work_dir;
	dirs[2] = g_alt_cache;
	dirs[3] = "/data/data/com.termux/files/home/aFakeSU/dex";
	struct stat st;
	dex[0] = '\0';
	for (int i = 0; i < 4 && dex[0] == '\0'; i++) {
		if (dirs[i] == NULL || dirs[i][0] == '\0')
			continue;
		char cand[PATH_MAX];
		snprintf(cand, sizeof(cand), "%s/%s", dirs[i], FACTS_DEX_NAME);
		if (stat(cand, &st) == 0) {
			snprintf(dex, sizeof(dex), "%s", cand);
			break;
		}
	}
	if (dex[0] == '\0') {
		facts_broken = 1;
		return -1;
	}
	/* app_process refuses a writable dex on Android 14+, so match what
	 * rish does with its own copy. */
	chmod(dex, 0400);
	char cpath[PATH_MAX + 32];
	snprintf(cpath, sizeof(cpath), "-Djava.class.path=%s", dex);
	char *av[9];
	av[0] = (char *)APP_PROCESS;
	av[1] = cpath;
	av[2] = (char *)"/system/bin";
	av[3] = (char *)"--nice-name=afsfacts";
	av[4] = (char *)"afakesu.facts.Facts";
	av[5] = (char *)mode;
	av[6] = (char *)arg;
	av[7] = NULL;
	int rc = run_capture_argv_list(av, out, outlen);
	if (rc < 0 || *out == NULL)
		facts_broken = 1;
	return rc;
}
static int rishq_query(const char *cmd, char **out, size_t *outlen)
{
	/* One failed attempt disables the rest for this process: with the
	 * bridge down every call blocks until the binder times out, and two
	 * harvests were enough to make a plain "su 0 -c id -Z" miss its own
	 * deadline even though the compiled-in baseline had the answer. */
	if (rishq_broken)
		return -1;
	/* rishq sits next to whichever copy of the binary is running, and the
	 * binary is installed at more than one path.  Looking only in the
	 * binary's own directory made the harvest fail silently for every copy
	 * but one: no rishq, no exception, no caches, and the session then ran
	 * with empty device facts.  Look in all three known places. */
	const char *qdirs[4];
	qdirs[0] = g_self_dir;
	qdirs[1] = g_work_dir;
	qdirs[2] = g_alt_cache;
	/* The packaged install puts rishq in the app's bin dir, which is not
	 * any of the three runtime directories above; without it the harvest
	 * silently found nothing and every session fell back to bare gids. */
	qdirs[3] = "/data/data/com.termux/files/usr/bin";
	char rishq_path[PATH_MAX];
	rishq_path[0] = '\0';
	struct stat st;
	for (int i = 0; i < 4 && rishq_path[0] == '\0'; i++) {
		if (qdirs[i] == NULL || qdirs[i][0] == '\0')
			continue;
		char cand[PATH_MAX];
		snprintf(cand, sizeof(cand), "%s/%s", qdirs[i], RISHQ_NAME);
		if (stat(cand, &st) == 0)
			snprintf(rishq_path, sizeof(rishq_path), "%s", cand);
	}
	if (rishq_path[0] == '\0') {
		rishq_broken = 1;
		return -1;
	}
	/* Publish it into the shared cache, so a copy of the binary sitting
	 * somewhere else can still harvest on its first run. */
	if (g_alt_cache[0] != '\0' &&
	    strncmp(rishq_path, g_alt_cache, strlen(g_alt_cache)) != 0) {
		mkdir(g_alt_cache, 0700);
		char pub[PATH_MAX];
		snprintf(pub, sizeof(pub), "%s/%s", g_alt_cache, RISHQ_NAME);
		(void)unlink(pub);
		(void)link(rishq_path, pub);
	}
	char bash_path[PATH_MAX];
	bash_path[0] = '\0';
	/* Every candidate must actually be executable by us.  stat() alone
	 * is not enough: /data/local/tmp/bash exists with a setuid bit this
	 * uid cannot use, so exec fails with EACCES and every harvest dies
	 * on a path that "exists".  Skip to the next one instead. */
	const char *bdirs[4];
	bdirs[0] = g_self_dir;
	bdirs[1] = g_alt_cache;
	bdirs[2] = "/data/data/com.termux/files/usr/bin";
	bdirs[3] = g_work_dir;
	for (int i = 0; i < 4 && bash_path[0] == '\0'; i++) {
		if (bdirs[i] == NULL || bdirs[i][0] == '\0')
			continue;
		char cand[PATH_MAX];
		snprintf(cand, sizeof(cand), "%s/bash", bdirs[i]);
		if (access(cand, X_OK) == 0 && stat(cand, &st) == 0)
			snprintf(bash_path, sizeof(bash_path), "%s", cand);
	}
	int rc;
	if (bash_path[0] != '\0')
		rc = run_cmd_capture_argv(bash_path, rishq_path, cmd, out, outlen);
	else
		rc = run_cmd_capture(rishq_path, cmd, out, outlen);
	/* Only a hard failure trips this.  Treating any non-zero status as
	 * a broken bridge disabled harvesting for the rest of the process on
	 * a command that had actually succeeded, which is how .seapp and
	 * .apptab stopped being written at all. */
	if (rc < 0 || *out == NULL)
		rishq_broken = 1;
	return rc;
}
static bool real_snapshot_valid(void)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/%s", g_work_dir, REAL_FILE);
	struct stat st;
	if (stat(path, &st) != 0)
		return false;
	return (time(NULL) - st.st_mtime) < 60;
}
static bool real_snapshot(void)
{
	if (real_snapshot_valid())
		return true;
	char *out = NULL;
	size_t out_len = 0;
	if (rishq_query("pm list users; echo __SEP__; pm list packages -U", &out, &out_len) != 0) {
		free(out);
		return false;
	}
	char *sep = strstr(out, "__SEP__");
	if (sep == NULL) {
		free(out);
		return false;
	}
	*sep = '\0';
	char *pkgs_part = sep + 7;
	if (*pkgs_part == '\n')
		pkgs_part++;
	char *users_csv = NULL;
	size_t users_csv_cap = 0, users_csv_len = 0;
	for (char *c = strstr(out, "UserInfo{"); c; c = strstr(c + 1, "UserInfo{")) {
		c += 9; 
		char *end = c;
		while (*end && isdigit((unsigned char)*end))
			end++;
		if (end == c)
			continue;
		if (users_csv_len)
			xstrcat_grow(&users_csv, &users_csv_cap, &users_csv_len, ",", 1);
		xstrcat_grow(&users_csv, &users_csv_cap, &users_csv_len, c, (size_t)(end - c));
	}
	if (users_csv == NULL || users_csv_len == 0) {
		free(out);
		free(users_csv);
		return false;
	}
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/%s", g_work_dir, REAL_FILE);
	char tmp_path[PATH_MAX];
	snprintf(tmp_path, sizeof(tmp_path), "%s/%s.tmp", g_work_dir, REAL_FILE);
	FILE *f = fopen(tmp_path, "w");
	if (!f) {
		free(users_csv);
		return false;
	}
	fprintf(f, "users:%s\n", users_csv);
	free(users_csv);
	char *pline = NULL, *ptok = NULL;
	for (char *line = strtok_r(pkgs_part, "\n", &pline); line; line = strtok_r(NULL, "\n", &pline)) {
		if (strncmp(line, "package:", 8) != 0)
			continue;
		char *uidmark = strstr(line, " uid:");
		if (!uidmark)
			continue;
		uidmark += 5;
		for (char *tok = strtok_r(uidmark, ",", &ptok); tok; tok = strtok_r(NULL, ",", &ptok)) {
			bool all_digits = tok[0] != '\0';
			for (char *p = tok; *p; p++)
				if (!isdigit((unsigned char)*p)) {
					all_digits = false;
					break;
				}
			if (all_digits)
				fprintf(f, "%s\n", tok);
		}
	}
	free(out);
	fclose(f);
	rename(tmp_path, path);
	return true;
}
static bool real_u_exists(long user_no, long check_uid)
{
	if (!real_snapshot())
		return true;
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/%s", g_work_dir, REAL_FILE);
	FILE *f = fopen(path, "r");
	if (!f)
		return true;
	char line[4096];
	if (fgets(line, sizeof(line), f) == NULL) {
		fclose(f);
		return true;
	}
	fclose(f);
	char *p = line;
	if (strncmp(p, "users:", 6) != 0)
		return true;
	p += 6;
	char userbuf[32];
	snprintf(userbuf, sizeof(userbuf), "%ld", user_no);
	bool found_user = false;
	char *save = NULL;
	for (char *tok = strtok_r(p, ",\n", &save); tok; tok = strtok_r(NULL, ",\n", &save))
		if (strcmp(tok, userbuf) == 0)
			found_user = true;
	if (!found_user)
		return false;
	if (check_uid < 0)
		return true;
	char uidbuf[32];
	snprintf(uidbuf, sizeof(uidbuf), "%ld", check_uid);
	f = fopen(path, "r");
	if (!f)
		return true;
	if (fgets(line, sizeof(line), f) == NULL) {
		fclose(f);
		return true;
	}
	bool found_uid = false;
	while (fgets(line, sizeof(line), f)) {
		line[strcspn(line, "\r\n")] = '\0';
		if (strcmp(line, uidbuf) == 0)
			found_uid = true;
	}
	fclose(f);
	return found_uid;
}
static bool parse_u_user(const char *name, long *out_uid, long *out_check)
{
	const char *p = name;
	if (p[0] != 'u')
		return false;
	p++;
	char *end;
	unsigned long u = strtoul(p, &end, 10);
	if (end == p)
		return false;
	if (*end != '_')
		return false;
	char type = end[1];
	if (type != 'a' && type != 'i')
		return false;
	p = end + 2;
	errno = 0;
	unsigned long a = strtoul(p, &end, 10);
	if (end == p || errno)
		return false;
	bool cache = false;
	if (*end == '_' && strcmp(end, "_cache") == 0)
		cache = true;
	else if (*end != '\0')
		return false;
	if (type == 'a') {
		if (a > 9999)
			return false;
		long base_appid = 10000 + (long)a;
		long base = (long)(u * 100000) + base_appid;
		*out_uid = base;
		*out_check = cache ? base + 1 : base;
		return true;
	} else {
		if (a > 8999)
			return false;
		long base = (long)(u * 100000) + 90000 + (long)a;
		*out_uid = base;
		*out_check = -1;
		return true;
	}
}
static bool app_uid(const char *name, long *out_uid)
{
	long user_no = 0;
	char pkg[256];
	strncpy(pkg, name, sizeof(pkg) - 1);
	pkg[sizeof(pkg) - 1] = '\0';
	char *at = strstr(pkg, "@user");
	if (at) {
		*at = '\0';
		char *end;
		long un = strtol(at + 5, &end, 10);
		if (end != at + 5)
			user_no = un;
	}
	char query[512];
	snprintf(query, sizeof(query), "pm list packages -U");
	char *out = NULL;
	size_t outlen = 0;
	if (rishq_query(query, &out, &outlen) != 0) {
		free(out);
		return false;
	}
	char *save = NULL;
	bool ok = false;
	for (char *line = strtok_r(out, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		if (strncmp(line, "package:", 8) != 0)
			continue;
		char *sp = strchr(line + 8, ' ');
		if (!sp)
			continue;
		*sp = '\0';
		if (strcmp(line + 8, pkg) != 0)
			continue;
		char *uidmark = strstr(sp + 1, "uid:");
		if (!uidmark)
			continue;
		uidmark += 4;
		char *utok = NULL;
		for (char *tok = strtok_r(uidmark, ",", &utok); tok; tok = strtok_r(NULL, ",", &utok)) {
			errno = 0;
			char *te;
			unsigned long u = strtoul(tok, &te, 10);
			if (te == tok || errno || *te != '\0')
				continue;
			if ((long)(u / 100000) == user_no) {
				*out_uid = (long)u;
				ok = true;
				break;
			}
		}
		if (ok)
			break;
	}
	free(out);
	return ok;
}
static void ensure_bash(void)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/bash", g_work_dir);
	struct stat st;
	if (stat(path, &st) == 0 && st.st_size == (off_t)EMBEDDED_BASH_SIZE)
		return;
	char tmp[PATH_MAX];
	snprintf(tmp, sizeof(tmp), "%s/bash.tmp", g_work_dir);
	int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0755);
	if (fd < 0)
		return;
	const unsigned char *p = _binary_bash_bin_start;
	size_t left = EMBEDDED_BASH_SIZE;
	while (left > 0) {
		ssize_t n = write(fd, p, left);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		p += n;
		left -= (size_t)n;
	}
	close(fd);
	rename(tmp, path);
	chmod(path, 0755);
}
static void copy_file(const char *src, const char *dst)
{
	int in = open(src, O_RDONLY);
	if (in < 0)
		return;
	int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (out < 0) {
		close(in);
		return;
	}
	char buf[65536];
	for (;;) {
		ssize_t n = read(in, buf, sizeof(buf));
		if (n <= 0)
			break;
		ssize_t off = 0;
		while (off < n) {
			ssize_t w = write(out, buf + off, (size_t)(n - off));
			if (w < 0) {
				if (errno == EINTR)
					continue;
				break;
			}
			off += w;
		}
	}
	close(out);
	close(in);
}
static void write_embedded(const char *path, const unsigned char *start, const unsigned char *end)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
	if (fd < 0)
		return;
	const unsigned char *p = start;
	size_t left = (size_t)(end - start);
	while (left > 0) {
		ssize_t n = write(fd, p, left);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		p += n;
		left -= (size_t)n;
	}
	close(fd);
}
static void ensure_libs(void)
{
	char libdir[PATH_MAX];
	snprintf(libdir, sizeof(libdir), "%s/lib", g_work_dir);
	mkdir(libdir, 0755);
	char ncu[PATH_MAX], ncu65[PATH_MAX], ncu_sym[PATH_MAX], iconv_src[PATH_MAX];
	snprintf(ncu, sizeof(ncu), "%s/libncursesw.so.6", libdir);
	snprintf(ncu65, sizeof(ncu65), "%s/libncursesw.so.6.5", libdir);
	snprintf(ncu_sym, sizeof(ncu_sym), "%s/libncursesw.so", libdir);
	snprintf(iconv_src, sizeof(iconv_src), "%s/libiconv.so", libdir);
	struct stat st_ncu;
	if (stat(ncu65, &st_ncu) != 0) {
		const char *srcs[2];
		char self_lib[PATH_MAX];
		snprintf(self_lib, sizeof(self_lib), "%s/lib", g_self_dir);
		srcs[0] = self_lib;
		srcs[1] = "/data/data/com.termux/files/usr/lib";
		for (int i = 0; i < 2; i++) {
			char s65[PATH_MAX];
			snprintf(s65, sizeof(s65), "%s/libncursesw.so.6.5", srcs[i]);
			struct stat st;
			if (stat(s65, &st) != 0)
				continue;
			copy_file(s65, ncu65);
			char sico[PATH_MAX];
			snprintf(sico, sizeof(sico), "%s/libiconv.so", srcs[i]);
			if (stat(sico, &st) == 0)
				copy_file(sico, iconv_src);
			break;
		}
		if (stat(ncu65, &st_ncu) != 0)
			write_embedded(ncu65, _binary_libncursesw_so_6_5_start, _binary_libncursesw_so_6_5_end);
	} else if (stat(iconv_src, &st_ncu) != 0) {
		const char *srcs[2];
		char self_lib[PATH_MAX];
		snprintf(self_lib, sizeof(self_lib), "%s/lib", g_self_dir);
		srcs[0] = self_lib;
		srcs[1] = "/data/data/com.termux/files/usr/lib";
		for (int i = 0; i < 2; i++) {
			char sico[PATH_MAX];
			snprintf(sico, sizeof(sico), "%s/libiconv.so", srcs[i]);
			struct stat st;
			if (stat(sico, &st) == 0) {
				copy_file(sico, iconv_src);
				break;
			}
		}
		if (stat(iconv_src, &st_ncu) != 0)
			write_embedded(iconv_src, _binary_libiconv_so_start, _binary_libiconv_so_end);
	}
	if (stat(ncu65, &st_ncu) == 0) {
		unlink(ncu);
		unlink(ncu_sym);
		symlink("libncursesw.so.6.5", ncu);
		symlink("libncursesw.so.6", ncu_sym);
	}
}
static void aid_files_setup(void)
{
	char pw[PATH_MAX], gr[PATH_MAX];
	snprintf(pw, sizeof(pw), "%s/etc_passwd", g_work_dir);
	snprintf(gr, sizeof(gr), "%s/etc_group", g_work_dir);
	struct stat st;
	if (stat(pw, &st) == 0 && st.st_size > 0 &&
	    stat(gr, &st) == 0 && st.st_size > 0)
		return;
	FILE *fp = fopen(pw, "w");
	FILE *fg = fopen(gr, "w");
	if (!fp || !fg) { if (fp) fclose(fp); if (fg) fclose(fg); return; }
	fprintf(fp, "root:x:0:0:root:/root:/system/bin/sh\n");
	fprintf(fp, "shell:x:2000:2000:shell:/data/user/0:/system/bin/sh\n");
	fprintf(fp, "system:x:1000:1000:system:/data/user/0:/system/bin/sh\n");
	fprintf(fg, "root:x:0:\n");
	fprintf(fg, "shell:x:2000:\n");
	fprintf(fg, "system:x:1000:\n");
	fprintf(fg, "input:x:1004:\n");
	fprintf(fg, "log:x:1007:\n");
	fprintf(fg, "sdcard_rw:x:1015:\n");
	fprintf(fg, "ext_data_rw:x:1078:\n");
	fprintf(fg, "ext_obb_rw:x:1079:\n");
	fclose(fp);
	fclose(fg);
}
/* Rewrite a passwd/group style file keeping one copy of each line, so a
 * file that is only ever appended to cannot grow without bound. */
static void dedupe_passwd_file(const char *path, long keep_uid, long keep_gid)
{
	FILE *f = fopen(path, "r");
	if (f == NULL)
		return;
	char seen[512][256];
	int ns = 0;
	char line[4096];
	while (ns < 512 && fgets(line, sizeof(line), f) != NULL) {
		size_t l = strlen(line);
		while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r'))
			line[--l] = '\0';
		if (l == 0)
			continue;
		int dup = 0;
		for (int i = 0; i < ns; i++)
			if (strcmp(seen[i], line) == 0) {
				dup = 1;
				break;
			}
		if (dup)
			continue;
		snprintf(seen[ns++], sizeof(seen[0]), "%s", line);
	}
	fclose(f);
	if (ns == 0)
		return;
	char tmp[PATH_MAX];
	snprintf(tmp, sizeof(tmp), "%s.dedup", path);
	FILE *o = fopen(tmp, "w");
	if (o == NULL)
		return;
	for (int i = 0; i < ns; i++)
		fprintf(o, "%s\n", seen[i]);
	fclose(o);
	rename(tmp, path);
	(void)keep_uid;
	(void)keep_gid;
}
static void ensure_current_uid_in_files(void)
{
	if (g_uid <= 0 || g_gid <= 0)
		return;
	char gr[PATH_MAX];
	snprintf(gr, sizeof(gr), "%s/etc_group", g_work_dir);
	char line[4096];
	bool found = false;
	FILE *f = fopen(gr, "r");
	if (f) {
		while (fgets(line, sizeof(line), f)) {
			char buf[64];
			snprintf(buf, sizeof(buf), "gid_%ld:x:", g_gid);
			if (strncmp(line, buf, strlen(buf)) == 0) {
				found = true;
				break;
			}
		}
		fclose(f);
	}
	char pw[PATH_MAX];
	snprintf(pw, sizeof(pw), "%s/etc_passwd", g_work_dir);

	/* Both files were checked through the group's "found" flag, so a uid
	 * whose gid was already listed never got its passwd line: getpwuid
	 * then failed and `id` / `whoami` printed nothing.  Check each file on
	 * its own. */
	if (!found) {
		FILE *fg = fopen(gr, "a");
		if (fg) {
			fprintf(fg, "gid_%ld:x:%ld:\n", g_gid, g_gid);
			fclose(fg);
		}
	}
	found = false;
	FILE *fchk = fopen(pw, "r");
	if (fchk) {
		char l2[4096];
		char buf[64];
		snprintf(buf, sizeof(buf), "user_%ld:x:", g_uid);
		while (fgets(l2, sizeof(l2), fchk)) {
			if (strncmp(l2, buf, strlen(buf)) == 0) {
				found = true;
				break;
			}
		}
		fclose(fchk);
	}
	if (!found) {
		FILE *fp = fopen(pw, "a");
		if (fp) {
			fprintf(fp, "user_%ld:x:%ld:%ld:User %ld:/data/user/0:/system/bin/sh\n",
				g_uid, g_uid, g_gid, g_uid);
			fclose(fp);
		}
	}

	/* Both files are opened in append mode and nothing ever removed a
	 * line, so every distinct uid ever used left a permanent entry behind
	 * and the pair grew without bound.  Collapse duplicates in place, and
	 * keep only the well-known AIDs plus the lines this session needs, so
	 * the files stay a fixed size no matter how many uids are tried. */
	dedupe_passwd_file(pw, g_uid, g_gid);
	dedupe_passwd_file(gr, g_uid, g_gid);
}
static void linker_config_setup(void)
{
	char dir[PATH_MAX], src[PATH_MAX], dst[PATH_MAX];
	snprintf(dir, sizeof(dir), "%s/linkerconfig", g_work_dir);
	snprintf(src, sizeof(src), "%s", "/linkerconfig/ld.config.txt");
	snprintf(dst, sizeof(dst), "%s/ld.config.txt", dir);
	mkdir(dir, 0755);
	struct stat ss, sd;
	if (stat(src, &ss) != 0)
		return;
	if (stat(dst, &sd) == 0 && sd.st_size == ss.st_size)
		return;
	copy_file(src, dst);
}
static void setenv_str(const char *k, const char *v)
{
	setenv(k, v, 1);
}
static void setup_ld_library_path(void)
{
	char libdir[PATH_MAX];
	snprintf(libdir, sizeof(libdir), "%s/lib", g_work_dir);
	const char *cur = getenv("LD_LIBRARY_PATH");
	char ld[4096];
	if (cur && cur[0])
		snprintf(ld, sizeof(ld), "%s:%s", libdir, cur);
	else
		snprintf(ld, sizeof(ld), "%s", libdir);
	setenv_str("LD_LIBRARY_PATH", ld);
}
/* Policy table, persisted next to the other harvest caches so a decision
 * survives across sessions the way Magisk's SQLite policies table does. */
#define POLICY_FILE ".policy"
#define POLICY_MAX 256

static const char *policy_file_path(void)
{
	static char p[PATH_MAX];
	snprintf(p, sizeof(p), "%s/%s", g_work_dir, POLICY_FILE);
	return p;
}

/* "uid policy" per line; policy is one of allow/deny/query/restrict. */
/* "uid policy" per line; policy is one of allow/deny/query/restrict.
 * Two global lines are also accepted: "root-access MODE" and
 * "multiuser MODE", written by the --root-access/--multiuser switches. */
static void policy_load_globals(void)
{
	FILE *f = fopen(policy_file_path(), "r");
	if (f == NULL)
		return;
	char line[128];
	while (fgets(line, sizeof(line), f) != NULL) {
		char what[32], val[32];
		if (sscanf(line, "root-access %31s", val) == 1) {
			if (strcmp(val, "disabled") == 0)        g_root_access = ROOT_ACCESS_DISABLED;
			else if (strcmp(val, "adb-only") == 0)   g_root_access = ROOT_ACCESS_ADB_ONLY;
			else if (strcmp(val, "apps-only") == 0)  g_root_access = ROOT_ACCESS_APPS_ONLY;
			else                                      g_root_access = ROOT_ACCESS_PROMPT;
		} else if (sscanf(line, "multiuser %31s", val) == 1) {
			if (strcmp(val, "owner-only") == 0)     g_multiuser = MULTIUSER_OWNER_ONLY;
			else if (strcmp(val, "global") == 0)     g_multiuser = MULTIUSER_GLOBAL;
			else                                     g_multiuser = MULTIUSER_OWNER_MANAGED;
		}
		(void)what;
	}
	fclose(f);
}

static enum su_policy policy_lookup(long uid, bool *found)
{
	*found = false;
	policy_load_globals();
	FILE *f = fopen(policy_file_path(), "r");
	if (f == NULL)
		return SU_POLICY_QUERY;
	char line[128];
	enum su_policy result = SU_POLICY_QUERY;
	while (fgets(line, sizeof(line), f) != NULL) {
		/* skip the global setting lines */
		if (strncmp(line, "root-access", 11) == 0
		    || strncmp(line, "multiuser", 10) == 0)
			continue;
		long u;
		char what[32];
		if (sscanf(line, "%ld %31s", &u, what) != 2)
			continue;
		if (u != uid)
			continue;
		*found = true;
		if (strcmp(what, "allow") == 0)         result = SU_POLICY_ALLOW;
		else if (strcmp(what, "deny") == 0)     result = SU_POLICY_DENY;
		else if (strcmp(what, "restrict") == 0) result = SU_POLICY_RESTRICT;
		else                                   result = SU_POLICY_QUERY;
		break;
	}
	fclose(f);
	return result;
}

static void policy_store(long uid, enum su_policy p)
{
	const char *what = "query";
	switch (p) {
	case SU_POLICY_ALLOW:    what = "allow";    break;
	case SU_POLICY_DENY:     what = "deny";     break;
	case SU_POLICY_RESTRICT: what = "restrict"; break;
	case SU_POLICY_QUERY:    what = "query";    break;
	}
	/* rewrite the single line for this uid, then append if absent */
	FILE *f = fopen(policy_file_path(), "r");
	if (f) {
		char tmp[PATH_MAX];
		snprintf(tmp, sizeof(tmp), "%s.tmp", policy_file_path());
		FILE *o = fopen(tmp, "w");
		if (o) {
			char line[128];
			int written = 0;
			while (fgets(line, sizeof(line), f) != NULL) {
				/* keep the global setting lines */
				if (strncmp(line, "root-access", 11) == 0
				    || strncmp(line, "multiuser", 10) == 0) {
					fputs(line, o);
					continue;
				}
				long u;
				if (sscanf(line, "%ld", &u) == 1 && u == uid)
					continue;	/* replaced below */
				fputs(line, o);
			}
			fprintf(o, "%ld %s\n", uid, what);
			written = 1;
			fclose(o);
			if (written) {
				rename(tmp, policy_file_path());
				fclose(f);
				return;
			}
			unlink(tmp);
		}
		fclose(f);
	}
	FILE *a = fopen(policy_file_path(), "a");
	if (a) {
		fprintf(a, "%ld %s\n", uid, what);
		fclose(a);
	}
}

/* Android user id = uid / 100000. */
static long to_user_id(long uid) { return uid / 100000; }
/* App id = uid % 100000. */
static long to_app_id(long uid) { return uid % 100000; }

#define AID_ROOT 0L
#define AID_SHELL 2000L

/*
 * Decide whether this caller may have root, following Magisk's
 * build_su_info() order: root is always allowed, the manager is allowed
 * silently, the global RootAccess mode is enforced, multiuser OwnerOnly
 * confines root to the device owner, and only then does the per-uid policy
 * table decide.  A caller with no stored decision lands on QUERY, which
 * Magisk resolves by asking its manager app; with no manager to ask it
 * denies, and so do we.
 */
static void apply_root_policy(void)
{
	if (g_caller_uid < 0)
		return;
	if (g_caller_uid == AID_ROOT) {
		/* uid 0 asking for root is root already. */
		return;
	}
	if (g_root_access == ROOT_ACCESS_DISABLED) {
		fprintf(stderr, "su: root access is disabled\n");
		exit(1);
	}
	if (g_root_access == ROOT_ACCESS_ADB_ONLY && g_caller_uid != AID_SHELL) {
		fprintf(stderr, "su: root access limited to ADB only\n");
		exit(1);
	}
	if (g_root_access == ROOT_ACCESS_APPS_ONLY && g_caller_uid == AID_SHELL) {
		fprintf(stderr, "su: root access is disabled for ADB\n");
		exit(1);
	}
	if (g_multiuser == MULTIUSER_OWNER_ONLY && to_user_id(g_caller_uid) != 0) {
		fprintf(stderr, "su: root access is limited to the device owner "
			"(user %ld)\n", to_user_id(g_caller_uid));
		exit(1);
	}

	bool found = false;
	enum su_policy pol = policy_lookup(g_caller_uid, &found);
	if (pol == SU_POLICY_DENY) {
		fprintf(stderr, "su: request rejected for uid %ld\n", g_caller_uid);
		exit(1);
	}
	if (pol == SU_POLICY_RESTRICT) {
		/* Magisk forces drop_cap for a restricted policy. */
		g_drop_cap = true;
	}
	if (pol == SU_POLICY_QUERY) {
		/* No decision stored.  Magisk would prompt its manager here;
		 * without one there is nobody to ask, and Magisk's own code
		 * path treats a missing manager as deny.  Termux is granted
		 * root explicitly below so the package is usable out of the
		 * box on a device that never ran a manager. */
		if (to_app_id(g_caller_uid) == to_app_id((long)getuid())) {
			pol = SU_POLICY_ALLOW;
		} else {
			fprintf(stderr, "su: uid %ld has no root policy; deny\n",
				g_caller_uid);
			exit(1);
		}
	}
	(void)to_app_id;
}

static void gen_fake_status(void)
{
	/* Fuse: transplant of thj_ptrace's build_fake_status().  Snapshot the
	 * supervisor's own /proc/self/status and rewrite the root-visible
	 * fields (Uid/Gid/Groups/Context/Cap*), so reads of /proc/self/status
	 * (grep, bash $'', python) look like a real root session. */
	char line[1024];
	char *buf = malloc(16384);
	if (!buf)
		return;
	size_t cap = 16384, n = 0;
	buf[0] = '\0';
	FILE *f = fopen("/proc/self/status", "r");
	if (!f) { free(buf); return; }
	const char *ctx = (g_selinux_ctx && g_selinux_ctx[0]) ? g_selinux_ctx : "u:r:shell:s0";
	while (fgets(line, sizeof(line), f)) {
		const char *repl = NULL;
		char uidbuf[64], gidbuf[64], grpbuf[512];
		if      (strncmp(line, "Name:", 5) == 0) {
			char nb[64];
			snprintf(nb, sizeof(nb), "Name:\t%s\n", g_fake_name);
			repl = nb;
		} else if (strncmp(line, "PPid:", 5) == 0) {
			/* A real root shell has no survivable parent chain to
			 * follow: seed the session as owned by pid 0. */
			repl = "PPid:\t0\n";
		} else if (strncmp(line, "Uid:", 4) == 0) {
			snprintf(uidbuf, sizeof(uidbuf), "Uid:\t%ld\t%ld\t%ld\t%ld\n",
				 g_uid, g_uid, g_uid, g_uid);
			repl = uidbuf;
		} else if (strncmp(line, "Gid:", 4) == 0) {
			snprintf(gidbuf, sizeof(gidbuf), "Gid:\t%ld\t%ld\t%ld\t%ld\n",
				 g_gid, g_gid, g_gid, g_gid);
			repl = gidbuf;
		} else if (strncmp(line, "Groups:", 7) == 0) {
			int glen = snprintf(grpbuf, sizeof(grpbuf), "Groups:\t%ld", g_gid);
			for (size_t k = 0; k < g_suppg_cnt && glen < (int)sizeof(grpbuf) - 8; k++) {
				long sv;
				if (valid_uint_str(g_suppg[k], &sv) && sv != g_gid)
					glen += snprintf(grpbuf + glen, sizeof(grpbuf) - (size_t)glen, " %ld", sv);
			}
			snprintf(grpbuf + glen, sizeof(grpbuf) - (size_t)glen, "\n");
			repl = grpbuf;
		} else if (strncmp(line, "Context:", 8) == 0) {
			char tmp[512];
			snprintf(tmp, sizeof(tmp), "Context:\t%s\n", ctx);
			repl = tmp;
		} else if (strncmp(line, "CapInh:", 7) == 0)
			repl = "CapInh:\t0000000000000000\n";
		else if (strncmp(line, "CapPrm:", 7) == 0)
			repl = g_uid == 0 && !g_drop_cap
				? "CapPrm:\t000001ffffffffff\n"
				: "CapPrm:\t0000000000000000\n";
		else if (strncmp(line, "CapEff:", 7) == 0)
			repl = g_uid == 0 && !g_drop_cap
				? "CapEff:\t000001ffffffffff\n"
				: "CapEff:\t0000000000000000\n";
		else if (strncmp(line, "CapBnd:", 7) == 0)
			/* setuid() does not touch the bounding set; only
			 * prctl(PR_CAPBSET_DROP) and capset() shrink it.  A real
			 * su session is forked from a root parent, so every
			 * persona in it inherits the full bounding set even
			 * after dropping to a non-zero uid.  Reporting an empty
			 * CapBnd for `su shell` would be the giveaway, since
			 * CapPrm/CapEff are 0 there but CapBnd is not. */
			repl = g_drop_cap
				? "CapBnd:\t0000000000000000\n"
				: "CapBnd:\t000001ffffffffff\n";
		else if (strncmp(line, "CapAmb:", 7) == 0)
			repl = "CapAmb:\t0000000000000000\n";
		/* PRoot runs its tracee with NoNewPrivs=1 and a seccomp filter
		 * installed, while a real root shell inherited from a root
		 * parent has neither.  Leaving the supervisor's values in place
		 * is what gave the fake away. */
		else if (strncmp(line, "NoNewPrivs:", 11) == 0)
			repl = "NoNewPrivs:\t0\n";
		else if (strncmp(line, "Seccomp:", 8) == 0)
			repl = "Seccomp:\t0\n";
		else if (strncmp(line, "Seccomp_filters:", 16) == 0)
			repl = "Seccomp_filters:\t0\n";
		const char *use = repl ? repl : line;
		size_t l = strlen(use);
		if (n + l < cap) {
			memcpy(buf + n, use, l);
			n += l;
		}
	}
	fclose(f);
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/status", g_work_dir);
	unlink(path);
	FILE *sf = fopen(path, "w");
	if (sf) {
		fwrite(buf, 1, n, sf);
		fclose(sf);
	}
	free(buf);
}

/* Fake /proc/<pid>/cmdline for the session: a real su runs
 * "/system/bin/sh -c <command>", so the procfs entry must show exactly
 * that (NUL separated, trailing NUL) instead of the Termux bash path. */
static void gen_fake_cmdline(void)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/cmdline", g_work_dir);
	unlink(path);
	FILE *f = fopen(path, "w");
	if (f == NULL)
		return;
	static const char sh[] = "/system/bin/sh";
	fwrite(sh, 1, sizeof(sh) - 1, f);
	fputc('\0', f);
	if (g_cmd != NULL && g_cmd[0] != '\0') {
		fwrite("-c", 1, 2, f);
		fputc('\0', f);
		fwrite(g_cmd, 1, strlen(g_cmd), f);
		fputc('\0', f);
	}
	fclose(f);
}

static void rm_rf(const char *path)
{
	char buf[PATH_MAX];
	struct stat st;
	if (lstat(path, &st) != 0)
		return;
	if (S_ISDIR(st.st_mode)) {
		DIR *d = opendir(path);
		if (!d)
			return;
		struct dirent *e;
		while ((e = readdir(d)) != NULL) {
			if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
				continue;
			snprintf(buf, sizeof(buf), "%s/%s", path, e->d_name);
			rm_rf(buf);
		}
		closedir(d);
		rmdir(path);
	} else {
		unlink(path);
	}
}

/*
 * Harvest the device's real property set and freeze it into
 * <workdir>/.props.  The session's getprop/setprop/resetprop wrappers
 * then operate on this file, so ro.* can be "changed" (resetprop) and
 * every getprop answer stays self-consistent -- including the values
 * that /system/build.prop mirrors.  An empty .props would make the
 * wrappers pure pass-through relays of the device, which is correct but
 * offers no place for a fake model/serial/... to stick.
 */
static void gen_fake_props(void)
{
	char path[PATH_MAX];
	char modpath[PATH_MAX];
	snprintf(path, sizeof(path), "%s/.props", g_work_dir);
	snprintf(modpath, sizeof(modpath), "%s/.propsmod", g_work_dir);

	/* Values the user set through the session's setprop/resetprop live
	 * in the previous .props and their keys are listed in .propsmod.
	 * gen_fake_props() rebuilds .props from a fresh device harvest on
	 * every session, so without this snapshot those edits would be
	 * wiped; copy them back over the harvested ones. */
	char frozen[4096][1024];
	size_t nfrozen = 0;
	{
		FILE *mf = fopen(modpath, "r");
		if (mf) {
			FILE *pf = fopen(path, "r");
			if (pf) {
				char line[1024];
				while (nfrozen < sizeof(frozen)/sizeof(frozen[0])
				       && fgets(line, sizeof(line), pf) != NULL) {
					char *eq = strchr(line, '=');
					if (eq == NULL)
						continue;
					char key[1024], val[1024];
					size_t klen = (size_t)(eq - line);
					if (klen >= sizeof(key))
						klen = sizeof(key) - 1;
					memcpy(key, line, klen);
					key[klen] = '\0';
					strncpy(val, eq + 1, sizeof(val) - 1);
					val[sizeof(val) - 1] = '\0';
					val[strcspn(val, "\n")] = '\0';
					rewind(mf);
					char mline[1024];
					while (fgets(mline, sizeof(mline), mf) != NULL) {
						mline[strcspn(mline, "\n")] = '\0';
						if (strcmp(mline, key) == 0) {
							snprintf(frozen[nfrozen],
								 sizeof(frozen[0]),
								 "%s=%s", key, val);
							frozen[nfrozen][sizeof(frozen[0]) - 1] = '\0';
							nfrozen++;
							break;
						}
					}
				}
				fclose(pf);
			}
			fclose(mf);
		}
	}

	unlink(path);

	char *out = NULL;
	size_t outlen = 0;
	if (run_cmd_capture("/system/bin/getprop", NULL, &out, &outlen) != 0) {
		free(out);
		return;
	}

	FILE *f = fopen(path, "w");
	if (f == NULL) {
		free(out);
		return;
	}
	size_t pos = 0;
	while (pos < outlen) {
		char *nl = memchr(out + pos, '\n', outlen - pos);
		size_t len = nl ? (size_t)(nl - (out + pos)) : outlen - pos;
		if (len > 0) {
			char line[1024];
			if (len >= sizeof(line))
				len = sizeof(line) - 1;
			memcpy(line, out + pos, len);
			line[len] = '\0';
			if (line[0] == '[') {
				size_t k;
				for (k = 1; k < len; k++)
					if (line[k] == ']' && k + 4 <= len
					    && strncmp(line + k, "]: [", 4) == 0)
						break;
				if (k < len) {
					line[k] = '\0';
					char *v = line + k + 4;
					size_t vlen = strlen(v);
					if (vlen > 0 && v[vlen - 1] == ']')
						v[vlen - 1] = '\0';
					char key[1024];
					snprintf(key, sizeof(key), "%s", line + 1);
					/* skip if this key was user-edited; its
					 * frozen value is appended after the
					 * harvest below */
					bool edited = false;
					for (size_t i = 0; i < nfrozen; i++) {
						if (strncmp(frozen[i], key,
							    strlen(key)) == 0
						    && frozen[i][strlen(key)] == '=') {
							edited = true;
							break;
						}
					}
					if (!edited)
						fprintf(f, "%s=%s\n", key, v);
				}
			}
		}
		pos += len + 1;
	}
	for (size_t i = 0; i < nfrozen; i++)
		fprintf(f, "%s\n", frozen[i]);
	fclose(f);
	free(out);
}

/*
 * Mirror /system/build.prop: the real one on this device is 0600
 * root-owned and unreadable to the app domain, yet a root-like session
 * must be able to read it.  Produce a plausible file from the SAME
 * harvested property set so its values match getprop exactly, and bind
 * it over /system/build.prop.
 */
static void gen_build_prop(void)
{
	char src[PATH_MAX], dst[PATH_MAX];
	snprintf(src, sizeof(src), "%s/.props", g_work_dir);
	snprintf(dst, sizeof(dst), "%s/build.prop", g_work_dir);

	FILE *in = fopen(src, "r");
	FILE *f = fopen(dst, "w");
	if (in == NULL || f == NULL) {
		if (in) fclose(in);
		if (f) fclose(f);
		return;
	}
	fprintf(f, "# begin build properties\n");
	fprintf(f, "# autogenerated by aFakeSU\n");
	char line[1024];
	while (fgets(line, sizeof(line), in) != NULL) {
		if (strncmp(line, "ro.", 3) == 0
		    || strncmp(line, "build.", 6) == 0
		    || strncmp(line, "persist.", 8) == 0) {
			fputs(line, f);
		}
	}
	fprintf(f, "# end build properties\n");
	fclose(in);
	fclose(f);
	chmod(dst, 0644);
}

/* Several su sessions can share one workdir, and the second one starting
 * used to delete the first one's bin/ and ctx out from under it: the guest
 * then had no wrapper directory and no context file, so commands vanished
 * and paths came out as /system/bin//id or "not found".  That is what made
 * an idle session start failing.  Track the live pids and leave a running
 * session's files alone; the next solo run still cleans up. */
static void sess_mark(void)
{
	char d[PATH_MAX], f[PATH_MAX];
	snprintf(d, sizeof(d), "%s/.sessions", g_work_dir);
	mkdir(d, 0700);
	snprintf(f, sizeof(f), "%s/%ld", d, (long)getpid());
	FILE *fp = fopen(f, "w");
	if (fp != NULL) {
		fputs("1\n", fp);
		fclose(fp);
	}
}
static void sess_unmark(void)
{
	char d[PATH_MAX], f[PATH_MAX];
	snprintf(d, sizeof(d), "%s/.sessions", g_work_dir);
	snprintf(f, sizeof(f), "%s/%ld", d, (long)getpid());
	unlink(f);
}
static int other_live_sessions(void)
{
	char d[PATH_MAX], f[PATH_MAX];
	snprintf(d, sizeof(d), "%s/.sessions", g_work_dir);
	DIR *dp = opendir(d);
	if (dp == NULL)
		return 0;
	struct dirent *e;
	long me = (long)getpid();
	int n = 0;
	while ((e = readdir(dp)) != NULL) {
		if (e->d_name[0] == '.')
			continue;
		long other = atol(e->d_name);
		if (other <= 0 || other == me)
			continue;
		snprintf(f, sizeof(f), "%s/%s", d, e->d_name);
		errno = 0;
		if (kill((pid_t)other, 0) == 0 || errno == EPERM)
			n++;
		else
			unlink(f);	/* crashed earlier: drop the stale marker */
	}
	closedir(dp);
	return n;
}
static void cleanup_workdir(void)
{
	/* A real su leaves nothing behind: drop every runtime artifact the
	 * session produced, keeping only the harvest caches (.usermap,
	 * .ugroups, .xattrs) that a following session may reuse.  The
	 * dot-prefixed cache files stay invisible to a plain `ls` anyway. */
	if (g_work_dir[0] == '\0')
		return;
	if (other_live_sessions() > 0)
		return;
	static const char *keep[] = { ".sessions", ".usermap", ".ugroups", ".xattrs", ".policy",
		SEAPP_FILE, APPTAB_FILE,
				      ".props", ".propsmod", NULL };
	DIR *d = opendir(g_work_dir);
	if (!d)
		return;
	struct dirent *e;
	char buf[PATH_MAX];
	while ((e = readdir(d)) != NULL) {
		if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
			continue;
		bool held = false;
		for (int i = 0; keep[i]; i++)
			if (strcmp(e->d_name, keep[i]) == 0)
				held = true;
		if (held)
			continue;
		snprintf(buf, sizeof(buf), "%s/%s", g_work_dir, e->d_name);
		rm_rf(buf);
	}
	closedir(d);
}

static void build_and_run_proot(void)
{
	bool enoexec_case = false;
	const char *shell = g_shell;
	const char *shell_argv0 = g_shell;
	/* Default session shell is the device's real /system/bin/sh, so the
	 * process that actually runs matches the faked /proc/<pid>/exe and
	 * comm ("sh").  The embedded bash is only an auxiliary interpreter
	 * for the rishq uid-table probe (see ensure_bash), never the session
	 * shell. */
	int rc = shell_validate(shell);
	if (rc == 1)
		exit(0);
	if (rc == 2) {
		enoexec_case = true;
		shell = "/bin/sh";
	}
	char *binds[8];
	int bind_cnt = 0;
	/* Freeze the device property set for the wrappers and mirror a
	 * readable /system/build.prop off it, BEFORE the binds below
	 * reference the generated build.prop. */
	gen_fake_props();
	gen_build_prop();
	{
		char ld[PATH_MAX];
		snprintf(ld, sizeof(ld), "%s/linkerconfig/ld.config.txt", g_work_dir);
		struct stat st;
		if (stat(ld, &st) == 0 && st.st_size > 0) {
			char *b = malloc(strlen(g_work_dir) + 64);
			sprintf(b, "-b %s/linkerconfig:/linkerconfig", g_work_dir);
			binds[bind_cnt++] = b;
		}
		char pw[PATH_MAX], grp[PATH_MAX];
		snprintf(pw, sizeof(pw), "%s/etc_passwd", g_work_dir);
		snprintf(grp, sizeof(grp), "%s/etc_group", g_work_dir);
		if (stat(pw, &st) == 0 && st.st_size > 0 &&
		    stat(grp, &st) == 0 && st.st_size > 0) {
			char *b = malloc(strlen(g_work_dir) * 2 + 64);
			sprintf(b, "-b %s/etc_passwd:/etc/passwd -b %s/etc_group:/etc/group", g_work_dir, g_work_dir);
			binds[bind_cnt++] = b;
		}
		/* The harvested /system/build.prop overlay: the original is
		 * unreadable to the app domain, and its values must mirror
		 * what getprop returns. */
		char bp[PATH_MAX];
		snprintf(bp, sizeof(bp), "%s/build.prop", g_work_dir);
		if (stat(bp, &st) == 0 && st.st_size > 0) {
			char *b = malloc(strlen(g_work_dir) + 64);
			sprintf(b, "-b %s/build.prop:/system/build.prop", g_work_dir);
			binds[bind_cnt++] = b;
		}
	}
	if (g_selinux_ctx != NULL && g_selinux_ctx[0] != '\0') {
		/* Mirror the wrapper dir at a non-Termux guest path so $PATH
		 * and `which` never reveal /data/data/com.termux/... . */
		char *gb = malloc(strlen(g_work_dir) + 64);
		if (gb != NULL) {
			sprintf(gb, "-b %s/bin:%s", g_work_dir, GUEST_BIN_DIR);
			binds[bind_cnt++] = gb;
		}
		/* The ctx file is consumed via the AFAKESU /proc redirect
		 * (readlink_proc attr-path self-binding), NOT a proot bind:
		 * a bind would let stat() show the plain file (size 14,
		 * mode 1777) instead of a procfs-shaped entry. */
		char ctx_path[PATH_MAX];
		snprintf(ctx_path, sizeof(ctx_path), "%s/ctx", g_work_dir);
		unlink(ctx_path);
		FILE *cf = fopen(ctx_path, "w");
		if (cf) {
			fprintf(cf, "%s", g_selinux_ctx);
			fclose(cf);
		}
	}
	{
		/* Fuse: the workdir fake-status file is redirected by proc.c's
		 * readlink_proc (component "status"), not by a proot bind: binds
		 * can't match /proc paths because self/thread-self canonicalize
		 * to /proc/<pid>, which is unknown at bind time. */
		char st[PATH_MAX];
		snprintf(st, sizeof(st), "%s/status", g_work_dir);
		/* Always regenerate: the status file is per-session and must
		 * reflect the current persona (uid/gid/groups/ctx/caps). */
		gen_fake_status();
		gen_fake_cmdline();

		/* Symlink used by enter.c to answer readlink("/proc/1/exe"). */
		char exe1[PATH_MAX];
		snprintf(exe1, sizeof(exe1), "%s/.exe1", g_work_dir);
		unlink(exe1);
		symlink("/system/bin/init", exe1);

		/* Fake kernel cmdline, substituted for the unreadable /proc/cmdline. */
		char cmd[PATH_MAX];
		snprintf(cmd, sizeof(cmd), "%s/.cmdline", g_work_dir);
		struct stat cst;
		if (stat(cmd, &cst) != 0 || cst.st_size <= 0) {
			FILE *mf = fopen(cmd, "w");
			if (mf) {
				fprintf(mf, "androidboot.hardware=qcom androidboot.bootdevice=soc/1d84000.ufshc "
					"androidboot.selinux=enforcing androidboot.verifiedbootstate=green "
					"androidboot.veritymode=enforcing console=ttyMSM0,115200n8 "
					"androidboot.serialno=XHA0123456 buildvariant=user\n");
				fclose(mf);
				chmod(cmd, 0444);
			}
		}

		/* SELinux global enforce state, substituted for the gated
		 * read of /sys/fs/selinux/enforce. */
		char enf[PATH_MAX];
		snprintf(enf, sizeof(enf), "%s/.enforce", g_work_dir);
		struct stat est;
		if (stat(enf, &est) != 0 || est.st_size <= 0) {
			FILE *ef = fopen(enf, "w");
			if (ef) {
				fprintf(ef, "1\n");
				fclose(ef);
				chmod(enf, 0444);
			}
		}

		/* Writtable-overlay root, plus the per-partition rw markers
		 * that model "mount -o remount,rw <part>".  A rooted phone
		 * ships system/vendor/product/odm already writable (Magisk),
		 * so seed them the same way. */
		char ovdir[PATH_MAX];
		snprintf(ovdir, sizeof(ovdir), "%s/ov", g_work_dir);
		mkdir(ovdir, 0755);

		char mntd[PATH_MAX];
		snprintf(mntd, sizeof(mntd), "%s/.mnt", g_work_dir);
		mkdir(mntd, 0755);
		static const char *def_roots[] = { "system", "vendor", "product", "odm", "root" };
		size_t di;
		for (di = 0; di < sizeof(def_roots) / sizeof(def_roots[0]); di++) {
			char mr[PATH_MAX];
			snprintf(mr, sizeof(mr), "%s/.mnt/%s", g_work_dir, def_roots[di]);
			if (access(mr, F_OK) != 0) {
				FILE *f = fopen(mr, "w");
				if (f) {
					fputs("1\n", f);
					fclose(f);
				}
			}
		}

		/* chcon/restorecon label store consumed by enter.c. */
		char xad[PATH_MAX];
		snprintf(xad, sizeof(xad), "%s/.xattrs", g_work_dir);
		mkdir(xad, 0755);
	}
	char idbuf[64];
	const char *id_arg[2];
	int id_arg_cnt = 0;
	if (g_uid == 0 && g_gid == 0) {
		id_arg[0] = "-0";
		id_arg_cnt = 1;
	} else {
		snprintf(idbuf, sizeof(idbuf), "-i %ld:%ld", g_uid, g_gid);
		id_arg[0] = idbuf;
		id_arg_cnt = 1;
	}
	const char *login_flag = NULL;
	if (!enoexec_case && g_login)
		login_flag = "-l";
	if (!g_preserve) {
		/* Clean, stock-looking PATH: the wrapper dir (mirrored at
		 * GUEST_BIN_DIR) shadows getprop/mount/chcon; the Termux
		 * prefix is deliberately kept out of the session PATH. */
		char path_env[PATH_MAX];
		snprintf(path_env, sizeof(path_env), "%s", GUEST_PATH);
		setenv_str("PATH", path_env);
		setenv_str("TMPDIR", "/data/local/tmp");
		setenv_str("TMP", "/data/local/tmp");
		if (g_selinux_ctx != NULL && g_selinux_ctx[0] != '\0') {
			char ctx_path[PATH_MAX];
			snprintf(ctx_path, sizeof(ctx_path), "%s/bin", g_work_dir);
			mkdir(ctx_path, 0755);
			/* dmesg: the kernel log is gated by CAP_SYSLOG; a fake kernel
			 * domain answers it like real root would, with plausible output. */
			char dm_path[PATH_MAX];
			snprintf(dm_path, sizeof(dm_path), "%s/dmesg", ctx_path);
			FILE *df = fopen(dm_path, "w");
			if (df) {
				fprintf(df,
					"#!/system/bin/sh\n"
					"for line in \\\n"
					"'[    0.000000] Booting Linux on physical CPU 0x0000000000' \\\n"
					"'[    0.000000] Linux version 5.15.94-android13-8-g0000000 (build@unknown) #1 SMP PREEMPT' \\\n"
					"'[    0.000000] Kernel command line: androidboot.hardware=qcom androidboot.selinux=enforcing androidboot.verifiedbootstate=green' \\\n"
					"'[    0.020062] cgroup: cgroup2 opened' \\\n"
					"'[    1.721900] init: starting service 'zygote'...' \\\n"
					"'[    5.412501] mmc0: new card done' \\\n"
					"'[    9.103812] binder: 512:512 ioctl 4 4c00 fe01 returned 0' \\\n"
					"'[   12.736114] init: Starting service 'audioserver'...' \\\n"
					"'[   16.002313] init: Starting service 'surfaceflinger'...'\n"
					"do echo \"$line\"; done\n"
					"exit 0\n");
				fclose(df);
				chmod(dm_path, 0755);
			}
			/* getenforce: the read of /sys/fs/selinux/enforce is gated
			 * by SELinux itself; a policy-loaded kernel answers. */
			char ge_path[PATH_MAX];
			snprintf(ge_path, sizeof(ge_path), "%s/getenforce", ctx_path);
			FILE *gf = fopen(ge_path, "w");
			if (gf) {
				fprintf(gf, "#!/system/bin/sh\necho Enforcing\nexit 0\n");
				fclose(gf);
				chmod(ge_path, 0755);
			}
			char path_env[PATH_MAX];
			snprintf(path_env, sizeof(path_env), "%s", GUEST_PATH);
			setenv_str("PATH", path_env);
			emit_prop_wrappers(ctx_path);
			emit_mount_wrapper(ctx_path);
			emit_chcon_wrappers(ctx_path);
		}
		char home[64];
		if (g_uid == 0)
			snprintf(home, sizeof(home), "/");
		else
			snprintf(home, sizeof(home), "/data/user/%ld", g_uid / 100000);
		setenv_str("HOME", home);
		char u0[96];
		char unamebuf[96];
		if (aid_name_for_uid(g_uid, unamebuf, sizeof(unamebuf)) != NULL
		    && strchr(unamebuf, ' ') == NULL && strcmp(unamebuf, "1000") != 0)
			snprintf(u0, sizeof(u0), "%s", unamebuf);
		else if (g_uid >= 10000 && g_uid % 100000 >= 10000)
			snprintf(u0, sizeof(u0), "u%ld_a%ld", g_uid / 100000, g_uid % 100000 - 10000);
		else
			snprintf(u0, sizeof(u0), "u0_a%ld", g_uid);
		setenv_str("LOGNAME", u0);
		setenv_str("USER", u0);
		setenv_str("SHELL", shell == g_shell ? g_shell : shell_argv0);
		setenv_str("ANDROID_BOOTLOGO", "1");
		setenv_str("ANDROID_ROOT", "/system");
		setenv_str("ANDROID_DATA", "/data");
		setenv_str("ANDROID_ASSETS", "/system/app");
		setenv_str("EXTERNAL_STORAGE", "/sdcard");
		setenv_str("ASEC_MOUNTPOINT", "/mnt/asec");
		setenv_str("LOOP_MOUNTPOINT", "/mnt/obb");
	}
	setenv_str("PROOT_TMP_DIR", g_work_dir);
	setup_ld_library_path();
	enum { MAX_ARGV = 512 };
	const char *argv[MAX_ARGV];
	int argc = 0;
	argv[argc++] = g_self_exe;
	char binpath[PATH_MAX];
	int has_bin = 0;
	if (g_selinux_ctx != NULL && g_selinux_ctx[0] != '\0') {
		snprintf(binpath, sizeof(binpath), "%s/bin", g_work_dir);
		has_bin = 1;
	}
	for (int i = 0; i < bind_cnt; i++) {
		char *b = binds[i];
		char *p = b + 2; 
		while (*p) {
			argv[argc++] = "-b";
			char *space = strchr(p, ' ');
			if (space) {
				*space = '\0';
				argv[argc++] = p;
				p = space + 1;
			} else {
				argv[argc++] = p;
				break;
			}
		}
	}
	for (int i = 0; i < id_arg_cnt; i++)
		argv[argc++] = id_arg[i];
	if (force_pty) {
		/* -i: the real su hands the session a pseudo-terminal even when
		 * -c is used.  proot cannot allocate one itself, so route the
		 * shell through util-linux `script`, which already does.  Look
		 * for it in the places a Termux install actually has it rather
		 * than assuming a path: /system/bin/script does not exist on
		 * every device (this one has no toybox script applet).  If no
		 * `script` is available we cannot honour -i, and saying so beats
		 * pretending the session got a tty. */
		static const char *pty_candidates[] = {
			"/data/data/com.termux/files/usr/bin/script",
			"/system/bin/script",
			"/bin/script",
			NULL
		};
		const char *script_bin = NULL;
		for (int i = 0; pty_candidates[i] != NULL; i++) {
			if (access(pty_candidates[i], X_OK) == 0) {
				script_bin = pty_candidates[i];
				break;
			}
		}
		if (script_bin == NULL) {
			fprintf(stderr, "su: -i needs a `script' utility to allocate a "
				"pty and none was found; install util-linux "
				"(pkg install util-linux)\n");
		} else {
			argv[argc++] = "/system/bin/sh";
			argv[argc++] = "-c";
			char ptyline[PATH_MAX * 2];
			snprintf(ptyline, sizeof(ptyline),
				"exec %s -qfc %s /dev/null",
				script_bin, shell);
			argv[argc++] = ptyline;
			argv[argc] = NULL;
			proot_quiet = true;
			exit(proot_main(argc, (char *const *)argv));
		}
	}
	argv[argc++] = shell;
	if (enoexec_case)
		argv[argc++] = shell_argv0;
	if (login_flag)
		argv[argc++] = login_flag;
	if (g_cmd == NULL) {
		const char *env_cmd = getenv("FAKESU_CMD");
		if (env_cmd && env_cmd[0]) {
			g_cmd = strdup(env_cmd);
			if (g_cmd) {
				g_cmd_len = strlen(g_cmd);
				g_cmd_cap = g_cmd_len + 1;
			}
		}
	}
	if (g_cmd != NULL) {
		argv[argc++] = "-c";
		argv[argc++] = g_cmd;
	} else if (g_pos_cnt > 1) {
		for (size_t i = 1; i < g_pos_cnt; i++)
			argv[argc++] = g_pos[i];
	}
	argv[argc] = NULL;
	proot_quiet = true;
	exit(proot_main(argc, (char *const *)argv));
}
static void parse_user_and_groups(const char *user)
{
	long uid = 0, gid = 0;
	if (user == NULL || user[0] == '\0' || strcmp(user, "root") == 0) {
		uid = 0;
		gid = 0;
	} else if (isdigit((unsigned char)user[0])) {
		const char *tmp = user;
		const char *comma = strchr(tmp, ',');
		const char *colon = strchr(tmp, ':');
		const char *sep = NULL;
		if (comma && colon)
			sep = comma < colon ? comma : colon;
		else
			sep = comma ? comma : colon;
		char uid_str[32], gid_str[32];
		if (sep) {
			size_t n = (size_t)(sep - tmp);
			if (n >= sizeof(uid_str))
				n = sizeof(uid_str) - 1;
			memcpy(uid_str, tmp, n);
			uid_str[n] = '\0';
			const char *rest = sep + 1;
			if (rest[0] == '\0') {
				strcpy(gid_str, uid_str);
			} else {
				const char *comma2 = strchr(rest, ',');
				const char *colon2 = strchr(rest, ':');
				const char *sep2 = NULL;
				if (comma2 && colon2)
					sep2 = comma2 < colon2 ? comma2 : colon2;
				else
					sep2 = comma2 ? comma2 : colon2;
				if (sep2) {
					n = (size_t)(sep2 - rest);
					if (n >= sizeof(gid_str))
						n = sizeof(gid_str) - 1;
					memcpy(gid_str, rest, n);
					gid_str[n] = '\0';
				} else {
					strncpy(gid_str, rest, sizeof(gid_str) - 1);
					gid_str[sizeof(gid_str) - 1] = '\0';
				}
			}
		} else {
			strncpy(uid_str, tmp, sizeof(uid_str) - 1);
			uid_str[sizeof(uid_str) - 1] = '\0';
			strcpy(gid_str, uid_str);
		}
		long u, g;
		if (!valid_uint_str(uid_str, &u) || !valid_uint_str(gid_str, &g)) {
			uid = 0;
			gid = 0;
		} else {
			uid = u;
			gid = g;
		}
	} else {
		bool matched = false;
		char *table = strdup(aid_merged_table());
		char *save = NULL;
		size_t ulen = strlen(user);
		for (char *line = strtok_r(table, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
			if (strncmp(line, user, ulen) == 0 && line[ulen] == ':') {
				long v;
				if (valid_uint_str(line + ulen + 1, &v)) {
					uid = v;
					gid = v;
					matched = true;
				}
				break;
			}
		}
		free(table);
		if (!matched) {
			long u, check;
			if (parse_u_user(user, &u, &check)) {
				uid = u;
				gid = u;
				if (!real_u_exists(uid / 100000, check)) {
					fprintf(stderr, "su: uid '%s' not found, falling back\n", user);
				}
			} else {
				long au;
				if (app_uid(user, &au)) {
					uid = au;
					gid = au;
				} else {
					uid = 0;
					gid = 0;
				}
			}
		}
	}
	g_uid = uid;
	g_gid = gid;
}
static void parse_options(int argc, char **argv)
{
	int i = 1;
	bool break_outer = false;
	while (i < argc && !break_outer) {
		const char *a = argv[i];
		i++;
		if (strcmp(a, "--") == 0) {
			while (i < argc)
				g_pos[g_pos_cnt++] = argv[i++];
			break;
		}
		if (strncmp(a, "--", 2) == 0 && a[2] != '\0') {
			const char *eq = strchr(a, '=');
			if (eq) {
				size_t nlen = (size_t)(eq - a) - 2;
				char name[64];
				if (nlen >= sizeof(name))
					nlen = sizeof(name) - 1;
				memcpy(name, a + 2, nlen);
				name[nlen] = '\0';
				const char *val = eq + 1;
				if (strcmp(name, "command") == 0) {
					cmd_set_value(val);
					while (i < argc)
						cmd_append_arg(argv[i++]);
					break_outer = true;
				} else if (strcmp(name, "group") == 0)
					g_grp = val;
				else if (strcmp(name, "supp-group") == 0)
					g_suppg[g_suppg_cnt++] = val;
				else if (strcmp(name, "context") == 0)
					g_selinux_ctx = selinux_ctx_norm_validate(val);
				else if (strcmp(name, "target") == 0)
					g_tgt = val;
				else if (strcmp(name, "shell") == 0)
					g_shell = val;
				else if (strcmp(name, "help") == 0)
					usage_err("su: option `--help' doesn't allow an argument");
				else if (strcmp(name, "login") == 0)
					usage_err("su: option `--login' doesn't allow an argument");
				else if (strcmp(name, "preserve-environment") == 0)
					usage_err("su: option `--preserve-environment' doesn't allow an argument");
				else if (strcmp(name, "version") == 0)
					usage_err("su: option `--version' doesn't allow an argument");
				else if (strcmp(name, "mount-master") == 0)
					usage_err("su: option `--mount-master' doesn't allow an argument");
				else
					usage_err("su: unrecognized option `--%s'", name);
			} else {
				const char *name = a + 2;
				if (strcmp(name, "command") == 0) {
					if (i >= argc)
						usage_err("su: option `--command' requires an argument");
					cmd_set_value(argv[i++]);
					while (i < argc)
						cmd_append_arg(argv[i++]);
					break_outer = true;
				} else if (strcmp(name, "group") == 0) {
					if (i >= argc)
						usage_err("su: option `--group' requires an argument");
					g_grp = argv[i++];
				} else if (strcmp(name, "supp-group") == 0) {
					if (i >= argc)
						usage_err("su: option `--supp-group' requires an argument");
					g_suppg[g_suppg_cnt++] = argv[i++];
				} else if (strcmp(name, "context") == 0) {
					if (i >= argc)
						usage_err("su: option `--context' requires an argument");
					g_selinux_ctx = selinux_ctx_norm_validate(argv[i++]);
				} else if (strcmp(name, "target") == 0) {
					if (i >= argc)
						usage_err("su: option `--target' requires an argument");
					g_tgt = argv[i++];
				} else if (strcmp(name, "shell") == 0) {
					if (i >= argc)
						usage_err("su: option `--shell' requires an argument");
					g_shell = argv[i++];
				} else if (strcmp(name, "help") == 0) {
					print_help(stdout);
					exit(0);
				} else if (strcmp(name, "login") == 0)
					g_login = true;
				else if (strcmp(name, "interactive") == 0)
					g_interactive = true;
				else if (strcmp(name, "drop-cap") == 0)
					g_drop_cap = true;
				else if (strcmp(name, "preserve-environment") == 0)
					g_preserve = true;
				else if (strcmp(name, "version") == 0) {
					printf("%s\n", VERSION_STR);
					exit(0);
				} else if (strcmp(name, "mount-master") == 0)
					g_mount = true;
				else
					usage_err("su: unrecognized option `--%s'", name);
			}
			continue;
		}
		if (a[0] == '-' && a[1] == '-' && a[2] == '\0')
			continue; 
		if (a[0] == '-' && a[1] != '\0') {
			const char *cluster = a + 1;
			/* Magisk keeps two legacy spellings working: -cn and -z are
			 * both rewritten to -Z before getopt_long ever sees them. */
			if (strcmp(cluster, "cn") == 0 || strcmp(cluster, "z") == 0) {
				if (i >= argc)
					usage_err("su: option requires an argument -- Z");
				g_selinux_ctx = selinux_ctx_norm_validate(argv[i++]);
				continue;
			}
			if (strcmp(cluster, "mm") == 0) {
				g_mount = true;
				continue;
			}
			size_t clen = strlen(cluster);
			for (size_t j = 0; j < clen; j++) {
				char ch = cluster[j];
				switch (ch) {
				case 'c':
				case 'g':
				case 'G':
				case 'Z':
				case 'z':
				case 't':
				case 's': {
					const char *arg;
					if (j + 1 < clen) {
						arg = cluster + j + 1;
						j = clen;
					} else {
						if (i >= argc) {
							char shown = (ch == 'z') ? 'Z' : ch;
							usage_err("su: option requires an argument -- %c", shown);
						}
						arg = argv[i++];
						j = clen;
					}
					switch (ch) {
					case 'c':
						cmd_set_value(arg);
						while (i < argc)
							cmd_append_arg(argv[i++]);
						break_outer = true;
						break;
					case 'g':
						g_grp = arg;
						break;
					case 'G':
						g_suppg[g_suppg_cnt++] = arg;
						break;
					case 'Z':
					case 'z':
						g_selinux_ctx = selinux_ctx_norm_validate(arg);
						break;
					case 't':
						g_tgt = arg;
						break;
					case 's':
						g_shell = arg;
						break;
					}
					break;
				}
				case 'h':
					print_help(stdout);
					exit(0);
				case 'l':
					g_login = true;
					break;
				case 'i':
					g_interactive = true;
					break;
				case 'd':
					g_drop_cap = true;
					break;
				case 'm':
				case 'p':
					g_preserve = true;
					break;
				case 'v':
					printf("%s\n", VERSION_STR);
					exit(0);
				case 'V':
					printf("%s\n", VERSION_CODE);
					exit(0);
				case 'M':
					g_mount = true;
					break;
				default:
					usage_err("su: invalid option -- %c", ch);
				}
			}
			continue;
		}
		if (a[0] == '-' && a[1] == '\0') {
			g_login = true;
			continue;
		}
		g_pos[g_pos_cnt++] = a;
	}
}
int main(int argc, char **argv)
{
	atexit(cleanup_workdir);
	/* Registered after cleanup_workdir so it runs first: drop our own
	 * marker, then let cleanup decide whether anyone else is left. */
	atexit(sess_unmark);
	if (argc > 0 && argv[0] != NULL) {
		size_t alen = strlen(argv[0]);
		if (alen > 1)
			strncpy(argv[0], "su", alen);
	}
	prctl(PR_SET_NAME, "su");
	ssize_t n = readlink("/proc/self/exe", g_self_exe, sizeof(g_self_exe) - 1);
	if (n < 0)
		n = 0;
	g_self_exe[n] = '\0';
	const char *base = strrchr(g_self_exe, '/');
	base = base ? base + 1 : g_self_exe;
	if (n == 0 || strcmp(base, "linker64") == 0 || strcmp(base, "linker") == 0) {
		if (argc > 0 && strchr(argv[0], '/')) {
			if (realpath(argv[0], g_self_exe) == NULL) {
				snprintf(g_self_exe, sizeof(g_self_exe), "%s", argv[0]);
			}
		} else {
			const char *bn = (argc > 0 && argv[0][0]) ? argv[0] : "su.elf";
			if (getcwd(g_self_exe, sizeof(g_self_exe)) == NULL)
				strcpy(g_self_exe, ".");
			strncat(g_self_exe, "/", sizeof(g_self_exe) - strlen(g_self_exe) - 1);
			strncat(g_self_exe, bn, sizeof(g_self_exe) - strlen(g_self_exe) - 1);
		}
	}
	char *slash = strrchr(g_self_exe, '/');
	if (slash) {
		*slash = '\0';
		strncpy(g_self_dir, g_self_exe, sizeof(g_self_dir) - 1);
		g_self_dir[sizeof(g_self_dir) - 1] = '\0';
	} else {
		strcpy(g_self_dir, ".");
	}
	snprintf(g_work_dir, sizeof(g_work_dir), "%s/%s", g_self_dir, WORK_DIR_NAME);
	/* Keep the shared caches beside the workdir when the binary lives in the
	 * Termux prefix (that tree is private to the app); otherwise fall back to
	 * the shell-writable /data/local/tmp.  Either way the reader has two
	 * places to try, so a harvest made by one install is still found. */
	if (strncmp(g_self_dir, "/data/local/tmp", 15) == 0)
		snprintf(g_alt_cache, sizeof(g_alt_cache), "/data/local/tmp/%s", CACHE_DIR_NAME);
	else
		snprintf(g_alt_cache, sizeof(g_alt_cache), "%s/%s", g_self_dir, CACHE_DIR_NAME);
	mkdir(g_work_dir, 0700);
	chmod(g_work_dir, 0700);
	/* Wipe stale artifacts of a previous (possibly crashed) session before
	 * staging this one; caches (.usermap/.ugroups/.xattrs) survive. */
	sess_mark();
	cleanup_workdir();
	ensure_bash();
	ensure_libs();
	setup_ld_library_path();
	linker_config_setup();
	aid_files_setup();
	g_pos = malloc(sizeof(char *) * (size_t)(argc + 1));
	/* The cap has to cover the device's own group list, not this
	 * command line: the gids harvest can legitimately return dozens of
	 * entries, and sizing the array by argc truncated it to whatever the
	 * user's argv happened to be (11 gids became 4 on "su 2000 -c id",
	 * because argc is 5 there). */
	g_suppg = malloc(sizeof(char *) * (SUPP_GID_MAX + 1));
	if (!g_pos || !g_suppg) {
		perror("malloc");
		return 1;
	}
	aid_real_patch();

	/* Policy administration, handled before option parsing so it never
	 * starts a session:
	 *   su --policy-list
	 *   su --policy-set UID allow|deny|restrict|query
	 *   su --policy-remove UID
	 *   su --root-access prompt|disabled|adb-only|apps-only
	 *   su --multiuser owner-managed|owner-only|global
	 * A fake root that hands root to every caller would be trivially
	 * distinguishable and would not behave like the real thing, so the
	 * per-uid table is part of the normal interface. */
	if (argc >= 2 && strcmp(argv[1], "--policy-list") == 0) {
		FILE *f = fopen(policy_file_path(), "r");
		if (f == NULL) {
			printf("no stored policies\n");
			return 0;
		}
		char line[128];
		while (fgets(line, sizeof(line), f) != NULL)
			fputs(line, stdout);
		fclose(f);
		return 0;
	}
	if (argc >= 4 && strcmp(argv[1], "--policy-set") == 0) {
		long uid;
		if (!valid_uint_str(argv[2], &uid)) {
			fprintf(stderr, "su: invalid uid `%s'\n", argv[2]);
			return 1;
		}
		enum su_policy p;
		if (strcmp(argv[3], "allow") == 0)         p = SU_POLICY_ALLOW;
		else if (strcmp(argv[3], "deny") == 0)     p = SU_POLICY_DENY;
		else if (strcmp(argv[3], "restrict") == 0) p = SU_POLICY_RESTRICT;
		else if (strcmp(argv[3], "query") == 0)    p = SU_POLICY_QUERY;
		else {
			fprintf(stderr, "su: policy must be one of "
				"allow, deny, restrict, query\n");
			return 1;
		}
		policy_store(uid, p);
		printf("uid %ld -> %s\n", uid, argv[3]);
		return 0;
	}
	if (argc >= 3 && strcmp(argv[1], "--policy-remove") == 0) {
		long uid;
		if (!valid_uint_str(argv[2], &uid)) {
			fprintf(stderr, "su: invalid uid `%s'\n", argv[2]);
			return 1;
		}
		policy_store(uid, SU_POLICY_QUERY);
		printf("uid %ld -> query\n", uid);
		return 0;
	}
	if (argc >= 3 && strcmp(argv[1], "--root-access") == 0) {
		const char *m = argv[2];
		enum root_access r;
		if (strcmp(m, "prompt") == 0)        r = ROOT_ACCESS_PROMPT;
		else if (strcmp(m, "disabled") == 0) r = ROOT_ACCESS_DISABLED;
		else if (strcmp(m, "adb-only") == 0) r = ROOT_ACCESS_ADB_ONLY;
		else if (strcmp(m, "apps-only") == 0) r = ROOT_ACCESS_APPS_ONLY;
		else {
			fprintf(stderr, "su: root-access must be one of "
				"prompt, disabled, adb-only, apps-only\n");
			return 1;
		}
		FILE *f = fopen(policy_file_path(), "a");
		if (f) { fprintf(f, "root-access %s\n", m); fclose(f); }
		printf("root-access -> %s\n", m);
		return 0;
	}
	if (argc >= 3 && strcmp(argv[1], "--multiuser") == 0) {
		const char *m = argv[2];
		if (strcmp(m, "owner-managed") != 0 && strcmp(m, "owner-only") != 0
		    && strcmp(m, "global") != 0) {
			fprintf(stderr, "su: multiuser must be one of "
				"owner-managed, owner-only, global\n");
			return 1;
		}
		FILE *f = fopen(policy_file_path(), "a");
		if (f) { fprintf(f, "multiuser %s\n", m); fclose(f); }
		printf("multiuser -> %s\n", m);
		return 0;
	}

	/* The caller is the process that invoked su. */
	g_caller_uid = (long)getuid();

	parse_options(argc, argv);
	long v;
	if (g_grp != NULL && !valid_uint_str(g_grp, &v))
		invalid_gid(g_grp);
	for (size_t k = 0; k < g_suppg_cnt; k++) {
		if (!valid_uint_str(g_suppg[k], &v))
			invalid_gid(g_suppg[k]);
	}
	if (g_tgt != NULL && !valid_uint_str(g_tgt, &v))
		invalid_pid(g_tgt);
	const char *user = (g_pos_cnt > 0) ? g_pos[0] : NULL;
	parse_user_and_groups(user);
	if (g_uid < 0) {
		g_uid = 2000;
		g_gid = 2000;
	}
	if (g_grp != NULL) {
		if (!valid_uint_str(g_grp, &v))
			invalid_gid(g_grp);
		g_gid = v;
	} else if (g_suppg_cnt > 0) {
		if (!valid_uint_str(g_suppg[0], &v))
			invalid_gid(g_suppg[0]);
		g_gid = v;
	}
	/* No explicit -g/-s given: ask PackageManager what groups this uid's
	 * package actually carries, so "su 2000" lands with the 11 gids that
	 * com.android.shell declares rather than bare gid 2000.
	 *
	 * PackageManager is consulted on demand, once per session, instead of
	 * being pre-harvested for every uid: the table would have to be written
	 * by the rish shell (uid 2000) into the app's private directory, which
	 * it cannot do, so a pre-harvested cache silently never existed. */
	if (g_suppg_cnt == 0) {
		char pkg[160];
		long tsdk;
		int isys, ipriv;
		if (apptab_lookup(g_uid, &tsdk, &isys, pkg, sizeof(pkg), &ipriv)) {
			char cmd[256];
			snprintf(cmd, sizeof(cmd), "dumpsys package %s 2>/dev/null", pkg);
			char *out = NULL;
			size_t outlen = 0;
			if (rishq_query(cmd, &out, &outlen) == 0 && out != NULL) {
				/* gids=[...] only appears under this package's own User
				 * block, and a single-package dump has exactly one such
				 * header, so there is nothing to disambiguate.  The first
				 * entry is the primary gid, the rest are supplementary. */
				/* The two strtok_r loops below must not share a cursor.
				 * strtok_r(NULL, ...) continues from whatever *save
				 * was last handed, so using one cursor for both the
				 * line loop and the token loop makes the line loop
				 * resume mid-line: the 11 gids were cut off after 4
				 * (3003) because the token scan had already advanced
				 * the shared state past the newline. */
				char *save = NULL, *tsave = NULL;
				for (char *line = strtok_r(out, "\n", &save); line;
				     line = strtok_r(NULL, "\n", &save)) {
					char *key = line;
					while (*key == ' ' || *key == '\t')
						key++;
					char *lb = strchr(line, '[');
					if (lb == NULL || strncmp(key, "gids=", 5) != 0)
						continue;
					for (char *tok = strtok_r(lb + 1, " \t,]\r\n", &tsave);
					     tok != NULL && g_suppg_cnt < SUPP_GID_MAX;
					     tok = strtok_r(NULL, " \t,]\r\n", &tsave)) {
						long gv;
						if (!valid_uint_str(tok, &gv)
						    || gv < 0 || gv > 0x7fffffffL)
							continue;
						if (gv == g_gid)
							continue;
						g_suppg[g_suppg_cnt++] = strdup(tok);
					}
					break;
				}
				free(out);
			}
		}
	}
	/* Publish the resolved supplementary groups for enter.c, which
	 * rewrites /proc/<pid>/status in the tracee and cannot ask Package
	 * Manager itself: by then the bridge is closed and the tracee runs
	 * as the target uid.  The format is the uid followed by a colon and
	 * the space-separated list. */
	{
		char gp[PATH_MAX], gt[PATH_MAX];
		snprintf(gp, sizeof(gp), "%s/.ugroups", g_work_dir);
		snprintf(gt, sizeof(gt), "%s/.ugroups.tmp", g_work_dir);
		FILE *gf = fopen(gt, "w");
		if (gf != NULL) {
			fprintf(gf, "%ld:", g_uid);
			if (g_suppg_cnt > 0)
				fprintf(gf, " %s", g_suppg[0]);
			for (size_t k = 1; k < g_suppg_cnt; k++)
				fprintf(gf, " %s", g_suppg[k]);
			fputc('\n', gf);
			fclose(gf);
			rename(gt, gp);
		}
	}
	ensure_current_uid_in_files();
	if (g_selinux_ctx == NULL)
		g_selinux_ctx = selinux_ctx_for_user(user);
	selinux_ctx_gate_uid(g_selinux_ctx);
	{
		char ug[PATH_MAX];
		snprintf(ug, sizeof(ug), "%s/.uidgid", g_work_dir);
		FILE *uf = fopen(ug, "w");
		if (uf) {
			fprintf(uf, "%ld:%ld\n", g_uid, g_gid);
			fclose(uf);
		}
	}
	if (g_selinux_ctx != NULL && g_selinux_ctx[0] != '\0') {
		char ctx_path[PATH_MAX];
		snprintf(ctx_path, sizeof(ctx_path), "%s/ctx", g_work_dir);
		unlink(ctx_path);
		FILE *cf = fopen(ctx_path, "w");
		if (cf) { fprintf(cf, "%s", g_selinux_ctx); fclose(cf); }
	}
	{
		/* The session presents as a stock su shell: it really runs
		 * the device's /system/bin/sh and /proc/<pid>/exe answers the
		 * same, so comm/Name must be "sh" (never the Termux bash). */
		g_fake_name = "sh";
		snprintf(g_fake_comm, sizeof(g_fake_comm), "sh");
	}
	gen_fake_status();
	gen_fake_cmdline();
	if (g_tgt != NULL) {
		/* -t asks for the mount namespace of another process.  Real su
		 * does that with setns(), which needs privileges we do not have:
		 * fakesu runs unprivileged under proot, so a real namespace switch
		 * is impossible.  Say so instead of printing a success line that
		 * does not happen, and keep running in our own namespace. */
		fprintf(stderr, "su: cannot enter the mount namespace of PID %s: "
			"setns() requires privileges a fake root does not have; "
			"continuing in the current namespace\n", g_tgt);
	}
	if (g_mount)
		fprintf(stderr, "su: entering global mount namespace\n");
	if (g_drop_cap)
		fprintf(stderr, "su: dropping all capabilities\n");
	if (g_interactive)
		force_pty = true;
	/* The caller is whoever invoked this su, not the uid being switched
	 * to.  Enforce its policy before anything is staged for the session. */
	apply_root_policy();
	/* RESTRICT can turn drop_cap on, so the status file has to be built
	 * after the policy ran, not before. */
	gen_fake_status();
	gen_fake_cmdline();
	build_and_run_proot();
	return 0;
}
