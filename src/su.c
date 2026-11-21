
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
#include <signal.h>
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

/* Vsud, the privilege anchor.  Implemented in vsud.c and kept separate on
 * purpose: it is a second, long-lived process whose whole job is to define
 * where the faked identity begins.  su.c must not grow that responsibility,
 * or the anchor would inherit the very state it is supposed to sit above. */
int vsud_daemon_main(void);
int vsud_client_main(int argc, char **argv);
#define VSUD_FALLBACK (-1)
extern const unsigned char _binary_bash_bin_start[];
extern const unsigned char _binary_bash_bin_end[];
#define EMBEDDED_BASH_SIZE ((size_t)(_binary_bash_bin_end - _binary_bash_bin_start))
extern const unsigned char _binary_libiconv_so_start[];
extern const unsigned char _binary_libiconv_so_end[];
extern const unsigned char _binary_libncursesw_so_6_5_start[];
extern const unsigned char _binary_libncursesw_so_6_5_end[];
/* facts.dex and rishq, embedded at build time (see build_su.sh). */
extern const unsigned char _binary_facts_dex_start[];
extern const unsigned char _binary_facts_dex_end[];
extern const unsigned char _binary_rishq_start[];
extern const unsigned char _binary_rishq_end[];
extern const unsigned char _binary_rish_start[];
extern const unsigned char _binary_rish_end[];
extern const unsigned char _binary_rish_shizuku_dex_start[];
extern const unsigned char _binary_rish_shizuku_dex_end[];
/* Historically these were hardcoded KernelSU 3.2.5 values.  They are kept
 * as macros so the many use sites stay untouched, but they now forward to
 * the active persona, which defaults to honest VirtualSU 1.3.0. */
#define VERSION_STR  g_p_version
#define VERSION_CODE g_p_code
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
/* -u/--user: the uid to run as, as an alternative to the positional
 * "su [user]" form.  Both end up in the same place; main() rejects the two
 * spellings disagreeing rather than picking one. */
static const char *g_user_opt = NULL;
/* Not static: proot's enter.c rewrites /proc/<pid>/status on every read and
 * needs the same flag, otherwise --drop-cap changes the file we generate
 * but not the one the session actually reads.  Superseded by --caps for
 * anything finer-grained, but still the switch --caps none is defined in
 * terms of, and still what decides the bounding set. */
int g_drop_cap = false;

/*
 * The five capability sets the session presents, in the two-32-bit-word
 * layout capget(2) version 3 uses.
 *
 * Exported, and deliberately so: two places answer "what capabilities does
 * this session hold" -- su.c's own /proc stand-in for the wrapper, and
 * enter.c's for everything running under proot.  Each used to re-derive the
 * answer from `uid == 0 && !g_drop_cap` independently, which is precisely
 * the duplicated decision that stops agreeing with itself; one of the two
 * would have been updated and the other not.  There is one answer now and
 * both read it.
 *
 * The default is what uid 0 really has on this kernel: all 38 implemented
 * bits in permitted/effective, nothing inheritable or ambient, and a full
 * bounding set.  --caps replaces it with whatever was asked for.
 */
struct af_capsets {
	uint32_t inh[2];
	uint32_t prm[2];
	uint32_t eff[2];
	uint32_t bnd[2];
	uint32_t amb[2];
};

struct af_capsets g_caps = {
	{ 0, 0 },			/* inh: nothing is inheritable */
	{ 0xffffffffu, 0x3fu },		/* prm: bits 0-37, all this kernel has */
	{ 0xffffffffu, 0x3fu },		/* eff */
	{ 0xffffffffu, 0x3fu },		/* bnd */
	{ 0, 0 },			/* amb */
};

/* Set when --caps was given, so a non-root uid can still be given a
 * capability set.  Without it the uid decides, matching setuid(): a uid
 * that is not 0 comes up with permitted/effective empty whatever the parent
 * had.  A capability that a real kernel would only obtain from a file or an
 * ambient set is something the caller has to ask for by name. */
int g_caps_explicit = false;

/* The capability bits this kernel's headers name.  `all' in a --caps
 * specification means exactly this set -- the legitimate tags -- rather
 * than 64 bits of which the top 23 name nothing.  Measured on the target
 * device, uid 0 holds 0x3fffffffff, i.e. the first 38 of these. */
struct af_capname {
	const char *name;
	int bit;
};

static const struct af_capname af_cap_names[] = {
	{ "chown",			0  }, { "dac_override",		1  },
	{ "dac_read_search",		2  }, { "fowner",		3  },
	{ "fsetid",			4  }, { "kill",		5  },
	{ "setgid",			6  }, { "setuid",		7  },
	{ "setpcap",			8  }, { "linux_immutable",	9  },
	{ "net_bind_service",		10 }, { "net_broadcast",		11 },
	{ "net_admin",			12 }, { "net_raw",		13 },
	{ "ipc_lock",			14 }, { "ipc_owner",		15 },
	{ "sys_module",			16 }, { "sys_rawio",		17 },
	{ "sys_chroot",			18 }, { "sys_ptrace",		19 },
	{ "sys_pacct",			20 }, { "sys_admin",		21 },
	{ "sys_boot",			22 }, { "sys_nice",		23 },
	{ "sys_resource",		24 }, { "sys_time",		25 },
	{ "sys_tty_config",		26 }, { "mknod",		27 },
	{ "lease",			28 }, { "audit_write",		29 },
	{ "audit_control",		30 }, { "setfcap",		31 },
	{ "mac_override",		32 }, { "mac_admin",		33 },
	{ "syslog",			34 }, { "wake_alarm",		35 },
	{ "block_suspend",		36 }, { "audit_read",		37 },
	{ "perfmon",			38 }, { "bpf",		39 },
	{ "checkpoint_restore",		40 },
};

/* Highest bit any name above claims; `all' stops here. */
#define AF_CAP_LAST_NAMED 40

static void af_cap_set(uint32_t w[2], int bit)
{
	if (bit < 32)
		w[0] |= 1u << bit;
	else if (bit < 64)
		w[1] |= 1u << (bit - 32);
}

static void af_cap_clear(uint32_t w[2], int bit)
{
	if (bit < 32)
		w[0] &= ~(1u << bit);
	else if (bit < 64)
		w[1] &= ~(1u << (bit - 32));
}

/* Render the way /proc/<pid>/status does: the high word first, so the
 * caller and this function cannot disagree about which half is which. */
static const char *af_caps_hex(const uint32_t w[2], char *buf, size_t cap)
{
	snprintf(buf, cap, "%08x%08x", w[1], w[0]);
	return buf;
}

static void af_caps_set_bit(int bit)
{
	af_cap_set(g_caps.prm, bit);
	af_cap_set(g_caps.eff, bit);
	/* Anything asked for by name has to be obtainable, and a real kernel
	 * only hands out a capability that is inside the bounding set. */
	af_cap_set(g_caps.bnd, bit);
}

static int af_cap_lookup(const char *s, size_t len)
{
	size_t i;

	if (len > 4 && strncmp(s, "cap_", 4) == 0) {
		s += 4;
		len -= 4;
	}
	for (i = 0; i < sizeof(af_cap_names) / sizeof(af_cap_names[0]); i++)
		if (strlen(af_cap_names[i].name) == len
		 && strncmp(af_cap_names[i].name, s, len) == 0)
			return af_cap_names[i].bit;
	return -1;
}

static void af_cap_invalid(const char *tok, size_t len)
{
	char name[64];
	size_t n = len < sizeof(name) - 1 ? len : sizeof(name) - 1;

	memcpy(name, tok, n);
	name[n] = '\0';
	if (len >= sizeof(name))
		fprintf(stderr, "su: capability name too long\n");
	else
		fprintf(stderr, "su: unknown capability `%s'\n", name);
	fprintf(stderr,
		"su: names are the kernel's, with or without the cap_ prefix "
		"(chown, net_raw, sys_admin, ...); a bare number 0-63 also works\n");
}

/*
 * Parse a --caps specification into permitted/effective/bounding.
 *
 * Grammar, all comma- or space-separated:
 *   all              every named capability
 *   none             nothing
 *   NAME | +NAME     add (NAME may be a bare bit number)
 *   -NAME            remove
 * The base is `all' unless the list opens with `none', so "-net_raw" reads
 * as "everything except net_raw" and "net_admin,net_raw" reads as exactly
 * those two.  Permitted and effective are set to the result and the
 * bounding set is widened to cover it, because a capability outside the
 * bounding set can never be held and asking for one would otherwise
 * produce a session that contradicts itself.
 */
static void parse_caps_spec(const char *spec)
{
	struct item { int bit; bool add; };
	struct item items[128];
	size_t nitems = 0;
	char buf[1024];
	char *save = NULL;
	char *tok;
	bool kw_none = false;
	bool kw_all = false;
	unsigned int removals = 0;
	size_t i;

	if (strlen(spec) >= sizeof(buf)) {
		fprintf(stderr, "su: --caps specification too long\n");
		exit(2);
	}
	strcpy(buf, spec);

	/* Pass one: read the list.  Nothing is applied yet, because whether the
	 * base is `all' or `none' is only known once the whole list has been
	 * seen -- `-net_raw,net_raw' has to cancel itself out. */
	for (tok = strtok_r(buf, ", \t", &save); tok != NULL;
	     tok = strtok_r(NULL, ", \t", &save)) {
		char *p = tok;
		bool add = true;
		int bit;
		char *endp = NULL;

		if (*p == '+') {
			p++;
		} else if (*p == '-') {
			add = false;
			p++;
		}
		if (*p == '\0')
			continue;

		if (strcmp(p, "none") == 0) {
			kw_none = true;
			continue;
		}
		if (strcmp(p, "all") == 0) {
			kw_all = true;
			continue;
		}

		if (p[0] >= '0' && p[0] <= '9') {
			long v = strtol(p, &endp, 10);

			if (endp == p || *endp != '\0' || v < 0 || v > 63) {
				af_cap_invalid(p, strlen(p));
				exit(2);
			}
			bit = (int) v;
		} else {
			bit = af_cap_lookup(p, strlen(p));
			if (bit < 0) {
				af_cap_invalid(p, strlen(p));
				exit(2);
			}
		}
		if (nitems >= sizeof(items) / sizeof(items[0])) {
			fprintf(stderr, "su: too many capabilities in --caps\n");
			exit(2);
		}
		items[nitems].bit = bit;
		items[nitems].add = add;
		nitems++;
		/* A removal only means something against something, so it selects
		 * the full set as the base.  Without one, a bare list means exactly
		 * what it names rather than everything plus it: "--caps net_raw"
		 * has to answer the question it looks like it asks. */
		if (!add)
			removals++;
	}

	/* Pass two: apply. */
	g_caps.inh[0] = g_caps.inh[1] = 0;
	g_caps.amb[0] = g_caps.amb[1] = 0;
	g_caps.prm[0] = g_caps.prm[1] = 0;
	g_caps.eff[0] = g_caps.eff[1] = 0;
	g_caps.bnd[0] = g_caps.bnd[1] = 0;

	/* An explicit keyword decides the base outright; otherwise a removal in
	 * the list implies it, and a list of nothing but additions starts from
	 * empty.  `all' and `none' in the same list is a contradiction, and
	 * `all' wins only because it was written first in this ordering -- the
	 * parser does not try to guess better than that. */
	if (kw_all || (!kw_none && removals > 0))
		for (i = 0; i <= AF_CAP_LAST_NAMED; i++)
			af_caps_set_bit((int) i);

	for (i = 0; i < nitems; i++) {
		if (items[i].add)
			af_caps_set_bit(items[i].bit);
		else {
			af_cap_clear(g_caps.prm, items[i].bit);
			af_cap_clear(g_caps.eff, items[i].bit);
			/* Removing something from the bounding set too is what
			 * makes "-x" mean the session can never hold x, rather
			 * than merely not holding it right now. */
			af_cap_clear(g_caps.bnd, items[i].bit);
		}
	}

	/* The bounding set has to contain permitted and effective, or the
	 * session reports a combination the kernel could never produce. */
	g_caps.bnd[0] |= g_caps.prm[0] | g_caps.eff[0];
	g_caps.bnd[1] |= g_caps.prm[1] | g_caps.eff[1];

	g_caps_explicit = true;
}

/* The empty set, for the branches that report "none of it". */
static const uint32_t g_caps_zero[2] = { 0, 0 };

/* The single place a capability set becomes the string /proc shows. */
static const char *capsline(const char *label, const uint32_t w[2],
			    char *buf, size_t cap)
{
	char hex[32];

	af_caps_hex(w, hex, sizeof(hex));
	snprintf(buf, cap, "%s\t%s\n", label, hex);
	return buf;
}

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
/* Whether the uid gets the persona's capability sets at all.  Root always
 * does.  A non-root uid does only when --caps asked for a set by name,
 * since setuid() would otherwise leave permitted and effective empty. */
static bool af_caps_active(void)
{
	return g_uid == 0 || g_caps_explicit;
}

static long g_gid = -1;
const char *g_selinux_ctx = NULL;
/* Set when the caller named a context explicitly (-Z / --context), as opposed
 * to one derived from the target user.  The distinction decides whether the
 * per-uid gate applies at all: asking for a specific domain is a claim about
 * identity that has to be checked against the caller's real one, while the
 * derived default is simply where the session is going -- no real process
 * runs in virtu_su, so requiring the caller to already be there would refuse
 * every run. */
bool g_ctx_explicit = false;

/* VirtualSU: -Z accepts any syntactically valid context by default, not
 * just one already in the running policy.  proot never touches real
 * SELinux enforcement, so rejecting an unknown domain bought no real
 * safety -- it only blocked the "present any label you want" use case.
 * Set to 1 (or pass --require-existing-domain) to restore the old
 * policy-membership check. */
int g_require_existing_domain = 0;

/* ------------------------------------------------------------------ *
 * Persona: the identity this binary presents.
 *
 * Up to now the name and version were compile-time constants claiming to
 * be KernelSU 3.2.5, which made the tool lie by default and made every
 * fidelity question unanswerable ("does it match?") whenever the real
 * thing was not on hand.  VirtualSU presents itself as VirtualSU and
 * treats the other identities as opt-in data.
 *
 * Everything user-visible funnels through these five strings, so a
 * persona is a file, not a rebuild:
 *
 *   $VIRTUALSU_PERSONA=/path/to/kernelsu.json su -c id
 *   $VIRTUALSU_PERSONA=... su -v          # 3.2.5-44-g0f65ab64:KernelSU
 *
 * Unknown keys are ignored and a malformed file is a warning, never a
 * hard error: identity presentation should not be able to stop a
 * session.
 * ------------------------------------------------------------------ */
static char g_p_name[64]    = "VirtualSU";
static char g_p_version[64] = "1.3.0";
static char g_p_code[32]    = "1300";
static char g_p_banner[64]  = "VirtualSU";
static char g_p_usage[64]   = "su";
/* Not static, unlike the four above: proot's enter.c keeps its own copy of
 * the root-domain fallback for the case where the session ctx file is
 * missing, and when that fallback was a literal of its own it drifted --
 * su.c moved to the persona domain and enter.c kept claiming u:r:ksu:s0,
 * so the two halves of one binary answered differently.  Declaring it here
 * is the same reason g_drop_cap is not static. */
char g_p_domain[128] = "u:r:virtu_su:s0";
static char g_p_shell[128]  = "";   /* empty = built-in default */

/* Trim leading/trailing space and, if present, one layer of "..." so a
 * quoted value in a hand-written file behaves the way people expect. */
static void persona_chomp(char *s)
{
	char *b = s;
	size_t n;
	while (*b == ' ' || *b == '\t')
		b++;
	if (b != s)
		memmove(s, b, strlen(b) + 1);
	n = strlen(s);
	while (n > 0 && (s[n-1] == ' ' || s[n-1] == '\t' || s[n-1] == '\r'
	                 || s[n-1] == '\n'))
		s[--n] = '\0';
	n = strlen(s);
	if (n >= 2 && s[0] == '"' && s[n-1] == '"') {
		s[n-1] = '\0';
		memmove(s, s + 1, n - 1);
	}
}

static void persona_set(char *dst, size_t cap, const char *val)
{
	if (val == NULL)
		return;
	snprintf(dst, cap, "%s", val);
	persona_chomp(dst);
}

static void persona_apply_kv(const char *k, const char *v)
{
	if (strcmp(k, "name") == 0)               persona_set(g_p_name,    sizeof(g_p_name),    v);
	else if (strcmp(k, "version") == 0)       persona_set(g_p_version, sizeof(g_p_version), v);
	else if (strcmp(k, "version_code") == 0)  persona_set(g_p_code,    sizeof(g_p_code),    v);
	else if (strcmp(k, "banner") == 0)        persona_set(g_p_banner,  sizeof(g_p_banner),  v);
	else if (strcmp(k, "usage_name") == 0)    persona_set(g_p_usage,   sizeof(g_p_usage),   v);
	else if (strcmp(k, "selinux_domain") == 0) persona_set(g_p_domain, sizeof(g_p_domain), v);
	else if (strcmp(k, "require_existing_domain") == 0)
		g_require_existing_domain = (v != NULL && (*v == '1' || *v == 't'
		                             || *v == 'y' || *v == 'T' || *v == 'Y'));
	else if (strcmp(k, "shell_path") == 0)    persona_set(g_p_shell,   sizeof(g_p_shell),   v);
}

/* Minimal JSON reader: finds "key" at the top level, then copies the
 * following string or bare scalar.  Not a general parser -- a persona file
 * is a flat object, and pretending otherwise would be a bug factory. */
static void persona_apply_file(const char *path)
{
	FILE *f = fopen(path, "r");
	char line[512];
	if (f == NULL) {
		fprintf(stderr, "su: persona file %s not readable; using built-in identity\n", path);
		return;
	}
	while (fgets(line, sizeof(line), f) != NULL) {
		char key[64], val[256], *p = line, *k, *v;
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '{' || *p == '}' || *p == ',' || *p == '\n' || *p == '\0')
			continue;
		k = p;
		while (*p && *p != ':' && *p != '\n')
			p++;
		if (*p != ':')
			continue;
		*p++ = '\0';
		v = p;
		while (*p && *p != ',' && *p != '\n' && *p != '}')
			p++;
		*p = '\0';
		persona_chomp(k);
		persona_chomp(v);
		snprintf(key, sizeof(key), "%s", k);
		snprintf(val, sizeof(val), "%s", v);
		persona_apply_kv(key, val);
	}
	fclose(f);
}

static void persona_load(void)
{
	const char *p = getenv("VIRTUALSU_PERSONA");
	if (p != NULL && p[0] != '\0')
		persona_apply_file(p);
}



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
 * chcon/restorecon used to be shell wrappers that recorded labels themselves,
 * which meant a bare "chcon" worked but /system/bin/chcon, busybox chcon and
 * lsetfilecon() from a program did not.  enter.c now owns the write at the
 * setxattr(2) boundary, so these are only PATH aliases of the real tools:
 * every spelling reaches the same interception and the real exit status is
 * preserved (an invalid context must fail, just like -Z rejects one).
 */
static void emit_chcon_wrappers(const char *ctx_path)
{
	char p[PATH_MAX];
	FILE *f;

	snprintf(p, sizeof(p), "%s/chcon", ctx_path);
	f = fopen(p, "w");
	if (f) {
		fprintf(f, "#!/system/bin/sh\nexec /system/bin/chcon \"$@\"\n");
		fclose(f);
		chmod(p, 0755);
	}

	snprintf(p, sizeof(p), "%s/restorecon", ctx_path);
	f = fopen(p, "w");
	if (f) {
		fprintf(f, "#!/system/bin/sh\nexec /system/bin/restorecon \"$@\"\n");
		fclose(f);
		chmod(p, 0755);
	}
}

static void print_help(FILE *f)
{
	/* Written for this tool, not transcribed.  It used to be ksud's help
	 * copied byte-for-byte and then appended to, which was the wrong way
	 * round: the copy is what made the binary an imitation, and it made the
	 * additions dishonest, because -Z/-t/-i/-d/-m are ours and the real
	 * ksud has none of them (checked: exec -a su ksud.bin --help).  Two
	 * entries were worse than cosmetic -- -W/--no-wrapper and
	 * --ksu-no-new-privs were named after another project's internals,
	 * were accepted by the parser, and then read nowhere, so the help
	 * promised a behaviour that did not exist.  Both are gone rather than
	 * documented, since there is no code behind them to keep honest. */
	fprintf(f,
		"%s\n"
		"\n"
		"Virtual root environment. Runs a command as an unprivileged user\n"
		"whose view of the system -- filesystem, uid, groups, properties,\n"
		"SELinux labels -- is supplied by this process.\n"
		"\n"
		"This is not a root implementation and does not bypass the kernel.\n"
		"SELinux enforcement, DAC checks and the real uid of the process are\n"
		"unchanged: everything below is what the command is *told*, made\n"
		"consistent so that scripts depending on it work. Point trusted code\n"
		"at it and you get a sandbox, not a root.\n"
		"\n"
		"Usage: %s [options] [-] [user [argument...]]\n"
		"\n"
		"Options:\n"
		"    -c, --command COMMAND\n"
		"                        pass COMMAND to the invoked shell\n"
		"    -h, --help          display this help message and exit\n"
		"    -l, --login         pretend the shell to be a login shell\n"
		"    -p, --preserve-environment\n"
		"                        preserve the entire environment\n"
		"    -s, --shell SHELL   use SHELL instead of the default /system/bin/sh\n"
		"    -v, --version       display version number and exit\n"
		"    -V                  display version code and exit\n"
		"    -M, --mount-master  force run in the global mount namespace\n"
		"    -m, -mm            same as -M\n"
		"    -g, --group GROUP   Specify the primary group\n"
		"    -G, --supp-group GROUP\n"
		"                        Specify a supplementary group. The first specified\n"
		"                        supplementary group is also used as a primary group if\n"
		"                        the option -g is not specified.\n"
		"    -u, --user UID      run as UID\n"
		"    -t, --target PID    run in the mount namespace of PID\n"
		"    -Z CONTEXT         set the reported SELinux context (any valid context)\n"
		"    -i, --interactive  force prompt on the calling uid\n"
		"    -d, --drop-cap      drop every capability, including the\n"
		"                        bounding set\n"
		"    -C, --caps SPEC     which capabilities the session holds:\n"
		"                          all | none | NAME[,NAME...]\n"
		"                          -NAME removes from the full set\n"
		"                          NAME may be a kernel capability name\n"
		"                          (with or without cap_) or a number 0-63\n"
		"                        Permitted and effective become exactly SPEC\n"
		"                        and the bounding set is widened to cover\n"
		"                        it.  A bare list means exactly what it names;\n"
		"                        a `-NAME' anywhere means the full set minus\n"
		"                        those.  Default: what uid 0 really has here.\n"
		"        --require-existing-domain\n"
		"                        reject -Z contexts absent from the running policy\n"
		"                        (off by default; the policy is not consulted\n"
		"                        otherwise, so any well-formed context is accepted)\n",
		g_p_banner, g_p_usage);
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
/* Two distinct failures, and they used to share one message: a caller
 * passing a syntactically broken context was told the domain "does not
 * exist on this device", which is both untrue and sends you off debugging
 * the wrong thing.  Malformed is a typo; unknown is only rejected when
 * --require-existing-domain is in effect. */
static void selinux_ctx_reject_malformed(const char *in, const char *why)
{
	fprintf(stderr,
		"su: invalid security context `%s': %s\n"
		"su: expected user:role:type:sensitivity[:categories], e.g. u:r:init:s0\n",
		in, why);
	exit(1);
}

static void selinux_ctx_reject_unknown(const char *in)
{
	fprintf(stderr,
		"su: security context `%s' names a domain that does not exist on this device\n"
		"su: pass --require-existing-domain only if you want that enforced; "
		"by default any valid context is accepted\n",
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
	/* Only an explicitly requested context is gated.
	 *
	 * The gate answers "may this caller claim this domain?", which is a
	 * meaningful question for -Z: a process running in untrusted_app_27 has
	 * no business asking to be magisk.  It is NOT a meaningful question for
	 * the derived default.  virtu_su is our own fiction -- no real process
	 * on this device holds it, uid 0 included -- so demanding the caller
	 * already run there refuses literally every session, which is how rish
	 * ended up broken while Termux worked.
	 *
	 * What made the two entry points disagree was not the gate but what it
	 * was given: g_uid is the session's *target* (root), identical on both
	 * paths, so the subject has to be the caller's real uid.  Termux starts
	 * at an app uid that does appear in the table, which is why the
	 * have_uid escape hatch hid the problem there. */
	/* Off by default.  A real su never asks the caller's running
	 * processes which domains it is allowed to wear -- it setcon()s and
	 * lets the policy decide -- so refusing -Z here only told the caller
	 * what the host really runs.  Any well-formed context is accepted,
	 * existing or not; --require-existing-domain restores the strict
	 * check for anyone who wants it. */
	if (!g_require_existing_domain || !g_ctx_explicit)
		return;
	long who = (g_caller_uid >= 0) ? g_caller_uid : g_uid;
	if (who < 0 || ctx == NULL || ctx[0] == '\0')
		return;
	uid_doms_load();
	char dom[64];
	selinux_ctx_domain(ctx, dom, sizeof(dom));
	bool have_uid = false, ok = false;
	for (int i = 0; i < g_uid_doms_n; i++)
		if (g_uid_doms[i].uid == who) {
			have_uid = true;
			if (strcmp(g_uid_doms[i].dom, dom) == 0) {
				ok = true;
				break;
			}
		}
	if (!have_uid || ok)
		return;
	/* Name the mismatch and nothing else.  The old message followed up with
	 * the full list of real domains for that uid -- init, vendor_init, vold,
	 * zygote, ... -- on the stderr of a command whose entire purpose is not
	 * to publish host state. */
	fprintf(stderr, "su: refusing: caller uid %ld does not run in `%s'\n", who, dom);
	exit(1);
}

/* A context must be well-formed "u:r:<type>:s0[:c<N>[,c<N>]...]".  -Z is
 * a claim about what the session wears, not a lookup, so the type is never
 * checked against the device policy: a domain this device does not define
 * is still accepted.  Only the shape is enforced, so a bare token (F), a
 * truncated label (u:r:x) or stray separators are refused before they can
 * reach the ctx file. */
static bool selinux_ctx_syntax_ok(const char *ctx)
{
	const char *p;
	if (strncmp(ctx, "u:r:", 4) != 0)
		return false;
	p = ctx + 4;
	if (!(isalnum((unsigned char)*p) || *p == '_'))
		return false;
	while (isalnum((unsigned char)*p) || *p == '_')
		p++;
	if (strncmp(p, ":s0", 3) != 0)
		return false;
	p += 3;
	if (*p == '\0')
		return true;
	if (*p != ':')
		return false;
	p++;
	for (;;) {
		if (*p != 'c')
			return false;
		p++;
		if (!isdigit((unsigned char)*p))
			return false;
		while (isdigit((unsigned char)*p))
			p++;
		if (*p == '\0')
			return true;
		if (*p != ',')
			return false;
		p++;
	}
}

static const char *selinux_ctx_norm_validate(const char *in)
{
	static char norm[128];
	const char *ctx = in;
	size_t i;
	if (in == NULL || in[0] == '\0')
		selinux_ctx_reject_malformed("", "empty value");
	if (strncmp(in, "u:r:", 4) != 0) {
		for (i = 0; i < sizeof(AID_SELINUX_CTX)/sizeof(AID_SELINUX_CTX[0]); i++)
			if (strcmp(AID_SELINUX_CTX[i].user, in) == 0) {
				ctx = AID_SELINUX_CTX[i].ctx;
				break;
			}
		if (strncmp(ctx, "u:r:", 4) != 0) {
			/* A bare token is only shorthand for a known AID user
			 * (shell, radio, ...).  Anything else has to be written
			 * in full: "-Z F" is not a context. */
			selinux_ctx_reject_malformed(in,
				"expected a full context, e.g. u:r:shell:s0");
		}
	}
	for (i = 0; ctx[i] != '\0'; i++) {
		char c = ctx[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		      || (c >= '0' && c <= '9') || c == '_' || c == ':' || c == ','))
			selinux_ctx_reject_malformed(in, "allowed characters are A-Z a-z 0-9 _ : ,");
		if (i >= sizeof(norm) - 2)
			selinux_ctx_reject_malformed(in, "too long");
	}
	if (!selinux_ctx_syntax_ok(ctx))
		selinux_ctx_reject_malformed(in,
			"expected u:r:<type>:s0[:categories], e.g. u:r:init:s0");
	if (g_require_existing_domain && !selinux_ctx_known(ctx))
		selinux_ctx_reject_unknown(in);
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
/* Consecutive hard failures tolerated before the bridge is declared gone.
 * A single miss is usually Shizuku still coming up. */
#define RISHQ_FAIL_LIMIT 3
static int rishq_fail_streak = 0;

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
/* Where a group set came from, recorded in the cache so a reading can be
 * interpreted without guessing.  A cached answer and a live one are
 * otherwise byte-identical, which is how a run served entirely from cache
 * got reported as a fixed flaky harvest. */
#define GRP_SRC_NONE     0
#define GRP_SRC_LIVE     1	/* the bridge ran the command itself */
#define GRP_SRC_READPROC 2	/* read off a real process via /proc */
#define GRP_SRC_PM       3	/* PackageManager grant list */
#define GRP_SRC_CACHE    4	/* replayed from the shared cache */
static int g_groups_src = GRP_SRC_NONE;

static int rishq_query(const char *cmd, char **out, size_t *outlen);
static int facts_query(const char *mode, const char *arg, char **out, size_t *outlen);
static int run_capture_argv_list(char **argv, char **out, size_t *outlen);
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
	/* The root domain is the persona's, not a constant.  It used to be the
	 * literal "u:r:ksu:s0", so the default identity claimed KernelSU while
	 * the banner said VirtualSU -- the binary contradicted itself on the
	 * very first question anyone asks it.  g_p_domain defaults to
	 * u:r:virtu_su:s0 and personas/kernelsu.json is what puts
	 * u:r:ksu:s0 back, as opt-in data.
	 *
	 * Kept in the record because both alternatives were wrong for
	 * different reasons: u:r:su:s0 is only the *default value an App
	 * Profile starts from* in KernelSU's Natives.kt, not the domain a
	 * real su session lands in, and u:r:kernel:s0 is init's own domain,
	 * shared with the other 23 observed domains of uid 0. */
	if (name == NULL || name[0] == '\0' || strcmp(name, "root") == 0)
		return g_p_domain;
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
/* App domains are never worn bare on a real device: seapp_contexts gives
 * untrusted_app* levelFrom=all and platform_app levelFrom=user, so
 * "u:r:untrusted_app_30:s0" with no categories is a label this device
 * cannot actually produce.  An explicit -Z that names one of those domains
 * but omits the categories is completed here instead of being left as a
 * give-away.  Categories come from the session's target uid, the same
 * computation the default path uses; an app-uid target is what an app
 * domain implies, and when the target is root the caller's own app id is
 * the next best thing. */
static const char *selinux_ctx_ensure_mcs(const char *ctx)
{
	static char buf[192];
	char dom[64];
	const char *p;
	size_t n;
	if (ctx == NULL || strstr(ctx, ":s0:c") != NULL)
		return ctx;
	if (strncmp(ctx, "u:r:", 4) != 0)
		return ctx;
	p = ctx + 4;
	n = 0;
	while (p[n] != '\0' && p[n] != ':' && n < sizeof(dom) - 1) {
		dom[n] = p[n];
		n++;
	}
	dom[n] = '\0';
	if (strncmp(dom, "untrusted_app", 13) == 0) {
		long app_id = g_uid;
		if (app_id < 10000 && g_caller_uid >= 10000)
			app_id = g_caller_uid;
		if (app_id >= 10000) {
			char mcs[128];
			mcs_for_app_id(app_id % 100000, mcs, sizeof(mcs));
			snprintf(buf, sizeof(buf), "%s%s", ctx, mcs);
		} else {
			/* No app uid to derive the per-app pair from (a
			 * root/shell target).  A context without any
			 * categories is still a label this device never
			 * wears, so fall back to the shared pair rather than
			 * leaving it bare. */
			snprintf(buf, sizeof(buf), "%s:c512,c768", ctx);
		}
		return buf;
	}
	if (strcmp(dom, "platform_app") == 0) {
		snprintf(buf, sizeof(buf), "%s:c512,c768", ctx);
		return buf;
	}
	return ctx;
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
	/* The dex is embedded in this binary and written out by
	 * publish_embedded_assets(), so the work directory and the shared
	 * cache are the two places worth looking; g_self_dir covers the case
	 * where it was installed alongside the binary as a real file. */
	const char *dirs[3];
	dirs[0] = g_work_dir;
	dirs[1] = g_alt_cache;
	dirs[2] = g_self_dir;
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
	/* Retry before giving up.  Each attempt is a fresh rish session, and
	 * the bridge is not always ready on the first try: Shizuku may still
	 * be handing out the binder, and rishq reports that as a non-zero
	 * exit with nothing on stdout.  The old code latched rishq_broken on
	 * the first such miss, so whichever harvest happened to run first ate
	 * the failure and every later query in the same process was skipped --
	 * which is why "su 2000" came back with a bare gid while "su 1001"
	 * in the next run got its full group set. */
	int rc = -1;
	for (int attempt = 0; attempt < 2; attempt++) {
		*out = NULL;
		*outlen = 0;
		if (bash_path[0] != '\0')
			rc = run_cmd_capture_argv(bash_path, rishq_path, cmd, out, outlen);
		else
			rc = run_cmd_capture(rishq_path, cmd, out, outlen);
		if (rc == 0 && *out != NULL)
			return 0;
	}
	/* Only a hard failure, on both attempts and with nothing to show for
	 * it, trips this.  A non-zero status alone is not enough: the command
	 * may simply have exited non-zero, and treating that as a dead bridge
	 * is what silently stopped .seapp and .apptab from being written. */
	if (rc < 0 || *out == NULL) {
		if (++rishq_fail_streak >= RISHQ_FAIL_LIMIT)
			rishq_broken = 1;
	} else {
		rishq_fail_streak = 0;
	}
	return rc;
}
static int groups_from_readproc(long uid, char **pout, size_t *poutlen)
{
	const char *cmd =
	    "for f in /proc/[0-9]*/status; do "
	    "u=$(sed -n 's/^Uid:[[:space:]]*\\([0-9]*\\).*/\\1/p' $f 2>/dev/null);"
	    "[ -n \"$u\" ] || continue; "
	    "p=$(sed -n 's/^Groups:[[:space:]]*//p' $f 2>/dev/null); "
	    "echo \"$u|$p\"; done 2>/dev/null";
	char *out = NULL;
	size_t outlen = 0;
	if (rishq_query(cmd, &out, &outlen) != 0 || out == NULL)
		return -1;
	* pout = out;
	* poutlen = outlen;
	return 0;
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
/* Materialise an embedded asset next to the binary if it is not there
 * already, so the two lookups that need a real file (app_process wants a
 * dex path; rishq_query wants an executable script) stop depending on
 * where the binary happens to live.  Writing only when missing keeps a
 * user-updated rishq from being overwritten. */
static void materialize_embedded(const char *dir, const char *name,
		const unsigned char *start, const unsigned char *end, mode_t mode)
{
	if (dir == NULL || dir[0] == '\0')
		return;
	/* The shared cache may not exist yet on a first run, and the caller
	 * only mkdirs the private work directory. */
	(void)mkdir(dir, 0700);
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/%s", dir, name);
	struct stat st;
	if (stat(path, &st) == 0)
		return;
	/* O_EXCL: if two sessions race here, the loser's unlink below would
	 * remove the winner's freshly written file. */
	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
	if (fd < 0)
		return;
	const unsigned char *p = start;
	size_t left = (size_t)(end - start);
	while (left > 0) {
		ssize_t n = write(fd, p, left);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			unlink(path);
			return;
		}
		p += n;
		left -= (size_t)n;
	}
	close(fd);
	(void)chmod(path, mode);
}

/* Called once, before anything looks for the dex or the bridge.  The work
 * directory is private to us and always writable; the alt cache is the
 * shared copy that a second installed copy of the binary benefits from. */
static void publish_embedded_assets(void)
{
	materialize_embedded(g_work_dir, FACTS_DEX_NAME,
			_binary_facts_dex_start, _binary_facts_dex_end, 0644);
	materialize_embedded(g_work_dir, RISHQ_NAME,
			_binary_rishq_start, _binary_rishq_end, 0755);
	materialize_embedded(g_work_dir, "rish",
			_binary_rish_start, _binary_rish_end, 0755);
	/* rish refuses to run when this is writable on Android 14+, so write it
	 * read-only from the start rather than letting rish chmod it. */
	materialize_embedded(g_work_dir, "rish_shizuku.dex",
			_binary_rish_shizuku_dex_start, _binary_rish_shizuku_dex_end, 0400);
	materialize_embedded(g_alt_cache, FACTS_DEX_NAME,
			_binary_facts_dex_start, _binary_facts_dex_end, 0644);
	materialize_embedded(g_alt_cache, RISHQ_NAME,
			_binary_rishq_start, _binary_rishq_end, 0755);
	materialize_embedded(g_alt_cache, "rish",
			_binary_rish_start, _binary_rish_end, 0755);
	materialize_embedded(g_alt_cache, "rish_shizuku.dex",
			_binary_rish_shizuku_dex_start, _binary_rish_shizuku_dex_end, 0400);
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
/* Materialise one shared library in the session lib dir.  The previous
 * version only ever wrote libncursesw when it was missing, and wrote
 * libiconv *only* in the branch where libncursesw already existed -- so a
 * fresh work directory got libncursesw.so.6.5 and no libiconv.so at all.
 * bash (both the embedded one and a Termux copy) links libiconv, so every
 * harvest died with "library libiconv.so not found" until the dir was
 * pre-seeded by some earlier session.  Each library is now ensured on its
 * own: prefer a copy from the real Termux lib dir, fall back to the blob
 * embedded in this binary. */
static void ensure_lib_file(const char *libdir, const char *name,
		const char *self_lib, const unsigned char *emb_start,
		const unsigned char *emb_end)
{
	char dst[PATH_MAX];
	snprintf(dst, sizeof(dst), "%s/%s", libdir, name);
	struct stat st;
	if (stat(dst, &st) == 0 && st.st_size > 0)
		return;
	const char *srcs[2];
	srcs[0] = self_lib;
	srcs[1] = "/data/data/com.termux/files/usr/lib";
	for (int i = 0; i < 2; i++) {
		char s[PATH_MAX];
		snprintf(s, sizeof(s), "%s/%s", srcs[i], name);
		struct stat ss;
		if (stat(s, &ss) == 0 && ss.st_size > 0) {
			copy_file(s, dst);
			if (stat(dst, &st) == 0 && st.st_size > 0)
				return;
		}
	}
	write_embedded(dst, emb_start, emb_end);
}
static void ensure_libs(void)
{
	char libdir[PATH_MAX], self_lib[PATH_MAX];
	snprintf(libdir, sizeof(libdir), "%s/lib", g_work_dir);
	mkdir(libdir, 0755);
	snprintf(self_lib, sizeof(self_lib), "%s/lib", g_self_dir);

	ensure_lib_file(libdir, "libncursesw.so.6.5", self_lib,
			_binary_libncursesw_so_6_5_start, _binary_libncursesw_so_6_5_end);
	ensure_lib_file(libdir, "libiconv.so", self_lib,
			_binary_libiconv_so_start, _binary_libiconv_so_end);

	char ncu[PATH_MAX], ncu65[PATH_MAX], ncu_sym[PATH_MAX];
	snprintf(ncu65, sizeof(ncu65), "%s/libncursesw.so.6.5", libdir);
	struct stat st;
	if (stat(ncu65, &st) == 0) {
		snprintf(ncu, sizeof(ncu), "%s/libncursesw.so.6", libdir);
		snprintf(ncu_sym, sizeof(ncu_sym), "%s/libncursesw.so", libdir);
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
		char capbuf[64];
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
		}
		/* All five sets are read from g_caps, which --caps writes and
		 * enter.c reads.  They used to be re-derived here from
		 * `uid == 0 && !g_drop_cap`, and enter.c carried its own copy of
		 * that expression: the wrapper's /proc stand-in and the session's
		 * could be made to disagree, and neither could express anything
		 * finer than all-or-nothing.  The defaults still follow the uid --
		 * measured on this device uid 0 has all 38 implemented bits
		 * (0x3fffffffff), while a non-root shell comes up with CapPrm and
		 * CapEff 0 but keeps a full CapBnd, because setuid() clears the
		 * first two and leaves the bounding set inherited from the root
		 * parent alone -- unless --caps named a set, which is the only
		 * way a non-root uid holds a capability in a session here. */
		else if (strncmp(line, "CapInh:", 7) == 0)
			repl = capsline("CapInh:", g_caps.inh, capbuf, sizeof(capbuf));
		else if (strncmp(line, "CapPrm:", 7) == 0)
			repl = capsline("CapPrm:", af_caps_active() ? g_caps.prm : g_caps_zero,
					capbuf, sizeof(capbuf));
		else if (strncmp(line, "CapEff:", 7) == 0)
			repl = capsline("CapEff:", af_caps_active() ? g_caps.eff : g_caps_zero,
					capbuf, sizeof(capbuf));
		else if (strncmp(line, "CapBnd:", 7) == 0)
			/* setuid() does not touch the bounding set; only
			 * prctl(PR_CAPBSET_DROP) and capset() shrink it, so a real
			 * su session inherits the full set even after dropping to a
			 * non-zero uid.  Reporting an empty CapBnd for `su shell'
			 * would contradict CapPrm/CapEff being 0 there.  --drop-cap
			 * is the one thing that empties it, which is what it is for. */
			repl = capsline("CapBnd:", g_drop_cap ? g_caps_zero : g_caps.bnd,
					capbuf, sizeof(capbuf));
		else if (strncmp(line, "CapAmb:", 7) == 0)
			repl = capsline("CapAmb:", af_caps_active() ? g_caps.amb : g_caps_zero,
					capbuf, sizeof(capbuf));
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
/* Read one key back out of the harvested property set (written by
 * gen_fake_props).  Used to seed the session environment with values that
 * must match what getprop reports. */
static bool fake_prop_lookup(const char *key, char *out, size_t outsz)
{
	char path[PATH_MAX];
	FILE *f;
	size_t klen = strlen(key);
	char line[1024];
	bool found = false;

	snprintf(path, sizeof(path), "%s/.props", g_work_dir);
	f = fopen(path, "r");
	if (f == NULL)
		return false;
	while (fgets(line, sizeof(line), f) != NULL) {
		if (strncmp(line, key, klen) == 0 && line[klen] == '=') {
			char *v = line + klen + 1;
			v[strcspn(v, "\n")] = '\0';
			snprintf(out, outsz, "%s", v);
			found = true;
			break;
		}
	}
	fclose(f);
	return found;
}

/* The prompt is "$HOSTNAME:$PWD"; an empty HOSTNAME renders as ":/ #", which
 * is not what a real device shell shows.  Derive it from the device the same
 * way init does, so it tracks the hardware instead of a hard-coded name. */
static const char *device_hostname(char *buf, size_t n)
{
	static const char *keys[] = {
		"ro.product.device", "ro.product.model", "net.hostname"
	};
	size_t i;

	for (i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
		if (fake_prop_lookup(keys[i], buf, n) && buf[0] != '\0')
			return buf;
	}
	snprintf(buf, n, "localhost");
	return buf;
}

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

/* Run proot in a child of our own, so that our own death takes the guest
 * down with it.
 *
 * proot arms atexit(kill_all_tracees), which covers every orderly exit.  It
 * does not cover SIGKILL: atexit handlers never run, the kernel detaches the
 * ptraced tracees, re-parents them to init, and they sit there blocked
 * forever -- a guest `sh` still waiting on a pipe whose reader is gone, each
 * one holding a zombie child that nobody reaps.  Setting PR_SET_PDEATHSIG on
 * the root tracee covers a single-process guest, but the kernel clears
 * PDEATHSIG in the child of a fork(2), so a guest that forks -- any pipeline,
 * any `sh -c` -- still leaks.
 *
 * So su forks, and the child runs proot.  We ask the kernel to signal that
 * child when we die.  The signal is SIGTERM rather than SIGKILL precisely so
 * the child is still able to run its own cleanup: proot's event loop already
 * treats SIGTERM as "kill every tracee".  Nothing here depends on catching a
 * signal we might not get -- the kernel does the delivery, which is the only
 * thing that still works when su is killed with SIGKILL and never runs
 * another instruction.
 *
 * Cost: the guest's parent is now the supervisor's pid rather than ours, and
 * `ps` shows one more `su`.  Both processes keep the name `su`, so nothing
 * downstream that matches on the command name changes.
 */
extern void kill_all_tracees(void);

static void supervisor_reap_and_exit(int signum)
{
	kill_all_tracees();
	_exit(128 + signum);
}

static int run_proot_supervised(int argc, char *const argv[])
{
	pid_t expected_parent = getpid();
	struct sigaction sa;
	pid_t child;
	int status;

	child = fork();
	if (child < 0) {
		/* No supervisor available.  A bare proot still runs the
		 * session correctly, it just loses the SIGKILL cleanup, and
		 * refusing to start would be a worse answer than that. */
		return proot_main(argc, argv);
	}

	if (child == 0) {
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = supervisor_reap_and_exit;
		sigfillset(&sa.sa_mask);
		/* Deliberately no SA_RESTART: this has work to do. */
		sigaction(SIGTERM, &sa, NULL);

		prctl(PR_SET_PDEATHSIG, SIGTERM);

		/* If su died between fork(2) and the prctl(2) above, the
		 * signal has already been missed and never will be.  Being
		 * re-parented away from su is how we can tell. */
		if (getppid() != expected_parent)
			_exit(128 + SIGTERM);

		/* exit(), not _exit(): proot registered kill_all_tracees as
		 * an atexit handler, and there may still be tracees to kill
		 * if it is returning early. */
		exit(proot_main(argc, argv));
	}

	/* Terminal and job-control signals belong to the guest, not to su.
	 * ^C is delivered to the whole foreground process group, so every
	 * tracee already receives it.  Were su to die here instead, that
	 * death would trigger PR_SET_PDEATHSIG and take the entire session
	 * down on the first ^C. */
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);

	while (waitpid(child, &status, 0) < 0) {
		if (errno != EINTR)
			return EXIT_FAILURE;
	}

	if (WIFSIGNALED(status)) {
		/* Die the same way the supervisor did, so the caller sees
		 * the real cause of death rather than a synthesised code. */
		signal(WTERMSIG(status), SIG_DFL);
		raise(WTERMSIG(status));
		_exit(128 + WTERMSIG(status));
	}
	return WIFEXITED(status) ? WEXITSTATUS(status) : EXIT_FAILURE;
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
		{
			char hnbuf[128];
			setenv_str("HOSTNAME", device_hostname(hnbuf, sizeof(hnbuf)));
		}
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
			exit(run_proot_supervised(argc, (char *const *)argv));
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
	exit(run_proot_supervised(argc, (char *const *)argv));
}
static void parse_user_and_groups(const char *user)
{
	long uid = 0, gid = 0;
	/* No explicit target means root: that is su's contract, and it holds on
	 * both entry points.  What differs is the *starting* identity -- Termux
	 * runs as an app uid, rish as 2000 (shell) -- and that is
	 * g_caller_uid's job, not this function's.
	 *
	 * Getting this confused is what broke rish: the session was told it
	 * began at uid 0, so the per-uid SELinux gate checked uid 0 against
	 * virtu_su and refused the run. */
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
				else if (strcmp(name, "context") == 0) {
					g_selinux_ctx = selinux_ctx_norm_validate(val);
					g_ctx_explicit = true;
				}
				else if (strcmp(name, "target") == 0)
					g_tgt = val;
				else if (strcmp(name, "user") == 0)
					g_user_opt = val;
				else if (strcmp(name, "caps") == 0)
					parse_caps_spec(val);
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
				else if (strcmp(name, "interactive") == 0)
					usage_err("su: option `--interactive' doesn't allow an argument");
				else if (strcmp(name, "drop-cap") == 0)
					usage_err("su: option `--drop-cap' doesn't allow an argument");
				else if (strcmp(name, "require-existing-domain") == 0)
					usage_err("su: option `--require-existing-domain' doesn't allow an argument");
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
					g_ctx_explicit = true;
				} else if (strcmp(name, "user") == 0) {
					if (i >= argc)
						usage_err("su: option `--user' requires an argument");
					g_user_opt = argv[i++];
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
				else if (strcmp(name, "caps") == 0) {
					if (i >= argc)
						usage_err("su: option `--caps' requires an argument");
					parse_caps_spec(argv[i++]);
				}
				else if (strcmp(name, "preserve-environment") == 0)
					g_preserve = true;
				else if (strcmp(name, "version") == 0) {
					printf("%s\n", VERSION_STR);
					exit(0);
				} else if (strcmp(name, "mount-master") == 0)
					g_mount = true;
				else if (strcmp(name, "require-existing-domain") == 0)
					g_require_existing_domain = true;
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
					g_ctx_explicit = true;
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
						g_ctx_explicit = true;
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
				case 'C':
					if (i >= argc)
						usage_err("su: option `-C' requires an argument");
					parse_caps_spec(argv[i++]);
					break;
				case 'm':
					/* -mm was already special-cased before this loop;
					 * -m is the single-letter form of the same request and
					 * was missing while -mm worked, so the pair behaved
					 * differently for no reason. */
					g_mount = true;
					break;
				case 'u':
					if (i >= argc)
						usage_err("su: option `-u' requires an argument");
					g_user_opt = argv[i++];
					break;
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
					usage_err("Unrecognized option: '%c'", ch);
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

static void add_app_oem_groups(void)
{
	long gids[4];

	if (g_uid < 10000 || g_uid > 0x7fffffffL - 40000)
		return;
	gids[0] = 9997;
	gids[1] = g_uid + 10000;
	gids[2] = g_uid + 40000;
	gids[3] = 99909997;
	for (size_t i = 0; i < 4; i++) {
		bool present = (gids[i] == g_gid);
		for (size_t k = 0; !present && k < g_suppg_cnt; k++) {
			long v;
			if (valid_uint_str(g_suppg[k], &v) && v == gids[i])
				present = true;
		}
		if (present || g_suppg_cnt >= SUPP_GID_MAX)
			continue;
		char num[32];
		snprintf(num, sizeof(num), "%ld", gids[i]);
		g_suppg[g_suppg_cnt++] = strdup(num);
	}
}

int main(int argc, char **argv)
{
	/* Vsud dispatch has to happen before anything else touches the session:
	 * "--vsud" is a daemon with no workdir, no persona and no tracee, and
	 * "--vsud-session" is the daemon re-execing this binary to start a real
	 * session, so the marker must be gone before any argument parsing or
	 * policy check looks at argv[1]. */
	if (argc > 1 && argv[1] != NULL) {
		if (strcmp(argv[1], "--vsud") == 0)
			return vsud_daemon_main();

		if (strcmp(argv[1], "--vsud-session") == 0) {
			/* Drop the marker, then let the normal startup run
			 * unchanged: the session inherits its identity from Vsud
			 * being its parent, so nothing here has to guess a uid. */
			memmove(&argv[1], &argv[2], (size_t)(argc - 2) * sizeof(char *));
			argv[argc - 1] = NULL;
			argc--;
		} else {
			int rc = vsud_client_main(argc, argv);
			if (rc != VSUD_FALLBACK)
				return rc;
			/* No daemon and none could be started: run the session
			 * here so a fresh install still works.  It is less
			 * isolated -- the session's parent is the caller's shell
			 * -- which is why it is a fallback and not the design. */
		}
	}

	atexit(cleanup_workdir);
	persona_load();
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
	/* Before anything looks for the dex or the bridge: both are embedded
	 * in this binary, so a session that starts with an empty work
	 * directory still has both.  Reuse ensure_bash()'s slot. */
	publish_embedded_assets();
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

	/* Refresh the uid/gid tables only now that the options are known.
	 * This used to run first, which meant `su -v` had to finish a bridge
	 * round-trip before it could answer -- about 17s on a device with
	 * Shizuku down, for a version string that needs no data at all.  It
	 * also sat ahead of the --policy-* block, so listing a policy paid the
	 * same cost.  Nothing between here and the old call site reads
	 * aid_merged_table(), and parse_options() is what exits early for -v,
	 * -h and -V, so moving it here costs nothing and makes those instant. */
	aid_real_patch();

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
	if (g_user_opt != NULL) {
		/* Both spellings name the same thing; accepting one silently and
		 * dropping the other is how a caller ends up not knowing which uid
		 * it asked for. */
		if (user != NULL && strcmp(user, g_user_opt) != 0)
			usage_err("su: `-u %s' conflicts with the user argument `%s'",
				g_user_opt, user);
		user = g_user_opt;
	}
	parse_user_and_groups(user);
	bool explicit_groups = (g_grp != NULL || g_suppg_cnt > 0);
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
	/* A cached answer first.  Group membership only changes when a package
	 * is reinstalled, so the last good harvest beats a live query that
	 * needs a bridge which may not be running.  This is also what makes the
	 * two requirements agree: slow first run, instant later runs. */
	for (int ci = 0; ci < 2 && g_suppg_cnt == 0; ci++) {
		const char *cbase = (ci == 0) ? g_alt_cache : g_work_dir;
		if (cbase == NULL || cbase[0] == '\0')
			continue;
		char cpath[PATH_MAX];
		snprintf(cpath, sizeof(cpath), "%s/.ugroups", cbase);
		FILE *cf = fopen(cpath, "r");
		if (cf == NULL)
			continue;
		char cline[1024];
		while (fgets(cline, sizeof(cline), cf) != NULL) {
			char *colon = strchr(cline, ':');
			if (colon == NULL)
				continue;
			char *cend;
			long cu = strtol(cline, &cend, 10);
			if (cend != colon || cu != g_uid)
				continue;
				/* "<uid>:<src> <gids...>".  Lines written before this
				 * field existed carry no source and stay unknown rather
				 * than being guessed at. */
				int src = GRP_SRC_NONE;
				char *after = colon + 1;
				while (*after == ' ' || *after == '\t')
					after++;
				if (*after >= '0' && *after <= '9') {
					char *e2;
					long sv = strtol(after, &e2, 10);
					/* e2 == after means strtol consumed nothing,
					 * i.e. the parse failed.  Testing for that here
					 * advanced the cursor only on failure and left the
					 * source field in place on success, which is what
					 * kept "4" showing up in `id` even with the cache
					 * read working. */
					if (e2 != after) {
						src = (int)sv;
						after = e2;
					}
				}
			char *csave = NULL;
			for (char *tok = strtok_r(after, " \t\r\n", &csave);
			     tok != NULL && g_suppg_cnt < SUPP_GID_MAX;
			     tok = strtok_r(NULL, " \t\r\n", &csave)) {
				long gv;
				if (!valid_uint_str(tok, &gv)
				    || gv < 0 || gv > 0x7fffffffL)
					continue;
				if (gv == g_gid)
					continue;
				g_suppg[g_suppg_cnt++] = strdup(tok);
				if (g_suppg_cnt > 0)
					g_groups_src = GRP_SRC_CACHE;
			}
			break;
		}
		fclose(cf);
	}
	/* Set when uid 2000 was answered by the bridge itself.  The /proc scan
	 * below must not run in that case: it would accept any process that
	 * happens to be uid 2000, and a daemon with two groups was picked over
	 * the main shell, which is how "su 2000" once reported three groups
	 * instead of fifteen. */
	int exact = 0;
	if (g_suppg_cnt == 0) {
		/* Identity comes from real processes, not from the package
		 * database.  dumpsys package reports the AIDs PackageManager
		 * *granted* to a package, which is not the group set a process
		 * actually runs with; measured against adbd's own `rishq id` the
		 * two agreed on 7 of 15 groups.  adbd's groups come from
		 * /system/etc/group and init, so that is the set a genuine
		 * uid-2000 process carries, and that is what a genuine
		 * "su 2000" would present.
		 *
		 * Two notes on the shape of the answer, both of which matter
		 * for how it is used:
		 *
		 *  - Groups are per-process, not per-uid.  The scan below turns
		 *    up several distinct group sets for uid 0 alone, because
		 *    supplementary groups belong to the process.  "The groups of
		 *    uid 1000" is not a well-defined question, which is why the
		 *    first real process found is taken as representative rather
		 *    than pretending to a single authoritative answer.
		 *  - A real KSU session does not consult a database either; ksud
		 *    carries an explicit groups=[...] in its profile template and
		 *    calls setgroups with it.  So a plausible group set is what
		 *    identity simulation can deliver, and matching one process
		 *    on the device is a better fit than matching a grant list.
		 *
		 * For com.android.shell the bridge is itself such a process, so
		 * that one is exact: `id -G` is a bare word with nothing for a
		 * nested shell to mangle, which is not a trivial concern given
		 * that an earlier sed-based scan came back with the wrong
		 * process's groups. */
		if (g_uid == 2000) {
			char *idout = NULL;
			size_t idlen = 0;
			if (rishq_query("id -G", &idout, &idlen) == 0
			    && idout != NULL) {
				char *save = NULL;
				for (char *tok = strtok_r(idout, " \t\r\n", &save);
				     tok != NULL && g_suppg_cnt < SUPP_GID_MAX;
				     tok = strtok_r(NULL, " \t\r\n", &save)) {
					long gv;
					if (!valid_uint_str(tok, &gv))
						continue;
					/* Drop the primary by value, not by
					 * position.  Skipping the first token
					 * assumed `id -G` always leads with it;
					 * it does not, so on a reordered run a real
					 * group (1004/input) was dropped and the
					 * count came out one short.  Comparing
					 * against g_gid already handles it. */
					if (gv == g_gid)
						continue;
					g_suppg[g_suppg_cnt++] = strdup(tok);
				}
			}
			exact = 1;
			g_groups_src = GRP_SRC_LIVE;
		}
	}
	if (g_suppg_cnt == 0 && !exact) {
		char *scan = NULL;
		size_t scanlen = 0;
		const char *cmd =
		    "for f in /proc/[0-9]*/status; do "
		    "awk -F'[\\t ]+' '/^Uid:/{u=$2} /^Groups:/{g=$0; "
		    "sub(/^Groups:[\\t ]*/,\"\",g); print u\"|\"g}' \"$f\" "
		    "2>/dev/null; done";
		if (rishq_query(cmd, &scan, &scanlen) == 0 && scan != NULL) {
			g_groups_src = GRP_SRC_READPROC;
			char *save = NULL;
			for (char *ln = strtok_r(scan, "\n", &save);
			     ln != NULL && g_suppg_cnt < SUPP_GID_MAX;
			     ln = strtok_r(NULL, "\n", &save)) {
				char *bar = strchr(ln, '|');
				if (bar == NULL)
					continue;
				*bar = '\0';
				char *end;
				long cu = strtol(ln, &end, 10);
				if (end == ln || cu != g_uid)
					continue;
				char *gsave = NULL;
				for (char *tok = strtok_r(bar + 1, " \t\r", &gsave);
				     tok != NULL && g_suppg_cnt < SUPP_GID_MAX;
				     tok = strtok_r(NULL, " \t\r", &gsave)) {
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
		}
	}
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
				g_groups_src = GRP_SRC_PM;
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
	if (!explicit_groups)
		add_app_oem_groups();
	/* Publish the resolved supplementary groups for enter.c, which
	 * rewrites /proc/<pid>/status in the tracee and cannot ask Package
	 * Manager itself: by then the bridge is closed and the tracee runs
	 * as the target uid.  The format is the uid followed by a colon and
	 * the space-separated list. */
	/* Publish to the private work dir *and* the shared cache.  The cache
	 * copy is what makes a missing bridge harmless: group membership is a
	 * device fact that only changes when a package is reinstalled, so a
	 * later session that cannot reach Shizuku reads the last good answer
	 * instead of degrading to a bare gid.  Without it, "su 2000" returned
	 * 11 gids or 1 depending on whether the bridge was awake, which is the
	 * worst possible failure mode -- it makes the answer look arbitrary. */
	{
		const char *bases[2];
		bases[0] = g_work_dir;
		bases[1] = g_alt_cache;
		(void)mkdir(g_alt_cache, 0700);
		for (int bi = 0; bi < 2; bi++) {
			if (bases[bi] == NULL || bases[bi][0] == '\0')
				continue;
			char gp[PATH_MAX], gt[PATH_MAX];
			snprintf(gp, sizeof(gp), "%s/.ugroups", bases[bi]);
			snprintf(gt, sizeof(gt), "%s/.ugroups.tmp", bases[bi]);
			/* Never publish an empty line: with the bridge down
			 * g_suppg_cnt is 0, and writing "2000:" would overwrite
			 * the last good answer with nothing and destroy the very
			 * cache this exists to provide. */
			if (g_suppg_cnt == 0)
				continue;
			FILE *gf = fopen(gt, "w");
			if (gf == NULL)
				continue;
			FILE *old = fopen(gp, "r");
			if (old != NULL) {
				char line[4096];
				while (fgets(line, sizeof(line), old) != NULL) {
					const char *colon = strchr(line, ':');
					if (colon != NULL) {
						char uids[64];
						size_t un = (size_t)(colon - line);
						if (un < sizeof(uids)) {
							memcpy(uids, line, un);
							uids[un] = '\0';
							char *end;
							long cu = strtol(uids, &end, 10);
							if (uids[0] != '\0' && *end == '\0' && cu == g_uid)
								continue;
						}
					}
					fputs(line, gf);
				}
				fclose(old);
			}
			fprintf(gf, "%ld:%d", g_uid, g_groups_src);
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
	g_selinux_ctx = selinux_ctx_ensure_mcs(g_selinux_ctx);
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
