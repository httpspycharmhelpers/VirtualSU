/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2015 STMicroelectronics
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include <stdio.h>   /* snprintf(3), */
#include <string.h>  /* strcmp(3), */
#include <stdlib.h>  /* atoi(3), strtol(3), */
#include <errno.h>   /* E*, */
#include <assert.h>  /* assert(3), */
#include <unistd.h>  /* access(2), */
#include <fcntl.h>   /* open(2), O_RDONLY */
#include <sys/types.h> /* pid_t, getpid(2) */
#include <stdbool.h> /* bool */

#include "path/proc.h"

/* ------------------------------------------------------------------ */
/* Which pids the fake identity covers                                 */
/* ------------------------------------------------------------------ */
/*
 * The rule, and why it is this rule
 * ---------------------------------
 * The session has exactly one privileged ancestor: Vsud.  Everything from
 * Vsud down -- the worker, the su wrapper, proot, and every tracee -- wears
 * virtu_su, because on a real rooted device that whole subtree inherits the
 * daemon's context.  Every other pid on the device keeps its own real label.
 *
 * That is not a cosmetic choice.  Forging the entire table (every pid reads
 * virtu_su) is the giveaway: no genuine root implementation can make an
 * unrelated app look like it is running inside the root domain, so a
 * *uniform* table is strictly less believable than a correct boundary.  A
 * checker comparing the session's view against a known-good rooted device
 * sees the difference immediately.
 *
 * It is also the only version that survives the obvious probe.  The caller
 * that typed `su` is NOT an ancestor here -- Vsud double-forks and re-parents
 * to init, so the guest's view of the caller is a sibling subtree.  A caller
 * that can see that its own process still reads untrusted_app_* from inside
 * the root shell has learned the whole thing is a trick.
 *
 * Implementation: climb from the given pid to init and stop at Vsud.  This
 * needs no registry and no communication with the daemon, so it keeps working
 * in the paths where a session is spawned directly (VSUD_NO_DAEMON), where
 * the wrapper su itself is the top of the tree.
 */

#define VSUD_COMM "vsud"

/* Read a pid's PPID out of /proc/<pid>/stat.  The comm field can contain
 * spaces and parentheses, so the scan starts after the *last* ')' rather
 * than tokenising from the front. */
static pid_t proc_ppid(pid_t pid)
{
	char path[64];
	char buf[1024];
	char *p, *end;
	ssize_t n;
	int fd;
	pid_t ppid = 0;

	if (pid <= 0)
		return 0;
	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return 0;
	buf[n] = '\0';

	p = strrchr(buf, ')');
	if (p == NULL)
		return 0;
	p++;				/* step past ") " */

	/* After comm come: state ppid pgrp session ...  strtol cannot be used
	 * on the state field (it is a character), so skip one token, then read
	 * the numeric one. */
	while (*p == ' ')
		p++;
	if (*p == '\0')
		return 0;
	p++;				/* skip the state character */
	while (*p == ' ')
		p++;
	if (*p == '\0')
		return 0;

	ppid = (pid_t) strtol(p, &end, 10);
	if (end == p || ppid < 0)
		return 0;
	return ppid;
}

static bool proc_comm_is(pid_t pid, const char *want)
{
	char path[64];
	char comm[64];
	char *nl;
	ssize_t n;
	int fd;
	bool match;

	snprintf(path, sizeof(path), "/proc/%d/comm", pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;
	n = read(fd, comm, sizeof(comm) - 1);
	close(fd);
	if (n <= 0)
		return false;
	comm[n] = '\0';
	nl = strchr(comm, '\n');
	if (nl != NULL)
		*nl = '\0';
	match = (strcmp(comm, want) == 0);
	return match;
}

/* True when @pid sits inside the privileged subtree, i.e. at or below this
 * process.  Walking to init and stopping early on a hit keeps the cost
 * proportional to the subtree height, and -- more to the point -- it makes
 * the fallback case (VSUD_NO_DAEMON, no Vsud anywhere) behave correctly
 * without a second code path: there the climb reaches this very process,
 * which is the top of the tree in that mode.
 *
 * Self always qualifies, since the interception runs inside the subtree by
 * construction and self is exactly what getcon()/id -Z report. */
bool afakesu_pid_in_session(pid_t pid)
{
	const pid_t self = (pid_t) getpid();
	bool passed_self = false;
	int depth;

	if (pid <= 0)
		return false;
	if (pid == self)
		return true;

	for (depth = 0; depth < 64; depth++) {
		if (proc_comm_is(pid, VSUD_COMM))
			return true;
		pid = proc_ppid(pid);
		if (pid <= 0)
			break;
		/* Do NOT stop here.  Reaching self only proves the climb
		 * entered our own tree; Vsud still sits above it, and stopping
		 * at that point is what made every guest tracee fall through
		 * to its real untrusted_app label.  Record it and keep going,
		 * so the no-daemon fallback (no Vsud anywhere above) still
		 * returns true via passed_self, while the normal daemon case
		 * finds the real Vsud further up. */
		if (pid == self)
			passed_self = true;
		if (pid == 1)
			break;
	}
	return passed_self;
}

/* True when @path names a /proc/<pid> entry that belongs to a process
 * outside this session.  The owner of /proc/<pid> is that process's real
 * uid, so the fake_id0 uid rewrite has to leave those entries alone:
 * faking them made toybox "ps" print the session identity in its USER
 * column for every process on the device, not just the ones we own.  Only
 * the privileged subtree is ours to wear. */
bool afakesu_proc_dir_foreign(const char *path)
{
	const char *p;
	char *end;
	long pid;

	if (path == NULL || strncmp(path, "/proc/", 6) != 0)
		return false;
	p = path + 6;
	if (*p < '0' || *p > '9')
		return false;
	errno = 0;
	pid = strtol(p, &end, 10);
	if (errno != 0 || end == p || (*end != '\0' && *end != '/'))
		return false;
	if (pid <= 0)
		return false;
	return !afakesu_pid_in_session((pid_t) pid);
}
#include "tracee/tracee.h"
#include "path/path.h"
#include "path/binding.h"

/* AFAKESU fusion: the fake /proc files (ctx, status) live in the su
 * wrapper's workdir; redirect tracee reads of /proc/self/{attr/current,
 * status} and /proc/thread-self/... onto those plain files. */
extern char g_work_dir[PATH_MAX];
extern const char *g_selinux_ctx;

static bool attr_is_selinux(const char *name)
{
	static const char *names[] = { "current", "prev", "exec", "fscreate",
				       "keycreate", "sockcreate" };
	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
		if (strcmp(name, names[i]) == 0)
			return true;
	return false;
}

/**
 * This function emulates the @result of readlink("@base/@component")
 * with respect to @tracee, where @base belongs to "/proc" (according
 * to @comparison).  This function returns -errno on error, an enum
 * @action otherwise (c.f. above).
 *
 * Unlike readlink(), this function includes the nul terminating byte
 * to @result.
 */
Action readlink_proc(const Tracee *tracee, char result[PATH_MAX],
			const char base[PATH_MAX], const char component[NAME_MAX],
			Comparison comparison)
{
	const Tracee *known_tracee;
	char proc_path[64]; /* 64 > sizeof("/proc//fd/") + 2 * sizeof(#ULONG_MAX) */
	int status;
	pid_t pid;

	/* TODO: Following assertion fails on some devices
	 * https://github.com/termux/termux-packages/issues/1679
	 */
	//assert(comparison == compare_paths("/proc", base));

	/* Remember: comparison = compare_paths("/proc", base)  */
	switch (comparison) {
	case PATHS_ARE_EQUAL:
		/* Substitute "/proc/self" and "/proc/thread-self" with
		 * "/proc/<PID>", so every proc pseudo-file (attr/current,
		 * status, ...) is serviced by the session stand-ins instead
		 * of the host proc.  "thread-self" is what libselinux
		 * getcon()/id actually reads.  */
		if (strcmp(component, "self") == 0
		 || strcmp(component, "thread-self") == 0) {
			status = snprintf(result, PATH_MAX, "/proc/%d", tracee->pid);
			if (status < 0 || status >= PATH_MAX)
				return -EPERM;
			return CANONICALIZE;
		}
		return DEFAULT;

	case PATH1_IS_PREFIX:
		/* Handle "/proc/<PID>" below, where <PID> is process
		 * monitored by PRoot.  */
		break;

	default:
		return DEFAULT;
	}

	/* When a binding maps /proc/self/fd to a guest path (e.g.
	 * -b /proc/self/fd:/dev/fd), canonicalize() resolves the
	 * bound path's components and ends up calling readlink_proc
	 * with base="/proc/self/fd".  atoi("self/fd") == 0 would
	 * cause an early DEFAULT return and fall through to a real
	 * readlink(2) on /proc/self/fd/N in proot's own namespace,
	 * failing with ENOENT.  Normalize /proc/self/... to
	 * /proc/<tracee_pid>/... so the fd-path handling below is
	 * reached and DONT_CANONICALIZE is returned instead.  */
	char normalized_base[PATH_MAX];
	if (strncmp(base + strlen("/proc/"), "self", 4) == 0
	    && (base[strlen("/proc/self")] == '/' || base[strlen("/proc/self")] == '\0')) {
		status = snprintf(normalized_base, sizeof(normalized_base),
				  "/proc/%d%s", tracee->pid,
				  base + strlen("/proc/self"));
		if (status < 0 || (size_t) status >= sizeof(normalized_base))
			return -EPERM;
		base = normalized_base;
	}

	pid = atoi(base + strlen("/proc/"));
	if (pid == 0)
		return DEFAULT;

	/* Handle links in "/proc/<PID>/".  */
	status = snprintf(proc_path, sizeof(proc_path), "/proc/%d", pid);
	if (status < 0 || (size_t) status >= sizeof(proc_path))
		return -EPERM;

	comparison = compare_paths(proc_path, base);
	switch (comparison) {
	case PATHS_ARE_EQUAL:
		known_tracee = get_tracee(tracee, pid, false);
		if (known_tracee == NULL) {
			/* Other processes' exe is unreadable to the faked
			 * session (real EACCES); a root-like domain should
			 * succeed.  Emulate the canonical init binary for
			 * PID 1, the one every root-checker samples. */
			if (pid == 1 && strcmp(component, "exe") == 0) {
				static const char init_exe[] = "/system/bin/init";
				strncpy(result, init_exe, sizeof(init_exe));
				return CANONICALIZE;
			}
			return DEFAULT;
		}

#define SUBSTITUTE(name, string)				\
		do {						\
			if (strcmp(component, #name) != 0)	\
				break;				\
								\
			status = strlen(string);		\
			if (status >= PATH_MAX)			\
				return -EPERM;			\
								\
			strncpy(result, string, status + 1);	\
			return CANONICALIZE;			\
		} while (0)

		/* Substitute link "/proc/<PID>/???" with the content
		 * of tracee->???.  */
		if (strcmp(component, "exe") == 0) {
			/* The whole session is a fake root domain: every owned
			 * process answers the stock shell as its executable, so
			 * the real termux/com.termux binaries can never surface. */
			const char *exe = "/system/bin/sh";
			status = strlen(exe);
			if (status >= PATH_MAX)
				return -EPERM;
			strncpy(result, exe, status + 1);
			return CANONICALIZE;
		}
		SUBSTITUTE(cwd, known_tracee->fs->cwd);
		SUBSTITUTE(root, get_root(known_tracee));
#undef SUBSTITUTE
		if (attr_is_selinux(component)
		    && g_selinux_ctx != NULL && g_selinux_ctx[0] != '\0') {
			char ctx_path[PATH_MAX];
			int s = snprintf(ctx_path, sizeof(ctx_path), "%s/ctx", g_work_dir);
			if (s > 0 && (size_t) s < sizeof(ctx_path)
			    && access(ctx_path, F_OK) == 0) {
				strncpy(result, ctx_path, PATH_MAX);
				return CANONICALIZE;
			}
		}
		if (strcmp(component, "status") == 0) {
			char st_path[PATH_MAX];
			int s = snprintf(st_path, sizeof(st_path), "%s/status", g_work_dir);
			if (s > 0 && (size_t) s < sizeof(st_path)
			    && access(st_path, F_OK) == 0) {
				strncpy(result, st_path, PATH_MAX);
				return CANONICALIZE;
			}
		}
		/* /proc/<pid>/cmdline must read as "/system/bin/sh -c ...",
		 * not as the Termux bash path (see gen_fake_cmdline). */
		if (strcmp(component, "cmdline") == 0) {
			char cl_path[PATH_MAX];
			int s = snprintf(cl_path, sizeof(cl_path), "%s/cmdline", g_work_dir);
			if (s > 0 && (size_t) s < sizeof(cl_path)
			    && access(cl_path, F_OK) == 0) {
				strncpy(result, cl_path, PATH_MAX);
				return CANONICALIZE;
			}
		}
		/* /proc/<pid>/maps: scrubbed copy (prooted-*, Termux paths
		 * replaced), regenerated on open (afakesu_regen_maps_for_pid). */
		if (strcmp(component, "maps") == 0) {
			char mp_path[PATH_MAX];
			int s = snprintf(mp_path, sizeof(mp_path), "%s/maps", g_work_dir);
			if (s > 0 && (size_t) s < sizeof(mp_path)
			    && access(mp_path, F_OK) == 0) {
				strncpy(result, mp_path, PATH_MAX);
				return CANONICALIZE;
			}
		}
		return DEFAULT;

	case PATH1_IS_PREFIX:
		/* Handle "/proc/<PID>/attr/current":  reached with
		 * base="/proc/<PID>/attr", component="current".  Also
		 * "/proc/<PID>/task/<TID>/status" (thread-self) and
		 * any deeper "<PID>/.../status": regular files, so the
		 * caller (canonicalize in canon.c) only consults this
		 * after the AFAKESU hook re-directs every non-link
		 * component under /proc.  */
		known_tracee = get_tracee(tracee, pid, false);

		/* SELinux interception, scoped to the privileged subtree.
		 * See afakesu_pid_in_session() above: Vsud and everything
		 * below it read virtu_su, the rest of the device keeps its
		 * real context.  This is the only thing that closes the label
		 * leak -- "ps -A -o LABEL" and /proc/<pid>/status do not ask
		 * for an xattr, they open this file and read the kernel's live
		 * context, so a tracee-only gate left every ancestor wearing
		 * untrusted_app_27, while forging the whole table would have
		 * been just as fake in the other direction. */
		if (g_selinux_ctx != NULL && g_selinux_ctx[0] != '\0'
		    && attr_is_selinux(component)
		    && afakesu_pid_in_session(pid)) {
			char *slash = strrchr(base, '/');
			if (slash != NULL && strcmp(slash, "/attr") == 0) {
				char ctx_path[PATH_MAX];
				int s = snprintf(ctx_path, sizeof(ctx_path), "%s/ctx", g_work_dir);
				if (s > 0 && (size_t) s < sizeof(ctx_path)
				    && access(ctx_path, F_OK) == 0) {
					strncpy(result, ctx_path, PATH_MAX);
					return CANONICALIZE;
				}
			}
		}
		if (known_tracee != NULL && strcmp(component, "status") == 0) {
			char st_path[PATH_MAX];
			int s = snprintf(st_path, sizeof(st_path), "%s/status", g_work_dir);
			if (s > 0 && (size_t) s < sizeof(st_path)
			    && access(st_path, F_OK) == 0) {
				strncpy(result, st_path, PATH_MAX);
				return CANONICALIZE;
			}
		}
		/* init's exe symlink is not readable by an untrusted domain;
		 * a member of the fake-root session answers it like init would
		 * (reached with base="/proc/1", component="/exe"). */
		if (pid == 1 && strcmp(component, "exe") == 0) {
			if (getenv("THJ_PDBG"))
				fprintf(stderr, "THJP p1exe base=%s comp=%s\n", base, component);
			char exe1[PATH_MAX];
			int s = snprintf(exe1, sizeof(exe1), "%s/.exe1", g_work_dir);
			if (s > 0 && (size_t) s < sizeof(exe1)
			    && access(exe1, F_OK) == 0) {
				strncpy(result, exe1, PATH_MAX);
				return CANONICALIZE;
			}
		}
		break;

	default:
		return DEFAULT;
	}

	/* Handle links in "/proc/<PID>/fd/".  */
	status = snprintf(proc_path, sizeof(proc_path), "/proc/%d/fd", pid);
	if (status < 0 || (size_t) status >= sizeof(proc_path))
		return -EPERM;

	comparison = compare_paths(proc_path, base);
	switch (comparison) {
		char *end_ptr;

	case PATHS_ARE_EQUAL:
		/* Sanity check: a number is expected.  */
		errno = 0;
		(void) strtol(component, &end_ptr, 10);
		if (errno != 0 || end_ptr == component)
			return -EPERM;

		/* Don't dereference "/proc/<PID>/fd/???" now: they
		 * can point to anonymous pipe, socket, ...  otherwise
		 * they point to a path already canonicalized by the
		 * kernel.
		 *
		 * Note they are still correctly detranslated in
		 * syscall/exit.c if a monitored process uses
		 * readlink() against any of them.  */
		status = snprintf(result, PATH_MAX, "%s/%s", base, component);
		if (status < 0 || status >= PATH_MAX)
			return -EPERM;

		return DONT_CANONICALIZE;

	default:
		break;
	}

	return DEFAULT;
}

/**
 * This function emulates the @result of readlink("@referer") with
 * respect to @tracee, where @referer is a strict subpath of "/proc".
 * This function returns -errno if an error occured, the length of
 * @result if the readlink was emulated, 0 otherwise.
 *
 * Unlike readlink(), this function includes the nul terminating byte
 * to @result (but this byte is not counted in the returned value).
 */
ssize_t readlink_proc2(const Tracee *tracee, char result[PATH_MAX], const char referer[PATH_MAX])
{
	Action action;
	char base[PATH_MAX];
	char *component;

	/* Sanity check.  */
	if (strnlen(referer, PATH_MAX) >= PATH_MAX)
		return -ENAMETOOLONG;

	assert(compare_paths("/proc", referer) == PATH1_IS_PREFIX);

	/* It's safe to use strrchr() here since @referer was
	 * previously canonicalized.  */
	strcpy(base, referer);
	component = strrchr(base, '/');

	/* These cases are not possible: @referer is supposed to be a
	 * canonicalized subpath of "/proc".  */
	assert(component != NULL && component != base);

	component[0] = '\0';
	component++;
	if (component[0] == '\0')
		return 0;

	action = readlink_proc(tracee, result, base, component, PATH1_IS_PREFIX);
	return (action == CANONICALIZE ? strlen(result) : 0);
}
