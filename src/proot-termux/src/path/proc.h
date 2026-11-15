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

#ifndef PROC_H
#define PROC_H

#include <limits.h>
#include <stdbool.h>
#include <sys/types.h>

#include "tracee/tracee.h"
#include "path/path.h"

/* Action to do after a call to readlink_proc().  */
typedef enum {
	DEFAULT,           /* Nothing special to do, treat it as a regular link.  */
	CANONICALIZE,      /* The symlink was dereferenced, now canonicalize it.  */
	DONT_CANONICALIZE, /* The symlink shouldn't be dereferenced nor canonicalized.  */
} Action;


extern Action readlink_proc(const Tracee *tracee, char result[PATH_MAX], const char path[PATH_MAX],
			const char component[NAME_MAX],	Comparison comparison);

extern ssize_t readlink_proc2(const Tracee *tracee, char result[PATH_MAX], const char path[PATH_MAX]);

/* True when @pid belongs to the privileged subtree -- Vsud and everything
 * below it -- and must therefore report the faked SELinux context and uid.
 * Implemented in proc.c; this is the single source of truth for that
 * boundary, so the xattr path (enter.c) and the /proc/<pid>/attr/current
 * path (proc.c) cannot drift apart. */
extern bool afakesu_pid_in_session(pid_t pid);

/* True when @path names a /proc/<pid> entry owned by a process outside this
 * session, so its real owner must not be rewritten to the session uid. */
extern bool afakesu_proc_dir_foreign(const char *path);

#endif /* PROC_H */
