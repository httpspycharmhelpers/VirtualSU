#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/xattr.h>
#include <stdatomic.h>
static atomic_int inlog = 0;
static void tr(const char *fmt, ...) {
	if (atomic_exchange(&inlog, 1)) return;
	va_list ap; va_start(ap, fmt);
	FILE *f = fopen("/data/data/com.termux/files/usr/tmp/idlog.txt", "a");
	if (f) { vfprintf(f, fmt, ap); fclose(f); } va_end(ap);
	atomic_store(&inlog, 0);
}
static int want_path(const char *p) { return p && strstr(p, "attr"); }
ssize_t getxattr(const char *p, const char *n, void *v, size_t s) {
	static ssize_t (*r)(const char*,const char*,void*,size_t);
	if (!r) r = dlsym(RTLD_NEXT, "getxattr");
	ssize_t x = r(p, n, v, s);
	if (want_path(p)) tr("getxattr(%s,%s)=%zd %s\n", p, n, x, (x>=0&&v)?(char*)v:"");
	return x;
}
int getcon(char **c) {
	static int (*r)(char**);
	if (!r) r = dlsym(RTLD_NEXT, "getcon");
	int rc = r(c);
	tr("getcon()=%d %s\n", rc, (rc==0&&c&&*c)?*c:"");
	return rc;
}
int open(const char *p, int f, ...) {
	mode_t m = 0;
	if (f & O_CREAT) { va_list ap; va_start(ap, f); m = va_arg(ap, mode_t); va_end(ap); }
	static int (*r)(const char*,int,mode_t);
	if (!r) r = dlsym(RTLD_NEXT, "open");
	int fd = r(p, f, m);
	if (want_path(p)) tr("open(\"%s\")=%d\n", p, fd);
	return fd;
}
int openat(int dirfd, const char *p, int f, ...) {
	mode_t m = 0;
	if (f & O_CREAT) { va_list ap; va_start(ap, f); m = va_arg(ap, mode_t); va_end(ap); }
	static int (*r)(int,const char*,int,mode_t);
	if (!r) r = dlsym(RTLD_NEXT, "openat");
	int fd = r(dirfd, p, f, m);
	if (dirfd != AT_FDCWD) tr("openat(dirfd=%d)\n", dirfd);
	if (want_path(p)) tr("openat(%d,\"%s\")=%d\n", dirfd, p, fd);
	return fd;
}
ssize_t read(int fd, void *b, size_t c) {
	static ssize_t (*r)(int,void*,size_t);
	if (!r) r = dlsym(RTLD_NEXT, "read");
	ssize_t x = r(fd, b, c);
	tr("read(fd=%d)=%zd\n", fd, x);
	return x;
}
ssize_t fgetxattr(int fd, const char *n, void *v, size_t s) {
	static ssize_t (*r)(int,const char*,void*,size_t);
	if (!r) r = dlsym(RTLD_NEXT, "fgetxattr");
	ssize_t x = r(fd, n, v, s);
	tr("fgetxattr(fd=%d,%s)=%zd %s\n", fd, n, x, (x>=0&&v)?(char*)v:"");
	return x;
}
ssize_t pread(int fd, void *b, size_t c, off_t o) {
	static ssize_t (*r)(int,void*,size_t,off_t);
	if (!r) r = dlsym(RTLD_NEXT, "pread");
	ssize_t x = r(fd, b, c, o);
	tr("pread(fd=%d)=%zd\n", fd, x);
	return x;
}
typedef long (*syscall_t)(long, long, long, long, long, long, long);
long syscall(long n, ...) {
	static syscall_t real_sys = NULL;
	if (!real_sys) real_sys = (syscall_t) dlsym(RTLD_NEXT, "syscall");
	va_list ap; va_start(ap, n);
	long a=va_arg(ap,long), b=va_arg(ap,long), c=va_arg(ap,long);
	long d=va_arg(ap,long), e=va_arg(ap,long), f=va_arg(ap,long);
	va_end(ap);
	long rc = real_sys(n, a,b,c,d,e,f);
	if (n > 400) tr("syscall(%ld)=%ld errno=%d\n", n, rc, errno);
	return rc;
}
