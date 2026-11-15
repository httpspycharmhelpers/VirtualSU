#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/xattr.h>
static void x(const char *tag, const char *p, const char *n) {
	char b[256]; b[0]=0; ssize_t r = getxattr(p, n, b, sizeof(b)-1);
	if (r>=0) { b[r]=0; printf("%-34s [%s] (%s)\n", tag, b, p); }
	else printf("%-34s errno=%d (%s)\n", tag, errno, p);
}
int main(void) {
	char me[64]; snprintf(me, sizeof(me), "/proc/%d", getpid());
	x("self selinux", "/proc/self", "security.selinux");
	x("self current", "/proc/self", "security.current");
	x("pid selinux", me, "security.selinux");
	x("pid current", me, "security.current");
	x("self/attr/current selinux", "/proc/self/attr/current", "security.selinux");
	x("self/attr/current current", "/proc/self/attr/current", "security.current");
	x("static/class current", "/sys/class", "security.selinux");
	return 0;
}
