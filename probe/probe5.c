#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/xattr.h>
static void x(const char *p, const char *n) {
	char b[512]; b[0]=0; ssize_t r = getxattr(p, n, b, sizeof(b)-1);
	if (r>=0) { b[r]=0; printf("getxattr(%-40s %-16s) = [%s]\n", p, n, b); }
	else printf("getxattr(%-40s %-16s) = E%d\n", p, n, errno);
}
int main(void) {
	pid_t me = getpid(), mytid = syscall(224);
	char p0[64]; snprintf(p0,sizeof(p0),"/proc/%d",me);
	char p1[64]; snprintf(p1,sizeof(p1),"/proc/%d/task/%d",me,mytid);
	x("/proc/self", "security.selinux");
	x("/proc/thread-self", "security.selinux");
	x(p0, "security.selinux");
	x(p1, "security.selinux");
	x("/proc/self/attr/current", "security.selinux");
	x("/proc/self/task/self/attr/current", "security.selinux");
	x("/proc/self/t/attr/current", "security.selinux");
	return 0;
}
