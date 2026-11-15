#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
typedef int (*getcon_t)(char **);
typedef int (*getfilecon_t)(const char *, char **);
typedef int (*isen_t)(void);
static void show(const char *t, const char *v) { printf("%-26s = [%s]\n", t, v?v:"(NULL)"); }
int main(void) {
	char buf[256] = {0}; char *c = NULL; ssize_t r; int rc;
	getcon_t getcon = (getcon_t)dlsym(RTLD_DEFAULT, "getcon");
	getfilecon_t getfilecon = (getfilecon_t)dlsym(RTLD_DEFAULT, "getfilecon");
	isen_t isen = (isen_t)dlsym(RTLD_DEFAULT, "is_selinux_enabled");
	if (getcon) { rc = getcon(&c); if (rc==0) show("getcon", c); else printf("getcon rc=%d errno=%d\n", rc, errno); } else printf("no getcon sym\n");
	if (getfilecon) { rc = getfilecon("/proc/self/attr/current", &c); if (rc==0) show("getfilecon selinux", c); else printf("getfilecon rc=%d errno=%d\n", rc, errno); } else printf("no getfilecon sym\n");
	r = getxattr("/proc/self/attr/current", "security.selinux", buf, sizeof(buf)-1);
	if (r >= 0) { buf[r]=0; show("getxattr selinux", buf); } else printf("getxattr selinux errno=%d\n", errno);
	buf[0]=0;
	r = getxattr("/proc/self/attr/current", "security.current", buf, sizeof(buf)-1);
	if (r >= 0) { buf[r]=0; show("getxattr current", buf); } else printf("getxattr current errno=%d\n", errno);
	FILE *f = fopen("/proc/self/attr/current", "re");
	if (f) { char ln[256]; ln[0]=0; if (fgets(ln, sizeof(ln), f)) { ln[strcspn(ln,"\n")]=0; show("fopen+read", ln); } fclose(f); } else printf("fopen errno=%d\n", errno);
	int fd = open("/proc/self/attr/current", O_RDONLY);
	if (fd>=0) { char pb[128]; pb[0]=0; ssize_t n = pread(fd, pb, sizeof(pb)-1, 0); if (n>=0){pb[n]=0; show("pread", pb);} else printf("pread errno=%d\n", errno); close(fd);} else printf("open errno=%d\n", errno);
	buf[0]=0; errno=0;
	long x = syscall(416, 0, buf, sizeof(buf), 0);
	printf("getselfattr(416) = %ld errno=%d\n", x, errno);
	printf("is_selinux_enabled = %d\n", isen?isen():-1);
	return 0;
}
