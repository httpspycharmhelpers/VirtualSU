/* Exercises the capability and xattr answers from inside a session.
 *
 * Built by run_tests.sh and run under fakesu.elf, so it is checking what a
 * program inside the virtual root environment sees, not what the binary
 * claims about itself.  Prints one "key=value" line per observation and
 * exits non-zero if any syscall failed, so the shell side can tell a real
 * pass from a session that died early.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

#ifndef SYS_capget
#define SYS_capget 90
#endif
#ifndef SYS_capset
#define SYS_capset 91
#endif

#define CAP_V3 0x20080522u

struct cap_hdr {
	unsigned int version;
	int pid;
};

struct cap_data {
	unsigned int effective;
	unsigned int permitted;
	unsigned int inheritable;
};

static int failures;

static void probe_caps(void)
{
	struct cap_hdr hdr;
	struct cap_data d[2];

	memset(&hdr, 0, sizeof(hdr));
	memset(d, 0, sizeof(d));
	hdr.version = CAP_V3;
	hdr.pid = 0;

	if (syscall(SYS_capget, &hdr, d) != 0) {
		printf("capget=failed:%s\n", strerror(errno));
		failures++;
		return;
	}
	printf("cap_eff=%08x%08x\n", d[1].effective, d[0].effective);
	printf("cap_prm=%08x%08x\n", d[1].permitted, d[0].permitted);
	printf("cap_inh=%08x%08x\n", d[1].inheritable, d[0].inheritable);

	/* A v1 header is a layout we do not implement; the kernel's answer is
	 * EINVAL and ours has to agree rather than reinterpret the words. */
	hdr.version = 0x19980330u;
	if (syscall(SYS_capget, &hdr, d) == 0)
		printf("capget_v1=unexpected_success\n");
	else
		printf("capget_v1=errno:%d\n", errno);
}

static void probe_capset(void)
{
	struct cap_hdr hdr;
	struct cap_data d[2];

	memset(&hdr, 0, sizeof(hdr));
	memset(d, 0, sizeof(d));
	hdr.version = CAP_V3;
	hdr.pid = 0;
	/* Raise exactly one capability (CAP_CHOWN, bit 0) and nothing else, so
	 * the round trip is unambiguous. */
	d[0].effective = d[0].permitted = 1u;
	d[0].inheritable = 0;
	d[1].effective = d[1].permitted = 0;
	d[1].inheritable = 0;

	if (syscall(SYS_capset, &hdr, d) != 0) {
		printf("capset=failed:%s\n", strerror(errno));
		failures++;
		return;
	}
	printf("capset=ok\n");

	memset(d, 0, sizeof(d));
	hdr.version = CAP_V3;
	if (syscall(SYS_capget, &hdr, d) != 0) {
		printf("capget_after_capset=failed:%s\n", strerror(errno));
		failures++;
		return;
	}
	printf("cap_eff_after=%08x%08x\n", d[1].effective, d[0].effective);
}

static void probe_xattr(const char *path)
{
	char buf[256];
	ssize_t n;
	int fd;

	n = getxattr(path, "security.selinux", buf, sizeof(buf));
	if (n < 0)
		printf("getxattr_selinux=%s\n", strerror(errno));
	else
		printf("getxattr_selinux=%.*s\n", (int) n, buf);

	n = listxattr(path, buf, sizeof(buf));
	if (n < 0)
		printf("listxattr=%s\n", strerror(errno));
	else
		printf("listxattr_has_selinux=%d\n",
			n > 0 && memmem(buf, (size_t) n, "security.selinux", 16) != NULL);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		printf("open=%s\n", strerror(errno));
		return;
	}
	/* The same three questions asked of the descriptor instead of the path.
	 * bionic resolves a path to an fd and then asks about the fd, so if
	 * these disagree with the answers above, libselinux sees the real label
	 * while getfattr sees ours. */
	n = fgetxattr(fd, "security.selinux", buf, sizeof(buf));
	if (n < 0)
		printf("fgetxattr_selinux=%s\n", strerror(errno));
	else
		printf("fgetxattr_selinux=%.*s\n", (int) n, buf);

	n = flistxattr(fd, buf, sizeof(buf));
	if (n < 0)
		printf("flistxattr=%s\n", strerror(errno));
	else
		printf("flistxattr_has_selinux=%d\n",
			n > 0 && memmem(buf, (size_t) n, "security.selinux", 16) != NULL);

	close(fd);
}

static void probe_status(void)
{
	char line[256];
	FILE *f = fopen("/proc/self/status", "r");

	if (f == NULL) {
		printf("status=open_failed:%s\n", strerror(errno));
		failures++;
		return;
	}
	while (fgets(line, sizeof(line), f) != NULL) {
		if (strncmp(line, "Uid:", 4) == 0
		 || strncmp(line, "CapEff:", 7) == 0
		 || strncmp(line, "CapPrm:", 7) == 0
		 || strncmp(line, "CapBnd:", 7) == 0
		 || strncmp(line, "CapInh:", 7) == 0
		 || strncmp(line, "CapAmb:", 7) == 0
		 || strncmp(line, "Context:", 8) == 0
		 || strncmp(line, "NoNewPrivs:", 11) == 0
		 || strncmp(line, "TracerPid:", 10) == 0) {
			line[strcspn(line, "\n")] = '\0';
			printf("status_%s\n", line);
		}
	}
	fclose(f);
}

int main(int argc, char **argv)
{
	const char *target = argc > 1 ? argv[1] : "/system/bin/id";

	probe_caps();
	probe_capset();
	probe_status();
	probe_xattr(target);

	printf("failures=%d\n", failures);
	return failures ? 1 : 0;
}
