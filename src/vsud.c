/*
 * Vsud -- the privilege anchor.
 *
 * Why this exists
 * ---------------
 * Everything the session claimed about itself used to be decided by a single
 * process, which made two things impossible to get right:
 *
 *   - Where the fake identity begins.  Either every process in /proc wore
 *     the session's context, or every process wore the host's real one.  A
 *     root shell whose parent was an untrusted app looks like nothing at all
 *     on Android.
 *   - What killed the guest.  atexit(kill_all_tracees) covers an orderly
 *     exit; SIGKILL to su did not, and the whole tracee tree was orphaned.
 *
 * A daemon gives both a single answer.  Vsud starts once and stays alive;
 * each request forks a session *underneath* it, so the guest's ancestry
 * contains exactly one privileged process and everything below it inherits
 * that identity the way it normally would.  Because the kernel re-parents
 * the daemon to init, a session no longer appears to be a child of whatever
 * app happened to type `su`.
 *
 * Honest limits: this device has no real root, so Vsud's own uid 0 is
 * proot's fiction too, exactly like the session's.  What the daemon buys is
 * one well-defined place where the fiction starts -- not its absence.
 *
 * The session runs the *unmodified* su startup: Vsud execs this same binary
 * with a --vsud-session marker, main() strips the marker and carries on.
 * Nothing about option parsing, personas or policy is duplicated here.
 *
 * Framing, and why it is shaped this way: a descriptor can only ride along
 * with a message, so the header travels in the same sendmsg as the stdio
 * descriptor.  The argv/env strings then follow as ordinary writes -- a
 * stream socket preserves order, so they cannot be reordered relative to
 * the descriptor, and keeping them out of the ancillary message means a long
 * command line cannot overflow what the kernel will carry in one sendmsg().
 */

#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define VSUD_SOCK_NAME	"afake_su_vsud"
#define VSUD_MAGIC	0x56535544u	/* "VSUD" */
#define VSUD_VERSION	1u

/* One argv/env entry plus its terminator.  Generous on purpose: LD_LIBRARY_PATH
 * and a long command line are both legitimate. */
#define VSUD_STR_MAX	(1u << 16)
#define VSUD_MAX_ARGS	1024

/* Returned by vsud_client_main() when the request never reached a daemon,
 * meaning the caller should run the session in this process instead. */
#define VSUD_FALLBACK	(-1)

/* Appended to the session's environment so the policy check knows who
 * actually asked, which is no longer this process's uid once the daemon is
 * in the middle. */
#define VSUD_CALLER_UID_ENV	"VSUD_CALLER_UID"

extern char **environ;

enum {
	CTL_HELLO = 1,	/* session pid, so the client can signal it directly */
	CTL_EXIT,	/* exit status */
	CTL_ERROR,	/* NUL-terminated message follows */
};

struct vsud_hdr {
	uint32_t magic;
	uint32_t version;
	uint32_t argc;
	uint32_t envc;
	/* uid of the process that connected, recorded by the daemon with
	 * SO_PEERCRED.  The session needs it for policy: it cannot ask
	 * getuid(), which by then reports the daemon's uid. */
	uint32_t caller_uid;
};

struct vsud_ctl_msg {
	uint32_t type;
	int32_t value;
};

/* Set once the daemon tells us the session pid.  A signal handler may only
 * touch sig_atomic_t and call kill(2), which is all this one does. */
static volatile sig_atomic_t g_session_pid;

static void vsud_forward_signal(int sig)
{
	pid_t target = (pid_t)g_session_pid;
	if (target > 0)
		kill(target, sig);
}

static int write_full(int fd, const void *buf, size_t len)
{
	const char *p = buf;
	while (len > 0) {
		ssize_t n = write(fd, p, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

static int read_full(int fd, void *buf, size_t len)
{
	char *p = buf;
	while (len > 0) {
		ssize_t n = read(fd, p, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0) {
			errno = ECONNRESET;
			return -1;
		}
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

static int send_header_and_fd(int sock, const struct vsud_hdr *hdr, int fd)
{
	struct msghdr msg;
	struct iovec iov;
	union {
		char buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} cmsgbuf;
	struct cmsghdr *cmsg;
	ssize_t n;

	memset(&msg, 0, sizeof(msg));
	memset(&cmsgbuf, 0, sizeof(cmsgbuf));
	iov.iov_base = (void *)hdr;
	iov.iov_len = sizeof(*hdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf.buf;
	msg.msg_controllen = CMSG_SPACE(sizeof(int));
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

	do {
		n = sendmsg(sock, &msg, MSG_NOSIGNAL);
	} while (n < 0 && errno == EINTR);
	return n < 0 ? -1 : 0;
}

static int recv_header_and_fd(int sock, struct vsud_hdr *hdr, int *fd)
{
	struct msghdr msg;
	struct iovec iov;
	union {
		char buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} cmsgbuf;
	struct cmsghdr *cmsg;
	ssize_t n;

	memset(&msg, 0, sizeof(msg));
	memset(&cmsgbuf, 0, sizeof(cmsgbuf));
	iov.iov_base = hdr;
	iov.iov_len = sizeof(*hdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);

	*fd = -1;
	do {
		n = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC);
	} while (n < 0 && errno == EINTR);
	if (n < 0)
		return -1;
	if (n == 0) {
		errno = ECONNRESET;
		return -1;
	}
	if (n < (ssize_t)sizeof(*hdr)) {
		errno = EPROTO;
		return -1;
	}

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
			continue;
		int count = (int)((cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int));
		if (count > 0)
			*fd = *(int *)CMSG_DATA(cmsg);
		break;
	}
	if (*fd < 0) {
		errno = EPROTO;
		return -1;
	}
	return 0;
}

static int send_ctl(int sock, const struct vsud_ctl_msg *m)
{
	struct msghdr msg;
	struct iovec iov;
	ssize_t n;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = (void *)m;
	iov.iov_len = sizeof(*m);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	do {
		n = sendmsg(sock, &msg, MSG_NOSIGNAL);
	} while (n < 0 && errno == EINTR);
	return n < 0 ? -1 : 0;
}

static int recv_ctl(int sock, struct vsud_ctl_msg *m)
{
	struct msghdr msg;
	struct iovec iov;
	ssize_t n;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = m;
	iov.iov_len = sizeof(*m);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	do {
		n = recvmsg(sock, &msg, 0);
	} while (n < 0 && errno == EINTR);
	if (n < 0)
		return -1;
	if (n == 0 || n < (ssize_t)sizeof(*m)) {
		errno = ECONNRESET;
		return -1;
	}
	return 0;
}

static bool vsud_addr(struct sockaddr_un *sa)
{
	memset(sa, 0, sizeof(*sa));
	sa->sun_family = AF_UNIX;
	/* Abstract namespace: the name lives in the socket table rather than the
	 * filesystem, so there is no stale file to clean up and no directory
	 * whose permissions have to be right.  The leading NUL is what makes
	 * the name abstract. */
	sa->sun_path[0] = '\0';

	/* Per-uid name, and it has to be.
	 *
	 * The two entry points do not share an abstract namespace: Termux runs
	 * in its app domain, rish in the shell domain, and Android separates
	 * them.  With one fixed name, whichever started first owned it and the
	 * other got EADDRINUSE -- which this code reported as success, so the
	 * loser spawned a daemon that could never listen, waited out the full
	 * retry budget on every single command, and then silently ran the
	 * session with no privilege anchor at all.
	 *
	 * Suffixing with the uid gives each user their own daemon, which is
	 * also the correct isolation: the session's identity is meant to be
	 * rooted in *this* user's Vsud, not in some other user's. */
	int n = snprintf(sa->sun_path + 1, sizeof(sa->sun_path) - 2,
			 "%s.%ld", VSUD_SOCK_NAME, (long)getuid());
	if (n < 0 || (size_t)n >= sizeof(sa->sun_path) - 2)
		return false;
	return true;
}

static int vsud_listen(void)
{
	struct sockaddr_un sa;
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	if (!vsud_addr(&sa)) {
		close(fd);
		errno = ENAMETOOLONG;
		return -1;
	}
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}
	if (listen(fd, 16) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static int vsud_connect(struct vsud_hdr *hdr)
{
	struct sockaddr_un sa;
	struct ucred cred;
	socklen_t clen = sizeof(cred);
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	if (!vsud_addr(&sa)) {
		close(fd);
		errno = ENAMETOOLONG;
		return -1;
	}
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}
	/* Tell the daemon who we are.  The session runs as the daemon's uid, so
	 * without this the policy check would authorise the wrong caller. */
	memset(&cred, 0, sizeof(cred));
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &clen) == 0)
		hdr->caller_uid = cred.uid;
	return fd;
}

static int self_exe(char *out, size_t cap)
{
	ssize_t n = readlink("/proc/self/exe", out, cap - 1);
	if (n <= 0)
		return -1;
	out[n] = '\0';
	return 0;
}

/* ------------------------------------------------------------------ */
/* Daemon side                                                         */
/* ------------------------------------------------------------------ */

static char **read_str_array(int sock, uint32_t count, int *err)
{
	char **out = calloc((size_t)count + 1, sizeof(char *));
	char *buf = malloc(VSUD_STR_MAX);

	*err = 0;
	if (out == NULL || buf == NULL) {
		free(out);
		free(buf);
		*err = ENOMEM;
		return NULL;
	}
	for (uint32_t i = 0; i < count; i++) {
		uint32_t len;
		if (read_full(sock, &len, sizeof(len)) < 0 || len >= VSUD_STR_MAX) {
			*err = EPROTO;
			break;
		}
		if (read_full(sock, buf, len) < 0) {
			*err = EPROTO;
			break;
		}
		buf[len] = '\0';
		out[i] = strdup(buf);
		if (out[i] == NULL) {
			*err = ENOMEM;
			break;
		}
	}
	free(buf);
	if (*err != 0) {
		for (uint32_t i = 0; i < count; i++)
			free(out[i]);
		free(out);
		return NULL;
	}
	return out;
}

static void free_str_array(char **a)
{
	if (a == NULL)
		return;
	for (char **p = a; *p != NULL; p++)
		free(*p);
	free(a);
}

/* Handle exactly one request.  Runs in a forked child of the daemon, so a
 * session that never exits cannot block the accept loop. */
static void vsud_serve(int sock)
{
	struct vsud_hdr hdr;
	int stdio_fd = -1;
	int err = 0;

	prctl(PR_SET_NAME, "vsud");

	if (recv_header_and_fd(sock, &hdr, &stdio_fd) < 0)
		goto out;
	if (hdr.magic != VSUD_MAGIC || hdr.version != VSUD_VERSION
	 || hdr.argc == 0 || hdr.argc > VSUD_MAX_ARGS
	 || hdr.envc > VSUD_MAX_ARGS) {
		struct vsud_ctl_msg m = { CTL_ERROR, 0 };
		send_ctl(sock, &m);
		goto out;
	}

	char **argv = read_str_array(sock, hdr.argc, &err);
	if (argv == NULL)
		goto out;
	char **envp = read_str_array(sock, hdr.envc, &err);
	if (envp == NULL) {
		free_str_array(argv);
		goto out;
	}

	char exe[PATH_MAX];
	if (self_exe(exe, sizeof(exe)) < 0) {
		free_str_array(argv);
		free_str_array(envp);
		goto out;
	}

	/* One more entry for the caller uid, plus room for our own string. */
	char **cenv = calloc((size_t)hdr.envc + 2, sizeof(char *));
	if (cenv == NULL) {
		free_str_array(argv);
		free_str_array(envp);
		goto out;
	}
	for (uint32_t i = 0; i < hdr.envc; i++)
		cenv[i] = envp[i];
	char uidbuf[64];
	snprintf(uidbuf, sizeof(uidbuf), "%s=%lu", VSUD_CALLER_UID_ENV,
		 (unsigned long)hdr.caller_uid);
	cenv[hdr.envc] = uidbuf;
	cenv[hdr.envc + 1] = NULL;

	pid_t child = fork();
	if (child < 0) {
		free(cenv);
		free_str_array(argv);
		free_str_array(envp);
		goto out;
	}

	/* The daemon runs with SA_NOCLDWAIT so the kernel reaps the *worker*
	 * once it is done, which the accept loop cannot do for itself.  That
	 * setting is inherited across fork, and it makes waitpid() below fail
	 * with ECHILD -- so status stayed 0 and every session reported exit
	 * code 0 no matter what the guest did.  The worker needs ordinary
	 * SIGCHLD semantics; it is the one process that has to observe a
	 * specific child. */
	struct sigaction dfl;
	memset(&dfl, 0, sizeof(dfl));
	dfl.sa_handler = SIG_DFL;
	sigemptyset(&dfl.sa_mask);
	sigaction(SIGCHLD, &dfl, NULL);

	if (child == 0) {
		/* The session.  Being a child of the daemon is the whole
		 * point: it is what puts a privileged ancestor above the
		 * guest instead of the caller's shell. */
		close(sock);

		if (dup2(stdio_fd, STDIN_FILENO) < 0
		 || dup2(stdio_fd, STDOUT_FILENO) < 0
		 || dup2(stdio_fd, STDERR_FILENO) < 0)
			_exit(126);
		if (stdio_fd > STDERR_FILENO)
			close(stdio_fd);

		/* When the caller handed us a pseudo-terminal (it relayed its
		 * own tty through a pty pair), take it as the controlling
		 * terminal: otherwise the interactive shell warns "won't have
		 * full job control" and fg/bg do not work.  A freshly opened
		 * pty is nobody's controlling terminal yet, so TIOCSCTTY
		 * succeeds; on the socketpair path isatty() is false and this
		 * is skipped. */
		if (isatty(STDIN_FILENO)) {
			setsid();
			ioctl(STDIN_FILENO, TIOCSCTTY, 0);
		}

		/* argv becomes: <exe> --vsud-session <original argv[1..]> */
		char **cargv = calloc((size_t)hdr.argc + 2, sizeof(char *));
		if (cargv == NULL)
			_exit(126);
		cargv[0] = exe;
		cargv[1] = (char *)"--vsud-session";
		for (uint32_t i = 1; i < hdr.argc; i++)
			cargv[i + 1] = argv[i];
		cargv[hdr.argc + 1] = NULL;

		execve(exe, cargv, cenv);
		_exit(127);
	}

	/* Daemon side: hand the client the pid it may signal, then pass the
	 * session's exit status back.  Both go over the request socket, so the
	 * client needs only the one connection. */
	close(stdio_fd);
	free(cenv);
	free_str_array(argv);
	free_str_array(envp);

	struct vsud_ctl_msg hello = { CTL_HELLO, (int32_t)child };
	(void) send_ctl(sock, &hello);

	/* Wait for the session, but not blindly: the socket is the caller's
	 * liveness.  Before the daemon existed, the caller *was* the session's
	 * parent, so killing it tore the session down with it.  Now the session
	 * outlives the client by construction, and nothing watched for the
	 * client's death -- a SIGKILLed client left `su` and its guest running
	 * forever, an unattended root shell nobody had a handle on.
	 *
	 * Both sides therefore sit in one loop: the session exiting completes
	 * the request normally, while the socket hanging up means the caller is
	 * gone and the session must go too.  Graceful SIGTERM first -- it runs
	 * proot's atexit(kill_all_tracees), which SIGKILL would bypass and
	 * orphan the whole guest tree with it. */
	int status = 0;
	bool have_status = false;
	for (;;) {
		struct pollfd pfd = { .fd = sock, .events = POLLIN };
		int pr = poll(&pfd, 1, 200);
		if (pr < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		pid_t w = waitpid(child, &status, WNOHANG);
		if (w == child || (w < 0 && errno == ECHILD)) {
			if (w == child)
				have_status = true;
			break;
		}

		if (pr > 0 && (pfd.revents & (POLLIN | POLLHUP | POLLERR))) {
			/* EOF or error: read it to be sure, then the caller is
			 * unreachable.  Any byte here would be out of protocol,
			 * so treat anything short of an intact stream the same. */
			char probe;
			ssize_t n = read(sock, &probe, 1);
			if (n <= 0) {
				kill(child, SIGTERM);
				int waited = 0;
				while (waited < 40) {
					w = waitpid(child, &status, WNOHANG);
					if (w == child) {
						have_status = true;
						break;
					}
					if (w < 0 && errno == ECHILD)
						break;
					struct timespec ts = { 0, 50 * 1000 * 1000L };
					nanosleep(&ts, NULL);
					waited++;
				}
				if (!have_status && waitpid(child, &status, WNOHANG) == 0)
					kill(child, SIGKILL);
				break;
			}
		}
	}
	if (!have_status)
		while (waitpid(child, &status, 0) < 0 && errno == EINTR)
			;

	struct vsud_ctl_msg done;
	done.type = CTL_EXIT;
	if (WIFEXITED(status))
		done.value = WEXITSTATUS(status);
	else if (WIFSIGNALED(status))
		done.value = 128 + WTERMSIG(status);
	else
		done.value = 255;
	(void) send_ctl(sock, &done);
	close(sock);
	_exit(0);

out:
	if (stdio_fd >= 0)
		close(stdio_fd);
	close(sock);
	_exit(0);
}

int vsud_daemon_main(void)
{
	int lfd = vsud_listen();
	if (lfd < 0) {
		/* EADDRINUSE means another daemon already owns the name -- a
		 * success from the client's point of view, so exit quietly.
		 *
		 * Any other errno is a real failure (an abstract socket refused
		 * outright, for instance) and must not look like success: this
		 * function used to return 0 for all of them, so the client saw
		 * a daemon that had started, waited, then fell back -- and the
		 * reason never appeared anywhere.  Report it and let the client
		 * fall back on its own. */
		if (errno == EADDRINUSE)
			return 0;
		fprintf(stderr, "vsud: cannot listen on %s: %s\n",
			VSUD_SOCK_NAME, strerror(errno));
		return 1;
	}

	if (fork() > 0)
		_exit(0);		/* leave the client's session */
	/* One fork, one setsid -- and only when we were launched by a client.
	 *
	 * spawn_daemon() has *already* double-forked and setsid()'d before
	 * exec'ing us, so arriving here from a client means we are already
	 * detached and must not fork again: a second round re-parents the
	 * daemon below whatever the intermediate process belonged to and, under
	 * rish, that group gets cleaned up when the shell returns -- the daemon
	 * vanished within a second, silently.
	 *
	 * Launched directly ("fakesu --vsud"), nothing detached us yet, so the
	 * classic double fork is what keeps it from reacquiring a tty.  Which
	 * case we are in is decided by whether the caller already has a
	 * controlling terminal-free session; VSUD_SPAWNED marks the former. */
	if (getenv("VSUD_SPAWNED") == NULL) {
		if (fork() > 0)
			_exit(0);
		if (setsid() < 0)
			_exit(1);
		if (fork() > 0)
			_exit(0);	/* never reacquire a tty */
	}

	prctl(PR_SET_NAME, "vsud");
	if (getenv("VSUD_TRACE"))
		{
		struct sockaddr_un sa;
		char nm[128];
		nm[0] = '\0';
		if (vsud_addr(&sa))
			snprintf(nm, sizeof(nm), "%s", sa.sun_path + 1);
		fprintf(stderr, "vsud[daemon]: listening on %s (fd=%d)\n",
			nm[0] ? nm : VSUD_SOCK_NAME, lfd);
	}
	chdir("/");
	umask(0);

	/* Let the kernel reap the per-request workers.  The accept loop below
	 * blocks in poll(-1) and cannot afford a reap pass of its own, so
	 * without this every finished session would leave a zombie behind
	 * until the next request happened to arrive.  Only the daemon gets
	 * this; each worker still waitpid()s its own session to forward the
	 * exit status. */
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = SA_NOCLDWAIT | SA_RESTART;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGCHLD, &sa, NULL);

	int devnull = open("/dev/null", O_RDWR);
	if (devnull >= 0) {
		dup2(devnull, STDIN_FILENO);
		dup2(devnull, STDOUT_FILENO);
		dup2(devnull, STDERR_FILENO);
		if (devnull > STDERR_FILENO)
			close(devnull);
	}

	for (;;) {
		struct pollfd pfd = { .fd = lfd, .events = POLLIN };
		if (poll(&pfd, 1, -1) < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		int cfd = accept(lfd, NULL, NULL);
		if (cfd < 0)
			continue;
		pid_t worker = fork();
		if (worker == 0) {
			close(lfd);
			vsud_serve(cfd);
			_exit(0);
		}
		close(cfd);
		/* No explicit reaping here.  poll() below blocks indefinitely,
		 * so a worker that finished while we were idle would sit as a
		 * zombie until the next request arrived -- and on a quiet
		 * device that is never.  SA_NOCLDWAIT (set once in the
		 * daemon, above) makes the kernel reap the worker the moment
		 * it exits instead.  vsud_serve() still waitpid()s the
		 * *session* itself, because it must forward the exit status;
		 * that is a specific pid, and it is not the child SA_NOCLDWAIT
		 * applies to. */
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* Client side                                                         */
/* ------------------------------------------------------------------ */

static int collect_env(char ***out)
{
	int n = 0;
	while (environ[n] != NULL)
		n++;
	char **v = calloc((size_t)n + 1, sizeof(char *));
	if (v == NULL)
		return -1;
	for (int i = 0; i < n; i++)
		v[i] = environ[i];
	*out = v;
	return n;
}

/* Poll for a daemon that is probably already running.
 *
 * The pre-spawn check must be cheap.  It used to sleep a flat 20ms between
 * attempts, which is fine when it succeeds on the first try (the common case)
 * but turns into 100ms of dead time on the very first invocation of a fresh
 * install, where there is no socket to connect to and nothing is going to
 * change while we wait.  A single retry at a short delay covers the racy case
 * -- a daemon that is mid-bind -- and everything else belongs in the
 * post-spawn wait below, which is where progress is actually possible. */
static int try_connect(struct vsud_hdr *hdr, int attempts, int delay_ms)
{
	for (int i = 0; i < attempts; i++) {
		int fd = vsud_connect(hdr);
		if (fd >= 0)
			return fd;
		if (i == attempts - 1)
			break;
		struct timespec ts = { .tv_sec = delay_ms / 1000,
				      .tv_nsec = (long)(delay_ms % 1000) * 1000000L };
		nanosleep(&ts, NULL);
	}
	return -1;
}

/* Start the daemon out of line.  Double forked here as well, so the daemon is
 * never a child of the client: the client exits within milliseconds and must
 * not leave the daemon re-parented to it mid-request. */
static void spawn_daemon(void)
{
	char exe[PATH_MAX];
	if (self_exe(exe, sizeof(exe)) < 0)
		return;
	if (fork() != 0)
		return;
	if (fork() > 0)
		_exit(0);
	/* setsid() fails with EPERM when the process is already a session
	 * leader, which is exactly what happens under rish: Shizuku runs the
	 * shell inside app_process, so our double-fork child can inherit the
	 * session-leader role and never get a fresh one.
	 *
	 * That matters more than it first appears.  Left in the caller's
	 * process group, the daemon dies the moment that group is cleaned up --
	 * rish's sh does exactly that when the command returns -- and the next
	 * client finds no daemon, silently falls back, and the session runs
	 * without the privilege anchor at all.  So retry the whole double fork
	 * once: a fresh child is *not* a session leader, and its setsid() then
	 * succeeds.  Only give up if that also fails. */
	if (setsid() < 0) {
		if (getenv("VSUD_TRACE"))
			fprintf(stderr, "vsud[spawn]: setsid failed (%s), retrying\n",
				strerror(errno));
		if (fork() != 0)
			_exit(0);
		if (setsid() < 0 && getenv("VSUD_TRACE"))
			fprintf(stderr, "vsud[spawn]: setsid failed again: %s\n",
				strerror(errno));
	}
	/* VSUD_SPAWNED tells --vsud that this process is already detached, so it
	 * must not fork again.  Pass it explicitly rather than inheriting it from
	 * a client that happened to set it, hence setenv() with overwrite=1. */
	setenv("VSUD_SPAWNED", "1", 1);
	{
		char *const a[] = { exe, (char *)"--vsud", NULL };
		execv(exe, a);
		if (getenv("VSUD_TRACE"))
			fprintf(stderr, "vsud[spawn]: execv failed: %s\n", strerror(errno));
	}
	_exit(127);
}

/* Terminal resize: forward the caller's new window size to the session's
 * pty.  Kept minimal because it runs in a signal handler. */
static int g_relay_master = -1;
static void vsud_on_winch(int sig)
{
	struct winsize ws;
	(void)sig;
	if (g_relay_master >= 0
	 && ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0)
		ioctl(g_relay_master, TIOCSWINSZ, &ws);
}

int vsud_client_main(int argc, char **argv)
{
	int sv[2] = { -1, -1 };
	char **envp = NULL;

	if (getenv("VSUD_NO_DAEMON") != NULL)
		return VSUD_FALLBACK;

	struct vsud_hdr hdr = {
		.magic = VSUD_MAGIC,
		.version = VSUD_VERSION,
		.argc = (uint32_t)argc,
		.envc = 0,
		.caller_uid = (uint32_t)getuid(),
	};

	/* Two quick attempts: covers "a daemon exists but we raced its bind".
	 * Deliberately not a retry loop -- if there is no daemon, waiting here
	 * achieves nothing, and the cost lands on the user's first command. */
	int sock = try_connect(&hdr, 2, 5);
	if (sock < 0) {
		if (getenv("VSUD_TRACE"))
			fprintf(stderr, "vsud[client]: no daemon, spawning\n");
		spawn_daemon();
		/* Wait for the daemon to reach accept(), backing off so the
		 * common case (it is up in a few ms) costs almost nothing while
		 * the hopeless case -- a socket name this user cannot bind, as
		 * happens under rish where the abstract namespace is separate
		 * from the app's -- still gives up promptly. */
		sock = try_connect(&hdr, 40, 20);
		if (getenv("VSUD_TRACE"))
			fprintf(stderr, "vsud[client]: connect after spawn = %d\n", sock);
	}
	if (sock < 0) {
		if (getenv("VSUD_TRACE"))
			fprintf(stderr, "vsud[client]: FALLBACK to local session\n");
		return VSUD_FALLBACK;
	}

	/* A session whose stdin is a socketpair is not a terminal, so an
	 * interactive shell started through the daemon decides it is
	 * non-interactive and never prints a prompt -- `su <user>` came up
	 * blank while bare `su` worked only because argc==1 skips the daemon
	 * and runs locally.  When all three standard fds are the same
	 * terminal, hand that terminal to the session directly and skip the
	 * relay entirely; otherwise keep the socketpair so redirections and
	 * pipes still flow through. */
	int tty_mode = isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)
		&& isatty(STDERR_FILENO);
	int stdio_fd = -1;
	int pty_master = -1;
	struct termios saved_term;
	bool have_saved_term = false;
	if (tty_mode) {
		/* Give the session a pseudo-terminal of its own and relay our
		 * real terminal to it.  Handing our tty over directly would
		 * leave the session without a controlling terminal -- the shell
		 * then warns "won't have full job control" -- and two sessions
		 * cannot share one controlling terminal anyway. */
		pty_master = posix_openpt(O_RDWR | O_NOCTTY);
		if (pty_master >= 0 && grantpt(pty_master) == 0
		 && unlockpt(pty_master) == 0) {
			char *slave_name = ptsname(pty_master);
			if (slave_name != NULL)
				stdio_fd = open(slave_name, O_RDWR | O_NOCTTY);
		}
		if (stdio_fd < 0) {
			/* No pty available: keep the session and lose the
			 * terminal rather than refuse to run. */
			if (pty_master >= 0) {
				close(pty_master);
				pty_master = -1;
			}
			tty_mode = false;
		} else {
			struct winsize ws;
			if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0)
				ioctl(pty_master, TIOCSWINSZ, &ws);
			if (tcgetattr(STDIN_FILENO, &saved_term) == 0) {
				struct termios raw = saved_term;
				cfmakeraw(&raw);
				tcsetattr(STDIN_FILENO, TCSANOW, &raw);
				have_saved_term = true;
			}
		}
	}
	if (!tty_mode) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
			close(sock);
			return VSUD_FALLBACK;
		}
		stdio_fd = sv[0];
	}

	int envc = collect_env(&envp);
	if (envc < 0) {
		if (have_saved_term)
			tcsetattr(STDIN_FILENO, TCSANOW, &saved_term);
		close(sock);
		close(stdio_fd);
		if (pty_master >= 0)
			close(pty_master);
		if (sv[1] >= 0)
			close(sv[1]);
		return VSUD_FALLBACK;
	}
	hdr.envc = (uint32_t)envc;

	if (send_header_and_fd(sock, &hdr, stdio_fd) < 0)
		goto cleanup;

	for (int i = 0; i < argc; i++) {
		uint32_t len = (uint32_t)strlen(argv[i]) + 1;
		if (write_full(sock, &len, sizeof(len)) < 0
		 || write_full(sock, argv[i], len) < 0)
			goto cleanup;
	}
	for (int i = 0; i < envc; i++) {
		uint32_t len = (uint32_t)strlen(envp[i]) + 1;
		if (write_full(sock, &len, sizeof(len)) < 0
		 || write_full(sock, envp[i], len) < 0)
			goto cleanup;
	}

	/* From here the request is in flight and a session may already exist:
	 * there is no going back to running it locally, because that would run
	 * the command twice.  Every failure below is reported as a failure. */
	free(envp);
	envp = NULL;
	close(stdio_fd);
	stdio_fd = -1;
	if (!tty_mode)
		sv[0] = -1;

	struct vsud_ctl_msg msg;
	if (recv_ctl(sock, &msg) < 0 || msg.type != CTL_HELLO)
		goto cleanup;
	g_session_pid = (pid_t)msg.value;

	/* Signals go straight to the session pid: same uid, same device, and a
	 * control round trip would only add a way to lose them.  The handler
	 * does nothing but kill(2), which is all one is allowed to do. */
	struct sigaction fa;
	memset(&fa, 0, sizeof(fa));
	fa.sa_handler = vsud_forward_signal;
	sigfillset(&fa.sa_mask);
	fa.sa_flags = 0;
	sigaction(SIGINT, &fa, NULL);
	sigaction(SIGTERM, &fa, NULL);
	sigaction(SIGHUP, &fa, NULL);
	if (tty_mode) {
		struct sigaction wa;
		memset(&wa, 0, sizeof(wa));
		wa.sa_handler = vsud_on_winch;
		sigemptyset(&wa.sa_mask);
		sigaction(SIGWINCH, &wa, NULL);
		g_relay_master = pty_master;
	}

	/* Relay the caller's terminal (or pipe) to the session's stdio.  When
	 * the caller's stdin ends, shut down the write side of the socket
	 * rather than closing it: a command like `cat` then sees a proper end
	 * of input, while a command that never reads stdin is unaffected.  In
	 * tty mode the far end is the pty master instead of the socketpair. */
	int relay_fd = tty_mode ? pty_master : sv[1];
	int stdin_open = 1;
	int out_open = 1;
	while (out_open) {
		struct pollfd pfd[2];
		int n = 0, idx_stdin = -1, idx_out;

		if (stdin_open) {
			pfd[n].fd = STDIN_FILENO;
			pfd[n].events = POLLIN;
			idx_stdin = n++;
		}
		pfd[n].fd = relay_fd;
		pfd[n].events = POLLIN;
		idx_out = n++;

		if (poll(pfd, (nfds_t)n, -1) < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		if (idx_stdin >= 0 && pfd[idx_stdin].revents) {
			char b[4096];
			ssize_t r = read(STDIN_FILENO, b, sizeof(b));
			if (r > 0) {
				if (write_full(relay_fd, b, (size_t)r) < 0)
					stdin_open = 0;
			} else {
				stdin_open = 0;
				shutdown(relay_fd, SHUT_WR);
			}
		}

		if (pfd[idx_out].revents) {
			char b[4096];
			ssize_t r = read(relay_fd, b, sizeof(b));
			if (r > 0) {
				/* EPIPE means the guest is gone; the exit
				 * status below reports what actually happened. */
				(void)write_full(STDOUT_FILENO, b, (size_t)r);
			} else {
				out_open = 0;
			}
		}
	}

	/* Drain whatever the session wrote just before exiting. */
	for (;;) {
		char b[4096];
		ssize_t r = read(relay_fd, b, sizeof(b));
		if (r <= 0)
			break;
		(void)write_full(STDOUT_FILENO, b, (size_t)r);
	}
	close(relay_fd);
	if (tty_mode)
		pty_master = -1;
	else
		sv[1] = -1;
	if (have_saved_term)
		tcsetattr(STDIN_FILENO, TCSANOW, &saved_term);

	int rc = 255;
	if (recv_ctl(sock, &msg) == 0 && msg.type == CTL_EXIT) {
		rc = msg.value;
		/* Die the same way the session did, with the default
		 * disposition, so our own caller sees the real cause. */
		if (rc > 128 && rc < 160) {
			signal(rc - 128, SIG_DFL);
			raise(rc - 128);
		}
	}
	close(sock);
	return rc;

cleanup:
	free(envp);
	if (have_saved_term)
		tcsetattr(STDIN_FILENO, TCSANOW, &saved_term);
	if (sock >= 0)
		close(sock);
	if (pty_master >= 0)
		close(pty_master);
	if (sv[0] >= 0)
		close(sv[0]);
	if (sv[1] >= 0)
		close(sv[1]);
	return 255;
}