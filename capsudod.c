/*
 * Copyright (c) 2024 Ariadne Conill <ariadne@ariadne.space>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * This software is provided 'as is' and without any warranty, express or
 * implied.  In no event shall the authors be liable for any damages arising
 * from the use of this software.
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <stdbool.h>
#include <alloca.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <signal.h>
#include <grp.h>
#include <pwd.h>
#include <limits.h>
#include <pty.h>

#include "capsudo-common.h"
#include "capsudo-message.h"
#include "capsudo-ownerspec.h"

static bool no_client_argv = false;
static bool no_client_env = false;

struct capsudo_session {
	int clientfd;
	int client_stdin;
	int client_stdout;
	int client_stderr;

	enum capsudo_sessiontype sessiontype;

	char **argv;
	size_t argv_nmemb;
	char **envp;
	size_t envp_nmemb;

	char *secontext;

	struct winsize winsize;
};

[[noreturn]]
static void usage(void)
{
	fprintf(stderr, "usage: capsudod [-S socket] [-fE] [-o user[:group]] [-m mode] [-e key=value...] [program]\n");
	exit(EXIT_FAILURE);
}

static bool get_client_secontext(struct capsudo_session *session)
{
#ifdef SO_PEERSEC
	socklen_t optlen, newoptlen;
	char secontext[NAME_MAX + 1];

	optlen = sizeof(secontext) - 1;
	if (getsockopt(session->clientfd, SOL_SOCKET, SO_PEERSEC, secontext, &optlen) < 0)
		return errno == ENOPROTOOPT;

	session->secontext = calloc(1, optlen + 1);

	if (!session->secontext)
		return false;

	if (optlen >= sizeof(secontext))
	{
		newoptlen = optlen;
		if (getsockopt(session->clientfd, SOL_SOCKET, SO_PEERSEC, session->secontext, &newoptlen) != 0 || newoptlen != optlen)
			return false;
	} else
		memcpy(session->secontext, secontext, optlen);

	session->secontext[optlen] = '\0';
	if (!*session->secontext)
	{
		free(session->secontext);
		session->secontext = NULL;
	}
#endif

	return true;
}

static bool receive_configuration(struct capsudo_session *session)
{
	while (true)
	{
		struct capsudo_message capsudo_msghdr = {};

		union {
			char buf[CMSG_SPACE(sizeof(int) * 3)];
			struct cmsghdr align;
		} cmsgbuf;

		struct iovec iov = {
			.iov_base = &capsudo_msghdr,
			.iov_len = sizeof(capsudo_msghdr),
		};

		struct msghdr msgh = {
			.msg_name = NULL,
			.msg_namelen = 0,
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = cmsgbuf.buf,
			.msg_controllen = sizeof(cmsgbuf.buf),
		};

		if (recvmsg(session->clientfd, &msgh, 0) != sizeof(capsudo_msghdr))
			return false;

		struct capsudo_message *msg = alloca(sizeof(struct capsudo_message) + capsudo_msghdr.length);
		memcpy(msg, &capsudo_msghdr, sizeof(struct capsudo_message));

		if (read(session->clientfd, msg->data, msg->length) != msg->length)
			return false;

		int fdtable[3];
		switch (msg->fieldtype)
		{
		case CAPSUDO_ARG:
			if (no_client_argv)
				continue;

			session->argv = reallocarray(session->argv, ++session->argv_nmemb + 1, sizeof(char *));
			session->argv[session->argv_nmemb - 1] = strdup(msg->data);
			session->argv[session->argv_nmemb] = NULL;
			break;
		case CAPSUDO_ENV:
			if (no_client_env)
				continue;

			session->envp = reallocarray(session->envp, ++session->envp_nmemb + 1, sizeof(char *));
			session->envp[session->envp_nmemb - 1] = strdup(msg->data);
			session->envp[session->envp_nmemb] = NULL;
			break;
		case CAPSUDO_FD:
			struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msgh);
			memcpy(fdtable, CMSG_DATA(cmsg), sizeof(fdtable));

			session->client_stdin = fdtable[0];
			session->client_stdout = fdtable[1];
			session->client_stderr = fdtable[2];
			break;
		case CAPSUDO_SESSION_TYPE:
			session->sessiontype = *(int *) msg->data;
			break;
		case CAPSUDO_WINSIZE:
			if (msg->length == sizeof(struct winsize))
				memcpy(&session->winsize, msg->data, sizeof(struct winsize));
			break;
		case CAPSUDO_END:
			return true;
		default:
			break;
		}
	}

	return false;
}

[[noreturn]]
static void fatality(int clientfd, int errorcode, char *errfmt, ...)
{
	char errbuf[8192];
	va_list va;

	va_start(va, errfmt);
	vsnprintf(errbuf, sizeof errbuf, errfmt, va);
	va_end(va);

	(void) write_message(clientfd, CAPSUDO_ERROR, errbuf);
	(void) write_u32_message(clientfd, CAPSUDO_EXIT, (uint32_t) errorcode);

	close(clientfd);
	_exit(errorcode);
}

/* Apply the client's SELinux context to the about-to-exec child, if any. */
static void apply_secontext(struct capsudo_session *session)
{
	if (session->secontext == NULL)
		return;

	size_t selen = strlen(session->secontext);
	int attrfd = open("/proc/self/attr/exec", O_WRONLY);
	if (attrfd < 0 || write(attrfd, session->secontext, selen) != (ssize_t) selen)
		fatality(session->clientfd, 127, "unable to set selinux context: %s", strerror(errno));
	close(attrfd);
}

/*
 * Interactive session: the daemon allocates the pty so the child gets a real
 * controlling terminal (with working job control) in this process's context.
 * The pty master is bridged to the descriptors the client delegated — its real
 * terminal — and window-size updates arrive as control messages.
 */
static int run_pty_session(struct capsudo_session *session)
{
	int master, slave;

	if (openpty(&master, &slave, NULL, NULL, &session->winsize) < 0)
		fatality(session->clientfd, 127, "unable to allocate pty: %s", strerror(errno));

	pid_t childpid = fork();
	if (childpid < 0)
		fatality(session->clientfd, 127, "unable to fork: %s", strerror(errno));

	if (childpid == 0)
	{
		close(master);

		if (setsid() < 0)
			fatality(session->clientfd, 127, "unable to setsid: %s", strerror(errno));

		if (dup2(slave, STDIN_FILENO) < 0 ||
		    dup2(slave, STDOUT_FILENO) < 0 ||
		    dup2(slave, STDERR_FILENO) < 0)
			fatality(session->clientfd, 127, "unable to dup pty slave: %s", strerror(errno));

		if (slave > STDERR_FILENO)
			close(slave);

		if (ioctl(STDIN_FILENO, TIOCSCTTY, 0) < 0)
			fatality(session->clientfd, 127, "unable to set controlling terminal: %s", strerror(errno));

		apply_secontext(session);

		execvpe(session->argv[0], session->argv, session->envp);
		fatality(session->clientfd, 127, "unable to execvpe: %s", strerror(errno));
	}

	close(slave);

	if (session->secontext != NULL)
		free(session->secontext);

	int cin = session->client_stdin;
	int cout = session->client_stdout;

	for (;;)
	{
		struct pollfd pfd[3] = {
			{ .fd = session->clientfd, .events = POLLIN },
			{ .fd = cin,               .events = POLLIN },
			{ .fd = master,            .events = POLLIN },
		};

		if (poll(pfd, 3, -1) < 0)
		{
			if (errno == EINTR)
				continue;
			break;
		}

		/* Control channel: window-size updates, or the client hanging up. */
		if (pfd[0].revents & (POLLIN | POLLHUP))
		{
			struct capsudo_message hdr;
			char payload[256];

			if (read(session->clientfd, &hdr, sizeof hdr) != (ssize_t) sizeof hdr)
				break;

			if (hdr.length > sizeof payload)
				break;

			if (hdr.length > 0 &&
			    read(session->clientfd, payload, hdr.length) != (ssize_t) hdr.length)
				break;

			if (hdr.fieldtype == CAPSUDO_WINSIZE && hdr.length == sizeof(struct winsize))
				ioctl(master, TIOCSWINSZ, payload);
		}

		/* Client terminal input -> pty master. */
		if (cin >= 0 && (pfd[1].revents & POLLIN))
		{
			char buf[8192];
			ssize_t n = read(cin, buf, sizeof buf);
			if (n > 0)
				(void) write(master, buf, (size_t) n);
			else
				cin = -1; /* input closed; stop polling it */
		}

		/* pty master -> client terminal output. */
		if (pfd[2].revents & (POLLIN | POLLHUP))
		{
			char buf[8192];
			ssize_t n = read(master, buf, sizeof buf);
			if (n > 0)
				(void) write(cout, buf, (size_t) n);
			else
				break; /* child closed the pty: it has exited */
		}
	}

	close(master);

	int status;
	int exitcode = EXIT_FAILURE;
	if (waitpid(childpid, &status, 0) >= 0)
	{
		if (WIFEXITED(status))
			exitcode = WEXITSTATUS(status);
		else if (WIFSIGNALED(status))
			exitcode = 128 + WTERMSIG(status);
	}

	if (!write_u32_message(session->clientfd, CAPSUDO_EXIT, (uint32_t) exitcode))
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

static int child_loop(int clientfd, char *envp[], int argc, char *argv[])
{
	int argi, envi;
	struct capsudo_session session = {
		.clientfd = clientfd,
		.winsize = { .ws_row = 24, .ws_col = 80 },
	};

	/*
	 * The listener ignores SIGCHLD so it never accumulates zombies, but this
	 * per-connection process must reap its own child to report the exit code.
	 */
	signal(SIGCHLD, SIG_DFL);

	for (argi = optind; argi < argc; argi++)
	{
		session.argv = reallocarray(session.argv, ++session.argv_nmemb + 1, sizeof(char *));
		session.argv[session.argv_nmemb - 1] = strdup(argv[argi]);
		session.argv[session.argv_nmemb] = NULL;
	}

	if (envp != NULL)
	{
		for (envi = 0; envp[envi]; envi++)
		{
			session.envp = reallocarray(session.envp, ++session.envp_nmemb + 1, sizeof(char *));
			session.envp[session.envp_nmemb - 1] = strdup(envp[envi]);
			session.envp[session.envp_nmemb] = NULL;
		}
	}

	if (!receive_configuration(&session))
		return EXIT_FAILURE;

	if (session.argv == NULL)
	{
		session.argv = reallocarray(session.argv, 2, sizeof(char *));
		session.argv[0] = strdup("sh");
		session.argv[1] = NULL;
	}

	if (!get_client_secontext(&session))
		return EXIT_FAILURE;

	if (session.sessiontype == CAPSUDO_INTERACTIVE)
		return run_pty_session(&session);

	pid_t childpid = fork();
	if (childpid < 0)
		err(EXIT_FAILURE, "forking child process");

	if (childpid == 0)
	{
		if (setsid() < 0)
			fatality(session.clientfd, 127, "unable to setsid: %s", strerror(errno));

		if (dup2(session.client_stdin, STDIN_FILENO) < 0)
			fatality(session.clientfd, 127, "unable to dup stdin: %s", strerror(errno));

		if (dup2(session.client_stdout, STDOUT_FILENO) < 0)
			fatality(session.clientfd, 127, "unable to dup stdout: %s", strerror(errno));

		if (dup2(session.client_stderr, STDERR_FILENO) < 0)
			fatality(session.clientfd, 127, "unable to dup stderr: %s", strerror(errno));

		apply_secontext(&session);

		execvpe(session.argv[0], session.argv, session.envp);
		fatality(session.clientfd, 127, "unable to execvpe: %s", strerror(errno));
	}

	if (session.secontext != NULL)
		free(session.secontext);

	int status;
	if (waitpid(childpid, &status, 0) < 0)
		return EXIT_FAILURE;

	int exitcode = EXIT_FAILURE;
	if (WIFEXITED(status))
		exitcode = WEXITSTATUS(status);
	else if (WIFSIGNALED(status))
		exitcode = 128 + WTERMSIG(status);

	if (!write_u32_message(session.clientfd, CAPSUDO_EXIT, (uint32_t) exitcode))
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

static int daemon_loop(const char *sockaddr, char *envp[], int argc, char *argv[], uid_t uid, gid_t gid, mode_t mode)
{
	int sockfd;

	sockfd = open_listener(sockaddr, uid, gid, mode);
	if (sockfd < 0)
		err(EXIT_FAILURE, "opening listener socket %s", sockaddr);

	while (true)
	{
		int clientfd = accept(sockfd, NULL, NULL);
		if (clientfd < 0)
			err(EXIT_FAILURE, "accepting client at %s", sockaddr);

		pid_t childpid = fork();

		switch (childpid)
		{
		case -1:
			err(EXIT_FAILURE, "forking child process");
			break;
		case 0:
			close(sockfd);
			exit(child_loop(clientfd, envp, argc, argv));
			break;
		default:
			close(clientfd);
			break;
		}
	}

	return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
	const char *sockaddr = NULL;
	char **envp = NULL;
	size_t envp_nmemb = 0;
	int opt;
	uid_t uid = -1;
	gid_t gid = -1;
	mode_t mode = 0770;

	(void) signal(SIGCHLD, SIG_IGN);

	while ((opt = getopt(argc, argv, "S:e:o:m:fEh")) != -1)
	{
		switch (opt)
		{
		case 'h':
			usage();
			break;
		case 'f':
			no_client_argv = true;
			break;
		case 'E':
			no_client_env = true;
			break;
		case 'S':
			sockaddr = optarg;
			break;
		case 'e':
			envp = reallocarray(envp, ++envp_nmemb + 1, sizeof(char *));
			envp[envp_nmemb - 1] = strdup(optarg);
			envp[envp_nmemb] = NULL;
			break;
		case 'o':
			if (!parse_owner_spec(optarg, &uid, &gid))
				errx(EXIT_FAILURE, "invalid owner spec: %s", optarg);
			break;
		case 'm':
			if (!parse_mode(optarg, &mode))
				errx(EXIT_FAILURE, "invalid mode spec: %s", optarg);
			break;
		default:
			break;
		}
	}

	if (sockaddr == NULL)
		return child_loop(STDIN_FILENO, envp, argc, argv);

	return daemon_loop(sockaddr, envp, argc, argv, uid, gid, mode);
}
