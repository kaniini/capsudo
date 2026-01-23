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

#include "capsudo-common.h"

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
};

[[noreturn]]
static void usage(void)
{
	fprintf(stderr, "usage: capsudod -s socket [-fE] [-o user[:group]] [-m mode] [-e key=value...] [program]\n");
	exit(EXIT_FAILURE);
}

static bool parse_mode(const char *spec, mode_t *mode_out)
{
	errno = 0;

	char *end = NULL;
	unsigned long val = strtoul(spec, &end, 8);

	if (errno || end == spec || (end != NULL && *end != '\0'))
		return false;

	if (val > 07777UL)
		return false;

	*mode_out = (mode_t) val;
	return true;
}

static bool parse_owner_spec(const char *spec, uid_t *uid_out, gid_t *gid_out)
{
	uid_t uid = -1;
	gid_t gid = -1;
	char specbuf[4096];

	strlcpy(specbuf, spec, sizeof specbuf);

	char *p = specbuf;
	char *user = strsep(&p, ":");
	char *group = p;

	if (user != NULL && *user)
	{
		errno = 0;

		char *end = NULL;
		unsigned long val = strtoul(user, &end, 10);

		if (!errno && end != NULL && !*end)
			uid = (uid_t) val;
		else
		{
			struct passwd *pw = getpwnam(user);

			if (pw == NULL)
				return false;

			uid = pw->pw_uid;
			gid = pw->pw_gid;
		}
	}

	if (group != NULL && *group)
	{
		errno = 0;

		char *end = NULL;
		unsigned long val = strtoul(group, &end, 10);

		if (!errno && end != NULL && !*end)
			gid = (gid_t) val;
		else
		{
			struct group *gr = getgrnam(group);

			if (gr == NULL)
				return false;

			gid = gr->gr_gid;
		}
	}

	if (uid == -1 && gid == -1)
		return false;

	*uid_out = uid;
	*gid_out = gid;

	return true;
}

static int open_listener(const char *sockaddr, uid_t uid, gid_t gid, mode_t mode)
{
	int sockfd;
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
	};

	unlink(sockaddr);
	strlcpy(addr.sun_path, sockaddr, sizeof(addr.sun_path));

	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0)
		err(EXIT_FAILURE, "opening listener socket %s", sockaddr);

	if (bind(sockfd, (struct sockaddr *) &addr, sizeof addr) < 0)
		err(EXIT_FAILURE, "binding listener socket to %s", sockaddr);

	if (uid != -1 || gid != -1)
		if (chown(sockaddr, uid, gid) < 0)
			err(EXIT_FAILURE, "setting listener socket ownership to %u:%u", uid, gid);

	if (chmod(sockaddr, mode) < 0)
		err(EXIT_FAILURE, "setting listener socket permissions to %o", mode);

	if (listen(sockfd, 50) < 0)
		err(EXIT_FAILURE, "listening on socket %s", sockaddr);

	return sockfd;
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
		case CAPSUDO_END:
			return true;
		default:
			break;
		}
	}

	return false;
}

static bool write_raw_message(int sockfd, struct capsudo_message *msg)
{
	size_t nwritten, xwritten;

	xwritten = sizeof(struct capsudo_message) + msg->length;
	if ((nwritten = write(sockfd, msg, xwritten)) != xwritten)
	{
		close(sockfd);
		return false;
	}

	return true;
}

static bool write_exitcode(int sockfd, enum capsudo_fieldtype fieldtype, int exitcode)
{
	struct capsudo_message *envmsg = alloca(sizeof(struct capsudo_message) + sizeof(int));

	envmsg->fieldtype = fieldtype;
	envmsg->length = sizeof(int);
	memcpy(envmsg->data, &exitcode, sizeof(int));

	return write_raw_message(sockfd, envmsg);
}

static bool write_message(int sockfd, enum capsudo_fieldtype fieldtype, const char *msgbuf)
{
	struct capsudo_message *envmsg = alloca(sizeof(struct capsudo_message) + strlen(msgbuf) + 1);

	envmsg->fieldtype = fieldtype;
	envmsg->length = strlen(msgbuf) + 1;
	strlcpy(envmsg->data, msgbuf, envmsg->length);

	return write_raw_message(sockfd, envmsg);
}

static void fatality(int clientfd, int errorcode, char *errfmt, ...)
{
	char errbuf[8192];
	va_list va;

	va_start(va, errfmt);
	vsnprintf(errbuf, sizeof errbuf, errfmt, va);
	va_end(va);

	(void) write_message(clientfd, CAPSUDO_ERROR, errbuf);
	(void) write_exitcode(clientfd, CAPSUDO_EXIT, errorcode);

	close(clientfd);
	_exit(errorcode);
}

static int child_loop(int clientfd, char *envp[], int argc, char *argv[])
{
	int argi, envi;
	struct capsudo_session session = {
		.clientfd = clientfd,
	};

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

	if (!get_client_secontext(&session))
		return EXIT_FAILURE;
	if (!receive_configuration(&session))
		return EXIT_FAILURE;

	if (session.argv == NULL)
	{
		session.argv = reallocarray(session.argv, 2, sizeof(char *));
		session.argv[0] = strdup("sh");
		session.argv[1] = NULL;
	}

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

		if (session.sessiontype == CAPSUDO_INTERACTIVE)
		{
			if (ioctl(STDIN_FILENO, TIOCSCTTY, 0) < 0)
				fatality(session.clientfd, 127, "unable to set controlling terminal: %s", strerror(errno));

			struct sigaction old, ignore = {
				.sa_handler = SIG_IGN,
			};

			sigaction(SIGTTOU, &ignore, &old);
			tcsetpgrp(STDIN_FILENO, getpgrp());
			sigaction(SIGTTOU, &old, NULL);
		}

		if (session.secontext)
		{
			size_t selen = strlen(session.secontext);
			int attrfd;

			attrfd = open("/proc/self/attr/exec", O_WRONLY);
			if (attrfd < 0 || write(attrfd, session.secontext, selen) != selen)
				fatality(session.clientfd, 127, "unable to set selinux context: %s", strerror(errno));
			close(attrfd);
		}

		execvpe(session.argv[0], session.argv, session.envp);
		fatality(session.clientfd, 127, "unable to execvpe: %s", strerror(errno));
	}

	int status;
	if (waitpid(childpid, &status, 0) < 0)
		return EXIT_FAILURE;

	int exitcode = EXIT_FAILURE;
	if (WIFEXITED(status))
		exitcode = WEXITSTATUS(status);
	else if (WIFSIGNALED(status))
		exitcode = 128 + WTERMSIG(status);

	if (!write_exitcode(session.clientfd, CAPSUDO_EXIT, WEXITSTATUS(exitcode)))
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

	while ((opt = getopt(argc, argv, "s:e:o:m:fEh")) != -1)
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
		case 's':
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
