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
#include <sys/wait.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <signal.h>

#include "capsudo-common.h"

struct capsudo_session {
	int clientfd;
	int client_stdin;
	int client_stdout;
	int client_stderr;

	char **argv;
	size_t argv_nmemb;
	char **envp;
	size_t envp_nmemb;
};

[[noreturn]]
static void usage(void)
{
	fprintf(stderr, "usage: capsudod -s socket [-e key=value...] [program]\n");
	exit(EXIT_FAILURE);
}

static int open_listener(const char *sockaddr)
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

	if (listen(sockfd, 50) < 0)
		err(EXIT_FAILURE, "listening on socket %s", sockaddr);

	return sockfd;
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
			session->argv = reallocarray(session->argv, ++session->argv_nmemb + 1, sizeof(char *));
			session->argv[session->argv_nmemb - 1] = strdup(msg->data);
			session->argv[session->argv_nmemb] = NULL;
			break;
		case CAPSUDO_ENV:
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
		case CAPSUDO_END:
			return true;
		default:
			break;
		}
	}

	return false;
}

static bool write_exitcode(int sockfd, enum capsudo_fieldtype fieldtype, int exitcode)
{
	size_t nwritten, xwritten;
	struct capsudo_message *envmsg = alloca(sizeof(struct capsudo_message) + sizeof(int));

	envmsg->fieldtype = fieldtype;
	envmsg->length = sizeof(int);
	memcpy(envmsg->data, &exitcode, sizeof(int));

	xwritten = sizeof(struct capsudo_message) + envmsg->length;
	if ((nwritten = write(sockfd, envmsg, xwritten)) != xwritten)
	{
		close(sockfd);
		return false;
	}

	return true;
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
			_exit(127);

		if (dup2(session.client_stdin, STDIN_FILENO) < 0)
			_exit(127);

		if (dup2(session.client_stdout, STDOUT_FILENO) < 0)
			_exit(127);

		if (dup2(session.client_stderr, STDERR_FILENO) < 0)
			_exit(127);

		if (ioctl(STDIN_FILENO, TIOCSCTTY, 0) < 0)
			_exit(127);

		struct sigaction old, ignore = {
			.sa_handler = SIG_IGN,
		};

		sigaction(SIGTTOU, &ignore, &old);
		tcsetpgrp(STDIN_FILENO, getpgrp());
		sigaction(SIGTTOU, &old, NULL);

		execvpe(session.argv[0], session.argv, session.envp);
		_exit(127);
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

static int daemon_loop(const char *sockaddr, char *envp[], int argc, char *argv[])
{
	int sockfd;

	sockfd = open_listener(sockaddr);
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

	while ((opt = getopt(argc, argv, "s:e:")) != -1)
	{
		switch (opt)
		{
		case 's':
			sockaddr = optarg;
			break;
		case 'e':
			envp = reallocarray(envp, ++envp_nmemb + 1, sizeof(char *));
			envp[envp_nmemb - 1] = strdup(optarg);
			envp[envp_nmemb] = NULL;
		default:
			break;
		}
	}

	if (sockaddr == NULL)
	{
		usage();
	}

	return daemon_loop(sockaddr, envp, argc, argv);
}
