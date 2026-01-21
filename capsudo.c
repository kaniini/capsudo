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
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <poll.h>
#include <signal.h>
#include <pty.h>

#include "capsudo-common.h"

static int pty_ourside = -1;
static int pty_theirside = -1;
static struct termios saved_tio;
static bool have_saved_tio = false;
static enum capsudo_sessiontype sessiontype = CAPSUDO_AUTO;

static enum capsudo_sessiontype determine_session_type(void)
{
	return isatty(STDIN_FILENO) && isatty(STDOUT_FILENO) ? CAPSUDO_INTERACTIVE : CAPSUDO_NONINTERACTIVE;
}

static int usage(void)
{
	fprintf(stderr, "usage: capsudo -s socket [-i|-n] [-e key=value...] [args]\n");
	return EXIT_FAILURE;
}

static void restore_tty(void)
{
	if (have_saved_tio)
		tcsetattr(STDIN_FILENO, TCSANOW, &saved_tio);
}

static void handle_sigwinch(int sig)
{
	(void) sig;

	if (pty_ourside < 0)
		return;

	struct winsize wsz;
	if (!ioctl(STDIN_FILENO, TIOCGWINSZ, &wsz))
		ioctl(pty_ourside, TIOCSWINSZ, &wsz);
}

static bool setup_pty(void)
{
	struct winsize wsz;

	if (!tcgetattr(STDIN_FILENO, &saved_tio))
		have_saved_tio = true;

	if (ioctl(STDIN_FILENO, TIOCGWINSZ, &wsz) < 0)
		return false;

	if (openpty(&pty_ourside, &pty_theirside, NULL, &saved_tio, &wsz) < 0)
		return false;

	return true;
}

static int connect_to_daemon(const char *sockaddr)
{
	int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
	};

	strlcpy(addr.sun_path, sockaddr, sizeof(addr.sun_path));

	if (sockfd < 0)
		return -1;

	if (connect(sockfd, (struct sockaddr *) &addr, sizeof addr) < 0)
	{
		close(sockfd);
		return -1;
	}

	return sockfd;
}

static bool write_raw_message(int sockfd, struct capsudo_message *msg)
{
	size_t nwritten, xwritten;

	xwritten = sizeof(struct capsudo_message) + msg->length;
	if ((nwritten = write(sockfd, msg, xwritten)) != xwritten)
	{
		close(sockfd);
		err(EXIT_FAILURE, "failed to write %zu bytes to capsudo daemon, wrote %zu instead", xwritten, nwritten);
	}

	return true;
}

static bool write_message(int sockfd, enum capsudo_fieldtype fieldtype, const char *msgbuf)
{
	struct capsudo_message *envmsg = alloca(sizeof(struct capsudo_message) + strlen(msgbuf) + 1);

	envmsg->fieldtype = fieldtype;
	envmsg->length = strlen(msgbuf) + 1;
	strlcpy(envmsg->data, msgbuf, envmsg->length);

	return write_raw_message(sockfd, envmsg);
}

static bool send_sessiontype(int sockfd)
{
	struct capsudo_message *msg = alloca(sizeof(struct capsudo_message) + sizeof(enum capsudo_sessiontype));

	msg->fieldtype = CAPSUDO_SESSION_TYPE;
	msg->length = sizeof(enum capsudo_sessiontype);
	memcpy(msg->data, &sessiontype, sizeof(enum capsudo_sessiontype));

	return write_raw_message(sockfd, msg);
}

static bool send_file_descriptors(int sockfd)
{
	struct capsudo_message fdmsg = {
		.fieldtype = CAPSUDO_FD,
		.length = 0,
	};

	struct iovec fdmsg_iov = {
		.iov_base = &fdmsg,
		.iov_len = sizeof(fdmsg),
	};

	union {
		char rawbuf[CMSG_SPACE(sizeof(int) * 3)];
		struct cmsghdr align;
	} controlbuf;

	struct msghdr msg = {
		.msg_iov = &fdmsg_iov,
		.msg_iovlen = 1,
		.msg_control = controlbuf.rawbuf,
		.msg_controllen = sizeof(controlbuf.rawbuf),
	};

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	*cmsg = (struct cmsghdr) {
		.cmsg_level = SOL_SOCKET,
		.cmsg_type = SCM_RIGHTS,
		.cmsg_len = CMSG_LEN(sizeof(int) * 3),
	};

	int fdtable[3] = {
		sessiontype == CAPSUDO_INTERACTIVE ? pty_theirside : STDIN_FILENO,
		sessiontype == CAPSUDO_INTERACTIVE ? pty_theirside : STDOUT_FILENO,
		sessiontype == CAPSUDO_INTERACTIVE ? pty_theirside : STDERR_FILENO,
	};

	memcpy(CMSG_DATA(cmsg), &fdtable, sizeof(fdtable));

	if (sendmsg(sockfd, &msg, 0) < 0)
		return false;

	return true;
}

static int setup_connection(const char *sockaddr, char *envp[], int argc, char *argv[])
{
	int sockfd;
	int envi, argi;

	sockfd = connect_to_daemon(sockaddr);
	if (sockfd < 0)
	{
		err(EXIT_FAILURE, "unable to connect to capsudo daemon at %s", sockaddr);
	}

	if (envp != NULL)
	{
		for (envi = 0; envp[envi] != NULL; envi++)
		{
			if (!write_message(sockfd, CAPSUDO_ENV, envp[envi]))
				return -1;
		}
	}

	for (argi = optind; argv[argi] != NULL; argi++)
	{
		if (!write_message(sockfd, CAPSUDO_ARG, argv[argi]))
			return -1;
	}

	if (!send_sessiontype(sockfd))
		return -1;

	if (!send_file_descriptors(sockfd))
		return -1;

	if (!write_message(sockfd, CAPSUDO_END, ""))
		return -1;

	return sockfd;
}

static void handle_incoming_message(int sockfd)
{
	struct capsudo_message msghdr;

	if (read(sockfd, &msghdr, sizeof msghdr) != sizeof(msghdr))
	{
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	struct capsudo_message *msg = alloca(sizeof(msghdr) + msghdr.length);
	memcpy(msg, &msghdr, sizeof(msghdr));

	ssize_t n = read(sockfd, msg->data, msg->length);
	if (n != msg->length)
	{
		close(sockfd);
		err(EXIT_FAILURE, "failed to read %zu bytes from the daemon, got %zu", msg->length, n);
	}

	switch (msg->fieldtype)
	{
		case CAPSUDO_EXIT:
		{
			int exitcode = *(int *) msg->data;

			close(sockfd);
			exit(exitcode);
		}

		case CAPSUDO_ERROR:
			fprintf(stderr, "capsudo: error: %s\n", msg->data);

		default:
			fprintf(stderr, "capsudo: ignoring unexpected message %d, length %zu\n", msg->fieldtype, msg->length);
	}
}

static void relay_buffer(int fromfd, int tofd)
{
	char buf[8192];

	ssize_t n = read(fromfd, buf, sizeof buf);
	if (n > 0)
		write(tofd, buf, (size_t) n);
}

static int client_loop_interactive(const char *sockaddr, char *envp[], int argc, char *argv[])
{
	int sockfd;

	if (!setup_pty())
		err(EXIT_FAILURE, "failed to allocate pty");

	if (have_saved_tio)
	{
		struct termios raw = saved_tio;

		cfmakeraw(&raw);
		tcsetattr(STDIN_FILENO, TCSANOW, &raw);
		atexit(restore_tty);
	}

	struct sigaction sa = {
		.sa_handler = handle_sigwinch,
	};

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sigaction(SIGWINCH, &sa, NULL);
	handle_sigwinch(SIGWINCH);

	sockfd = setup_connection(sockaddr, envp, argc, argv);

	for (;;)
	{
		struct pollfd pfd[3] = {
			{ .fd = STDIN_FILENO,	.events = POLLIN },
			{ .fd = pty_ourside,	.events = POLLIN },
			{ .fd = sockfd,		.events = POLLIN },
		};

		if (poll(pfd, 3, -1) < 0)
		{
			close(sockfd);
			return EXIT_FAILURE;
		}

		if (pfd[0].revents & POLLIN)
			relay_buffer(STDIN_FILENO, pty_ourside);

		if (pfd[1].revents & POLLIN)
			relay_buffer(pty_ourside, STDOUT_FILENO);

		if (pfd[2].revents & POLLIN)
			handle_incoming_message(sockfd);
	}

	close(sockfd);
	return EXIT_SUCCESS;
}

static int client_loop_noninteractive(const char *sockaddr, char *envp[], int argc, char *argv[])
{
	int sockfd;

	sockfd = setup_connection(sockaddr, envp, argc, argv);

	for (;;)
	{
		struct pollfd pfd[1] = {
			{ .fd = sockfd,	.events = POLLIN },
		};

		if (poll(pfd, 1, -1) < 0)
		{
			close(sockfd);
			return EXIT_FAILURE;
		}

		if (pfd[0].revents & POLLIN)
			handle_incoming_message(sockfd);
	}

	close(sockfd);
	return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
	const char *sockaddr = NULL;
	char **envp = NULL;
	size_t envp_nmemb = 0;
	int opt;
	int (*loop)(const char *sockaddr, char *envp[], int argc, char *argv[]) = NULL;

	while ((opt = getopt(argc, argv, "ins:e:")) != -1)
	{
		switch (opt)
		{
		case 'i':
			sessiontype = CAPSUDO_INTERACTIVE;
			break;
		case 'n':
			sessiontype = CAPSUDO_NONINTERACTIVE;
			break;
		case 's':
			sockaddr = optarg;
			break;
		case 'e':
			envp = reallocarray(envp, ++envp_nmemb + 1, sizeof(char *));
			envp[envp_nmemb - 1] = strdup(optarg);
			envp[envp_nmemb] = NULL;
			break;
		default:
			break;
		}
	}

	if (sockaddr == NULL)
		return usage();

	if (sessiontype == CAPSUDO_AUTO)
		sessiontype = determine_session_type();

	loop = sessiontype == CAPSUDO_INTERACTIVE ? client_loop_interactive : client_loop_noninteractive;
	return loop(sockaddr, envp, argc, argv);
}
