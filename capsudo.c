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
#include <errno.h>
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

#include "capsudo-message.h"
#include "capsudo-common.h"

static struct termios saved_tio;
static bool have_saved_tio = false;
static enum capsudo_sessiontype sessiontype = CAPSUDO_AUTO;

/* Set by the SIGWINCH handler; the client loop forwards the new size. */
static volatile sig_atomic_t winch_pending = 0;

enum capsudo_sessionresult {
	CAPSUDO_SESSION_OK,
	CAPSUDO_SESSION_SECRET_REQUIRED,
};

static char *prompt_for_secret(const char *prompt)
{
	if (prompt == NULL || !*prompt)
		prompt = "capsudo secret: ";

	char *p = getpass(prompt);
	dprintf(STDERR_FILENO, "\r");
	if (p == NULL || !*p)
		return NULL;

	return strdup(p);
}

static enum capsudo_sessiontype determine_session_type(void)
{
	return isatty(STDIN_FILENO) && isatty(STDOUT_FILENO) ? CAPSUDO_INTERACTIVE : CAPSUDO_NONINTERACTIVE;
}

static int usage(void)
{
	fprintf(stderr, "usage: capsudo [-S socket] [-i|-n] [-s] [-e key=value...] [args]\n");
	fprintf(stderr, "Default socket path is '%s'.\n", CAPSUDO_DEFAULT_SOCK);
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
	winch_pending = 1;
}

/* Put our terminal into raw mode, saving the prior settings for restore. */
static bool setup_raw_terminal(void)
{
	if (tcgetattr(STDIN_FILENO, &saved_tio) < 0)
		return false;

	have_saved_tio = true;

	struct termios raw = saved_tio;
	cfmakeraw(&raw);
	tcsetattr(STDIN_FILENO, TCSANOW, &raw);

	return true;
}

/* Send the current terminal dimensions to the daemon. */
static bool write_winsize(int sockfd)
{
	struct winsize wsz;

	if (ioctl(STDIN_FILENO, TIOCGWINSZ, &wsz) < 0)
		return true;

	struct capsudo_message *msg = alloca(sizeof(*msg) + sizeof(wsz));
	msg->fieldtype = CAPSUDO_WINSIZE;
	msg->length = sizeof(wsz);
	memcpy(msg->data, &wsz, sizeof(wsz));

	return write_raw_message(sockfd, msg);
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

	/*
	 * The daemon allocates the pty now, so we always delegate our real
	 * standard streams; for an interactive session these are our terminal,
	 * which the daemon bridges to the pty it creates on its side.
	 */
	int fdtable[3] = {
		STDIN_FILENO,
		STDOUT_FILENO,
		STDERR_FILENO,
	};

	memcpy(CMSG_DATA(cmsg), &fdtable, sizeof(fdtable));

	if (sendmsg(sockfd, &msg, 0) < 0)
		return false;

	return true;
}

static int setup_connection(const char *sockaddr, char *envp[], int argc, char *argv[], const char *secret)
{
	int sockfd;
	int envi, argi;

	sockfd = connect_to_daemon(sockaddr);
	if (sockfd < 0)
	{
		restore_tty();
		err(EXIT_FAILURE, "unable to connect to capsudo daemon at %s", sockaddr);
	}

	if (secret != NULL)
	{
		if (!write_message(sockfd, CAPSUDO_SECRET, secret))
			return -1;
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

	if (!write_u32_message(sockfd, CAPSUDO_SESSION_TYPE, (uint32_t) sessiontype))
		return -1;

	if (sessiontype == CAPSUDO_INTERACTIVE)
	{
		if (!write_winsize(sockfd))
			return -1;
	}

	if (!send_file_descriptors(sockfd))
		return -1;

	if (!write_message(sockfd, CAPSUDO_END, ""))
		return -1;

	return sockfd;
}

static enum capsudo_sessionresult handle_incoming_message(int sockfd, char **errmsg)
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
		restore_tty();
		close(sockfd);
		err(EXIT_FAILURE, "failed to read %zu bytes from the daemon, got %zu", msg->length, n);
	}

	switch (msg->fieldtype)
	{
		case CAPSUDO_UNAUTHORIZED:
		{
			*errmsg = strdup(msg->data);
			close(sockfd);
			return CAPSUDO_SESSION_SECRET_REQUIRED;
		}

		case CAPSUDO_EXIT:
		{
			int exitcode = *(int *) msg->data;

			close(sockfd);
			exit(exitcode);
			break;
		}

		case CAPSUDO_ERROR:
		{
			restore_tty();
			fprintf(stderr, "capsudo: error: %s\n", msg->data);
			break;
		}

		default:
			fprintf(stderr, "capsudo: ignoring unexpected message %d, length %zu\n", msg->fieldtype, msg->length);
	}

	return CAPSUDO_SESSION_OK;
}

static int client_loop_interactive(const char *sockaddr, char *envp[], int argc, char *argv[])
{
	int sockfd;
	char *secret = NULL;

	/*
	 * The pty lives on the daemon now: it reads and writes our real terminal
	 * directly (via the descriptors we pass).  We only put the terminal into
	 * raw mode and forward resize events; there is no local data relay.
	 */
	if (setup_raw_terminal())
		atexit(restore_tty);

	struct sigaction sa = {
		.sa_handler = handle_sigwinch,
	};

	sigemptyset(&sa.sa_mask);
	/* No SA_RESTART: a resize interrupts poll() so we can forward it. */
	sa.sa_flags = 0;
	sigaction(SIGWINCH, &sa, NULL);

	sockfd = setup_connection(sockaddr, envp, argc, argv, secret);

	for (;;)
	{
		struct pollfd pfd[1] = {
			{ .fd = sockfd,		.events = POLLIN },
		};

		if (poll(pfd, 1, -1) < 0)
		{
			if (errno != EINTR)
			{
				if (secret != NULL)
					free(secret);

				close(sockfd);
				return EXIT_FAILURE;
			}
		}

		if (winch_pending)
		{
			winch_pending = 0;
			write_winsize(sockfd);
		}

		if (pfd[0].revents & POLLIN)
		{
			char *prompt = NULL;
			enum capsudo_sessionresult ret = handle_incoming_message(sockfd, &prompt);

			if (ret == CAPSUDO_SESSION_SECRET_REQUIRED)
			{
				close(sockfd);

				if (secret != NULL)
				{
					free(secret);
					restore_tty();
					errx(EXIT_FAILURE, "provided secret is invalid");
				}

				secret = prompt_for_secret(prompt);
				if (secret == NULL)
				{
					restore_tty();
					errx(EXIT_FAILURE, "secret required, but none was provided");
				}

				sockfd = setup_connection(sockaddr, envp, argc, argv, secret);
			}

			if (prompt != NULL)
				free(prompt);
		}
	}

	close(sockfd);

	if (secret)
	{
		explicit_bzero(secret, strlen(secret));
		free(secret);
	}

	return EXIT_SUCCESS;
}

static int client_loop_noninteractive(const char *sockaddr, char *envp[], int argc, char *argv[])
{
	int sockfd;
	char *secret = NULL;

	sockfd = setup_connection(sockaddr, envp, argc, argv, secret);

	for (;;)
	{
		char *errmsg = NULL;

		struct pollfd pfd[1] = {
			{ .fd = sockfd,	.events = POLLIN },
		};

		if (poll(pfd, 1, -1) < 0)
		{
			close(sockfd);
			return EXIT_FAILURE;
		}

		if (pfd[0].revents & POLLIN)
			handle_incoming_message(sockfd, &errmsg);

		if (errmsg != NULL)
			free(errmsg);
	}

	close(sockfd);

	if (secret)
	{
		explicit_bzero(secret, strlen(secret));
		free(secret);
	}

	return EXIT_SUCCESS;
}

void append_default_environment(char ***envp, size_t *envp_nmemb)
{
	static const char *envnames[] = {
		"TERM",
		"LANG",
		"LC_ALL",
		"LC_CTYPE",
		"LC_MESSAGES",
		"COLORTERM",
	};

	size_t nmemb = *envp_nmemb;
	for (size_t i = 0; i < sizeof(envnames) / sizeof(*envnames); i++)
	{
		const char *val = getenv(envnames[i]);
		if (val == NULL)
			continue;

		size_t envlen = strlen(envnames[i]) + 1 + strlen(val) + 1;
		char *out = calloc(1, envlen);
		if (out == NULL)
			continue;

		snprintf(out, envlen, "%s=%s", envnames[i], val);

		*envp = reallocarray(*envp, ++nmemb + 1, sizeof(char *));
		(*envp)[nmemb - 1] = out;
		(*envp)[nmemb] = NULL;
	}

	*envp_nmemb = nmemb;
}

int main(int argc, char *argv[])
{
	const char *sockaddr = CAPSUDO_DEFAULT_SOCK;
	char **envp = NULL;
	size_t envp_nmemb = 0;
	int opt;
	bool sflag = false;
	char *sh;
	char *shargv[2] = { NULL, NULL };
	int (*loop)(const char *sockaddr, char *envp[], int argc, char *argv[]) = NULL;

	while ((opt = getopt(argc, argv, "hinsS:e:")) != -1)
	{
		switch (opt)
		{
		case 'h':
			return usage();
			break;
		case 'i':
			sessiontype = CAPSUDO_INTERACTIVE;
			break;
		case 'n':
			sessiontype = CAPSUDO_NONINTERACTIVE;
			break;
		case 's':
			sflag = true;
			break;
		case 'S':
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

	if (sflag)
	{
		sh = getenv("SHELL");
		if (sh == NULL || !*sh)
			sh = "sh";

		shargv[0] = sh;
		argv = shargv;
		argc = 1;
		optind = 0;
	}

	append_default_environment(&envp, &envp_nmemb);

	if (sockaddr == NULL)
		return usage();

	if (sessiontype == CAPSUDO_AUTO)
		sessiontype = determine_session_type();

	loop = sessiontype == CAPSUDO_INTERACTIVE ? client_loop_interactive : client_loop_noninteractive;
	return loop(sockaddr, envp, argc, argv);
}
