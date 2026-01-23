/*
 * Copyright (c) 2026 Ariadne Conill <ariadne@ariadne.space>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * This software is provided 'as is' and without any warranty, express or
 * implied.  In no event shall the authors be liable for any damages arising
 * from the use of this software.
 */

#include <err.h>
#include <errno.h>
#include <pwd.h>
#include <shadow.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "capsudo-common.h"
#include "capsudo-message.h"
#include "capsudo-ownerspec.h"

static const char *listen_sock = NULL;
static const char *capsudod_path = "capsudod";

static uid_t socket_uid = (uid_t)-1;
static gid_t socket_gid = (gid_t)-1;
static mode_t socket_mode = 0770;

static void usage(void)
{
	fprintf(stderr,
	        "usage: capsudod-pwauth -S socket [-d capsudod] [-o user[:group]] [-m mode] [-- capsudod-args...]\n");
	exit(EXIT_FAILURE);
}

/* Linux peer credentials -> username */
static const char *username_from_peercred(int clientfd)
{
#ifdef SO_PEERCRED
	struct ucred cred;
	socklen_t len = sizeof cred;

	if (getsockopt(clientfd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
		return NULL;

	struct passwd *pw = getpwuid(cred.uid);
	return pw ? pw->pw_name : NULL;
#else
	(void) clientfd;
	return NULL;
#endif
}

static void format_prompt(char *out, size_t outlen, const char *user)
{
	char host[256];

	if (gethostname(host, sizeof host) != 0)
		strncpy(host, "localhost", sizeof host);

	host[sizeof host - 1] = '\0';

	/* Prompt text to be displayed by the client. */
	snprintf(out, outlen, "[capsudo] %s@%s's password: ", user, host);
}

static bool shadow_check_password(const char *user, const char *password)
{
	struct spwd *sp = getspnam(user);
	if (!sp || !sp->sp_pwdp || !*sp->sp_pwdp)
		return false;

	/* Locked / disabled accounts */
	if (sp->sp_pwdp[0] == '!' || sp->sp_pwdp[0] == '*')
		return false;

	char *calc = crypt(password, sp->sp_pwdp);
	if (!calc)
		return false;

	return strcmp(calc, sp->sp_pwdp) == 0;
}

static void wipe_free(char *s)
{
	if (!s)
		return;
	explicit_bzero(s, strlen(s));
	free(s);
}

static void send_error_and_close(int clientfd, enum capsudo_fieldtype msgtype, const char *msg)
{
	(void) write_message(clientfd, msgtype, msg);
	close(clientfd);
}

/*
 * Read exactly one message header using recvmsg so we can detect SCM_RIGHTS smuggling.
 * Returns false on EOF/error or if SCM_RIGHTS are present.
 */
static bool recv_header_no_rights(int fd, struct capsudo_message *hdr)
{
	union {
		char buf[CMSG_SPACE(sizeof(int) * 8)];
		struct cmsghdr align;
	} cmsgbuf;

	struct iovec iov = {
		.iov_base = hdr,
		.iov_len  = sizeof *hdr,
	};

	struct msghdr mh = {
		.msg_iov        = &iov,
		.msg_iovlen     = 1,
		.msg_control    = cmsgbuf.buf,
		.msg_controllen = sizeof cmsgbuf.buf,
	};

	ssize_t n = recvmsg(fd, &mh, 0);
	if (n != (ssize_t)sizeof *hdr)
		return false;

	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mh);
	     cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&mh, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type  == SCM_RIGHTS) {
			return false;
		}
	}

	return true;
}

static void handle_client(int sockfd, int clientfd, const char *user, char **capsudod_argv, int capsudod_argc)
{
	char prompt[512];
	format_prompt(prompt, sizeof prompt, user);

	struct capsudo_message hdr;
	if (!recv_header_no_rights(clientfd, &hdr))
	{
		send_error_and_close(clientfd, CAPSUDO_UNAUTHORIZED, prompt);
		return;
	}

	if (hdr.fieldtype != CAPSUDO_SECRET)
	{
		if (hdr.length > 0 && hdr.length <= 4096)
		{
			char *tmp = malloc(hdr.length);

			if (tmp != NULL)
			{
				(void) recv_exact(clientfd, tmp, hdr.length);
				free(tmp);
			}
		}

		send_error_and_close(clientfd, CAPSUDO_UNAUTHORIZED, prompt);
		return;
	}

	if (hdr.length == 0 || hdr.length > 4096)
	{
		send_error_and_close(clientfd, CAPSUDO_ERROR, "invalid secret length");
		return;
	}

	char *secret = calloc(1, hdr.length);
	if (secret == NULL)
	{
		send_error_and_close(clientfd, CAPSUDO_ERROR, "out of memory");
		return;
	}

	if (!recv_exact(clientfd, secret, hdr.length))
	{
		wipe_free(secret);
		close(clientfd);
		return;
	}

	secret[hdr.length - 1] = '\0';
	if (secret[0] == '\0')
	{
		wipe_free(secret);
		send_error_and_close(clientfd, CAPSUDO_ERROR, "empty secret");
		return;
	}

	bool ok = shadow_check_password(user, secret);
	wipe_free(secret);

	if (!ok)
	{
		send_error_and_close(clientfd, CAPSUDO_ERROR, "secret invalid");
		return;
	}

	pid_t pid = fork();
	if (pid < 0)
	{
		send_error_and_close(clientfd, CAPSUDO_ERROR, "internal error");
		return;
	}

	if (pid == 0)
	{
		close(sockfd);

		if (dup2(clientfd, 0) < 0)
			_exit(127);
		if (clientfd != 0)
			close(clientfd);

		if (capsudod_argc > 0) {
			execvp(capsudod_path, capsudod_argv);
			_exit(127);
		}

		char *const av[] = { (char *)capsudod_path, NULL };
		execvp(capsudod_path, av);
		_exit(127);
	}

	/* Parent */
	close(clientfd);
}

int main(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "S:d:o:m:")) != -1)
	{
		switch (opt)
		{
		case 'S':
			listen_sock = optarg;
			break;
		case 'd':
			capsudod_path = optarg;
			break;
		case 'o':
			if (!parse_owner_spec(optarg, &socket_uid, &socket_gid))
				errx(EXIT_FAILURE, "invalid owner spec: %s", optarg);
			break;
		case 'm':
			if (!parse_mode(optarg, &socket_mode))
				errx(EXIT_FAILURE, "invalid mode: %s", optarg);
			break;
		default:
			usage();
		}
	}

	if (!listen_sock)
		usage();

	/* Everything after -- goes to capsudod */
	char **capsudod_argv = &argv[optind];
	int capsudod_argc = argc - optind;

	if (capsudod_argc > 0 && strcmp(capsudod_argv[0], "--") == 0)
	{
		capsudod_argv++;
		capsudod_argc--;
	}

	int sockfd = open_listener(listen_sock, socket_uid, socket_gid, socket_mode);

	for (;;)
	{
		int clientfd = accept(sockfd, NULL, NULL);
		if (clientfd < 0)
		{
			if (errno == EINTR)
				continue;
			err(EXIT_FAILURE, "accept");
		}

		const char *user = username_from_peercred(clientfd);
		if (!user)
		{
			send_error_and_close(clientfd, CAPSUDO_ERROR, "unable to determine peer user");
			continue;
		}

		handle_client(sockfd, clientfd, user, capsudod_argv, capsudod_argc);
	}
}
