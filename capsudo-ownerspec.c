#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "capsudo-ownerspec.h"

bool parse_mode(const char *spec, mode_t *mode_out)
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

bool parse_owner_spec(const char *spec, uid_t *uid_out, gid_t *gid_out)
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
