/*
 * Copyright (c) 2024 Klara, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "config.h"

#include <sys/types.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "daemon.h"


static int daemon_rangelock(struct sess *, const char *, const char *, int);

/* Compatible with smb rsync, just in case. */
#define	CONNLOCK_START(conn)	((conn) * 4)
#define	CONNLOCK_SIZE(conn)	(4)

void
daemon_client_error(struct sess *sess, const char *fmt, ...)
{
	struct daemon_role *role;
	char *msg;
	va_list ap;

	role = (void *)sess->role;

	if (!role->client_control) {
		va_start(ap, fmt);
		if (vasprintf(&msg, fmt, ap) != -1) {
			if (!io_write_buf(sess, role->client, "@ERROR ",
			    sizeof("@ERROR ") - 1) ||
			    !io_write_line(sess, role->client, msg)) {
				/* XXX Log the additional error. */
			}
			free(msg);
		}
		va_end(ap);
	}

	/*
	 * We may want to log this to the log file as well, but for now we'll
	 * settle on just making the client aware.
	 */
}

/*
 * Return value of this one is reversed, as we're describing whether the
 * connection is being limited from happening or not.
 */
int
daemon_connection_limited(struct sess *sess, const char *module)
{
	struct daemon_role *role;
	const char *lockf;
	int max, rc;

	role = (void *)sess->role;
	if (cfg_param_int(role->dcfg, module, "max connections", &max) != 0) {
		ERRX("%s: 'max connections' invalid", module);
		return 1;
	}

	if (max < 0) {
		/* Disabled */
		daemon_client_error(sess,
		    "module '%s' is currently disabled", module);
		return 1;
	} else if (max == 0) {
		/* Unlimited allowed */
		return 0;
	}

	rc = cfg_param_str(role->dcfg, module, "lock file", &lockf);
	assert(rc == 0);

	if (*lockf == '\0') {
		ERR("%s: 'lock file' is empty with 'max connections' in place", module);
		return 1;
	}

	return !daemon_rangelock(sess, module, lockf, max);
}

int
daemon_limit_verbosity(struct sess *sess, const char *module)
{
	struct daemon_role *role;
	int max;

	role = (void *)sess->role;
	if (cfg_param_int(role->dcfg, module, "max verbosity", &max) != 0) {
		ERRX("%s: 'max verbosity' invalid", module);
		return 0;
	}

	verbose = MINIMUM(verbose, max);
	return 1;
}

void
daemon_normalize_paths(const char *module, int argc, char *argv[])
{
	char *path;
	size_t modlen, pathlen;

	modlen = strlen(module);
	for (int i = 0; i < argc; i++) {
		path = argv[i];

		/* Search for <module>[/...] */
		if (strncmp(path, module, modlen) != 0 ||
		    (path[modlen] != '/' && path[modlen] != '\0'))
			continue;

		/*
		 * If we just had <module> and not <module>/..., then we can
		 * just truncate it entirely.
		 */
		if (path[modlen] == '\0') {
			path[0] = '\0';
			continue;
		}

		/*
		 * Strip the leading <module>/ prefix.  Any unprefixed paths are
		 * assumed to be relative to the module root anyways.
		 */
		pathlen = strlen(&path[modlen + 1]);
		memmove(&path[0], &path[modlen + 1],  pathlen + 1);
	}
}

int
daemon_open_logfile(const char *logfile, bool printerr)
{

	if (logfile != NULL && *logfile == '\0')
		logfile = NULL;
	if (logfile != NULL) {
		FILE *fp;

		fp = fopen(logfile, "a");
		if (fp == NULL) {
			if (printerr)
				ERR("%s: fopen", logfile);
			return 0;
		}

		/*
		 * Logging infrastructure will take the FILE and close it if we
		 * switch away later.
		 */
		rsync_set_logfile(fp);
	} else {
		rsync_set_logfile(NULL);
	}

	return 1;
}

int
daemon_operation_allowed(struct sess *sess, const struct opts *opts,
    const char *module)
{
	struct daemon_role *role;
	int deny;

	role = (void *)sess->role;
	if (!opts->sender) {
		/* Client wants to send files, check read only. */
		if (cfg_param_bool(role->dcfg, module, "read only",
		    &deny) != 0) {
			ERRX("%s: 'read only' invalid", module);
			return 0;
		}
	} else {
		/* Client wants to receive files, check write only. */
		if (cfg_param_bool(role->dcfg, module, "write only",
		    &deny) != 0) {
			ERRX("%s: 'write only' invalid", module);
			return 0;
		}
	}

	if (deny) {
		daemon_client_error(sess, "module '%s' is %s-protected",
		    module, opts->sender ? "read" : "write");
	}

	return !deny;
}

static int
daemon_rangelock(struct sess *sess, const char *module, const char *lockf,
    int max)
{
	struct flock rlock = {
		.l_start = 0,
		.l_len = 0,
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
	};
	struct daemon_role *role;
	int fd, rc;

	role = (void *)sess->role;
	fd = open(lockf, O_WRONLY | O_CREAT, 0644);
	if (fd == -1) {
		daemon_client_error(sess, "%s: failed to open the lock file",
		    module);
		return 0;
	}

	/*
	 * We naturally can't guarantee a specific slot, so search the entire
	 * space until we find an open one.
	 */
	for (int i = 0; i < max; i++) {
		rlock.l_start = CONNLOCK_START(i);
		rlock.l_start = CONNLOCK_SIZE(i);

		rc = fcntl(fd, F_SETLK, &rlock);
		if (rc == -1 && errno != EAGAIN) {
			/*
			 * We won't alert the client on these, apparently.
			 */
			ERR("%s: lock fcntl", lockf);
			break;
		} else if (rc == -1) {
			continue;
		}

		/* Success! Stash the fd. */
		role->lockfd = fd;
		return 1;
	}

	daemon_client_error(sess, "%s: too many connections (%d max)", module,
	    max);
	close(fd);
	return 0;
}

int
daemon_set_numeric_ids(struct sess *sess, struct opts *opts,
    const char *module, int use_chroot)
{
	struct daemon_role *role;
	int bnids;

	role = (void *)sess->role;

	/* If the client requested --numeric-ids, we'll just leave it be. */
	if (opts->numeric_ids != NIDS_OFF)
		return 1;

	/*
	 * If the parameter's not been specified, then its default depends on
	 * whether we're chrooted or not.  Note that `use_chroot` may be 0, 1,
	 * or 2, but the distinction between 1 and 2 (must chroot, try chroot)
	 * does not mattter because the caller shouldn't pass a try chroot if
	 * the chroot failed.
	 */
	if (!cfg_has_param(role->dcfg, module, "numeric ids")) {
		/*
		 * The client isn't aware that we're running with --numeric-ids,
		 * so we had to make this a tri-state to support a mode where we
		 * still send an empty list.
		 */
		if (use_chroot)
			opts->numeric_ids = NIDS_STEALTH;
		else
			opts->numeric_ids = NIDS_OFF;
		return 1;
	}

	/*
	 * Otherwise, we'll defer to a config-set value of numeric ids to
	 * determine if we're doing it or not.
	 */
	if (cfg_param_bool(role->dcfg, module, "numeric ids", &bnids) != 0) {
		ERR("%s: 'numeric ids' invalid", module);
		return 0;
	}

	if (bnids)
		opts->numeric_ids = NIDS_STEALTH;

	return 1;
}

int
daemon_setup_logfile(struct sess *sess, const char *module)
{
	struct daemon_role *role;
	const char *logfile;
	int rc;
	bool syslog = false;

	role = (void *)sess->role;
	logfile = NULL;
	if (cfg_has_param(role->dcfg, module, "log file")) {
		rc = cfg_param_str(role->dcfg, module, "log file", &logfile);
		assert(rc == 0);
	}

	if (logfile == NULL || *logfile == '\0')
		return 1;

	if (!daemon_open_logfile(logfile, false)) {
		/* Just fallback to syslog on error. */
		if (!daemon_open_logfile(NULL, false))
			return 0;

		syslog = true;
	}

	/* Setup syslog facility, if we ended up with syslog. */
	if (syslog) {
		const char *facility;

		rc = cfg_param_str(role->dcfg, module, "syslog facility",
		    &facility);
		assert(rc == 0);

		if (rsync_set_logfacility(facility) != 0) {
			ERRX1("%s: 'syslog facility' does not exist: %s",
			    module, facility);
			return 0;
		}
	}

	return 1;
}
