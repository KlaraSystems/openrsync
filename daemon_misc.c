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
#include <grp.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "daemon.h"

_Static_assert(sizeof(id_t) <= INT_MAX, "{u,g}id_t larger than expected");

static int daemon_rangelock(struct sess *, const char *, const char *, int);

/* Compatible with smb rsync, just in case. */
#define	CONNLOCK_START(conn)	((conn) * 4)
#define	CONNLOCK_SIZE(conn)	(4)

static int
daemon_chuser_resolve_name(const char *name, bool is_gid, id_t *oid)
{
	struct passwd *pwd;
	struct group *grp;
	char *endp;
	long long rid;

	if (is_gid) {
		grp = getgrnam(name);
		if (grp != NULL) {
			*oid = grp->gr_gid;
			return 1;
		}
	} else {
		pwd = getpwnam(name);
		if (pwd != NULL) {
			*oid = pwd->pw_uid;
			return 1;
		}
	}

	errno = 0;
	rid = strtoll(name, &endp, 10);
	if (errno != 0 || *endp != '\0')
		return 0;

	if (rid < INT_MIN || rid > INT_MAX)
		return 0;

	*oid = (id_t)rid;
	return 1;
}

int
daemon_chuser_setup(struct sess *sess, const char *module)
{
	struct daemon_role *role;
	const char *gidstr, *uidstr;
	int rc;

	role = (void *)sess->role;
	role->do_setid = geteuid() == 0;

	/* If we aren't root, nothing to do. */
	if (!role->do_setid)
		return 1;

	rc = cfg_param_str(role->dcfg, module, "uid", &uidstr);
	assert(rc == 0);
	if (!daemon_chuser_resolve_name(uidstr, false, &role->uid)) {
		daemon_client_error(sess, "%s: uid '%s' invalid",
		    module, uidstr);
		return 0;
	}

	rc = cfg_param_str(role->dcfg, module, "gid", &gidstr);
	assert(rc == 0);
	if (!daemon_chuser_resolve_name(gidstr, true, &role->gid)) {
		daemon_client_error(sess, "%s: gid '%s' invalid",
		    module, gidstr);
		return 0;
	}

	return 1;
}

int
daemon_chuser(struct sess *sess, const char *module)
{
	struct daemon_role *role;

	role = (void *)sess->role;

	if (!role->do_setid)
		return 1;
	if (role->gid != 0 && setgid((gid_t)role->gid) == -1) {
		daemon_client_error(sess, "%s: setgid to '%d' failed",
		    module, role->gid);
		return 0;
	}
	if (role->uid != 0 && setuid((uid_t)role->uid) == -1) {
		daemon_client_error(sess, "%s: setuid to '%d' failed",
		    module, role->uid);
		return 0;
	}

	return 1;
}

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

static long
parse_addr(sa_family_t family, const char *strmask, struct sockaddr *maskaddr)
{
	void *addr;

	if (family == AF_INET) {
		struct sockaddr_in *sin = (void *)maskaddr;

		addr = &sin->sin_addr;
	} else {
		struct sockaddr_in6 *sin6 = (void *)maskaddr;

		addr = &sin6->sin6_addr;
	}

	if (inet_pton(family, strmask, addr) != 1)
		return 0;

	maskaddr->sa_family = family;
	return 1;
}

static long
parse_mask(sa_family_t family, const char *strmask, struct sockaddr *maskaddr)
{
	char *endp;
	unsigned long mask;

	errno = 0;
	mask = strtoul(strmask, &endp, 10);
	if (errno == 0 && *endp == '\0') {
		uint8_t *addr;
		size_t addrsz, nbytes;
		int rem;

		/* No sanity checking at all. */
		if (family == AF_INET) {
			struct sockaddr_in *sin = (void *)maskaddr;

			addr = (uint8_t *)&sin->sin_addr;
			addrsz = sizeof(sin->sin_addr);
		} else {
			struct sockaddr_in6 *sin6 = (void *)maskaddr;

			addr = (uint8_t *)&sin6->sin6_addr;
			addrsz = sizeof(sin6->sin6_addr);
		}

		memset(addr, 0, addrsz);

		/* Invalid...  */
		if (mask > (addrsz << 3))
			return 0;

		/*
		 * We can memset up until the last byte of the mask, then
		 * set the remainder manually.
		 */
		nbytes = mask >> 3;

		/* Recalculate our last byte's worth, if any. */
		rem = mask & 0x07;	/* Truncated bits */
		mask = ~((1 << (8 - rem)) - 1);

		memset(addr, 0xff, nbytes);
		if (rem != 0)
			addr[nbytes] |= mask;

		return 1;
	}

	/* Must be an address mask... */
	if (parse_addr(family, strmask, maskaddr))
		return 1;
	return 0;
}

static int
masked_match(char *host, struct sockaddr *addr)
{
	struct sockaddr_storage hostaddr, maskaddr;
	uint8_t *laddr, *maddr, *raddr;
	char *strmask;
	size_t addrsz;
	sa_family_t family;

	family = addr->sa_family;
	strmask = strrchr(host, '/');
	assert(strmask != NULL);

	if (!parse_mask(family, strmask + 1, (struct sockaddr *)&maskaddr))
		return 0;

	*strmask = '\0';

	if (!parse_addr(family, host, (struct sockaddr *)&hostaddr))
		return 0;

	if (family == AF_INET) {
		struct sockaddr_in *left, *right, *mask;

		left = (struct sockaddr_in *)&hostaddr;
		right = (struct sockaddr_in *)addr;
		mask = (struct sockaddr_in *)&maskaddr;

		laddr = (uint8_t *)&left->sin_addr;
		raddr = (uint8_t *)&right->sin_addr;
		maddr = (uint8_t *)&mask->sin_addr;
		addrsz = sizeof(left->sin_addr);
	} else {
		struct sockaddr_in6 *left, *right, *mask;

		left = (struct sockaddr_in6 *)&hostaddr;
		right = (struct sockaddr_in6 *)addr;
		mask = (struct sockaddr_in6 *)&maskaddr;

		laddr = (uint8_t *)&left->sin6_addr;
		raddr = (uint8_t *)&right->sin6_addr;
		maddr = (uint8_t *)&mask->sin6_addr;
		addrsz = sizeof(left->sin6_addr);
	}

	/* Finally, compare the two. */
	for (size_t i = 0; i < addrsz; i++) {
		if (((laddr[i] ^ raddr[i]) & maddr[i]) != 0)
			return 0;
	}

	return 1;
}

static int
daemon_connection_matches_one(const struct sess *sess, char *host)
{
	const struct daemon_role *role;
	const char *addr, *masked;

	role = (void *)sess->role;
	if (role->client_host[0] != '\0' &&
	    rmatch(host, role->client_host, 0) == 0)
		return 1;

	masked = strrchr(host, '/');
	addr = &role->client_addr[0];
	if (masked == NULL)
		return strcmp(host, addr) == 0;

	return masked_match(host, role->client_sa);
}

static int
daemon_connection_matches(struct sess *sess, const char *hostlistp, bool *match,
    int *total)
{
	char *host, *hostlist;
	int cnt;
	bool matched;

	hostlist = strdup(hostlistp);
	if (hostlist == NULL) {
		daemon_client_error(sess, "out of memory");
		return -1;
	}

	cnt = 0;
	matched = false;
	while ((host = strsep(&hostlist, ", \t")) != NULL) {
		if (*host == '\0')
			continue;

		cnt++;

		/* Check host */
		if (daemon_connection_matches_one(sess, host)) {
			matched = true;
			break;
		}
	}

	*total = cnt;
	*match = matched;

	free(hostlist);
	return 0;
}

/* Check 'hosts allow' and 'hosts deny' */
int
daemon_connection_allowed(struct sess *sess, const char *module)
{
	struct daemon_role *role;
	const char *hostlist;
	int allowcnt, denycnt, rc;
	bool has_deny, matched;

	role = (void *)sess->role;

	allowcnt = denycnt = 0;
	has_deny = cfg_has_param(role->dcfg, module, "hosts deny");
	if (cfg_has_param(role->dcfg, module, "hosts allow")) {
		rc = cfg_param_str(role->dcfg, module, "hosts allow",
		    &hostlist);
		assert(rc == 0);

		/* Fail safe, don't allow if we failed to parse. */
		if (daemon_connection_matches(sess, hostlist,
		    &matched, &allowcnt) == -1) {
			daemon_client_error(sess, "failed to process allow host list");
			return 0;
		}

		if (allowcnt > 0) {
			if (matched)
				return 1;

			if (!has_deny) {
				daemon_client_error(sess,
				    "access denied by allow policy from %s [%s]",
				    role->client_host, role->client_addr);
				return 0;
			}
		}
	}

	if (has_deny) {
		rc = cfg_param_str(role->dcfg, module, "hosts deny",
		    &hostlist);
		assert(rc == 0);

		/* Fail safe, don't allow if we failed to parse. */
		if (daemon_connection_matches(sess, hostlist,
		    &matched, &denycnt) == -1) {
			daemon_client_error(sess, "failed to process deny host list");
			return 0;
		}

		if (denycnt > 0) {
			if (matched) {
				daemon_client_error(sess,
				    "access denied by deny policy from %s [%s]",
				    role->client_host, role->client_addr);
				return 0;
			}
		} else if (allowcnt > 0) {
			/*
			 * We had an allow list and we thought we had a deny
			 * list, but we parsed the list only to discover it was
			 * actually empty.  Deny the connection, since they were
			 * not allowed by the allow list.
			 */
			daemon_client_error(sess,
			    "access denied by allow policy from %s [%s]",
			    role->client_host, role->client_addr);
			return 0;
		}
	}

	/* Default policy is to accept all. */
	return 1;
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
daemon_fill_hostinfo(struct sess *sess, const char *module,
    const struct sockaddr *addr, size_t slen)
{
	struct daemon_role *role;

	role = (void *)sess->role;

	/*
	 * Nothing left to do here, nothing configured that needs reverse dns.
	 */
	if (!cfg_has_param(role->dcfg, module, "hosts allow") &&
	    !cfg_has_param(role->dcfg, module, "hosts deny"))
		return 1;

	if (getnameinfo(addr, slen, &role->client_host[0],
	    sizeof(role->client_host), NULL, 0, 0) != 0) {
		daemon_client_error(sess, "%s: reverse dns lookup failed: %s",
		    module, strerror(errno));
		return 0;
	}

	return 1;
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
    const char *module, int user_read_only)
{
	struct daemon_role *role;
	int deny;

	role = (void *)sess->role;
	if (!opts->sender) {
		/* Client wants to send files, check read only. */
		if (user_read_only != -1) {
			deny = user_read_only;
		} else if (cfg_param_bool(role->dcfg, module, "read only",
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
