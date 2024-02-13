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
#if HAVE_ERR
# include <err.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <paths.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if HAVE_SCAN_SCALED
# include <util.h>
#endif

#include "extern.h"
#include "daemon.h"

#ifndef _PATH_ETC
#define	_PATH_ETC	"/etc"
#endif

#define	_PATH_RSYNCD_CONF	_PATH_ETC "/rsyncd.conf"

extern struct cleanup_ctx	*cleanup_ctx;

static const char proto_prefix[] = "@RSYNCD: ";

enum {
	OP_DAEMON = CHAR_MAX + 1,
	OP_NO_DETACH,
	OP_ADDRESS,
	OP_BWLIMIT,
	OP_CONFIG,
	OP_PORT,
	OP_LOG_FILE,
	OP_LOG_FILE_FORMAT,
	OP_SOCKOPTS,
};

static const struct option	daemon_lopts[] = {
	{ "address",	required_argument,	NULL,		OP_ADDRESS },
	{ "bwlimit",	required_argument,	NULL,		OP_BWLIMIT },
	{ "config",	required_argument,	NULL,		OP_CONFIG },
	{ "daemon",	no_argument,	NULL,			OP_DAEMON },
	{ "no-detach",	no_argument,	NULL,			OP_NO_DETACH },
	{ "ipv4",	no_argument,	NULL,			'4' },
	{ "ipv6",	no_argument,	NULL,			'6' },
	{ "help",	no_argument,	NULL,			'h' },
	{ "log-file",	required_argument,	NULL,		OP_LOG_FILE },
#if 0
	{ "log-file-format",	required_argument,	NULL,	OP_LOG_FILE_FORMAT },
#endif
	{ "port",	required_argument,	NULL,		OP_PORT },
	{ "sockopts",	required_argument,	NULL,		OP_SOCKOPTS },
	{ "verbose",	no_argument,		NULL,		'v' },
	{ NULL,		0,		NULL,			0 },
};

static void
daemon_usage(int exitcode)
{
	fprintf(exitcode == 0 ? stdout : stderr, "usage: %s --daemon"
	    " [-46hv] [--address=bindaddr] [--bwlimit=limit] [--no-detach]\n"
	    "\t[--log-file=logfile] [--port=portnumber] [--sockopts=sockopts]\n",
	    getprogname());
	exit(exitcode);
}

static int
daemon_list_module(struct daemon_cfg *dcfg, const char *module, void *cookie)
{
	struct sess *sess;
	struct daemon_role *role;
	char *buf;
	const char *comment;
	int fd, list, rc;

	sess = cookie;
	role = (void *)sess->role;
	fd = role->client;

	if (cfg_param_bool(dcfg, module, "list", &list) != 0) {
		ERRX("%s: 'list' is not valid", module);
		return 0;
	}

	if (!list)
		return 1;

	if (!cfg_has_param(dcfg, module, "comment")) {
		if (!io_write_line(sess, fd, module)) {
			ERR("io_write_line");
			return 0;
		}

		return 1;
	}

	rc = cfg_param_str(dcfg, module, "comment", &comment);
	assert(rc == 0);

	if (asprintf(&buf, "%-15s%s", module, comment) == -1) {
		ERR("asprintf");
		return 0;
	}


	if (!io_write_line(sess, fd, buf)) {
		free(buf);
		ERR("io_write_line");
		return 0;
	}

	free(buf);
	return 1;
}

static int
daemon_list(struct sess *sess)
{
	struct daemon_role *role;

	role = (void *)sess->role;
	return cfg_foreach_module(role->dcfg, daemon_list_module, sess);
}

static int
daemon_read_hello(struct sess *sess, int fd, char **module)
{
	char buf[BUFSIZ];
	size_t linesz;

	/*
	 * Client is waiting for us to respond, so just grab everything we can.
	 * It should have sent us exactly two lines:
	 *   @RSYNCD: <version>\n
	 *   <module>\n
	 */
	sess->rver = -1;
	*module = NULL;

	for (size_t linecnt = 0; linecnt < 2; linecnt++) {
		linesz = sizeof(buf);
		if (!io_read_line(sess, fd, buf, &linesz) ||
		    (linesz == 0 && linecnt == 0)) {
			/*
			 * An empty line is an error, unless we already have our
			 * version information.  If we only receive version
			 * information, it's implied that the client just wants
			 * a listing.
			 */
			daemon_client_error(sess,
			    "protocol violation: expected version and module information");
			return -1;
		} else if (linesz == sizeof(buf)) {
			daemon_client_error(sess, "line buffer overrun");
			errno = EINVAL;
			return -1;
		}

		if (linecnt == 0) {
			const char *line;
			int major, minor;

			line = buf;
			if (strncmp(line, proto_prefix,
			    sizeof(proto_prefix) - 1) != 0) {
				daemon_client_error(sess,
				    "protocol violation: expected version line, got '%s'",
				    line);
				errno = EINVAL;
				return -1;
			}

			line += sizeof(proto_prefix) - 1;

			/*
			 * XXX Modern rsync sends:
			 * @RSYNCD: <version>.<subprotocol> <digest1> <digestN>
			 * @RSYNCD: 31.0 sha512 sha256 sha1 md5 md4
			 */
			if (sscanf(line, "%d.%d", &major, &minor) == 2) {
				sess->rver = major;
			} else if (sscanf(line, "%d", &major) == 1) {
				sess->rver = major;
			} else {
				daemon_client_error(sess,
				   "protocol violation: malformed version line, got '%s'",
				    line);
				errno = EINVAL;
				return -1;
			}

			/*
			 * Discard the rest of the line, respond with our
			 * protocol version.
			 */
			(void)snprintf(buf, sizeof(buf), "@RSYNCD: %d",
			    sess->lver);

			if (!io_write_line(sess, fd, buf)) {
				/* XXX OS ERR */
				return -1;
			}
		} else {
			if (linesz == 0) {
				*module = strdup("#list");
			} else {
				*module = strdup(buf);
			}

			if (*module == NULL) {
				ERR("strdup");
				return -1;
			}
		}
	}

	return 0;
}

static int
daemon_read_options(struct sess *sess, int fd, int *oargc, char ***oargv)
{
	char buf[BUFSIZ];
	char **argv, **pargv;
	size_t argc, argvsz, linesz, nextsz;

	argv = NULL;
	argc = nextsz = 0;

	/*
	 * At a minimum we'll have these three lines:
	 *
	 * --server
	 * .
	 * <module>[/<path>]
	 *
	 * So we'll start with an array sized for 4 arguments to allow a little
	 * wiggle room, and we'll allocate in groups of 5 as we need more.
	 */
#define	OPT_ALLOC_SLOTS	5
	argvsz = OPT_ALLOC_SLOTS;
	argv = recallocarray(argv, 0, OPT_ALLOC_SLOTS, sizeof(*argv));
	if (argv == NULL) {
		daemon_client_error(sess, "daemon out of memory");
		return -1;
	}

	/* Fake first arg, because we can't actually reset to the 0'th argv */
	argv[argc++] = NULL;

	for (;;) {
		linesz = sizeof(buf);
		if (!io_read_line(sess, fd, buf, &linesz)) {
			daemon_client_error(sess,
			    "protocol violation: expected option line");
			errno = EINVAL;
			return -1;
		} else if (linesz == sizeof(buf)) {
			daemon_client_error(sess, "line buffer overrun");
			errno = EINVAL;
			return -1;
		} else if (linesz == 0) {
			break;
		}

		if (argc == INT_MAX) {
			/* XXX Do we want to limit byte size as well? */
			daemon_client_error(sess,
			    "protection error: too many arguments sent");
			goto fail;
		}

		/*
		 * If argc == argvsz, we need more to be able to null terminate
		 * the array properly.
		 */
		if (argc == argvsz) {
			pargv = argv;
			nextsz = argvsz + OPT_ALLOC_SLOTS;
			argv = recallocarray(pargv, argvsz, nextsz,
			    sizeof(*argv));
			if (argv == NULL) {
				daemon_client_error(sess,
				    "daemon out of memory");
				argv = pargv;
				goto fail;
			}
		}

		argv[argc] = strdup(buf);
		if (argv[argc] == NULL) {
			daemon_client_error(sess, "daemon out of memory");
			goto fail;
		}

		argc++;
	}

	*oargc = argc;
	*oargv = argv;
	return 0;
fail:
	for (size_t i = 0; i < argc; i++)
		free(argv[i]);
	free(argv);
	return -1;
}

static int
daemon_reject(struct sess *sess, int opt, const struct option *lopt)
{

	if (lopt != NULL && strcmp(lopt->name, "daemon") == 0) {
		daemon_client_error(sess,
		    "protection error: --daemon sent as client option");
		return 0;
	}

	return 1;
}

static int
daemon_write_motd(struct sess *sess, const char *motd_file, int outfd)
{
	FILE *fp;
	char *line;
	size_t linesz;
	ssize_t linelen;
	int retval;

	/* Errors largely ignored, maybe logged. */
	if (motd_file[0] == '\0')
		return 1;

	line = NULL;
	linesz = 0;
	fp = fopen(motd_file, "r");
	if (fp == NULL) {
		/* XXX Log */
		return 1;
	}

	retval = 1;
	while ((linelen = getline(&line, &linesz, fp)) > 0) {
		if (!io_write_buf(sess, outfd, line, linelen)) {
			/* XXX Log */
			retval = 0;
			break;
		}
	}

	fclose(fp);
	free(line);
	return retval;
}

static int
daemon_extract_addr(struct sess *sess, struct sockaddr_storage *saddr,
    size_t slen)
{
	sa_family_t family = saddr->ss_family;
	struct daemon_role *role;
	void *addr;

	role = (void *)sess->role;
	assert(family == AF_INET || family == AF_INET6);
	if (family == AF_INET) {
		struct sockaddr_in *sin = (void *)saddr;

		addr = &sin->sin_addr;
	} else {
		struct sockaddr_in6 *sin6 = (void *)saddr;

		addr = &sin6->sin6_addr;
	}

	if (inet_ntop(family, addr, &role->client_addr[0],
	    sizeof(role->client_addr)) == NULL) {
		ERR("inet_ntop");
		return 0;
	}

	return 1;
}


static int
rsync_daemon_handler(struct sess *sess, int fd, struct sockaddr_storage *saddr,
    size_t slen)
{
	struct daemon_role *role;
	struct opts *client_opts;
	const char *module_path;
	char **argv, *module, *motd_file;
	int argc, flags, rc, use_chroot;

	module = NULL;
	argc = 0;
	argv = NULL;

	role = (void *)sess->role;
	role->client = fd;
	assert(role->lockfd == -1);

	motd_file = role->motd_file;
	role->motd_file = NULL;

	fclose(role->pidfp);
	cfg_free(role->dcfg);
	role->dcfg = NULL;

	/* XXX These should perhaps log an error, but they are not fatal. */
	(void)rsync_setsockopts(fd, "SO_KEEPALIVE");
	(void)rsync_setsockopts(fd, sess->opts->sockopts);

	if (!daemon_extract_addr(sess, saddr, slen))
		goto fail;

	sess->lver = RSYNC_PROTOCOL;

	cleanup_init(cleanup_ctx);

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1 ||
	    fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		daemon_client_error(sess, "failed to set non-blocking");
		goto fail;
	}

	role->dcfg = cfg_parse(sess, role->cfg_file, 1);
	if (role->dcfg == NULL)
		return ERR_IPC;

	/* saddr == NULL only for inetd driven invocations. */
	if (daemon_read_hello(sess, fd, &module) < 0)
		goto fail;	/* Error already logged. */

	/* XXX PROTOCOL_MIN, etc. */
	if (sess->rver < sess->lver) {
		daemon_client_error(sess,
		    "could not negotiate a protocol; client requested %d (supported range: %d to %d)",
		    sess->rver, sess->lver, sess->lver);
		goto fail;
	}

	/* Grab the motd before we free it. */
	rc = daemon_write_motd(sess, motd_file, fd);
	free(motd_file);
	motd_file = NULL;

	/* Fatal error, already logged. */
	if (!rc)
		goto fail;

	if (module[0] == '#') {
		/*
		 * This is actually a command, but the only command we know of
		 * at the moment is #list.  If we grow more, we can perhaps make
		 * this table-based instead of inlined.
		 */
		if (strcmp(module + 1, "list") != 0) {
			daemon_client_error(sess, "%s is not a known command",
			    module);
			goto fail;
		}

		if (!daemon_list(sess))
			goto fail;

		if (!io_write_line(sess, fd, "@RSYNCD: EXIT")) {
			ERR("io_write_line");
			goto fail;
		}

		goto done;
	} else if (!cfg_is_valid_module(role->dcfg, module)) {
		daemon_client_error(sess, "%s is not a valid module", module);
		goto fail;
	}

	if (!daemon_fill_hostinfo(sess, module,
	    (const struct sockaddr *)saddr, slen))
		goto fail;

	if (daemon_connection_limited(sess, module))
		goto fail;

	if (!daemon_setup_logfile(sess, module))
		goto fail;

	if (cfg_param_bool(role->dcfg, module, "use chroot",
	    &use_chroot) != 0) {
		/* Log it and pretend it's unset. */
		WARN("%s: 'use chroot' malformed", module);
	} else if (use_chroot && !cfg_has_param(role->dcfg, module,
	    "use chroot")) {
		/*
		 * If it's not set, note that in case it fails -- we will
		 * fallback.
		 */
		use_chroot = 2;
	}

	rc = cfg_param_str(role->dcfg, module, "path", &module_path);
	assert(rc == 0);

	/*
	 * Resolve UIDs/GIDs before we enter our chroot, just in case they're
	 * not strictly numeric.
	 */
	if (!daemon_chuser_setup(sess, module))
		goto fail;

	/*
	 * We don't currently support the /./ chroot syntax of rsync 3.x.
	 */
	chdir(module_path);
	if (use_chroot && chroot(".") == -1) {
		if (errno != EPERM || use_chroot == 1) {
			/* XXX Fail it. */
			goto fail;
		}

		WARN("%s: attempt to chroot failed, falling back to 'no' since it is not explicitly set",
		    module);
		use_chroot = 0;
	}

	role->client_control = true;

	if (!daemon_chuser(sess, module))
		goto fail;

	if (!io_write_line(sess, fd, "@RSYNCD: OK")) {
		ERRX1("io_write_line");
		goto fail;
	}

	if (daemon_read_options(sess, fd, &argc, &argv) < 0)
		goto fail;	/* Error already logged. */

	/*
	 * Reset some state; our default poll_timeout is no longer valid, and
	 * we need to reset getopt_long(3).  poll_timeout after this point will
	 * not be overwritten by the client unless the client wants a little bit
	 * longer.
	 */
	poll_timeout = 0;
	if (cfg_param_int(role->dcfg, module, "timeout", &poll_timeout) != 0)
		WARN("%s: bad value for 'timeout'", module);

	optreset = 1;
	optind = 1;
	client_opts = rsync_getopt(argc, argv, &daemon_reject, sess);
	if (client_opts == NULL)
		goto fail;	/* Should have been logged. */

	argc -= optind;
	argv += optind;

	if (strcmp(argv[0], ".") != 0) {
		daemon_client_error(sess,
		    "protocol violation: expected hard stop before file list");
		goto fail;
	}

	argc--;
	argv++;

	if (!daemon_operation_allowed(sess, client_opts, module))
		goto fail;	/* Error already logged. */

	if (!daemon_limit_verbosity(sess, module))
		goto fail;

	/* Generate a seed. */
	if (client_opts->checksum_seed == 0) {
#if HAVE_ARC4RANDOM
		sess->seed = arc4random();
#else
		sess->seed = random();
#endif
	} else {
		sess->seed = client_opts->checksum_seed;
	}

	/* Seed send-off completes the handshake. */
	if (!io_write_int(sess, fd, sess->seed)) {
		ERR("io_write_int");
		goto fail;
	}

	/* Strip any <module>/ off the beginning. */
	daemon_normalize_paths(module, argc, argv);

	/* Also from --files-from */
	if (client_opts->filesfrom_path != NULL)
		daemon_normalize_paths(module, 1, &client_opts->filesfrom_path);

	if (!daemon_set_numeric_ids(sess, client_opts, module, use_chroot))
		goto fail;

	sess->opts = client_opts;
	sess->mplex_writes = 1;
	/* XXX LOG2("write multiplexing enabled"); */

	cleanup_set_session(cleanup_ctx, sess);
	cleanup_release(cleanup_ctx);

	if (sess->opts->sender) {
		if (!rsync_sender(sess, fd, fd, argc, argv)) {
			ERR("rsync_sender");
			goto fail;
		}
	} else {
		if (!rsync_receiver(sess, cleanup_ctx, fd, fd, argv[0])) {
			ERR("rsync_receiver");
			goto fail;
		}
	}

done:
	if (role->lockfd != -1) {
		close(role->lockfd);
		role->lockfd = -1;
	}

	for (int i = 0; i < argc; i++)
		free(argv[i]);
	free(argv);

	return 0;

fail:
	free(module);
	cfg_free(role->dcfg);
	role->dcfg = NULL;
	if (role->lockfd != -1) {
		close(role->lockfd);
		role->lockfd = -1;
	}

	for (int i = 0; i < argc; i++)
		free(argv[i]);
	free(argv);

	return ERR_IPC;
}

static void
get_global_cfgstr(struct daemon_cfg *dcfg, const char *key, const char **out)
{
	int error;

	error = cfg_param_str(dcfg, "global", key, out);

	assert(error == 0);
}

static int
daemon_do_pidfile(struct sess *sess, struct daemon_cfg *dcfg)
{
	struct flock pidlock = {
		.l_start = 0,
		.l_len = 0,
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
	};
	FILE *pidfp;
	const char *pidfile;
	struct daemon_role *role = (struct daemon_role *)sess->role;

	/* If it's empty, nothing to do here. */
	get_global_cfgstr(dcfg, "pid file", &pidfile);
	if (*pidfile == '\0')
		return 0;

	pidfp = fopen(pidfile, "w");
	if (pidfp == NULL) {
		ERR("%s: fopen", pidfile);
		return -1;
	}

	if (fcntl(fileno(pidfp), F_SETLK, &pidlock)) {
		fclose(pidfp);
		if (errno == EAGAIN)
			ERRX("%s: failed to obtain lock (is another rsyncd running?)", pidfile);
		else
			ERR("%s: acquiring lock", pidfile);
		return -1;
	}

	fprintf(pidfp, "%d\n", getpid());
	fflush(pidfp);

	role->pid_file = pidfile;
	role->pidfp = pidfp;
	return 0;
}

int
rsync_daemon(int argc, char *argv[], struct opts *daemon_opts)
{
	struct sess sess;
	struct daemon_role role;
	long long tmpint;
	const char *cfg_motd, *logfile;
	int c, opt_daemon = 0, detach = 1, rc;

	/* Start with a fresh session / opts */
	memset(&role, 0, sizeof(role));
	memset(daemon_opts, 0, sizeof(*daemon_opts));
	memset(&sess, 0, sizeof(sess));
	sess.opts = daemon_opts;
	sess.role = (void *)&role;

	role.cfg_file = "/etc/rsyncd.conf";
	role.client = -1;
	role.lockfd = -1;
	/* Log to syslog by default. */
	logfile = NULL;

	/*
	 * optind starting at 1, because we're parsing the original program args
	 * and should skip argv[0].
	 */
	optreset = 1;
	optind = 1;
	while ((c = getopt_long(argc, argv, "46hv", daemon_lopts,
	    NULL)) != -1) {
		switch (c) {
		case OP_ADDRESS:
			daemon_opts->address = optarg;
			break;
		case OP_BWLIMIT:
			if (scan_scaled_def(optarg, &tmpint, 'k') == -1)
				err(1, "bad bwlimit");
			daemon_opts->bwlimit = tmpint;
			break;
		case OP_CONFIG:
			role.cfg_file = optarg;
			break;
		case OP_DAEMON:
			if (++opt_daemon > 1) {
				errx(ERR_SYNTAX,
				    "--daemon may not be specified multiple times");
			}
			break;
		case OP_NO_DETACH:
			detach = 0;
			break;
		case OP_LOG_FILE:
			logfile = optarg;
			break;
		case OP_PORT:
			daemon_opts->port = optarg;
			break;
		case OP_SOCKOPTS:
			daemon_opts->sockopts = optarg;
			break;
		case '4':
			daemon_opts->ipf = 4;
			break;
		case '6':
			daemon_opts->ipf = 6;
			break;
		case 'h':
			daemon_usage(0);
			break;
		case 'v':
			verbose++;
			break;
		default:
			daemon_usage(ERR_SYNTAX);
		}
	}

	argc -= optind;
	argv += optind;

	if (!daemon_open_logfile(logfile, true))
		return ERR_IPC;

	/*
	 * The reference rsync doesn't seem to complain about extra non-option
	 * arguments, though they aren't documented to do anything.
	 */

	poll_timeout = -1;

	if (rsync_is_socket(STDIN_FILENO))
		return rsync_daemon_handler(&sess, STDIN_FILENO, NULL, 0);

	if (detach && daemon(0, 0) == -1)
		err(ERR_IPC, "daemon");

	role.dcfg = cfg_parse(&sess, role.cfg_file, 0);
	if (role.dcfg == NULL)
		return ERR_IPC;

	if (daemon_do_pidfile(&sess, role.dcfg) != 0)
		return ERR_IPC;

	if (daemon_opts->address == NULL) {
		if (cfg_param_str(role.dcfg, "global", "address",
		    &daemon_opts->address) == -1) {
			assert(errno != ENOENT);
		} else {
			if (*daemon_opts->address == '\0')
				daemon_opts->address = NULL;
		}
	}

	/*
	 * "rsync" is set as our default value, so if it's not found
	 * we'll get that.  We'll only fetch it if it wasn't specified via
	 * arguments.
	 */
	if (daemon_opts->port == NULL)
		get_global_cfgstr(role.dcfg, "port", &daemon_opts->port);

	/* Grab the motd filename, too. */
	get_global_cfgstr(role.dcfg, "motd file", &cfg_motd);
	role.motd_file = strdup(cfg_motd);
	if (role.motd_file == NULL)
		err(ERR_IPC, "strdup");

	if (daemon_opts->sockopts == NULL)
		get_global_cfgstr(role.dcfg, "socket options",
		    &daemon_opts->sockopts);

	LOG0("openrsync listening on port '%s'", daemon_opts->port);

	rc = rsync_listen(&sess, &rsync_daemon_handler);
	if (role.pidfp != NULL) {
		/*
		 * We still have the lock, so we can safely unlink and close it.
		 * Failure doesn't change our exit disposition; it's not a
		 * critical issue to have an unlocked stale pidfile laying
		 * around.
		 */
		(void)unlink(role.pid_file);
		fclose(role.pidfp);
	}

	return rc;
}
