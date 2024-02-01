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
#include <getopt.h>
#include <limits.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if HAVE_SCAN_SCALED
# include <util.h>
#endif

#include "extern.h"

#ifndef _PATH_ETC
#define	_PATH_ETC	"/etc"
#endif

#define	_PATH_RSYNCD_CONF	_PATH_ETC "/rsyncd.conf"

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
#if 0
	{ "log-file",	required_argument,	NULL,		OP_LOG_FILE },
	{ "log-file-format",	required_argument,	NULL,	OP_LOG_FILE_FORMAT },
#endif
	{ "port",	required_argument,	NULL,		OP_PORT },
	{ "sockopts",	required_argument,	NULL,		OP_SOCKOPTS },
	{ "verbose",	no_argument,		NULL,		'v' },
	{ NULL,		0,		NULL,			0 },
};

struct daemon_role {
	struct role		 role;
	const char		*cfg_file;
	struct daemon_cfg	*dcfg;
};

static void
daemon_usage(int exitcode)
{
	fprintf(exitcode == 0 ? stdout : stderr, "usage: %s --daemon"
	    " [-46hv] [--address=bindaddr] [--bwlimit=limit] [--no-detach]\n"
	    "\t[--port=portnumber] [--sockopts=sockopts]\n",
	    getprogname());
	exit(exitcode);
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
		if (!io_read_line(sess, fd, buf, &linesz)) {
			/* XXX Log error */
			return -1;
		} else if (linesz == 0 || linesz == sizeof(buf)) {
			/* XXX Log error */
			fprintf(stderr, "linesz %zu\n", linesz);
			errno = EINVAL;
			return -1;
		}

		if (linecnt == 0) {
			const char *line;
			int major, minor;

			line = buf;
			if (strncmp(line, proto_prefix,
			    sizeof(proto_prefix) - 1) != 0) {
				/* XXX Protocol violation. */
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
				/* XXX Protocol violation */
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
			*module = strdup(buf);
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
		/* XXX Error */
		return -1;
	}

	for (;;) {
		linesz = sizeof(buf);
		if (!io_read_line(sess, fd, buf, &linesz)) {
			/* XXX ERROR */
			errno = EINVAL;
			return -1;
		} else if (linesz == sizeof(buf)) {
			/* XXX Log error */
			fprintf(stderr, "linesz %zu\n", linesz);
			errno = EINVAL;
			return -1;
		} else if (linesz == 0) {
			break;
		}

		if (argc == INT_MAX) {
			/*
			 * XXX Something hinky; don't allow it because we cannot
			 * exceed an int's worth.  Do we want to limit byte size
			 * as well? Possibly.
			 */
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
				/* XXX Error */
				argv = pargv;
				goto fail;
			}
		}

		argv[argc] = strdup(buf);
		if (argv[argc] == NULL) {
			/* XXX Maybe try to log it? */
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
rsync_daemon_handler(struct sess *sess, int fd, struct sockaddr_storage *saddr,
    size_t slen)
{
	struct daemon_role *role;
	char **argv, *module;
	int argc;

	role = (void *)sess->role;
	cfg_free(role->dcfg);

	role->dcfg = cfg_parse(sess, role->cfg_file, 1);
	if (role->dcfg == NULL)
		return ERR_IPC;

	sess->lver = RSYNC_PROTOCOL;
	module = NULL;
	argc = 0;
	argv = NULL;

	/* saddr == NULL only for inetd driven invocations. */
	if (daemon_read_hello(sess, fd, &module) < 0) {
		/* XXX Error */
		goto fail;
	}

	if (!cfg_is_valid_module(role->dcfg, module)) {
		/* XXX Send error */
		fprintf(stderr, "not a valid module %s\n", module);
		goto fail;
	}

	/* XXX */
	fprintf(stderr, "got valid module %s\n", module);

	if (!io_write_line(sess, fd, "@RSYNCD: OK")) {
		ERRX1("io_write_line");
		goto fail;
	}

	if (daemon_read_options(sess, fd, &argc, &argv) < 0) {
		/* XXX Error */
		goto fail;
	}

#if 1
	fprintf(stderr, "Got %d arguments.\n", argc);
	for (int i = 0; i < argc; i++) {
		fprintf(stderr, "argv[%d] = %s\n", i, argv[i]);
	}
#endif
	/* XXX Parse arguments. */

	for (int i = 0; i < argc; i++)
		free(argv[i]);
	free(argv);

	return 0;

fail:
	free(module);
	cfg_free(role->dcfg);
	role->dcfg = NULL;

	for (int i = 0; i < argc; i++)
		free(argv[i]);
	free(argv);

	return ERR_IPC;
}

int
rsync_daemon(int argc, char *argv[], struct opts *daemon_opts)
{
	struct sess sess;
	struct daemon_role role;
	long long tmpint;
	int c, opt_daemon = 0, detach = 1;

	/* Start with a fresh session / opts */
	memset(&role, 0, sizeof(role));
	memset(daemon_opts, 0, sizeof(*daemon_opts));
	memset(&sess, 0, sizeof(sess));
	sess.opts = daemon_opts;
	sess.role = (void *)&role;

	role.cfg_file = "/etc/rsyncd.conf";

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

	if (argc != 0)
		daemon_usage(ERR_SYNTAX);

	if (poll_timeout == 0)
		poll_timeout = -1;
	else
		poll_timeout *= 1000;

	if (rsync_is_socket(STDIN_FILENO))
		return rsync_daemon_handler(&sess, STDIN_FILENO, NULL, 0);

	if (detach && daemon(0, 0) == -1)
		err(ERR_IPC, "daemon");

	role.dcfg = cfg_parse(&sess, role.cfg_file, 0);
	if (role.dcfg == NULL)
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

	/* Fetch the port if it wasn't specified via arguments. */
	if (daemon_opts->port == NULL) {
		int error;

		/*
		 * "rsync" is set as our default value, so if it's not found
		 * we'll get that.
		 */
		error = cfg_param_str(role.dcfg, "global", "port",
		    &daemon_opts->port);

		assert(error == 0);
	}

	return rsync_listen(&sess, &rsync_daemon_handler);
}
