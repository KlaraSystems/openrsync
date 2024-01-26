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

#if HAVE_ERR
# include <err.h>
#endif
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
#if 0
	{ "bwlimit",	required_argument,	NULL,		OP_BWLIMIT },
	{ "config",	required_argument,	NULL,		OP_CONFIG },
#endif
	{ "daemon",	no_argument,	NULL,			OP_DAEMON },
#if 0
	{ "no-detach",	no_argument,	NULL,			OP_NO_DETACH },
	{ "ipv4",	no_argument,	NULL,			'4' },
	{ "ipv6",	no_argument,	NULL,			'6' },
#endif
	{ "help",	no_argument,	NULL,			'h' },
#if 0
	{ "log-file",	required_argument,	NULL,		OP_LOG_FILE },
	{ "log-file-format",	required_argument,	NULL,	OP_LOG_FILE_FORMAT },
#endif
	{ "port",	required_argument,	NULL,		OP_PORT },
#if 0
	{ "sockopts",	required_argument,	NULL,		OP_SOCKOPTS },
	{ "verbose",	no_argument,		NULL,		'v' },
#endif
	{ NULL,		0,		NULL,			0 },
};

static void
daemon_usage(int exitcode)
{
	fprintf(exitcode == 0 ? stdout : stderr, "usage: %s"
	    " ...\n",
	    getprogname());
	exit(exitcode);
}

static int
rsync_daemon_handler(struct sess *sess, int fd)
{
	/* XXX */
	return 0;
}

int
rsync_daemon(int argc, char *argv[], struct opts *daemon_opts)
{
	struct sess sess;
	int c, opt_daemon = 0, detach = 1;

	/* Start with a fresh session / opts */
	memset(daemon_opts, 0, sizeof(*daemon_opts));
	memset(&sess, 0, sizeof(sess));
	sess.opts = daemon_opts;

	optreset = 1;
	optind = 1;
	while ((c = getopt_long(argc, argv, "h", daemon_lopts, NULL)) != -1) {
		switch (c) {
		case OP_ADDRESS:
			daemon_opts->address = optarg;
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
		case 'h':
			daemon_usage(0);
		default:
			daemon_usage(ERR_SYNTAX);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		daemon_usage(ERR_SYNTAX);

	if (rsync_is_socket(STDIN_FILENO))
		return rsync_daemon_handler(&sess, STDIN_FILENO);

	if (detach && daemon(0, 0) == -1)
		err(ERR_IPC, "daemon");

	if (daemon_opts->port == NULL)
		daemon_opts->port = (char *)"rsync";

	/* XXX Bind, Listen, Accept -> rsync_daemon_handler */

	return 0;
}
