/*
 * Copyright (c) 2019 Kristaps Dzonsons <kristaps@bsd.lv>
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

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <assert.h>
#if HAVE_ERR
# include <err.h>
#endif
#if !HAVE_SOCK_NONBLOCK
# include <fcntl.h>
#endif
#include <getopt.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if HAVE_SCAN_SCALED
# include <util.h>
#endif
#include <ctype.h>

#include "extern.h"

extern struct cleanup_ctx *cleanup_ctx;

int verbose;
int poll_timeout;

/*
 * A remote host is has a colon before the first path separator.
 * This works for rsh remote hosts (host:/foo/bar), implicit rsync
 * remote hosts (host::/foo/bar), and explicit (rsync://host/foo).
 * Return zero if local, non-zero if remote.
 */
static int
fargs_is_remote(const char *v)
{
	size_t	 pos;

	pos = strcspn(v, ":/");
	return v[pos] == ':';
}

/*
 * Test whether a remote host is specifically an rsync daemon.
 * Return zero if not, non-zero if so.
 */
static int
fargs_is_daemon(const char *v)
{
	size_t	 pos;

	if (strncasecmp(v, "rsync://", 8) == 0)
		return 1;

	pos = strcspn(v, ":/");
	return v[pos] == ':' && v[pos + 1] == ':';
}

/*
 * Take the command-line filenames (e.g., rsync foo/ bar/ baz/) and
 * determine our operating mode.
 * For example, if the first argument is a remote file, this means that
 * we're going to transfer from the remote to the local.
 * We also make sure that the arguments are consistent, that is, if
 * we're going to transfer from the local to the remote, that no
 * filenames for the local transfer indicate remote hosts.
 * Always returns the parsed and sanitised options.
 */
static struct fargs *
fargs_parse(size_t argc, char *argv[], struct opts *opts)
{
	struct fargs	*f = NULL;
	char		*cp, *ccp;
	size_t		 i, j, len = 0;

	/* Allocations. */

	if ((f = calloc(1, sizeof(struct fargs))) == NULL)
		err(ERR_NOMEM, NULL);

	f->sourcesz = argc - 1;
	if ((f->sources = calloc(f->sourcesz, sizeof(char *))) == NULL)
		err(ERR_NOMEM, NULL);

	for (i = 0; i < argc - 1; i++)
		if ((f->sources[i] = strdup(argv[i])) == NULL)
			err(ERR_NOMEM, NULL);

	if ((f->sink = strdup(argv[i])) == NULL)
		err(ERR_NOMEM, NULL);

	/*
	 * Test files for its locality.
	 * If the last is a remote host, then we're sending from the
	 * local to the remote host ("sender" mode).
	 * If the first, remote to local ("receiver" mode).
	 * If neither, a local transfer in sender style.
	 */

	f->mode = FARGS_SENDER;

	if (fargs_is_remote(f->sink)) {
		f->mode = FARGS_SENDER;
		if ((f->host = strdup(f->sink)) == NULL)
			err(ERR_NOMEM, NULL);
	}

	if (fargs_is_remote(f->sources[0])) {
		if (f->host != NULL)
			errx(ERR_SYNTAX, "both source and destination "
			    "cannot be remote files");
		f->mode = FARGS_RECEIVER;
		if ((f->host = strdup(f->sources[0])) == NULL)
			err(ERR_NOMEM, NULL);
	}

	if (f->host != NULL) {
		if (strncasecmp(f->host, "rsync://", 8) == 0) {
			/* rsync://host[:port]/module[/path] */
			f->remote = 1;
			len = strlen(f->host) - 8 + 1;
			memmove(f->host, f->host + 8, len);
			if ((cp = strchr(f->host, '/')) == NULL)
				errx(ERR_SYNTAX,
				    "rsync protocol requires a module name");
			*cp++ = '\0';
			f->module = cp;
			if ((cp = strchr(f->module, '/')) != NULL)
				*cp = '\0';
			if ((cp = strchr(f->host, ':')) != NULL) {
				/* host:port --> extract port */
				*cp++ = '\0';
				opts->port = cp;
			}
		} else {
			/* host:[/path] */
			cp = strchr(f->host, ':');
			assert(cp != NULL);
			*cp++ = '\0';
			if (*cp == ':') {
				/* host::module[/path] */
				f->remote = 1;
				f->module = ++cp;
				cp = strchr(f->module, '/');
				if (cp != NULL)
					*cp = '\0';
			}
		}
		if ((len = strlen(f->host)) == 0)
			errx(ERR_SYNTAX, "empty remote host");
		if (f->remote && strlen(f->module) == 0)
			errx(ERR_SYNTAX, "empty remote module");
	}

	/* Make sure we have the same "hostspec" for all files. */

	if (!f->remote) {
		if (f->mode == FARGS_SENDER)
			for (i = 0; i < f->sourcesz; i++) {
				if (!fargs_is_remote(f->sources[i]))
					continue;
				errx(ERR_SYNTAX,
				    "remote file in list of local sources: %s",
				    f->sources[i]);
			}
		if (f->mode == FARGS_RECEIVER)
			for (i = 0; i < f->sourcesz; i++) {
				if (fargs_is_remote(f->sources[i]) &&
				    !fargs_is_daemon(f->sources[i]))
					continue;
				if (fargs_is_daemon(f->sources[i]))
					errx(ERR_SYNTAX,
					    "remote daemon in list of remote "
					    "sources: %s", f->sources[i]);
				errx(ERR_SYNTAX, "local file in list of "
				    "remote sources: %s", f->sources[i]);
			}
	} else {
		if (f->mode != FARGS_RECEIVER)
			errx(ERR_SYNTAX, "sender mode for remote "
				"daemon receivers not yet supported");
		for (i = 0; i < f->sourcesz; i++) {
			if (fargs_is_daemon(f->sources[i]))
				continue;
			errx(ERR_SYNTAX, "non-remote daemon file "
				"in list of remote daemon sources: "
				"%s", f->sources[i]);
		}
	}

	/*
	 * If we're not remote and a sender, strip our hostname.
	 * Then exit if we're a sender or a local connection.
	 */

	if (!f->remote) {
		if (f->host == NULL)
			return f;
		if (f->mode == FARGS_SENDER) {
			assert(f->host != NULL);
			assert(len > 0);
			j = strlen(f->sink);
			memmove(f->sink, f->sink + len + 1, j - len);
			return f;
		} else if (f->mode != FARGS_RECEIVER)
			return f;
	}

	/*
	 * Now strip the hostnames from the remote host.
	 *   rsync://host/module/path -> module/path
	 *   host::module/path -> module/path
	 *   host:path -> path
	 * Also make sure that the remote hosts are the same.
	 */

	assert(f->host != NULL);
	assert(len > 0);

	for (i = 0; i < f->sourcesz; i++) {
		cp = f->sources[i];
		j = strlen(cp);
		if (f->remote &&
		    strncasecmp(cp, "rsync://", 8) == 0) {
			/* rsync://path */
			cp += 8;
			
			/* 
			 * FIXME: broken.
			 * URIs can allow colons too.
			 * Fix this after merge.
			 */

			if ((ccp = strchr(cp, ':')) != NULL) /* skip :port */
				*ccp = '\0';
			if (strncmp(cp, f->host, len) ||
			    (cp[len] != '/' && cp[len] != '\0'))
				errx(ERR_SYNTAX, "different remote host: %s",
				    f->sources[i]);
			memmove(f->sources[i],
				f->sources[i] + len + 8 + 1,
				j - len - 8);
		} else if (f->remote && strncmp(cp, "::", 2) == 0) {
			/* ::path */
			memmove(f->sources[i],
				f->sources[i] + 2, j - 1);
		} else if (f->remote) {
			/* host::path */
			if (strncmp(cp, f->host, len) ||
			    (cp[len] != ':' && cp[len] != '\0'))
				errx(ERR_SYNTAX, "different remote host: %s",
				    f->sources[i]);
			memmove(f->sources[i], f->sources[i] + len + 2,
			    j - len - 1);
		} else if (cp[0] == ':') {
			/* :path */
			memmove(f->sources[i], f->sources[i] + 1, j);
		} else {
			/* host:path */
			if (strncmp(cp, f->host, len) ||
			    (cp[len] != ':' && cp[len] != '\0'))
				errx(ERR_SYNTAX, "different remote host: %s",
				    f->sources[i]);
			memmove(f->sources[i],
				f->sources[i] + len + 1, j - len);
		}
	}

	return f;
}

/*
 * Like scan_scaled, but with a default for the case where no characterr
 * is given.
 * Return 0 on success, -1 and errno set on error.
 */
static int
scan_scaled_def(char *maybe_scaled, long long *result, char def)
{
	int ret;
	char *s = NULL;
	int length;

	length = strlen(maybe_scaled);
	if (length > 0) {
		if (isascii(maybe_scaled[length - 1]) &&
			isdigit(maybe_scaled[length - 1])) {
			asprintf(&s, "%s%c", maybe_scaled, def);
			if (s == NULL) {
				err(ERR_NOMEM, NULL);
			}
		}
	}
	ret = scan_scaled(s ? s : maybe_scaled, result);
	free(s);
	return ret;
}

static struct opts	 opts;

#define OP_ADDRESS	1000
#define OP_PORT		1001
#define OP_RSYNCPATH	1002
#define OP_TIMEOUT	1003

#define OP_EXCLUDE	1005
#define OP_NO_D		1006
#define OP_INCLUDE	1007
#define OP_EXCLUDE_FROM	1008
#define OP_INCLUDE_FROM	1009
#define OP_COMP_DEST	1010
#define OP_COPY_DEST	1011
#define OP_LINK_DEST	1012
#define OP_MAX_SIZE	1013
#define OP_MIN_SIZE	1014
#define OP_SPARSE	1015

#define OP_IGNORE_EXISTING	1018
#define OP_IGNORE_NON_EXISTING	1019
#define OP_DEL			1020
#define OP_DEL_BEFORE	1021
#define OP_DEL_DURING	1022
#define OP_DEL_DELAY	1023
#define OP_DEL_AFTER	1024
#define OP_BWLIMIT	1025

#define OP_NO_RELATIVE	1026

#define OP_NO_DIRS	1028
#define OP_FILESFROM	1029
#define OP_APPEND	1030
#define OP_PARTIAL_DIR	1031

const struct option	 lopts[] = {
    { "address",	required_argument, NULL,		OP_ADDRESS },
    { "append",		no_argument,	NULL,			OP_APPEND },
    { "archive",	no_argument,	NULL,			'a' },
    { "bwlimit",	required_argument, NULL,		OP_BWLIMIT },
    { "checksum",	no_argument,	NULL,			'c' },
    { "compare-dest",	required_argument, NULL,		OP_COMP_DEST },
#if 0
    { "copy-dest",	required_argument, NULL,		OP_COPY_DEST },
#endif
    { "link-dest",	required_argument, NULL,		OP_LINK_DEST },
    { "compress",	no_argument,	NULL,			'z' },
    { "copy-dirlinks",	no_argument,	NULL,			'k' },
    { "copy-links",	no_argument,	&opts.copy_links,	'L' },
    { "cvs-exclude",	no_argument,	NULL,			'C' },
    { "no-D",		no_argument,	NULL,			OP_NO_D },
    { "del",		no_argument,	NULL,			OP_DEL },
    { "delete",		no_argument,	NULL,			OP_DEL },
    { "delete-before",	no_argument,	NULL,		OP_DEL_BEFORE },
    { "delete-during",	no_argument,	NULL,		OP_DEL_DURING },
    { "delete-delay",	no_argument,	NULL,		OP_DEL_DELAY },
    { "delete-after",	no_argument,	NULL,		OP_DEL_AFTER },
    { "delete-excluded",	no_argument,	&opts.del_excl,	1 },
    { "devices",	no_argument,	&opts.devices,		1 },
    { "no-devices",	no_argument,	&opts.devices,		0 },
    { "dry-run",	no_argument,	NULL,			'n' },
    { "exclude",	required_argument, NULL,		OP_EXCLUDE },
    { "exclude-from",	required_argument, NULL,		OP_EXCLUDE_FROM },
    { "existing",	no_argument, NULL,			OP_IGNORE_NON_EXISTING },
    { "filter",		required_argument, NULL,		'f' },
    { "group",		no_argument,	NULL,			'g' },
    { "no-group",	no_argument,	&opts.preserve_gids,	0 },
    { "no-g",		no_argument,	&opts.preserve_gids,	0 },
    { "hard-links",	no_argument,	&opts.hard_links,	'H' },
    { "help",		no_argument,	NULL,			'h' },
    { "ignore-existing", no_argument,	NULL,			OP_IGNORE_EXISTING },
    { "ignore-non-existing", no_argument, NULL,			OP_IGNORE_NON_EXISTING },
    { "ignore-times",	no_argument,	NULL,			'I' },
    { "include",	required_argument, NULL,		OP_INCLUDE },
    { "include-from",	required_argument, NULL,		OP_INCLUDE_FROM },
    { "inplace",	no_argument,	&opts.inplace,		1 },
    { "links",		no_argument,	NULL,			'l' },
    { "max-size",	required_argument, NULL,		OP_MAX_SIZE },
    { "min-size",	required_argument, NULL,		OP_MIN_SIZE },
    { "motd",		no_argument,	&opts.no_motd,		0 },
    { "no-motd",	no_argument,	&opts.no_motd,		1 },
    { "no-links",	no_argument,	&opts.preserve_links,	0 },
    { "no-l",		no_argument,	&opts.preserve_links,	0 },
    { "no-super",	no_argument,	&opts.supermode,	SMODE_OFF },
    { "numeric-ids",	no_argument,	&opts.numeric_ids,	1 },
    { "owner",		no_argument,	NULL,			'o' },
    { "no-owner",	no_argument,	&opts.preserve_uids,	0 },
    { "no-o",		no_argument,	&opts.preserve_uids,	0 },
    { "one-file-system",no_argument,	NULL,			'x' },
    { "partial",	no_argument,	&opts.partial,		1 },
    { "no-partial",	no_argument,	&opts.partial,		0 },
    { "partial-dir",	required_argument,	NULL,		OP_PARTIAL_DIR },
    { "perms",		no_argument,	NULL,			'p' },
    { "no-perms",	no_argument,	&opts.preserve_perms,	0 },
    { "no-p",		no_argument,	&opts.preserve_perms,	0 },
    { "port",		required_argument, NULL,		OP_PORT },
    { "recursive",	no_argument,	NULL,			'r' },
    { "no-recursive",	no_argument,	&opts.recursive,	0 },
    { "no-r",		no_argument,	&opts.recursive,	0 },
    { "rsh",		required_argument, NULL,		'e' },
    { "rsync-path",	required_argument, NULL,		OP_RSYNCPATH },
    { "sender",		no_argument,	&opts.sender,		1 },
    { "server",		no_argument,	&opts.server,		1 },
    { "specials",	no_argument,	&opts.specials,		1 },
    { "sparse",		no_argument,	NULL,			'S' },
    { "super",		no_argument,	&opts.supermode,	SMODE_ON },
#if 0
    { "sync-file",	required_argument, NULL,		6 },
#endif
    { "no-specials",	no_argument,	&opts.specials,		0 },
    { "timeout",	required_argument, NULL,		OP_TIMEOUT },
    { "times",		no_argument,	NULL,			't' },
    { "no-times",	no_argument,	&opts.preserve_times,	0 },
    { "no-t",		no_argument,	&opts.preserve_times,	0 },
    { "update",		no_argument,	NULL,			'u' },
    { "verbose",	no_argument,	NULL,			'v' },
    { "no-verbose",	no_argument,	&verbose,		0 },
    { "no-v",		no_argument,	&verbose,		0 },
    { "progress",	no_argument,	&opts.progress,		1 },
    { "no-progress",	no_argument,	&opts.progress,		0 },
    { "backup",		no_argument,	NULL,			'b' },
    { "version",	no_argument,	NULL,			'V' },
    { "relative",	no_argument,	NULL,			'R' },
    { "no-R",		no_argument,	NULL,			OP_NO_RELATIVE },
    { "no-relative",	no_argument,	NULL,			OP_NO_RELATIVE },
    { "remove-source-files",	no_argument,	&opts.remove_source,	1 },
    { "dirs",		no_argument,	NULL,			'd' },
    { "no-dirs",	no_argument,	NULL,			OP_NO_DIRS },
    { "files-from",	required_argument,	NULL,		OP_FILESFROM },
    { "delay-updates",	no_argument,	&opts.dlupdates,	1 },
    { NULL,		0,		NULL,			0 }
};

static void
usage(int exitcode)
{
	fprintf(exitcode == 0 ? stdout : stderr, "usage: %s"
	    " [-CDLPacdgklnoprtuvx] [-e program] [-f filter] [--address=sourceaddr]\n"
	    "\t[--append] [--bwlimit=limit] [--compare-dest=dir]\n"
	    "\t[--del | --delete-before | --delete-during | --delete-after | --delete-during]\n"
	    "\t[--delay-updates] [--dirs] [--no-dirs]\n"
	    "\t[--exclude] [--exclude-from=file]\n"
	    "\t[--existing] [--ignore-existing] [--ignore-non-existing]\n"
	    "\t[--include] [--include-from=file]\n"
	    "\t[--inplace] [--link-dest=dir] [--no-motd] [--numeric-ids]\n"
	    "\t[--partial] [--port=portnumber] [--progress]\n"
	    "\t[--relative] [--remove-source-files]\n"
	    "\t[--rsync-path=program] [--timeout=seconds] [--version] source ... directory\n",
	    getprogname());
	exit(exitcode);
}

int
main(int argc, char *argv[])
{
	pid_t		 child;
	int		 cvs_excl, fds[2], sd = -1, rc, c, st, i, lidx;
	size_t		 basedir_cnt = 0;
	struct sess	 sess;
	struct fargs	*fargs;
	char		**args;
	const char	*errstr;
	long long 	 tmpint;
	int		 opts_no_relative = 0, opts_no_dirs = 0;

	/* Global pledge. */

	if (pledge("stdio unix rpath wpath cpath dpath inet fattr chown dns getpw proc exec unveil",
	    NULL) == -1)
		err(ERR_IPC, "pledge");

	cvs_excl = 0;
	opts.max_size = opts.min_size = -1;

	while ((c = getopt_long(argc, argv, "CDHILPRSVabcde:f:ghklnoprtuvxz", lopts,
	    &lidx)) != -1) {
		switch (c) {
		case 'C':
			cvs_excl = 1;
			break;
		case 'D':
			opts.devices = 1;
			opts.specials = 1;
			break;
		case 'H':
			opts.hard_links = 1;
			break;
		case 'a':
			opts.recursive = 1;
			opts.preserve_links = 1;
			opts.preserve_perms = 1;
			opts.preserve_times = 1;
			opts.preserve_gids = 1;
			opts.preserve_uids = 1;
			opts.devices = 1;
			opts.specials = 1;
			break;
		case 'b':
		        opts.backup++;
			break;
		case 'c':
			opts.checksum = 1;
			break;
		case 'd':
			opts.dirs = 1;
			break;
		case 'e':
			opts.ssh_prog = optarg;
			break;
		case 'f':
			if (parse_rule(optarg, RULE_NONE) == -1)
				errx(ERR_SYNTAX, "syntax error in filter: %s",
				    optarg);
			break;
		case 'g':
			opts.preserve_gids = 1;
			break;
		case 'k':
			opts.copy_dirlinks = 1;
			break;
		case 'l':
			opts.preserve_links = 1;
			break;
		case 'L':
			opts.copy_links = 1;
			break;
		case 'n':
			opts.dry_run = 1;
			break;
		case 'o':
			opts.preserve_uids = 1;
			break;
		case 'P':
			opts.partial = 1;
			opts.progress++;
			break;
		case 'p':
			opts.preserve_perms = 1;
			break;
		case 'r':
			opts.recursive = 1;
			break;
		case 't':
			opts.preserve_times = 1;
			break;
		case 'u':
			opts.update++;
			break;
		case 'v':
			verbose++;
			break;
		case 'x':
			opts.one_file_system++;
			break;
		case 'z':
			fprintf(stderr, "%s: -z not supported yet\n", getprogname());
			break;
		case 'I':
			opts.ignore_times++;
			break;
		case 'S':
			opts.sparse++;
			break;
		case 0:
			/* Non-NULL flag values (e.g., --sender). */
			break;
#if 0
		case 6:
			opts.syncfile = optarg;
			break;
#endif
		case OP_ADDRESS:
			opts.address = optarg;
			break;
		case OP_PORT:
			opts.port = optarg;
			break;
		case OP_RSYNCPATH:
			opts.rsync_path = optarg;
			break;
		case OP_TIMEOUT:
			poll_timeout = strtonum(optarg, 0, 60*60, &errstr);
			if (errstr != NULL)
				errx(ERR_SYNTAX, "timeout is %s: %s",
				    errstr, optarg);
			break;
		case OP_EXCLUDE:
			if (parse_rule(optarg, RULE_EXCLUDE) == -1)
				errx(ERR_SYNTAX, "syntax error in exclude: %s",
				    optarg);
			break;
		case OP_INCLUDE:
			if (parse_rule(optarg, RULE_INCLUDE) == -1)
				errx(ERR_SYNTAX, "syntax error in include: %s",
				    optarg);
			break;
		case OP_EXCLUDE_FROM:
			parse_file(optarg, RULE_EXCLUDE);
			break;
		case OP_INCLUDE_FROM:
			parse_file(optarg, RULE_INCLUDE);
			break;
		case OP_COMP_DEST:
			if (opts.alt_base_mode !=0 &&
			    opts.alt_base_mode != BASE_MODE_COMPARE) {
				errx(1, "option --%s conflicts with %s",
				    lopts[lidx].name,
				    alt_base_mode(opts.alt_base_mode));
			}
			opts.alt_base_mode = BASE_MODE_COMPARE;
			goto basedir;
#if 0
		case OP_COPY_DEST:
			if (opts.alt_base_mode !=0 &&
			    opts.alt_base_mode != BASE_MODE_COPY) {
				errx(1, "option --%s conflicts with %s",
				    lopts[lidx].name,
				    alt_base_mode(opts.alt_base_mode));
			}
			opts.alt_base_mode = BASE_MODE_COPY;
			goto basedir;
#endif
		case OP_DEL:
			/* nop if a --delete-* option has already been specified. */
			if (opts.del == DMODE_NONE)
				opts.del = DMODE_UNSPECIFIED;
			break;
		case OP_DEL_BEFORE:
			if (opts.del > DMODE_UNSPECIFIED)
				errx(1, "may only specify one --delete-* option");

			opts.del = DMODE_BEFORE;
			break;
		case OP_DEL_DURING:
			if (opts.del > DMODE_UNSPECIFIED)
				errx(1, "may only specify one --delete-* option");

			opts.del = DMODE_DURING;
			break;
		case OP_DEL_DELAY:
			if (opts.del > DMODE_UNSPECIFIED)
				errx(1, "may only specify one --delete-* option");

			opts.del = DMODE_DELAY;
			break;
		case OP_DEL_AFTER:
			if (opts.del > DMODE_UNSPECIFIED)
				errx(1, "may only specify one --delete-* option");

			opts.del = DMODE_AFTER;
			break;
		case OP_LINK_DEST:
			if (opts.alt_base_mode !=0 &&
			    opts.alt_base_mode != BASE_MODE_LINK) {
				errx(1, "option --%s conflicts with %s",
				    lopts[lidx].name,
				    alt_base_mode(opts.alt_base_mode));
			}
			opts.alt_base_mode = BASE_MODE_LINK;

basedir:
			if (basedir_cnt >= MAX_BASEDIR)
				errx(1, "too many --%s directories specified",
				    lopts[lidx].name);
			opts.basedir[basedir_cnt++] = optarg;
			break;
		case OP_SPARSE:
			opts.sparse++;
			break;
		case OP_MAX_SIZE:
			if (scan_scaled(optarg, &tmpint) == -1)
				err(1, "bad max-size");
			opts.max_size = tmpint;
			break;
		case OP_MIN_SIZE:
			if (scan_scaled(optarg, &tmpint) == -1)
				err(1, "bad min-size");
			opts.min_size = tmpint;
			break;
		case OP_NO_D:
			opts.devices = 0;
			opts.specials = 0;
			break;
		case OP_IGNORE_EXISTING:
		        opts.ign_exist++;
			break;
		case OP_IGNORE_NON_EXISTING:
		        opts.ign_non_exist++;
			break;
		case 'R':
		        opts.relative++;
			break;
		case OP_NO_RELATIVE:
		        opts_no_relative++;
			break;
		case OP_NO_DIRS:
		        opts_no_dirs++;
			break;
		case OP_FILESFROM:
		        opts.filesfrom = optarg;
			break;
		case OP_APPEND:
			opts.append++;
			break;
		case OP_BWLIMIT:
			if (scan_scaled_def(optarg, &tmpint, 'k') == -1)
				err(1, "bad bwlimit");
			opts.bwlimit = tmpint;
			break;
		case OP_PARTIAL_DIR:
			opts.partial = 1;

			/*
			 * We stash off our own copy just to be logically
			 * consistent; if it's not specified here, we instead
			 * use RSYNC_PARTIAL_DIR from the environment if it's
			 * set which we'll naturally want to make a copy of.  We
			 * can thus always assume it's on the heap, rather than
			 * sometimes part of argv.
			 */
			free(opts.partial_dir);
			opts.partial_dir = strdup(optarg);
			if (opts.partial_dir == NULL)
				errx(ERR_NOMEM, NULL);
			break;
		case 'V':
			fprintf(stderr, "openrsync: protocol version %u\n",
			    RSYNC_PROTOCOL);
			exit(0);
		case 'h':
			usage(0);
		default:
			usage(ERR_SYNTAX);
		}
	}

	argc -= optind;
	argv += optind;

	/* FIXME: reference implementation rsync accepts this. */

	if (argc < 2)
		usage(ERR_SYNTAX);

	if (opts.inplace) {
		if (opts.partial_dir != NULL)
			errx(ERR_SYNTAX,
			    "option --partial-dir conflicts with --inplace");
		opts.partial = 1;
	} else if (opts.partial && opts.partial_dir == NULL) {
		char *rsync_partial_dir;

		/*
		 * XXX For delayed update mode, this should use .~tmp~ instead
		 * of RSYNC_PARTIAL_DIR if --partial-dir was not supplied here.
		 */
		rsync_partial_dir = getenv("RSYNC_PARTIAL_DIR");
		if (rsync_partial_dir != NULL && rsync_partial_dir[0] != '\0') {
			opts.partial_dir = strdup(rsync_partial_dir);
			if (opts.partial_dir == NULL)
				errx(ERR_NOMEM, NULL);
		}
	}

	if (opts.partial_dir != NULL) {
		char *partial_dir;

		/* XXX Samba rsync would normalize this path a little better. */
		partial_dir = opts.partial_dir;
		if (partial_dir[0] == '\0' || strcmp(partial_dir, ".") == 0) {
			free(opts.partial_dir);
			opts.partial_dir = NULL;
		} else {
			char *endp;

			endp = &partial_dir[strlen(partial_dir) - 1];
			while (endp > partial_dir && *(endp - 1) == '/') {
				*endp-- = '\0';
			}

			if (parse_rule(partial_dir, RULE_EXCLUDE) == -1) {
				errx(ERR_SYNTAX, "syntax error in exclude: %s",
				    partial_dir);
			}
		}
	}

	if (opts.port == NULL)
		opts.port = (char *)"rsync";

	/* by default and for --timeout=0 disable poll_timeout */
	if (poll_timeout == 0)
		poll_timeout = -1;
	else
		poll_timeout *= 1000;

	if (opts.filesfrom != NULL) {
		if (opts_no_relative)
			opts.relative = 0;
		else
			opts.relative = 1;
		if (opts_no_dirs)
			opts.dirs = 0;
		else
			opts.dirs = 1;
	}

	if (opts.relative && opts_no_relative)
		ERRX1("Cannot use --relative and --no-relative at the same time");
	if (opts.dirs && opts_no_dirs)
		ERRX1("Cannot use --dirs and --no-dirs at the same time");

	/*
	 * Signals blocked until we understand what session we'll be using.
	 */
	cleanup_init(cleanup_ctx);

	/*
	 * XXX rsync started defaulting to --delete-during in later versions of the
	 * protocol (30 and up).
	 */
	if (opts.del == DMODE_UNSPECIFIED)
		opts.del = DMODE_BEFORE;

	/*
	 * This is what happens when we're started with the "hidden"
	 * --server option, which is invoked for the rsync on the remote
	 * host by the parent.
	 */

	if (opts.server)
		exit(rsync_server(cleanup_ctx, &opts, (size_t)argc, argv));

	if (cvs_excl) {
		int ret;

		ret = parse_rule("-C", RULE_NONE);
		assert(ret == 0);

		ret = parse_rule(":C", RULE_NONE);
		assert(ret == 0);

		/* Silence NDEBUG warnings */
		(void)ret;
	}

	/*
	 * Now we know that we're the client on the local machine
	 * invoking rsync(1).
	 * At this point, we need to start the client and server
	 * initiation logic.
	 * The client is what we continue running on this host; the
	 * server is what we'll use to connect to the remote and
	 * invoke rsync with the --server option.
	 */

	fargs = fargs_parse(argc, argv, &opts);
	assert(fargs != NULL);

	cleanup_set_args(cleanup_ctx, fargs);

	/*
	 * If we're contacting an rsync:// daemon, then we don't need to
	 * fork, because we won't start a server ourselves.
	 * Route directly into the socket code, unless a remote shell
	 * has explicitly been specified.
	 */

	if (fargs->remote && opts.ssh_prog == NULL) {
		assert(fargs->mode == FARGS_RECEIVER);
		if ((rc = rsync_connect(&opts, &sd, fargs)) == 0) {
			rc = rsync_socket(cleanup_ctx, &opts, sd, fargs);
			close(sd);
		}
		exit(rc);
	}

	/* Drop the dns/inet possibility. */

	if (pledge("stdio unix rpath wpath cpath dpath fattr chown getpw proc exec unveil",
	    NULL) == -1)
		err(ERR_IPC, "pledge");

	/* Create a bidirectional socket and start our child. */

#if HAVE_SOCK_NONBLOCK
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds) == -1)
		err(ERR_IPC, "socketpair");
#else
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == -1)
		err(ERR_IPC, "socketpair");
	if (fcntl(fds[0], F_SETFL, fcntl(fds[0], F_GETFL, 0) | O_NONBLOCK) == -1)
		err(ERR_IPC, "fcntl");
	if (fcntl(fds[1], F_SETFL, fcntl(fds[1], F_GETFL, 0) | O_NONBLOCK) == -1)
		err(ERR_IPC, "fcntl");
#endif

	switch ((child = fork())) {
	case -1:
		err(ERR_IPC, "fork");
	case 0:
		close(fds[0]);
		if (pledge("stdio exec", NULL) == -1)
			err(ERR_IPC, "pledge");

		memset(&sess, 0, sizeof(struct sess));
		sess.opts = &opts;

		/*
		 * We're about to exec(), but we need to make sure the
		 * appropriate signals are unblocked so that we can be
		 * interrupted earlier if needed.
		 */
		cleanup_set_session(cleanup_ctx, &sess);
		cleanup_release(cleanup_ctx);

		args = fargs_cmdline(&sess, fargs, NULL);

		for (i = 0; args[i] != NULL; i++)
			LOG2("exec[%d] = %s", i, args[i]);

		/* Make sure the child's stdin is from the sender. */
		if (dup2(fds[1], STDIN_FILENO) == -1)
			err(ERR_IPC, "dup2");
		if (dup2(fds[1], STDOUT_FILENO) == -1)
			err(ERR_IPC, "dup2");
		if (execvp(args[0], args) == -1)
			ERR("exec on '%s'", args[0]);
		_exit(ERR_IPC);
		/* NOTREACHED */
	default:
		cleanup_set_child(cleanup_ctx, child);

		close(fds[1]);
		if (!fargs->remote)
			rc = rsync_client(cleanup_ctx, &opts, fds[0], fargs);
		else
			rc = rsync_socket(cleanup_ctx, &opts, fds[0], fargs);
		break;
	}

	close(fds[0]);

#if 0
	/*
	 * The server goes into an infinite sleep loop once it's concluded to
	 * avoid closing the various pipes.  This gives us time to finish
	 * draining whatever's left and making our way cleanly through the state
	 * machine, after which we come here and signal the child that it's safe
	 * to shutdown.
	 */
	kill(child, SIGUSR2);
#endif

	if (waitpid(child, &st, 0) == -1)
		err(ERR_WAITPID, "waitpid");

	/*
	 * Best effort to avoid a little bit of work during cleanup, but cleanup
	 * will use WNOHANG and just move on if the child's already been reaped.
	 */
	cleanup_set_child(cleanup_ctx, 0);

	/*
	 * If we don't already have an error (rc == 0), then inherit the
	 * error code of rsync_server() if it has exited.
	 * If it hasn't exited, it overrides our return value.
	 */

	if (rc == 0) {
		if (WIFEXITED(st))
			rc = WEXITSTATUS(st);
		else if (WIFSIGNALED(st)) {
			if (WTERMSIG(st) != SIGUSR2)
				rc = ERR_TERMIMATED;
		} else
			rc = ERR_WAITPID;
	}

	exit(rc);
}
