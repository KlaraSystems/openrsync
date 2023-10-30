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

#include <assert.h>
#if HAVE_ERR
# include <err.h>
#endif
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "extern.h"

#define	RSYNC_PATH	"openrsync"

const char *
alt_base_mode(int mode)
{
	switch (mode) {
	case BASE_MODE_COMPARE:
		return "--compare-dest";
	case BASE_MODE_COPY:
		return "--copy-dest";
	case BASE_MODE_LINK:
		return "--link-dest";
	default:
		errx(1, "unknown base mode %d", mode);
	}
}

char **
fargs_cmdline(struct sess *sess, const struct fargs *f, size_t *skip)
{
	arglist		 args;
	size_t		 j;
	char		*rsync_path, *ap, *arg;

	memset(&args, 0, sizeof args);

	assert(f != NULL);
	assert(f->sourcesz > 0);

	if ((rsync_path = sess->opts->rsync_path) == NULL)
		rsync_path = (char *)RSYNC_PATH;

	if (f->host != NULL) {
		/*
		 * Splice arguments from -e "foo bar baz" into array
		 * elements required for execve(2).
		 * This doesn't do anything fancy: it splits along
		 * whitespace into the array.
		 */

		if (sess->opts->ssh_prog) {
			ap = strdup(sess->opts->ssh_prog);
			if (ap == NULL)
				err(ERR_NOMEM, NULL);

			while ((arg = strsep(&ap, " \t")) != NULL) {
				if (arg[0] == '\0') {
					ap++;	/* skip separators */
					continue;
				}

				addargs(&args, "%s", arg);
			}
		} else
			addargs(&args, "ssh");

		addargs(&args, "%s", f->host);
		addargs(&args, "%s", rsync_path);
		if (skip)
			*skip = args.num;
		addargs(&args, "--server");
		if (f->mode == FARGS_RECEIVER)
			addargs(&args, "--sender");
	} else {
		addargs(&args, "%s", rsync_path);
		addargs(&args, "--server");
	}

	/* Shared arguments. */

	if (sess->opts->del) {
		switch (sess->opts->del) {
		case DMODE_UNSPECIFIED:
			addargs(&args, "--delete");
			break;
		case DMODE_BEFORE:
			addargs(&args, "--delete-before");
			break;
		case DMODE_DURING:
			addargs(&args, "--delete-during");
			break;
		case DMODE_DELAY:
			addargs(&args, "--delete-delay");
			break;
		case DMODE_AFTER:
			addargs(&args, "--delete-after");
			break;
		default:
			errx(1, "bogus delete mode %d\n", sess->opts->del);
		}
	}
	if (sess->opts->append)
		addargs(&args, "--append");
	if (sess->opts->checksum)
		addargs(&args, "-c");
	if (sess->opts->del_excl)
		addargs(&args, "--delete-excluded");
	if (sess->opts->numeric_ids)
		addargs(&args, "--numeric-ids");
	if (sess->opts->preserve_gids)
		addargs(&args, "-g");
	if (sess->opts->preserve_links)
		addargs(&args, "-l");
	if (sess->opts->dry_run)
		addargs(&args, "-n");
	if (sess->opts->inplace)
		addargs(&args, "--inplace");
	if (sess->opts->preserve_uids)
		addargs(&args, "-o");
	if (sess->opts->preserve_perms)
		addargs(&args, "-p");
	if (sess->opts->devices)
		addargs(&args, "-D");
	if (sess->opts->recursive)
		addargs(&args, "-r");
	if (sess->opts->preserve_times)
		addargs(&args, "-t");
	if (sess->opts->sparse)
		addargs(&args, "-S");
	if (sess->opts->hard_links)
		addargs(&args, "-H");
	if (sess->opts->update)
		addargs(&args, "-u");
	if (verbose > 3)
		addargs(&args, "-v");
	if (verbose > 2)
		addargs(&args, "-v");
	if (verbose > 1)
		addargs(&args, "-v");
	if (verbose > 0)
		addargs(&args, "-v");
	if (sess->opts->progress > 0)
		addargs(&args, "--progress");
	if (sess->opts->backup > 0)
		addargs(&args, "--backup");
	if (sess->opts->ign_exist > 0)
		addargs(&args, "--ignore-existing");
	if (sess->opts->ign_non_exist > 0)
		addargs(&args, "--ignore-non-existing");
	if (sess->opts->one_file_system > 1)
		addargs(&args, "-x");
	if (sess->opts->one_file_system > 0)
		addargs(&args, "-x");
	if (sess->opts->specials && !sess->opts->devices)
		addargs(&args, "--specials");
	if (!sess->opts->specials && sess->opts->devices)
		/* --devices is sent as -D --no-specials */
		addargs(&args, "--no-specials");
	if (sess->opts->max_size >= 0)
		addargs(&args, "--max-size=%lld", (long long)sess->opts->max_size);
	if (sess->opts->min_size >= 0)
		addargs(&args, "--min-size=%lld", (long long)sess->opts->min_size);
	if (sess->opts->relative > 0)
		addargs(&args, "--relative");
	if (sess->opts->dirs > 0)
		addargs(&args, "--dirs");
	if (sess->opts->dlupdates > 0)
		addargs(&args, "--delay-updates");
	if (sess->opts->copy_links)
		addargs(&args, "-L");
	if (sess->opts->copy_dirlinks)
		addargs(&args, "-k");
	if (f->mode == FARGS_SENDER && sess->opts->ignore_times > 0)
		addargs(&args, "--ignore-times");
	if (sess->opts->bwlimit >= 0)
		addargs(&args, "--bwlimit=%lldb", (long long)sess->opts->bwlimit);

	/* only add --compare-dest, etc if this is the sender */
	if (sess->opts->alt_base_mode != 0 &&
	    f->mode == FARGS_SENDER) {
		for (j = 0; j < MAX_BASEDIR; j++) {
			if (sess->opts->basedir[j] == NULL)
				break;
			addargs(&args, "%s=%s",
			    alt_base_mode(sess->opts->alt_base_mode),
			    sess->opts->basedir[j]);
		}
	}

	/* Terminate with a full-stop for reasons unknown. */

	addargs(&args, ".");

	if (f->mode == FARGS_RECEIVER) {
		for (j = 0; j < f->sourcesz; j++)
			addargs(&args, "%s", f->sources[j]);
	} else
		addargs(&args, "%s", f->sink);

	return args.list;
}
