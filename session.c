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

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "extern.h"

/*
 * Accept how much we've read, written, and file-size, and print them in
 * a human-readable fashion (with GB, MB, etc. prefixes).
 * This only prints as the client.
 */
static void
stats_log(struct sess *sess,
    uint64_t tread, uint64_t twrite, uint64_t tsize, uint64_t fbuild,
    uint64_t fxfer)
{
	char		rbuf[32], wbuf[32], sbuf[32];

	assert(verbose);
	if (sess->opts->server)
		return;

	rsync_humanize(sess, (char*)&rbuf, sizeof(rbuf), tread);
	rsync_humanize(sess, (char*)&wbuf, sizeof(wbuf), twrite);
	rsync_humanize(sess, (char*)&sbuf, sizeof(sbuf), tsize);

	LOG1("Transfer complete: "
	    "%s sent, %s read, %s file size",
	    (char*)&rbuf, (char*)&wbuf, (char*)&sbuf);

	LOG3("File list generation time: %.3f seconds, "
	    "transfer time: %.3f seconds",
	    (double)sess->flist_build / 1000,
	    (double)sess->flist_xfer / 1000);
}

static void
stats_output(struct sess *sess)
{
	char *tbuf[32];

	LOG0("Number of files: %lu", sess->total_files);
	LOG0("Number of files transferred: %lu", sess->total_files_xfer);
	rsync_humanize(sess, (char*)&tbuf, sizeof(tbuf), sess->total_size);
	LOG0("Total file size: %s", (char*)&tbuf);
	rsync_humanize(sess, (char*)&tbuf, sizeof(tbuf), sess->total_xfer_size);
	LOG0("Total transferred file size: %s", (char*)&tbuf);
	rsync_humanize(sess, (char*)&tbuf, sizeof(tbuf), sess->total_unmatched);
	LOG0("Unmatched data: %s", (char*)&tbuf);
	rsync_humanize(sess, (char*)&tbuf, sizeof(tbuf), sess->total_matched);
	LOG0("Matched data: %s", (char*)&tbuf);
	rsync_humanize(sess, (char*)&tbuf, sizeof(tbuf), sess->flist_size);
	LOG0("File list size: %s", (char*)&tbuf);
	if (sess->flist_build) {
		LOG0("File list generation time: %.3f seconds",
		    (double)sess->flist_build / 1000);
		LOG0("File list transfer time: %.3f seconds",
		    (double)sess->flist_xfer / 1000);
	}
	rsync_humanize(sess, (char*)&tbuf, sizeof(tbuf), sess->total_write);
	LOG0("Total sent: %s", (char*)&tbuf);
	rsync_humanize(sess, (char*)&tbuf, sizeof(tbuf), sess->total_read);
	LOG0("Total received: %s", (char*)&tbuf);

}

/*
 * At the end of transmission, we write our statistics if we're the
 * server, then log only if we're not the server.
 * Either way, only do this if we're in verbose mode.
 * Returns zero on failure, non-zero on success.
 */
int
sess_stats_send(struct sess *sess, int fd)
{
	uint64_t tw, tr, ts, fb, fx;
	int statfd = -1;

	if (!sess->opts->server && sess->wbatch_fd == -1 && verbose == 0)
		return 1;

	tw = sess->total_write;
	tr = sess->total_read;
	ts = sess->total_size;
	fb = 0;
	fx = 0;

	/*
	 * The client-sender doesn't need to send stats, unless we're writing a
	 * batch file; they're going to be read by a client-receiver, and will
	 * be expecting stats.  In that case, we'll just write the stats
	 * directly to the batch file.
	 */
	if (sess->opts->server || sess->wbatch_fd != -1) {
		if (sess->opts->server)
			statfd = fd;
		else
			statfd = sess->wbatch_fd;
	}

	if (statfd != -1) {
		if (!io_write_ulong(sess, statfd, tr)) {
			ERRX1("io_write_ulong");
			return 0;
		} else if (!io_write_ulong(sess, statfd, tw)) {
			ERRX1("io_write_ulong");
			return 0;
		} else if (!io_write_ulong(sess, statfd, ts)) {
			ERRX1("io_write_ulong");
			return 0;
		}
		if (protocol_fliststats) {
			if (!io_write_ulong(sess, statfd, fb)) {
				ERRX1("io_write_ulong");
				return 0;
			} else if (!io_write_ulong(sess, statfd, fx)) {
				ERRX1("io_write_ulong");
				return 0;
			}
		}
	}

	if (verbose > 0 || sess->opts->stats)
		stats_log(sess, tr, tw, ts, fb, fx);
	return 1;
}

/*
 * At the end of the transmission, we have some statistics to read.
 * Only do this (1) if we're in verbose mode and (2) if we're the
 * server.
 * Then log the findings.
 * Return zero on failure, non-zero on success.
 */
int
sess_stats_recv(struct sess *sess, int fd)
{
	uint64_t tr, tw, ts, fb, fx;

	if (sess->opts->server)
		return 1;

	if (!io_read_ulong(sess, fd, &tw)) {
		ERRX1("io_read_ulong");
		return 0;
	} else if (!io_read_ulong(sess, fd, &tr)) {
		ERRX1("io_read_ulong");
		return 0;
	} else if (!io_read_ulong(sess, fd, &ts)) {
		ERRX1("io_read_ulong");
		return 0;
	}
	if (protocol_fliststats) {
		if (!io_read_ulong(sess, fd, &fb)) {
			ERRX1("io_read_ulong");
			return 0;
		} else if (!io_read_ulong(sess, fd, &fx)) {
			ERRX1("io_read_ulong");
			return 0;
		}
	}

	if (verbose > 0 || sess->opts->stats)
		stats_log(sess, tr, tw, ts, fb, fx);
	return 1;
}
