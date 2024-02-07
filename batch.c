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
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

/*
 * Flag bitmap in the header.  Note that `protocol` may be set to 0 if it was
 * one of the initial flags preserved in the batch file.  These should be kept
 * in bit order.  Note that all of these fields should be ints in our
 * `struct opts`.
 */
#define	OPT_FIELD(n)	offsetof(struct opts, n)
static const struct batchflag {
	const char	*name;		/* Informational purposes */
	size_t		 offset;	/* Offset into struct opts */
	int		 protocol;	/* Minimum protocol */
} batchflags[] = {
	{ "recurse",	OPT_FIELD(recursive),		0 },
	{ "owner",	OPT_FIELD(preserve_uids),	0 },
	{ "group",	OPT_FIELD(preserve_gids),	0 },
	{ "links",	OPT_FIELD(preserve_links),	0 },
	{ "devices",	OPT_FIELD(devices),		0 },
	{ "hard-links",	OPT_FIELD(hard_links),		0 },
	{ "checksum",	OPT_FIELD(checksum),		0 },
	{ "dirs",	OPT_FIELD(dirs),		29 },
#ifdef NOTYET
	{ "compress",	OPT_FIELD(compress),		29 },
#endif
};

struct batchhdr {
	int		flags;
	int		rver;
	int		seed;
};

/*
 * Read the batchhdr from our file; flags is a bitmap described above, and
 * rver and seed are the initial communications we'd normally receive from a
 * remote end.
 */
static int
read_batch_header(struct sess *sess, int batch_fd, struct batchhdr *hdr)
{

	if (!io_read_int(sess, batch_fd, &hdr->flags)) {
		ERRX1("io_read_int");
		return ERR_PROTOCOL;
	}

	if (!io_read_int(sess, batch_fd, &hdr->rver)) {
		ERRX1("io_read_int");
		return ERR_PROTOCOL;
	}

	if (!io_read_int(sess, batch_fd, &hdr->seed)) {
		ERRX1("io_read_int");
		return ERR_PROTOCOL;
	}

	return 0;
}

static void
batch_apply_flags(struct sess *sess, struct batchhdr *hdr, struct opts *opts)
{
	const struct batchflag	*bflag;
	int			*field, value;

	for (size_t bit = 0; bit < nitems(batchflags); bit++) {
		bflag = &batchflags[bit];
		/* XXX Negotiated protocol */
		if (bflag->protocol > 0 && bflag->protocol > sess->lver)
			break;

		assert(bflag->offset >= 0 && bflag->offset < sizeof(*opts));
		value = !!(hdr->flags & (1 << bit));
		field = (int *)(((uintptr_t)opts) + bflag->offset);
		if (*field != value) {
			LOG1("Mismatch of %s option, changing from %d -> %d",
			    bflag->name, *field, value);
		}

		*field = value;
	}

	/* XXX Negotiated protocol */
	if (sess->lver < 29) {
		if (opts->recursive) {
			/* XXX Implied */
			opts->dirs = 1;
		} else {
			/* XXX Should turn off implied --dirs */
		}
	}
}

int
rsync_batch(struct cleanup_ctx *cleanup_ctx, struct opts *opts,
    const struct fargs *f)
{
	struct sess	 sess;
	struct batchhdr	 hdr;
	int		 batch_fd, rc;

	memset(&sess, 0, sizeof(struct sess));
	sess.opts = opts;
	sess.mode = FARGS_RECEIVER;
	sess.lver = RSYNC_PROTOCOL;

	cleanup_set_session(cleanup_ctx, &sess);
	cleanup_release(cleanup_ctx);

	batch_fd = open(opts->read_batch, O_RDONLY);
	if (batch_fd == -1) {
		ERR("%s: open", opts->read_batch);
		return ERR_IPC;
	}

	rc = read_batch_header(&sess, batch_fd, &hdr);
	if (rc != 0)
		goto out;

	rc = ERR_IPC;
	if (hdr.rver < RSYNC_PROTOCOL_MIN) {
		ERRX("batch protocol %d is older than we support (%d)",
		    hdr.rver, RSYNC_PROTOCOL_MIN);
		goto out;
	} else if (hdr.rver > sess.lver) {
		ERRX("batch protocol %d is newer than we support (%d)",
		    hdr.rver, sess.lver);
		goto out;
	}

	batch_apply_flags(&sess, &hdr, opts);

	sess.rver = hdr.rver;
	sess.seed = hdr.seed;

	LOG2("batch detected client version %d, batch version %d, seed %d\n",
	    sess.lver, sess.rver, sess.seed);

	if (!rsync_receiver(&sess, cleanup_ctx, batch_fd, batch_fd, f->sink)) {
		ERRX1("rsync_receiver");
		goto out;
	}

	rc = 0;
out:

	close(batch_fd);
	return rc;
}
