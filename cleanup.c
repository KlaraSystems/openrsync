/*
 * Copyright (c) 2023 Klara, Inc.
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

#include <sys/param.h>

#include <assert.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>

#include "extern.h"

static struct cleanup_ctx {
	struct sess		*sess;
	struct download		*dl;
	struct fargs		*fargs;

	pid_t			 child_pid;
	int			 exitstatus;
	int			 signal;

	int			 hold;
	sigset_t		 holdmask;
} cleanup_ctx_storage = {
	.exitstatus = -1,
};

/*
 * We need to be able to access our context from a signal context and there can
 * only really reasonably be one anyways, so we allocated it globally above and
 * just use that.  Everything outside of main() and cleanup.c won't be aware of
 * this implementation detail, though.
 */
struct cleanup_ctx *cleanup_ctx = &cleanup_ctx_storage;

/*
 * Hold any signals that may cause us to need a graceful cleanup until the hold
 * is released.  Used if we're freeing resources during normal execution so that
 * we don't end up in an unpredictable state when interrupted at just the right
 * time.
 *
 * We technically allow these sections to be nested, because it adds very little
 * complexity to track.
 */
void
cleanup_hold(struct cleanup_ctx *ctx)
{

	/* No underflow */
	assert(ctx->hold >= 0);
	if (++ctx->hold == 1) {
		sigset_t set;

		sigemptyset(&set);
		sigaddset(&set, SIGHUP);
		sigaddset(&set, SIGINT);
		sigaddset(&set, SIGTERM);

		sigprocmask(SIG_BLOCK, &set, &ctx->holdmask);
	}
}

/*
 * Releases the hold previously taken, unblocking any signals that we may have
 * previously blocked to avoid being preempted by user interruption.
 */
void
cleanup_release(struct cleanup_ctx *ctx)
{

	assert(ctx->hold > 0);
	if (--ctx->hold == 0)
		sigprocmask(SIG_SETMASK, &ctx->holdmask, NULL);
}

/*
 * Bare minimum needed for cleanup -- the session gives us options, if we're the
 * client we'll later pick up some fargs that we'll use for additional
 * decisions.
 */
void
cleanup_init(struct cleanup_ctx *ctx, struct sess *sess)
{

	ctx->sess = sess;
}

void
cleanup_set_args(struct cleanup_ctx *ctx, struct fargs *fargs)
{

	ctx->fargs = fargs;
}

void
cleanup_set_child(struct cleanup_ctx *ctx, pid_t pid)
{

	/* No process groups here. */
	assert(pid >= 0);
	ctx->child_pid = pid;
}

void
cleanup_set_download(struct cleanup_ctx *ctx, struct download *dl)
{

	ctx->dl = dl;
}
