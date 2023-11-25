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

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include COMPAT_ENDIAN_H

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>

#include "md4.h"

#include "extern.h"

#ifndef ACCESSPERMS
#define ACCESSPERMS	(S_IRWXU|S_IRWXG|S_IRWXO)
#endif

/*
 * A small optimisation: have a 1 MB pre-write buffer.
 * Disable the pre-write buffer by having this be zero.
 * (It doesn't affect performance much.)
 */
#define	OBUF_SIZE	(1024 * 1024)

enum	downloadst {
	DOWNLOAD_READ_NEXT = 0,
	DOWNLOAD_READ_LOCAL,
	DOWNLOAD_READ_REMOTE
};

/*
 * Like struct upload, but used to keep track of what we're downloading.
 * This also is managed by the receiver process.
 */
struct	download {
	enum downloadst	    state; /* state of affairs */
	size_t		    idx; /* index of current file */
	struct blkset	    blk; /* its blocks */
	void		   *map; /* mmap of current file */
	size_t		    mapsz; /* length of mapsz */
	int		    ofd; /* open origin file */
	int		    fd; /* open output file */
	char		   *fname; /* output filename */
	MD4_CTX		    ctx; /* current hashing context */
	off_t		    downloaded; /* total downloaded */
	off_t		    total; /* total in file */
	const struct flist *fl; /* file list */
	size_t		    flsz; /* size of file list */
	int		    rootfd; /* destination directory */
	int		    fdin; /* read descriptor from sender */
	char		   *obuf; /* pre-write buffer */
	size_t		    obufsz; /* current size of obuf */
	size_t		    obufmax; /* max size we'll wbuffer */
};


/*
 * Simply log the filename.
 */
static void
log_file(struct sess *sess,
	const struct download *dl, const struct flist *f)
{
	float		 frac, tot = dl->total;
	int		 prec = 0;
	const char	*unit = "B";

	if (sess->opts->server)
		return;

	frac = (dl->total == 0) ? 100.0 :
		100.0 * dl->downloaded / dl->total;

	if (dl->total > 1024 * 1024 * 1024) {
		tot = dl->total / (1024. * 1024. * 1024.);
		prec = 3;
		unit = "GB";
	} else if (dl->total > 1024 * 1024) {
		tot = dl->total / (1024. * 1024.);
		prec = 2;
		unit = "MB";
	} else if (dl->total > 1024) {
		tot = dl->total / 1024.;
		prec = 1;
		unit = "KB";
	}

	LOG1("%s (%.*f %s, %.1f%% downloaded)",
	    f->path, prec, tot, unit, frac);
}

/*
 * Reinitialise a download context w/o overwriting the persistent parts
 * of the structure (like p->fl or p->flsz) for index "idx".
 * The MD4 context is pre-seeded.
 */
static void
download_reinit(struct sess *sess, struct download *p, size_t idx)
{
	int32_t seed = htole32(sess->seed);

	assert(p->state == DOWNLOAD_READ_NEXT);

	p->idx = idx;
	memset(&p->blk, 0, sizeof(struct blkset));
	p->map = MAP_FAILED;
	p->mapsz = 0;
	p->ofd = -1;
	p->fd = -1;
	p->fname = NULL;
	MD4_Init(&p->ctx);
	p->downloaded = p->total = 0;
	/* Don't touch p->fl. */
	/* Don't touch p->flsz. */
	/* Don't touch p->rootfd. */
	/* Don't touch p->fdin. */
	MD4_Update(&p->ctx, &seed, sizeof(int32_t));
}

/*
 * Free a download context.
 * If "cleanup" is non-zero, we also try to clean up the temporary file,
 * assuming that it has been opened in p->fd.
 */
static void
download_cleanup(struct download *p, int cleanup)
{

	if (p->map != MAP_FAILED) {
		assert(p->mapsz);
		munmap(p->map, p->mapsz);
		p->map = MAP_FAILED;
		p->mapsz = 0;
	}
	if (p->ofd != -1) {
		close(p->ofd);
		p->ofd = -1;
	}
	if (p->fd != -1) {
		close(p->fd);
		if (cleanup && p->fname != NULL)
			unlinkat(p->rootfd, p->fname, 0);
		p->fd = -1;
	}
	free(p->fname);
	p->fname = NULL;
	p->state = DOWNLOAD_READ_NEXT;
}

/*
 * Initial allocation of the download object using the file list "fl" of
 * size "flsz", the destination "rootfd", and the sender read "fdin".
 * Returns NULL on allocation failure.
 * On success, download_free() must be called with the pointer.
 */
struct download *
download_alloc(struct sess *sess, int fdin,
	const struct flist *fl, size_t flsz, int rootfd)
{
	struct download	*p;

	if ((p = malloc(sizeof(struct download))) == NULL) {
		ERR("malloc");
		return NULL;
	}

	p->state = DOWNLOAD_READ_NEXT;
	p->fl = fl;
	p->flsz = flsz;
	p->rootfd = rootfd;
	p->fdin = fdin;
	download_reinit(sess, p, 0);
	p->obufsz = 0;
	p->obuf = NULL;
	p->obufmax = OBUF_SIZE;
	if (p->obufmax && (p->obuf = malloc(p->obufmax)) == NULL) {
		ERR("malloc");
		free(p);
		return NULL;
	}
	return p;
}

/*
 * Perform all cleanups (including removing stray files) and free.
 * Passing a NULL to this function is ok.
 */
void
download_free(struct download *p)
{

	if (p == NULL)
		return;
	download_cleanup(p, 1);
	free(p->obuf);
	free(p);
}

/*
 * Optimisation: instead of dumping directly into the output file, keep
 * a buffer and write as much as we can into the buffer.
 * That way, we can avoid calling write() too much, and instead call it
 * with big buffers.
 * To flush the buffer w/o changing it, pass 0 as "sz".
 * Returns zero on failure, non-zero on success.
 */
static int
buf_copy(const char *buf, size_t sz, struct download *p, struct sess *sess)
{
	size_t	 rem, tocopy;
	ssize_t	 ssz;

	assert(p->obufsz <= p->obufmax);

	/*
	 * Copy as much as we can.
	 * If we've copied everything, exit.
	 * If we have no pre-write buffer (obufmax of zero), this never
	 * gets called, so we never buffer anything.
	 */

	if (sz && p->obufsz < p->obufmax) {
		assert(p->obuf != NULL);
		rem = p->obufmax - p->obufsz;
		assert(rem > 0);
		tocopy = rem < sz ? rem : sz;
		memcpy(p->obuf + p->obufsz, buf, tocopy);
		sz -= tocopy;
		buf += tocopy;
		p->obufsz += tocopy;
		assert(p->obufsz <= p->obufmax);
		if (sz == 0)
			return 1;
	}

	/* Drain the main buffer. */

	if (p->obufsz) {
		assert(p->obufmax);
		assert(p->obufsz <= p->obufmax);
		assert(p->obuf != NULL);
		if (sess->opts->sparse && iszerobuf(p->obuf, p->obufsz)) {
			if (lseek(p->fd, p->obufsz, SEEK_CUR) == -1) {
				ERR("%s: lseek", p->fname);
				return 0;
		        }
		} else {
			if ((ssz = write(p->fd, p->obuf, p->obufsz)) < 0) {
				ERR("%s: write", p->fname);
				return 0;
			} else if ((size_t)ssz != p->obufsz) {
				ERRX("%s: short write", p->fname);
				return 0;
			}
		}
		p->obufsz = 0;
	}

	/*
	 * Now drain anything left.
	 * If we have no pre-write buffer, this is it.
	 */

	if (sz) {
		if ((ssz = write(p->fd, buf, sz)) < 0) {
			ERR("%s: write", p->fname);
			return 0;
		} else if ((size_t)ssz != sz) {
			ERRX("%s: short write", p->fname);
			return 0;
		}
	}
	return 1;
}

/*
 * Print time as hh:mm:ss
 */
static void
print_time(FILE *f, double time)
{
	int i = time;
	fprintf(f, "   %02d:%02d:%02d",
	    i / 3600, (i - i / 3600 * 3600) / 60,
	    (i - i / 60 * 60));
}

/*
 * Maybe print progress in current file.
 */
static void
progress(struct sess *sess, uint64_t total_bytes, uint64_t so_far)
{
	struct timeval tv;
	double now;
	double rate;
	double remaining_time;

	if (!sess->opts->progress)
		return;

	gettimeofday(&tv, NULL);
	now = tv.tv_sec + (double)tv.tv_usec / 1000000.0;

	if (sess->last_time == 0) {
		sess->last_time = now;
		return;
	}
	if (now - sess->last_time < 0.1)
		return;
	fprintf(stderr, " %14lu", so_far);
	fprintf(stderr, " %3.0f%%", (double)so_far / 
	    (double)total_bytes * 100.0);
	rate = (double)so_far / (now - sess->last_time);
	if (rate > 1024.0 * 1024.0 * 1024.0) {
		fprintf(stderr, " %7.2fGB/s", rate / 
		    1024.0 / 1024.0 / 1024.0);
	} else if (rate > 1024.0 * 1024.0) {
		fprintf(stderr, " %7.2fMB/s", rate / 
		    1024.0 / 1024.0);
	} else if (rate > 1024.0) {
		fprintf(stderr, " %7.2fKB/s", rate / 
		    1024.0);
	}
	remaining_time = (total_bytes - so_far) / rate;
	print_time(stderr, remaining_time);
	fprintf(stderr, "\r");
	sess->last_time = now;
}

/*
 * Infrastructure for --delay-updates.
 */
struct dlrename_entry {
	char *from;  /* Will be free()ed after use */
	const char *to;    /* Will not be free()ed after use */
	const struct flist *file;
	char *rmdir; /* Directory to remove, will free() */
};
struct dlrename {
	struct dlrename_entry *entries;
	struct download *dl;
	const struct hardlinks *hl;
	int n;
	int fd;
};

void
delayed_renames(struct sess *sess)
{
	int i;
	struct dlrename *dlr = sess->dlrename;
	const struct flist *hl_p = NULL;
	struct download *p;

	if (dlr == NULL)
		return;

	p = dlr->dl;
	for (i = 0; i < dlr->n; i++) {
		LOG3("mv '%s' -> '%s'", dlr->entries[i].from,
			dlr->entries[i].to);
		if (sess->opts->hard_links)
			hl_p = find_hl(dlr->entries[i].file, dlr->hl);
		if (renameat(dlr->fd, dlr->entries[i].from, dlr->fd,
				dlr->entries[i].to) == -1) {
			ERR("rename '%s' -> '%s'", dlr->entries[i].from,
				dlr->entries[i].to);
		}
		if (hl_p != NULL) {
			const char *path = dlr->entries[i].to;

			if (unlinkat(p->rootfd, path, 0) == -1)
				if (errno != ENOENT)
					ERRX1("unlink");

			if (linkat(p->rootfd, hl_p->path, p->rootfd, path,
			    0) == -1) {
				LOG0("While hard linking '%s' to '%s' ",
				    hl_p->path, path);
				ERRX1("linkat");
			}

			hl_p = NULL;
		}
		if (unlinkat(dlr->fd, dlr->entries[i].rmdir, AT_REMOVEDIR) == 
			-1) {
			if (errno != ENOTEMPTY) {
				ERR("rmdir '%s'", dlr->entries[i].rmdir);
			}
		}
		free(dlr->entries[i].from);
		free(dlr->entries[i].rmdir);
		dlr->entries[i].from = NULL;
		dlr->entries[i].rmdir = NULL;
	}
	free(dlr->entries);
	dlr->entries = NULL;
	free(sess->dlrename);
	sess->dlrename = NULL;
}

/*
 * Fix metadata of the temp file based on the original destination file.  This
 * is the logical inverse of rsync_set_metadata*() as we're determining which
 * of the metadata won't be clobbered by preseration of the source file.
 */
static int
download_fix_metadata(const struct sess *sess, const char *fname, int fd,
    const struct stat *ost)
{
	uid_t uid = (uid_t)-1, puid = (uid_t)-1;
	gid_t gid = (gid_t)-1, pgid = (gid_t)-1;
	mode_t mode;

	if (!sess->opts->preserve_uids) {
		puid = getuid();

		if (puid != ost->st_uid && puid == 0)
			uid = ost->st_uid;
	}

	if (!sess->opts->preserve_gids) {
		pgid = getgid();

		if (pgid != ost->st_gid)
			gid = ost->st_gid;
	}

	/*
	 * Unlike rsync_set_metadata, we're using perms from the local system
	 * and thus, we'll trust them a little bit more.
	 */
	mode = ost->st_mode & ALLPERMS;
	if (uid != (uid_t)-1 || gid != (gid_t)-1) {
		if (fchown(fd, uid, gid) == -1) {
			if (errno != EPERM) {
				ERR("%s: fchown", fname);
				return 0;
			}
			if (getuid() == 0)
				WARNX("%s: identity unknown or not available "
				    "to user.group: %u.%u", fname, uid, gid);
		}
	}

	if (!sess->opts->preserve_perms && fchmod(fd, mode) == -1) {
		ERR("%s: fchmod", fname);
		return 0;
	}

	return 1;
}

/*
 * The downloader waits on a file the sender is going to give us, opens
 * and mmaps the existing file, opens a temporary file, dumps the file
 * (or metadata) into the temporary file, then renames.
 * This happens in several possible phases to avoid blocking.
 * Returns <0 on failure, 0 on no more data (end of phase), >0 on
 * success (more data to be read from the sender).
 */
int
rsync_downloader(struct download *p, struct sess *sess, int *ofd, int flsz,
    const struct hardlinks *hl)
{
	int		 c;
	int32_t		 idx, rawtok;
	const struct flist *f, *hl_p = NULL;
	size_t		 sz, tok;
	struct stat	 st, st2;
	char		*buf = NULL;
	unsigned char	 ourmd[MD4_DIGEST_LENGTH],
			 md[MD4_DIGEST_LENGTH];
	char             buf2[PATH_MAX];
	char            *usethis;
	int		 dirlen;
	struct dlrename  *renamer = NULL;

	if (sess->opts->dlupdates) {
		if (sess->dlrename == NULL) {
			sess->dlrename = malloc(sizeof(struct dlrename));
			if (sess->dlrename == NULL) {
				ERR("malloc renamer");
				goto out;
			}
			renamer = sess->dlrename;
			renamer->entries = NULL;
			renamer->hl = hl;
			renamer->dl = p;
			renamer->n = 0;
			renamer->fd = p->rootfd;
		} else
			renamer = sess->dlrename;
	}

	/*
	 * If we don't have a download already in session, then the next
	 * one is coming in.
	 * Read either the stop (phase) signal from the sender or block
	 * metadata, in which case we open our file and wait for data.
	 */

	if (p->state == DOWNLOAD_READ_NEXT) {
		if (!io_read_int(sess, p->fdin, &idx)) {
			ERRX1("io_read_int");
			return -1;
		} else if (idx >= 0 && (size_t)idx >= p->flsz) {
			ERRX("index out of bounds");
			return -1;
		} else if (idx < 0) {
			LOG3("downloader: phase complete");
			return 0;
		}

		/* Short-circuit: dry_run mode does nothing. */

		if (sess->opts->dry_run)
			return 1;

		/*
		 * Now get our block information.
		 * This is all we'll need to reconstruct the file from
		 * the map, as block sizes are regular.
		 */

		download_reinit(sess, p, idx);
		if (!blk_send_ack(sess, p->fdin, &p->blk)) {
			ERRX1("blk_send_ack");
			goto out;
		}

		/*
		 * Next, we want to open the existing file for using as
		 * block input.
		 * We do this in a non-blocking way, so if the open
		 * succeeds, then we'll go reentrant til the file is
		 * readable and we can mmap() it.
		 * Set the file descriptor that we want to wait for.
		 */

		p->state = DOWNLOAD_READ_LOCAL;
		f = &p->fl[idx];
		p->ofd = openat(p->rootfd, f->path, O_RDONLY | O_NONBLOCK);
		if (sess->opts->progress && !verbose)
			fprintf(stderr, "%s\n", f->path);

		if (p->ofd == -1 && errno != ENOENT) {
			ERR("%s: openat", f->path);
			goto out;
		} else if (p->ofd != -1) {
			*ofd = p->ofd;
			return 1;
		}

		/* Fall-through: there's no file. */
	}

	/*
	 * At this point, the server is sending us data and we want to
	 * hoover it up as quickly as possible or we'll deadlock.
	 * We want to be pulling off of f->fdin as quickly as possible,
	 * so perform as much buffering as we can.
	 */

	f = &p->fl[p->idx];

	/*
	 * Next in sequence: we have an open download session but
	 * haven't created our temporary file.
	 * This means that we've already opened (or tried to open) the
	 * original file in a nonblocking way, and we can map it.
	 */

	if (p->state == DOWNLOAD_READ_LOCAL) {
		assert(p->fname == NULL);

		/*
		 * Try to fstat() the file descriptor if valid and make
		 * sure that we're still a regular file.
		 * Then, if it has non-zero size, mmap() it for hashing.
		 */

		if (p->ofd != -1 &&
		    fstat(p->ofd, &st) == -1) {
			ERR("%s: fstat", f->path);
			goto out;
		} else if (p->ofd != -1 && !S_ISREG(st.st_mode)) {
			WARNX("%s: not regular", f->path);
			goto out;
		}

		hl_p = find_hl(f, hl);

		if (p->ofd != -1 && st.st_size > 0) {
			p->mapsz = st.st_size;
			p->map = mmap(NULL, p->mapsz,
				PROT_READ, MAP_SHARED, p->ofd, 0);
			if (p->map == MAP_FAILED) {
				ERR("%s: mmap", f->path);
				goto out;
			}
		}

		/* Success either way: we don't need this. */

		*ofd = -1;

		/* Create the temporary file. */
		if (sess->opts->inplace) {
			char *basename;

			p->fd = openat(p->rootfd, f->path, O_RDWR | O_CREAT | O_NONBLOCK,
			    f->st.mode & ACCESSPERMS);
			if (p->fd == -1) {
				ERRX1("%s: open", f->path);
				goto out;
			}

			basename = strrchr(f->path, '/');
			if (basename == NULL)
				basename = f->path;
			else
				basename++;
			p->fname = strdup(basename);
			if (p->fname == NULL) {
				ERRX1("strdup");
				goto out;
			}

			LOG3("%s: writing inplace", f->path);
		} else {
			if (mktemplate(&p->fname, f->path,
			    sess->opts->recursive || sess->opts->relative) ==
				-1) {
				ERRX1("mktemplate");
				goto out;
			}

			if ((p->fd = mkstempat(p->rootfd, p->fname)) == -1) {
				ERR("mkstempat: '%s'", p->fname);
				goto out;
			}

			if (p->ofd != -1 &&
			    !download_fix_metadata(sess, p->fname, p->fd,
			    &st)) {
				goto out;
			}

			/*
			 * FIXME: we can technically wait until the temporary
			 * file is writable, but since it's guaranteed to be
			 * empty, I don't think this is a terribly expensive
			 * operation as it doesn't involve reading the file into
			 * memory beforehand.
			 */

			LOG3("%s: temporary: %s", f->path, p->fname);
		}

		p->state = DOWNLOAD_READ_REMOTE;
		return 1;
	}

	/*
	 * This matches the sequence in blk_flush().
	 * If we've gotten here, then we have a possibly-open map file
	 * (not for new files) and our temporary file is writable.
	 * We read the size/token, then optionally the data.
	 * The size >0 for reading data, 0 for no more data, and <0 for
	 * a token indicator.
	 */

again:
	progress(sess, p->fl[p->idx].st.size, p->downloaded);

	assert(p->state == DOWNLOAD_READ_REMOTE);
	assert(p->fname != NULL);
	assert(p->fd != -1);
	assert(p->fdin != -1);

	if (!io_read_int(sess, p->fdin, &rawtok)) {
		ERRX1("io_read_int");
		goto out;
	}

	if (rawtok > 0) {
		sz = rawtok;
		if ((buf = malloc(sz)) == NULL) {
			ERR("realloc");
			goto out;
		}
		if (!io_read_buf(sess, p->fdin, buf, sz)) {
			ERRX1("io_read_int");
			goto out;
		} else if (!buf_copy(buf, sz, p, sess)) {
			ERRX1("buf_copy");
			goto out;
		}
		p->total += sz;
		p->downloaded += sz;
		LOG4("%s: received %zu B block", p->fname, sz);
		MD4_Update(&p->ctx, buf, sz);
		free(buf);

		/* Fast-track more reads as they arrive. */

		if ((c = io_read_check(p->fdin)) < 0) {
			ERRX1("io_read_check");
			goto out;
		} else if (c > 0)
			goto again;

		return 1;
	} else if (rawtok < 0) {
		tok = -rawtok - 1;
		if (tok >= p->blk.blksz) {
			ERRX("%s: token not in block set: %zu (have %zu blocks)",
			    p->fname, tok, p->blk.blksz);
			goto out;
		}
		sz = tok == p->blk.blksz - 1 ? p->blk.rem : p->blk.len;
		assert(sz);
		assert(p->map != MAP_FAILED);
		buf = p->map + (tok * p->blk.len);

		/*
		 * Now we read from our block.
		 * We should only be at this point if we have a
		 * block to read from, i.e., if we were able to
		 * map our origin file and create a block
		 * profile from it.
		 */

		assert(p->map != MAP_FAILED);
		if (!buf_copy(buf, sz, p, sess)) {
			ERRX1("buf_copy");
			goto out;
		}
		p->total += sz;
		LOG4("%s: copied %zu B", p->fname, sz);
		MD4_Update(&p->ctx, buf, sz);

		/* Fast-track more reads as they arrive. */

		if ((c = io_read_check(p->fdin)) < 0) {
			ERRX1("io_read_check");
			goto out;
		} else if (c > 0)
			goto again;

		return 1;
	}

	if (!buf_copy(NULL, 0, p, sess)) {
		ERRX1("buf_copy");
		goto out;
	}

	assert(rawtok == 0);
	assert(p->obufsz == 0);

	/*
	 * Make sure our resulting MD4 hashes match.
	 * FIXME: if the MD4 hashes don't match, then our file has
	 * changed out from under us.
	 * This should require us to re-run the sequence in another
	 * phase.
	 */

	MD4_Final(ourmd, &p->ctx);

	if (!io_read_buf(sess, p->fdin, md, MD4_DIGEST_LENGTH)) {
		ERRX1("io_read_buf");
		goto out;
	} else if (memcmp(md, ourmd, MD4_DIGEST_LENGTH)) {
		ERRX("%s: hash does not match", p->fname);
		goto out;
	}

	if (sess->opts->backup) {
		if (fstatat(p->rootfd, f->path, &st2, 0) == -1) {
			/*
			 * As-of-now missing file is OK, however
			 * we take no action for --backup.
			 */
			if (errno != ENOENT) {
				ERR("%s: stat during --backup", f->path);
				goto out;
			}
		} else {
			if (!S_ISDIR(st2.st_mode)) {
				LOG2("%s: doing backup", f->path);
				snprintf(buf2, sizeof(buf2), "%s~", f->path);
				if (renameat(p->rootfd, f->path,
					p->rootfd, buf2) == -1) {
					ERR("%s: renameat: %s", f->path, buf2);
					goto out;
				}
			}
		}
	}

	/* Adjust our file metadata (uid, mode, etc.). */

	if (!rsync_set_metadata(sess, p->ofd == -1, p->fd, f, p->fname)) {
		ERRX1("rsync_set_metadata");
		goto out;
	}

	/* 
	 * Finally, rename the temporary to the real file, unless 
	 * --delay-updates is in effect, in which case it is doing to
	 * the .~tmp~ subdirectory for now and is renamed later in
	 * a batch with all the other new or changed files.
	 */
	if (sess->opts->dlupdates) {
		if (renamer->entries == NULL) {
			renamer->entries = calloc(flsz,
				sizeof(struct dlrename_entry));
			if (renamer->entries == NULL) {
				ERR("malloc dlrenamer entries");
				goto out;
			}
			renamer->n = 0;
		}
		renamer->n++;
		if ((usethis = strrchr(f->path, '/')) != NULL) {
			dirlen = usethis - f->path;
			snprintf(buf2, sizeof(buf2), "%.*s/.~tmp~",
			    dirlen, f->path);
			if (mkdirat(p->rootfd, buf2, 0700) == -1)
				if (errno != EEXIST) {
					ERR("mkdir '%s'", buf2);
					goto out;
				}
			renamer->entries[renamer->n - 1].rmdir = strdup(buf2);
			if (renamer->entries[renamer->n - 1].rmdir == NULL) {
				ERR("strdup");
				goto out;
			}
			snprintf(buf2, sizeof(buf2), "%.*s/.~tmp~/%s",
			    dirlen, f->path, f->path + dirlen + 1);
		} else {
			snprintf(buf2, sizeof(buf2), ".~tmp~/%s", f->path);
			if (mkdirat(p->rootfd, ".~tmp~", 0700) == -1)
				if (errno != EEXIST) {
					ERR("mkdir '%s'", buf2);
					goto out;
				}
			renamer->entries[renamer->n - 1].rmdir = strdup(".~tmp~");
			if (renamer->entries[renamer->n - 1].rmdir == NULL) {
				ERR("strdup");
				goto out;
			}
		}
		usethis = buf2;
	} else {
		usethis = f->path;
		if (sess->opts->hard_links)
			hl_p = find_hl(f, hl);
	}
	if (!sess->opts->inplace &&
	    renameat(p->rootfd, p->fname, p->rootfd, usethis) == -1) {
		ERR("%s: renameat: %s", p->fname, usethis);
		goto out;
	}
	if (sess->opts->dlupdates) {
		struct dlrename_entry *entry = &renamer->entries[renamer->n - 1];

		entry->from = strdup(usethis);
		if (entry->from == NULL) {
			ERR("strdup");
			goto out;
		}

		entry->file = f;
		entry->to = f->path;
	} else if (hl_p != NULL) {
		if (unlinkat(p->rootfd, f->path, 0) == -1)
			if (errno != ENOENT)
				ERRX1("unlink");

		if (linkat(p->rootfd, hl_p->path, p->rootfd, f->path, 0) == -1) {
			LOG0("While hard linking '%s' to '%s' ",
			    hl_p->path, f->path);
			ERRX1("linkat");
		}
	}

	progress(sess, p->fl[p->idx].st.size, p->fl[p->idx].st.size);
	if (sess->opts->progress)
		fprintf(stderr, "\n");
	log_file(sess, p, f);
	download_cleanup(p, 0);
	return 1;
out:
	download_cleanup(p, 1);
	return -1;
}
