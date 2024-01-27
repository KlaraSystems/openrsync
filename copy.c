/*
 * Copyright (c) 2021 Claudio Jeker <claudio@openbsd.org>
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
#if HAVE_ERR
# include <err.h>
#endif
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

#define _MAXBSIZE (64 * 1024)

/*
 * Return true if all bytes in buffer are zero.
 * A buffer of zero lenght is also considered a zero buffer.
 */
int
iszerobuf(const void *b, size_t len)
{
	const unsigned char *c = b;

	for (; len > 0; len--) {
		if (*c++ != '\0')
			return 0;
	}
	return 1;
}

static int
copy_internal(int fromfd, int tofd)
{
	char buf[_MAXBSIZE];
	ssize_t r, w;

	while ((r = read(fromfd, buf, sizeof(buf))) > 0) {
		if (iszerobuf(buf, sizeof(buf))) {
			if (lseek(tofd, r, SEEK_CUR) == -1)
				return -1;
		} else {
			w = write(tofd, buf, r);
			if (r != w || w == -1)
				return -1;
		}
	}
	if (r == -1)
		return -1;
	if (ftruncate(tofd, lseek(tofd, 0, SEEK_CUR)) == -1)
		return -1;
	return 0;
}

/*
 * Create the directory struction required for storing backups.
 * The fname will be the relative filename prefixed with the backup_dir.
 * We then check the deepest directory and see if we can mkdir it, if we can
 * (or it exists), we advance to the second step.  If the mkdir fails with
 * ENOENT because the parent doesn't exist, we work backwards through the
 * provided path until we find a directory that exists or that we can create.
 *
 * In the second step, we work forwards through the path again and create the
 * child directories required, and chown/chmod them match the directories that
 * we are backing up.
 */
static int
mk_backup_dir(struct sess *sess, int rootfd, const char *fname)
{
	char *bpath, *bporig, *bpend;
	char *bpp;
	char *rpath = NULL;
	mode_t mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
	struct stat st;
	int ret = 0;

	bporig = bpath = strdup(fname);
	if (bpath == NULL) {
		return ENOMEM;
	}
	bpend = bpath + strlen(bpath);
	while (strncmp(bpath, "./", 2) == 0) {
		bpath += 2;
	}
	rpath = bpath + strlen(sess->opts->backup_dir);
	assert(rpath < bpend);
	if (*rpath == '/') {
		rpath++;
	}
	/*
	 * Walk backwards through the backup path to find the deepest directory
	 * that already exists.
	 */
	while ((bpp = strrchr(bpath, '/')) != NULL) {
		*bpp = '\0';
		if ((ret = mkdirat(rootfd, bpath, mode)) == 0 || errno == EEXIST) {
			ret = 0;
			/* Found a directory that exists or that we could create */
			break;
		} else if (errno != ENOENT) {
			ERR("%s: mkdir", bpath);
			goto out;
		}
	}

	/*
	 * Walk forwards through the backup path creating the ancestor directories
	 * as we go.
	 */
	bpp = bpath + strlen(bpath);
	assert(bpp < bpend);
	while (1) {
		if ((rpath + strlen(rpath)) != bpend && *rpath != '\0') {
			if ((ret = fstatat(rootfd, rpath, &st, AT_RESOLVE_BENEATH)) < 0) {
				ERR("%s: stat", rpath);
				goto out;
			} else {
				fchownat(rootfd, bpath, st.st_uid, st.st_gid,
				    AT_SYMLINK_NOFOLLOW);
				fchmodat(rootfd, bpath, st.st_mode,
				    AT_SYMLINK_NOFOLLOW);
			}
		}
		*bpp = '/';
		bpp += strlen(bpp);
		if (bpp == bpend) {
			break;
		}
		assert(bpp < bpend);
		if ((ret = mkdirat(rootfd, bpath, mode)) < 0) {
			ERR("%s: mkdir", bpath);
			goto out;
		}
	}

out:
	free(bporig);
	return ret;
}

int
backup_to_dir(struct sess *sess, int rootfd, const struct flist *f,
    const char *dest, mode_t mode)
{
	int ret = 0;
	struct stat st;

	if (fstatat(rootfd, f->path, &st, AT_SYMLINK_NOFOLLOW) < 0) {
		/* Can't backup files that do not exist */
		return 0;
	}

	if ((ret = mk_backup_dir(sess, rootfd, dest)) != 0) {
		ERR("%s: mk_backup_dir: %s", f->path, dest);
		return ret;
	}

	if (S_ISDIR(mode)) {
		/* Make an empty directory as the backup */
		if ((ret = mkdirat(rootfd, dest, mode)) > 0) {
			ERR("%s: mkdirat", dest);
			return ret;
		}
		unlinkat(rootfd, f->path, AT_REMOVEDIR);
	} else if (sess->opts->preserve_links && S_ISLNK(mode)) {
		/* apply safe_symlinks here */
		unlinkat(rootfd, dest, AT_RESOLVE_BENEATH);
		if ((ret = symlinkat(f->link, rootfd, dest)) < 0) {
			ERR("%s: symlinkat", dest);
			return ret;
		}
		unlinkat(rootfd, f->path, AT_RESOLVE_BENEATH);
	} else if (!S_ISREG(mode)) {
		WARNX("backup_to_dir: skipping non-regular file "
		    "%s\n", f->path);
		return 0;
	} else {
		if ((ret = move_file(rootfd, f->path, rootfd, dest)) < 0) {
			ERR("%s: move_file: %s", f->path, dest);
			return ret;
		}
	}

	return ret;
}

int
move_file(int fromdfd, const char *fname, int todfd, const char *tname)
{
	int fromfd, tofd;
	int ret, serrno;

	/* We'll try a rename(2) first. */
	ret = renameat(fromdfd, fname, todfd, tname);
	if (ret == 0)
		return (0);
	if (ret == -1 && errno != EXDEV)
		return (ret);

	/* Fallback to a copy. */
	fromfd = openat(fromdfd, fname, O_RDONLY | O_NOFOLLOW);
	if (fromfd == -1)
		return (-1);
	tofd = openat(todfd, tname,
	    O_WRONLY | O_NOFOLLOW | O_TRUNC | O_CREAT | O_EXCL,
	    0600);
	if (tofd == -1) {
		serrno = errno;
		close(fromfd);
		errno = serrno;
		return (-1);
	}

	ret = copy_internal(fromfd, tofd);

	serrno = errno;
	close(fromfd);
	close(tofd);
	errno = serrno;

	if (ret == 0)
		(void)unlinkat(fromdfd, fname, 0);

	return (ret);
}

void
copy_file(int rootfd, const char *basedir, const struct flist *f)
{
	int fromfd, tofd, dfd;

	dfd = openat(rootfd, basedir, O_RDONLY | O_DIRECTORY);
	if (dfd == -1)
		err(ERR_FILE_IO, "%s: openat", basedir);

	fromfd = openat(dfd, f->path, O_RDONLY | O_NOFOLLOW);
	if (fromfd == -1)
		err(ERR_FILE_IO, "%s/%s: openat", basedir, f->path);
	close(dfd);

	tofd = openat(rootfd, f->path,
	    O_WRONLY | O_NOFOLLOW | O_TRUNC | O_CREAT | O_EXCL,
	    0600);
	if (tofd == -1)
		err(ERR_FILE_IO, "%s: openat", f->path);

	if (copy_internal(fromfd, tofd) == -1)
		err(ERR_FILE_IO, "%s: copy file", f->path);

	close(fromfd);
	close(tofd);
}
