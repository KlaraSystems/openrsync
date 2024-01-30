/*
 * Platform hooks to more cleanly provide some functionality not otherwise
 * applicable to openrsync at-large.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include "extern.h"

#ifdef __APPLE__
#include <assert.h>
#include <copyfile.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <paths.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define	FLSTAT_PLATFORM_XATTR		FLSTAT_PLATFORM_BIT1

static int
apple_open_xattrs(const struct sess *sess, const struct flist *f, int oflags)
{
	char *path, tmpfile[PATH_MAX];
	size_t idx;
	int copyflags, fd, error, serrno;

	assert(strstr(f->path, "._") != NULL);

	copyflags = COPYFILE_PACK | COPYFILE_ACL | COPYFILE_XATTR;
	if (sess->opts->preserve_links)
		copyflags |= COPYFILE_NOFOLLOW;

	/* Chop off the ._ */
	if (asprintf(&path, "%s/%s", dirname(f->path),
	    basename(f->path) + 2) == -1) {
		ERR("asprintf");
		return -1;
	}

	idx = snprintf(tmpfile, sizeof(tmpfile), "%s.%d.", _PATH_TMP, getpid());

	/* We need to synthesize the xattrs. */
	for (const char *c = f->wpath; *c != '\0' && idx < sizeof(tmpfile) - 1;
	    c++) {
		if (*c == '/')
			tmpfile[idx++] = '_';
		else
			tmpfile[idx++] = *c;
	}

	tmpfile[idx++] = '\0';

	error = copyfile(path, tmpfile, NULL, copyflags);
	free(path);

	if (error != 0) {
		ERR("copyfile");
		return -1;
	}

	fd = open(tmpfile, oflags);
	serrno = errno;
	unlink(tmpfile);

	if (fd == -1)
		errno = serrno;

	return fd;
}

static int
apple_flist_sent(struct sess *sess, int fdout, const struct flist *f)
{
	char send;

	assert(sess->opts->extended_attributes);

	if ((f->st.flags & FLSTAT_PLATFORM_XATTR) != 0)
		send = 1;
	else
		send = 0;

	if (!io_write_byte(sess, fdout, send)) {
		ERRX("io_write_int");
		return 0;
	}

	return 1;
}

#define	HAVE_PLATFORM_FLIST_MODIFY	1
int
platform_flist_modify(const struct sess *sess, struct fl *fl)
{
	struct flist *f;
	size_t insz;
	int copyflags;

	if (!sess->opts->extended_attributes)
		return 1;

	copyflags = COPYFILE_CHECK | COPYFILE_ACL | COPYFILE_XATTR;
	if (sess->opts->preserve_links)
		copyflags |= COPYFILE_NOFOLLOW;
	insz = fl->sz;
	for (size_t i = 0; i < insz; i++) {
		struct flist *packed;
		const char *base;
		int stripdir;

		f = &fl->flp[i];
		base = strrchr(f->path, '/');
		if (base == NULL)
			base = f->path;
		else
			base++;

		if (strncmp(base, "._", 2) == 0)
			goto hooksent;

		if (copyfile(f->path, NULL, 0, copyflags) == 0)
			goto hooksent;

		stripdir = f->wpath - f->path;
		packed = fl_new(fl);
		memcpy(packed, f, sizeof(*f));

		/* Setup the different bits */
		if (asprintf(&packed->path, "%.*s._%s",
		    base - f->path, f->path, basename(f->path)) == -1) {
			ERR("asprintf --extended-attributes path");
			return 0;
		}

		packed->wpath = packed->path + stripdir;
		packed->link = NULL;
		packed->open = &apple_open_xattrs;
		packed->sent = &apple_flist_sent;
		f->st.flags |= FLSTAT_PLATFORM_XATTR;

hooksent:
		f->sent = &apple_flist_sent;
	}

	return 1;
}
#endif

#if !HAVE_PLATFORM_FLIST_MODIFY
int
platform_flist_modify(const struct sess *sess, struct fl *fl)
{

	return 1;
}
#endif

#if !HAVE_PLATFORM_FLIST_RECEIVED
void
platform_flist_received(struct sess *sess, struct flist *fl, size_t flsz)
{

}
#endif

#if !HAVE_PLATFORM_FLIST_ENTRY_RECEIVED
int
platform_flist_entry_received(struct sess *sess, int fdin, struct flist *f)
{

	return 1;
}
#endif

#if !HAVE_PLATFORM_MOVE_FILE
int
platform_move_file(const struct sess *sess, struct flist *fl,
    int fromfd, const char *fname, int tofd, const char *toname, int final)
{

	if (move_file(fromfd, fname, tofd, toname) != 0) {
		ERR("%s: move_file: %s", fname, toname);
		return 0;
	}

	return 1;
}
#endif

#if !HAVE_PLATFORM_FINISH_TRANSFER
int
platform_finish_transfer(const struct sess *sess, struct flist *fl,
    int rootfd, const char *name)
{

	return 1;
}
#endif
