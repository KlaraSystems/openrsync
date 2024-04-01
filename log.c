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
#include <ctype.h>
#include <errno.h>
#include <libutil.h>
#include <locale.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <libutil.h>
#ifdef __APPLE__
#include <usbuf.h>
#else
#include <sys/sbuf.h>
#endif
#include <sys/stat.h>

#include "extern.h"

#ifndef LOG_NDELAY
#define	LOG_NDELAY	0
#endif

#define	RSYNCD_SYSLOG_IDENT	"openrsyncd"
#define	RSYNCD_SYSLOG_OPTIONS	(LOG_PID | LOG_NDELAY)

extern int verbose;

#define	FACILITY(f)	{ #f, LOG_ ##f }
const struct syslog_facility {
	const char	*name;
	int		 value;
} facilities[] = {
	FACILITY(AUTH),
	FACILITY(AUTHPRIV),
#ifdef LOG_CONSOLE
	FACILITY(CONSOLE),
#endif
	FACILITY(CRON),
	FACILITY(DAEMON),
	FACILITY(FTP),
	FACILITY(KERN),
	FACILITY(LPR),
	FACILITY(MAIL),
	FACILITY(NEWS),
#ifdef LOG_NTP
	FACILITY(NTP),
#endif
#ifdef LOG_SECURITY
	FACILITY(SECURITY),
#endif
	FACILITY(USER),
	FACILITY(UUCP),
	FACILITY(LOCAL0),
	FACILITY(LOCAL1),
	FACILITY(LOCAL2),
	FACILITY(LOCAL3),
	FACILITY(LOCAL4),
	FACILITY(LOCAL6),
	FACILITY(LOCAL7),
};

static FILE *log_file;
static int log_facility = LOG_DAEMON;

int
rsync_set_logfacility(const char *facility)
{
	const struct syslog_facility *def;

	for (size_t i = 0; i < nitems(facilities); i++) {
		def = &facilities[i];

		if (strcasecmp(def->name, facility)) {
			log_facility = def->value;
			return 0;
		}
	}

	errno = ENOENT;
	return -1;
}

static void
rsync_logfile_changed(FILE *old_logfile, FILE *new_logfile)
{

	/* We're the last reference to the log file; close it. */
	if (old_logfile != stderr && old_logfile != NULL)
		fclose(old_logfile);

	if (old_logfile != NULL && new_logfile == NULL) {
		/* <anything> -> syslog */
		openlog(RSYNCD_SYSLOG_IDENT, RSYNCD_SYSLOG_OPTIONS,
		    log_facility);
	} else if (old_logfile == NULL && new_logfile != NULL) {
		closelog();
	}
}

void
rsync_set_logfile(FILE *new_logfile)
{
	FILE *prev_logfile;

	prev_logfile = log_file;
	log_file = new_logfile;

	rsync_logfile_changed(prev_logfile, new_logfile);
}

static void __printflike(2, 0)
log_vwritef(int priority, const char *fmt, va_list ap)
{

	if (log_file == NULL)
		vsyslog(priority, fmt, ap);
	else
		vfprintf(log_file, fmt, ap);
}

static void __printflike(2, 3)
log_writef(int priority, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_vwritef(priority, fmt, ap);
	va_end(ap);
}

/*
 * Log a message at level "level", starting at zero, which corresponds
 * to the current verbosity level opts->verbose (whose verbosity starts
 * at one).
 */
void
rsync_log(int level, const char *fmt, ...)
{
	char	*buf = NULL;
	va_list	 ap;

	if (verbose < level + 1)
		return;

	if (fmt != NULL) {
		va_start(ap, fmt);
		if (vasprintf(&buf, fmt, ap) == -1) {
			va_end(ap);
			return;
		}
		va_end(ap);
	}

	if (level <= 0 && buf != NULL)
		log_writef(LOG_INFO, "%s\n", buf);
	else if (level > 0)
		log_writef(LOG_INFO, "%s: %s%s\n", getprogname(),
		    (buf != NULL) ? ": " : "",
		    (buf != NULL) ? buf : "");
	free(buf);
}

/*
 * This reports an error---not a warning.
 * However, it is not like errx(3) in that it does not exit.
 */
void
rsync_errx(const char *fmt, ...)
{
	char	*buf = NULL;
	va_list	 ap;

	if (fmt != NULL) {
		va_start(ap, fmt);
		if (vasprintf(&buf, fmt, ap) == -1) {
			va_end(ap);
			return;
		}
		va_end(ap);
	}

	log_writef(LOG_ERR, "%s: error%s%s\n", getprogname(),
	   (buf != NULL) ? ": " : "",
	   (buf != NULL) ? buf : "");
	free(buf);
}

/*
 * This reports an error---not a warning.
 * However, it is not like err(3) in that it does not exit.
 */
void
rsync_err(const char *fmt, ...)
{
	char	*buf = NULL;
	va_list	 ap;
	int	 er = errno;

	if (fmt != NULL) {
		va_start(ap, fmt);
		if (vasprintf(&buf, fmt, ap) == -1) {
			va_end(ap);
			return;
		}
		va_end(ap);
	}

	log_writef(LOG_ERR, "%s: error%s%s: %s\n", getprogname(),
	   (buf != NULL) ? ": " : "",
	   (buf != NULL) ? buf : "", strerror(er));
	free(buf);
}

/*
 * Prints a non-terminal error message, that is, when reporting on the
 * chain of functions from which the actual warning occurred.
 */
void
rsync_errx1(const char *fmt, ...)
{
	char	*buf = NULL;
	va_list	 ap;

	if (verbose < 1)
		return;

	if (fmt != NULL) {
		va_start(ap, fmt);
		if (vasprintf(&buf, fmt, ap) == -1) {
			va_end(ap);
			return;
		}
		va_end(ap);
	}

	log_writef(LOG_ERR, "%s: error%s%s\n", getprogname(),
	   (buf != NULL) ? ": " : "",
	   (buf != NULL) ? buf : "");
	free(buf);
}

/*
 * Prints a warning message if we're running -v.
 */
void
rsync_warnx1(const char *fmt, ...)
{
	char	*buf = NULL;
	va_list	 ap;

	if (verbose < 1)
		return;

	if (fmt != NULL) {
		va_start(ap, fmt);
		if (vasprintf(&buf, fmt, ap) == -1) {
			va_end(ap);
			return;
		}
		va_end(ap);
	}

	log_writef(LOG_WARNING, "%s: warning%s%s\n", getprogname(),
	   (buf != NULL) ? ": " : "",
	   (buf != NULL) ? buf : "");
	free(buf);
}

/*
 * Prints a warning message.
 */
void
rsync_warnx(const char *fmt, ...)
{
	char	*buf = NULL;
	va_list	 ap;

	if (fmt != NULL) {
		va_start(ap, fmt);
		if (vasprintf(&buf, fmt, ap) == -1) {
			va_end(ap);
			return;
		}
		va_end(ap);
	}

	log_writef(LOG_WARNING, "%s: warning%s%s\n", getprogname(),
	   (buf != NULL) ? ": " : "",
	   (buf != NULL) ? buf : "");
	free(buf);
}

/*
 * Prints a warning with an errno.
 * It uses a level detector for when to inhibit printing.
 */
void
rsync_warn(int level, const char *fmt, ...)
{
	char	*buf = NULL;
	va_list	 ap;
	int	 er = errno;

	if (verbose < level)
		return;

	if (fmt != NULL) {
		va_start(ap, fmt);
		if (vasprintf(&buf, fmt, ap) == -1) {
			va_end(ap);
			return;
		}
		va_end(ap);
	}

	log_writef(LOG_WARNING, "%s: warning%s%s: %s\n", getprogname(),
	   (buf != NULL) ? ": " : "",
	   (buf != NULL) ? buf : "", strerror(er));
	free(buf);
}

/*
 * Cut down printf implementation taken from printf(1) in
 * FreeBSD 15-current rev 30189156d325fbcc9d1997d791daedc9fa3bed20
 */

static const char widthchars[] = "'+- 0123456789";

/*
 * Copies string 2 into string 1, which is quaranteed to be at least
 * as longly allocated as string 2, omitting "'".  Returns the number
 * of "'"s.
 */

static int
isit_human(char *s1, const char *s2)
{
	char *p1;
	const char *p2;
	int count = 0;

	for (p1 = s1, p2 = s2; *p2; p2++) {
		if (*p2 == '\'')
			count++;
		else
			*p1++ = *p2;
	}
	*p1 = '\0';

	return count;
}

/*
 * Do the 8-bit escaping as needed for `s`.  If `sbuf` is NULL, then the result
 * will be written to the log file -- otherwise, it'll be stashed in the sbuf
 * passed in as requested.
 */
int __printflike(2, 0)
print_7_or_8_bit(const struct sess *sess, const char *fmt, const char *s,
    struct sbuf *sbuf)
{
	const char *p;
	struct sbuf *innerbuf;

	if (sess->opts->bit8) {
		if (sbuf != NULL)
			sbuf_printf(sbuf, fmt, s);
		else
			log_writef(LOG_INFO, fmt, s);

		return 1;
	}

	innerbuf = sbuf_new_auto();
	if (innerbuf == NULL) {
		ERR("sbuf_new_auto");
		return 0;
	}

	for (p = s; *p; p++) {
		if (isprint(*(unsigned char*)p) || *p == '\t') {
			sbuf_putc(innerbuf, *p);
		} else {
			sbuf_printf(innerbuf, "\\#%03o", *(unsigned char*)p);
		}
	}

	if (sbuf_finish(innerbuf) != 0) {
		ERR("sbuf_finish");
		sbuf_delete(innerbuf);
		return 0;
	}

	if (sbuf != NULL)
		sbuf_printf(sbuf, fmt, sbuf_data(innerbuf));
	else
		log_writef(LOG_INFO, fmt, sbuf_data(innerbuf));
	sbuf_delete(innerbuf);

	return 1;
}

/*
 * rval is filled with whether there is any argument that requires
 * late printing or whether itemization is requested.
 * 0 = neither
 * 1 = %i
 * 2 = late print
 * 4 = %o
 *
 * rval is expected to be initialized to zero before the first call.
 */
static const char * __printflike(1, 0)
printf_doformat(const char *fmt, int *rval, const struct sess *sess,
    const struct flist *fl, struct sbuf *sbuf)
{
	static const char skip1[] = "'-+ 0";
	char convch;
	char start[strlen(fmt) + 1];
	char *dptr;
	size_t l;
	char widthstring[8192];
	int humanlevel = 0;

	dptr = start;
	*dptr++ = '%';
	*dptr = 0;

	fmt++;

	widthstring[0] = '%';
	l = strspn(fmt, widthchars);
	/* We need a reserve of 4 chars for substitutions below, plus lead */
	if (l + 5u > sizeof(widthstring)) {
		ERRX("Insufficient buffer for width format");
		return NULL;
	}
	strlcpy(widthstring + 1, fmt, l + 1);

	if (strchr(widthstring, '\'')) {
		char *cooked = malloc(strlen(widthstring));

		if (cooked == NULL) {
			ERR("malloc");
			return NULL;
		}
		humanlevel = isit_human(cooked, widthstring);
		strlcpy(widthstring, cooked, l + 1);
		l -= humanlevel;
		free(cooked);
	}

	/* skip to field width */
	while (*fmt && strchr(skip1, *fmt) != NULL) {
		*dptr++ = *fmt++;
		*dptr = 0;
	}
	if (!*fmt) {
		ERRX("missing format character");
		return NULL;
	}
	while (isdigit(*fmt)) {
		*dptr++ = *fmt++;
		*dptr = 0;
	}

	*dptr++ = *fmt;
	*dptr = 0;
	convch = *fmt;
	fmt++;

	switch (convch) {
	case 'a':	/* Server address (daemon) */
	case 'h': {	/* Remote host (daemon) */
		if (!sess->opts->daemon)
			break;	/* Nop in non-daemon mode. */
		/* FALLTHROUGH */
	}
	case 'm':	/* Module */
	case 'P':	/* Module path */
	case 'u': {	/* Auth username */
		const char *rolestr = NULL;

		/*
		 * These are also effectively daemon-only, but we'll still
		 * render a blank string for clients.  All of them are delegated
		 * to the role.
		 */
		if (sess->role->role_fetch_outfmt != NULL) {
			rolestr = sess->role->role_fetch_outfmt(sess,
			    sess->role->role_fetch_outfmt_cookie, convch);
		}
		if (rolestr == NULL)
			rolestr = "";

		if (sbuf != NULL) {
			widthstring[l + 1] = 's';
			widthstring[l + 2] = '\0';
			sbuf_printf(sbuf, widthstring, rolestr);
		}

		break;
	}
	case 'b': {
		char foo[8192];
		uint64_t bytes_transferred;
		*rval |= 2;

		bytes_transferred = sess->total_read - sess->total_read_lf +
			sess->total_write - sess->total_write_lf;

		if (sbuf != NULL) {
			switch (humanlevel) {
			case 0:
				widthstring[l + 1] = 'l';
				widthstring[l + 2] = 'd';
				widthstring[l + 3] = '\0';
				sbuf_printf(sbuf, widthstring,
				    bytes_transferred);
				break;
			case 1:
				widthstring[l + 1] = 'l';
				widthstring[l + 2] = 'd';
				widthstring[l + 3] = '\0';
				sbuf_printf(sbuf, widthstring,
				    bytes_transferred);
				break;
			case 2:
				humanize_number(foo, 5, bytes_transferred,
				    "", HN_AUTOSCALE, HN_DECIMAL|HN_NOSPACE);
				widthstring[l + 1] = 's';
				widthstring[l + 2] = '\0';
				sbuf_printf(sbuf, widthstring, foo);
				break;
			case 3:
				humanize_number(foo, 5, bytes_transferred, "",
				    HN_AUTOSCALE,
				    HN_DECIMAL|HN_NOSPACE|HN_DIVISOR_1000);
				widthstring[l + 1] = 's';
				widthstring[l + 2] = '\0';
				sbuf_printf(sbuf, widthstring, foo);
				break;
			}
		}
		break;
	}
	case 'B': {
		/* Print mode human-readable */
		char buf[STRMODE_BUFSZ];

		if (sbuf != NULL) {
			our_strmode(fl->st.mode, buf);
			widthstring[l + 1] = 's';
			widthstring[l + 2] = '\0';
			sbuf_printf(sbuf, widthstring, buf);
		}
		break;
	}
	case 'c': {
		/* "%c the total size of the block checksums received for the
		   basis file (only when sending)" */
		/*
		 * I don't think smb rsync implements what it says in the
		 * manpage.
		 */
		*rval |= 2;
		break;
	}
#if 0
	case 'C': {

		/* This is a rsync 3.x feature */

		/* the full-file checksum if it is known for the file.
		 * For older rsync protocols/versions, the checksum
		 * was salted, and is thus not a useful value (and is
		 * not dis- played when that is the case). For the
		 * checksum to output for a file, either the
		 * --checksum option must be in-ef- fect or the file
		 * must have been transferred without a salted
		 * checksum being used.  See the --checksum-choice
		 * option for a way to choose the algorithm.
		*/

		break;
	}
#endif
	case 'f': {
		/*
		 * "the filename (long form on sender; no trailing "/")"
		 */
		if (sbuf != NULL) {
			widthstring[l + 1] = 's';
			widthstring[l + 2] = '\0';
			if (!print_7_or_8_bit(sess, widthstring, fl->path,
			    sbuf)) {
				ERRX("print_7_or_8_bit");
				return NULL;
			}
		}
		break;
	}
	case 'G': {
		/* FIXME this is incorrect since gid 0 is also root */
		if (sbuf != NULL) {
			if (fl->st.gid) {
				widthstring[l + 1] = 'd';
				widthstring[l + 2] = '\0';
				sbuf_printf(sbuf, widthstring, fl->st.gid);
			} else {
				widthstring[l + 1] = 's';
				widthstring[l + 2] = '\0';
				sbuf_printf(sbuf, widthstring, "DEFAULT");
			}
		}
		break;
	}
	case 'i': {
		/* itemize string YXcstpogz */
		char buf[10];
		int32_t ifl;

		*rval |= 1;
		if (sbuf != NULL) {
			ifl = fl->iflags;
			if (ifl & IFLAG_DELETED) {
				/*
				 * TODO - this is not filled in by
				 * mainline code yet.  Never gets here.
				 */
				strlcpy(buf, "*deleted", sizeof(buf));
				break;
			}
			bzero(buf, sizeof(buf));

			/* TODO: finish buf[0].  This is very approximate */
			if (ifl & IFLAG_HLINK_FOLLOWS)
				buf[0] = 'h';
			if (S_ISDIR(fl->st.mode))
				buf[0] = 'c';
			if (S_ISLNK(fl->st.mode))
				buf[0] = 'c';
			if (buf[0] == '\0' ) {
				if (sess->opts->sender)
					buf[0] = '>';
				else
					buf[0] = '<';
			}

			if (S_ISDIR(fl->st.mode))
				buf[1] = 'd';
			if (S_ISLNK(fl->st.mode))
				buf[1] = 'L';
			if (S_ISSOCK(fl->st.mode) || S_ISFIFO(fl->st.mode))
				buf[1] = 'S';
			if (S_ISBLK(fl->st.mode) || S_ISCHR(fl->st.mode))
				buf[1] = 'D';
			if (buf[1] == '\0')
				buf[1] = 'f';

			if (ifl & IFLAG_CHECKSUM)
				buf[2] = 'c';
			else
				buf[2] = '.';

			if (ifl & IFLAG_SIZE)
				buf[3] = 's';
			else
				buf[3] = '.';

			buf[4] = '.';
			if (ifl & IFLAG_TIME) {
				if (!sess->opts->preserve_times ||
				    S_ISLNK(fl->st.mode)) {
					buf[4] = 'T';
				} else {
					buf[4] = 't';
				}
			}

			if (ifl & IFLAG_PERMS)
				buf[5] = 'p';
			else
				buf[5] = '.';

			if (ifl & IFLAG_OWNER)
				buf[6] = 'o';
			else
				buf[6] = '.';

			if (ifl & IFLAG_GROUP)
				buf[7] = 'g';
			else
				buf[7] = '.';

			buf[8] = '.';

			if (ifl & IFLAG_MISSING_DATA || ifl & IFLAG_NEW) {
				char c;

				if (ifl & IFLAG_NEW)
					c = '+';
				else
					c = '?';
				buf[2] = c; buf[3] = c; buf[4] = c;
				buf[5] = c; buf[6] = c; buf[7] = c;
				buf[8] = c;
			} else {
				if (buf[0] == '.' || buf[0] == 'h' ||
				    (buf[0] == 'c' && buf[1] == 'f')) {
					/* TODO: that weird space-filling */
				}
			}

			widthstring[l + 1] = 's';
			widthstring[l + 2] = '\0';
			sbuf_printf(sbuf, widthstring, buf);
		}
		break;
	}
	case 'l': {
		/* File length */
		char foo[8192];

		if (sbuf != NULL) {
			switch (humanlevel) {
			case 0:
				widthstring[l + 1] = 'l';
				widthstring[l + 2] = 'd';
				widthstring[l + 3] = '\0';
				sbuf_printf(sbuf, widthstring, fl->st.size);
				break;
			case 1:
				/* TODO for 3.x: use a printf with "'" */
				widthstring[l + 1] = '\'';
				widthstring[l + 2] = 'l';
				widthstring[l + 3] = 'd';
				widthstring[l + 4] = '\0';
				sbuf_printf(sbuf, widthstring, fl->st.size);
				break;
			case 2:
				humanize_number(foo, 5, fl->st.size,
				    "", HN_AUTOSCALE, HN_DECIMAL|HN_NOSPACE);
				widthstring[l + 1] = 's';
				widthstring[l + 2] = '\0';
				sbuf_printf(sbuf, widthstring, foo);
				break;
			case 3:
				humanize_number(foo, 5, fl->st.size, "", HN_AUTOSCALE,
				    HN_DECIMAL|HN_NOSPACE|HN_DIVISOR_1000);
				widthstring[l + 1] = 's';
				widthstring[l + 2] = '\0';
				sbuf_printf(sbuf, widthstring, foo);
				break;
			}
		}
		break;
	}
	case 'L': {
		char buf[8192];

		/*
		 * We set *rval |= 2
		 * for "late print" here.  Theoretically late print is
		 * only needed when hardlink printing is requested.
		 * But with just the format string we can't tell
		 * whether there will ever be hardlinks.
		 */
		*rval |= 2;

		if (sbuf != NULL) {
			if (fl->iflags & IFLAG_HLINK_FOLLOWS) {
				snprintf(buf, sizeof(buf), " => %s", fl->link);
				widthstring[l + 1] = 's';
				widthstring[l + 2] = '\0';
				if (!print_7_or_8_bit(sess, widthstring, buf,
				    sbuf)) {
					ERRX("print_7_or_8_bit");
					return NULL;
				}
			} else if (fl->link != NULL) {
				snprintf(buf, sizeof(buf), " -> %s", fl->link);
				widthstring[l + 1] = 's';
				widthstring[l + 2] = '\0';
				if (!print_7_or_8_bit(sess, widthstring, buf,
				    sbuf)) {
					ERRX("print_7_or_8_bit");
					return NULL;
				}
			}

		}
		break;
	}
	case 'M': {
		/* Modification time of item */
		char buf[8192];

		if (sbuf != NULL) {
			/* 2024/01/30-16:23:29 */
			strftime(buf, sizeof(buf), "%Y/%m/%d-%H:%M:%S",
			    localtime(&fl->st.mtime));
			widthstring[l + 1] = 's';
			widthstring[l + 2] = '\0';
			sbuf_printf(sbuf, widthstring, buf);
		}
		break;
	}
	case 'n': {
		/* Alternate file name print */
		char buf[8192];

		if (sbuf != NULL) {
			widthstring[l + 1] = 's';
			widthstring[l + 2] = '\0';
			/* "(short form; trailing "/" on dir)" */
			if (S_ISDIR(fl->st.mode))
				snprintf(buf, sizeof(buf), "%s/", fl->wpath);
			else
				snprintf(buf, sizeof(buf), "%s", fl->wpath);
			if (!print_7_or_8_bit(sess, widthstring, buf,
			    sbuf)) {
				ERRX("print_7_or_8_bit");
				return NULL;
			}
		}
		break;
	}
	case 'o': {
		*rval |= 4;
		/*
		 * "the operation, which is "send", "recv", or "del." (the
		 * latter includes the trailing period)"
		 */
		if (sbuf != NULL) {
			widthstring[l + 1] = 's';
			widthstring[l + 2] = '\0';
			if (!print_7_or_8_bit(sess, widthstring,
			    sess->opts->sender ? "send" : "recv", sbuf)) {
				ERRX("print_7_or_8_bit");
				return NULL;
			}
		}
		break;
	}
	case 'p': {
		/* PID as a number */
		if (sbuf != NULL) {
			widthstring[l + 1] = 'd';
			widthstring[l + 2] = '\0';
			/* TODO: capture top-level pid in main() */
			sbuf_printf(sbuf, widthstring, getpid());
		}
		break;
	}
	case 't': {
		/* Current machine time */
		char buf[8192];
		time_t now;

		if (sbuf != NULL) {
			time(&now);
			strftime(buf, sizeof(buf), "%Y/%m/%d-%H:%M:%S",
			    localtime(&now));
			widthstring[l + 1] = 's';
			widthstring[l + 2] = '\0';
			sbuf_printf(sbuf, widthstring, buf);
		}
		break;
	}
	case 'U': {
		/* FIXME this is incorrect since uid 0 is also root */
		if (sbuf != NULL) {
			if (fl->st.uid) {
				widthstring[l + 1] = 'd';
				widthstring[l + 2] = '\0';
				sbuf_printf(sbuf, widthstring, fl->st.uid);
			} else {
				widthstring[l + 1] = 's';
				widthstring[l + 2] = '\0';
				sbuf_printf(sbuf, widthstring, "DEFAULT");
			}
		}
		break;
	}
	}
	return fmt;
}

int
output(struct sess *sess, const struct flist *fl, int do_print)
{
	size_t len;
	int end, rval = 0;
	const char *start;
	const char *fmt, *format;
	struct sbuf *sbuf;

	if (sess->opts->outformat == NULL)
		return 0;

	sbuf = NULL;
	if (do_print) {
		sbuf = sbuf_new_auto();
		if (sbuf == NULL) {
			ERR("sbuf_new_auto");
			return 0;
		}
	}

	fmt = format = sess->opts->outformat;
	len = strlen(fmt);
	rval = end = 0;

	for (; *fmt;) {
		start = fmt;
		while (fmt < format + len) {
			if (fmt[0] == '%') {
				if (do_print)
					sbuf_bcat(sbuf, start, fmt - start);
				if (fmt[1] == '%') {
					/* %% prints a % */
					if (do_print)
						sbuf_putc(sbuf, '%');
					fmt += 2;
				} else {
					fmt = printf_doformat(fmt, &rval, sess,
					    fl, sbuf);
					if (fmt == NULL || *fmt == '\0')
						goto out;
					end = 0;
				}
				start = fmt;
			} else
				fmt++;
		}
		if (end == 1) {
			ERRX("missing format character");
			if (sbuf != NULL)
				sbuf_delete(sbuf);
			return rval;
		}
		if (do_print)
			sbuf_bcat(sbuf, start, fmt - start);
	}

out:
	if (do_print) {
		sbuf_putc(sbuf, '\n');

		if (sbuf_finish(sbuf) != 0) {
			ERR("sbuf_finish");
			sbuf_delete(sbuf);
			return 0;
		}

		log_writef(LOG_INFO, "%s", sbuf_data(sbuf));
		sbuf_delete(sbuf);
	} else {
		assert(sbuf == NULL);
	}

	sess->total_read_lf = sess->total_read;
	sess->total_write_lf = sess->total_write;
	return rval;
}

/*
 * Print a number into the provided buffer depending on the current
 * --human-readable level.
 * Returns 0 on success, -1 if the buffer is too small.
 */
int
rsync_humanize(struct sess *sess, char *buf, size_t len, int64_t val)
{
	size_t res;
	char tbuf[32];

	switch (sess->opts->human_readable) {
	case 0:
		humanize_number(tbuf, sizeof(tbuf), val, "B", 0, 0);
		res = snprintf(buf, len, "%s", tbuf);
		break;
	case 1:
		humanize_number(tbuf, 9, val, "B",
		    HN_AUTOSCALE, HN_DECIMAL|HN_DIVISOR_1000);
		res = snprintf(buf, len, "%s", tbuf);
		break;
	case 2:
		humanize_number(tbuf, 10, val, "B",
		    HN_AUTOSCALE, HN_DECIMAL|HN_IEC_PREFIXES);
		res = snprintf(buf, len, "%s", tbuf);
		break;
	}

	if (res >= len) {
		return -1;
	}

	return 0;
}
