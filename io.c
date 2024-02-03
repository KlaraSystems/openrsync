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
#if HAVE_SYS_QUEUE
#include <sys/queue.h>
#endif

#include <assert.h>
#include COMPAT_ENDIAN_H
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

struct io_tag_handler {
	SLIST_ENTRY(io_tag_handler)	 entry;
	io_tag_handler_fn		*handler;
	void				*cookie;
	enum iotag			 tag;
};

static SLIST_HEAD(, io_tag_handler) io_tag_handlers =
    SLIST_HEAD_INITIALIZER(io_tag_handlers);

/*
 * A non-blocking check to see whether there's POLLIN data in fd.
 * Returns <0 on failure, 0 if there's no data, >0 if there is.
 */
int
io_read_check(int fd)
{
	struct pollfd	pfd;

	pfd.fd = fd;
	pfd.events = POLLIN;

	if (poll(&pfd, 1, 0) == -1) {
		ERR("poll");
		return -1;
	}
	return (pfd.revents & POLLIN);
}

/*
 * Write buffer to non-blocking descriptor.
 * Returns zero on failure, non-zero on success (zero or more bytes).
 * On success, fills in "sz" with the amount written.
 */
static int
io_write_nonblocking(int fd, const void *buf, size_t bsz,
    size_t *sz)
{
	struct pollfd	pfd;
	ssize_t		wsz;
	int		c;

	*sz = 0;

	if (bsz == 0)
		return 1;

	pfd.fd = fd;
	pfd.events = POLLOUT;

	/* Poll and check for all possible errors. */

	if ((c = poll(&pfd, 1, poll_timeout)) == -1) {
		ERR("poll");
		return 0;
	} else if (c == 0) {
		ERRX("poll: timeout");
		return 0;
	} else if ((pfd.revents & (POLLERR|POLLNVAL))) {
		ERRX("poll: bad fd");
		return 0;
	} else if ((pfd.revents & POLLHUP)) {
		ERRX("poll: hangup");
		return 0;
	} else if (!(pfd.revents & POLLOUT)) {
		ERRX("poll: unknown event");
		return 0;
	}

	/* Now the non-blocking write. */

	if ((wsz = write(fd, buf, bsz)) == -1) {
		ERR("write");
		return 0;
	}

	*sz = wsz;
	return 1;
}

/*
 * Blocking write of the full size of the buffer.
 * Returns 0 on failure, non-zero on success (all bytes written).
 */
static int
io_write_blocking(int fd, const void *buf, size_t sz)
{
	size_t		wsz;
	int		c;

	while (sz > 0) {
		c = io_write_nonblocking(fd, buf, sz, &wsz);
		if (!c) {
			ERRX1("io_write_nonblocking");
			return 0;
		} else if (wsz == 0) {
			ERRX("io_write_nonblocking: short write");
			return 0;
		}
		buf += wsz;
		sz -= wsz;
	}

	return 1;
}

/*
 * Write "buf" of size "sz" to non-blocking descriptor.
 * Returns zero on failure, non-zero on success (all bytes written to
 * the descriptor).
 */
static int
io_write_buf_tagged(struct sess *sess, int fd, const void *buf, size_t sz,
    enum iotag iotag)
{
	int32_t	 tag, tagbuf;
	size_t	 wsz;
	int	 c;

	if (!sess->mplex_writes) {
		/*
		 * If we try to write non-data to a non-multiplexed socket, then
		 * we're going to have a bad time.
		 */
		assert(iotag == IT_DATA);

		c = io_write_blocking(fd, buf, sz);
		sess->total_write += sz;
		return c;
	}

	/*
	 * Some things can send 0-byte buffers in the reference implementation,
	 * but I think those are all peer messages rather than client <-> server
	 */
	while (sz > 0) {
		wsz = (sz < 0xFFFFFF) ? sz : 0xFFFFFF;
		tag = ((iotag + IOTAG_OFFSET) << 24) + wsz;
		tagbuf = htole32(tag);
		if (!io_write_blocking(fd, &tagbuf, sizeof(tagbuf))) {
			ERRX1("io_write_blocking");
			return 0;
		}
		if (!io_write_blocking(fd, buf, wsz)) {
			ERRX1("io_write_blocking");
			return 0;
		}
		sess->total_write += wsz;
		sz -= wsz;
		buf += wsz;
	}

	return 1;
}

int
io_write_buf(struct sess *sess, int fd, const void *buf, size_t sz)
{

	return io_write_buf_tagged(sess, fd, buf, sz, IT_DATA);
}

/*
 * Write "line" (NUL-terminated) followed by a newline.
 * Returns zero on failure, non-zero on success.
 */
int
io_write_line(struct sess *sess, int fd, const char *line)
{

	if (!io_write_buf(sess, fd, line, strlen(line)))
		ERRX1("io_write_buf");
	else if (!io_write_byte(sess, fd, '\n'))
		ERRX1("io_write_byte");
	else
		return 1;

	return 0;
}

/*
 * Read buffer from non-blocking descriptor.
 * Returns zero on failure, non-zero on success (zero or more bytes).
 */
static int
io_read_nonblocking(int fd, void *buf, size_t bsz, size_t *sz)
{
	struct pollfd	pfd;
	ssize_t		rsz;
	int		c;

	*sz = 0;

	if (bsz == 0)
		return 1;

	pfd.fd = fd;
	pfd.events = POLLIN;

	/* Poll and check for all possible errors. */

	if ((c = poll(&pfd, 1, poll_timeout)) == -1) {
		ERR("poll");
		return 0;
	} else if (c == 0) {
		ERRX("poll: timeout");
		return 0;
	} else if ((pfd.revents & (POLLERR|POLLNVAL))) {
		ERRX("poll: bad fd");
		return 0;
	} else if (!(pfd.revents & (POLLIN|POLLHUP))) {
		ERRX("poll: unknown event");
		return 0;
	}

	/* Now the non-blocking read, checking for EOF. */

	if ((rsz = read(fd, buf, bsz)) == -1) {
		ERR("read");
		return 0;
	} else if (rsz == 0) {
		ERRX("unexpected end of file");
		return 0;
	}

	*sz = rsz;
	return 1;
}

/*
 * Blocking read of the full size of the buffer.
 * This can be called from either the error type message or a regular
 * message---or for that matter, multiplexed or not.
 * Returns 0 on failure, non-zero on success (all bytes read).
 */
static int
io_read_blocking(int fd, void *buf, size_t sz)
{
	size_t	 rsz;
	int	 c;

	while (sz > 0) {
		c = io_read_nonblocking(fd, buf, sz, &rsz);
		if (!c) {
			ERRX1("io_read_nonblocking");
			return 0;
		} else if (rsz == 0) {
			ERRX("io_read_nonblocking: short read");
			return 0;
		}
		buf += rsz;
		sz -= rsz;
	}

	return 1;
}

int
io_register_handler(enum iotag tag, io_tag_handler_fn *fn, void *cookie)
{
	struct io_tag_handler *ihandler;

#ifndef NDEBUG
	SLIST_FOREACH(ihandler, &io_tag_handlers, entry) {
		assert(ihandler->tag != tag);
	}
#endif

	ihandler = malloc(sizeof(*ihandler));
	if (ihandler == NULL) {
		ERR("malloc");
		return 0;
	}

	ihandler->handler = fn;
	ihandler->cookie = cookie;
	ihandler->tag = tag;
	SLIST_INSERT_HEAD(&io_tag_handlers, ihandler, entry);
	return 1;
}

/*
 * Call a handler for the tag with the given buffer.
 * Returns 1 if the tag was handled, and sets *ret to the handler's return
 * value, or 0 if the tag was not handled.
 */
static int
io_call_handler(enum iotag tag, const void *buffer, size_t bufsz, int *ret)
{
	struct io_tag_handler *ihandler;

	SLIST_FOREACH(ihandler, &io_tag_handlers, entry) {
		if (ihandler->tag == tag) {
			*ret = (*ihandler->handler)(ihandler->cookie, buffer,
			    bufsz);
			return 1;
		}
	}

	return 0;
}

/*
 * When we do a lot of writes in a row (such as when the sender emits
 * the file list), the server might be sending us multiplexed log
 * messages.
 * If it sends too many, it clogs the socket.
 * This function looks into the read buffer and clears out any log
 * messages pending.
 * If called when there are valid data reads available, this function
 * does nothing.
 * Returns zero on failure, non-zero on success.
 */
int
io_read_flush(struct sess *sess, int fd)
{
	int32_t	 tagbuf, tag;
	char	 mpbuf[1024];
	size_t	 mpbufsz;
	int	 ret;

	if (sess->mplex_read_remain)
		return 1;

	/*
	 * First, read the 4-byte multiplex tag.
	 * The first byte is the tag identifier (7 for normal
	 * data, !7 for out-of-band data), the last three are
	 * for the remaining data size.
	 */

	if (!io_read_blocking(fd, &tagbuf, sizeof(tagbuf))) {
		ERRX1("io_read_blocking");
		return 0;
	}
	tag = le32toh(tagbuf);
	sess->mplex_read_remain = tag & 0xFFFFFF;
	tag >>= 24;
	tag -= IOTAG_OFFSET;
	if (tag == IT_DATA)
		return 1;

	if (sess->mplex_read_remain > sizeof(mpbuf)) {
		ERRX("multiplex buffer overflow");
		return 0;
	}

	if ((mpbufsz = sess->mplex_read_remain) != 0) {
		if (!io_read_blocking(fd, mpbuf, mpbufsz)) {
			ERRX1("io_read_blocking");
			return 0;
		}
		if (mpbuf[mpbufsz - 1] == '\n')
			mpbuf[--mpbufsz] = '\0';

		/*
		 * We'll either handle the payload or it will get dropped; in
		 * either case, there's nothing persisting for the caller to
		 * be able to read -- zap the size.
		 */
		sess->mplex_read_remain = 0;
	}

	/*
	 * We'll call the handler for all tagged data, regardless of whether it
	 * had a non-empty payload.  Handlers should cope with having
	 * insufficient data either way.
	 */
	if (io_call_handler(tag, mpbuf, mpbufsz, &ret))
		return ret;

	/*
	 * Always print the server's messages, as the server
	 * will control its own log levelling.
	 */
	if (tag >= IT_ERROR_XFER && tag <= IT_WARNING) {
		if (mpbufsz != 0)
			LOG0("%.*s", (int)mpbufsz, mpbuf);

		if (tag == IT_ERROR_XFER || tag == IT_ERROR) {
			ERRX1("error from remote host");
			return 0;
		}
	}

	return 1;
}

/*
 * Read buffer from non-block descriptor, possibly in multiplex read
 * mode, until a newline or the buffer size has been exhausted.
 * Returns zero on failure, non-zero on success (all bytes read from
 * the descriptor or a newline has been hit).  The newline is omitted from the
 * final result, and *sz is updated with the size of the line.
 */
int
io_read_line(struct sess *sess, int fd, char *buf, size_t *sz)
{
	size_t	i, insz = *sz;
	unsigned char byte;

	for (i = 0; i < insz; i++) {
		if (!io_read_byte(sess, fd, &byte)) {
			ERRX1("io_read_byte");
			return 0;
		}
		if (byte == '\n') {
			buf[i] = '\0';
			*sz = i;
			return 1;
		}

		buf[i] = byte;
	}

	/* Buffer is full before reaching EOL -- kick back what we have. */
	return 1;
}

/*
 * Read buffer from non-blocking descriptor, possibly in multiplex read
 * mode.
 * Returns zero on failure, non-zero on success (all bytes read from
 * the descriptor).
 */
int
io_read_buf(struct sess *sess, int fd, void *buf, size_t sz)
{
	size_t	 rsz;
	int	 c;

	/* If we're not multiplexing, read directly. */

	if (!sess->mplex_reads) {
		assert(sess->mplex_read_remain == 0);
		c = io_read_blocking(fd, buf, sz);
		sess->total_read += sz;
		return c;
	}

	while (sz > 0) {
		/*
		 * First, check to see if we have any regular data
		 * hanging around waiting to be read.
		 * If so, read the lesser of that data and whatever
		 * amount we currently want.
		 */

		if (sess->mplex_read_remain) {
			rsz = sess->mplex_read_remain < sz ?
				sess->mplex_read_remain : sz;
			if (!io_read_blocking(fd, buf, rsz)) {
				ERRX1("io_read_blocking");
				return 0;
			}
			sz -= rsz;
			sess->mplex_read_remain -= rsz;
			buf += rsz;
			sess->total_read += rsz;
			continue;
		}

		assert(sess->mplex_read_remain == 0);
		if (!io_read_flush(sess, fd)) {
			ERRX1("io_read_flush");
			return 0;
		}
	}

	return 1;
}

/*
 * Like io_write_buf(), but for a long (which is a composite type).
 * Returns zero on failure, non-zero on success.
 */
int
io_write_ulong(struct sess *sess, int fd, uint64_t val)
{
	uint64_t	nv;
	int64_t		sval = (int64_t)val;

	/* Short-circuit: send as an integer if possible. */

	if (sval <= INT32_MAX && sval >= 0) {
		if (!io_write_int(sess, fd, (int32_t)val)) {
			ERRX1("io_write_int");
			return 0;
		}
		return 1;
	}

	/* Otherwise, pad with -1 32-bit, then send 64-bit. */

	nv = htole64(val);

	if (!io_write_int(sess, fd, -1))
		ERRX1("io_write_int");
	else if (!io_write_buf(sess, fd, &nv, sizeof(int64_t)))
		ERRX1("io_write_buf");
	else
		return 1;

	return 0;
}

int
io_write_long(struct sess *sess, int fd, int64_t val)
{
	return io_write_ulong(sess, fd, (uint64_t)val);
}

static int
io_write_uint_tagged(struct sess *sess, int fd, uint32_t val, enum iotag tag)
{
	uint32_t	nv;

	nv = htole32(val);

	if (!io_write_buf_tagged(sess, fd, &nv, sizeof(nv), tag)) {
		ERRX1("io_write_buf");
		return 0;
	}
	return 1;
}

/*
 * Like io_write_buf(), but for an unsigned integer.
 * Returns zero on failure, non-zero on success.
 */
int
io_write_uint(struct sess *sess, int fd, uint32_t val)
{

	return io_write_uint_tagged(sess, fd, val, IT_DATA);
}

int
io_write_int_tagged(struct sess *sess, int fd, int32_t val, enum iotag tag)
{
	return io_write_uint_tagged(sess, fd, (uint32_t)val, tag);
}

/*
 * Like io_write_buf(), but for an integer.
 * Returns zero on failure, non-zero on success.
 */
int
io_write_int(struct sess *sess, int fd, int32_t val)
{
	return io_write_uint(sess, fd, (uint32_t)val);
}

/*
 * Like io_write_buf(), but for an unsigned short.
 * Returns zero on failure, non-zero on success.
 */
int
io_write_ushort(struct sess *sess, int fd, uint32_t val)
{
	uint16_t oval = val;

	return io_write_buf(sess, fd, &oval, sizeof(oval));
}

/*
 * Like io_write_buf(), but for a short.
 * Returns zero on failure, non-zero on success.
 */
int
io_write_short(struct sess *sess, int fd, int32_t val)
{
	return io_write_ushort(sess, fd, (uint32_t)val);
}

/*
 * A simple assertion-protected memory copy from the input "val" or size
 * "valsz" into our buffer "buf", full size "buflen", position "bufpos".
 * Increases our "bufpos" appropriately.
 * This has no return value, but will assert() if the size of the buffer
 * is insufficient for the new data.
 */
void
io_buffer_buf(void *buf, size_t *bufpos, size_t buflen, const void *val,
    size_t valsz)
{

	assert(*bufpos + valsz <= buflen);
	memcpy(buf + *bufpos, val, valsz);
	*bufpos += valsz;
}

/*
 * Like io_buffer_buf(), but also accommodating for multiplexing codes.
 * This should NEVER be passed to io_write_buf(), but instead passed
 * directly to a write operation.
 */
void
io_lowbuffer_buf(struct sess *sess, void *buf,
	size_t *bufpos, size_t buflen, const void *val, size_t valsz)
{
	int32_t	tagbuf;

	if (valsz == 0)
		return;

	if (!sess->mplex_writes) {
		io_buffer_buf(buf, bufpos, buflen, val, valsz);
		return;
	}

	assert(*bufpos + valsz + sizeof(int32_t) <= buflen);
	assert(valsz == (valsz & 0xFFFFFF));
	tagbuf = htole32((7 << 24) + valsz);

	io_buffer_int(buf, bufpos, buflen, tagbuf);
	io_buffer_buf(buf, bufpos, buflen, val, valsz);
}

/*
 * Like io_lowbuffer_buf() but a vstring, a size following by the raw string.
 */
void
io_lowbuffer_vstring(struct sess *sess, void *buf, size_t *bufpos,
    size_t buflen, char *str, size_t sz)
{
	int32_t	tagbuf;

	if (sz == 0)
		return;

	if (!sess->mplex_writes) {
		io_buffer_vstring(buf, bufpos, buflen, str, sz);
		return;
	}

	assert(*bufpos + sz + sizeof(int32_t) <= buflen);
	assert(sz == (sz & 0xFFFFFF));
	tagbuf = htole32((7 << 24) + sz + (sz > 0x7f ? 2 : 1));

	io_buffer_int(buf, bufpos, buflen, tagbuf);
	io_buffer_vstring(buf, bufpos, buflen, str, sz);
}

/*
 * Allocate the space needed for io_lowbuffer_buf() and friends.
 * This should be called for *each* lowbuffer operation, so:
 *   io_lowbuffer_alloc(... sizeof(int32_t));
 *   io_lowbuffer_int(...);
 *   io_lowbuffer_alloc(... sizeof(int32_t));
 *   io_lowbuffer_int(...);
 * And not sizeof(int32_t) * 2 or whatnot.
 * Returns zero on failure, non-zero on success.
 */
int
io_lowbuffer_alloc(struct sess *sess, void **buf,
	size_t *bufsz, size_t *bufmax, size_t sz)
{
	void	*pp;
	size_t	 extra;

	extra = sess->mplex_writes ? sizeof(int32_t) : 0;

	if (*bufsz + sz + extra > *bufmax) {
		pp = realloc(*buf, *bufsz + sz + extra);
		if (pp == NULL) {
			ERR("realloc");
			return 0;
		}
		*buf = pp;
		*bufmax = *bufsz + sz + extra;
	}
	*bufsz += sz + extra;
	return 1;
}

/*
 * Like io_lowbuffer_buf(), but for a single integer.
 */
void
io_lowbuffer_int(struct sess *sess, void *buf,
	size_t *bufpos, size_t buflen, int32_t val)
{
	int32_t	nv = htole32(val);

	io_lowbuffer_buf(sess, buf, bufpos, buflen, &nv, sizeof(int32_t));
}

/*
 * Like io_lowbuffer_buf(), but for a single byte.
 */
void
io_lowbuffer_byte(struct sess *sess, void *buf,
	size_t *bufpos, size_t buflen, int8_t val)
{
	int8_t	nv = val;

	io_lowbuffer_buf(sess, buf, bufpos, buflen, &nv, sizeof(nv));
}

/*
 * Like io_lowbuffer_buf(), but for a single short.
 */
void
io_lowbuffer_short(struct sess *sess, void *buf,
	size_t *bufpos, size_t buflen, int32_t val)
{
	int16_t	nv = htole32((int16_t)val);

	io_lowbuffer_buf(sess, buf, bufpos, buflen, &nv, sizeof(nv));
}

/*
 * Like io_buffer_buf(), but for a single integer.
 */
void
io_buffer_int(void *buf, size_t *bufpos, size_t buflen, int32_t val)
{
	int32_t	nv = htole32(val);

	io_buffer_buf(buf, bufpos, buflen, &nv, sizeof(int32_t));
}

/*
 * Like io_buffer_buf(), but for a single short.
 */
void
io_buffer_short(void *buf, size_t *bufpos, size_t buflen, int32_t val)
{
	int16_t	nv = htole16((int16_t)val);

	io_buffer_buf(buf, bufpos, buflen, &nv, sizeof(nv));
}

/*
 * Like io_buffer_buf(), but for a single byte.
 */
void
io_buffer_byte(void *buf, size_t *bufpos, size_t buflen, int8_t val)
{

	io_buffer_buf(buf, bufpos, buflen, &val, sizeof(val));
}

void
io_buffer_vstring(void *buf, size_t *bufpos, size_t buflen, char *str,
    size_t sz)
{

	assert(sz <= 0x7fff);
	if (sz > 0x7f) {
		io_buffer_byte(buf, bufpos, buflen, (sz >> 8) + 0x80);
	}
	io_buffer_byte(buf, bufpos, buflen, sz & 0xff);
	io_buffer_buf(buf, bufpos, buflen, str, sz);
}

/*
 * Like io_read_buf(), but for a long >=0.
 * Returns zero on failure, non-zero on success.
 */
int
io_read_long(struct sess *sess, int fd, int64_t *val)
{
	uint64_t	uoval;

	if (!io_read_ulong(sess, fd, &uoval)) {
		ERRX1("io_read_long");
		return 0;
	}
	*val = (int64_t)uoval;
	if (*val < 0) {
		ERRX1("io_read_long negative");
		return 0;
	}
	return 1;
}

/*
 * Like io_read_buf(), but for a long.
 * Returns zero on failure, non-zero on success.
 */
int
io_read_ulong(struct sess *sess, int fd, uint64_t *val)
{
	uint64_t	 oval;
	int32_t		 sval;

	/* Start with the short-circuit: read as an int. */

	if (!io_read_int(sess, fd, &sval)) {
		ERRX1("io_read_int");
		return 0;
	}
	if (sval != -1) {
		*val = sval;
		return 1;
	}

	/* If the int is -1, read as 64 bits. */

	if (!io_read_buf(sess, fd, &oval, sizeof(uint64_t))) {
		ERRX1("io_read_buf");
		return 0;
	}

	*val = le64toh(oval);
	return 1;
}

/*
 * One thing we often need to do is read a size_t.
 * These are transmitted as int32_t, so make sure that the value
 * transmitted is not out of range.
 * FIXME: I assume that size_t can handle int32_t's max.
 * Returns zero on failure, non-zero on success.
 */
int
io_read_size(struct sess *sess, int fd, size_t *val)
{
	int32_t	oval;

	if (!io_read_int(sess, fd, &oval)) {
		ERRX1("io_read_int");
		return 0;
	} else if (oval < 0) {
		ERRX("io_read_size: negative value");
		return 0;
	}

	*val = oval;
	return 1;
}

/*
 * Like io_read_buf(), but for an integer.
 * Returns zero on failure, non-zero on success.
 */
int
io_read_uint(struct sess *sess, int fd, uint32_t *val)
{
	uint32_t	oval;

	if (!io_read_buf(sess, fd, &oval, sizeof(uint32_t))) {
		ERRX1("io_read_buf");
		return 0;
	}

	*val = le32toh(oval);
	return 1;
}

int
io_read_int(struct sess *sess, int fd, int32_t *val)
{
	return io_read_uint(sess, fd, (uint32_t *)val);
}

/*
 * Like io_read_buf(), but for a short.
 * Returns zero on failure, non-zero on success.
 */
int
io_read_ushort(struct sess *sess, int fd, uint32_t *val)
{
	uint16_t	oval;

	if (!io_read_buf(sess, fd, &oval, sizeof(uint16_t))) {
		ERRX1("io_read_buf");
		return 0;
	}

	*val = le16toh(oval);

	return 1;
}

int
io_read_short(struct sess *sess, int fd, int32_t *val)
{
	return io_read_ushort(sess, fd, (uint32_t *)val);
}

/*
 * Copies "valsz" from "buf", full size "bufsz" at position" bufpos",
 * into "val".
 * Calls assert() if the source doesn't have enough data.
 * Increases "bufpos" to the new position.
 */
void
io_unbuffer_buf(const void *buf, size_t *bufpos, size_t bufsz, void *val,
    size_t valsz)
{

	assert(*bufpos + valsz <= bufsz);
	memcpy(val, buf + *bufpos, valsz);
	*bufpos += valsz;
}

/*
 * Calls io_unbuffer_buf() and converts.
 */
void
io_unbuffer_int(const void *buf, size_t *bufpos, size_t bufsz, int32_t *val)
{
	int32_t	oval;

	io_unbuffer_buf(buf, bufpos, bufsz, &oval, sizeof(int32_t));
	*val = le32toh(oval);
}

/*
 * Calls io_unbuffer_buf() and converts.
 */
int
io_unbuffer_size(const void *buf, size_t *bufpos, size_t bufsz, size_t *val)
{
	int32_t	oval;

	io_unbuffer_int(buf, bufpos, bufsz, &oval);
	if (oval < 0) {
		ERRX("io_unbuffer_size: negative value");
		return 0;
	}
	*val = oval;
	return 1;
}

/*
 * Like io_read_buf(), but for a single byte >=0.
 * Returns zero on failure, non-zero on success.
 */
int
io_read_byte(struct sess *sess, int fd, uint8_t *val)
{

	if (!io_read_buf(sess, fd, val, sizeof(uint8_t))) {
		ERRX1("io_read_buf");
		return 0;
	}
	return 1;
}

/*
 * Like io_write_buf(), but for a single byte.
 * Returns zero on failure, non-zero on success.
 */
int
io_write_byte(struct sess *sess, int fd, uint8_t val)
{

	if (!io_write_buf(sess, fd, &val, sizeof(uint8_t))) {
		ERRX1("io_write_buf");
		return 0;
	}
	return 1;
}

/*
 */
int
io_read_vstring(struct sess *sess, int fd, char *str, size_t sz)
{
	uint8_t bval;
	size_t len = 0;

	if (!io_read_byte(sess, fd, &bval)) {
		ERRX1("io_read_vstring byte 1");
		return 0;
	}
	if (bval & 0x80) {
		len = (bval - 0x80) << 8;
		if (!io_read_byte(sess, fd, &bval)) {
			ERRX1("io_read_vstring byte 1");
			return 0;
		}
	}
	len |= bval;

	if (len >= sz) {
		ERRX1("io_read_vstring: incoming string too large (%zu > %zu)",
		    len, sz);
		return 0;
	}

	if (!io_read_buf(sess, fd, str, len)) {
		ERRX1("io_read_vstring buf");
		return 0;
	}

	return 1;
}

/*
 * Write a vstring, a size following by the raw string.
 * Returns zero on failure, non-zero on success.
 */
int
io_write_vstring(struct sess *sess, int fd, char *str, size_t sz)
{

	if (sz > 0x7fff) {
		ERRX1("io_write_vstring too long: (%zu > %d)", sz, 0x7fff);
		return 0;
	} else if (sz > 0x7f && !io_write_byte(sess, fd, (sz >> 8) + 0x80)) {
		ERRX1("io_write_vstring byte 1");
		return 0;
	} else if (!io_write_byte(sess, fd, sz & 0xff)) {
		ERRX1("io_write_vstring byte 2");
		return 0;
	} else if (!io_write_buf(sess, fd, str, sz)) {
		ERRX1("io_write_vstring buf");
		return 0;
	}
	return 1;
}
