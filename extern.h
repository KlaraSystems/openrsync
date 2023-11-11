/*	$Id$ */
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
#ifndef EXTERN_H
#define EXTERN_H

#include <fts.h>

#include "md4.h"

#if !HAVE_PLEDGE
# define pledge(x, y) (1)
#endif
#if !HAVE_UNVEIL
# define unveil(x, y) (1)
#endif

/*
 * This is the rsync protocol version that we support.
 */
#define	RSYNC_PROTOCOL	(27)

/*
 * Maximum amount of file data sent over the wire at once.
 */
#define MAX_CHUNK	(32 * 1024)

/*
 * This is the minimum size for a block of data not including those in
 * the remainder block.
 */
#define	BLOCK_SIZE_MIN  (700)

/*
 * Maximum number of base directories that can be used.
 */
#define MAX_BASEDIR	20

#define BASE_MODE_COMPARE	1
#define BASE_MODE_COPY		2
#define BASE_MODE_LINK		3

/*
 * The sender and receiver use a two-phase synchronisation process.
 * The first uses two-byte hashes; the second, 16-byte.
 * (The second must hold a full MD4 digest.)
 */
#define	CSUM_LENGTH_PHASE1 (2)
#define	CSUM_LENGTH_PHASE2 (16)

/*
 * Rsync error codes.
 */
#define ERR_SYNTAX	1
#define ERR_PROTOCOL	2
#define ERR_SOCK_IO	10
#define ERR_FILE_IO	11
#define ERR_WIREPROTO	12
#define ERR_IPC		14	/* catchall for any kind of syscall error */
#define ERR_TERMIMATED	16
#define ERR_SIGUSR1	19
#define ERR_SIGNAL	20
#define ERR_WAITPID	21
#define ERR_NOMEM	22

/*
 * Use this for --timeout.
 * All poll events will use it and catch time-outs.
 */
extern int poll_timeout;

/*
 * Operating mode for a client or a server.
 * Sender means we synchronise local files with those from remote.
 * Receiver is the opposite.
 * This is relative to which host we're running on.
 */
enum	fmode {
	FARGS_SENDER,
	FARGS_RECEIVER
};

/*
 * Delete modes:
 * - unspecified: transforms into one of the below after option processing,
 *    i.e., --del / --delete.
 * - before: delete files up-front
 * - during: delete files during transfer
 * - delay:  gather deletions and delete after after
 * - after: delete after transfer
 * - excluded: delete excluded files, too
 */
enum	delmode {
	DMODE_NONE,
	DMODE_UNSPECIFIED,
	DMODE_BEFORE,
	DMODE_DURING,
	DMODE_DELAY,
	DMODE_AFTER,
};

/*
 * File arguments given on the command line.
 * See struct opts.
 */
struct	fargs {
	char	  *host; /* hostname or NULL if local */
	char	 **sources; /* transfer source */
	size_t	   sourcesz; /* number of sources */
	char	  *sink; /* transfer endpoint */
	enum fmode mode; /* mode of operation */
	int	   remote; /* uses rsync:// or :: for remote */
	char	  *module; /* if rsync://, the module */
};

/*
 * The subset of stat(2) information that we need.
 * (There are some parts we don't use yet.)
 */
struct	flstat {
	mode_t		 mode;	 /* mode */
	uid_t		 uid;	 /* user */
	gid_t		 gid;	 /* group */
	dev_t		 rdev;	 /* device type */
	off_t		 size;	 /* size */
	time_t		 mtime;	 /* modification */
	unsigned int	 flags;
	int64_t		 device; /* device number, for hardlink detection */
	int64_t		 inode;  /* inode number, for hardlink detection */
#define	FLSTAT_TOP_DIR	 0x01	 /* a top-level directory */

};

/*
 * A list of files with their statistics.
 * Note that the md[] field is only used by the --checksum option, and
 * hence could be eliminated (when not needed) by making struct flist
 * a variably-sized structure and handling its variability in both the
 * sender and receiver.
 */
struct	flist {
	char		*path; /* path relative to root */
	const char	*wpath; /* "working" path for receiver */
	struct flstat	 st; /* file information */
	char		*link; /* symlink target or NULL */
	unsigned char    md[MD4_DIGEST_LENGTH]; /* MD4 hash for --checksum */
	int		 redo; /* flagged for redo */
};

/*
 * Options passed into the command line.
 * See struct fargs.
 */
struct	opts {
	int		 sender;		/* --sender */
	int		 server;		/* --server */
	int		 append;		/* --append */
	int		 checksum;		/* -c */
	int		 recursive;		/* -r */
	int		 dry_run;		/* -n */
	int		 inplace;		/* --inplace */
	int		 partial;		/* --partial */
	char		*partial_dir;		/* --partial-dir */
	int		 preserve_times;	/* -t */
	int		 preserve_perms;	/* -p */
	int		 copy_links;		/* -L */
	int		 copy_dirlinks;		/* -k */
	int		 preserve_links;	/* -l */
	int		 preserve_gids;		/* -g */
	int		 preserve_uids;		/* -u */
	enum delmode	 del;			/* --delete */
	int		 del_excl;		/* --delete-excluded */
	int		 devices;		/* --devices */
	int		 specials;		/* --specials */
	int		 no_motd;		/* --no-motd */
	int		 numeric_ids;		/* --numeric-ids */
	int		 one_file_system;	/* -x */
	int		 ignore_times;		/* -I --ignore-times */
	int              progress;              /* --progress */
	int		 alt_base_mode;
	int		 sparse;		/* -S --sparse */
	int		 update;		/* -u --update */
	int		 backup;		/* --backup */
	int		 ign_exist;		/* --ignore-existing */
	int		 ign_non_exist;		/* --ignore-nonexisting */
	int		 relative;		/* --relative */
	int		 dirs;			/* -d --dirs */
	int		 dlupdates;             /* --delay-updates */
	int		 hard_links;		/* -H --hard-links */
	off_t		 max_size;		/* --max-size */
	off_t		 min_size;		/* --min-size */
	char		*rsync_path;		/* --rsync-path */
	char		*ssh_prog;		/* --rsh or -e */
	char		*port;			/* --port */
	char		*address;		/* --address */
	char		*basedir[MAX_BASEDIR];
	char            *filesfrom;             /* --files-from */
	off_t		 bwlimit;		/* --bwlimit */
#if 0
	char		*syncfile;		/* --sync-file */
#endif
};

enum rule_type {
	RULE_NONE,
	RULE_EXCLUDE,
	RULE_INCLUDE,
	RULE_CLEAR,
#ifdef NOTYET
	RULE_MERGE,
	RULE_DIR_MERGE,
	RULE_SHOW,
	RULE_HIDE,
	RULE_PROTECT,
	RULE_RISK,
#endif
};

/*
 * An individual block description for a file.
 * See struct blkset.
 */
struct	blk {
	off_t		 offs; /* offset in file */
	size_t		 idx; /* block index */
	size_t		 len; /* bytes in block */
	uint32_t	 chksum_short; /* fast checksum */
	unsigned char	 chksum_long[CSUM_LENGTH_PHASE2]; /* slow checksum */
};

enum	blkstatst {
	BLKSTAT_NONE = 0,
	BLKSTAT_NEXT,
	BLKSTAT_DATA,
	BLKSTAT_TOK,
	BLKSTAT_HASH,
	BLKSTAT_DONE,
	BLKSTAT_PHASE,
};

/*
 * Information for the sender updating receiver blocks reentrantly.
 */
struct	blkstat {
	off_t		 offs; /* position in sender file */
	off_t		 total; /* total amount processed */
	off_t		 dirty; /* total amount sent */
	size_t		 hint; /* optimisation: next probable match */
	void		*map; /* mapped file or MAP_FAILED otherwise */
	size_t		 mapsz; /* size of file or zero */
	int		 fd; /* descriptor girding the map */
	enum blkstatst	 curst; /* FSM for sending file blocks */
	off_t		 curpos; /* sending: position in file to send */
	off_t		 curlen; /* sending: length of send */
	int32_t		 curtok; /* sending: next matching token or zero */
	struct blktab	*blktab; /* hashtable of blocks */
	uint32_t	 s1; /* partial sum for computing fast hash */
	uint32_t	 s2; /* partial sum for computing fast hash */
};

/*
 * When transferring file contents, we break the file down into blocks
 * and work with those.
 */
struct	blkset {
	off_t		 size; /* file size */
	size_t		 rem; /* terminal block length if non-zero */
	size_t		 len; /* block length */
	size_t		 csum; /* checksum length */
	struct blk	*blks; /* all blocks */
	size_t		 blksz; /* number of blks */
};

/*
 * Context for the role (sender/receiver).  The role may embed this into their
 * own context struct.
 */
struct	role {
	int		 append;		/* Append mode active */

	/*
	 * We basically track two different forms of phase: the metadata phase,
	 * and the transfer phase.  The metadata phase may be advanced from the
	 * transfer phase, as we'll immediately move on to checking for or
	 * processing redo entries when the first phase's file requests are
	 * done.
	 *
	 * Each role has its own way of tracking these, so we just have them
	 * drop a pointer here to avoid having to keep things in sync.  `append`
	 * above will be reset as the transfer phase progresses, so parts
	 * dealing with block metadata should check `*phase` *and* `append` to
	 * determine if they need to send/receive block checksums, and anything
	 * part of the data transfer process should just be checking `append`.
	 */
	const int	*phase;			/* Metadata phase */
};

/*
 * Values required during a communication session.
 */
struct	sess {
	const struct opts *opts; /* system options */
	int32_t		   seed; /* checksum seed */
	int32_t		   lver; /* local version */
	int32_t		   rver; /* remote version */
	uint64_t	   total_read; /* non-logging wire/reads */
	uint64_t	   total_size; /* total file size */
	uint64_t	   total_write; /* non-logging wire/writes */
	int		   mplex_reads; /* multiplexing reads? */
	size_t		   mplex_read_remain; /* remaining bytes */
	int		   mplex_writes; /* multiplexing writes? */
	double             last_time; /* last time printed --progress */  
	char             **filesfrom; /* Contents of files-from */
	size_t             filesfrom_n; /* Number of lines for filesfrom */
	struct dlrename    *dlrename; /* Deferred renames for --delay-update */
	struct role	  *role; /* Role context */
	double             start_time; /* Time of first transfer */
};

/*
 * Combination of name and numeric id for groups and users.
 */
struct	ident {
	int32_t	 id; /* the gid_t or uid_t */
	int32_t	 mapped; /* if receiving, the mapped gid */
	char	*name; /* resolved name */
};

typedef struct arglist arglist;
struct arglist {
	char	**list;
	u_int	num;
	u_int	nalloc;
};
void	addargs(arglist *, const char *, ...)
	    __attribute__((format(printf, 2, 3)));
void	freeargs(arglist *);

struct cleanup_ctx;

struct	download;
struct	upload;

struct hardlinks;
const struct flist *find_hl(const struct flist *this,
			    const struct hardlinks *hl);

extern int verbose;

#define MINIMUM(a, b) (((a) < (b)) ? (a) : (b))

#define LOG0(_fmt, ...) \
	rsync_log( -1, (_fmt), ##__VA_ARGS__)
#define LOG1(_fmt, ...) \
	rsync_log( 0, (_fmt), ##__VA_ARGS__)
#define LOG2(_fmt, ...) \
	rsync_log( 1, (_fmt), ##__VA_ARGS__)
#define LOG3(_fmt, ...) \
	rsync_log( 2, (_fmt), ##__VA_ARGS__)
#define LOG4(_fmt, ...) \
	rsync_log( 3, (_fmt), ##__VA_ARGS__)
#define ERRX1(_fmt, ...) \
	rsync_errx1( (_fmt), ##__VA_ARGS__)
#define WARNX(_fmt, ...) \
	rsync_warnx( (_fmt), ##__VA_ARGS__)
#define WARNX1(_fmt, ...) \
	rsync_warnx1( (_fmt), ##__VA_ARGS__)
#define WARN(_fmt, ...) \
	rsync_warn(0,  (_fmt), ##__VA_ARGS__)
#define WARN1(_fmt, ...) \
	rsync_warn(1,  (_fmt), ##__VA_ARGS__)
#define WARN2(_fmt, ...) \
	rsync_warn(2,  (_fmt), ##__VA_ARGS__)

#if defined(__sun) && defined(ERR)
# undef ERR
#endif
#define ERR(_fmt, ...) \
	rsync_err( (_fmt), ##__VA_ARGS__)
#define ERRX(_fmt, ...) \
	rsync_errx( (_fmt), ##__VA_ARGS__)

void	rsync_log(int, const char *, ...)
			__attribute__((format(printf, 2, 3)));
void	rsync_warnx1(const char *, ...)
			__attribute__((format(printf, 1, 2)));
void	rsync_warn(int, const char *, ...)
			__attribute__((format(printf, 2, 3)));
void	rsync_warnx(const char *, ...)
			__attribute__((format(printf, 1, 2)));
void	rsync_err(const char *, ...)
			__attribute__((format(printf, 1, 2)));
void	rsync_errx(const char *, ...)
			__attribute__((format(printf, 1, 2)));
void	rsync_errx1(const char *, ...)
			__attribute__((format(printf, 1, 2)));

int	flist_fts_check(struct sess *, FTSENT *, enum fmode);
int	flist_del(struct sess *, int, const struct flist *, size_t);
int	flist_gen(struct sess *, size_t, char **, struct flist **, size_t *);
int	flist_gen_local(struct sess *, const char *, struct flist **, size_t *);
void	flist_free(struct flist *, size_t);
int	flist_recv(struct sess *, int, struct flist **, size_t *);
int	flist_send(struct sess *, int, int, const struct flist *, size_t);
int	flist_gen_dels(struct sess *, const char *, struct flist **, size_t *,
	    const struct flist *, size_t);
int	flist_add_del(struct sess *, const char *, size_t, struct flist **,
	    size_t *, size_t *, const struct stat *st);

const char	 *alt_base_mode(int);
char		**fargs_cmdline(struct sess *, const struct fargs *, size_t *);

void	cleanup_hold(struct cleanup_ctx *);
void	cleanup_release(struct cleanup_ctx *);
void	cleanup_init(struct cleanup_ctx *);
void	cleanup_run(int code);
void	cleanup_set_args(struct cleanup_ctx *, struct fargs *);
void	cleanup_set_child(struct cleanup_ctx *, pid_t);
void	cleanup_set_session(struct cleanup_ctx *, struct sess *);
void	cleanup_set_download(struct cleanup_ctx *, struct download *);

int	io_read_buf(struct sess *, int, void *, size_t);
int	io_read_byte(struct sess *, int, uint8_t *);
int	io_read_check(int);
int	io_read_flush(struct sess *, int);
int	io_read_int(struct sess *, int, int32_t *);
int	io_read_uint(struct sess *, int, uint32_t *);
int	io_read_long(struct sess *, int, int64_t *);
int	io_read_size(struct sess *, int, size_t *);
int	io_read_ulong(struct sess *, int, uint64_t *);
int	io_write_buf(struct sess *, int, const void *, size_t);
int	io_write_byte(struct sess *, int, uint8_t);
int	io_write_int(struct sess *, int, int32_t);
int	io_write_uint(struct sess *, int, uint32_t);
int	io_write_line(struct sess *, int, const char *);
int	io_write_long(struct sess *, int, int64_t);
int	io_write_ulong(struct sess *, int, uint64_t);

int	io_lowbuffer_alloc(struct sess *, void **, size_t *, size_t *, size_t);
void	io_lowbuffer_int(struct sess *, void *, size_t *, size_t, int32_t);
void	io_lowbuffer_buf(struct sess *, void *, size_t *, size_t, const void *,
	    size_t);

void	io_buffer_int(void *, size_t *, size_t, int32_t);
void	io_buffer_buf(void *, size_t *, size_t, const void *, size_t);

void	io_unbuffer_int(const void *, size_t *, size_t, int32_t *);
int	io_unbuffer_size(const void *, size_t *, size_t, size_t *);
void	io_unbuffer_buf(const void *, size_t *, size_t, void *, size_t);

int	rsync_receiver(struct sess *, struct cleanup_ctx *, int, int,
	    const char *);
int	rsync_sender(struct sess *, int, int, size_t, char **);
int	rsync_client(struct cleanup_ctx *, const struct opts *, int,
	    const struct fargs *);
int	rsync_connect(const struct opts *, int *, const struct fargs *);
int	rsync_socket(struct cleanup_ctx *, const struct opts *, int,
	    const struct fargs *);
int	rsync_server(struct cleanup_ctx *, const struct opts *, size_t,
	    char *[]);
int	rsync_downloader(struct download *, struct sess *, int *, int,
	    const struct hardlinks *);
int	rsync_set_metadata(struct sess *, int, int, const struct flist *,
	    const char *);
int	rsync_set_metadata_at(struct sess *, int, int, const struct flist *,
	    const char *);
int	rsync_uploader(struct upload *, int *, struct sess *, int *,
		       const struct hardlinks *);
int	rsync_uploader_tail(struct upload *, struct sess *);

struct download	*download_alloc(struct sess *, int, struct flist *, size_t,
		    int);
size_t		 download_needs_redo(struct download *);
void		 download_interrupted(struct sess *, struct download *);
void		 download_free(struct sess *, struct download *);
struct upload	*upload_alloc(const char *, int, int, size_t,
		    const struct flist *, size_t, mode_t);
void		upload_next_phase(struct upload *);
void		upload_free(struct upload *);
int		upload_del(struct upload *, struct sess *);

struct blktab	*blkhash_alloc(void);
int		 blkhash_set(struct blktab *, const struct blkset *);
void		 blkhash_free(struct blktab *);

struct blkset	*blk_recv(struct sess *, int, const char *);
void		 blk_recv_ack(char [20], const struct blkset *, int32_t);
void		 blk_match(struct sess *, const struct blkset *,
		    const char *, struct blkstat *);
int		 blk_send(struct sess *, int, size_t, const struct blkset *,
		    const char *);
int		 blk_send_ack(struct sess *, int, struct blkset *);

uint32_t	 hash_fast(const void *, size_t);
void		 hash_slow(const void *, size_t, unsigned char *,
		    const struct sess *);
void		 hash_file(const void *, size_t, unsigned char *,
		    const struct sess *);
int		 hash_file_by_path(int, const char *, size_t, unsigned char *);

void		 copy_file(int, const char *, const struct flist *);

int		 mkpath(char *);
int		 mksock(const char *, char *);

int		 mkstempat(int, char *);
char		*mkstemplinkat(char*, int, char *);
char		*mkstempfifoat(int, char *);
char		*mkstempnodat(int, char *, mode_t, dev_t);
char		*mkstempsock(const char *, char *);
int		 mktemplate(char **, const char *, int);

int		 parse_rule(char *line, enum rule_type);
void		 parse_file(const char *, enum rule_type);
void		 send_rules(struct sess *, int);
void		 recv_rules(struct sess *, int);
int		 rules_match(const char *, int);

int		 rmatch(const char *, const char *, int);

char		*symlink_read(const char *);
char		*symlinkat_read(int, const char *);

int		 sess_stats_send(struct sess *, int);
int		 sess_stats_recv(struct sess *, int);

int		 idents_add(int, struct ident **, size_t *, int32_t);
void		 idents_assign_gid(struct sess *, struct flist *, size_t,
		    const struct ident *, size_t);
void		 idents_assign_uid(struct sess *, struct flist *, size_t,
		    const struct ident *, size_t);
void		 idents_free(struct ident *, size_t);
int		 idents_recv(struct sess *, int, struct ident **, size_t *);
void		 idents_remap(struct sess *, int, struct ident *, size_t);
int		 idents_send(struct sess *, int, const struct ident *, size_t);

int		 iszerobuf(const void *b, size_t len);

int              read_filesfrom(struct sess *sess, const char *basedir);
void		 cleanup_filesfrom(struct sess *sess);
void		 delayed_renames(struct sess *sess);

static inline int
sess_is_inplace(struct sess *sess)
{

	return sess->opts->inplace || sess->opts->append;
}

#endif /*!EXTERN_H*/
