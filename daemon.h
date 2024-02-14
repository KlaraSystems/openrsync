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
#ifndef DAEMON_H
#define	DAEMON_H

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <netdb.h>
#include <stdbool.h>

#include "extern.h"

/*
 * Memory legend:
 *
 * (c) Allocated within config, or an option pointer -- do not free
 * (f) Allocated independently, child should free
 */
struct daemon_role {
	struct role		 role;
	char			 client_host[NI_MAXHOST]; /* hostname */
	char			 client_addr[INET6_ADDRSTRLEN]; /* addr */
	struct sockaddr		*client_sa;
	const char		*cfg_file;	/* (c) daemon config file */
	char			*motd_file;	/* (f) client motd */
	struct daemon_cfg	*dcfg;		/* (f) daemon config */
	const char		*pid_file;	/* (c) daemon pidfile path */
	FILE			*pidfp;		/* (f) daemon pidfile */
	int			 lockfd;
	id_t			 uid;		/* setuid if root */
	id_t			 gid;		/* setgid if root */
	int			 client;
	bool			 client_control;
	bool			 do_setid;	/* do setuid/setgid */
};

int	daemon_chuser_setup(struct sess *, const char *);
int	daemon_chuser(struct sess *, const char *);
void	daemon_client_error(struct sess *, const char *, ...);
int	daemon_connection_allowed(struct sess *, const char *);
int	daemon_connection_limited(struct sess *, const char *);
int	daemon_fill_hostinfo(struct sess *, const char *,
	    const struct sockaddr *, size_t);
int	daemon_limit_verbosity(struct sess *, const char *);
void	daemon_normalize_paths(const char *, int, char *[]);
int	daemon_open_logfile(const char *, bool);
int	daemon_operation_allowed(struct sess *, const struct opts *,
	    const char *, int);
int	daemon_set_numeric_ids(struct sess *, struct opts *, const char *, int);
int	daemon_setup_logfile(struct sess *, const char *);

#endif /* !DAEMON_H */
