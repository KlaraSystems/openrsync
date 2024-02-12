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
	const char		*cfg_file;	/* (c) daemon config file */
	char			*motd_file;	/* (f) client motd */
	struct daemon_cfg	*dcfg;		/* (f) daemon config */
	const char		*pid_file;	/* (c) daemon pidfile path */
	FILE			*pidfp;		/* (f) daemon pidfile */
	int			 lockfd;
	int			 client;
	bool			 client_control;
};

void	daemon_client_error(struct sess *, const char *, ...);
int	daemon_connection_limited(struct sess *, const char *);
int	daemon_limit_verbosity(struct sess *, const char *);
void	daemon_normalize_paths(const char *, int, char *[]);
int	daemon_operation_allowed(struct sess *, const struct opts *,
	    const char *);
int	daemon_set_numeric_ids(struct sess *, struct opts *, const char *, int);

#endif /* !DAEMON_H */
