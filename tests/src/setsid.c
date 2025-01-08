/*
 * Copyright (c) 2024, Klara, Inc.
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

#include <assert.h>
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int
main(int argc, char *argv[])
{
	pid_t pid;

	if (argc <= 1) {
		fprintf(stderr, "usage: %s command [...]\n", getprogname());
		return (1);
	}

	argc--;
	argv++;

	/*
	 * If we're already the session leader, we'll fork off to ensure that we
	 * have a fresh session.
	 */
	pid = getpid();
	if (getsid(pid) == pid) {
		pid = fork();
		if (pid == -1)
			err(1, "fork");
		if (pid != 0)
			return (0);	/* All done here */
	}

	if (setsid() == -1)
		err(1, "setsid");

	execvp(argv[0], argv);
	err(1, "execv");
}
