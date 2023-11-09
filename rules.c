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

#include <sys/param.h>

#include <assert.h>
#if HAVE_ERR
# include <err.h>
#endif
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "extern.h"

struct rule {
	char			*pattern;
	enum rule_type		 type;
	unsigned int		 omodifiers;
	unsigned int		 modifiers;
	short			 numseg;
	unsigned char		 anchored;
	unsigned char		 fileonly;
	unsigned char		 nowild;
	unsigned char		 onlydir;
	unsigned char		 leadingdir;
};

static char		 rule_base[MAXPATHLEN];
static char		*rule_base_cwdend;

static struct rule	*rules;
static size_t		 numrules;	/* number of rules */
static size_t		 rulesz;	/* available size */

static void parse_file_impl(const char *, enum rule_type, unsigned int);

/* up to protocol 29 filter rules only support - + ! and no modifiers */

const struct command {
	enum rule_type		type;
	char			sopt;
	const char		*lopt;
} commands[] = {
	{ RULE_EXCLUDE,		'-',	"exclude" },
	{ RULE_INCLUDE,		'+',	"include" },
	{ RULE_CLEAR,		'!',	"clear" },
	{ RULE_MERGE,		'.',	"merge" },
	{ RULE_DIR_MERGE,	':',	"dir-merge" },
	{ RULE_SHOW,		'S',	"show" },
	{ RULE_HIDE,		'H',	"hide" },
	{ RULE_PROTECT,		'P',	"protect" },
	{ RULE_RISK,		'R',	"risk" },
	{ 0 }
};

#define MOD_ABSOLUTE			0x0001
#define MOD_NEGATE			0x0002
#define MOD_CVSEXCLUDE			0x0004
#define MOD_SENDING			0x0008
#define MOD_RECEIVING			0x0010
#define MOD_PERISHABLE			0x0020
#ifdef NOTYET
#define MOD_XATTR			0x0040
#endif
#define MOD_MERGE_EXCLUDE		0x0080
#define MOD_MERGE_INCLUDE		0x0100
#define MOD_MERGE_CVSCOMPAT		0x0200
#define MOD_MERGE_EXCLUDE_FILE		0x0400
#define MOD_MERGE_NO_INHERIT		0x0800
#define MOD_MERGE_WORDSPLIT		0x1000

#define MOD_SENDRECV_MASK		(MOD_SENDING | MOD_RECEIVING)

#define MOD_MERGE_MASK			0x1f80
#define MOD_VALID_MASK			0x1fff

/* maybe support absolute and negate */
const struct modifier {
	unsigned int		modifier;
	char			sopt;
} modifiers[] = {
	{ MOD_ABSOLUTE,			'/' },
	{ MOD_NEGATE,			'!' },
	{ MOD_CVSEXCLUDE,		'C' },
	{ MOD_SENDING,			's' },
	{ MOD_RECEIVING,		'r' },
	{ MOD_PERISHABLE,		'p' },
#ifdef NOTYET
	{ MOD_XATTR,			'x' },
#endif
	/* for '.' and ':' types */
	{ MOD_MERGE_EXCLUDE,		'-' },
	{ MOD_MERGE_INCLUDE,		'+' },
	{ MOD_MERGE_CVSCOMPAT,		'C' },
	{ MOD_MERGE_EXCLUDE_FILE,	'e' },
	{ MOD_MERGE_NO_INHERIT,		'n' },
	{ MOD_MERGE_WORDSPLIT,		'w' },
	{ 0 }
};

static struct rule *
get_next_rule(void)
{
	struct rule *new;
	size_t newsz;

	if (++numrules > rulesz) {
		if (rulesz == 0)
			newsz = 16;
		else
			newsz = rulesz * 2;

		new = recallocarray(rules, rulesz, newsz, sizeof(*rules));
		if (new == NULL)
			err(ERR_NOMEM, NULL);

		rules = new;
		rulesz = newsz;
	}

	return rules + numrules - 1;
}

static unsigned int
parse_modifiers(const char *command, size_t *len)
{
	unsigned int modmask, modparsed;
	size_t idx;
	char mod;

	modmask = 0;
	for (idx = 0; idx < *len; idx++) {
		mod = command[idx];

		modparsed = 0;
		for (size_t i = 0; modifiers[i].modifier != 0; i++) {
			if (modifiers[i].sopt == mod) {
				modparsed = modifiers[i].modifier;
				break;
			}
		}

		if (modparsed == 0)
			break;

		modmask |= modparsed;
	}

	*len -= idx;

	return modmask;
}

static enum rule_type
parse_command(const char *command, size_t len, unsigned int *omodifiers)
{
	const struct command *cmd;
	const char *mod;
	size_t	cmdlen, i;
	unsigned int modifiers;

	/* Command has been omitted, short-circuit. */
	if (len == 0)
		return RULE_NONE;

	cmd = NULL;
	cmdlen = len;

	mod = memchr(command, ',', cmdlen);
	if (mod != NULL) {
		cmdlen = mod - command;
		mod++;
	}

	/*
	 * Do a pass up front to figure out the command.  We don't need to use
	 * cmdlen to check for short names because they're designed to not
	 * conflict with the first character of any long name.
	 */
	for (i = 0; commands[i].type != RULE_NONE; i++) {
		if (strncmp(commands[i].lopt, command, cmdlen) == 0) {
			cmd = &commands[i];
			break;
		} else if (commands[i].sopt == *command) {
			cmd = &commands[i];

			/*
			 * The comma separator for modifiers is optional if a
			 * short name is used, so point mod in the right
			 * direction if there was no comma in the rule string.
			 */
			if (mod == NULL && command[1] != '\0')
				mod = &command[1];
			break;
		}
	}

	if (cmd == NULL)
		return RULE_NONE;

	modifiers = 0;
	if (mod != NULL) {
		size_t modlen;

		modlen = len - (mod - command);
		modifiers = parse_modifiers(mod, &modlen);

		/* Some modifier could not be processed. */
		if (modlen != 0)
			return RULE_NONE;
	}

	if (omodifiers != NULL)
		*omodifiers = modifiers;
	return cmd->type;
}

static void
parse_pattern(struct rule *r, const char *pattern)
{
	size_t plen;
	char *p;
	short nseg = 1;

	/*
	 * check for / at start and end of pattern both are special and
	 * can bypass full path matching.
	 */
	if (*pattern == '/') {
		pattern++;
		r->anchored = 1;
	}
	plen = strlen(pattern);
	/*
	 * check for patterns ending in '/' and '/'+'***' and handle them
	 * specially. Because of this and the check above pattern will never
	 * start or end with a '/'.
	 */
	if (plen > 1 && pattern[plen - 1] == '/') {
		r->onlydir = 1;
		plen--;
	}
	if (!r->onlydir && plen > 4 &&
	    strcmp(pattern + plen - 4, "/***") == 0) {
		r->leadingdir = 1;
		plen -= 4;
	}

	r->pattern = strndup(pattern, plen);
	if (r->pattern == NULL)
		err(ERR_NOMEM, NULL);

	/* count how many segments the pattern has. */
	for (p = r->pattern; *p != '\0'; p++)
		if (*p == '/')
			nseg++;
	r->numseg = nseg;

	/* check if this pattern only matches against the basename */
	if (nseg == 1 && !r->anchored)
		r->fileonly = 1;

	if (strpbrk(r->pattern, "*?[") == NULL) {
		/* no wildchar matching */
		r->nowild = 1;
	} else {
		/* requires wildchar matching */
		if (strstr(r->pattern, "**") != NULL)
			r->numseg = -1;
	}
}

static bool
modifiers_valid(enum rule_type rule, unsigned int *modifiers)
{
	unsigned int valid_mask;

	switch (rule) {
	case RULE_DIR_MERGE:
	case RULE_MERGE:
		if ((*modifiers & (MOD_MERGE_EXCLUDE | MOD_MERGE_INCLUDE)) ==
		    (MOD_MERGE_EXCLUDE | MOD_MERGE_INCLUDE))
			return false;
		valid_mask = MOD_VALID_MASK;
		break;
	case RULE_EXCLUDE:
	case RULE_INCLUDE:
		valid_mask = MOD_VALID_MASK & ~MOD_MERGE_MASK;
		break;
	default:
		valid_mask = 0;
		break;
	}

	*modifiers &= valid_mask;
	return (true);
}

static int
pattern_valid(enum rule_type rule, unsigned int modifiers, const char *pattern)
{
	bool is_empty, need_empty = false;

	switch (rule) {
	case RULE_EXCLUDE:
		if ((modifiers & MOD_CVSEXCLUDE) == 0)
			break;
		/* FALLTHROUGH */
	case RULE_CLEAR:
		need_empty = true;
		break;
	default:
		break;
	}

	is_empty = *pattern == '\0';
	return is_empty == need_empty;
}

static enum rule_type
rule_modified(enum rule_type rule, unsigned int *modifiers)
{
	unsigned int mod = *modifiers;

	if (mod == 0)
		return rule;

	switch (rule) {
	case RULE_EXCLUDE:
		if ((mod & MOD_SENDRECV_MASK) == MOD_SENDRECV_MASK) {
			/* Just unset the modifiers. */
		} else if ((mod & MOD_SENDING) != 0) {
			rule = RULE_HIDE;
		} else if ((mod & MOD_RECEIVING) != 0) {
			rule = RULE_PROTECT;
		}

		mod &= ~MOD_SENDRECV_MASK;
		break;
	case RULE_INCLUDE:
		if ((mod & MOD_SENDRECV_MASK) == MOD_SENDRECV_MASK) {
			/* Just unset the modifiers. */
		} else if ((mod & MOD_SENDING) != 0) {
			rule = RULE_SHOW;
		} else if ((mod & MOD_RECEIVING) != 0) {
			rule = RULE_RISK;
		}

		mod &= ~MOD_SENDRECV_MASK;
		break;
	case RULE_MERGE:
	case RULE_DIR_MERGE:
		/*
		 * We can't zap any modifiers for merge rules; they need to be
		 * either inherited or just enacted for the merge directive on
		 * the other side.
		 */
		return rule;
	default:
		/* Zap modifiers for everything else; inherited, not needed. */
		mod = 0;
		break;
	}

	*modifiers = mod;
	return rule;
}

/*
 * Parses the line for a rule with consideration for the inherited modifiers.
 */
static int
parse_rule_impl(const char *line, enum rule_type def, unsigned int imodifiers)
{
	enum rule_type type = RULE_NONE;
	struct rule *r;
	const char *pattern;
	size_t len;
	unsigned int modifiers;

	modifiers = 0;
	switch (*line) {
	case '#':
	case ';':
		/* comment */
		return 0;
	case '\0':
		/* ingore empty lines */
		return 0;
	default:
		modifiers = 0;
		if (def == RULE_NONE) {
			len = strcspn(line, " _");
			type = parse_command(line, len, &modifiers);
		}
		if (type == RULE_NONE) {
			if (def == RULE_NONE)
				return -1;
			type = def;
			pattern = line;
		} else {
			/*
			 * Some available rules have no arguments, so we're
			 * pointing at the NUL byte and we shouldn't walk past
			 * that.
			 */
			pattern = line + len;
			if (*pattern != '\0')
				pattern++;
		}

		if (!modifiers_valid(type, &modifiers))
			return -1;

		if (!pattern_valid(type, modifiers, pattern))
			return -1;

		/*
		 * We inherit the modifiers here to bypass the validity check,
		 * but we want them to be considered in rule_modified() in case
		 * we need to promote some rules.  There's a good chance it will
		 * simply zap most of the modifiers and send us on our way.
		 */
		modifiers |= imodifiers;
		if (modifiers != 0)
			type = rule_modified(type, &modifiers);
		break;
	}

	r = get_next_rule();
	r->type = type;
	r->omodifiers = r->modifiers = modifiers;
	if (type == RULE_MERGE || type == RULE_DIR_MERGE)
		r->modifiers &= MOD_MERGE_MASK;
	parse_pattern(r, pattern);
	if (type == RULE_MERGE || type == RULE_DIR_MERGE) {
		if ((modifiers & MOD_MERGE_EXCLUDE_FILE) != 0) {
			if (parse_rule_impl(r->pattern, RULE_EXCLUDE, 0) == -1)
				return -1;
		}
	}

	if (type == RULE_MERGE) {
		/*  - and + are mutually exclusive. */
		if ((modifiers & (MOD_MERGE_EXCLUDE | MOD_MERGE_INCLUDE)) ==
		    (MOD_MERGE_EXCLUDE | MOD_MERGE_INCLUDE))
			return -1;

		if ((modifiers & MOD_MERGE_EXCLUDE) != 0)
			def = RULE_EXCLUDE;
		else if ((modifiers & MOD_MERGE_INCLUDE) != 0)
			def = RULE_INCLUDE;
		else
			def = RULE_NONE;

		parse_file_impl(pattern, def, modifiers);
	}

	return 0;
}

int
parse_rule(const char *line, enum rule_type def)
{
	return parse_rule_impl(line, def, 0);
}

static void
parse_file_impl(const char *file, enum rule_type def, unsigned int imodifiers)
{
	FILE *fp;
	char *line = NULL;
	size_t linesize = 0, linenum = 0;
	ssize_t linelen;

	if ((fp = fopen(file, "r")) == NULL)
		err(ERR_SYNTAX, "open: %s", file);

	while ((linelen = getline(&line, &linesize, fp)) != -1) {
		linenum++;
		line[linelen - 1] = '\0';
		if (parse_rule_impl(line, def, imodifiers) == -1)
			errx(ERR_SYNTAX, "syntax error in %s at entry %zu",
			    file, linenum);
	}

	free(line);
	if (ferror(fp))
		err(ERR_SYNTAX, "failed to parse file %s", file);
	fclose(fp);
}

void
parse_file(const char *file, enum rule_type def)
{

	parse_file_impl(file, def, 0);
}

static const char *
send_command(struct rule *r)
{
	static char buf[16];
	char *b = buf;
	char *ep = buf + sizeof(buf);

	switch (r->type) {
	case RULE_EXCLUDE:
		*b++ = '-';
		break;
	case RULE_INCLUDE:
		*b++ = '+';
		break;
	case RULE_CLEAR:
		*b++ = '!';
		break;
	case RULE_MERGE:
		*b++ = '.';
		break;
	case RULE_DIR_MERGE:
		*b++ = ':';
		break;
	case RULE_SHOW:
		*b++ = 'S';
		break;
	case RULE_HIDE:
		*b++ = 'H';
		break;
	case RULE_PROTECT:
		*b++ = 'P';
		break;
	case RULE_RISK:
		*b++ = 'R';
		break;
	default:
		err(ERR_SYNTAX, "unknown rule type %d", r->type);
	}

	for (int i = 0; modifiers[i].modifier != 0; i++) {
		if (r->omodifiers & modifiers[i].modifier)
			*b++ = modifiers[i].sopt;
		if (b >= ep - 3)
			err(ERR_SYNTAX, "rule modifiers overflow");
	}
	if (b >= ep - 3)
		err(ERR_SYNTAX, "rule prefix overflow");
	*b++ = ' ';

	/* include the stripped root '/' for anchored patterns */
	if (r->anchored)
		*b++ = '/';
	*b++ = '\0';
	return buf;
}

static const char *
postfix_command(struct rule *r)
{
	static char buf[8];

	buf[0] = '\0';
	if (r->onlydir)
		strlcpy(buf, "/", sizeof(buf));
	if (r->leadingdir)
		strlcpy(buf, "/***", sizeof(buf));

	return buf;
}

static bool
rule_should_xfer(struct sess *sess, struct rule *r)
{

	/*
	 * Merge files without the include/exclude modifiers get passed through
	 * for compatibility.
	 */
	if (r->type == RULE_MERGE) {
		return (r->modifiers &
		    (MOD_MERGE_EXCLUDE | MOD_MERGE_INCLUDE)) == 0;
	}

	/*
	 * If *we* are the sender, the other side is mostly interested in
	 * exclusion rules for the purposes of --delete-excluded.
	 */
	if (sess->mode == FARGS_SENDER) {
		switch (r->type) {
		case RULE_INCLUDE:
		case RULE_EXCLUDE:
		case RULE_PROTECT:
		case RULE_RISK:
			/* Explicitly receiver-side rules */
			return true;
		default:
			break;
		}

		return false;
	}

	return true;
}

void
send_rules(struct sess *sess, int fd)
{
	const char *cmd;
	const char *postfix;
	struct rule *r;
	size_t cmdlen, len, postlen, i;

	for (i = 0; i < numrules; i++) {
		r = &rules[i];

		if (!rule_should_xfer(sess, r))
			continue;

		cmd = send_command(r);
		if (cmd == NULL)
			err(ERR_PROTOCOL,
			    "rules are incompatible with remote rsync");
		postfix = postfix_command(r);
		cmdlen = strlen(cmd);
		len = strlen(r->pattern);
		postlen = strlen(postfix);

		if (!io_write_int(sess, fd, cmdlen + len + postlen))
			err(ERR_SOCK_IO, "send rules");
		if (!io_write_buf(sess, fd, cmd, cmdlen))
			err(ERR_SOCK_IO, "send rules");
		if (!io_write_buf(sess, fd, r->pattern, len))
			err(ERR_SOCK_IO, "send rules");
		/* include the '/' stripped by onlydir */
		if (postlen > 0)
			if (!io_write_buf(sess, fd, postfix, postlen))
				err(ERR_SOCK_IO, "send rules");
	}

	if (!io_write_int(sess, fd, 0))
		err(ERR_SOCK_IO, "send rules");
}

/*
 * + rules are sent without the command in some circumstances, so see if we have
 * what looks like an unsalted exclude rule.
 */
static enum rule_type
rule_xfer_type(const char **linep)
{
	const char *line = *linep;
	size_t len;
	enum rule_type type;

	if (line[1] != ' ' && line[1] != '_')
		return RULE_EXCLUDE;

	len = strcspn(line, " _");

	/*
	 * Not completely sure... see if this matches one of our rule prefixes.
	 * If it doesn't, we have to assume that it's an exclude rule.
	 */
	type = parse_command(line, len, NULL);
	if (type != RULE_NONE)
		*linep = line + len + 1;
	else
		type = RULE_EXCLUDE;
	return type;
}

void
recv_rules(struct sess *sess, int fd)
{
	char line[8192];
	char *rule;
	size_t len;
	enum rule_type type;

	do {
		if (!io_read_size(sess, fd, &len))
			err(ERR_SOCK_IO, "receive rules");

		if (len == 0)
			return;
		if (len >= sizeof(line) - 1)
			errx(ERR_SOCK_IO, "received rule too long");
		if (!io_read_buf(sess, fd, line, len))
			err(ERR_SOCK_IO, "receive rules");
		line[len] = '\0';

		rule = &line[0];
		type = rule_xfer_type((const char **)&rule);
		if (parse_rule(rule, type) == -1)
			errx(ERR_PROTOCOL, "syntax error in received rules");
	} while (1);
}

static inline int
rule_actionable(const struct rule *r, enum fmode rulectx)
{

	switch (r->type) {
	/* Almost always actionable */
	case RULE_EXCLUDE:
		if ((r->modifiers & MOD_CVSEXCLUDE) != 0)
			return 0;
		/* FALLTHROUGH */
	case RULE_INCLUDE:
		return 1;
	/* Sender side */
	case RULE_HIDE:
	case RULE_SHOW:
		return rulectx == FARGS_SENDER;
	/* Receiver side */
	case RULE_PROTECT:
	case RULE_RISK:
		return rulectx == FARGS_RECEIVER;
	/* Meta, never actionable */
	case RULE_CLEAR:
	case RULE_MERGE:
	case RULE_DIR_MERGE:
	default:
		return 0;
	}

	return 0;
}

static inline int
rule_matched(const struct rule *r)
{
	int ret = 0;

	switch (r->type) {
	/*
	 * We decomposed RULE_EXCLUDE and RULE_INCLUDE based on sender/receiver
	 * modifiers earlier on, so we don't need to check it again here.  We
	 * won't see hide/show/protect/risk rules here unless we're on the
	 * appropriate side, so we don't need to worry about that, either.
	 */
	case RULE_HIDE:
	case RULE_PROTECT:
	case RULE_EXCLUDE:
		ret = -1;
		break;
	case RULE_SHOW:
	case RULE_RISK:
	case RULE_INCLUDE:
		ret = 1;
		break;
	default:
		/* Illegal, should have been filtered out above. */
		break;
	}

	assert(ret != 0);
	return ret;
}

static inline int
rule_pattern_matched(const struct rule *r, const char *path)
{
	bool matched, negate = (r->modifiers & MOD_NEGATE) != 0;

	/*
	 * We need to augment this result with the negate modifier; the
	 * intention of the negate modifier is that the rule shoud only take
	 * effect if the pattern did *not* match.  If it *did* match, then we
	 * still need to check other rules for possible applicability.
	 */
	matched = strcmp(path, r->pattern) == 0;
	return matched != negate;
}

static void
rule_abspath(const char *path, char *outpath, size_t outpathsz)
{
	assert(outpathsz >= PATH_MAX);

	if (path[0] == '/') {
		if (strlcpy(outpath, path, outpathsz) >= outpathsz) {
			errno = ENAMETOOLONG;
			err(ERR_FILEGEN, "%s", path);
		}

		return;
	}

	if (strlcpy(outpath, rule_base, outpathsz) >= outpathsz) {
		errno = ENAMETOOLONG;
		err(ERR_FILEGEN, "%s", rule_base);
	}

	/* rule_base is guaranteed to be /-terminated. */
	if (strlcat(outpath, path, outpathsz) >= outpathsz) {
		errno = ENAMETOOLONG;
		err(ERR_FILEGEN, "%s/%s", outpath, path);
	}
}

void
rules_base(const char *root)
{
	size_t slen;

	if (root[0] == '/') {
		if (strlcpy(rule_base, root, sizeof(rule_base)) >=
		    sizeof(rule_base)) {
			errno = ENAMETOOLONG;
			err(ERR_FILEGEN, "strlcpy");
		}

		rule_base_cwdend = NULL;
		return;
	}

	if (rule_base_cwdend == NULL) {
		getcwd(rule_base, sizeof(rule_base) - 1);
		rule_base_cwdend = &rule_base[strlen(rule_base)];
	}

	/*
	 * If we're working with a path within cwd, truncate this back to cwd so
	 * that we can strlcat() it.
	 */
	*rule_base_cwdend = '/';
	*(rule_base_cwdend + 1) = '\0';

	if (strcmp(root, ".") == 0)
		return;

	slen = strlen(root);

	if (strlcat(rule_base, root, sizeof(rule_base)) >= sizeof(rule_base)) {
		errno = ENAMETOOLONG;
		err(ERR_FILEGEN, "strlcat");
	}

	/* Guarantee / termination */
	if (root[slen - 1] != '/' &&
	    strlcat(rule_base, root, sizeof(rule_base)) >= sizeof(rule_base)) {
		errno = ENAMETOOLONG;
		err(ERR_FILEGEN, "strlcat");
	}
}

int
rules_match(const char *path, int isdir, enum fmode rulectx)
{
	char abspath[PATH_MAX];
	const char *basename, *inpath = path, *p = NULL;
	struct rule *r;
	size_t i;

	assert(rule_base != NULL);
	abspath[0] = '\0';

	basename = strrchr(path, '/');
	if (basename != NULL)
		basename += 1;
	else
		basename = path;

	for (i = 0; i < numrules; i++) {
		r = &rules[i];

		if (r->onlydir && !isdir)
			continue;

		/* Rule out merge rules and other meta-actions. */
		if (!rule_actionable(r, rulectx))
			continue;

		if ((r->modifiers & MOD_ABSOLUTE) != 0) {
			if (abspath[0] == '\0')
				rule_abspath(path, abspath, sizeof(abspath));

			path = abspath;
		} else {
			path = inpath;
		}

		if (r->nowild) {
			/* fileonly and anchored are mutually exclusive */
			if (r->fileonly) {
				if (rule_pattern_matched(r, basename))
					return rule_matched(r);
			} else if (r->anchored) {
				/*
				 * assumes that neither path nor pattern
				 * start with a '/'.
				 */
				if (rule_pattern_matched(r, path))
					return rule_matched(r);
			} else if (r->leadingdir) {
				size_t plen = strlen(r->pattern);

				p = strstr(path, r->pattern);
				/*
				 * match from start or dir boundary also
				 * match to end or to dir boundary
				 */
				if (p != NULL && (p == path || p[-1] == '/') &&
				    (p[plen] == '\0' || p[plen] == '/'))
					return rule_matched(r);
			} else {
				size_t len = strlen(path);
				size_t plen = strlen(r->pattern);

				if (len >= plen && rule_pattern_matched(r,
				    path + len - plen)) {
					/* match all or start on dir boundary */
					if (len == plen ||
					    path[len - plen - 1] == '/')
						return rule_matched(r);
				}
			}
		} else {
			if (r->fileonly) {
				p = basename;
			} else if (r->anchored || r->numseg == -1) {
				/* full path matching */
				p = path;
			} else {
				short nseg = 1;

				/* match against the last numseg elements */
				for (p = path; *p != '\0'; p++)
					if (*p == '/')
						nseg++;
				if (nseg < r->numseg) {
					p = NULL;
				} else {
					nseg -= r->numseg;
					for (p = path; *p != '\0' && nseg > 0;
					    p++) {
						if (*p == '/')
							nseg--;
					}
				}
			}

			if (p != NULL) {
				bool matched, negate;

				negate = (r->modifiers & MOD_NEGATE) != 0;
				matched =  rmatch(r->pattern, p,
				    r->leadingdir) == 0;
				if (matched != negate)
					return rule_matched(r);
			}
		}
	}

	return 0;
}
