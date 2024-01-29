/*
 * Platform hooks to more cleanly provide some functionality not otherwise
 * applicable to openrsync at-large.
 */

#include <sys/types.h>

#include "extern.h"

#if !HAVE_PLATFORM_FLIST_MODIFY
int
platform_flist_modify(const struct sess *sess, struct fl *fl)
{

	return 1;
}
#endif
