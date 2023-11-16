#!/bin/sh

set -e

: ${TMPDIR:=/tmp}

test_one() {
	rsync_path="$1"
	destdir="$2"

	$PWD/openrsync -avv \
	    --rsync-path="$rsync_path" \
	    --exclude 'openrsync' --exclude '*.o' --exclude '.git' \
	    "$PWD/" "$destdir"
	if [ ! -f "$destdir/main.c" ]; then
		1>&2 echo "transfer with '$rsync_path' failed"
		ls -l "$destdir"
		return 1
	fi

	1>&2 echo "transfer with '$rsync_path' OK"

	return 0
}

BASE_DEST="$TMPDIR/openrsync-src-xfer"

test_one "$PWD/openrsync" "$BASE_DEST"
if which rsync 1>/dev/null; then
	test_one rsync "$BASE_DEST-interop"
fi

