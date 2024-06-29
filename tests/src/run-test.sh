#!/bin/sh

RSYNC_SSHKEY=$(realpath ~/.ssh/id_openrsync)
RSYNC_FLAGS=""

mkdir -p /tmp/openrsync-testsuite/tmp
export TMPDIR=/tmp/openrsync-testsuite/tmp
script=$(realpath ~/openrsync-testsuite/src/tests_kyua.sh)
resultfile="/tmp/openrsync-testsuite/rsync.results"
rsyncdir="$(realpath ~/openrsync)"

rsync_path() {
	type=$1

#	echo "/usr/libexec/rsync/rsync.$type"
	echo "$rsyncdir/rsync.$type"
}

write_header() {
	date > "$resultfile"
	printf "%-50s\t%s\n" "Test Name" "Result" >> "$resultfile"
}

write_result() {
	tst=$1
	result=$2
	printf "%-50s\t%s\n" "$tst" "$result" >> "$resultfile"
	printf "$result\t$tst\n"
}

# --force-delete not currently implemented"
#exclusions="test5b_symlink_kills_dir"

# globstar doesn't currently work if we exclude the containing directory.
# Example: --include '**/???.txt' --exclude '*'
exclusions="test12d_inex"

# XXX sparse files currently broken on macOS
exclusions="$exclusions test13_sparse test13b_sparse"

# rsync 2.6.9 does not support modifiers (only run with openrsync/openrsync?)
exclusions="$exclusions test25_filter_mods"

# ... or sending non-include rules over the wire for protocol < 29
exclusions="$exclusions test25_filter_basic_clear test25_filter_basic_cvs"
exclusions="$exclusions test25_filter_clear test25_filter_dir test25_filter_merge_cvs"

# Known bug with mtime
exclusions="$exclusions test40_backup test41_backup_dir"

exclusions=$(echo "$exclusions" | sed -Ee 's/[[:space:]]+/|/g')
tests=$(atf-sh "$script" -l | grep '^ident:' | sed -e 's/ident: //' | \
	grep -Ev "$exclusions")

roles="sender receiver"
impls="samba openrsync"
impls_client="samba"
impls_server="openrsync"

tstdir=$(mktemp -dt rsync_test)
trap '(echo; date) >> $resultfile; rm -rf $tstdir' EXIT

write_header

pass=0
fail=0
for client in $impls; do
	for server in $impls; do
		for crole in $roles; do
			srcprefix=""
			destprefix=""

			# Reduce test cases
			case "$client$server" in
			sambasamba*)
				# We don't need to test this combination
				continue
				;;
			esac
			case "$crole" in
			sender)
				destprefix="allan@localhost:"
				;;
			receiver)
				srcprefix="allan@localhost:"
				;;
			esac

			for tst in $tests; do
				mkdir -p "$tstdir"

				testname="${tst}__${client}-${server}_c${crole}"
				stdout="$resultfile.$testname.stdout"
				stderr="$resultfile.$testname.stderr"

				(
				cd "$tstdir" && \
				env RSYNC_CLIENT="$(rsync_path "$client")" \
					RSYNC_SERVER="$(rsync_path "$server")" \
					RSYNC_PREFIX_SRC="$srcprefix" \
					RSYNC_PREFIX_DEST="$destprefix" \
					RSYNC_SSHKEY="$RSYNC_SSHKEY" \
					RSYNC_FLAGS="$RSYNC_FLAGS" \
				    cstream="/usr/local/bin/cstream" \
					atf-sh "$script" "$tst"
				) > "$stdout" 2> "$stderr"

				rc=$?

				if [ "$rc" -eq 0 ]; then
					rm -f "$stderr" "$stdout"
					write_result "$testname" "PASS"
					pass=$((pass + 1))
				else
					write_result "$testname" "FAIL"
					fail=$((fail + 1))
				fi

				sudo rm -rf "$tstdir"
			done
		done
	done
done

echo "$pass/$((pass + fail)) tests passed"
if [ "$fail" -ne 0 ]; then
	exit 1
fi
