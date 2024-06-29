#! /bin/sh

if [ ! $srcdir ] ; then
	srcdir=.
fi

testdir=$srcdir/tests

. ${testdir}/vars.sh

input ()
{
	echo bla
}

stderrfilter ()
{
	sed 's/^\([0-9][0-9]* B\).*$/\1/' \
	| sed 's/ ([0-9]*)$//' \
	| grep -v '^Since end of first transfer: '
}

testit ()
{
	echo Testing with options "$@"
	echo Testing with options "$@" 1>&2
	input | $PRG -v4  "$@"
	input | $PRG -v4 -b1 "$@"
	input | $PRG -v4 -b1 -B 8192 "$@"
	input | $PRG -v4 -b2 -B 8192 "$@"
	input | $PRG  "$@"
	input | $PRG -b1 "$@"
	input | $PRG -b1 -B 8192 "$@"
	input | $PRG -b2 -B 8192 "$@"

	$PRG -i/dev/zero     -n 6 -B 200 -b 3 -v4 -l -o- "$@" -c 0
	$PRG -i/dev/null     -n 6 -B 200 -b 3 -v4 -l -o- "$@" -c 0
	$PRG -i/etc/services -n 6 -B 200 -b 3 -v4 -l -o- "$@" -c 0
	$PRG -i/dev/zero     -n 6 -B 200 -b 3 -v4 -l "$@" | wc -c
	$PRG -i/dev/null     -n 6 -B 200 -b 3 -v4 -l "$@" | wc -c
	$PRG -i/etc/services -n 6 -B 200 -b 3 -v4 -l "$@" | wc -c

	$PRG -i- -n 6 -B 200 -b 3 -v4 -l -o- "$@" -c 0
	$PRG -i- -n 6 -B 200 -b 3 -v4 -l -o- "$@" -c 0
	$PRG -i- -n 6 -B 200 -b 3 -v4 -l -o- "$@" -c 0
	$PRG -i- -n 6 -B 200 -b 3 -v4 -l "$@" -c 0 | wc -l
	$PRG -i- -n 6 -B 200 -b 3 -v4 -l "$@" -c 0 | wc -l
	$PRG -i- -n 6 -B 200 -b 3 -v4 -l "$@" -c 0 | wc -l

	$PRG -i $PRG | cmp - $PRG
	$PRG -B1m -i $PRG | cmp - $PRG
	$PRG -B80k -i $PRG | cmp - $PRG
	$PRG -B2 -b1 -i $PRG | cmp - $PRG
	$PRG -B1048578 -b1048577 -i $PRG | cmp - $PRG
}

fail ()
{
	echo $* 1>&2
	exit 1
}

# Tests where stderr must match exactly
for opt in 0 ; do
	testit -c $opt
done > ${testdir}/log1 2> ${testdir}/log2a

# Child data alway appended, not interleaved
stderrfilter < ${testdir}/log2a | grep -v '#1 ' > ${testdir}/log2
stderrfilter < ${testdir}/log2a | grep '#1 ' >> ${testdir}/log2

diff ${testdir}/test1.log1 ${testdir}/log1 || fail log1
diff ${testdir}/test1.log2 ${testdir}/log2 || fail log2

# For these tests, there is only minimal hope of comparing stderr
for opt in 1 2 3 4 ; do
	testit -c $opt
done > ${testdir}/log3 2> ${testdir}/log4
diff ${testdir}/test1.log3 ${testdir}/log3 || fail log3
if [ `wc -l < ${testdir}/log4` != `wc -l < ${testdir}/test1.log4` ] ; then
	echo Number of lines does not match: 1>&2
	wc -l ${testdir}/log4 1>&2
	wc -l ${testdir}/test1.log4 1>&2
	exit 1
fi

# Test with data > 4 GB
if [ ! -n ""$1 ] || [ $1 != small ] ; then
	(
		for i in 1 2 3 4 5 6 7 8 ; do
			cstream -b64k -i - -n1g
		done
	) | $PRG -b 64k -B 153k -v1 -o- 2> ${testdir}/log5
	egrep '8589934592 B 8.0 GB [0-9]+.[0-9][0-9] s [0-9]+ B/s [0-9]+.[0-9][0-9] MB/s' ${testdir}/log5 > /dev/null || fail 8GB-test failed
fi
exit 0
