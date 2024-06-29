# Test suites for openrsync.

All tests are for the kyua framework.

cstream is a general-purpose stream-handling tool like dd, see
https://www.cons.org/cracauer/cstream.html for more.  To build, run its
./configure script && make.

run-orig/ contains slightly changed tests from GNU rsync.  See the
README.md in there.

src/ contains a new test suite.  See the README.md in there.

## src/ instructions

Edit conf.sh to your liking.

Run like this:

`./generate-kyua && kyua test`

You can also run the individual test cases like this:
`./test5_symlink-kills-dir.test`

Requirements:
- pkg misc/cstream is required for some modes of testing.
- perl5 for some one-liners

Makefile has some useful functions you might want to check out.

## src/ TODO items

Next flags to test:

- -l symbolic links # done
- -t times # done
- -r recursive (as in, do not for the test) # done
- atimes
- see whether chmod goes to umask # done

Then:
- include (and mix with exclude)
- include-from / exclude-from

  Make sure the +/- syntax inside the file is implemented

  Make sure that --include=- works for stdin

  Error on ! in include file

Then:
- max-size
- min-size
- specials (actually use the pipe)

Later:
- server mode
- -x (requires root and needs to be portable to macOS)

Postphone testing these options:
- -g group - would introduce a dependency on groups on the machine
- -o owner - would introduce a dependency on groups on the machine and
             would have to run uid root
Also test:
- group symbolic and group by number, which requires a second machine
  with different groups


## run-orig/ directory

Tools to run the tests in GNU rsync-<version>/testsuite outside their
own framework.

Instructions:

cd to rsync-$version/testsuite/ (from the tar.gz).  It must be built
(to get the ./tls utility).

copy file conf.sh from this repository and edit to your liking.
copy file generate-kyua from this repository.

source the config file in your shell:
`$ . ./conf.sh`

# run single test with output
`$ sh sometest.test`

# run all tests in kyua
`./generate-kyua && kyua test`


At the time of this writing no original tests pass with openrsync
unchanged.  This isn't because it is so broken, it is because the
tests use all kinds of exotic flags for rsync that openrsync does not
have yet, even for trivial tests.

I am currently going through the upstream GNU rsync tests to edit the
ones that make sense for us to use them from Kyua.  Those are the
tests with o_* filenames (which are picked up by the generate-kyua
scripts).

I have implemented some rsync flags in the "cracauer" branch here:
https://gitlab.klara.systems/klara/openrsync/-/tree/cracauer
