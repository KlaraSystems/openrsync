openrsync and grsync2 use a 2-process model, grsync3 uses 3.

openrsync has the highest number of mmaps and generally system calls.

In the system call traces of a plain rsync there is no indication that
grsync3 starts sending data while the initial scan is still underway.
Might be something like a cutoff by number of files when that kicks
in.

The option that OpenBSD openrsync has over github/portable openrsync
is the connection timeout commandline parameter.  There also is code
messing with the root directory (or the sync) that might be a bugfix.



