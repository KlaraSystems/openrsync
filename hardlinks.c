/*
  How does preserving of hardlinks work?

  1) in the protocol the sender already transmits the device a file is
  on and the inode number.  This identifies hardlinks in the source
  tree visibly to the receiver process.  The number of links in the
  original file is not transported, so a full search needs to happen.

  All the following happens purely in the receiver:

  2) when writing any plain file, check whether has the same file id
  (device number and inode number) as a file already transmitted
  (regardless of whether it has then been newly written or was already
  exsting).  If yes, then don't write it. (but see footnote)

  3) go through the sent file list, identify all hard links and store
  those in a list.

  4) go through that list and make hardlinks for all of those entries,
  ignoring errors when the target is already there.

  5) don't forget to print about this activity when -v is on.

  BUG: this scheme does not transport newly made hardlinks in the
  source when the destination already had it as a plain file.  In such
  cases the second plain file should be unlinked before hardlinking,
  the trick being to not unlink the first one.  The solution probably
  is for step 2 to do unlinking on any existing file.

  QUESTION: imagine this situation.  Three files, all hardlinked.  On
  the sending side you have two and on the receiving side you have 2
  with one of them being the other file from the set of 3.  Assuming
  --delete is on.

  QUESTION: imagine this situation.  On the receiving side you already
  have one (and only one) side of an incoming hardlink, but the dir
  entry is the second one in the sender's file list.  Does the above
  scheme work correctly here, and even if so how do we prevent a 
  retransmit of the file when it is first in the file list?

  NOTE: the file list is always sorted by strcmp(2).

  TODO: write tests first to see how many of these situations are
  handled correctly by GNU rsync.

  TODO: see how much of this is tested in the original GNU rsync
  testsuite.

  TODO: make sure un-hardlinking works

  */
