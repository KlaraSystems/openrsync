include Makefile.configure

OBJS	   = blocks.o \
	     client.o \
	     compats.o \
	     downloader.o \
	     fargs.o \
	     flist.o \
	     hash.o \
	     ids.o \
	     io.o \
	     log.o \
	     md4.o \
	     misc.o \
	     mkpath.o \
	     mktemp.o \
	     receiver.o \
	     sender.o \
	     server.o \
	     session.o \
	     socket.o \
	     symlinks.o \
	     uploader.o
ALLOBJS	   = $(OBJS) \
	     main.o
AFLS	   = afl/test-blk_recv \
	     afl/test-flist_recv

# The -O0 is to help with debugging coredumps.
CFLAGS	+= -O0

all: openrsync

afl: $(AFLS)

openrsync: $(ALLOBJS)
	$(CC) -o $@ $(ALLOBJS) -lm

$(AFLS): $(OBJS)
	$(CC) -o $@ $*.c $(OBJS)

install: all
	mkdir -p $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(MANDIR)/man1
	mkdir -p $(DESTDIR)$(MANDIR)/man5
	$(INSTALL_MAN) openrsync.1 $(DESTDIR)$(MANDIR)/man1
	$(INSTALL_MAN) rsync.5 rsyncd.5 $(DESTDIR)$(MANDIR)/man5
	$(INSTALL_PROG) openrsync $(DESTDIR)$(BINDIR)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/openrsync
	rm -f $(DESTDIR)$(MANDIR)/man1/openrsync.1
	rm -f $(DESTDIR)$(MANDIR)/man5/rsync.5
	rm -f $(DESTDIR)$(MANDIR)/man5/rsyncd.5

clean:
	rm -f $(ALLOBJS) openrsync $(AFLS)

$(ALLOBJS) $(AFLS): extern.h config.h

blocks.o downloader.o hash.o md4.o: md4.h
