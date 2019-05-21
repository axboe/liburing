NAME=liburing
SPECFILE=$(NAME).spec
VERSION=$(shell awk '/Version:/ { print $$2 }' $(SPECFILE))
TAG = $(NAME)-$(VERSION)
RPMBUILD=$(shell `which rpmbuild >&/dev/null` && echo "rpmbuild" || echo "rpm")

INSTALL=install
prefix ?= /usr
includedir=$(prefix)/include
libdir=$(prefix)/lib
mandir=$(prefix)/man

default: all

all:
	@$(MAKE) -C src
	@$(MAKE) -C test
	@$(MAKE) -C examples

runtests:
	@$(MAKE) -C test runtests

config-host.mak: configure
	@if [ ! -e "$@" ]; then					\
	  echo "Running configure ...";				\
	  ./configure;						\
	else							\
	  echo "$@ is out-of-date, running configure";		\
	  sed -n "/.*Configured with/s/[^:]*: //p" "$@" | sh;	\
	fi

ifneq ($(MAKECMDGOALS),clean)
include config-host.mak
endif

install:
	@$(MAKE) -C src install prefix=$(DESTDIR)$(prefix) includedir=$(DESTDIR)$(includedir) libdir=$(DESTDIR)$(libdir)
	$(INSTALL) -m 755 -d $(DESTDIR)$(mandir)/man2
	$(INSTALL) -m 644 man/*.2 $(DESTDIR)$(mandir)/man2

clean:
	@rm -f config-host.mak config-host.h cscope.out
	@$(MAKE) -C src clean
	@$(MAKE) -C test clean
	@$(MAKE) -C examples clean

cscope:
	@cscope -b -R

tag-archive:
	@git tag $(TAG)

create-archive:
	@git archive --prefix=$(NAME)-$(VERSION)/ -o $(NAME)-$(VERSION).tar.gz $(TAG)
	@echo "The final archive is ./$(NAME)-$(VERSION).tar.gz."

archive: clean tag-archive create-archive

srpm: create-archive
	$(RPMBUILD) --define "_sourcedir `pwd`" --define "_srcrpmdir `pwd`" --nodeps -bs $(SPECFILE)
