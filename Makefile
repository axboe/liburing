NAME=liburing
SPECFILE=$(NAME).spec
VERSION=$(shell awk '/Version:/ { print $$2 }' $(SPECFILE))
TAG = $(NAME)-$(VERSION)
RPMBUILD=$(shell `which rpmbuild >&/dev/null` && echo "rpmbuild" || echo "rpm")

prefix=/usr
includedir=$(prefix)/include
libdir=$(prefix)/lib

default: all

all:
	@$(MAKE) -C src
	@$(MAKE) -C test

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

clean:
	@rm -f config-host.mak config-host.h cscope.out
	@$(MAKE) -C src clean
	@$(MAKE) -C test clean

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
