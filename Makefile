# Top-level convenience wrapper for make / make install / make clean.
# src/mk.sh remains the full-featured entry (arch and debug options).
# 'install' currently exists only in Makefile.linux.

UNAME := $(shell uname)

ifeq ($(UNAME),Linux)
MKFILE := Makefile.linux
else ifeq ($(UNAME),Darwin)
MKFILE := Makefile.osx
else ifeq ($(UNAME),FreeBSD)
MKFILE := Makefile.fbsd
else ifeq ($(UNAME),OpenBSD)
MKFILE := Makefile.obsd
else ifneq (,$(findstring CYGWIN,$(UNAME)))
MKFILE := Makefile.cygwin
else
$(error unsupported OS: $(UNAME))
endif

# mk.sh passes -O2 (plus arch flags); keep direct 'make' equivalent.
export CCOPT ?= -O2

all install clean:
	$(MAKE) -C src -f $(MKFILE) $@

.PHONY: all install clean
