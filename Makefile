UNAME := $(shell uname)

ifeq ($(UNAME), Linux)
	MAKEFILE=Makefile.linux
else
	MAKEFILE=Makefile.windows
endif

all:
	$(MAKE) -f $(MAKEFILE)

clean:
	$(MAKE) -f $(MAKEFILE) clean

clear-smoke-stack:
	$(MAKE) -f $(MAKEFILE) clear-smoke-stack

debug-with-source:
	$(MAKE) -f $(MAKEFILE) debug-with-source

distclean:
	$(MAKE) -f $(MAKEFILE) distclean

kill-adb-server:
	$(MAKE) -f $(MAKEFILE) kill-adb-server

kill-gradle-daemon:
	$(MAKE) -f $(MAKEFILE) kill-gradle-daemon

launch-emulator:
	$(MAKE) -f $(MAKEFILE) launch-emulator

list-devices:
	$(MAKE) -f $(MAKEFILE) list-devices

list-files:
	$(MAKE) -f $(MAKEFILE) list-files

load-apk:
	$(MAKE) -f $(MAKEFILE) load-apk

load-apk-release:
	$(MAKE) -f $(MAKEFILE) load-apk-release

pull-database:
	$(MAKE) -f $(MAKEFILE) pull-database

purge:
	$(MAKE) -f $(MAKEFILE) purge

release:
	$(MAKE) -f $(MAKEFILE) release

remove-database:
	$(MAKE) -f $(MAKEFILE) remove-database

stop-smoke-stack:
	$(MAKE) -f $(MAKEFILE) stop-smoke-stack
