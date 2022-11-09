###########################################################################
##
## File:        ./Makefile.am
##
###########################################################################
##
## run  automake to generate a Makefile.in
##      Makefile.am \
##      configure.ac >  Makefile.in
##      aclocal.m4  /
##

ACLOCAL_AMFLAGS = -I m4

man_MANS = pam_single_kcm_cache.7

moduledir = @libdir@
module_LTLIBRARIES = pam_single_kcm_cache.la
pam_single_kcm_cache_la_SOURCES = pam_single_kcm_cache.c
pam_single_kcm_cache_la_CFLAGS = $(AM_CFLAGS)
pam_single_kcm_cache_la_LDFLAGS = -module -avoid-version -lkrb5

dist-hook:
	-rm -rf `find $(distdir) -name CVS`

install-data-hook:
#	@echo === install-data-hook ===
	-rm $(DESTDIR)/$(libdir)/$(module_LTLIBRARIES)
help:
	@echo ""
	@echo "make		- compile sources to a shared library module"
	@echo "make all		- same as above"
	@echo "make install	- copy module and docs to destination"
	@echo "make clean	- cleans out most useless files"
	@echo "make disthelp	- extra help for developers"
	@echo ""

disthelp:
	@echo ""
	@echo "make dist	- creates distribution tarballs"
	@echo "make distclean	- cleans & removes most made files"
	@echo "make maintainer-clean	- cleans even more"
	@echo ""
