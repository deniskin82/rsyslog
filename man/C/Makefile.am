man_MANS = rsyslogd.8 rsyslog.conf.5

EXTRA_DIST = $(man_MANS)
EXTRA_DIST += rsyslog.conf.5.xml rsyslogd.8.xml


if ENABLE_REGENERATE_MAN
CLEANFILES = $(man_MANS)

rsyslog.conf.5: rsyslog.conf.5.xml Makefile
	$(XSLTPROC) $(XSLTPROC_FLAGS) -o $@ $(DOCBOOK_MANPAGES_XSL_URI) $<

rsyslogd.8: rsyslogd.8.xml Makefile
	$(XSLTPROC) $(XSLTPROC_FLAGS) -o $@ $(DOCBOOK_MANPAGES_XSL_URI) $<

endif
