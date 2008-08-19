LANG = ja

mandir = @mandir@/$(LANG)
man_MANS = rsyslogd.8 rsyslog.conf.5

EXTRA_DIST = $(man_MANS)
EXTRA_DIST += rsyslog.conf.5.xml rsyslogd.8.xml \
	rsyslog.conf.5.po rsyslogd.8.po


if ENABLE_REGENERATE_MAN
CLEANFILES = $(man_MANS)

create-pot: rsyslog.conf.5.pot rsyslogd.8.pot
create-xml: rsyslog.conf.5.xml rsyslogd.8.xml
update-po: rsyslog.conf.5.po rsyslogd.8.po

.PHONY: create-pot create-xml update-po

rsyslog.conf.5.pot: ../C/rsyslog.conf.5.xml
	$(XML2PO) $(XML2PO_FLAGS) -o $@ $<

rsyslogd.8.pot: ../C/rsyslogd.8.xml
	$(XML2PO) $(XML2PO_FLAGS) -o $@ $<

rsyslog.conf.5.xml: ../C/rsyslog.conf.5.xml rsyslog.conf.5.po
	$(XML2PO) $(XML2PO_FLAGS) -l $(LANG) -p rsyslog.conf.5.po -o $@ $<
	sed -i 's:\(^<refentry .*\)>:\1 lang="$(LANG)">:' $@

rsyslogd.8.xml: ../C/rsyslogd.8.xml rsyslogd.8.po
	$(XML2PO) $(XML2PO_FLAGS) -l $(LANG) -p rsyslogd.8.po -o $@ $<
	sed -i 's:\(^<refentry .*\)>:\1 lang="$(LANG)">:' $@

rsyslog.conf.5.po: ../C/rsyslog.conf.5.xml
	$(XML2PO) $(XML2PO_FLAGS) -u $@ $<

rsyslogd.8.po: ../C/rsyslogd.8.xml
	$(XML2PO) $(XML2PO_FLAGS) -u $@ $<

rsyslog.conf.5: rsyslog.conf.5.xml Makefile
	$(XSLTPROC) $(XSLTPROC_FLAGS) -o $@ $(DOCBOOK_MANPAGES_XSL_URI) $<

rsyslogd.8: rsyslogd.8.xml Makefile
	$(XSLTPROC) $(XSLTPROC_FLAGS) -o $@ $(DOCBOOK_MANPAGES_XSL_URI) $<

endif
