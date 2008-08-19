#
# doc-i18n.m4 - m4 macros for document i18n/l10n.
#

# 
# AC_CHECK_MAN_I18N_TOOLS([ACTION-IF-FOUND],[ACTION-IF-NOT-FOUND])
#
# Check the followings:
#
# 1. Are required tools and files for DocBook XML file to man page
#    transformation available? Looks for xsltproc, DocBook DTD and DocBook XSL
#    stylesheet for manpage target.
#
# 2. Is it possible to convert PO file to DocBook XML? Look for xml2po.
#
AC_DEFUN([AC_CHECK_MAN_I18N_TOOLS],[
        AC_PROG_XMLLINT
        AC_PROG_XSLTPROC
        AC_PROG_XML2PO
        AC_CHECK_DOCBOOK_DTD([4.5],[have_docbook_dtd="yes"])
        AC_CHECK_DOCBOOK_XSL([current],[manpages],[have_docbook_xsl="yes"
                AC_SUBST([DOCBOOK_MANPAGES_XSL_URI],[$DOCBOOK_XSL_URI])
                ])
        AS_IF([test "x$have_docbook_dtd" = "xyes" && test "x$have_docbook_xsl" = "xyes"],[
                ifelse([$1],[],[ :],[$1])
                ],[
                ifelse([$2],[],[ :],[$2])])
])

