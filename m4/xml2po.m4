#
# AC_PROG_XML2PO 
# 
# Check xml2po is installed. Optionally, set options for xml2po.
# (xml2po is contained in gnome-doc-utils.)
#
AC_DEFUN([AC_PROG_XML2PO],[
        AC_PATH_PROG([XML2PO],[xml2po])

        AC_SUBST([XML2PO_FLAGS],["-e"]) dnl default: --expand-all-entities
        AC_ARG_WITH([xml2po-flags],
                [AS_HELP_STRING([--with-xml2po-flags],
                        [Options for xml2po. @<:@default="$XML2PO_FLAGS"@:>@])],
                [XML2PO_FLAGS="$withval"],[])
])
