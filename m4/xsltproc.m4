#
# AC_PROG_XSLTPROC and AC_TRY_RUN_XSLTPROC
#
# Basic idea is borrowed from ac_prog_xsltproc.m4 and ac_check_docbook_dtd.m4
# which are developed by Dustin J. Mitchell (Zmanda Inc.
# <http://www.zmanda.com/>) and distributed under GPL v2+ with special autoconf
# exception at Autoconf Macro Archive (http://autoconf-archive.cryp.to/).
#
# My version is sort of a simplified version of these macros. So if you want
# complete one, try these macros.
#
# This macro is distributed under the same license as these macros.
#
#
# Copyright (c) 2008 Satoru SATOH <satoru.satoh@gmail.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
# Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program. If not, see <http://www.gnu.org/licenses/>.
#
# As a special exception, the respective Autoconf Macro's copyright owner
# gives unlimited permission to copy, distribute and modify the configure
# scripts that are the output of Autoconf when processing the Macro. You
# need not follow the terms of the GNU General Public License when using
# or distributing such scripts, even though portions of the text of the
# Macro appear in them. The GNU General Public License (GPL) does govern
# all other use of the material that constitutes the Autoconf Macro.
#
# This special exception to the GPL applies to versions of the Autoconf
# Macro released by the Autoconf Macro Archive. When you make and
# distribute a modified version of the Autoconf Macro, you may extend this
# special exception to the GPL to apply to your modified version as well.
#

#
# AC_PROG_XSLTPROC
#
# Check xsltproc is installed. Optionally, set options for xsltproc.
#
AC_DEFUN([AC_PROG_XSLTPROC],[
        AC_PATH_PROG([XSLTPROC],[xsltproc])

        AC_SUBST([XSLTPROC_FLAGS],["--catalogs"])
        AC_ARG_WITH([xsltproc-flags],
                [AS_HELP_STRING([--with-xsltproc-flags],
                        [Options for xsltproc. @<:@default="$XSLTPROC_FLAGS"@:>@])],
                [XSLTPROC_FLAGS="$withval"],[])
])

#
# AC_TRY_RUN_XSLTPROC([xml-file],[xsl-stylesheet],
#       [ACTION-IF-FOUND],[ACTION-IF-NOT-FOUND])
#
# Try to transform input xml file (xml-file) with xsltproc and specified
# stylesheet (xsl-stylesheet).
#
# If $1 (xml-file) is "none", then just check the stylesheet (xsl-stylesheet).
#
# It requires that AC_PROG_XSLTPROC is run previously and then $XSLTPROC and
# $XSLTPROC_FLAGS are set successfully.
#
AC_DEFUN([AC_TRY_RUN_XSLTPROC],[
        AC_REQUIRE([AC_PROG_XSLTPROC])

        input_xml=$1
        stylesheet=$2
        conftestout=try-run-xsltproc.conftest.out

        AS_IF([test -z "$input_xml"],
                [input_xml=conftest.xml; echo "<?xml version='1.0' encoding='ISO-8859-1'?><test/>" > $input_xml],
                [AS_IF([test "x$input_xml" = "xnone"],[input_xml=""])])
        AS_IF([test -z "$stylesheet"],[stylesheet=conftest.xsl;
                cat << EOF > $stylesheet
<?xml version="1.0" encoding='ISO-8859-1'?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version='1.0'>
<xsl:output method="text"/>
<xsl:template match="*|/"><xsl:apply-templates/></xsl:template>
<xsl:template match="text()"><xsl:value-of select="."/></xsl:template>
</xsl:stylesheet>
EOF
                ])

        $XSLTPROC $XSLTPROC_FLAGS $stylesheet $input_xml > $conftestout 2>&1
        AS_IF([test "$?" = 0],
                [AS_IF([grep 'warning: failed to load external entity' $conftestout > /dev/null 2>&1],
                        [ifelse([$4],[],[:],[$4])
                        ],[ifelse([$3],[],[:],[$3])
                        ])],[
                ifelse([$4],[],[:],[$4])])

        cat $conftestout >& AS_MESSAGE_LOG_FD
        rm -f $conftestout conftest.xsl conftest.xml
])
