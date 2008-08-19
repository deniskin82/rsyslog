#
# AC_CHECK_DOCBOOK_DTD and AC_CHECK_DOCBOOK_XSL
#
# Basic idea is borrowed from ac_check_docbook_dtd.m4 and
# ac_check_docbook_xsl.m4 which are developed by Dustin J. Mitchell
# (Zmanda Inc. <http://www.zmanda.com/>) and distributed under GPL v2+ with
# special autoconf exception at Autoconf Macro Archive
# (http://autoconf-archive.cryp.to/).
# 
# My version is sort of a simplified version of these macros. So if you want
# complete one, try these macros.
# 
# This macro is distributed under the same license as these macros.
#
# NOTE: You need xmllint.m4 and xsltproc.m4 to use this macro.
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
# AC_CHECK_DOCBOOK_DTD([dtd-version],
#       [ACTION-IF-FOUND],[ACTION-IF-NOT-FOUND])
#
# Check access to DocBook DTD.
#
AC_DEFUN([AC_CHECK_DOCBOOK_DTD],[
        AC_REQUIRE([AC_TRY_RUN_XMLLINT])

        define([_DTDVER],[$1])
        ifelse([_DTDVER],[],[define([_DTDVER],[4.5])]) dnl current?

        cat << EOF > conftest.xml
<?xml version="1.0" encoding='ISO-8859-1'?>
<!DOCTYPE book PUBLIC "-//OASIS//DTD DocBook XML V[]_DTDVER//EN"
        "http://www.oasis-open.org/docbook/xml/_DTDVER/docbookx.dtd">
<book/>
EOF
        AC_MSG_CHECKING(for DocBook DTD v[]_DTDVER)
        AC_TRY_RUN_XMLLINT([conftest.xml],[AC_MSG_RESULT(yes)
                ifelse([$2],[],[:],[$2])
                ],[AC_MSG_RESULT(no)
                ifelse([$3],[],[:],[$3])])

        rm -f conftest.xml
        undefine([_DTDVER])
])

# 
# AC_CHECK_DOCBOOK_XSL([xsl-stylesheet-version],[target-format],
#       [ACTION-IF-FOUND],[ACTION-IF-NOT-FOUND])
#
# Check access to DocBook XSL stylesheet, then define DOCBOOK_XSL_URI and set
# the uri of that docbook xsl stylesheet if found.
#
# $2 (target-format) is one of target format names: fo, html, htmlhelp,
# javahelp, manpages and xhtml.
#
AC_DEFUN([AC_CHECK_DOCBOOK_XSL],[
        AC_REQUIRE([AC_TRY_RUN_XSLTPROC])

        define([_XSLVER],[$1])
        define([_FORMAT],[$2])
        ifelse([_XSLVER],[],[define([_XSLVER],[current])])
        ifelse([_FORMAT],[],[define([_FORMAT],[xhtml])])
        db_xsl_uri="http://docbook.sourceforge.net/release/xsl/_XSLVER/_FORMAT/docbook.xsl"

        cat << EOF > conftest.xsl
<?xml version="1.0" encoding='ISO-8859-1'?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version='1.0'>
<xsl:import href="$db_xsl_uri"/>
</xsl:stylesheet>
EOF
        AC_MSG_CHECKING(for DocBook XSL stylesheet _XSLVER of target _FORMAT)
        AC_TRY_RUN_XSLTPROC([none],[conftest.xsl],[AC_MSG_RESULT(yes)
                AC_SUBST([DOCBOOK_XSL_URI],[$db_xsl_uri])
                ifelse([$3],[],[:],[$3])
                ],[AC_MSG_RESULT(no)
                ifelse([$4],[],[:],[$4])])

        dnl rm -f conftest.xsl
        undefine([_XSLVER])
        undefine([_FORMAT])
])
