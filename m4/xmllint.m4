#
# AC_PROG_XMLLINT and AC_TRY_RUN_XMLLINT
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
# AC_PROG_XMLLINT
#
# Check xmllint is installed. Optionally, set options for xmllint.
#
AC_DEFUN([AC_PROG_XMLLINT],[
        AC_PATH_PROG([XMLLINT],[xmllint])

        AC_SUBST([XMLLINT_FLAGS],["--catalogs"])
        AC_ARG_WITH([xmllint-flags],
                [AS_HELP_STRING([--with-xmllint-flags],
                        [Options for xmllint. @<:@default="$XMLLINT_FLAGS"@:>@])],
                [XMLLINT_FLAGS="$withval"],[])
])

#
# AC_TRY_RUN_XMLLINT(xml-file,[ACTION-IF-FOUND],[ACTION-IF-NOT-FOUND])
#
# Try to validate input xml file (xml-file) with xmllint.
#
# It requires that AC_PROG_XMLLINT is run previously and then $XMLLINT and
# $XMLLINT_FLAGS are set successfully.
#
AC_DEFUN([AC_TRY_RUN_XMLLINT],[
        AC_REQUIRE([AC_PROG_XMLLINT])

        $XMLLINT $XMLLINT_FLAGS $1 > xmllint.conftest.out 2>&1
        AS_IF([test "$?" = 0],[ifelse([$2],[],[:],[$2])],[ifelse([$3],[],[:],[$3])])

        cat xmllint.conftest.out >& AS_MESSAGE_LOG_FD
        rm -f xmllint.conftest.out
])
