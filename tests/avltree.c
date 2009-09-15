/* This test checks the avltree class.
 *
 * Part of the testbench for rsyslog.
 *
 * Copyright 2009 Rainer Gerhards and Adiscon GmbH.
 *
 * This file is part of rsyslog.
 *
 * Rsyslog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Rsyslog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Rsyslog.  If not, see <http://www.gnu.org/licenses/>.
 *
 * A copy of the GPL can be found in the file "COPYING" in this distribution.
 */
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <glob.h>
#include <sys/stat.h>

#include "rsyslog.h"
#include "testbench.h"
#include "avltree.h"

MODULE_TYPE_TESTBENCH
/* define addtional objects we need for our tests */
DEFobjCurrIf(avltree)


BEGINInit
CODESTARTInit
	pErrObj = "avltree"; CHKiRet(objUse(avltree, CORE_COMPONENT));
ENDInit

BEGINExit
CODESTARTExit
ENDExit

typedef struct {
	char *key;
} testnode_t;

/* tree callbacks */
static rsRetVal ConstructNode(void *ppNode, void *pKey)
{
	testnode_t *pNode;
	DEFiRet;

	CHKmalloc(pNode = malloc(sizeof(testnode_t)));
	pNode->key = strdup((char*) pKey);
	*((testnode_t**) ppNode) = pNode;

finalize_it:
	RETiRet;
}


static rsRetVal DestructNode(void *ppNode)
{
	DEFiRet;
	free((*((testnode_t **) ppNode))->key);
	free(*((testnode_t **) ppNode));
	*((testnode_t**) ppNode) = NULL;
	RETiRet;
}


static rsRetVal CmpKey(void *pNode, void *pKey, int *pCmpResult)
{
	DEFiRet;
	*pCmpResult = strcmp(((testnode_t*)pNode)->key, (char*) pKey);
	RETiRet;
}


static rsRetVal GetKeyString(void *pNode, cstr_t **ppStr)
{
	DEFiRet;
	iRet = rsCStrConstructFromszStr(ppStr, (uchar*) ((testnode_t*)pNode)->key);
	RETiRet;
}


/* a helper macro to generate some often-used code... */
#define CHKEOF \
	if(feof(fp)) { \
		printf("error: unexpected end of control file %s\n", pszFileName); \
		ABORT_FINALIZE(RS_RET_ERR); \
	}
/* process a single test file
 * Note that we do not do a real parser here. The effort is not
 * justified by what we need to do. So it is a quick shot.
 * rgerhards, 2008-07-07
 */
static rsRetVal
ProcessTestFile(uchar *pszFileName)
{
	FILE *fp;
	char *lnptr = NULL;
	size_t lenLn;
	cstr_t *pstrOut = NULL;
	cstr_t *pSignature;
	avltree_t *pTree = NULL;
	DEFiRet;

	if((fp = fopen((char*)pszFileName, "r")) == NULL) {
		perror((char*)pszFileName);
		ABORT_FINALIZE(RS_RET_FILE_NOT_FOUND);
	}

	/* skip comments at start of file */

	getline(&lnptr, &lenLn, fp);
	while(!feof(fp)) {
		if(*lnptr == '#')
			getline(&lnptr, &lenLn, fp);
		else
			break; /* first non-comment */
	}
	CHKEOF;

	/* and now we look for "in:" (and again ignore the rest...) */
	if(strncmp(lnptr, "add:", 4)) {
		printf("error: expected 'add:'-line, but got: '%s'\n", lnptr);
		ABORT_FINALIZE(RS_RET_ERR);
	}
	/* if we reach this point, we need to read in the input data and add the nodes
	 * to the tree. Thus we need to create a tree, first. Note that the input data
	 * is terminated by a line with three sole $ ($$$\n)
	 */
	CHKiRet(avltree.Construct(&pTree));
	CHKiRet(avltree.ConfigureTree(pTree, ConstructNode, DestructNode, CmpKey, GetKeyString));
	CHKiRet(avltree.ConstructFinalize(pTree));

	getline(&lnptr, &lenLn, fp); CHKEOF;
	while(strncmp(lnptr, "$$$\n", 4)) {
		int keylen = strlen(lnptr);
		if(lnptr[keylen - 1] == '\n')
			lnptr[keylen - 1] = '\0';
		CHKiRet(avltree.Insert(pTree, (void*)lnptr));
		getline(&lnptr, &lenLn, fp); CHKEOF;
	}
	getline(&lnptr, &lenLn, fp); CHKEOF; /* skip $$$-line */

	/* and now we look for "out:" (and again ignore the rest...) */
	if(strncmp(lnptr, "out:", 4)) {
		printf("error: expected 'out:'-line, but got: '%s'\n", lnptr);
		ABORT_FINALIZE(RS_RET_ERR);
	}
	/* if we reach this point, we need to read in the expected program code. It is
	 * terminated by a line with three sole $ ($$$\n)
	 */
	CHKiRet(rsCStrConstruct(&pstrOut));
	getline(&lnptr, &lenLn, fp); CHKEOF;
	while(strncmp(lnptr, "$$$\n", 4)) {
		CHKiRet(rsCStrAppendStr(pstrOut, (uchar*)lnptr));
		getline(&lnptr, &lenLn, fp); CHKEOF;
	}

	/* un-comment for testing:
	 * printf("iRet: %d, script: %s\n, out: %s\n", iRetExpected, rsCStrGetSzStr(pstrIn),rsCStrGetSzStr(pstrOut));
	 */
	if(rsCStrGetSzStr(pstrOut) == NULL) {
		printf("error: output script is empty!\n");
		ABORT_FINALIZE(RS_RET_ERR);
	}

	/* everything read in, now get the signature of the tree we generated
	 * and check if it matches the expected signature.
	 */
	CHKiRet(rsCStrConstruct(&pSignature));
	CHKiRet(avltree.GetSignature(pTree, pSignature));
	printf("signature: '%s'\n", rsCStrGetSzStr(pSignature));

finalize_it:
	if(pTree != NULL)
		avltree.Destruct(&pTree);
	if(pstrOut != NULL)
		rsCStrDestruct(&pstrOut);

	RETiRet;
}


/* This test is parameterized. It search for test control files and
 * loads all that it finds. To add tests, simply create new .rstest
 * files.
 * rgerhards, 2008-07-07
 */
BEGINTest
	uchar *testFile;
	glob_t testFiles;
	size_t i = 0;
	struct stat fileInfo;
CODESTARTTest
	glob("*.avltest", GLOB_MARK, NULL, &testFiles);

	for(i = 0; i < testFiles.gl_pathc; i++) {
		testFile = (uchar*) testFiles.gl_pathv[i];

		if(stat((char*) testFile, &fileInfo) != 0) 
			continue; /* continue with the next file if we can't stat() the file */

		/* all regular files are run through the test logic. Symlinks don't work. */
		if(S_ISREG(fileInfo.st_mode)) { /* config file */
			printf("processing avltree test file '%s'...\n", testFile);
			iRet = ProcessTestFile((uchar*) testFile);
			if(iRet != RS_RET_OK) {
				/* in this case, re-run with debugging on */
				printf("processing test case failed with %d, re-running with debug messages:\n",
				       iRet);
				Debug = 1; /* these two are dirty, but we need them today... */
				debugging_on = 1;
				CHKiRet(ProcessTestFile((uchar*) testFile));
			}
		}
	}
	globfree(&testFiles);

finalize_it:
ENDTest
