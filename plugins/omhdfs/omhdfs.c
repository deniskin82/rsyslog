/* omhdfs.c
 * This is an output module to support Hadoop's HDFS.
 *
 * NOTE: read comments in module-template.h to understand how this file
 *       works!
 *
 * Copyright 2010 Rainer Gerhards and Adiscon GmbH.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * A copy of the GPL can be found in the file "COPYING" in this distribution.
 */

#include "config.h"
#include "rsyslog.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/file.h>
#include <pthread.h>
#include <hdfs.h>

#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "conf.h"
#include "cfsysline.h"
#include "module-template.h"
#include "unicode-helper.h"
#include "errmsg.h"
#include "hashtable.h"
#include "hashtable_itr.h"

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("omhdfs")

/* internal structures
 */
DEF_OMOD_STATIC_DATA
DEFobjCurrIf(errmsg)

/* global data */
static struct hashtable *files;		/* holds all file objects that we know */

/* tables for interfacing with the v6 config system */
/* module-global parameters */
static struct cnfparamdescr modpdescr[] = {
	{ "template", eCmdHdlrGetWord, 0 },
};
static struct cnfparamblk modpblk =
	{ CNFPARAMBLK_VERSION,
	  sizeof(modpdescr)/sizeof(struct cnfparamdescr),
	  modpdescr
	};
/* action (instance) parameters */
static struct cnfparamdescr actpdescr[] = {
	{ "file", eCmdHdlrString, 0 },     /* either "file" or ... */
	{ "dynafile", eCmdHdlrString, 0 }, /* "dynafile" MUST be present */
	{ "target", eCmdHdlrString, 0 },
	{ "port", eCmdHdlrInt, 0 },
	{ "template", eCmdHdlrGetWord, 0 },
};

static struct cnfparamblk actpblk =
	{ CNFPARAMBLK_VERSION,
	  sizeof(actpdescr)/sizeof(struct cnfparamdescr),
	  actpdescr
	};


typedef struct configSettings_s {
	uchar *fileName;	
	uchar *hdfsHost;	
	uchar *dfltTplName;	/* default template name to use */
	int hdfsPort;
} configSettings_t;
static configSettings_t cs;


typedef struct {
	uchar	*name;
	hdfsFS fs;
	hdfsFile fh;
	const char *hdfsHost;
	tPort hdfsPort;
	int nUsers;
	pthread_mutex_t mut;
} file_t;


typedef struct _instanceData {
	uchar 	*tplName;	/* name of assigned template */
	uchar *fname;
	uchar *target;		/* server for this file */
	int port;		/* port to connect to on target */
	char bDynamicName;	/* 0 - static name, 1 - dynamic name (with properties) */
	file_t *pFile;
	uchar ioBuf[64*1024];
	unsigned offsBuf;
	/* TODO: implement the following settings! rgerhards, 2012-07-12 */
	int	iIOBufSize;		/* size of associated io buffer */
} instanceData;
uchar	*pszFileDfltTplName; /* name of the default template to use */

struct modConfData_s {
	rsconf_t *pConf;	/* our overall config object */
	uchar 	*tplName;	/* default template */
};

static modConfData_t *loadModConf = NULL;/* modConf ptr to use for the current load process */
static modConfData_t *runModConf = NULL;/* modConf ptr to use for the current exec process */

/* forward definitions (down here, need data types) */
static inline rsRetVal fileClose(file_t *pFile);

/* this function gets the default template. It coordinates action between
 * old-style and new-style configuration parts.
 */
static inline uchar*
getDfltTpl(void)
{
	if(loadModConf != NULL && loadModConf->tplName != NULL)
		return loadModConf->tplName;
	else if(pszFileDfltTplName == NULL)
		return (uchar*)"RSYSLOG_FileFormat";
	else
		return pszFileDfltTplName;
}


/* set the default template to be used
 * This is a module-global parameter, and as such needs special handling. It needs to
 * be coordinated with values set via the v2 config system (rsyslog v6+). What we do
 * is we do not permit this directive after the v2 config system has been used to set
 * the parameter.
 */
rsRetVal
setLegacyDfltTpl(void __attribute__((unused)) *pVal, uchar* newVal)
{
	DEFiRet;

	if(loadModConf != NULL && loadModConf->tplName != NULL) {
		free(newVal);
		errmsg.LogError(0, RS_RET_ERR, "omhdfs default template already set via module "
			"global parameter - can no longer be changed");
		ABORT_FINALIZE(RS_RET_ERR);
	}
	free(pszFileDfltTplName);
	pszFileDfltTplName = newVal;
finalize_it:
	RETiRet;
}


BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
	if(eFeat == sFEATURERepeatedMsgReduction)
		iRet = RS_RET_OK;
ENDisCompatibleWithFeature


BEGINdbgPrintInstInfo
CODESTARTdbgPrintInstInfo
	printf("omhdfs: file:%s", pData->pFile->name);
ENDdbgPrintInstInfo


/* note that hdfsFileExists() does not work, so we did our
 * own function to see if a pathname exists. Returns 0 if the
 * file does not exists, something else otherwise. Note that
 * we can also check a directroy (if that matters...)
 */
static int
HDFSFileExists(hdfsFS fs, uchar *name)
{
	int r;
	hdfsFileInfo *info;

	info = hdfsGetPathInfo(fs, (char*)name);
	/* if things go wrong, we assume it is because the file
	 * does not exist. We do not get too much information...
	 */
	if(info == NULL) {
		r = 0;
	} else {
		r = 1;
		hdfsFreeFileInfo(info, 1);
	}
	return r;
}

static inline rsRetVal
HDFSmkdir(hdfsFS fs, uchar *name)
{
	DEFiRet;
	if(hdfsCreateDirectory(fs, (char*)name) == -1)
		ABORT_FINALIZE(RS_RET_ERR);

finalize_it:
	RETiRet;
}


/* ---BEGIN FILE OBJECT---------------------------------------------------- */
/* This code handles the "file object". This is split from the actual
 * instance data, because several instances may write into the same file.
 * If so, we need to use a single object, and also synchronize their writes.
 * So we keep the file object separately, and just stick a reference into
 * the instance data.
 */

static inline rsRetVal
fileObjConstruct(file_t **ppFile)
{
	file_t *pFile;
	DEFiRet;

	CHKmalloc(pFile = malloc(sizeof(file_t)));
	pFile->name = NULL;
	pFile->hdfsHost = NULL;
	pFile->fh = NULL;
	pFile->nUsers = 0;

	*ppFile = pFile;
finalize_it:
	RETiRet;
}

static inline void
fileObjAddUser(file_t *pFile)
{
	/* init mutex only when second user is added */
	++pFile->nUsers;
	if(pFile->nUsers == 2)
		pthread_mutex_init(&pFile->mut, NULL);
	DBGPRINTF("omhdfs: file %s now being used by %d actions\n", pFile->name, pFile->nUsers);
}

static rsRetVal
fileObjDestruct(file_t **ppFile)
{
	file_t *pFile = *ppFile;
	if(pFile->nUsers > 1)
		pthread_mutex_destroy(&pFile->mut);
	fileClose(pFile);
	free(pFile->name);
	free((char*)pFile->hdfsHost);
	free(pFile->fh);

	return RS_RET_OK;
}


/* check, and potentially create, all names inside a path */
static rsRetVal
filePrepare(file_t *pFile)
{
	uchar *p;
	uchar *pszWork;
	size_t len;
	DEFiRet;

	if(HDFSFileExists(pFile->fs, pFile->name))
		FINALIZE;

	/* file does not exist, create it (and eventually parent directories */
	if(1) { // check if bCreateDirs
		len = ustrlen(pFile->name) + 1;
		CHKmalloc(pszWork = MALLOC(sizeof(uchar) * len));
		memcpy(pszWork, pFile->name, len);
		for(p = pszWork+1 ; *p ; p++)
			if(*p == '/') {
				/* temporarily terminate string, create dir and go on */
				*p = '\0';
				if(!HDFSFileExists(pFile->fs, pszWork)) {
					CHKiRet(HDFSmkdir(pFile->fs, pszWork));
				}
				*p = '/';
			}
		free(pszWork);
		return 0;
	}

finalize_it:
	RETiRet;
}


/* this function is to be used as destructor for the
 * hash table code.
 */
static void
fileObjDestruct4Hashtable(void *ptr)
{
	file_t *pFile = (file_t*) ptr;
	fileObjDestruct(&pFile);
}


static inline rsRetVal
fileOpen(file_t *pFile)
{
	DEFiRet;

	assert(pFile->fh == NULL);
	if(pFile->nUsers > 1)
		d_pthread_mutex_lock(&pFile->mut);

	DBGPRINTF("omhdfs: try to connect to HDFS at host '%s', port %d\n",
		  pFile->hdfsHost, pFile->hdfsPort);
	pFile->fs = hdfsConnect(pFile->hdfsHost, pFile->hdfsPort);
	if(pFile->fs == NULL) {
		DBGPRINTF("omhdfs: error can not connect to hdfs\n");
		ABORT_FINALIZE(RS_RET_SUSPENDED);
	}

	CHKiRet(filePrepare(pFile));

	pFile->fh = hdfsOpenFile(pFile->fs, (char*)pFile->name, O_WRONLY|O_APPEND, 0, 0, 0);
	if(pFile->fh == NULL) {
		/* maybe the file does not exist, so we try to create it now.
		 * Note that we can not use hdfsExists() because of a deficit in
		 * it: https://issues.apache.org/jira/browse/HDFS-1154
		 * As of my testing, libhdfs at least seems to return ENOENT if
		 * the file does not exist.
		 */
		if(errno == ENOENT) {
			DBGPRINTF("omhdfs: ENOENT trying to append to '%s', now trying create\n",
				  pFile->name);
		 	pFile->fh = hdfsOpenFile(pFile->fs,
						 (char*)pFile->name, O_WRONLY|O_CREAT, 0, 0, 0);
		}
	}
	if(pFile->fh == NULL) {
		DBGPRINTF("omhdfs: failed to open %s for writing!\n", pFile->name);
		ABORT_FINALIZE(RS_RET_SUSPENDED);
	}

finalize_it:
	if(pFile->nUsers > 1)
		d_pthread_mutex_unlock(&pFile->mut);
	RETiRet;
}


/* Note: lenWrite is reset to zero on successful write! */
static inline rsRetVal
fileWrite(file_t *pFile, uchar *buf, size_t *lenWrite)
{
	DEFiRet;

	if(*lenWrite == 0)
		FINALIZE;

	if(pFile->nUsers > 1)
		d_pthread_mutex_lock(&pFile->mut);

	/* open file if not open. This must be done *here* and while mutex-protected
	 * because of HUP handling (which is async to normal processing!).
	 */
	if(pFile->fh == NULL) {
		fileOpen(pFile);
		if(pFile->fh == NULL) {
			ABORT_FINALIZE(RS_RET_SUSPENDED);
		}
	}

dbgprintf("XXXXX: omhdfs writing %u bytes\n", *lenWrite);
	tSize num_written_bytes = hdfsWrite(pFile->fs, pFile->fh, buf, *lenWrite);
	if((unsigned) num_written_bytes != *lenWrite) {
		errmsg.LogError(errno, RS_RET_ERR_HDFS_WRITE,
			        "omhdfs: failed to write %s, expected %lu bytes, "
			        "written %lu\n", pFile->name, (unsigned long) *lenWrite,
				(unsigned long) num_written_bytes);
		ABORT_FINALIZE(RS_RET_SUSPENDED);
	}
	*lenWrite = 0;

finalize_it:
	RETiRet;
}


static inline rsRetVal
fileClose(file_t *pFile)
{
	DEFiRet;

	if(pFile->fh == NULL)
		FINALIZE;

	if(pFile->nUsers > 1)
		d_pthread_mutex_lock(&pFile->mut);

	hdfsCloseFile(pFile->fs, pFile->fh);
	pFile->fh = NULL;

	if(pFile->nUsers > 1)
		d_pthread_mutex_unlock(&pFile->mut);

finalize_it:
	RETiRet;
}

/* ---END FILE OBJECT---------------------------------------------------- */

/* This adds data to the output buffer and performs an actual write
 * if the new data does not fit into the buffer. Note that we never write
 * partial data records. Other actions may write into the same file, and if
 * we would write partial records, data could become severely mixed up.
 * Note that we must check of some new data arrived is large than our
 * buffer. In that case, the new data will written with its own
 * write operation.
 */
static inline rsRetVal
addData(instanceData *pData, uchar *buf)
{
	unsigned len;
	DEFiRet;

	len = strlen((char*)buf);
	if(pData->offsBuf + len < sizeof(pData->ioBuf)) {
		/* new data fits into remaining buffer */
		memcpy((char*) pData->ioBuf + pData->offsBuf, buf, len);
		pData->offsBuf += len;
	} else {
dbgprintf("XXXXX: not enough room, need to flush\n");
		CHKiRet(fileWrite(pData->pFile, pData->ioBuf, &pData->offsBuf));
		if(len >= sizeof(pData->ioBuf)) {
			CHKiRet(fileWrite(pData->pFile, buf, &len));
		} else {
			memcpy((char*) pData->ioBuf + pData->offsBuf, buf, len);
			pData->offsBuf += len;
		}
	}

	iRet = RS_RET_DEFER_COMMIT;
finalize_it:
	RETiRet;
}

BEGINcreateInstance
CODESTARTcreateInstance
	pData->pFile = NULL;
ENDcreateInstance


BEGINfreeInstance
CODESTARTfreeInstance
	if(pData->pFile != NULL)
		fileObjDestruct(&pData->pFile);
ENDfreeInstance


BEGINtryResume
CODESTARTtryResume
	fileClose(pData->pFile);
	fileOpen(pData->pFile);
	if(pData->pFile->fh == NULL){
		dbgprintf("omhdfs: tried to resume file %s, but still no luck...\n",
			  pData->pFile->name);
		iRet = RS_RET_SUSPENDED;
	}
ENDtryResume


BEGINbeginTransaction
CODESTARTbeginTransaction
dbgprintf("omhdfs: beginTransaction\n");
ENDbeginTransaction


BEGINdoAction
CODESTARTdoAction
	DBGPRINTF("omhdfs: action to to write to %s\n", pData->pFile->name);
	iRet = addData(pData, ppString[0]);
dbgprintf("omhdfs: done doAction\n");
ENDdoAction


BEGINendTransaction
CODESTARTendTransaction
dbgprintf("omhdfs: endTransaction\n");
	if(pData->offsBuf != 0) {
		DBGPRINTF("omhdfs: data unwritten at end of transaction, persisting...\n");
		iRet = fileWrite(pData->pFile, pData->ioBuf, &pData->offsBuf);
	}
ENDendTransaction


static inline void
setInstParamDefaults(instanceData *pData)
{
	pData->fname = NULL;
	pData->tplName = NULL;
	pData->iIOBufSize = 64*1024;
}

BEGINbeginCnfLoad
CODESTARTbeginCnfLoad
	loadModConf = pModConf;
	pModConf->pConf = pConf;
	pModConf->tplName = NULL;
ENDbeginCnfLoad

BEGINsetModCnf
	struct cnfparamvals *pvals = NULL;
	int i;
CODESTARTsetModCnf
	pvals = nvlstGetParams(lst, &modpblk, NULL);
	if(pvals == NULL) {
		errmsg.LogError(0, RS_RET_MISSING_CNFPARAMS, "error processing module "
				"config parameters [module(...)]");
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}

	if(Debug) {
		dbgprintf("module (global) param blk for omhdfs:\n");
		cnfparamsPrint(&modpblk, pvals);
	}

	for(i = 0 ; i < modpblk.nParams ; ++i) {
		if(!pvals[i].bUsed)
			continue;
		if(!strcmp(modpblk.descr[i].name, "template")) {
			loadModConf->tplName = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
			if(pszFileDfltTplName != NULL) {
				errmsg.LogError(0, RS_RET_DUP_PARAM, "omhdfs: warning: default template "
						"was already set via legacy directive - may lead to inconsistent "
						"results.");
			}
		} else {
			dbgprintf("omhdfs: program error, non-handled "
			  "param '%s' in beginCnfLoad\n", modpblk.descr[i].name);
		}
	}
finalize_it:
	if(pvals != NULL)
		cnfparamvalsDestruct(pvals, &modpblk);
ENDsetModCnf

BEGINendCnfLoad
CODESTARTendCnfLoad
	loadModConf = NULL; /* done loading */
	/* free legacy config vars */
	free(pszFileDfltTplName);
	pszFileDfltTplName = NULL;
ENDendCnfLoad

BEGINcheckCnf
CODESTARTcheckCnf
ENDcheckCnf

BEGINactivateCnf
CODESTARTactivateCnf
	runModConf = pModConf;
ENDactivateCnf

BEGINfreeCnf
CODESTARTfreeCnf
	free(pModConf->tplName);
ENDfreeCnf


BEGINnewActInst
	struct cnfparamvals *pvals;
	int i;
CODESTARTnewActInst
	DBGPRINTF("newActInst (omhdfs)\n");
	pvals = nvlstGetParams(lst, &actpblk, NULL);
	if(pvals == NULL) {
		errmsg.LogError(0, RS_RET_MISSING_CNFPARAMS, "omhdfs: either the \"file\" or "
				"\"dynfile\" parameter must be given");
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}
	if(Debug) {
		dbgprintf("action param blk in omhdfs:\n");
		cnfparamsPrint(&actpblk, pvals);
	}
	CHKiRet(createInstance(&pData));
	setInstParamDefaults(pData);
	for(i = 0 ; i < actpblk.nParams ; ++i) {
		if(!pvals[i].bUsed)
			continue;
		if(!strcmp(actpblk.descr[i].name, "file")) {
			pData->fname = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
			CODE_STD_STRING_REQUESTnewActInst(1)
			pData->bDynamicName = 0;
		} else if(!strcmp(actpblk.descr[i].name, "dynafile")) {
			pData->fname = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
			CODE_STD_STRING_REQUESTnewActInst(2)
			pData->bDynamicName = 1;
		} else if(!strcmp(actpblk.descr[i].name, "target")) {
			pData->target = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(actpblk.descr[i].name, "port")) {
			pData->port = (int) pvals[i].val.d.n;
		} else if(!strcmp(actpblk.descr[i].name, "template")) {
			pData->tplName = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else {
			dbgprintf("omhdfs: program error, non-handled "
			  "param '%s'\n", actpblk.descr[i].name);
		}
	}
	if(pData->fname == NULL) {
		errmsg.LogError(0, RS_RET_MISSING_CNFPARAMS, "omhdfs: either the \"file\" or "
				"\"dynfile\" parameter must be given");
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}

	CHKiRet(OMSRsetEntry(*ppOMSR, 0, ustrdup(pData->tplName == NULL ?
                                         getDfltTpl() : pData->tplName), OMSR_NO_RQD_TPL_OPTS));

	if(pData->bDynamicName) {
		/* "filename" is actually a template name, we need this as string 1. So let's add it */
		CHKiRet(OMSRsetEntry(*ppOMSR, 1, ustrdup(pData->fname), OMSR_NO_RQD_TPL_OPTS));
	}

CODE_STD_FINALIZERnewActInst
	cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst


BEGINparseSelectorAct
	file_t *pFile;
	int r;
	uchar *keybuf;
CODESTARTparseSelectorAct

	/* first check if this config line is actually for us */
	if(strncmp((char*) p, ":omhdfs:", sizeof(":omhdfs:") - 1)) {
		ABORT_FINALIZE(RS_RET_CONFLINE_UNPROCESSED);
	}

	/* ok, if we reach this point, we have something for us */
	p += sizeof(":omhdfs:") - 1; /* eat indicator sequence  (-1 because of '\0'!) */
	CHKiRet(createInstance(&pData));
	CODE_STD_STRING_REQUESTparseSelectorAct(1)
	CHKiRet(cflineParseTemplateName(&p, *ppOMSR, 0, 0,
				       (cs.dfltTplName == NULL) ? (uchar*)"RSYSLOG_FileFormat" : cs.dfltTplName));

	if(cs.fileName == NULL) {
		errmsg.LogError(0, RS_RET_ERR_HDFS_OPEN, "omhdfs: no file name specified, can not continue");
		ABORT_FINALIZE(RS_RET_FILE_NOT_SPECIFIED);
	}

	pFile = hashtable_search(files, cs.fileName);
	if(pFile == NULL) {
		/* we need a new file object, this one not seen before */
		CHKiRet(fileObjConstruct(&pFile));
		CHKmalloc(pFile->name = cs.fileName);
		CHKmalloc(keybuf = ustrdup(cs.fileName));
		cs.fileName = NULL; /* re-set, data passed to file object */
		CHKmalloc(pFile->hdfsHost = strdup((cs.hdfsHost == NULL) ? "default" : (char*) cs.hdfsHost));
		pFile->hdfsPort = cs.hdfsPort;
		fileOpen(pFile);
		if(pFile->fh == NULL){
			errmsg.LogError(0, RS_RET_ERR_HDFS_OPEN, "omhdfs: failed to open %s - "
				    	"retrying later", pFile->name);
			iRet = RS_RET_SUSPENDED;
		}
		r = hashtable_insert(files, keybuf, pFile);
		if(r == 0)
			ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
	}
	fileObjAddUser(pFile);
	pData->pFile = pFile;
	pData->offsBuf = 0;

CODE_STD_FINALIZERparseSelectorAct
ENDparseSelectorAct


BEGINdoHUP
    file_t *pFile;
    struct hashtable_itr *itr;
CODESTARTdoHUP
	DBGPRINTF("omhdfs: HUP received (file count %d)\n", hashtable_count(files));
	/* Iterator constructor only returns a valid iterator if
	* the hashtable is not empty */
	itr = hashtable_iterator(files);
	if(hashtable_count(files) > 0)
	{
		do {
			pFile = (file_t *) hashtable_iterator_value(itr);
			fileClose(pFile);
			DBGPRINTF("omhdfs: HUP, closing file %s\n", pFile->name);
		} while (hashtable_iterator_advance(itr));
	}
ENDdoHUP


/* Reset config variables for this module to default values.
 * rgerhards, 2007-07-17
 */
static rsRetVal resetConfigVariables(uchar __attribute__((unused)) *pp, void __attribute__((unused)) *pVal)
{
	cs.hdfsHost = NULL;
	cs.hdfsPort = 0;
	free(cs.fileName);
	cs.fileName = NULL;
	free(cs.dfltTplName);
	cs.dfltTplName = NULL;
	return RS_RET_OK;
}


BEGINmodExit
CODESTARTmodExit
	objRelease(errmsg, CORE_COMPONENT);
	if(files != NULL)
		hashtable_destroy(files, 1); /* 1 => free all values automatically */
ENDmodExit


BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_OMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_QUERIES
CODEqueryEtryPt_STD_CONF2_setModCnf_QUERIES
CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES
CODEqueryEtryPt_TXIF_OMOD_QUERIES /* we support the transactional interface! */
CODEqueryEtryPt_doHUP
ENDqueryEtryPt



BEGINmodInit()
CODESTARTmodInit
	*ipIFVersProvided = CURR_MOD_IF_VERSION;
CODEmodInit_QueryRegCFSLineHdlr
	CHKiRet(objUse(errmsg, CORE_COMPONENT));
	CHKmalloc(files = create_hashtable(20, hash_from_string, key_equals_string,
			                   fileObjDestruct4Hashtable));

	CHKiRet(regCfSysLineHdlr((uchar *)"omhdfsfilename", 0, eCmdHdlrGetWord, NULL, &cs.fileName, NULL));
	CHKiRet(regCfSysLineHdlr((uchar *)"omhdfshost", 0, eCmdHdlrGetWord, NULL, &cs.hdfsHost, NULL));
	CHKiRet(regCfSysLineHdlr((uchar *)"omhdfsport", 0, eCmdHdlrInt, NULL, &cs.hdfsPort, NULL));
	CHKiRet(regCfSysLineHdlr((uchar *)"omhdfsdefaulttemplate", 0, eCmdHdlrGetWord, setLegacyDfltTpl, NULL, NULL));
	CHKiRet(omsdRegCFSLineHdlr((uchar *)"resetconfigvariables", 1, eCmdHdlrCustomHandler, resetConfigVariables, NULL, STD_LOADABLE_MODULE_ID));
	DBGPRINTF("omhdfs: module compiled with rsyslog version %s.\n", VERSION);
CODEmodInit_QueryRegCFSLineHdlr
ENDmodInit
