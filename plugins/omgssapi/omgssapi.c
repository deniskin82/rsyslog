/* omgssapi.c rewrite
 * based on omfwd.c rsyslog 5.8.6
 *
 * Copyright 2007-2012 Adiscon GmbH.
 *
 * This file is part of rsyslog.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */
#include "config.h"
#ifdef USE_GSSAPI
#include "rsyslog.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fnmatch.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#ifdef USE_NETZIP
#include <zlib.h>
#endif
#include <pthread.h>
#include <gssapi/gssapi.h>
#include "conf.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "net.h"
#include "netstrms.h"
#include "netstrm.h"
#include "template.h"
#include "msg.h"
#include "tcpclt.h"
#include "cfsysline.h"
#include "module-template.h"
#include "gss-misc.h"
#include "glbl.h"
#include "errmsg.h"

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP

/* internal structures
 */
DEF_OMOD_STATIC_DATA
DEFobjCurrIf(errmsg)
DEFobjCurrIf(glbl)
DEFobjCurrIf(net)
DEFobjCurrIf(netstrms)
DEFobjCurrIf(netstrm)
DEFobjCurrIf(gssutil)
DEFobjCurrIf(tcpclt)

typedef struct _instanceData {
	netstrms_t *pNS; /* netstream subsystem */
	netstrm_t *pNetstrm; /* our output netstream */
	uchar *pszGssStrmDrvr;
	uchar *pszGssStrmDrvrAuthMode;
	permittedPeers_t *pGssPermPeers;
	int iGssStrmDrvrMode;
	char	*f_hname;
	int bIsConnected;  /* are we connected to remote host? 0 - no, 1 - yes, UDP means addr resolved */
	struct addrinfo *f_addr;
	int compressionLevel;	/* 0 - no compression, else level for zlib */
	char *port;
	int iGSSRebindInterval;	/* rebind interval */
	int nXmit;		/* number of transmissions since last (re-)bind */
	/* following fields for TCP-based delivery */
	tcpclt_t *pTCPClt;	/* our tcpclt object */

	gss_ctx_id_t gss_context;
	OM_uint32 gss_flags;
} instanceData;

/* config data */
static uchar *pszTplName = NULL; /* name of the default template to use */
static uchar *pszGssStrmDrvr = NULL; /* name of the stream driver to use */
static int iGssStrmDrvrMode = 0; /* mode for stream driver, driver-dependent (0 mostly means plain tcp) */
static int bGssResendLastOnRecon = 0; /* should the last message be re-sent on a successful reconnect? */
static uchar *pszGssStrmDrvrAuthMode = NULL; /* authentication mode to use */
static int iGSSRebindInterval = 0;	/* support for automatic re-binding (load balancers!). 0 - no rebind */

static permittedPeers_t *pGssPermPeers = NULL;

static char *gss_base_service_name = NULL;
static enum gss_mode_t {
	GSSMODE_MIC,
	GSSMODE_ENC
} gss_mode = GSSMODE_ENC;

static rsRetVal doTryResume(instanceData *pData);

/* get the syslog forward port from selector_t. The passed in
 * struct must be one that is setup for forwarding.
 * rgerhards, 2007-06-28
 * We may change the implementation to try to lookup the port
 * if it is unspecified. So far, we use the IANA default auf 514.
 */
static char *getFwdPt(instanceData *pData)
{
	assert(pData != NULL);
	if(pData->port == NULL)
		return("514");
	else
		return(pData->port);
}


/* destruct the TCP helper objects
 * This, for example, is needed after something went wrong.
 * This function is void because it "can not" fail.
 * rgerhards, 2008-06-04
 */
static inline void
DestructTCPInstanceData(instanceData *pData)
{
	OM_uint32 maj_stat, min_stat;

	assert(pData != NULL);

	if (pData->gss_context != GSS_C_NO_CONTEXT) {
		maj_stat = gss_delete_sec_context(&min_stat, &pData->gss_context, GSS_C_NO_BUFFER);
		if (maj_stat != GSS_S_COMPLETE)
			gssutil.display_status("deleting context", maj_stat, min_stat);
	}
	/* this is meant to be done when module is unloaded,
	   but since this module is static...
	*/
	if (gss_base_service_name != NULL) {
		free(gss_base_service_name);
		gss_base_service_name = NULL;
	}

	if(pData->pNetstrm != NULL)
		netstrm.Destruct(&pData->pNetstrm);
	if(pData->pNS != NULL)
		netstrms.Destruct(&pData->pNS);
}

BEGINcreateInstance
CODESTARTcreateInstance
ENDcreateInstance


BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
	if(eFeat == sFEATURERepeatedMsgReduction)
		iRet = RS_RET_OK;
ENDisCompatibleWithFeature


BEGINfreeInstance
CODESTARTfreeInstance
	/* final cleanup */

	DestructTCPInstanceData(pData);
	tcpclt.Destruct(&pData->pTCPClt);
	free(pData->port);
	free(pData->f_hname);
	free(pData->pszGssStrmDrvr);
	free(pData->pszGssStrmDrvrAuthMode);
	net.DestructPermittedPeers(&pData->pGssPermPeers);
ENDfreeInstance


BEGINdbgPrintInstInfo
CODESTARTdbgPrintInstInfo
	dbgprintf("%s", pData->f_hname);
ENDdbgPrintInstInfo



/* set the permitted peers -- rgerhards, 2008-05-19
 */
static rsRetVal
setPermittedPeer(void __attribute__((unused)) *pVal, uchar *pszID)
{
	DEFiRet;
	CHKiRet(net.AddPermittedPeer(&pGssPermPeers, pszID));
	free(pszID); /* no longer needed, but we must free it as of interface def */
finalize_it:
	RETiRet;
}



/* CODE FOR SENDING TCP MESSAGES */


/* Send a frame via plain TCP protocol
 * rgerhards, 2007-12-28
 */
static rsRetVal TCPSendGSSFrame(void *pvData, char *msg, size_t len)
{
	DEFiRet;
	ssize_t lenSend;

	int s;
	gss_ctx_id_t *context;
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc in_buf, out_buf;

	instanceData *pData = (instanceData *) pvData;

	lenSend = len;

	netstrm.GetSock(pData->pNetstrm, &s);
	context = &pData->gss_context;
	in_buf.value = msg;
	in_buf.length = len;
	maj_stat = gss_wrap(&min_stat, *context, (gss_mode == GSSMODE_ENC) ? 1 : 0, GSS_C_QOP_DEFAULT,
			    &in_buf, NULL, &out_buf);
	if (maj_stat != GSS_S_COMPLETE) {
		gssutil.display_status("wrapping message", maj_stat, min_stat);
		ABORT_FINALIZE(RS_RET_ERR);
	}
	
	if (gssutil.send_token(s, &out_buf) < 0) {
		ABORT_FINALIZE(RS_RET_ERR);
	}
	gss_release_buffer(&min_stat, &out_buf);

	dbgprintf("GSS sent %ld bytes, requested %ld\n", (long) lenSend, (long) len);

finalize_it:
	if(iRet != RS_RET_OK) {

		errmsg.LogError(0, RS_RET_GSS_SENDINIT_ERROR, "GSS-API Context initialization failed\n");
		gss_release_buffer(&min_stat, &out_buf);
		if (*context != GSS_C_NO_CONTEXT) {
			gss_delete_sec_context(&min_stat, context, GSS_C_NO_BUFFER);
			*context = GSS_C_NO_CONTEXT;
		}
		DestructTCPInstanceData(pData);
	}
	RETiRet;
}


/* This function is called immediately before a send retry is attempted.
 * It shall clean up whatever makes sense.
 * rgerhards, 2007-12-28
 */
static rsRetVal TCPSendGSSPrepRetry(void *pvData)
{
	DEFiRet;
	instanceData *pData = (instanceData *) pvData;

	assert(pData != NULL);
	DestructTCPInstanceData(pData);
	RETiRet;
}


/* initializes everything so that TCPSend can work.
 * rgerhards, 2007-12-28
 */
static rsRetVal TCPSendGSSInit(void *pvData)
{
	DEFiRet;

	char *base;
	OM_uint32 maj_stat, min_stat, init_sec_min_stat, *sess_flags, ret_flags;
	gss_buffer_desc out_tok, in_tok;
	gss_buffer_t tok_ptr;
	gss_name_t target_name;
	gss_ctx_id_t *context = NULL;
	int s;

	instanceData *pData = (instanceData *) pvData;

	assert(pData != NULL);
	if(pData->pNetstrm == NULL) {
		base = (gss_base_service_name == NULL) ? "host" : gss_base_service_name;
		out_tok.length = strlen(pData->f_hname) + strlen(base) + 2;
		CHKmalloc(out_tok.value = MALLOC(out_tok.length));
		strcpy(out_tok.value, base);
		strcat(out_tok.value, "@");
		strcat(out_tok.value, pData->f_hname);
		dbgprintf("GSS-API service name: %s\n", (char*) out_tok.value);
		tok_ptr = GSS_C_NO_BUFFER;
		context = &pData->gss_context;
		*context = GSS_C_NO_CONTEXT;
		maj_stat = gss_import_name(&min_stat, &out_tok, GSS_C_NT_HOSTBASED_SERVICE, &target_name);
		free(out_tok.value);
		out_tok.value = NULL;
		out_tok.length = 0;
		if (maj_stat != GSS_S_COMPLETE) {
			gssutil.display_status("parsing name", maj_stat, min_stat);
			iRet = RS_RET_ERR;
			goto finalize_it;
		}
		sess_flags = &pData->gss_flags;
		*sess_flags = GSS_C_MUTUAL_FLAG;
		if (gss_mode == GSSMODE_MIC) {
			*sess_flags |= GSS_C_INTEG_FLAG;
		}
		if (gss_mode == GSSMODE_ENC) {
			*sess_flags |= GSS_C_CONF_FLAG;
		}
		dbgprintf("GSS-API requested context flags:\n");
		gssutil.display_ctx_flags(*sess_flags);


		do {
			maj_stat = gss_init_sec_context(&init_sec_min_stat, GSS_C_NO_CREDENTIAL, context,
							target_name, GSS_C_NO_OID, *sess_flags, 0, NULL,
							tok_ptr, NULL, &out_tok, &ret_flags, NULL);
			if (tok_ptr != GSS_C_NO_BUFFER)
				free(in_tok.value);

			if (maj_stat != GSS_S_COMPLETE
			    && maj_stat != GSS_S_CONTINUE_NEEDED) {
				gssutil.display_status("initializing context", maj_stat, init_sec_min_stat);
				ABORT_FINALIZE(RS_RET_ERR);
			}

			if (pData->pNetstrm == NULL) {
				CHKiRet(netstrms.Construct(&pData->pNS));
				/* the stream driver must be set before the object is finalized! */
				CHKiRet(netstrms.SetDrvrName(pData->pNS, pszGssStrmDrvr));
				CHKiRet(netstrms.ConstructFinalize(pData->pNS));
	
				/* now create the actual stream and connect to the server */
				CHKiRet(netstrms.CreateStrm(pData->pNS, &pData->pNetstrm));
				CHKiRet(netstrm.ConstructFinalize(pData->pNetstrm));
				CHKiRet(netstrm.SetDrvrMode(pData->pNetstrm, pData->iGssStrmDrvrMode));
				/* now set optional params, but only if they were actually configured */
				if(pData->pszGssStrmDrvrAuthMode != NULL) {
					CHKiRet(netstrm.SetDrvrAuthMode(pData->pNetstrm, pData->pszGssStrmDrvrAuthMode));
				}
				if(pData->pGssPermPeers != NULL) {
					CHKiRet(netstrm.SetDrvrPermPeers(pData->pNetstrm, pData->pGssPermPeers));
				}
				/* params set, now connect */
				CHKiRet(netstrm.Connect(pData->pNetstrm, glbl.GetDefPFFamily(),
					(uchar*)getFwdPt(pData), (uchar*)pData->f_hname));
			}

			if (out_tok.length != 0) {
				dbgprintf("GSS-API Sending init_sec_context token (length: %ld)\n", (long) out_tok.length);
				netstrm.GetSock(pData->pNetstrm, &s);
				if (gssutil.send_token(s, &out_tok) < 0) {
					ABORT_FINALIZE(RS_RET_ERR);
				}
			}
			gss_release_buffer(&min_stat, &out_tok);

			if (maj_stat == GSS_S_CONTINUE_NEEDED) {
				dbgprintf("GSS-API Continue needed...\n");
				if (gssutil.recv_token(s, &in_tok) <= 0) {
					ABORT_FINALIZE(RS_RET_ERR);
				}

				tok_ptr = &in_tok;
			}
		} while (maj_stat == GSS_S_CONTINUE_NEEDED);

		dbgprintf("GSS-API Provided context flags:\n");
		*sess_flags = ret_flags;
		gssutil.display_ctx_flags(*sess_flags);
	
		dbgprintf("GSS-API Context initialized\n");
		gss_release_name(&min_stat, &target_name);
	}


finalize_it:
	if(iRet != RS_RET_OK) {
		errmsg.LogError(0, RS_RET_GSS_SENDINIT_ERROR, "GSS-API Context initialization failed\n");
		gss_release_name(&min_stat, &target_name);
		gss_release_buffer(&min_stat, &out_tok);
		if (*context != GSS_C_NO_CONTEXT) {
			gss_delete_sec_context(&min_stat, context, GSS_C_NO_BUFFER);
			*context = GSS_C_NO_CONTEXT;
		}
		DestructTCPInstanceData(pData);
	}
	RETiRet;
}


/* try to resume connection if it is not ready
 * rgerhards, 2007-08-02
 */
static rsRetVal doTryResume(instanceData *pData)
{
	DEFiRet;

	if(pData->bIsConnected)
		FINALIZE;

	/* The remote address is not yet known and needs to be obtained */
	dbgprintf(" %s\n", pData->f_hname);
	CHKiRet(TCPSendGSSInit((void*)pData));

finalize_it:
	if(iRet != RS_RET_OK) {
		if(pData->f_addr != NULL) {
			freeaddrinfo(pData->f_addr);
			pData->f_addr = NULL;
		}
		iRet = RS_RET_SUSPENDED;
	}

	RETiRet;
}


BEGINtryResume
CODESTARTtryResume
	iRet = doTryResume(pData);
ENDtryResume

BEGINdoAction
	char *psz = NULL; /* temporary buffering */
	register unsigned l;
	int iMaxLine;
CODESTARTdoAction
	CHKiRet(doTryResume(pData));

	iMaxLine = glbl.GetMaxLine();
	dbgprintf(" gssapi %s:%s\n", pData->f_hname, getFwdPt(pData));

	psz = (char*) ppString[0];
	l = strlen((char*) psz);
	if((int) l > iMaxLine)
		l = iMaxLine;

#	ifdef	USE_NETZIP
	/* Check if we should compress and, if so, do it. We also
	 * check if the message is large enough to justify compression.
	 * The smaller the message, the less likely is a gain in compression.
	 * To save CPU cycles, we do not try to compress very small messages.
	 * What "very small" means needs to be configured. Currently, it is
	 * hard-coded but this may be changed to a config parameter.
	 * rgerhards, 2006-11-30
	 */
	if(pData->compressionLevel && (l > CONF_MIN_SIZE_FOR_COMPRESS)) {
		Bytef *out;
		uLongf destLen = iMaxLine + iMaxLine/100 +12; /* recommended value from zlib doc */
		uLong srcLen = l;
		int ret;
		/* TODO: optimize malloc sequence? -- rgerhards, 2008-09-02 */
		CHKmalloc(out = (Bytef*) MALLOC(destLen));
		out[0] = 'z';
		out[1] = '\0';
		ret = compress2((Bytef*) out+1, &destLen, (Bytef*) psz,
				srcLen, pData->compressionLevel);
		dbgprintf("Compressing message, length was %d now %d, return state  %d.\n",
			l, (int) destLen, ret);
		if(ret != Z_OK) {
			/* if we fail, we complain, but only in debug mode
			 * Otherwise, we are silent. In any case, we ignore the
			 * failed compression and just sent the uncompressed
			 * data, which is still valid. So this is probably the
			 * best course of action.
			 * rgerhards, 2006-11-30
			 */
			dbgprintf("Compression failed, sending uncompressed message\n");
			free(out);
		} else if(destLen+1 < l) {
			/* only use compression if there is a gain in using it! */
			dbgprintf("there is gain in compression, so we do it\n");
			psz = (char*) out;
			l = destLen + 1; /* take care for the "z" at message start! */
		} else {
			free(out);
		}
		++destLen;
	}
#	endif

	/* forward via TCP */
	rsRetVal ret;
	ret = tcpclt.Send(pData->pTCPClt, pData, psz, l);
	if(ret != RS_RET_OK) {
		/* error! */
		dbgprintf("error forwarding via GSS, suspending\n");
		DestructTCPInstanceData(pData);
		iRet = RS_RET_SUSPENDED;
	}

finalize_it:
#	ifdef USE_NETZIP
	if((psz != NULL) && (psz != (char*) ppString[0]))  {
		/* we need to free temporary buffer, alloced above - Naoya Nakazawa, 2010-01-11 */
		free(psz);
	}
#	endif
ENDdoAction


/* This function loads TCP support, if not already loaded. It will be called
 * during config processing. To server ressources, TCP support will only
 * be loaded if it actually is used. -- rgerhard, 2008-04-17
 */
static rsRetVal
loadTCPSupport(void)
{
	DEFiRet;
	CHKiRet(objUse(netstrms, LM_NETSTRMS_FILENAME));
	CHKiRet(objUse(netstrm, LM_NETSTRMS_FILENAME));
	CHKiRet(objUse(tcpclt, LM_TCPCLT_FILENAME));

finalize_it:
	RETiRet;
}


BEGINparseSelectorAct
	uchar *q;
	int i;
	rsRetVal localRet;
        struct addrinfo;
	TCPFRAMINGMODE tcp_framing = TCP_FRAMING_OCTET_STUFFING;
CODESTARTparseSelectorAct
CODE_STD_STRING_REQUESTparseSelectorAct(1)
	if(!strncmp((char*) p, ":omgssapi:", sizeof(":omgssapi:") - 1)) {
		p += sizeof(":omgssapi:") - 1; /* eat indicator sequence (-1 because of '\0'!) */

		CHKiRet(createInstance(&pData));
	
		localRet = loadTCPSupport();
		if(localRet != RS_RET_OK) {
			errmsg.LogError(0, localRet, "could not activate network stream modules for GSS "
					"(internal error %d) - are modules missing?", localRet);
			ABORT_FINALIZE(localRet);
		}
	} else {
		ABORT_FINALIZE(RS_RET_CONFLINE_UNPROCESSED);
	}

	/* we are now after the protocol indicator. Now check if we should
	 * use compression. We begin to use a new option format for this:
	 * @(option,option)host:port
	 * The first option defined is "z[0..9]" where the digit indicates
	 * the compression level. If it is not given, 9 (best compression) is
	 * assumed. An example action statement might be:
	 * @@(z5,o)127.0.0.1:1400  
	 * Which means send via TCP with medium (5) compresion (z) to the local
	 * host on port 1400. The '0' option means that octet-couting (as in
	 * IETF I-D syslog-transport-tls) is to be used for framing (this option
	 * applies to TCP-based syslog only and is ignored when specified with UDP).
	 * That is not yet implemented.
	 * rgerhards, 2006-12-07
	 * In order to support IPv6 addresses, we must introduce an extension to
	 * the hostname. If it is in square brackets, whatever is in them is treated as
	 * the hostname - without any exceptions ;) -- rgerhards, 2008-08-05
	 */
	if(*p == '(') {
		/* at this position, it *must* be an option indicator */
		do {
			++p; /* eat '(' or ',' (depending on when called) */
			/* check options */
			if(*p == 'z') { /* compression */
#				ifdef USE_NETZIP
				++p; /* eat */
				if(isdigit((int) *p)) {
					int iLevel;
					iLevel = *p - '0';
					++p; /* eat */
					pData->compressionLevel = iLevel;
				} else {
					errmsg.LogError(0, NO_ERRCODE, "Invalid compression level '%c' specified in "
						 "forwardig action - NOT turning on compression.",
						 *p);
				}
#				else
				errmsg.LogError(0, NO_ERRCODE, "Compression requested, but rsyslogd is not compiled "
					 "with compression support - request ignored.");
#				endif /* #ifdef USE_NETZIP */
			} else if(*p == 'o') { /* octet-couting based TCP framing? */
				++p; /* eat */
				/* no further options settable */
				tcp_framing = TCP_FRAMING_OCTET_COUNTING;
			} else { /* invalid option! Just skip it... */
				errmsg.LogError(0, NO_ERRCODE, "Invalid option %c in forwarding action - ignoring.", *p);
				++p; /* eat invalid option */
			}
			/* the option processing is done. We now do a generic skip
			 * to either the next option or the end of the option
			 * block.
			 */
			while(*p && *p != ')' && *p != ',')
				++p;	/* just skip it */
		} while(*p && *p == ','); /* Attention: do.. while() */
		if(*p == ')')
			++p; /* eat terminator, on to next */
		else
			/* we probably have end of string - leave it for the rest
			 * of the code to handle it (but warn the user)
			 */
			errmsg.LogError(0, NO_ERRCODE, "Option block not terminated in GSS forwarding action.");
	}

	/* extract the host first (we do a trick - we replace the ';' or ':' with a '\0')
	 * now skip to port and then template name. rgerhards 2005-07-06
	 */
	if(*p == '[') { /* everything is hostname upto ']' */
		++p; /* skip '[' */
		for(q = p ; *p && *p != ']' ; ++p)
			/* JUST SKIP */;
		if(*p == ']') {
			*p = '\0'; /* trick to obtain hostname (later)! */
			++p; /* eat it */
		}
	} else { /* traditional view of hostname */
		for(q = p ; *p && *p != ';' && *p != ':' && *p != '#' ; ++p)
			/* JUST SKIP */;
	}

	pData->port = NULL;
	if(*p == ':') { /* process port */
		uchar * tmp;

		*p = '\0'; /* trick to obtain hostname (later)! */
		tmp = ++p;
		for(i=0 ; *p && isdigit((int) *p) ; ++p, ++i)
			/* SKIP AND COUNT */;
		pData->port = MALLOC(i + 1);
		if(pData->port == NULL) {
			errmsg.LogError(0, NO_ERRCODE, "Could not get memory to store syslog forwarding port, "
				 "using default port, results may not be what you intend\n");
			/* we leave f_forw.port set to NULL, this is then handled by getFwdPt(). */
		} else {
			memcpy(pData->port, tmp, i);
			*(pData->port + i) = '\0';
		}
	}
	
	/* now skip to template */
	while(*p && *p != ';'  && *p != '#' && !isspace((int) *p))
		++p; /*JUST SKIP*/

	/* TODO: make this if go away! */
	if(*p == ';' || *p == '#' || isspace(*p)) {
		uchar cTmp = *p;
		*p = '\0'; /* trick to obtain hostname (later)! */
		CHKmalloc(pData->f_hname = strdup((char*) q));
		*p = cTmp;
	} else {
		CHKmalloc(pData->f_hname = strdup((char*) q));
	}

	/* copy over config data as needed */
	pData->iGSSRebindInterval = iGSSRebindInterval;

	/* process template */
	CHKiRet(cflineParseTemplateName(&p, *ppOMSR, 0, OMSR_NO_RQD_TPL_OPTS,
		(pszTplName == NULL) ? (uchar*)"RSYSLOG_TraditionalForwardFormat" : pszTplName));

	/* create our tcpclt */
	CHKiRet(tcpclt.Construct(&pData->pTCPClt));
	CHKiRet(tcpclt.SetResendLastOnRecon(pData->pTCPClt, bGssResendLastOnRecon));
	/* and set callbacks */
	CHKiRet(tcpclt.SetSendInit(pData->pTCPClt, TCPSendGSSInit));
	CHKiRet(tcpclt.SetSendFrame(pData->pTCPClt, TCPSendGSSFrame));
	CHKiRet(tcpclt.SetSendPrepRetry(pData->pTCPClt, TCPSendGSSPrepRetry));
	CHKiRet(tcpclt.SetFraming(pData->pTCPClt, tcp_framing));
	CHKiRet(tcpclt.SetRebindInterval(pData->pTCPClt, pData->iGSSRebindInterval));
	pData->iGssStrmDrvrMode = iGssStrmDrvrMode;
	if(pszGssStrmDrvr != NULL)
		CHKmalloc(pData->pszGssStrmDrvr = (uchar*)strdup((char*)pszGssStrmDrvr));
	if(pszGssStrmDrvrAuthMode != NULL)
		CHKmalloc(pData->pszGssStrmDrvrAuthMode =
			     (uchar*)strdup((char*)pszGssStrmDrvrAuthMode));
	if(pGssPermPeers != NULL) {
		pData->pGssPermPeers = pGssPermPeers;
		pGssPermPeers = NULL;
	}

CODE_STD_FINALIZERparseSelectorAct
ENDparseSelectorAct


/* a common function to free our configuration variables - used both on exit
 * and on $ResetConfig processing. -- rgerhards, 2008-05-16
 */
static void
freeConfigVars(void)
{
	free(pszTplName);
	pszTplName = NULL;
	free(pszGssStrmDrvr);
	pszGssStrmDrvr = NULL;
	free(pszGssStrmDrvrAuthMode);
	pszGssStrmDrvrAuthMode = NULL;
	free(pGssPermPeers);
	pGssPermPeers = NULL;
}


BEGINmodExit
CODESTARTmodExit
	/* release what we no longer need */
	objRelease(errmsg, CORE_COMPONENT);
	objRelease(glbl, CORE_COMPONENT);
	objRelease(net, LM_NET_FILENAME);
	objRelease(netstrm, LM_NETSTRMS_FILENAME);
	objRelease(netstrms, LM_NETSTRMS_FILENAME);
	objRelease(tcpclt, LM_TCPCLT_FILENAME);
	objRelease(gssutil, LM_GSSUTIL_FILENAME);

	freeConfigVars();
ENDmodExit


BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_OMOD_QUERIES
ENDqueryEtryPt


/* Reset config variables for this module to default values.
 * rgerhards, 2008-03-28
 */
static rsRetVal resetConfigVariables(uchar __attribute__((unused)) *pp, void __attribute__((unused)) *pVal)
{
	freeConfigVars();

	/* we now must reset all non-string values */
	iGssStrmDrvrMode = 0;
	bGssResendLastOnRecon = 0;
	iGSSRebindInterval = 0;

	gss_mode = GSSMODE_ENC;
	if (gss_base_service_name != NULL) {
		free(gss_base_service_name);
		gss_base_service_name = NULL;
	}
	if(pszTplName != NULL) {
		free(pszTplName);
		pszTplName = NULL;
	}

	return RS_RET_OK;
}

/* set a new GSSMODE based on config directive */
static rsRetVal setGSSMode(void __attribute__((unused)) *pVal, uchar *mode)
{
	DEFiRet;

	if (!strcmp((char *) mode, "integrity")) {
		gss_mode = GSSMODE_MIC;
		dbgprintf("GSS-API gssmode set to GSSMODE_MIC\n");
	} else if (!strcmp((char *) mode, "encryption")) {
		gss_mode = GSSMODE_ENC;
		dbgprintf("GSS-API gssmode set to GSSMODE_ENC\n");
	} else {
		errmsg.LogError(0, RS_RET_INVALID_PARAMS, "unknown gssmode parameter: %s", (char *) mode);
		iRet = RS_RET_INVALID_PARAMS;
	}
	free(mode);

	RETiRet;
}

BEGINmodInit()
CODESTARTmodInit
	*ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */
CODEmodInit_QueryRegCFSLineHdlr
	CHKiRet(objUse(errmsg, CORE_COMPONENT));
	CHKiRet(objUse(glbl, CORE_COMPONENT));
	CHKiRet(objUse(net, LM_NET_FILENAME));
	CHKiRet(objUse(netstrm, LM_NETSTRMS_FILENAME));
	CHKiRet(objUse(netstrms, LM_NETSTRMS_FILENAME));
	CHKiRet(objUse(gssutil, LM_GSSUTIL_FILENAME));
	CHKiRet(objUse(tcpclt, LM_TCPCLT_FILENAME));

	CHKiRet(omsdRegCFSLineHdlr((uchar *)"actiongsssendtcprebindinterval", 0, eCmdHdlrInt, NULL, &iGSSRebindInterval, STD_LOADABLE_MODULE_ID));
	CHKiRet(omsdRegCFSLineHdlr((uchar *)"actiongsssendstreamdriver", 0, eCmdHdlrGetWord, NULL, &pszGssStrmDrvr, STD_LOADABLE_MODULE_ID));
	CHKiRet(omsdRegCFSLineHdlr((uchar *)"actiongsssendstreamdrivermode", 0, eCmdHdlrInt, NULL, &iGssStrmDrvrMode, STD_LOADABLE_MODULE_ID));
	CHKiRet(omsdRegCFSLineHdlr((uchar *)"actiongsssendstreamdriverauthmode", 0, eCmdHdlrGetWord, NULL, &pszGssStrmDrvrAuthMode, STD_LOADABLE_MODULE_ID));
	CHKiRet(omsdRegCFSLineHdlr((uchar *)"actiongsssendstreamdriverpermittedpeer", 0, eCmdHdlrGetWord, setPermittedPeer, NULL, STD_LOADABLE_MODULE_ID));
	CHKiRet(omsdRegCFSLineHdlr((uchar *)"actiongsssendresendlastmsgonreconnect", 0, eCmdHdlrBinary, NULL, &bGssResendLastOnRecon, STD_LOADABLE_MODULE_ID));

	CHKiRet(omsdRegCFSLineHdlr((uchar *)"gssforwardservicename", 0, eCmdHdlrGetWord, NULL, &gss_base_service_name, STD_LOADABLE_MODULE_ID));
	CHKiRet(omsdRegCFSLineHdlr((uchar *)"gssmode", 0, eCmdHdlrGetWord, setGSSMode, &gss_mode, STD_LOADABLE_MODULE_ID));
	CHKiRet(omsdRegCFSLineHdlr((uchar *)"actiongssforwarddefaulttemplate", 0, eCmdHdlrGetWord, NULL, &pszTplName, STD_LOADABLE_MODULE_ID));
	CHKiRet(omsdRegCFSLineHdlr((uchar *)"resetconfigvariables", 1, eCmdHdlrCustomHandler, resetConfigVariables, NULL, STD_LOADABLE_MODULE_ID));
ENDmodInit

#endif /* #ifdef USE_GSSAPI */
/* vim:set ai:
 */
