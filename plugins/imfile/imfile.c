/* imfile.c
 * 
 * This is the input module for reading text file data. A text file is a
 * non-binary file who's lines are delemited by the \n character.
 *
 * Work originally begun on 2008-02-01 by Rainer Gerhards
 *
 * Copyright 2008-2011 Rainer Gerhards, Adiscon GmbH and Nikolaidis Fotis.
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
#include "config.h" /* this is for autotools and always must be the first include */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/inotify.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>		/* do NOT remove: will soon be done by the module generation macros */
#ifdef HAVE_SYS_STAT_H
#	include <sys/stat.h>
#endif
#include "rsyslog.h"		/* error codes etc... */
#include "dirty.h"
#include "cfsysline.h"		/* access to config file objects */
#include "module-template.h"	/* generic module interface code - very important, read it! */
#include "srUtils.h"		/* some utility functions */
#include "msg.h"
#include "stream.h"
#include "errmsg.h"
#include "glbl.h"
#include "datetime.h"
#include "unicode-helper.h"
#include "prop.h"
#include <dirent.h>
#include "stringbuf.h"
#include "ruleset.h"
#include "signal.h"


/*  Dynamic naming : 
 *  If in the monitoring list we have a directory, we load all the files in this directory.
 *  For the loading, we are trying to load any previously saved state
 *  Files that are dynamically generated, have their normal filenames bu the state file is
 *  named as directory-file-state
 * */

/* TO BE FIXED : 
 * On Polling everything end to dumpDir */

/***************************************************
 *                  GLOBAL DEFINITIONS             *
 **************************************************/

/****************
 Module specific
****************/
MODULE_TYPE_INPUT	/* must be present for input modules, do not remove */
MODULE_TYPE_NOKEEP

/* defines */

/* Module static data */
DEF_IMOD_STATIC_DATA	/* must be present, starts static data */
DEFobjCurrIf(errmsg)
DEFobjCurrIf(glbl)
DEFobjCurrIf(datetime)
DEFobjCurrIf(strm)
DEFobjCurrIf(prop)
DEFobjCurrIf(ruleset)


/****************
    Functions
****************/ 

     void get_event ( void );
     void handle_error (char* msg);


#define checkValid( FILENAME , ERRORMSG )			\
  if  ( FILENAME == NULL )  {					\
    errmsg.LogError(0, RS_RET_CONFIG_ERROR, ERRORMSG);	\
    ABORT_FINALIZE(RS_RET_CONFIG_ERROR);		\
  }


// This is used for naming the child based on parent's info
#define inheritParent(CHILD,PARENT,NAME)  			\
sprintf ( (char*) CHILD->fileName, "%s/%s", PARENT->fileName , NAME ) ; \
sprintf ( (char*) CHILD->stateFile, "%s-%s", PARENT->stateFile, NAME  ) ; \
sprintf ( (char*) CHILD->stateFileName, "%s-%s", PARENT->stateFileName, NAME  ) ; \
strcpy( (char *) CHILD->fileTag , (char *) PARENT->fileTag );				\
CHILD->facility = PARENT->facility ;	     				\
CHILD->severity = PARENT->severity ;  					\
CHILD->pollInterval = PARENT->pollInterval ;  					\
CHILD->nRecords = PARENT->nRecords ;  					\
CHILD->readMode = PARENT->readMode ;  					\
CHILD->pRuleset = PARENT->pRuleset ;  					\


 /****************
       Variables
 ****************/
     static prop_t *pInputName = NULL;	/* there is only one global inputName for all messages generated by this input */
     int INOTIFY_DESC; // Inotify watch descriptor

     //  Here are included all the necessary field that describe a file that is needed to be monitored
     typedef struct  fileInfo_s
     {
       	char* fileName;                // The name of the file. Path is included
       	char* fileTag;                   // The tag
       	uint lenTag;                       //  Tag length (Is used to avoid injection)
       	char* stateFileName;                // Keep only the fileName given in configuration
		char* stateFile; 			// Combine with Working Directory
       	int facility;
		int severity;
       	int isDir ;
	   	int pollInterval;
		int nRecords; /**< How many records did we process before persisting the stream? */
		int iPersistStateInterval; /**< how often should state be persisted? (0=on close only) */
		int readMode;	/* which mode to use in ReadMulteLine call? */
		ruleset_t *pRuleset;	/* ruleset to bind listener to (use system default if unspecified) */
   
       strm_t *pStrm;       // its stream (NULL if not assigned )
     } fileInfo;

// GLOBAL DEFINITIONS
static fileInfo * COMMITFILE;
fileInfo **DESCRIPTORS; // Dynamic table for every file Descriptor
int DESC_ELEMS;
static linkedList_t FILE_LIST;
int ACTIVE_INOTIFY;

/***************************************************
 *                       UTILITIES                                               *
 **************************************************/


void handle_error (char* msg)
{
  perror ( msg ); 
  return;
}  /* handle_error */


/* If the argument is NULL, a new file struct is returned. Otherwise
 * we copy the old data to a new struct */
fileInfo* getFileStruct ( fileInfo *oldFile  ) {

  	fileInfo* newFile = (fileInfo*) malloc(sizeof (struct fileInfo_s) );

	if ( oldFile ) 
	{
	 	newFile->lenTag = oldFile->lenTag;
	  	newFile->isDir = oldFile->isDir;
	  	newFile->facility = oldFile->facility;
  		newFile->severity = oldFile->severity;
	   	newFile->pollInterval = oldFile->pollInterval;
	  	newFile->pStrm = oldFile->pStrm;
 		newFile->fileTag = strdup ( oldFile->fileTag );
	 	newFile->fileName = strdup (oldFile->fileName);
 		newFile->stateFileName = strdup (oldFile->stateFileName);
	 	newFile->stateFile = strdup (oldFile->stateFile);
		newFile->nRecords = oldFile->nRecords;
		newFile->iPersistStateInterval = oldFile->iPersistStateInterval;
		newFile->readMode = oldFile->readMode;
		newFile->pRuleset = oldFile->pRuleset;
	}
	else 
	{
  		newFile->lenTag = 0;
	  	newFile->isDir = 0;
  		newFile->facility = 128; // local0
	  	newFile->severity = 5;   // notice, as of rfc 3164
	   	newFile->pollInterval = 10;   // default polling time is 10s
	  	newFile->pStrm = (strm_t *) malloc( sizeof(strm_t ) ); 
	 	newFile->fileTag = (char *) malloc(1024);
 		newFile->fileName = (char*) malloc(1024);
	 	newFile->stateFileName = (char*) malloc(1024); 
	 	newFile->stateFile = (char *) malloc(1024 );
		newFile->nRecords = 0;
		newFile->iPersistStateInterval = 0;
		newFile->readMode = 0;
		newFile->pRuleset = NULL;
	}

return newFile;
}
// Define how to destroy a file object
static rsRetVal destroyFile ( fileInfo *pThis ) { 
DEFiRet;

	assert ( pThis );
	if ( pThis->fileTag ) 
		free ( pThis->fileTag );
	if ( pThis->fileName  ) 
		free ( pThis->fileName );
	if ( pThis->stateFile  ) 
		free ( pThis->stateFile );
	if ( pThis->pStrm ) 
		free ( pThis->pStrm );
	
	free ( pThis );
RETiRet;
}

void printFileStruct ( fileInfo *file) {

  assert(file);

  fprintf( stderr,  "FileName : %s , Tag : %s , Status : %s , Severity : %d, Facility :%d , pollinterval : %d \n"  ,
	file->fileName , file->fileTag, file->stateFile, file->severity, file->facility , file->pollInterval);

  dbgprintf(  "FileName : %s , Tag : %s , Status : %s , Severity : %d, Facility :%d , pollinterval : %d \n"  ,
	  file->fileName , file->fileTag, file->stateFile, file->severity, file->facility , file->pollInterval);

}


/* accept a new ruleset to bind. Checks if it exists and complains, if not */
static rsRetVal
setRuleset(void __attribute__((unused)) *pVal, uchar *pszName)
{
	ruleset_t *pRuleset;
	rsRetVal localRet;
	DEFiRet;

	localRet = ruleset.GetRuleset(&pRuleset, pszName);
	if(localRet == RS_RET_NOT_FOUND) {
		errmsg.LogError(0, NO_ERRCODE, "error: ruleset '%s' not found - ignored", pszName);
	}
	CHKiRet(localRet);
	DBGPRINTF("imfile current bind ruleset %p: '%s'\n", pRuleset, pszName);

finalize_it:
	free(pszName); /* no longer needed */
	RETiRet;
}


static rsRetVal openFile( fileInfo *pThis)
{
	DEFiRet;
	strm_t *psSF = NULL;
	struct stat stat_buf;

	fprintf(stderr, "Opening : %s\n", pThis->stateFile );
	/* check if the file exists */
	if(stat((char*) pThis->stateFile, &stat_buf) == -1) {
		if(errno == ENOENT) {
			/* currently no object! dbgoprint((obj_t*) pThis, "clean startup, no .si file found\n"); */
			ABORT_FINALIZE(RS_RET_FILE_NOT_FOUND);
		} else {
			/* currently no object! dbgoprint((obj_t*) pThis, "error %d trying to access .si file\n", errno); */
			ABORT_FINALIZE(RS_RET_IO_ERROR);
		}
	}

	/* If we reach this point, we have a .si file */

	CHKiRet( strm.Construct( &psSF ) );
	CHKiRet( strm.SettOperationsMode(psSF, STREAMMODE_READ) );
	CHKiRet( strm.SetsType(psSF, STREAMTYPE_FILE_SINGLE) );
	CHKiRet( strm.SetFName(psSF, (uchar *) pThis->stateFile , strlen(pThis->stateFile)  ));
	CHKiRet( strm.ConstructFinalize(psSF) );

	/* read back in the object */
	CHKiRet(obj.Deserialize(&pThis->pStrm, (uchar*) "strm", psSF, NULL, pThis));

	CHKiRet(strm.SeekCurrOffs(pThis->pStrm));

	psSF->bDeleteOnClose = 1;
	fprintf(stderr, "\tStream successfully restored\n");
	/* note: we do not delete the state file, so that the last position remains
	 * known even in the case that rsyslogd aborts for some reason (like powerfail)
	 */

finalize_it:
	if(iRet != RS_RET_OK) {

		CHKiRet(strm.Construct(&pThis->pStrm));
		CHKiRet(strm.SettOperationsMode(pThis->pStrm, STREAMMODE_READ));
		CHKiRet(strm.SetsType(pThis->pStrm, STREAMTYPE_FILE_MONITOR));
		CHKiRet(strm.SetFName(pThis->pStrm, (uchar *)pThis->fileName, strlen((char*) pThis->fileName)));
		CHKiRet(strm.ConstructFinalize(pThis->pStrm));

		fprintf(stderr, "\tUnable to restore.Opening new stream : %s\n" , pThis->stateFile);
	}
	

	CHKiRet(persistStrmState ( pThis ) ) ;
	if(psSF != NULL)
		strm.Destruct(&psSF);

RETiRet;
}


/* enqueue the read file line as a message. The provided string is
 * not freed - thuis must be done by the caller.
 */
static rsRetVal enqLine(fileInfo *pInfo, cstr_t *cstrLine)
{
  DEFiRet;
  msg_t *pMsg;

  if(rsCStrLen(cstrLine) == 0) 
    {
      /* we do not process empty lines */
      FINALIZE;
    }

  CHKiRet(msgConstruct( &pMsg));
  MsgSetFlowControlType( pMsg ,  eFLOWCTL_FULL_DELAY);
  MsgSetInputName( pMsg ,  pInputName);
  MsgSetRawMsg( pMsg , (char*)rsCStrGetSzStr(cstrLine) , cstrLen( cstrLine ) );
  MsgSetMSGoffs( pMsg , 0);	/* we do not have a header... */
  MsgSetHOSTNAME( pMsg, glbl.GetLocalHostName(), ustrlen(glbl.GetLocalHostName())) ;
  MsgSetTAG( pMsg, (uchar *) pInfo->fileTag ,pInfo->lenTag );
  pMsg->iFacility = LOG_FAC( pInfo->facility );
  pMsg->iSeverity = LOG_PRI( pInfo->severity );
  CHKiRet(submitMsg( pMsg ) );

 finalize_it:
  RETiRet;
}

/***************************************************
 *                       INOTIFY functions                                  *
 **************************************************/


rsRetVal registerTarget ( char* target) 
{

  DEFiRet;
  int wd;

  wd = inotify_add_watch ( INOTIFY_DESC , target, IN_ALL_EVENTS);
  if ( wd  < 0) {
    handle_error ( "Could not add file to inotify\n" );
    return RS_RET_IO_ERROR;
  }

  dbgprintf(  " (inotify desc :  %d  )\n", wd);
  RETiRet;
}



/* This function persists information for a specific file being monitored.
 * To do so, it simply persists the stream object. We do NOT abort on error
 * iRet as that makes matters worse (at least we can try persisting the others...).
 * rgerhards, 2008-02-13
 */
rsRetVal persistStrmState( fileInfo *pInfo)
{
	DEFiRet;
  	strm_t *psSF = NULL; /* state file (stream) */
  	size_t lenDir;

  	assert(pInfo != NULL && pInfo->pStrm != NULL);

	  /* TODO: create a function persistObj in obj.c? */
  	CHKiRet(strm.Construct(&psSF));
	lenDir = strlen((char*)glbl.GetWorkDir());

	if(lenDir > 0)
    	CHKiRet(strm.SetDir(psSF, glbl.GetWorkDir(), lenDir));
  	CHKiRet(strm.SettOperationsMode(psSF, STREAMMODE_WRITE_TRUNC));
  	CHKiRet(strm.SetsType(psSF, STREAMTYPE_FILE_SINGLE));
  	CHKiRet(strm.SetFName(psSF, (uchar *) pInfo->stateFileName, strlen((char*) pInfo->stateFileName)));
  	CHKiRet(strm.ConstructFinalize(psSF));

  	CHKiRet(strm.Serialize(pInfo->pStrm, psSF));

  	CHKiRet(strm.Destruct(&psSF));

finalize_it:

	if ( iRet != RS_RET_OK ) {
		perror("");
	}

	if(psSF != NULL)
    	strm.Destruct(&psSF);
}



static void pollFileCancelCleanup(void *pArg)
 {
	 BEGINfunc;

	 fprintf(stderr, "Cleaning up Threads ...\n");
	 cstr_t **ppCStr = (cstr_t**) pArg;
	 if(*ppCStr != NULL)
		 rsCStrDestruct(ppCStr);
	 ENDfunc;
 }

//#pragma GCC diagnostic ignored "-Wempty-body"
static rsRetVal readData ( fileInfo *pThis )
{
  DEFiRet;

  	cstr_t *strBuf = NULL; // String buffer object
  /* loop until strmReadLine() returns EOF. Every line is saved it to strBuf and after enqueuing free the buffer */
  while ( 1 ) {
    CHKiRet(strm.ReadLine(pThis->pStrm, &strBuf , pThis->readMode) );
    CHKiRet(enqLine( pThis, strBuf )); 
    rsCStrDestruct( &strBuf  ); 
  }


 finalize_it:
 
	if(strBuf != NULL) {
		rsCStrDestruct(&strBuf);
	}
}


/* Allow for 2048 simultanious events */
#define MAX_EVENTS  2048 
static rsRetVal inotifyTakesOver (  void ) {

  DEFiRet;
  
  ssize_t len, i = 0; 
  u_char eventList[ MAX_EVENTS ] = {0}; 
  struct inotify_event *pevent;

  //TODO : add support for excluded files
  while ( 1 )
    {
      	i = 0;
      	len = read (INOTIFY_DESC , eventList , MAX_EVENTS); // get events in eventlist
      	if ( len < 0 ) {
			handle_error ( "Inotify stopped.\n");
       		RETiRet;
	   	}
      	if ( len > MAX_EVENTS ) 
			handle_error ( "Must be recompiled with higher MAX_EVENTS \n" );
       
		/* Iterate events */
		for ( i = 0; i < len ; i  += sizeof(struct inotify_event) + pevent->len ) 
		{
		/* FIXME : na dior8wsw thn katastash me ta threads edw */
		  pthread_t curThread;
		  pevent = (struct inotify_event *) & eventList[ i ];
    
		  switch  ( pevent->mask )  {

		  case IN_MODIFY : 
			if ( DESCRIPTORS [pevent->wd - 1]  ->isDir  ) // If it's dir , just skip it
	  			break;
		
		    pthread_create( &curThread, NULL, (void *) readData ,  DESCRIPTORS[ pevent->wd -1 ]);	    

			break;

		  case IN_CREATE :

			// FIXME : For The moment every time that a file is appended we have to reallocate the table.
		    // Something better must be added here
		    DESCRIPTORS = (fileInfo **) realloc ( DESCRIPTORS,   DESC_ELEMS * sizeof ( struct fileInfo_s ));

	    	// Inheriting parent's facility, severity and generating unique fileName , statefile (Combination of file and path )
		    fileInfo *newFile = getFileStruct ( NULL );

		    inheritParent ( newFile, DESCRIPTORS [ pevent->wd - 1] , pevent->name );
			// FIXME : use addToWatchList instead of these
	    	registerTarget ( (char *) newFile->fileName );

		    DESCRIPTORS [ DESC_ELEMS ] = newFile;
		    CHKiRet ( openFile ( DESCRIPTORS [ DESC_ELEMS  ]  ) );
	    	DESC_ELEMS++;
		    continue;
		  } // Switch
		}// For
    } // While

finalize_it :

	// TODO : Maybe some error cases ?
	RETiRet;  

}//  inotifyTakesOver 


static rsRetVal pollFile ( fileInfo *pThis ) 
{
	DEFiRet;

	fprintf(stderr, "Polling file %s  ( %s ) every :%d seconds\n", pThis->fileName, pThis->stateFile, pThis->pollInterval);

	if(pThis->pStrm == NULL) {
		CHKiRet(openFile(pThis)); /* open file */
	}

	while (    glbl.GetGlobalInputTermState() == 0 ) {
	
		if ( glbl.GetGlobalInputTermState() == 1 )
			break;

			srSleep( pThis->pollInterval, 10);

		readData ( pThis );
	}

RETiRet;
finalize_it :

	fprintf(stderr, "PollFile : %s Terminated \n", pThis->fileName );
}

/***************************************************
 *    Actual Runtime Functions                     *
 **************************************************/


/* The function is called by rsyslog before runInput() is called. It is a last chance
 * to set up anything specific. Most importantly, it can be used to tell rsyslog if the
 * input shall run or not. The idea is that if some config settings (or similiar things)
 * are not OK, the input can tell rsyslog it will not execute. To do so, return
 * RS_RET_NO_RUN or a specific error code. If RS_RET_OK is returned, rsyslog will
 * proceed and uall the runInput() entry point.
 */
BEGINwillRun
CODESTARTwillRun

	/* we need to create the inputName property (only once during our lifetime) */
	CHKiRet(prop.Construct(&pInputName));
	CHKiRet(prop.SetString(pInputName, UCHAR_CONSTANT("imfile"), sizeof("imfile") - 1));
	CHKiRet(prop.ConstructFinalize(pInputName));


	int cnt_Elements = 0;
	linkedListCookie_t listPtr = NULL; // Pointer to current node. DON'T RELY ON IT

	llGetNumElts ( &FILE_LIST , &cnt_Elements) ; // Get number of elements
	if( cnt_Elements == 0 ) {
		errmsg.LogError(0, RS_RET_NO_RUN, "No files configured to be monitored");
		ABORT_FINALIZE(RS_RET_NO_RUN);
	}

	/* Here, we keep a table of pointers of every node in the linked list.
	 * It is used for fast searching */
	DESCRIPTORS = (fileInfo **) malloc( cnt_Elements * sizeof ( fileInfo *) );
	DESC_ELEMS = cnt_Elements ;

	int i = 0;
	fprintf(stderr, "\n******** Opening Streams ********\n");
	while ( (iRet =   llGetNextElt ( &FILE_LIST , &listPtr, (void **) &DESCRIPTORS[i] )  == RS_RET_OK) ) 
	{
		fprintf(stderr, "%d : %s ( %s ) (%s) \n", i, DESCRIPTORS[i]->fileName, DESCRIPTORS[i]->stateFile , DESCRIPTORS[i]->stateFileName );
		openFile ( (fileInfo *) DESCRIPTORS[ i ] );
		i++;
	}
	fprintf(stderr, "\n*******************************\n");
finalize_it:
	/* If something is wrong, free the resources and terminate */
   if(iRet != RS_RET_OK) {
   		fprintf(stderr, "Destroying list ....\n");
   		llDestroy ( &FILE_LIST );
	}
	RETiRet;
ENDwillRun


BEGINrunInput
CODESTARTrunInput

	//pthread_cleanup_push ( inputModuleleCleanup, NULL );

	if ( ACTIVE_INOTIFY ) 
	{
		fprintf(stderr, "Using Inotify\n");
  		inotifyTakesOver (   );
	}
	else
	{
		fprintf(stderr, "Fall back to Polling\n");
		dbgprintf("Falling back to Polling\n");
		int i = 0;
		cstr_t * pCStr = NULL;

		pthread_t thread_id[300];
        /* Note: we must do pthread_cleanup_push() immediately, because the POXIS macros
         * otherwise do not work if I include the _cleanup_pop() inside an if... -- rgerhards, 2008-08-14
         */

	    for ( i = 0;  i < DESC_ELEMS  ; i ++ ) 
		{
	  		pthread_create( &thread_id[i], NULL, (void *) pollFile , DESCRIPTORS [ i ] ); 
		}

		for ( i =0; i < DESC_ELEMS; i++ ) 
		{
			pthread_join ( thread_id[i] , NULL ) ;
		}

	}


fprintf(stderr, "Exit RunInput...\n");
RETiRet;
ENDrunInput


/* This function is called by the framework after runInput() has been terminated. It
 * shall free any resources and prepare the module for unload.
 */
BEGINafterRun
int i;
CODESTARTafterRun
	/* Close files and persist file state information. We do NOT abort on error iRet as that makes */
	/* matters worse (at least we can try persisting the others...). Please note that, under stress */
	/* conditions, it may happen that we are terminated before we actuall could open all streams. So */
	/* before we change anything, we need to make sure the stream was open. */
	fprintf( stderr, "Releasing resources\n");
	for(i = 0 ; i < DESC_ELEMS ; i++) {
  		if( DESCRIPTORS[i]->pStrm != NULL ) { /* stream open? */
  			fprintf(stderr, "Saving : %s\n " , DESCRIPTORS[i] -> fileName );
  			dbgprintf("Saving : %s\n " , DESCRIPTORS[i] -> fileName );
		    persistStrmState ( DESCRIPTORS[i] );
    		strm.Destruct(  &DESCRIPTORS[i]->pStrm );
		}
		//free ( &DESCRIPTORS[i]->fileName );
 	}

	if(pInputName != NULL)
  		prop.Destruct( &pInputName );
ENDafterRun


/***************************************************
 *   Configuration Parsing  Functions              *
 **************************************************/


/* Check file's type. If it's a directory include every subfile to the monitoring list. 
 * For the moment it works only for files in depth 1.
 * It adds every component that we want to monitor in a linked list.*/
rsRetVal addToWatchList ( fileInfo *file  ) {
	
DEFiRet;

	assert ( file != NULL );
	struct stat stats;

  	if ( stat(  (char *) file->fileName  , &stats) == - 1 ) 
	{
		fprintf(stderr, "Could not open : %s . Ignore it\n", file->fileName );
		ABORT_FINALIZE ( RS_RET_OK );
	}

	if ( ACTIVE_INOTIFY )
		registerTarget ( (char *) file->fileName );  // Add file to inotify watch list

	llAppend ( &FILE_LIST , file->fileName ,  file ); // Append object to the list only if it's a file
	fprintf(stderr, "Added To Watch List Outer : %s ( %s ) (DIR ? : %d ) \n", file->fileName ,  file->stateFile, file->isDir);

	if ( S_ISDIR ( stats.st_mode ) ) {
		DIR *dir;
		struct dirent *ent;
		fileInfo* subFile;
 
		file->isDir = 1;
		dir = opendir ( (const char * ) file->fileName );

		while ((ent = readdir (dir)) != NULL) 
		{

			// Ignoring "." and ".." which are parts of every directory
			if (  !strcmp( ent->d_name , "." ) || !strcmp( ent->d_name, ".." )  )
				continue;

	 		subFile = getFileStruct (NULL);
			inheritParent ( subFile, file , ent->d_name );

			/* 0x8 is the type code for a file */
			if ( ent->d_type != 0x8 ) 
			{
				addToWatchList ( subFile );
				RETiRet;
			}

			if ( ACTIVE_INOTIFY )
				registerTarget ( (char *) subFile->fileName );  // Add file to inotify watch list

			llAppend ( &FILE_LIST , subFile->fileName ,  subFile ); // Append CommitFile to FILE_LIST with entry number as key
			fprintf(stderr, "Added To Watch List : %s ( %s ) ( DIR ? :%d ) \n", subFile->fileName ,  subFile->stateFile, subFile->isDir);
		}
   	}

finalize_it :
	
	if ( iRet != RS_RET_OK ) 
	{ 
		fprintf(stderr,  "Error  occured while reading : %s . Removing from monitoring\n", file->fileName);
		llFindAndDelete ( &FILE_LIST , file->fileName );
	}
	RETiRet;
}


static int addMonitor(void __attribute__((unused)) *pVal, uchar *possibleEntry)
{
	DEFiRet;

  	checkValid ( COMMITFILE->fileName ,  "imfile error: no file name given, file monitor can not be created" );
  	checkValid ( COMMITFILE->fileTag ,  "imfile error: no tag value given, file monitor can not be created" );
  	checkValid ( COMMITFILE->stateFileName ,  "imfile error: no state file given, file monitor can not be created" );


  	//   We need to make a new instance out of Commit File because Commit FIle is used recursively
	sprintf((char*)COMMITFILE->stateFile,  "%s/%s", (char*) glbl.GetWorkDir(), (char*)COMMITFILE->stateFileName);
	fileInfo *toCommit = getFileStruct( COMMITFILE );
	
	if ( ACTIVE_INOTIFY ) 
	{
		registerTarget ( (char* )COMMITFILE->fileName );
	}
	addToWatchList ( toCommit  );


finalize_it:
	;
	// Actually, this is a redundant check
}



/***************************************************
 *                  Module Entry - Exit points     *
 **************************************************/

BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
	if(eFeat == sFEATURENonCancelInputTermination)
		iRet = RS_RET_OK;
ENDisCompatibleWithFeature


/* The following entry points are defined in module-template.h.
 * In general, they need to be present, but you do NOT need to provide
 * any code here.
 */
BEGINmodExit
CODESTARTmodExit
	/* release objects we used */
	objRelease(strm, CORE_COMPONENT);
	objRelease(datetime, CORE_COMPONENT);
	objRelease(glbl, CORE_COMPONENT);
	objRelease(errmsg, CORE_COMPONENT);
	objRelease(prop, CORE_COMPONENT);
	objRelease(ruleset, CORE_COMPONENT);
ENDmodExit


BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_IMOD_QUERIES
CODEqueryEtryPt_IsCompatibleWithFeature_IF_OMOD_QUERIES
ENDqueryEtryPt




BEGINmodInit()
CODESTARTmodInit
  *ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */
	CODEmodInit_QueryRegCFSLineHdlr
	CHKiRet(objUse(errmsg, CORE_COMPONENT));
	CHKiRet(objUse(glbl, CORE_COMPONENT));
	CHKiRet(objUse(datetime, CORE_COMPONENT));
	CHKiRet(objUse(strm, CORE_COMPONENT));
	CHKiRet(objUse(prop, CORE_COMPONENT));
	CHKiRet(objUse(ruleset, CORE_COMPONENT));

	/* Try to start inotify. If it fails, fallback to polling */
	INOTIFY_DESC = inotify_init();
	if ( INOTIFY_DESC < 0) {
		handle_error ( "Could not start inotify. Fall back to polling\n" );
		ACTIVE_INOTIFY = 0; 
	}
	//ACTIVE_INOTIFY = 1;


	/* Various initializations */
	fileInfo* commitFile = getFileStruct( NULL );
	CHKiRet( llInit ( &FILE_LIST , destroyFile , NULL , NULL ) ) ;


/* Gather the info */
	CHKiRet( omsdRegCFSLineHdlr((uchar *)"inputfilename", 0, eCmdHdlrGetWord,
			    NULL,  &commitFile->fileName , STD_LOADABLE_MODULE_ID));

	CHKiRet( omsdRegCFSLineHdlr((uchar *)"inputfiletag", 0, eCmdHdlrGetWord,
			    NULL,  &commitFile->fileTag , STD_LOADABLE_MODULE_ID));

	CHKiRet( omsdRegCFSLineHdlr((uchar *)"inputfilestatefile", 0, eCmdHdlrGetWord,
			    NULL, &commitFile->stateFileName , STD_LOADABLE_MODULE_ID));

	CHKiRet( omsdRegCFSLineHdlr((int *)"inputfileseverity", 0, eCmdHdlrSeverity, 
			    NULL,  &commitFile->severity , STD_LOADABLE_MODULE_ID));

	CHKiRet( omsdRegCFSLineHdlr((uchar *)"inputfilefacility", 0, eCmdHdlrFacility,
			    NULL,   &commitFile->facility , STD_LOADABLE_MODULE_ID));

	CHKiRet( omsdRegCFSLineHdlr((uchar *)"inputfilepollinterval", 0, eCmdHdlrInt, 
			   	NULL, &commitFile->pollInterval, STD_LOADABLE_MODULE_ID));

	CHKiRet(omsdRegCFSLineHdlr((uchar *)"inputfilereadmode", 0, eCmdHdlrInt,
			  	NULL, &commitFile->readMode, STD_LOADABLE_MODULE_ID));
	
	CHKiRet(omsdRegCFSLineHdlr((uchar *)"inputfilepersiststateinterval", 0, eCmdHdlrInt,
			  	NULL, &commitFile->iPersistStateInterval, STD_LOADABLE_MODULE_ID));

	CHKiRet(omsdRegCFSLineHdlr((uchar *)"inputfilebindruleset", 0, eCmdHdlrGetWord,
				setRuleset, NULL, STD_LOADABLE_MODULE_ID));

	CHKiRet(omsdRegCFSLineHdlr((uchar *)"inputrunfilemonitor", 0, eCmdHdlrGetWord,
				addMonitor, NULL, STD_LOADABLE_MODULE_ID));

//	CHKiRet(omsdRegCFSLineHdlr((uchar *)"resetconfigvariables", 1, eCmdHdlrCustomHandler,
//				resetConfigVariables, NULL, STD_LOADABLE_MODULE_ID));

COMMITFILE = commitFile;


ENDmodInit
