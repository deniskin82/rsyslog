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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/inotify.h>
#include <stdlib.h>
#include <unistd.h>
#include "config.h" /* this is for autotools and always must be the first include */
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


/*  Dynamic naming : 
 *  If in the monitoring list we have a directory, we load all the files in this directory.
 *  For the loading, we are trying to load any previously saved state
 *  Files that are dynamically generated, have their normal filenames bu the state file is
 *  named as directory-file-state
 * */

/***************************************************
 *                  GLOBAL DEFINITIONS             *
 **************************************************/

/****************
 Module specific
****************/
/* Module static data */
DEF_IMOD_STATIC_DATA	/* must be present, starts static data */
DEFobjCurrIf(errmsg)
     DEFobjCurrIf(glbl)
     DEFobjCurrIf(datetime)
     DEFobjCurrIf(strm)
     DEFobjCurrIf(prop)

     MODULE_TYPE_INPUT	/* must be present for input modules, do not remove */


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
 strcpy( CHILD->fileTag , PARENT->fileTag );				\
CHILD->facility = PARENT->facility ;	     				\
CHILD->severity = PARENT->severity ;  					\


 /****************
       Variables
 ****************/
     static prop_t *pInputName = NULL;	/* there is only one global inputName for all messages generated by this input */
     int INOTIFY_DESC; // Inotify watch descriptor

     //  Here are included all the necessary field that describe a file that is needed to be monitored
     typedef struct  fileInfo_s
     {
       uchar* fileName;                // The name of the file. Path is included
       uchar* fileTag;                   // The tag
       uint lenTag;                       //  Tag length (Is used to avoid injection)
       uchar* stateFile;                // The file that save the status
       int facility;
       int severity;
       int isDir ;
       //       int inotifyDesc;      // The file descriptor of the opened file
       strm_t *pStrm;       // its stream (NULL if not assigned )
     } fileInfo;

// GLOBAL DEFINITIONS
static fileInfo * COMMITFILE;
fileInfo **DESCRIPTORS; // Dynamic table for every file Descriptor
int DESC_ELEMS;
static linkedList_t FILE_LIST;


/***************************************************
 *                       UTILITIES                                               *
 **************************************************/


void handle_error (char* msg)
{
  perror ( msg ); 
  return;
}  /* handle_error */



fileInfo* getNewFileStruct ( void  ) {

  fileInfo* newFile = (fileInfo*) malloc(sizeof (struct fileInfo_s) );

  newFile->lenTag = 0;
  newFile->isDir = 0;
  newFile->facility = 128; // local0
  newFile->severity = 5;   // notice, as of rfc 3164
  newFile->pStrm = NULL; 
  newFile->fileTag = (uchar*) malloc(1024);
  newFile->fileName = (uchar*) malloc(1024);
  newFile->stateFile = (uchar*) malloc(1024); 


  return newFile;
}
// Define how to destroy a file object
static rsRetVal destroyFile ( fileInfo *pThis ) { 
DEFiRet;

	assert ( pThis );
	if ( pThis->fileTag != NULL ) 
		free ( pThis->fileTag );

	if ( pThis->fileName != NULL ) 
		free ( pThis->fileName );

	if ( pThis->stateFile != NULL ) 
		free ( pThis->stateFile );

	if ( pThis->pStrm != NULL ) 
		free ( pThis->pStrm );
	
	free ( pThis );
RETiRet;
}

void printFileStruct ( fileInfo *file) {

  assert(file);

  dbgprintf(  "FileName : %s , Tag : %s , Status : %s , Severity : %d, Facility :%d \n"  ,
	  file->fileName , file->fileTag, file->stateFile, file->severity, file->facility );

}



/* Pre-open file and keep them open for better performance */
static rsRetVal openFile ( fileInfo *openThis ) 
{
  DEFiRet;
  strm_t *psSF = NULL;
  struct stat stat_buf;
  char* stateFile[100];

	assert ( openThis );
  /* check if the saved state exists */

	sprintf( stateFile , "%s/%s", glbl.GetWorkDir() , openThis->stateFile );
      
	fprintf(stderr, "lala :%s\n", stateFile );
   if (  stat(  (char *) stateFile  , &stat_buf) == -1  )
    {

      fprintf( stderr, " No state file found. Opening new stream for : %s ( %s )\n", openThis->fileName , openThis->stateFile);

      CHKiRet( strm.Construct( &openThis->pStrm ) );

      CHKiRet( strm.SettOperationsMode( openThis->pStrm, STREAMMODE_READ));
      CHKiRet( strm.SetsType( openThis->pStrm, STREAMTYPE_FILE_MONITOR));
      CHKiRet( strm.SetFName( openThis->pStrm, openThis->fileName , strlen( (char *) openThis->fileName )) ); 	    // Set file Prefix
      CHKiRet( strm.ConstructFinalize( openThis->pStrm));
    }
  else 
    {
      fprintf( stderr, "State file found for : %s . Loading settings\n", openThis->fileName);

      CHKiRet( strm.Construct( &psSF) );
      CHKiRet( strm.SettOperationsMode( psSF, STREAMMODE_READ) );
      CHKiRet( strm.SetsType( psSF, STREAMTYPE_FILE_SINGLE) );
      CHKiRet( strm.SetFName( psSF, openThis->stateFile , strlen ( (char *)openThis->stateFile )) );
      CHKiRet( strm.ConstructFinalize( psSF) );

      /* read back in the object */      
      CHKiRet(obj.Deserialize( &openThis->pStrm, (uchar*) "strm", psSF , NULL, openThis ));

      CHKiRet(strm.SeekCurrOffs( openThis->pStrm) );

      // We took the state. Now it can be deleted
      psSF->bDeleteOnClose = 1;
    }

 /* Just an extra check that everything is working ... */
  if ( openThis->pStrm == NULL) 
    ABORT_FINALIZE( RS_RET_IO_ERROR );

  RETiRet;

finalize_it :
  if(psSF != NULL)
    strm.Destruct(&psSF);

  perror ( " DEBUG from open File \n" );

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
  MsgSetTAG( pMsg, pInfo->fileTag , pInfo->lenTag );
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
  dbgprintf( "Registering .... : %s , ", target );

  wd = inotify_add_watch ( INOTIFY_DESC , target, IN_ALL_EVENTS);
  if ( wd  < 0) {
    handle_error ( "Could not add file to inotify\n" );
    return RS_RET_IO_ERROR;
  }

  dbgprintf(  " (inotify desc :  %d  )\n", wd);
  RETiRet;
}


static void pollFileCancelCleanup(void *pArg)
 {
	 BEGINfunc;
	 cstr_t **ppCStr = (cstr_t**) pArg;
	 if(*ppCStr != NULL)
		 rsCStrDestruct(ppCStr);
	 ENDfunc;
 }

#pragma GCC diagnostic ignored "-Wempty-body"
static rsRetVal readData ( fileInfo *pThis )
{
  cstr_t *strBuf = NULL; // String buffer object
  DEFiRet;

  /* loop until strmReadLine() returns EOF. Every line is saved it to strBuf and after enqueuing free the buffer */
  while ( 1 ) {
    CHKiRet(strm.ReadLine(pThis->pStrm, &strBuf ) );
    CHKiRet(enqLine( pThis, strBuf )); 
    rsCStrDestruct( &strBuf  ); 
  }

 finalize_it:	
  ;

  RETiRet;
}


/* Allow for 2048 simultanious events */
#define MAX_EVENTS  2048 
static rsRetVal inotifyTakesOver (  void ) {

  DEFiRet;
  
  ssize_t len, i = 0; 
  u_char eventList[ MAX_EVENTS ] = {0}; 
  struct inotify_event *pevent;

  dbgprintf( "Inotify started\n");
  /* Every entry in inotify watch has an ID. We use this ( ID - 1 ) for positioning
     inside DESCRIPTORS.
     TODO : add support for excluded files
  */
  while ( 1 )
    {
      i = 0;
       
      len = read (INOTIFY_DESC , eventList , MAX_EVENTS); // get events in eventlist
      if ( len < 0 )
	handle_error ( "Problem in Reading inotify events\n");
       
      if ( len > MAX_EVENTS ) 
	handle_error ( "Must be recompiled with higher MAX_EVENTS \n" );
       
      /* Iterate events */
      for ( i = 0; i < len ; i  += sizeof(struct inotify_event) + pevent->len ) 
	{
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
	    fileInfo *newFile = getNewFileStruct ();

	    inheritParent ( newFile, DESCRIPTORS [ pevent->wd - 1] , pevent->name );
	    registerTarget ( (char *) newFile->fileName );  // Add file to inotify watch list


	    DESCRIPTORS [ DESC_ELEMS ] = newFile;        // Add the new file to the list  
	    CHKiRet ( openFile ( DESCRIPTORS [ DESC_ELEMS  ]  ) );
	    DESC_ELEMS++;
	    continue;
	  } // Switch
	}// For
    } // While

  RETiRet;  
 finalize_it :
  
  handle_error ( "Inotify stopped \n");

}//  inotifyTakesOver 


// TODO : This one ... (use poll )
static rsRetVal pollingTakesOver (  void ) {

  DEFiRet;

  /************************
   *  Case of Polling             *
   ***********************/


  int iPollInterval = 2;
  int i = 0;
  while ( 1 ) {
    
    for ( i = 0;  i < DESC_ELEMS  ; i ++ ) {
      readData ( &DESCRIPTORS [ i ]  )  ;
    }
	srSleep(iPollInterval, 10);
  }

  /* while(1) { */

  /*   dbgprintf( "lalala" ); */
  /* 	do { */
  /* 		bHadFileData = 0; */
  /* 		for(i = 0 ; i < D_SIZE ; ++i) { */
  /* 			/\* pollFile(&files[i], &bHadFileData); *\/ */
  /* 		} */
  /* 	} while( D_SIZE > 1 && bHadFileData == 1); /\* warning: do...while()! *\/ */

  /* 	/\* Note: the additional 10ns wait is vitally important. It guards rsyslog against totally */
  /* 	 * hogging the CPU if the users selects a polling interval of 0 seconds. It doesn't hurt any */
  /* 	 * other valid scenario. So do not remove. -- rgerhards, 2008-02-14 */
  /* 	 *\/ */
  /* 	//		srSleep(iPollInterval, 10); */

  /* } */
  /*NOTREACHED*/


  RETiRet;
  
}


/***************************************************
 *   Actual Runtime Functions                                        *
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
	// I 'm not really sure why they are needed. They were here before me :>
	CHKiRet(prop.Construct(&pInputName));
	CHKiRet(prop.SetString(pInputName, UCHAR_CONSTANT("imfile"), sizeof("imfile") - 1));
	CHKiRet(prop.ConstructFinalize(pInputName));


	int cnt_Elements = 0;
	linkedListCookie_t listPtr = NULL; // Pointer to current node. DON'T RELY ON IT


	llGetNumElts ( &FILE_LIST , &cnt_Elements) ; // Get number of elements

	if( cnt_Elements == 0 ) {
		dbgprintf( "DEBUG OUT : %s (%d)\n" , __func__, __LINE__ );
		errmsg.LogError(0, RS_RET_NO_RUN, "No files configured to be monitored");
		ABORT_FINALIZE(RS_RET_NO_RUN);
	}



	// Allocate a table large enough for cnt_Elements * fileInfo 
	DESCRIPTORS = (fileInfo **) malloc( cnt_Elements * sizeof ( struct fileInfo_s ) );
	DESC_ELEMS = cnt_Elements ;

	int i = 0;
	fileInfo *tempFile;
	while ( (iRet =   llGetNextElt ( &FILE_LIST , &listPtr,  (void **) &tempFile )  == RS_RET_OK) ) 
	{
		CHKiRet ( openFile (  tempFile  ) ) ;
		DESCRIPTORS [  i++ ] = tempFile;
		tempFile = NULL;
	 }

finalize_it:

if ( iRet == RS_RET_OK ) 
  {
    dbgprintf( "calling RunInput ...\n");

  }
 else 
   {
     perror("lalalala\n");
     
   }

	
dbgprintf(" EndWillRun just stopped  \n");

ENDwillRun


/*************************************
 * This is the eternal loop ....                  *
 *************************************/


//#pragma GCC diagnostic ignored "-Wempty-body"
BEGINrunInput
int i;

CODESTARTrunInput


// if inotify exists ....
while(1)
  inotifyTakesOver (   );
// else
//    pollingTakesOver ( ) ;
   

RETiRet;

ENDrunInput
//#pragma GCC diagnostic warning "-Wempty-body"
/* END no-touch zone                                                                          *
 * ------------------------------------------------------------------------------------------ */



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

dbgprintf( " SAVING STATE , elems : %d \n", DESC_ELEMS);
for(i = 0 ; i < DESC_ELEMS ; i++) {
  //  if( DESCRIPTORS[i]->pStrm != NULL ) { /* stream open? */
  dbgprintf("Saving : %s\n " , DESCRIPTORS[i] -> fileName );
    persistStrmState ( DESCRIPTORS[i] );
    strm.Destruct(  &DESCRIPTORS[i]->pStrm );
    // }
 }

if(pInputName != NULL)
  prop.Destruct( &pInputName );
ENDafterRun


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

  ASSERT(pInfo != NULL);


  /* TODO: create a function persistObj in obj.c? */
  CHKiRet(strm.Construct(&psSF));
  lenDir = strlen((char*)glbl.GetWorkDir());
  if(lenDir > 0)
    CHKiRet(strm.SetDir(psSF, glbl.GetWorkDir(), lenDir));
  CHKiRet(strm.SettOperationsMode(psSF, STREAMMODE_WRITE_TRUNC));
  CHKiRet(strm.SetsType(psSF, STREAMTYPE_FILE_SINGLE));
  CHKiRet(strm.SetFName(psSF, pInfo->stateFile, strlen((char*) pInfo->stateFile)));
  CHKiRet(strm.ConstructFinalize(psSF));

  CHKiRet(strm.Serialize(pInfo->pStrm, psSF));

  CHKiRet(strm.Destruct(&psSF));

 finalize_it:
  if(psSF != NULL)
    strm.Destruct(&psSF);

  RETiRet;
}


/***************************************************
 *   Configuration Parsing  Functions                              *
 **************************************************/



/* add a new monitor */
static rsRetVal addMonitor(void __attribute__((unused)) *pVal, uchar *possibleEntry)
{
  DEFiRet;
  struct stat stat_buf;

  // Check if we have some necessary components ;p
  checkValid ( COMMITFILE->fileName ,  "imfile error: no file name given, file monitor can not be created" );
  checkValid ( COMMITFILE->fileTag ,  "imfile error: no tag value given, file monitor can not be created" );
  checkValid ( COMMITFILE->stateFile ,  "imfile error: no state file given, file monitor can not be created" );

  if ( stat(  (char *) COMMITFILE->fileName  , &stat_buf) == - 1 ) {
	errmsg.LogError(0, RS_RET_CONFIG_ERROR, "Could not open the file\n" );	
	ABORT_FINALIZE ( RS_RET_CONFIG_ERROR );
 }


  //   We need to make a new instance out of Commit File because Commit FIle is used recursively
   if(iRet == RS_RET_OK) {
	fileInfo *toCommit;

	toCommit = getNewFileStruct();

	registerTarget ( (char* )COMMITFILE->fileName );

	memcpy ( toCommit ,  COMMITFILE , sizeof(struct fileInfo_s )  );
	toCommit->fileName = strdup ( (uchar*) COMMITFILE->fileName );
	toCommit->fileTag = strdup ( (uchar*) COMMITFILE->fileTag );
	toCommit->stateFile = strdup ( (uchar*) COMMITFILE->stateFile );
 
	// If it's a directory, recursively add all of its content
 	if ( S_ISDIR ( stat_buf.st_mode ) ) {
		DIR *dir;
		struct dirent *ent;
		fileInfo* subFile;
 
		toCommit->isDir = 1;
		dir = opendir ( (const char * )toCommit->fileName );
		while ((ent = readdir (dir)) != NULL) {

			// Ignoring . and .. which are parts of every directory
			if (  !strcmp( ent->d_name , "." ) || !strcmp( ent->d_name, ".." )  )
				continue;

		     subFile = getNewFileStruct ();
		     inheritParent ( subFile, toCommit , ent->d_name );
		    registerTarget ( (char *) subFile->fileName );  // Add file to inotify watch list

    		    llAppend ( &FILE_LIST , 0 ,  subFile ); // Append CommitFile to FILE_LIST with entry number as key
     		} 
	  }
    llAppend ( &FILE_LIST , 0 ,  toCommit ); // Append CommitFile to FILE_LIST with entry number as key
  }

 finalize_it:

  if ( iRet != RS_RET_OK )
    handle_error ( "Ignoring the file" );

  RETiRet;
}



/***************************************************
 *                  Module Entry - Exit points                          *
 **************************************************/

/*  The following entry points are defined in module-template.h.
 * In general, they need to be present, but you do NOT need to provide
 * any code here.
 */
BEGINmodExit
CODESTARTmodExit
/* release objects we used */
objRelease( strm, CORE_COMPONENT);
objRelease( datetime, CORE_COMPONENT);
objRelease( glbl, CORE_COMPONENT);
objRelease( errmsg, CORE_COMPONENT);
objRelease( prop, CORE_COMPONENT);
ENDmodExit


BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_IMOD_QUERIES
ENDqueryEtryPt



/* Maybe it's a good idea to use inotify tools */
BEGINmodInit()
  CODESTARTmodInit
  *ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */
CODEmodInit_QueryRegCFSLineHdlr
CHKiRet(objUse(errmsg, CORE_COMPONENT));
CHKiRet(objUse(glbl, CORE_COMPONENT));
CHKiRet(objUse(datetime, CORE_COMPONENT));
CHKiRet(objUse(strm, CORE_COMPONENT));
CHKiRet(objUse(prop, CORE_COMPONENT));

/* That's the best place to enable inotify */          
INOTIFY_DESC = inotify_init();
if ( INOTIFY_DESC < 0) {
  handle_error ( "Problem in start inotify\n" );
  return 1;
 }


/* Various initializations */
fileInfo* commitFile = getNewFileStruct(  );
CHKiRet( llInit ( &FILE_LIST , destroyFile , NULL , NULL ) ) ;


/* Gather the info */
CHKiRet( omsdRegCFSLineHdlr((uchar *)"inputfilename", 0, eCmdHdlrGetWord,
			    NULL,  &commitFile->fileName , STD_LOADABLE_MODULE_ID));

CHKiRet( omsdRegCFSLineHdlr((uchar *)"inputfiletag", 0, eCmdHdlrGetWord,
			    NULL,  &commitFile->fileTag , STD_LOADABLE_MODULE_ID));

CHKiRet( omsdRegCFSLineHdlr((uchar *)"inputfilestatefile", 0, eCmdHdlrGetWord,
			    NULL, &commitFile->stateFile , STD_LOADABLE_MODULE_ID));

CHKiRet( omsdRegCFSLineHdlr((int *)"inputfileseverity", 0, eCmdHdlrSeverity, 
			    NULL,  &commitFile->severity , STD_LOADABLE_MODULE_ID));

CHKiRet( omsdRegCFSLineHdlr((uchar *)"inputfilefacility", 0, eCmdHdlrFacility,
			    NULL,   &commitFile->facility , STD_LOADABLE_MODULE_ID));

/* CHKiRet( omsdRegCFSLineHdlr((uchar *)"inputfilepollinterval", 0, eCmdHdlrInt, */
/*   	NULL, &iPollInterval, STD_LOADABLE_MODULE_ID)); */

/* submit info to register the file */
COMMITFILE = commitFile;
CHKiRet(omsdRegCFSLineHdlr((uchar *)"inputrunfilemonitor", 0, eCmdHdlrGetWord,
			   addMonitor, NULL,  STD_LOADABLE_MODULE_ID));



dbgprintf(  "%s (%d)  (STOP) \n" , __func__ , __LINE__);


ENDmodInit
