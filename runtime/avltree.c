/* avltree.c - a generic avl tree class.
 *
 * Module begun 2009-09-14 by Rainer Gerhards
 *
 * Copyright 2008 Rainer Gerhards and Adiscon GmbH.
 *
 * This file is part of the rsyslog runtime library.
 *
 * The rsyslog runtime library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The rsyslog runtime library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the rsyslog runtime library.  If not, see <http://www.gnu.org/licenses/>.
 *
 * A copy of the GPL can be found in the file "COPYING" in this distribution.
 * A copy of the LGPL can be found in the file "COPYING.LESSER" in this distribution.
 */

#include "config.h"
#include <stdlib.h>
#include <assert.h>

#include "rsyslog.h"
#include "obj.h"
#include "avltree.h"

/* static data */
DEFobjStaticHelpers


#warning remove getsig! && stdio
static rsRetVal GetSignature(avltree_t *pThis, cstr_t *pSig);
#include <stdio.h>

/* Standard-Constructor
 */
BEGINobjConstruct(avltree) /* be sure to specify the object type also in END macro! */
	pThis->pRoot = NULL;
ENDobjConstruct(avltree)


/* ConstructionFinalizer
 * rgerhards, 2008-01-09
 */
static rsRetVal
avltreeConstructFinalize(avltree_t __attribute__((unused)) *pThis)
{
	DEFiRet;
	ISOBJ_TYPE_assert(pThis, avltree);
	RETiRet;
}


/* destruct a tree node and everything below it. This is a helper for
 * the tree destructor. We do a postorder traversal, else we would delete
 * memory we need to keep using (for the right child). Note that we do not
 * abort if we have an error during destruction. Doing so would probably cause
 * more harm than it saves...
 */
static inline void
DestructNode(avltree_t *pThis, avlnode_t **ppNode)
{
	if(*ppNode != NULL) {
		DestructNode(pThis, &((*ppNode)->pLeft));
		DestructNode(pThis, &((*ppNode)->pRight));
		pThis->DestructNode(&((*ppNode)->pUsrNode));
		free(*ppNode);
		*ppNode = NULL;
	}
}

/* destructor for the avltree object
 * Note that this discards the complete tree, so we do not need to
 * rebalance it while deleting entries.
 */
BEGINobjDestruct(avltree) /* be sure to specify the object type also in END and CODESTART macros! */
CODESTARTobjDestruct(avltree)
	DestructNode(pThis, &pThis->pRoot);
ENDobjDestruct(avltree)


/* debugprint for the avltree object */
BEGINobjDebugPrint(avltree) /* be sure to specify the object type also in END and CODESTART macros! */
CODESTARTobjDebugPrint(avltree)
	dbgoprint((obj_t*) pThis, "AVLtree object\n");
ENDobjDebugPrint(avltree)


/* configure the tree for use. This MUST be called before finalizing and using, because
 * it sets a nubmer of important callbacks. If they are not set, we will probably segfault!
 * Note that the fourth parameter may be NULL, in which case no debug functions can be called.
 * This is valid!
 */
static rsRetVal
ConfigureTree(avltree_t *pThis, rsRetVal (*pConstructNode)(), rsRetVal (*pDestructNode)(void*),
	      rsRetVal (*pCmpKey)(void *, void *, int *), rsRetVal (*pGetKeyString)(void*, cstr_t**))
{
	DEFiRet;
	ISOBJ_TYPE_assert(pThis, avltree);
	pThis->ConstructNode = pConstructNode;
	pThis->DestructNode = pDestructNode;
	pThis->CmpKey = pCmpKey;
	pThis->GetKeyString = pGetKeyString;
	RETiRet;
}


/* Construct a avltree node, but do not do any balancing.
 * rgerhards, 2009-09-14
 */
static rsRetVal
ConstructNode(avltree_t *pThis, avlnode_t **ppNode, void *pKey)
{
	void *pUsrNode = NULL;
	avlnode_t *pNode;
	DEFiRet;
	
	ISOBJ_TYPE_assert(pThis, avltree);
	CHKiRet(pThis->ConstructNode(&pUsrNode, pKey));
	CHKmalloc(pNode = malloc(sizeof(avlnode_t)));
	pNode->pLeft = NULL;
	pNode->pRight = NULL;
	pNode->height = 0;
	pNode->pUsrNode = pUsrNode;
	*ppNode = pNode;

finalize_it:
	if(iRet != RS_RET_OK) {
		if(pUsrNode != NULL)
			pThis->DestructNode(&pUsrNode);
	}

	RETiRet;
}


/* update the height of a given node. The height is the max height of its
 * children plus 1. We use non-standard calling conventions as this is mostly
 * code moved to a separate short function for clarity (saving overhead!)
 */
static inline void
UpdateHeight(avlnode_t *pNode)
{
	int hLeft;
	int hRight;
	hLeft  = pNode->pLeft == NULL ? 0 : pNode->pLeft->height + 1;
	hRight = pNode->pRight == NULL ? 0 : pNode->pRight->height + 1;
	if(hLeft > hRight)
		pNode->height = hLeft;
	else
		pNode->height = hRight;
}


/* return the balance of this node. Possible values are: -2..0..2 where
 * the 2-values mean that rebalancing is necessary. -2 means that the tree
 * must be balanced on the left, 2 means it must be balanced on the right.
 */
static inline int
GetBalance(avlnode_t *pNode)
{
	int hLeft;
	int hRight;
	hLeft  = pNode->pLeft == NULL ? 0 : pNode->pLeft->height + 1;
	hRight = pNode->pRight == NULL ? 0 : pNode->pRight->height + 1;
	return hRight - hLeft;
}


/* find or insert a tree node, keeping the tree balanced (following algo
 * as described by Knuth, Wirth)
 * rgerhards, 2009-09-14
 */
static inline rsRetVal
InsertNode(avltree_t *pThis, avlnode_t **ppNode, void *pKey)
{
	int cmpRes; 	/* result of comparison operation (cache potentially lengthy op!) */
	avlnode_t *pChild; /* for Rotation */
	avlnode_t *pGrandChild; /* for Rotation */
	DEFiRet;
	avlnode_t *pNode = *ppNode;

	CHKiRet(pThis->CmpKey(pNode->pUsrNode, pKey, &cmpRes));
	if(cmpRes == 0) { /* is equal? */
		/*NOTHING TO DO - we found the right node and it is already in ppNode!*/;
		FINALIZE;
	} else if(cmpRes > 0) { /* current node greater than new key (so key is less than node)? */
		if(pNode->pLeft == NULL) {
			CHKiRet(ConstructNode(pThis, &pNode->pLeft, pKey));
		} else {
			CHKiRet(InsertNode(pThis, &pNode->pLeft, pKey));
		}
	} else { /* is greater than! */
		if(pNode->pRight == NULL) {
			CHKiRet(ConstructNode(pThis, &pNode->pRight, pKey));
		} else {
			CHKiRet(InsertNode(pThis, &pNode->pRight, pKey));
		}
	}
	UpdateHeight(pNode);

	/* we added the entry and updated the height counters. Now we need to check if
	 * we need to rebalance...
	 */
	if(GetBalance(pNode) == -2) {
		/* tree to deep on the left */
		if(GetBalance(pNode->pLeft) < 0) {
			/* outer subtree -> single rotation */
			pChild = pNode->pLeft;
			pNode->pLeft = pChild->pRight;
			pChild->pRight = pNode;
			UpdateHeight(pNode);
			UpdateHeight(pChild);
			*ppNode = pNode = pChild;
		} else {
			/* inner subtree -> double rotation*/
			pChild = pNode->pLeft;
			pGrandChild = pChild->pRight;
			pNode->pLeft = pGrandChild->pRight;
			pChild->pRight = pGrandChild->pLeft;
			pGrandChild->pLeft = pChild;
			pGrandChild->pRight = pNode;
			UpdateHeight(pNode);
			UpdateHeight(pChild);
			UpdateHeight(pGrandChild);
			*ppNode = pNode = pGrandChild;
		}
	} else if(GetBalance(pNode) == 2) {
		/* tree to deep on the right */
		if(GetBalance(pNode->pRight) < 0) {
			/* inner subtree -> double rotation*/
			pChild = pNode->pRight;
			pGrandChild = pChild->pLeft;
			pNode->pRight = pGrandChild->pLeft;
			pChild->pLeft = pGrandChild->pRight;
			pGrandChild->pRight = pChild;
			pGrandChild->pLeft = pNode;
			UpdateHeight(pNode);
			UpdateHeight(pChild);
			UpdateHeight(pGrandChild);
			*ppNode = pNode = pGrandChild;
		} else {
			/* outer subtree -> single rotation */
			pChild = pNode->pRight;
			pNode->pRight = pChild->pLeft;
			pChild->pLeft = pNode;
			UpdateHeight(pNode);
			UpdateHeight(pChild);
			*ppNode = pNode = pChild;
		}
	}

cstr_t *cstrSig;
rsCStrConstruct(&cstrSig);
GetSignature(pThis, cstrSig);
printf("done adding key %s, signature %s\n", (char*) pKey, rsCStrGetSzStrNoNULL(cstrSig));
rsCStrDestruct(&cstrSig);

finalize_it:
	RETiRet;
}


/* Find existing entry or insert it, if not yet present.
 * rgerhards, 2009-09-14
 */
static rsRetVal
Insert(avltree_t *pThis, void *pKey)
{
	ISOBJ_TYPE_assert(pThis, avltree);
	DEFiRet;

	if(pThis->pRoot == NULL) {
		CHKiRet(ConstructNode(pThis, &pThis->pRoot, pKey));
	} else {
		CHKiRet(InsertNode(pThis, &pThis->pRoot, pKey));
	}

finalize_it:
	RETiRet;
}



/* recursively generate the signature. Helper to GetSignature()
 */
static inline rsRetVal
AddToSignature(avltree_t *pThis, avlnode_t *pNode, cstr_t *pSig)
{
	cstr_t *pStr = NULL;
	DEFiRet;

	if(pNode == NULL)
		FINALIZE;

	CHKiRet(AddToSignature(pThis, pNode->pLeft, pSig));
	CHKiRet(AddToSignature(pThis, pNode->pRight, pSig));

	CHKiRet(pThis->GetKeyString(pNode->pUsrNode, &pStr));
	CHKiRet(cstrAppendCStr(pSig, pStr));
	CHKiRet(cstrAppendChar(pSig, ':'));

finalize_it:
	if(pStr != NULL)
		cstrDestruct(&pStr);

	RETiRet;
}


/* generate a "signature" for the avl tree. This shall identify the ordering of elements
 * and is primarily meant as a debugging aid. The signature is all key values as discovered
 * during a postorder traversal, delimited by colons (no spaces around them). While this may
 * not be a perfect signature, it looks good enough for our testing purposes. Actually, I
 * initially wanted to create the signature based on a bfs traversal, but it turned out that
 * it needs to much code (the queue) to justify its implementation *just* as a debugging aid.
 */
static rsRetVal
GetSignature(avltree_t *pThis, cstr_t *pSig)
{
	DEFiRet;
	ASSERT(pSig != NULL);
	if(pThis->GetKeyString == NULL)
		ABORT_FINALIZE(RS_RET_NO_KEY2STR);

	CHKiRet(cstrAppendChar(pSig, ':'));
	iRet = AddToSignature(pThis, pThis->pRoot, pSig);

finalize_it:
	RETiRet;
}


/* queryInterface function
 * rgerhards, 2008-02-21
 */
BEGINobjQueryInterface(avltree)
CODESTARTobjQueryInterface(avltree)
	if(pIf->ifVersion != avltreeCURR_IF_VERSION) { /* check for current version, increment on each change */
		ABORT_FINALIZE(RS_RET_INTERFACE_NOT_SUPPORTED);
	}

	/* ok, we have the right interface, so let's fill it
	 * Please note that we may also do some backwards-compatibility
	 * work here (if we can support an older interface version - that,
	 * of course, also affects the "if" above).
	 */
	pIf->Construct = avltreeConstruct;
	pIf->ConstructFinalize = avltreeConstructFinalize;
	pIf->Destruct = avltreeDestruct;
	pIf->DebugPrint = avltreeDebugPrint;
	pIf->ConfigureTree = ConfigureTree;
	pIf->Insert = Insert;
	pIf->GetSignature = GetSignature;

finalize_it:
ENDobjQueryInterface(avltree)


/* Initialize the avltree class. Must be called as the very first method
 * before anything else is called inside this class.
 * rgerhards, 2008-02-19
 */
BEGINObjClassInit(avltree, 1, OBJ_IS_CORE_MODULE) /* class, version */
	/* request objects we use */
	//CHKiRet(objUse(var, CORE_COMPONENT));

	/* set our own handlers */
	OBJSetMethodHandler(objMethod_DEBUGPRINT, avltreeDebugPrint);
	OBJSetMethodHandler(objMethod_CONSTRUCTION_FINALIZER, avltreeConstructFinalize);
ENDObjClassInit(avltree)

/* vi:set ai:
 */
