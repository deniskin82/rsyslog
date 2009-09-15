/* The avltree object. This class implements an AVL-Tree and its entries.
 *
 * Copyright 2009 Rainer Gerhards and Adiscon GmbH.
 *
 * The class consist of the avltree and, more importantly, its nodes. The tree
 * itself is more or less a container, while the core of the functionality exists
 * inside the nodes. Both types of objects reside in this file.
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
#ifndef INCLUDED_AVLTREE_H
#define INCLUDED_AVLTREE_H

/* the avltree node object */
typedef struct avlnode_s avlnode_t;
struct avlnode_s {
	BEGINobjInstance;	/* Data to implement generic object - MUST be the first data element! */
	avlnode_t *pLeft;
	avlnode_t *pRight;
	short height;
	void *pUsrNode;		/* actual user data, including the key (pCmpOp() must work on key!) */
};


/* the avltree object */
struct avltree_s {
	BEGINobjInstance;	/* Data to implement generic object - MUST be the first data element! */
	avlnode_t *pRoot;
	/* user-provided functions to handle the user part of a node */
	rsRetVal (*ConstructNode)(void *ppNode, void *pKey);/* "returns" pointer to newly created user node */
	rsRetVal (*DestructNode)(void *);	/* destructs a user node */
	rsRetVal (*CmpKey)(void *pUsrNode, void *pKey, int *cmpResult); /* compares a key against a user
				node and returns the strcmp()-like result in cmpResult */
	rsRetVal (*GetKeyString)(void *, cstr_t **ppStr);/* return key value as string (debug aid) */
	/* and user-provided callbacks */
};


/* interfaces */
BEGINinterface(avltree) /* name must also be changed in ENDinterface macro! */
	INTERFACEObjDebugPrint(avltree);
	rsRetVal (*Construct)(avltree_t **ppThis);
	rsRetVal (*ConstructFinalize)(avltree_t __attribute__((unused)) *pThis);
	rsRetVal (*ConfigureTree)(avltree_t *pThis, rsRetVal (*CostructNode)(), rsRetVal (*DestructNode)(void*),
	                          rsRetVal (*pCmpOp)(void *, void *, int *), rsRetVal (*GetKeyString)(void*, cstr_t**));
	rsRetVal (*Destruct)(avltree_t **ppThis);
	rsRetVal (*Insert)(avltree_t *pThis, void *pKey);
	rsRetVal (*GetSignature)(avltree_t *pThis, cstr_t *pStr);
ENDinterface(avltree)
#define avltreeCURR_IF_VERSION 1 /* increment whenever you change the interface structure! */


/* prototypes */
PROTOTYPEObj(avltree);

#endif /* #ifndef INCLUDED_AVLTREE_H */
