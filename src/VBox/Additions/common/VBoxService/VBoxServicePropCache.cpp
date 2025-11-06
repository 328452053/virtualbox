/* $Id: VBoxServicePropCache.cpp 111560 2025-11-06 13:34:38Z knut.osmundsen@oracle.com $ */
/** @file
 * VBoxServicePropCache - Guest property cache.
 */

/*
 * Copyright (C) 2010-2025 Oracle and/or its affiliates.
 *
 * This file is part of VirtualBox base platform packages, as
 * available from https://www.virtualbox.org.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, in version 3 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses>.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */


/*********************************************************************************************************************************
*   Header Files                                                                                                                 *
*********************************************************************************************************************************/
#include <iprt/assert.h>
#include <iprt/list.h>
#include <iprt/mem.h>
#include <iprt/string.h>

#include <VBox/VBoxGuestLib.h>
#include <VBox/HostServices/GuestPropertySvc.h> /* For GUEST_PROP_MAX_VALUE_LEN */
#include "VBoxServiceInternal.h"
#include "VBoxServiceUtils.h"
#include "VBoxServicePropCache.h"


/**
 * Searches a property within a property cache.
 *
 * @returns A pointer to the found property cache entry on success, or NULL if not found.
 * @param   pCache          The property cache.
 * @param   pszName         Name of property to search for. Case sensitive.
 */
static PVBOXSERVICEVEPROPCACHEENTRY
vgsvcPropCacheFindInternalLocked(PVBOXSERVICEVEPROPCACHE pCache, const char *pszName)
{
    /** @todo This is a O(n) lookup, maybe improve this later to O(1) using a
     *        map.
     *  r=bird: Use a string space (RTstrSpace*). That is O(log n) in its current
     *        implementation (AVL tree). However, this is not important at the
     *        moment. */
    PVBOXSERVICEVEPROPCACHEENTRY pNodeIt;
    RTListForEach(&pCache->NodeHead, pNodeIt, VBOXSERVICEVEPROPCACHEENTRY, NodeSucc)
    {
        if (strcmp(pNodeIt->pszName, pszName) == 0)
            return pNodeIt;
    }
    return NULL;
}


/**
 * Inserts (appends) a property into a property cache.
 *
 * Caller must first make sure the name isn't in the cache already.
 *
 * @returns A pointer to the inserted property cache entry on success, or NULL on failure.
 * @param   pCache          The property cache.
 * @param   pszName         Name of property to insert. Case sensitive.
 */
static PVBOXSERVICEVEPROPCACHEENTRY vgsvcPropCacheInsertEntryInternalLocked(PVBOXSERVICEVEPROPCACHE pCache, const char *pszName)
{
    PVBOXSERVICEVEPROPCACHEENTRY pNode = (PVBOXSERVICEVEPROPCACHEENTRY)RTMemAlloc(sizeof(VBOXSERVICEVEPROPCACHEENTRY));
    if (pNode)
    {
        pNode->pszName = RTStrDup(pszName);
        AssertPtrReturnStmt(pNode->pszName, RTMemFree(pNode), NULL);
        pNode->pszValue = NULL;
        pNode->fFlags = 0;
        pNode->pszValueReset = NULL;

        RTListAppend(&pCache->NodeHead, &pNode->NodeSucc);
    }
    return pNode;
}


/**
 * Writes a new value to a property.
 *
 * @returns VBox status code.
 * @param   pClient         The guest property client session info.
 * @param   pszName         Name of property to write value for. Case sensitive.
 * @param   fFlags          Property cache flags of type VGSVCPROPCACHE_FLAGS_XXX.
 * @param   pszValue        The value to write, NULL to delete.
 */
static int vgsvcPropCacheWriteProp(PVBGLGSTPROPCLIENT pClient, const char *pszName, uint32_t fFlags, const char *pszValue)
{
    AssertPtrReturn(pszName, VERR_INVALID_POINTER);

    int rc;
    if (pszValue != NULL)
    {
        if (fFlags & VGSVCPROPCACHE_FLAGS_TRANSIENT)
        {
            /*
             * Because a value can be temporary we have to make sure it also
             * gets deleted when the property cache did not have the chance to
             * gracefully clean it up (due to a hard VM reset etc), so set this
             * guest property using the TRANSRESET flag..
             */
            rc = VbglGuestPropWrite(pClient, pszName, pszValue, "TRANSRESET");
            if (rc == VERR_PARSE_ERROR)
            {
                /* Host does not support the "TRANSRESET" flag, so only
                 * use the "TRANSIENT" flag -- better than nothing :-). */
                rc = VbglGuestPropWrite(pClient, pszName, pszValue, "TRANSIENT");
                /** @todo r=bird: Remember that the host doesn't support this. */
            }
        }
        else
            rc = VbglGuestPropWriteValue(pClient, pszName, pszValue); /* no flags */
    }
    else
        rc = VbglGuestPropWriteValue(pClient, pszName, NULL);
    return rc;
}


#if 0 /* unused */
/**
 * Writes a new value to a property, using a format value.
 *
 * @returns VBox status code.
 * @param   pClient         The guest property client session info.
 * @param   pszName         Name of property to write value for. Case sensitive.
 * @param   fFlags          Property cache flags of type VGSVCPROPCACHE_FLAGS_XXX.
 * @param   pszValueFormat  Format string of value to write.
 */
static int vgsvcPropCacheWritePropF(PVBGLGSTPROPCLIENT pClient, const char *pszName, uint32_t fFlags,
                                    const char *pszValueFormat, ...)
{
    int rc;
    if (pszValueFormat != NULL)
    {
        va_list va;
        va_start(va, pszValueFormat);

        char *pszValue;
        if (RTStrAPrintfV(&pszValue, pszValueFormat, va) >= 0)
        {
            rc = vgsvcPropCacheWriteProp(pClient, pszName, fFlags, pszValue);
            RTStrFree(pszValue);
        }
        else
            rc = VERR_NO_MEMORY;
        va_end(va);
    }
    else
        rc = VbglGuestPropWriteValue(pClient, pszName, NULL);
    return rc;
}
#endif


/**
 * Creates a property cache.
 *
 * @returns VBox status code.
 * @param   pCache          Pointer to the cache.
 * @param   pClient         The guest property client session info.
 */
int VGSvcPropCacheCreate(PVBOXSERVICEVEPROPCACHE pCache, PVBGLGSTPROPCLIENT pClient)
{
    AssertPtrReturn(pCache, VERR_INVALID_POINTER);
    Assert(pCache->pClient == NULL);

    RTListInit(&pCache->NodeHead);
    int rc = RTCritSectInit(&pCache->CritSect);
    if (RT_SUCCESS(rc))
        pCache->pClient = pClient;
    return rc;
}


/**
 * Creates/updates a cache entry without submitting any changes to the host.
 *
 * This is handy for defining default values/flags.
 *
 * @returns VBox status code.
 * @param   pCache          The property cache.
 * @param   pszName         The property name.
 * @param   fFlags          The property flags to set.
 * @param   pszValueReset   The property reset value.
 */
int VGSvcPropCacheUpdateEntry(PVBOXSERVICEVEPROPCACHE pCache, const char *pszName, uint32_t fFlags, const char *pszValueReset)
{
    AssertPtrReturn(pCache, VERR_INVALID_POINTER);
    AssertPtrReturn(pszName, VERR_INVALID_POINTER);

    int rc = RTCritSectEnter(&pCache->CritSect);
    AssertRCReturn(rc, rc);

    PVBOXSERVICEVEPROPCACHEENTRY pNode = vgsvcPropCacheFindInternalLocked(pCache, pszName);
    if (pNode == NULL)
        pNode = vgsvcPropCacheInsertEntryInternalLocked(pCache, pszName);
    if (pNode != NULL)
    {
        pNode->fFlags = fFlags;
        if (pszValueReset)
        {
            if (pNode->pszValueReset)
                RTStrFree(pNode->pszValueReset);
            pNode->pszValueReset = RTStrDup(pszValueReset);
            AssertStmt(pNode->pszValueReset, rc = VERR_NO_STR_MEMORY);
        }
    }
    else
        rc = VERR_NO_MEMORY;

    RTCritSectLeave(&pCache->CritSect);
    return rc;
}


/**
 * Core of VGSvcPropCacheUpdate shared with VGSvcPropCacheUpdateByPath.
 */
static int vgsvcPropCacheUpdateNode(PVBOXSERVICEVEPROPCACHE pCache, PVBOXSERVICEVEPROPCACHEENTRY pNode, const char *pszValue)
{
    int rc = VINF_SUCCESS;
    if (pszValue) /* Do we have a value to check for? */
    {
        bool fUpdate = false;
        /* Always update this property, no matter what? */
        if (pNode->fFlags & VGSVCPROPCACHE_FLAGS_ALWAYS_UPDATE)
            fUpdate = true;
        /* Did the value change so we have to update? */
        else if (pNode->pszValue && strcmp(pNode->pszValue, pszValue) != 0)
            fUpdate = true;
        /* No value stored at the moment but we have a value now? */
        else if (pNode->pszValue == NULL)
            fUpdate = true;

        if (fUpdate)
        {
            /* Write the update. */
            rc = vgsvcPropCacheWriteProp(pCache->pClient, pNode->pszName, pNode->fFlags, pszValue);
            VGSvcVerbose(4, "[PropCache %p]: Written '%s'='%s' (flags: %x), rc=%Rrc\n",
                         pCache, pNode->pszName, pszValue, pNode->fFlags, rc);
            if (RT_SUCCESS(rc)) /* Only update the node's value on successful write. */
            {
                RTStrFree(pNode->pszValue);
                pNode->pszValue = RTStrDup(pszValue);
                if (!pNode->pszValue)
                    rc = VERR_NO_STR_MEMORY;
            }
        }
        else
            rc = VINF_NO_CHANGE; /* No update needed. */
    }
    else
    {
        /* No value specified. Deletion (or no action required). */
        if (pNode->pszValue) /* Did we have a value before? Then the value needs to be deleted. */
        {
            rc = vgsvcPropCacheWriteProp(pCache->pClient, pNode->pszName, 0, /*fFlags*/ NULL /*pszValue*/);
            VGSvcVerbose(4, "[PropCache %p]: Deleted '%s'='%s' (flags: %x), rc=%Rrc\n",
                         pCache, pNode->pszName, pNode->pszValue, pNode->fFlags, rc);
            if (RT_SUCCESS(rc)) /* Only delete property value on successful Vbgl deletion. */
            {
                /* Delete property (but do not remove from cache) if not deleted yet. */
                RTStrFree(pNode->pszValue);
                pNode->pszValue = NULL;
            }
        }
        else
            rc = VINF_NO_CHANGE; /* No update needed. */
    }
    return rc;
}


/**
 * Creates/Updates the locally cached value and writes it to the host if modified.
 *
 * @returns VBox status code.
 * @retval  VERR_BUFFER_OVERFLOW if the property name or value exceeds the limit.
 * @retval  VINF_NO_CHANGE if the value is the same and nothing was written.
 * @param   pCache          The property cache.
 * @param   pszName         The property name.
 * @param   pszValue        The property value.  If this is NULL then the
 *                          property will be deleted (if possible).
 */
int VGSvcPropCacheUpdate(PVBOXSERVICEVEPROPCACHE pCache, const char *pszName, const char *pszValue)
{
    AssertPtrReturn(pCache, VERR_INVALID_POINTER);
    AssertPtrReturn(pszName, VERR_INVALID_POINTER);

    AssertPtr(pCache->pClient);

    if (RTStrNLen(pszName, GUEST_PROP_MAX_NAME_LEN) > GUEST_PROP_MAX_NAME_LEN - 1 /* Terminator */)
        return VERR_BUFFER_OVERFLOW;

    /*
     * Lock the cache.
     */
    int rc = RTCritSectEnter(&pCache->CritSect);
    AssertRC(rc);
    if (RT_SUCCESS(rc))
    {
        /*
         * Find the cache entry, create a new one if necessary, then update it.
         */
        PVBOXSERVICEVEPROPCACHEENTRY pNode = vgsvcPropCacheFindInternalLocked(pCache, pszName);
        if (pNode == NULL)
            pNode = vgsvcPropCacheInsertEntryInternalLocked(pCache, pszName);
        if (pNode != NULL)
            rc = vgsvcPropCacheUpdateNode(pCache, pNode, pszValue);
        else
            rc = VERR_NO_MEMORY;

        /*
         * Release cache.
         */
        RTCritSectLeave(&pCache->CritSect);
    }

    VGSvcVerbose(4, "[PropCache %p]: Updating '%s' resulted in rc=%Rrc\n", pCache, pszName, rc);
    return rc;
}


/**
 * Creates/Updates the locally cached value and writes it to the host if modified.
 *
 * @returns VBox status code.
 * @retval  VERR_BUFFER_OVERFLOW if the property name or value exceeds the limit.
 * @retval  VINF_NO_CHANGE if the value is the same and nothing was written.
 * @param   pCache          The property cache.
 * @param   pszName         The property name.
 * @param   pszValueFormat  The property format string.  If this is NULL then
 *                          the property will be deleted (if possible).
 * @param   ...             Format arguments.
 */
int VGSvcPropCacheUpdateF(PVBOXSERVICEVEPROPCACHE pCache, const char *pszName, const char *pszValueFormat, ...)
{
    if (pszValueFormat)
    {
        char    szValue[GUEST_PROP_MAX_VALUE_LEN];
        va_list va;
        va_start(va, pszValueFormat);
        ssize_t cchValue = RTStrPrintf2V(szValue, sizeof(szValue), pszValueFormat, va);
        va_end(va);
        if (cchValue >= 0)
            return VGSvcPropCacheUpdate(pCache, pszName, szValue);
        return VERR_BUFFER_OVERFLOW;
    }
    return VGSvcPropCacheUpdate(pCache, pszName, NULL);
}


/**
 * Updates all cache values which are starting with the specified path prefix.
 *
 * @returns VBox status code.
 * @param   pCache          The property cache.
 * @param   pszValue        The value to set.  A NULL will delete the value.
 * @param   pszPathFormat   The path prefix format string.  May not be null and
 *                          has to be an absolute path.
 * @param   ...             Format arguments.
 */
int VGSvcPropCacheUpdateByPath(PVBOXSERVICEVEPROPCACHE pCache, const char *pszValue, const char *pszPathFormat, ...)
{
    AssertPtrReturn(pCache, VERR_INVALID_POINTER);
    AssertPtrReturn(pszPathFormat, VERR_INVALID_POINTER);

    /*
     * Format the value first.
     */
    int rc;
    char szPath[GUEST_PROP_MAX_NAME_LEN];
    va_list va;
    va_start(va, pszPathFormat);
    ssize_t const cchPath = RTStrPrintf2V(szPath, sizeof(szPath), pszPathFormat, va);
    va_end(va);
    if (cchPath > 0)
    {
        rc = RTCritSectEnter(&pCache->CritSect);
        AssertRC(rc);
        if (RT_SUCCESS(rc))
        {
            /*
             * Iterate through all nodes, update those starting with the given path.
             */
            rc = VERR_NOT_FOUND;
            PVBOXSERVICEVEPROPCACHEENTRY pNodeIt;
            RTListForEach(&pCache->NodeHead, pNodeIt, VBOXSERVICEVEPROPCACHEENTRY, NodeSucc)
            {
                if (RTStrNCmp(pNodeIt->pszName, szPath, (size_t)cchPath) == 0)
                {
                    int const rc2 = vgsvcPropCacheUpdateNode(pCache, pNodeIt, pszValue);
                    if (rc == VERR_NOT_FOUND || RT_FAILURE(rc2))
                        rc = rc2 == VINF_NO_CHANGE ? VINF_SUCCESS : rc2;
                }
            }

            RTCritSectLeave(&pCache->CritSect);
        }
    }
    else
    {
        AssertFailed();
        rc = VERR_FILENAME_TOO_LONG;
    }
    return rc;
}


/**
 * Flushes the cache by writing every item regardless of its state.
 *
 * @returns VBox status code.
 * @param   pCache          The property cache.
 */
int VGSvcPropCacheFlush(PVBOXSERVICEVEPROPCACHE pCache)
{
    AssertPtrReturn(pCache, VERR_INVALID_POINTER);

    int rc = RTCritSectEnter(&pCache->CritSect);
    if (RT_SUCCESS(rc))
    {
        PVBOXSERVICEVEPROPCACHEENTRY pNodeIt;
        RTListForEach(&pCache->NodeHead, pNodeIt, VBOXSERVICEVEPROPCACHEENTRY, NodeSucc)
        {
            int rc2 = vgsvcPropCacheWriteProp(pCache->pClient, pNodeIt->pszName, pNodeIt->fFlags, pNodeIt->pszValue);
            if (RT_FAILURE(rc2) && RT_SUCCESS(rc))
                rc = rc2;
        }
        RTCritSectLeave(&pCache->CritSect);
    }
    return rc;
}


/**
 * Reset all temporary properties and destroy the cache.
 *
 * @param   pCache          The property cache.
 */
void VGSvcPropCacheDestroy(PVBOXSERVICEVEPROPCACHE pCache)
{
    AssertPtrReturnVoid(pCache);
    AssertReturnVoid(pCache->pClient);

    /* Lock the cache. */
    int rc = RTCritSectEnter(&pCache->CritSect);
    AssertRC(rc);
    if (RT_SUCCESS(rc))
    {
        /* Destroy all the entries, writing the reset value for the temporary ones. */
        PVBOXSERVICEVEPROPCACHEENTRY pNode, pNextNode;
        RTListForEachSafe(&pCache->NodeHead, pNode, pNextNode, VBOXSERVICEVEPROPCACHEENTRY, NodeSucc)
        {
            AssertPtr(pNode->pszName);
            RTListNodeRemove(&pNode->NodeSucc);

            if (pNode->fFlags & VGSVCPROPCACHE_FLAGS_TEMPORARY)
                vgsvcPropCacheWriteProp(pCache->pClient, pNode->pszName, pNode->fFlags, pNode->pszValueReset);

            RTStrFree(pNode->pszName);
            pNode->pszName       = NULL;
            RTStrFree(pNode->pszValue);
            pNode->pszValue      = NULL;
            RTStrFree(pNode->pszValueReset);
            pNode->pszValueReset = NULL;
            pNode->fFlags        = 0;
            RTMemFree(pNode);
        }

        RTCritSectLeave(&pCache->CritSect);
    }

    /* Destroy critical section. */
    RTCritSectDelete(&pCache->CritSect);
    pCache->pClient = NULL;
}

