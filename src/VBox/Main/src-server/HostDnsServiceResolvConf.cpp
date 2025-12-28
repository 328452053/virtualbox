/* $Id: HostDnsServiceResolvConf.cpp 112242 2025-12-28 15:50:23Z knut.osmundsen@oracle.com $ */
/** @file
 * Base class for Host DNS & Co services.
 */

/*
 * Copyright (C) 2014-2025 Oracle and/or its affiliates.
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

/* -*- indent-tabs-mode: nil; -*- */
#include <VBox/com/string.h>
#include <VBox/com/ptr.h>

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include <iprt/assert.h>
#include <iprt/errcore.h>
#include <iprt/critsect.h>
#include <iprt/file.h>
#include <iprt/net.h>
#include <iprt/stream.h>

#include <VBox/log.h>

#include "HostDnsService.h"


#define RCPS_MAX_NAMESERVERS 3
#define RCPS_MAX_SEARCHLIST 10
#define RCPS_BUFFER_SIZE 256
#define RCPS_IPVX_SIZE 47


struct HostDnsServiceResolvConf::Data
{
    Data(const char *fileName)
        : resolvConfFilename(fileName)
    {
    };

    com::Utf8Str resolvConfFilename;
};

HostDnsServiceResolvConf::~HostDnsServiceResolvConf()
{
    if (m)
    {
        delete m;
        m = NULL;
    }
}

HRESULT HostDnsServiceResolvConf::init(HostDnsMonitorProxy *pProxy, const char *aResolvConfFileName)
{
    HRESULT hrc = HostDnsServiceBase::init(pProxy);
    AssertComRCReturn(hrc, hrc);

    m = new Data(aResolvConfFileName);
    AssertPtrReturn(m, E_OUTOFMEMORY);

    return readResolvConf();
}

void HostDnsServiceResolvConf::uninit(void)
{
    if (m)
    {
        delete m;
        m = NULL;
    }

    HostDnsServiceBase::uninit();
}

const com::Utf8Str &HostDnsServiceResolvConf::getResolvConf(void) const
{
    return m->resolvConfFilename;
}

HRESULT HostDnsServiceResolvConf::readResolvConf(void)
{
    HostDnsInformation dnsInfo;
    int vrc = i_rcpParse(m->resolvConfFilename.c_str(), dnsInfo);

    /** @todo r=jack: Why are we returning S_OK after a general failure? */
    if (vrc == -1)
        return S_OK;

    setInfo(dnsInfo);
    return S_OK;
}

int HostDnsServiceResolvConf::i_rcpParse(const char *filename, HostDnsInformation &dnsInfo)
{
    if (RT_UNLIKELY(filename == NULL /*impossible as c_str() never returns NULL*/ || *filename == '\0'))
        return VERR_INVALID_PARAMETER;

    PRTSTREAM stream;
    int vrc = RTStrmOpen(filename, "r", &stream);
    if (RT_FAILURE(vrc))
        return vrc;

    char buf[RCPS_BUFFER_SIZE];
    unsigned i = 0;
    for (;;)
    {
        vrc = RTStrmGetLine(stream, buf, sizeof(buf));
        if (RT_FAILURE(vrc))
        {
            if (vrc == VERR_EOF)
                vrc = VINF_SUCCESS;
            break;
        }

        /*
         * Strip comment if present.
         *
         * This is not how ad-hoc parser in bind's res_init.c does it,
         * btw, so this code will accept more input as valid compared
         * to res_init.  (e.g. "nameserver 1.1.1.1; comment" is
         * misparsed by res_init).
         */
        char *s;
        for (s = buf; *s != '\0'; ++s)
        {
            if (*s == '#' || *s == ';')
            {
                *s = '\0';
                break;
            }
        }

        char *tok = i_getToken(buf, &s);
        if (tok == NULL)
            continue;


        /*
         * NAMESERVER
         */
        if (RTStrCmp(tok, "nameserver") == 0)
        {
            if (RT_UNLIKELY(dnsInfo.servers.size() >= RCPS_MAX_NAMESERVERS))
            {
                LogRel(("HostDnsServiceResolvConf: too many nameserver lines, ignoring %s\n", s));
                continue;
            }

            /*
             * parse next token as an IP address
             */
            tok = i_getToken(NULL, &s);
            char * const pszAddr = tok;
            if (tok == NULL)
            {
                LogRel(("HostDnsServiceResolvConf: nameserver line without value\n"));
                continue;
            }

            RTNETADDR NetAddr = { { {0, 0} }, RTNETADDRTYPE_INVALID, RTNETADDR_PORT_NA };

            /* Check if entry is IPv4 nameserver, save if true */
            char *pszNext = NULL;
            vrc = RTNetStrToIPv4AddrEx(tok, &NetAddr.uAddr.IPv4, &pszNext);
            if (RT_SUCCESS(vrc))
            {
                if (*pszNext == '\0')
                    NetAddr.enmType = RTNETADDRTYPE_IPV4;
                else
                {
                    LogRel(("HostDnsServiceResolvConf: garbage at the end of IPv4 address %s\n", tok));
                    continue;
                }

                LogRel(("HostDnsServiceResolvConf: IPv4 nameserver %RTnaddr\n", &NetAddr));

                RTStrPurgeEncoding(pszAddr);
                dnsInfo.servers.push_back(pszAddr);
            }

            /* Check if entry is IPv6 nameserver, save if true */
            /** @todo r=bird: Why try IPv6 parsing if IPv4 succeeded? */
            vrc = RTNetStrToIPv6AddrEx(tok, &NetAddr.uAddr.IPv6, &pszNext);
            if (RT_SUCCESS(vrc))
            {
                if (*pszNext == '%') /** @todo XXX: TODO: IPv6 zones */
                {
                    size_t zlen = RTStrOffCharOrTerm(pszNext, '.');
                    LogRel(("HostDnsServiceResolvConf: FIXME: ignoring IPv6 zone %*.*s\n",
                            zlen, zlen, pszNext));
                    pszNext += zlen;
                }

                if (*pszNext == '\0')
                    NetAddr.enmType = RTNETADDRTYPE_IPV6;
                else
                {
                    LogRel(("HostDnsServiceResolvConf: garbage at the end of IPv6 address %s\n", tok));
                    continue;
                }

                LogRel(("HostDnsServiceResolvConf: IPv6 nameserver %RTnaddr\n", &NetAddr));

                RTStrPurgeEncoding(pszAddr);
                dnsInfo.serversV6.push_back(pszAddr);
            }

            if (NetAddr.enmType == RTNETADDRTYPE_INVALID)
            {
                LogRel(("HostDnsServiceResolvConf: bad nameserver address %s\n", tok));
                continue;
            }


            tok = i_getToken(NULL, &s);
            if (tok != NULL)
                LogRel(("HostDnsServiceResolvConf: ignoring unexpected trailer on the nameserver line\n"));
        }
        /*
         * DOMAIN
         */
        else if (RTStrCmp(tok, "domain") == 0)
        {
            if (dnsInfo.domain.isNotEmpty())
            {
                LogRel(("HostDnsServiceResolvConf: ignoring multiple domain lines\n"));
                continue;
            }

            tok = i_getToken(NULL, &s);
            if (tok == NULL)
            {
                LogRel(("HostDnsServiceResolvConf: domain line without value\n"));
                continue;
            }

            /** @todo r=bird: RTStrNLen is pointless here, use strlen. */
            if (RTStrNLen(tok, 255) > 253) /* Max FQDN Length */
            {
                LogRel(("HostDnsServiceResolvConf: domain name too long\n"));
                continue;
            }

            RTStrPurgeEncoding(tok);
            dnsInfo.domain = tok;
        }
        /*
         * SEARCH
         */
        else if (RTStrCmp(tok, "search") == 0)
        {
            while ((tok = i_getToken(NULL, &s)) && tok != NULL)
            {
                if (RT_UNLIKELY(i >= RCPS_MAX_SEARCHLIST))
                {
                    LogRel(("HostDnsServiceResolvConf: too many search domains, ignoring %s\n", tok));
                    continue;
                }

                LogRel(("HostDnsServiceResolvConf: search domain %s", tok));

                RTStrPurgeEncoding(tok);
                dnsInfo.searchList.push_back(tok);
            }
        }
        else
            LogRel(("HostDnsServiceResolvConf: ignoring \"%s %s\"\n", tok, s));
    }

    RTStrmClose(stream);
    return vrc;
}

char *HostDnsServiceResolvConf::i_getToken(char *psz, char **ppszSavePtr)
{
    AssertPtrReturn(ppszSavePtr, NULL);

    if (psz == NULL)
    {
        psz = *ppszSavePtr;
        if (psz == NULL)
            return NULL;
    }

    /* skip leading blanks. */
    while (*psz == ' ' || *psz == '\t')
        ++psz;

    if (*psz == '\0')
    {
        *ppszSavePtr = NULL;
        return NULL;
    }

    /* Found the start of the token we will be returning. */
    char * const pszToken = psz;

    /* Find the end so we can terminate it. */
    while (*psz && *psz != ' ' && *psz != '\t')
        ++psz;

    if (*psz == '\0')
        psz = NULL;
    else
        *psz++ = '\0';

    *ppszSavePtr = psz;
    return pszToken;
}
