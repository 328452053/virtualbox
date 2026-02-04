/* $Id: UIDockIconPreview.h 112817 2026-02-04 13:07:18Z sergey.dubov@oracle.com $ */
/** @file
 * VBox Qt GUI - UIDockIconPreview class declaration.
 */

/*
 * Copyright (C) 2009-2026 Oracle and/or its affiliates.
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

#ifndef FEQT_INCLUDED_SRC_platform_darwin_UIDockIconPreview_h
#define FEQT_INCLUDED_SRC_platform_darwin_UIDockIconPreview_h
#ifndef RT_WITHOUT_PRAGMA_ONCE
# pragma once
#endif

/* Other VBox includes: */
#include <VBox/VBoxCocoa.h>

/* External includes: */
#include <ApplicationServices/ApplicationServices.h>

/* Forward declarations: */
class QPixmap;
class UIDockIconPreviewPrivate;
class UIFrameBuffer;
class UIMachine;

class UIDockIconPreview
{
public:

    UIDockIconPreview(UIMachine *pMachine, const QPixmap& overlayImage);
    ~UIDockIconPreview();

    void updateDockOverlay();
    void updateDockPreview(CGImageRef VMImage);
    void updateDockPreview(UIFrameBuffer *pFrameBuffer);

    void setOriginalSize(int aWidth, int aHeight);

private:

    UIDockIconPreviewPrivate *d;
};

class UIDockIconPreviewHelper
{
public:
    UIDockIconPreviewHelper(UIMachine *pMachine, const QPixmap& overlayImage);
    virtual ~UIDockIconPreviewHelper();
    void initPreviewImages();
    void drawOverlayIcons(CGContextRef context);

    void* currentPreviewWindowId() const;

    /* Flipping is necessary cause the drawing context in Mac OS X is flipped by 180 degree */
    CGRect flipRect(CGRect rect) const;
    CGRect centerRect(CGRect rect) const;
    CGRect centerRectTo(CGRect rect, const CGRect& toRect) const;

    /* Private member vars */
    UIMachine *m_pMachine;
    const CGRect m_dockIconRect;

    CGImageRef m_overlayImage;
    CGImageRef m_dockMonitor;
    CGImageRef m_dockMonitorGlossy;

    CGRect m_updateRect;
    CGRect m_monitorRect;
};

#endif /* !FEQT_INCLUDED_SRC_platform_darwin_UIDockIconPreview_h */
