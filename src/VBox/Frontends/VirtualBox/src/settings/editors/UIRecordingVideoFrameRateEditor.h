/* $Id: UIRecordingVideoFrameRateEditor.h 111878 2025-11-26 09:42:09Z serkan.bayraktar@oracle.com $ */
/** @file
 * VBox Qt GUI - UIRecordingVideoFrameRateEditor class declaration.
 */

/*
 * Copyright (C) 2006-2025 Oracle and/or its affiliates.
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

#ifndef FEQT_INCLUDED_SRC_settings_editors_UIRecordingVideoFrameRateEditor_h
#define FEQT_INCLUDED_SRC_settings_editors_UIRecordingVideoFrameRateEditor_h
#ifndef RT_WITHOUT_PRAGMA_ONCE
# pragma once
#endif

/* GUI includes: */
#include "UIEditor.h"

/* Forward declarations: */
class QLabel;
class QSpinBox;
class QWidget;
class QIAdvancedSlider;

/** UIEditor sub-class used as a recording settings editor. */
class SHARED_LIBRARY_STUFF UIRecordingVideoFrameRateEditor : public UIEditor
{
    Q_OBJECT;

signals:

    void sigFrameRateChanged(int iFrameRate);

public:

    /** Constructs editor passing @a pParent to the base-class. */
    UIRecordingVideoFrameRateEditor(QWidget *pParent = 0, bool fShowInBasicMode = false);

    /** Defines frame @a iRate. */
    void setFrameRate(int iRate);
    /** Returns frame rate. */
    int frameRate() const;

private slots:

    /** Handles translation event. */
    virtual void sltRetranslateUI() RT_OVERRIDE RT_FINAL;
    /** Handles frame rate slider change. */
    void sltHandleFrameRateSliderChange();
    /** Handles frame rate spinbox change. */
    void sltHandleFrameRateSpinboxChange();

private:

    /** Prepares all. */
    void prepare();
    /** Prepares widgets. */
    void prepareWidgets();
    /** Prepares connections. */
    void prepareConnections();


    /** @name Widgets
     * @{ */
        /** Holds the frame rate label instance. */
        QLabel             *m_pLabelFrameRate;
        /** Holds the frame rate settings widget instance. */
        QWidget            *m_pWidgetFrameRateSettings;
        /** Holds the frame rate slider instance. */
        QIAdvancedSlider   *m_pSliderFrameRate;
        /** Holds the frame rate spinbox instance. */
        QSpinBox           *m_pSpinboxFrameRate;
        /** Holds the frame rate min label instance. */
        QLabel             *m_pLabelFrameRateMin;
        /** Holds the frame rate max label instance. */
        QLabel             *m_pLabelFrameRateMax;
    /** @} */
};

#endif /* !FEQT_INCLUDED_SRC_settings_editors_UIRecordingVideoFrameRateEditor_h */
