/* $Id: UIRecordingAudioProfileEditor.h 111969 2025-12-02 07:59:05Z serkan.bayraktar@oracle.com $ */
/** @file
 * VBox Qt GUI - UIRecordingAudioProfileEditor class declaration.
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

#ifndef FEQT_INCLUDED_SRC_settings_editors_UIRecordingAudioProfileEditor_h
#define FEQT_INCLUDED_SRC_settings_editors_UIRecordingAudioProfileEditor_h
#ifndef RT_WITHOUT_PRAGMA_ONCE
# pragma once
#endif

/* GUI includes: */
#include "UIEditor.h"
#include "UISettingsDefs.h"

/* COM includes: */
#include "KRecordingCodecDeadline.h"

/* Forward declarations: */
class QGridLayout;
class QLabel;
class QIAdvancedSlider;

/** UIEditor sub-class used as a recording settings editor. */
class SHARED_LIBRARY_STUFF UIRecordingAudioProfileEditor : public UIEditor
{
    Q_OBJECT;

public:

    /** Constructs editor passing @a pParent to the base-class. */
    UIRecordingAudioProfileEditor(QWidget *pParent = 0, bool fShowInBasicMode = false);

    /** Defines audio @a strProfile. */
    void setAudioProfile(const QString &strProfile);
    /** Returns audio profile. */
    QString audioProfile() const;

    /** Returns minimum layout hint. */
    int minimumLabelHorizontalHint() const;
    /** Defines minimum layout @a iIndent. */
    void setMinimumLayoutIndent(int iIndent);

private slots:

    /** Handles translation event. */
    virtual void sltRetranslateUI() RT_OVERRIDE RT_FINAL;

private:

    /** Prepares all. */
    void prepare();
    /** Prepares widgets. */
    void prepareWidgets();
    /** Prepares connections. */
    void prepareConnections();

    /** @name Values
     * @{ */
        /** Holds the audio profile. */
        QString                  m_strAudioProfile;
    /** @} */

    /** @name Widgets
     * @{ */
        /** Holds the main layout instance. */
        QGridLayout      *m_pLayout;
        /** Holds the audio profile label instance. */
        QLabel             *m_pLabel;
        /** Holds the audio profile slider instance. */
        QIAdvancedSlider   *m_pSlider;
        /** Holds the audio profile min label instance. */
        QLabel             *m_pLabelMin;
        /** Holds the audio profile med label instance. */
        QLabel             *m_pLabelMed;
        /** Holds the audio profile max label instance. */
        QLabel             *m_pLabelMax;
    /** @} */
};

#endif /* !FEQT_INCLUDED_SRC_settings_editors_UIRecordingAudioProfileEditor_h */
