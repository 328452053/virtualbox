/* $Id: UIRecordingAudioProfileEditor.cpp 111969 2025-12-02 07:59:05Z serkan.bayraktar@oracle.com $ */
/** @file
 * VBox Qt GUI - UIRecordingAudioProfileEditor class implementation.
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

/* Qt includes: */
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QSpinBox>

/* GUI includes: */
#include "QIAdvancedSlider.h"
#include "UIRecordingAudioProfileEditor.h"


UIRecordingAudioProfileEditor::UIRecordingAudioProfileEditor(QWidget *pParent /* = 0 */, bool fShowInBasicMode /* = false */)
    : UIEditor(pParent, fShowInBasicMode)
    , m_pLayout(0)
    , m_pLabel(0)
    , m_pSlider(0)
    , m_pLabelMin(0)
    , m_pLabelMed(0)
    , m_pLabelMax(0)
{
    prepare();
}

int UIRecordingAudioProfileEditor::minimumLabelHorizontalHint() const
{
    return m_pLabel ? m_pLabel->minimumSizeHint().width() : 0;
}

void UIRecordingAudioProfileEditor::setMinimumLayoutIndent(int iIndent)
{
    if (m_pLayout)
        m_pLayout->setColumnMinimumWidth(0, iIndent + m_pLayout->spacing());
}

void UIRecordingAudioProfileEditor::setAudioProfile(const QString &strProfile)
{
    /* Update cached value and
     * slider if value has changed: */
    if (m_strAudioProfile != strProfile)
    {
        m_strAudioProfile = strProfile;
        if (m_pSlider)
        {
            const QStringList profiles = QStringList() << "low" << "med" << "high";
            int iIndexOfProfile = profiles.indexOf(m_strAudioProfile);
            if (iIndexOfProfile == -1)
                iIndexOfProfile = 1; // "med" by default
            m_pSlider->setValue(iIndexOfProfile);
        }
    }
}

QString UIRecordingAudioProfileEditor::audioProfile() const
{
    if (m_pSlider)
    {
        const QStringList profiles = QStringList() << "low" << "med" << "high";
        return profiles.value(m_pSlider->value(), "med" /* by default */);
    }
    return m_strAudioProfile;
}


void UIRecordingAudioProfileEditor::sltRetranslateUI()
{
    m_pLabel->setText(tr("&Audio Profile"));
    m_pSlider->setToolTip(tr("Audio profile. Increasing this value will make the audio "
                                         "sound better at the cost of an increased file size."));
    m_pLabelMin->setText(tr("low", "profile"));
    m_pLabelMed->setText(tr("medium", "profile"));
    m_pLabelMax->setText(tr("high", "profile"));
}

void UIRecordingAudioProfileEditor::prepare()
{
    /* Prepare everything: */
    prepareWidgets();
    prepareConnections();

    /* Apply language settings: */
    sltRetranslateUI();
}

void UIRecordingAudioProfileEditor::prepareWidgets()
{
    /* Prepare main layout: */
    m_pLayout = new QGridLayout(this);
    if (m_pLayout)
    {
        m_pLayout->setContentsMargins(0, 0, 0, 0);

        /* Prepare recording audio profile label: */
        m_pLabel = new QLabel(this);
        if (m_pLabel)
        {
            m_pLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
            m_pLayout->addWidget(m_pLabel, 0, 0);
        }
        QWidget *pWidgetContainer = new QWidget(this);
        if (pWidgetContainer)
        {
            pWidgetContainer->setSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Preferred);
            /* Prepare recording audio profile layout: */
            QVBoxLayout *pLayoutRecordingAudioProfile = new QVBoxLayout(pWidgetContainer);
            if (pLayoutRecordingAudioProfile)
            {
                pLayoutRecordingAudioProfile->setContentsMargins(0, 0, 0, 0);

                /* Prepare recording audio profile slider: */
                m_pSlider = new QIAdvancedSlider(this);
                if (m_pSlider)
                {
                    if (m_pLabel)
                        m_pLabel->setBuddy(m_pSlider);
                    m_pSlider->setOrientation(Qt::Horizontal);
                    m_pSlider->setMinimum(0);
                    m_pSlider->setMaximum(2);
                    m_pSlider->setPageStep(1);
                    m_pSlider->setSingleStep(1);
                    m_pSlider->setTickInterval(1);
                    m_pSlider->setSnappingEnabled(true);
                    m_pSlider->setOptimalHint(0, 1);
                    m_pSlider->setWarningHint(1, 2);

                    pLayoutRecordingAudioProfile->addWidget(m_pSlider);
                }
                /* Prepare recording audio profile scale layout: */
                QHBoxLayout *pLayoutRecordingAudioProfileScale = new QHBoxLayout;
                if (pLayoutRecordingAudioProfileScale)
                {
                    pLayoutRecordingAudioProfileScale->setContentsMargins(0, 0, 0, 0);

                    /* Prepare recording audio profile min label: */
                    m_pLabelMin = new QLabel(this);
                    if (m_pLabelMin)
                        pLayoutRecordingAudioProfileScale->addWidget(m_pLabelMin);
                    pLayoutRecordingAudioProfileScale->addStretch();
                    /* Prepare recording audio profile med label: */
                    m_pLabelMed = new QLabel(this);
                    if (m_pLabelMed)
                        pLayoutRecordingAudioProfileScale->addWidget(m_pLabelMed);
                    pLayoutRecordingAudioProfileScale->addStretch();
                    /* Prepare recording audio profile max label: */
                    m_pLabelMax = new QLabel(this);
                    if (m_pLabelMax)
                        pLayoutRecordingAudioProfileScale->addWidget(m_pLabelMax);

                    pLayoutRecordingAudioProfile->addLayout(pLayoutRecordingAudioProfileScale);
                }
            }
            m_pLayout->addWidget(pWidgetContainer, 0, 1);
        }
    }
}

void UIRecordingAudioProfileEditor::prepareConnections()
{
}
