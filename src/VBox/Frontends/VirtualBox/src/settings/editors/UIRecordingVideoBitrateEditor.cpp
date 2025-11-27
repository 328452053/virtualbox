/* $Id: UIRecordingVideoBitrateEditor.cpp 111922 2025-11-27 13:03:56Z serkan.bayraktar@oracle.com $ */
/** @file
 * VBox Qt GUI - UIRecordingVideoBitrateEditor class implementation.
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
#include <QGridLayout>
#include <QLabel>
#include <QSpinBox>

/* GUI includes: */
#include "QIAdvancedSlider.h"
#include "UICommon.h"
#include "UIRecordingVideoBitrateEditor.h"

/* Defines: */
#define VIDEO_CAPTURE_BIT_RATE_MIN 32
#define VIDEO_CAPTURE_BIT_RATE_MAX 2048


UIRecordingVideoBitrateEditor::UIRecordingVideoBitrateEditor(QWidget *pParent /* = 0 */, bool fShowInBasicMode /* = false */)
    : UIEditor(pParent, fShowInBasicMode)
    , m_pLabel(0)
    , m_pWidgetBitRateSettings(0)
    , m_pSliderQuality(0)
    , m_pSpinbox(0)
    , m_pLabelMin(0)
    , m_pLabelMed(0)
    , m_pLabelMax(0)
    , m_pLayout(0)
{
    prepare();
}

void UIRecordingVideoBitrateEditor::setBitrate(int iRate)
{
    if (!m_pSpinbox || m_pSpinbox->value() == iRate)
        return;
    m_pSpinbox->setValue(iRate);
}

int UIRecordingVideoBitrateEditor::bitrate() const
{
    return m_pSpinbox ? m_pSpinbox->value() : 0;
}

void UIRecordingVideoBitrateEditor::setQuality(int iQuality)
{
    if (!m_pSliderQuality || m_pSliderQuality->value() == iQuality)
        return;
    m_pSliderQuality->setValue(iQuality);
}

int UIRecordingVideoBitrateEditor::quality() const
{
    return m_pSliderQuality ? m_pSliderQuality->value() : 0;
}

int UIRecordingVideoBitrateEditor::minimumLabelHorizontalHint() const
{
    return m_pLabel ? m_pLabel->minimumSizeHint().width() : 0;
}

void UIRecordingVideoBitrateEditor::setMinimumLayoutIndent(int iIndent)
{
    if (m_pLayout)
        m_pLayout->setColumnMinimumWidth(0, iIndent + m_pLayout->spacing());
}

void UIRecordingVideoBitrateEditor::sltRetranslateUI()
{
    m_pLabel->setText(tr("&Bitrate"));
    m_pSliderQuality->setToolTip(tr("Bitrate. Increasing this value will make the video "
                                    "look better at the cost of an increased file size."));
    m_pSpinbox->setSuffix(QString(" %1").arg(tr("kbps")));
    m_pSpinbox->setToolTip(tr("Bitrate in kilobits per second. Increasing this value "
                                     "will make the video look better at the cost of an increased file size."));
    m_pLabelMin->setText(tr("low", "quality"));
    m_pLabelMed->setText(tr("medium", "quality"));
    m_pLabelMax->setText(tr("high", "quality"));
}

void UIRecordingVideoBitrateEditor::sltHandleBitRateSliderChange()
{
    emit sigBitrateQualitySliderChanged();
}

void UIRecordingVideoBitrateEditor::sltHandleBitRateSpinboxChange()
{
    emit sigBitrateChanged(m_pSpinbox->value());
}

void UIRecordingVideoBitrateEditor::prepare()
{
    /* Prepare everything: */
    prepareWidgets();
    prepareConnections();

    /* Apply language settings: */
    sltRetranslateUI();
}

void UIRecordingVideoBitrateEditor::prepareWidgets()
{
    /* Prepare main layout: */
    m_pLayout = new QGridLayout(this);
    if (m_pLayout)
    {
        m_pLayout->setContentsMargins(0, 0, 0, 0);

        /* Prepare recording bit rate label: */
        m_pLabel = new QLabel(this);
        if (m_pLabel)
        {
            m_pLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
            m_pLayout->addWidget(m_pLabel, 0, 0);
        }
        /* Prepare recording bit rate widget: */
        m_pWidgetBitRateSettings = new QWidget(this);
        if (m_pWidgetBitRateSettings)
        {
            /* Prepare recording bit rate layout: */
            QVBoxLayout *pLayoutRecordingBitRate = new QVBoxLayout(m_pWidgetBitRateSettings);
            if (pLayoutRecordingBitRate)
            {
                pLayoutRecordingBitRate->setContentsMargins(0, 0, 0, 0);

                /* Prepare recording bit rate slider: */
                m_pSliderQuality = new QIAdvancedSlider(m_pWidgetBitRateSettings);
                if (m_pSliderQuality)
                {
                    m_pSliderQuality->setOrientation(Qt::Horizontal);
                    m_pSliderQuality->setMinimum(1);
                    m_pSliderQuality->setMaximum(10);
                    m_pSliderQuality->setPageStep(1);
                    m_pSliderQuality->setSingleStep(1);
                    m_pSliderQuality->setTickInterval(1);
                    m_pSliderQuality->setSnappingEnabled(true);
                    m_pSliderQuality->setOptimalHint(1, 5);
                    m_pSliderQuality->setWarningHint(5, 9);
                    m_pSliderQuality->setErrorHint(9, 10);

                    pLayoutRecordingBitRate->addWidget(m_pSliderQuality);
                }
                /* Prepare recording bit rate scale layout: */
                QHBoxLayout *pLayoutRecordingBitRateScale = new QHBoxLayout;
                if (pLayoutRecordingBitRateScale)
                {
                    pLayoutRecordingBitRateScale->setContentsMargins(0, 0, 0, 0);

                    /* Prepare recording bit rate min label: */
                    m_pLabelMin = new QLabel(m_pWidgetBitRateSettings);
                    if (m_pLabelMin)
                        pLayoutRecordingBitRateScale->addWidget(m_pLabelMin);
                    pLayoutRecordingBitRateScale->addStretch();
                    /* Prepare recording bit rate med label: */
                    m_pLabelMed = new QLabel(m_pWidgetBitRateSettings);
                    if (m_pLabelMed)
                        pLayoutRecordingBitRateScale->addWidget(m_pLabelMed);
                    pLayoutRecordingBitRateScale->addStretch();
                    /* Prepare recording bit rate max label: */
                    m_pLabelMax = new QLabel(m_pWidgetBitRateSettings);
                    if (m_pLabelMax)
                        pLayoutRecordingBitRateScale->addWidget(m_pLabelMax);

                    pLayoutRecordingBitRate->addLayout(pLayoutRecordingBitRateScale);
                }
            }

            m_pLayout->addWidget(m_pWidgetBitRateSettings, 0, 1);
        }
        /* Prepare recording bit rate spinbox: */
        m_pSpinbox = new QSpinBox(this);
        if (m_pSpinbox)
        {
            if (m_pLabel)
                m_pLabel->setBuddy(m_pSpinbox);
            uiCommon().setMinimumWidthAccordingSymbolCount(m_pSpinbox, 5);
            m_pSpinbox->setMinimum(VIDEO_CAPTURE_BIT_RATE_MIN);
            m_pSpinbox->setMaximum(VIDEO_CAPTURE_BIT_RATE_MAX);

            m_pLayout->addWidget(m_pSpinbox, 0, 2);
        }
    }
}

void UIRecordingVideoBitrateEditor::prepareConnections()
{
    connect(m_pSliderQuality, &QIAdvancedSlider::valueChanged,
            this, &UIRecordingVideoBitrateEditor::sltHandleBitRateSliderChange);
    connect(m_pSpinbox, &QSpinBox::valueChanged,
            this, &UIRecordingVideoBitrateEditor::sltHandleBitRateSpinboxChange);
}
