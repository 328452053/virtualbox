/* $Id: UIRecordingVideoFrameRateEditor.cpp 111878 2025-11-26 09:42:09Z serkan.bayraktar@oracle.com $ */
/** @file
 * VBox Qt GUI - UIRecordingVideoFrameRateEditor class implementation.
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
#include <QLabel>
#include <QSpinBox>

/* GUI includes: */
#include "QIAdvancedSlider.h"
#include "UIRecordingVideoFrameRateEditor.h"
#include "UICommon.h"

UIRecordingVideoFrameRateEditor::UIRecordingVideoFrameRateEditor(QWidget *pParent /* = 0 */, bool fShowInBasicMode /* = false */)
    : UIEditor(pParent, fShowInBasicMode /* show in basic mode */)
    , m_pLabelFrameRate(0)
    , m_pWidgetFrameRateSettings(0)
    , m_pSliderFrameRate(0)
    , m_pSpinboxFrameRate(0)
    , m_pLabelFrameRateMin(0)
    , m_pLabelFrameRateMax(0)
{
    prepare();
}

void UIRecordingVideoFrameRateEditor::setFrameRate(int iRate)
{
    if (!m_pSpinboxFrameRate)
        return;
    if (m_pSpinboxFrameRate->value() != iRate)
            m_pSpinboxFrameRate->setValue(iRate);
}

int UIRecordingVideoFrameRateEditor::frameRate() const
{
    if (m_pSpinboxFrameRate)
        return m_pSpinboxFrameRate->value();
    if (m_pSliderFrameRate)
        return m_pSliderFrameRate->value();
    return 0;
}

void UIRecordingVideoFrameRateEditor::sltRetranslateUI()
{
    m_pLabelFrameRate->setText(tr("Frame R&ate"));
    m_pSliderFrameRate->setToolTip(tr("Maximum number of frames per second. Additional frames "
                                      "will be skipped. Reducing this value will increase the number of skipped "
                                      "frames and reduce the file size."));
    m_pSpinboxFrameRate->setSuffix(QString(" %1").arg(tr("fps")));
    m_pSpinboxFrameRate->setToolTip(tr("Maximum number of frames per second. Additional frames "
                                       "will be skipped. Reducing this value will increase the number of skipped "
                                       "frames and reduce the file size."));
    m_pLabelFrameRateMin->setText(tr("%1 fps").arg(m_pSliderFrameRate->minimum()));
    m_pLabelFrameRateMin->setToolTip(tr("Minimum recording frame rate"));
    m_pLabelFrameRateMax->setText(tr("%1 fps").arg(m_pSliderFrameRate->maximum()));
    m_pLabelFrameRateMax->setToolTip(tr("Maximum recording frame rate"));
}

void UIRecordingVideoFrameRateEditor::sltHandleFrameRateSliderChange()
{
    /* Apply proposed frame-rate: */
    m_pSpinboxFrameRate->blockSignals(true);
    m_pSpinboxFrameRate->setValue(m_pSliderFrameRate->value());
    m_pSpinboxFrameRate->blockSignals(false);
    emit sigFrameRateChanged(m_pSliderFrameRate->value());
}

void UIRecordingVideoFrameRateEditor::sltHandleFrameRateSpinboxChange()
{
    /* Apply proposed frame-rate: */
    m_pSliderFrameRate->blockSignals(true);
    m_pSliderFrameRate->setValue(m_pSpinboxFrameRate->value());
    m_pSliderFrameRate->blockSignals(false);
    emit sigFrameRateChanged(m_pSpinboxFrameRate->value());
}

void UIRecordingVideoFrameRateEditor::prepare()
{
    /* Prepare everything: */
    prepareWidgets();
    prepareConnections();

    /* Apply language settings: */
    sltRetranslateUI();
}

void UIRecordingVideoFrameRateEditor::prepareWidgets()
{
    /* Prepare main layout: */
    QHBoxLayout *pLayout = new QHBoxLayout(this);
    if (pLayout)
    {
        pLayout->setContentsMargins(0, 0, 0, 0);

        /* Prepare recording frame rate label: */
        m_pLabelFrameRate = new QLabel(this);
        if (m_pLabelFrameRate)
        {
            m_pLabelFrameRate->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
            pLayout->addWidget(m_pLabelFrameRate);
        }

        /* Prepare recording frame rate widget: */
        m_pWidgetFrameRateSettings = new QWidget(this);
        if (m_pWidgetFrameRateSettings)
        {
            /* Prepare recording frame rate layout: */
            QVBoxLayout *pLayoutRecordingFrameRate = new QVBoxLayout(m_pWidgetFrameRateSettings);
            if (pLayoutRecordingFrameRate)
            {
                pLayoutRecordingFrameRate->setContentsMargins(0, 0, 0, 0);

                /* Prepare recording frame rate slider: */
                m_pSliderFrameRate = new QIAdvancedSlider(m_pWidgetFrameRateSettings);
                if (m_pSliderFrameRate)
                {
                    m_pSliderFrameRate->setOrientation(Qt::Horizontal);
                    m_pSliderFrameRate->setMinimum(1);
                    m_pSliderFrameRate->setMaximum(30);
                    m_pSliderFrameRate->setPageStep(1);
                    m_pSliderFrameRate->setSingleStep(1);
                    m_pSliderFrameRate->setTickInterval(1);
                    m_pSliderFrameRate->setSnappingEnabled(true);
                    m_pSliderFrameRate->setOptimalHint(1, 25);
                    m_pSliderFrameRate->setWarningHint(25, 30);

                    pLayoutRecordingFrameRate->addWidget(m_pSliderFrameRate);
                }
                /* Prepare recording frame rate scale layout: */
                QHBoxLayout *pLayoutRecordingFrameRateScale = new QHBoxLayout;
                if (pLayoutRecordingFrameRateScale)
                {
                    pLayoutRecordingFrameRateScale->setContentsMargins(0, 0, 0, 0);

                    /* Prepare recording frame rate min label: */
                    m_pLabelFrameRateMin = new QLabel(m_pWidgetFrameRateSettings);
                    if (m_pLabelFrameRateMin)
                        pLayoutRecordingFrameRateScale->addWidget(m_pLabelFrameRateMin);
                    pLayoutRecordingFrameRateScale->addStretch();
                    /* Prepare recording frame rate max label: */
                    m_pLabelFrameRateMax = new QLabel(m_pWidgetFrameRateSettings);
                    if (m_pLabelFrameRateMax)
                        pLayoutRecordingFrameRateScale->addWidget(m_pLabelFrameRateMax);

                    pLayoutRecordingFrameRate->addLayout(pLayoutRecordingFrameRateScale);
                }
            }
            pLayout->addWidget(m_pWidgetFrameRateSettings);
        }
        /* Prepare recording frame rate spinbox: */
        m_pSpinboxFrameRate = new QSpinBox(this);
        if (m_pSpinboxFrameRate)
        {
            if (m_pLabelFrameRate)
                m_pLabelFrameRate->setBuddy(m_pSpinboxFrameRate);
            uiCommon().setMinimumWidthAccordingSymbolCount(m_pSpinboxFrameRate, 3);
            m_pSpinboxFrameRate->setMinimum(1);
            m_pSpinboxFrameRate->setMaximum(30);
            pLayout->addWidget(m_pSpinboxFrameRate);
        }
    }
}


void UIRecordingVideoFrameRateEditor::prepareConnections()
{
    connect(m_pSliderFrameRate, &QIAdvancedSlider::valueChanged,
            this, &UIRecordingVideoFrameRateEditor::sltHandleFrameRateSliderChange);
    connect(m_pSpinboxFrameRate, &QSpinBox::valueChanged,
            this, &UIRecordingVideoFrameRateEditor::sltHandleFrameRateSpinboxChange);
}
