/* $Id: UIRecordingFilePathEditor.cpp 111878 2025-11-26 09:42:09Z serkan.bayraktar@oracle.com $ */
/** @file
 * VBox Qt GUI - UIRecordingFilePathEditor class implementation.
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

/* GUI includes: */
#include "UIFilePathSelector.h"
#include "UIRecordingFilePathEditor.h"

UIRecordingFilePathEditor::UIRecordingFilePathEditor(QWidget *pParent /* = 0 */, bool fShowInBasicMode /* = false */)
    : UIEditor(pParent, fShowInBasicMode /* show in basic mode */)
    , m_pLabelFilePath(0)
    , m_pEditorFilePath(0)
{
    prepare();
}

void UIRecordingFilePathEditor::setFolder(const QString &strFolder)
{
    if (!m_pEditorFilePath || m_pEditorFilePath->initialPath() == strFolder)
        return;
    m_pEditorFilePath->setInitialPath(strFolder);
}

QString UIRecordingFilePathEditor::folder() const
{
    return m_pEditorFilePath ? m_pEditorFilePath->initialPath() : QString();
}

void UIRecordingFilePathEditor::setFilePath(const QString &strFilePath)
{
    if (!m_pEditorFilePath || m_pEditorFilePath->path() == strFilePath)
        return;
    m_pEditorFilePath->setPath(strFilePath);
}

QString UIRecordingFilePathEditor::filePath() const
{
    return m_pEditorFilePath ? m_pEditorFilePath->path() : QString();
}

void UIRecordingFilePathEditor::sltRetranslateUI()
{
    m_pLabelFilePath->setText(tr("File &Path"));
    m_pEditorFilePath->setToolTip(tr("The filename VirtualBox uses to save the recorded content"));
}

void UIRecordingFilePathEditor::prepare()
{
    /* Prepare everything: */
    prepareWidgets();
    prepareConnections();

    /* Apply language settings: */
    sltRetranslateUI();
}

void UIRecordingFilePathEditor::prepareWidgets()
{
    /* Prepare main layout: */
    QHBoxLayout *pLayout = new QHBoxLayout(this);
    if (pLayout)
    {
        pLayout->setContentsMargins(0, 0, 0, 0);


        /* Prepare recording file path label: */
        m_pLabelFilePath = new QLabel(this);
        if (m_pLabelFilePath)
        {
            m_pLabelFilePath->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
            pLayout->addWidget(m_pLabelFilePath);
            pLayout->setAlignment(m_pLabelFilePath, Qt::AlignLeft);
        }

        /* Prepare recording file path editor: */
        m_pEditorFilePath = new UIFilePathSelector(this);
        if (m_pEditorFilePath)
        {
            if (m_pLabelFilePath)
                m_pLabelFilePath->setBuddy(m_pEditorFilePath);
            m_pEditorFilePath->setEditable(false);
            m_pEditorFilePath->setMode(UIFilePathSelector::Mode_File_Save);
            m_pEditorFilePath->setSizePolicy(QSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Fixed));
            pLayout->addWidget(m_pEditorFilePath);
        }

    }
}

void UIRecordingFilePathEditor::prepareConnections()
{
}

void UIRecordingFilePathEditor::filterOut(bool fExpertMode, const QString &strFilter, const QMap<QString, QVariant> &flags)
{
    UIEditor::filterOut(fExpertMode, strFilter, flags);
}
