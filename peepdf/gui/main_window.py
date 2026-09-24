#!/usr/bin/env python3
#
#    peepdf-3 is a tool to analyse and modify PDF files
#    https://github.com/digitalsleuth/peepdf-3
#    Original Author: Jose Miguel Esparza <jesparza AT eternal-todo.com>
#    Updated for Python 3 by Corey Forman (digitalsleuth - https://github.com/digitalsleuth/peepdf-3)
#    Copyright (C) 2011-2017 Jose Miguel Esparza
#
#    This file is part of peepdf-3.
#
#        peepdf-3 is free software: you can redistribute it and/or modify
#        it under the terms of the GNU General Public License as published by
#        the Free Software Foundation, either version 3 of the License, or
#        (at your option) any later version.
#
#        peepdf-3 is distributed in the hope that it will be useful,
#        but WITHOUT ANY WARRANTY; without even the implied warranty of
#        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#        GNU General Public License for more details.
#
#        You should have received a copy of the GNU General Public License
#        along with peepdf-3. If not, see <http://www.gnu.org/licenses/>.

"""
MainWindow for peepdf-3 GUI
"""

import builtins
import io
import os
import sys
from datetime import datetime as dt, timezone

from PyQt6.QtCore import QEvent, Qt, QProcess, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QFont, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QDialog,
    QFileDialog,
    QFrame,
    QInputDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSizeGrip,
    QSplitter,
    QStyle,
    QStyleFactory,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)
from prettytable import PrettyTable, TableStyle

try:
    from peepdf.PDFCore import PDFParser, VERSION
    import peepdf.PDFCore as pdfCoreModule
    from peepdf.PDFVulns import vulnsDict
    from peepdf.PDFConsole import PDFConsole, OCR_PAGE_WARNING_THRESHOLD
    from peepdf.PDFUtils import DTFMT
    from peepdf.PDFComments import (
        commentNotes,
        commentObjectTag,
        oneLine,
        printableText,
    )
except ModuleNotFoundError:
    from PDFCore import PDFParser, VERSION
    import PDFCore as pdfCoreModule
    from PDFVulns import vulnsDict
    from PDFConsole import PDFConsole, OCR_PAGE_WARNING_THRESHOLD
    from PDFUtils import DTFMT
    from PDFComments import commentNotes, commentObjectTag, oneLine, printableText


_ROOT_PATH = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
_CONSOLE_MUTATING_COMMANDS = frozenset(
    {
        "create",
        "decrypt",
        "embed",
        "encode_strings",
        "encrypt",
        "filters",
        "modify",
        "open",
        "replace",
        "save",
        "save_version",
    }
)
MONO_FONT = "Consolas" if os.name == "nt" else "Monospace"
MAX_COMMENT_ROWS = 5000


def hexdumpColumns(data, width=16, offsetFormat="hex"):
    """
    Hex viewer columns. offsetFormat is "hex" or "decimal".
    """
    if not data:
        return "", "", ""
    if isinstance(data, str):
        data = data.encode("latin-1")
    offsetLines = []
    hexLines = []
    asciiLines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        offsetLines.append(f"{i:08d}" if offsetFormat == "decimal" else f"{i:08x}")
        hexLines.append(" ".join(f"{b:02x}" for b in chunk))
        asciiLines.append("".join(chr(b) if 32 <= b < 127 else "." for b in chunk))
    return "\n".join(offsetLines), "\n".join(hexLines), "\n".join(asciiLines)


## UI Start ##


class _PDFParseWorker(QThread):
    """
    Set up threading to allow the UI a way to cancel working with large files.

    manualAnalysis defaults to True (skip automatic JS beautification and
    eval-hooking) since STPyV8 has no execution timeout.
    Pass manualAnalysis=False only for an explicit, user-initiated "Analyse JS" action.
    """

    resultReady = pyqtSignal(int, object, str)  # ret, pdf, errorMessage

    def __init__(self, fileName, parent=None, manualAnalysis=True, jsErrFile=None):
        super().__init__(parent)
        self.fileName = fileName
        self.manualAnalysis = manualAnalysis
        self.jsErrFile = jsErrFile

    def run(self):
        try:
            parser = PDFParser()
            ret, pdf = parser.parse(
                self.fileName,
                forceMode=True,
                looseMode=True,
                manualAnalysis=self.manualAnalysis,
                jsErrFile=self.jsErrFile,
            )
            self.resultReady.emit(ret, pdf, "")
        except Exception as exc:
            self.resultReady.emit(-1, None, str(exc))


class _ChangelogWorker(QThread):
    """
    Runs the 'changelog' console command off the GUI thread istead of reinventing
    the changelog for the GUI.
    """

    resultReady = pyqtSignal(str, str)  # output, errorMessage

    def __init__(self, pdf, parent=None):
        super().__init__(parent)
        self.pdf = pdf

    def run(self):
        try:
            console = PDFConsole(self.pdf, "", avoidOutputColors=True, isCommand=True)
            console.use_rawinput = False
            output, _ = MainWindow._captureConsoleCommand(console, "changelog detailed")
            self.resultReady.emit(output, "")
        except Exception as exc:
            self.resultReady.emit("", str(exc))


class _LoadingDialog(QDialog):
    canceled = pyqtSignal()

    def __init__(self, labelText, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Loading PDF")
        self.setWindowModality(Qt.WindowModality.WindowModal)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(labelText))
        self.progressBar = QProgressBar()
        self.progressBar.setRange(0, 0)
        self._progressBarStyle = QStyleFactory.create("Fusion")
        if self._progressBarStyle is not None:
            self.progressBar.setStyle(self._progressBarStyle)
        layout.addWidget(self.progressBar)

        buttonRow = QHBoxLayout()
        buttonRow.addStretch(1)
        cancelButton = QPushButton("Cancel")
        cancelButton.clicked.connect(self._onCancelClicked)
        buttonRow.addWidget(cancelButton)
        layout.addLayout(buttonRow)
        self.setFixedSize(self.sizeHint())

    def _onCancelClicked(self):
        self.canceled.emit()
        self.close()


class _ObjectTreeItem(QTreeWidgetItem):
    """
    The QTreeWidgetItem for the Object/Type tree.
    Enables sorting by Object or Type, retaining the grouping under Version.
    Also ensures that the Object numbers are treated as digits for sorting
    and not simply text.
    """

    def __lt__(self, other):
        if not isinstance(other, QTreeWidgetItem):
            return super().__lt__(other)
        myData = self.data(0, Qt.ItemDataRole.UserRole) or {}
        otherData = other.data(0, Qt.ItemDataRole.UserRole) or {}
        tree = self.treeWidget()
        if myData.get("kind") == "version" and otherData.get("kind") == "version":
            result = myData.get("version", 0) < otherData.get("version", 0)
            if (
                tree is not None
                and tree.header().sortIndicatorOrder() == Qt.SortOrder.DescendingOrder
            ):
                result = not result
            return result
        column = tree.sortColumn() if tree is not None else 0
        if column == 0:
            try:
                return int(self.text(0)) < int(other.text(0))
            except ValueError:
                pass
        return self.text(column).lower() < other.text(column).lower()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.pdf = None
        self.fileName = None
        self.console = None
        self._currentSelection = None
        self._currentRawStream = None
        self._currentDecodedStream = None
        self._hexOffsetFormat = "hex"
        self._activeParseWorker = None
        self._loadingProgress = None
        self._activeJSAnalysisProcess = None
        self._jsAnalysisProgress = None
        self._pendingJsErrFile = None
        self._afterJSAnalysis = None
        self._activeChangelogWorker = None
        self._changelogProgress = None
        self._activeObjectJSProcess = None
        self._objectJSProgress = None
        self._lastTreeSnapshot = None
        self._treeExpandedBeforeFilter = None
        self._consoleHistory = []
        self._consoleHistoryIndex = 0
        self.setWindowTitle(f"peepdf-3 v{VERSION}")
        self.resize(1200, 800)

        self._buildMenus()
        self._buildLayout()
        self.setStyleSheet(
            self.styleSheet() + "QPlainTextEdit { border: 1px solid black; }"
            "QPlainTextEdit:focus { border: 1px solid black; }"
        )
        self.statusBar().showMessage("No file open")
        self.statusBar().setSizeGripEnabled(False)
        self._cornerGrip = QSizeGrip(self)
        self._cornerGrip.setFixedSize(self._cornerGrip.sizeHint())
        self._updatingStatusBarGeometry = False
        self.statusBar().installEventFilter(self)
        self._updateStatusBarWidth()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._updateStatusBarWidth()

    def eventFilter(self, obj, event):
        if (
            obj is self.statusBar()
            and event.type() in (QEvent.Type.Resize, QEvent.Type.Move)
            and not self._updatingStatusBarGeometry
        ):
            self._updateStatusBarWidth()
        elif obj is self.consoleInputEdit and event.type() == QEvent.Type.KeyPress:
            if event.key() == Qt.Key.Key_Up:
                self._consoleHistoryUp()
                return True
            if event.key() == Qt.Key.Key_Down:
                self._consoleHistoryDown()
                return True
        elif (
            obj is self.treeFilterEdit
            and event.type() == QEvent.Type.KeyPress
            and event.key() == Qt.Key.Key_Escape
            and self.treeFilterEdit.text()
        ):
            self.treeFilterEdit.clear()
            return True
        return super().eventFilter(obj, event)

    def _consoleHistoryUp(self):
        """
        Recalls the previous command in a history, like a shell's Up arrow.
        """
        if not self._consoleHistory or self._consoleHistoryIndex == 0:
            return
        self._consoleHistoryIndex -= 1
        text = self._consoleHistory[self._consoleHistoryIndex]
        self.consoleInputEdit.setText(text)
        self.consoleInputEdit.setCursorPosition(len(text))

    def _consoleHistoryDown(self):
        """
        Scrolls to the next command in a history, like a shell's Down arrow.
        """
        if not self._consoleHistory:
            return
        if self._consoleHistoryIndex >= len(self._consoleHistory) - 1:
            self._consoleHistoryIndex = len(self._consoleHistory)
            self.consoleInputEdit.clear()
            return
        self._consoleHistoryIndex += 1
        text = self._consoleHistory[self._consoleHistoryIndex]
        self.consoleInputEdit.setText(text)
        self.consoleInputEdit.setCursorPosition(len(text))

    def _updateStatusBarWidth(self, buffer=10):
        statusBar = self.statusBar()
        desiredWidth = max(self.width() - 2 * buffer, 0)
        if statusBar.width() != desiredWidth or statusBar.x() != buffer:
            self._updatingStatusBarGeometry = True
            statusBar.setFixedWidth(desiredWidth)
            statusBar.move(buffer, statusBar.y())
            self._updatingStatusBarGeometry = False
        gripSize = self._cornerGrip.size()
        self._cornerGrip.move(
            self.width() - gripSize.width(), self.height() - gripSize.height()
        )
        self._cornerGrip.raise_()

    def _buildMenus(self):
        menuStylesheet = """
        QMenu {
            background-color: white; color: black; border: 1px solid black; margin: 0;
        }
        QMenu::item {
            background-color: white; color: black; margin: 0; padding: 4px 20px 4px 20px;
        }
        QMenu::item:selected {
            background-color: #1644b9; color: white; margin: 0; padding: 4px 20px 4px 20px;
        }
        QMenuBar {
            background-color: white; color: black;
        }
        QMenuBar::item {
            background-color: white; color: black;
        }
        QMenuBar::item:selected {
            background-color: #1644b9; color: white;
        }
        """
        fileMenu = self.menuBar().addMenu("&File")
        if os.name == "nt":
            fileMenu.setStyleSheet(menuStylesheet)
        openAction = QAction("&Open...", self)
        openAction.setShortcut("Ctrl+O")
        openAction.triggered.connect(self.promptOpenFile)
        fileMenu.addAction(openAction)

        closeAction = QAction("&Close", self)
        closeAction.triggered.connect(self.closeFile)
        fileMenu.addAction(closeAction)

        fileMenu.addSeparator()

        self.decryptAction = QAction("&Decrypt Document...", self)
        self.decryptAction.setEnabled(False)
        self.decryptAction.triggered.connect(self._decryptDocument)
        fileMenu.addAction(self.decryptAction)

        fileMenu.addSeparator()

        exitAction = QAction("E&xit", self)
        exitAction.setShortcut("Ctrl+Q")
        exitAction.triggered.connect(self.close)
        fileMenu.addAction(exitAction)

        analysisMenu = self.menuBar().addMenu("&Analysis")
        if os.name == "nt":
            analysisMenu.setStyleSheet(menuStylesheet)
        self.analyseJSAction = QAction("Analyse &JS...", self)
        self.analyseJSAction.setEnabled(False)
        self.analyseJSAction.triggered.connect(self._analyseJS)
        analysisMenu.addAction(self.analyseJSAction)

        self.exportCaseReportAction = QAction("&Export Case Report...", self)
        self.exportCaseReportAction.setEnabled(False)
        self.exportCaseReportAction.triggered.connect(self._exportCaseReport)
        analysisMenu.addAction(self.exportCaseReportAction)

        self.verifySignaturesAction = QAction("&Verify Signatures", self)
        self.verifySignaturesAction.setEnabled(False)
        self.verifySignaturesAction.triggered.connect(self._verifySignatures)
        analysisMenu.addAction(self.verifySignaturesAction)

        helpMenu = self.menuBar().addMenu("&Help")
        if os.name == "nt":
            helpMenu.setStyleSheet(menuStylesheet)
        aboutAction = QAction("&About", self)
        aboutAction.triggered.connect(self.showAbout)
        helpMenu.addAction(aboutAction)

    def _buildLayout(self):
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        self.mainSplitter = splitter

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Object", "Type"])
        self.tree.setMinimumWidth(220)
        self.tree.itemSelectionChanged.connect(self.onTreeSelectionChanged)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._onTreeContextMenu)
        treeHeader = self.tree.header()
        objectColumnWidth = treeHeader.fontMetrics().horizontalAdvance("Object") + 24
        typeColumnWidth = treeHeader.fontMetrics().horizontalAdvance("Type") + 24
        treeHeader.setStretchLastSection(False)
        treeHeader.setMinimumSectionSize(min(objectColumnWidth, typeColumnWidth))
        self.tree.setColumnWidth(0, objectColumnWidth)
        self.tree.setColumnWidth(1, typeColumnWidth)

        self.treeFilterEdit = QLineEdit()
        self.treeFilterEdit.setPlaceholderText(
            "Filter by object number or type (Ctrl+F)"
        )
        self.treeFilterEdit.setClearButtonEnabled(True)
        self.treeFilterEdit.setEnabled(False)
        self.treeFilterEdit.textChanged.connect(self._onTreeFilterTextChanged)
        self.treeFilterEdit.returnPressed.connect(self._selectFirstFilteredObject)
        self.treeFilterLabel = QLabel("")
        self.treeFilterLabel.setVisible(False)
        self._treeFilterTimer = QTimer(self)
        self._treeFilterTimer.setSingleShot(True)
        self._treeFilterTimer.setInterval(150)
        self._treeFilterTimer.timeout.connect(self._applyTreeFilter)
        findShortcut = QShortcut(QKeySequence(QKeySequence.StandardKey.Find), self)
        findShortcut.activated.connect(self._focusTreeFilter)

        treePane = QWidget()
        treeLayout = QVBoxLayout(treePane)
        treeLayout.setContentsMargins(0, 0, 0, 0)
        treeLayout.setSpacing(2)
        treeLayout.addWidget(self.treeFilterEdit)
        treeLayout.addWidget(self.tree)
        treeLayout.addWidget(self.treeFilterLabel)
        splitter.addWidget(treePane)

        self.tabs = QTabWidget()
        self._buildInfoTab()
        self._buildMetadataTab()
        self._buildVersionInfoTab()
        self._buildChangelogTab()
        self._buildObjectTab()
        self._buildErrorsTab()
        self._buildSuspiciousTab()
        self._buildCommentsTab()
        self._buildAttachmentsTab()
        self._buildConsoleTab()
        self.treeFilterEdit.installEventFilter(self)

        rightFrame = QFrame()
        rightFrame.setFrameShape(QFrame.Shape.StyledPanel)
        rightFrame.setMinimumWidth(420)
        rightLayout = QVBoxLayout(rightFrame)
        rightLayout.setContentsMargins(0, 0, 0, 0)
        rightLayout.addWidget(self.tabs)
        splitter.addWidget(rightFrame)
        self.rightFrame = rightFrame

        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)
        self.setCentralWidget(splitter)

        self._enforceMinimumWindowSize()

    def _enforceMinimumWindowSize(self):
        """
        Sets an explicit minimum size on the whole window.
        Stops the splitter/section handle from being dragged too far to make
        the content of the window unusable.
        """
        nestedTabChromeAllowance = 40
        hexSplitterMinWidth = (
            self.hexOffsetView.parentWidget().minimumWidth()
            + self.hexBytesView.parentWidget().minimumWidth()
            + self.hexAsciiView.parentWidget().minimumWidth()
            + 2 * self.hexSplitter.handleWidth()
            + nestedTabChromeAllowance
        )
        rightPaneMinWidth = max(self.rightFrame.minimumWidth(), hexSplitterMinWidth)
        self.rightFrame.setMinimumWidth(rightPaneMinWidth)

        totalMinWidth = (
            self.tree.minimumWidth()
            + self.mainSplitter.handleWidth()
            + rightPaneMinWidth
        )
        chromeHeight = (
            self.menuBar().sizeHint().height()
            + self.tabs.tabBar().sizeHint().height()
            + self.objHeaderLabel.sizeHint().height()
            + self.objSubTabs.tabBar().sizeHint().height()
            + self._hexColumnHeaderHeight
            + self.statusBar().sizeHint().height()
            + 40
        )
        totalMinHeight = chromeHeight + self.hexBytesView.minimumHeight()

        self.setMinimumSize(totalMinWidth, totalMinHeight)

    def _buildInfoTab(self):
        self.infoView = QPlainTextEdit()
        self.infoView.setReadOnly(True)
        self.infoView.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.infoView.setFont(QFont(MONO_FONT, 10))
        self.infoView.setPlainText("Load a file to display available file info.")
        self.tabs.addTab(self.infoView, "Document Info")

    def _buildMetadataTab(self):
        self.metadataView = QPlainTextEdit()
        self.metadataView.setReadOnly(True)
        self.metadataView.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.metadataView.setFont(QFont(MONO_FONT, 10))
        self.metadataView.setPlainText(
            "Load a file to display available file metadata."
        )
        self.tabs.addTab(self.metadataView, "Metadata")

    def _buildVersionInfoTab(self):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)

        toolbar = QHBoxLayout()
        self.showAllVersionsButton = QPushButton("Show All Versions")
        self.showAllVersionsButton.setEnabled(False)
        self.showAllVersionsButton.clicked.connect(self._showAllVersionsInfo)
        toolbar.addWidget(
            self.showAllVersionsButton, alignment=Qt.AlignmentFlag.AlignCenter
        )
        toolbar.addStretch(1)
        layout.addLayout(toolbar)

        self.versionInfoView = QPlainTextEdit()
        self.versionInfoView.setReadOnly(True)
        self.versionInfoView.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.versionInfoView.setFont(QFont(MONO_FONT, 10))
        self.versionInfoView.setPlainText(
            "Select a version in the tree on the left to see its summary, "
            'or click "Show All Versions" above to see them all at once.'
        )
        layout.addWidget(self.versionInfoView)

        self.versionInfoTabIndex = self.tabs.addTab(container, "Version Info")

    def _buildChangelogTab(self):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)

        toolbar = QHBoxLayout()
        self.computeChangelogButton = QPushButton("Compute Changelog")
        self.computeChangelogButton.setEnabled(False)
        self.computeChangelogButton.clicked.connect(self._computeChangelog)
        toolbar.addWidget(self.computeChangelogButton, 0, Qt.AlignmentFlag.AlignVCenter)
        toolbar.addStretch(1)
        layout.addLayout(toolbar)

        self.changelogView = QPlainTextEdit()
        self.changelogView.setReadOnly(True)
        self.changelogView.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.changelogView.setFont(QFont(MONO_FONT, 10))
        self.changelogView.setPlainText(self._changelogPlaceholderText())
        layout.addWidget(self.changelogView)

        self.changelogTabIndex = self.tabs.addTab(container, "Changelog")

    def _buildObjectTab(self):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)

        self.objHeaderLabel = QLabel("No object selected")
        self.objHeaderLabel.setStyleSheet("font-weight: bold; padding: 4px;")
        layout.addWidget(self.objHeaderLabel)

        self.objSubTabs = QTabWidget()
        layout.addWidget(self.objSubTabs)

        monoFont = QFont(MONO_FONT, 10)

        self.decodedValueView = QPlainTextEdit()
        self.decodedValueView.setReadOnly(True)
        self.decodedValueView.setFont(monoFont)
        self.objSubTabs.addTab(self.decodedValueView, "Decoded Value")

        self._buildDecodedHexTab(monoFont)

        self.rawValueView = QPlainTextEdit()
        self.rawValueView.setReadOnly(True)
        self.rawValueView.setFont(monoFont)
        self.objSubTabs.addTab(self.rawValueView, "Raw Value")

        self._buildHexTab(monoFont)

        self.objStatsTable = QTableWidget(0, 2)
        self.objStatsTable.horizontalHeader().setVisible(False)
        self.objStatsTable.verticalHeader().setVisible(False)
        self.objStatsTable.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.objSubTabs.addTab(self.objStatsTable, "Stats")

        self.tabs.addTab(container, "Object")
        self.objectTabContainer = container

    def _buildHexTab(self, monoFont):
        (
            splitter,
            self.hexOffsetView,
            self.hexBytesView,
            self.hexAsciiView,
            self.hexOffsetHeaderButton,
        ) = self._buildHexColumns(monoFont)
        self.hexSplitter = splitter
        self.rawHexTabIndex = self.objSubTabs.addTab(splitter, "Raw Stream (hex)")

    def _buildDecodedHexTab(self, monoFont):
        (
            splitter,
            self.decodedHexOffsetView,
            self.decodedHexBytesView,
            self.decodedHexAsciiView,
            self.decodedHexOffsetHeaderButton,
        ) = self._buildHexColumns(monoFont)
        self.decodedHexTabIndex = self.objSubTabs.addTab(
            splitter, "Decoded Stream (hex)"
        )

    def _buildHexColumns(self, monoFont):
        """
        Builds one set of offset/hex/ASCII columns for a hex viewer tab.
        Returns (splitter, offsetView, bytesView, asciiView, offsetHeaderButton).
        """
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(6)

        offsetView = self._makeHexColumn(monoFont)
        bytesView = self._makeHexColumn(monoFont)
        asciiView = self._makeHexColumn(monoFont)

        fm = offsetView.fontMetrics()
        offsetMinWidth = fm.horizontalAdvance("0") * 10 + 12
        scrollBarExtent = bytesView.style().pixelMetric(
            QStyle.PixelMetric.PM_ScrollBarExtent
        )
        hexMinWidth = fm.horizontalAdvance("00 " * 16) + 12 + scrollBarExtent
        asciiMinWidth = fm.horizontalAdvance("0") * 17 + 12

        offsetView.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        asciiView.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        bytesView.verticalScrollBar().valueChanged.connect(
            offsetView.verticalScrollBar().setValue
        )
        bytesView.verticalScrollBar().valueChanged.connect(
            asciiView.verticalScrollBar().setValue
        )

        # The Offset header doubles as a toggle button: click it to switch
        # between hexadecimal and decimal offsets.
        offsetHeaderButton = QPushButton(self._hexOffsetHeaderText())
        offsetHeaderButton.setFlat(True)
        offsetHeaderButton.setCursor(Qt.CursorShape.PointingHandCursor)
        offsetHeaderButton.setToolTip(
            "Click to toggle between hexadecimal and decimal offsets"
        )
        offsetHeaderButton.setStyleSheet(
            "QPushButton { font-weight: bold; padding: 2px; text-align: left; "
            "border: none; background: transparent; }"
            "QPushButton:hover { text-decoration: underline; }"
        )
        offsetHeaderButton.clicked.connect(self._toggleHexOffsetFormat)

        hexHeader = QLabel("Hex")
        hexHeader.setStyleSheet("font-weight: bold; padding: 2px;")
        asciiHeader = QLabel("ASCII")
        asciiHeader.setStyleSheet("font-weight: bold; padding: 2px;")
        self._hexColumnHeaderHeight = max(
            offsetHeaderButton.sizeHint().height(),
            hexHeader.sizeHint().height(),
            asciiHeader.sizeHint().height(),
        )
        hexContentMinHeight = round(
            fm.lineSpacing() * 16
            + 2 * bytesView.frameWidth()
            + 2 * bytesView.document().documentMargin()
        )
        for view in (offsetView, bytesView, asciiView):
            view.setMinimumHeight(hexContentMinHeight)

        offsetGroup = self._hexColumnGroup(
            offsetHeaderButton, offsetView, offsetMinWidth
        )
        hexGroup = self._hexColumnGroup(hexHeader, bytesView, hexMinWidth)
        asciiGroup = self._hexColumnGroup(asciiHeader, asciiView, asciiMinWidth)

        splitter.addWidget(offsetGroup)
        splitter.addWidget(hexGroup)
        splitter.addWidget(asciiGroup)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setStretchFactor(2, 0)
        splitter.setSizes([offsetMinWidth, hexMinWidth, asciiMinWidth])

        return splitter, offsetView, bytesView, asciiView, offsetHeaderButton

    @staticmethod
    def _makeHexColumn(font):
        view = QPlainTextEdit()
        view.setReadOnly(True)
        view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        view.setFont(font)
        return view

    def _setHexColumns(self, offsetView, bytesView, asciiView, data):
        offsetText, hexText, asciiText = (
            hexdumpColumns(data, offsetFormat=self._hexOffsetFormat)
            if data
            else ("", "", "")
        )
        offsetView.setPlainText(offsetText)
        bytesView.setPlainText(hexText)
        asciiView.setPlainText(asciiText)

    @staticmethod
    def _hexColumnGroup(header, view, minWidth):
        group = QWidget()
        group.setMinimumWidth(minWidth)
        layout = QVBoxLayout(group)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        layout.addWidget(header)
        layout.addWidget(view)
        return group

    def _hexOffsetHeaderText(self):
        return "Offset (h)" if self._hexOffsetFormat == "hex" else "Offset (d)"

    def _toggleHexOffsetFormat(self):
        self._hexOffsetFormat = "decimal" if self._hexOffsetFormat == "hex" else "hex"
        headerText = self._hexOffsetHeaderText()
        self.hexOffsetHeaderButton.setText(headerText)
        self.decodedHexOffsetHeaderButton.setText(headerText)
        self._refreshHexOffsetColumn(
            self.hexOffsetView, self.hexBytesView, self._currentRawStream
        )
        self._refreshHexOffsetColumn(
            self.decodedHexOffsetView,
            self.decodedHexBytesView,
            self._currentDecodedStream,
        )

    def _refreshHexOffsetColumn(self, offsetView, bytesView, data):
        if not data:
            return
        offsetText, _hexText, _asciiText = hexdumpColumns(
            data, offsetFormat=self._hexOffsetFormat
        )
        # Make sure the hex offsets realign with the scroll position because
        # setPlainText resets the position to 0 when the hex/dec view changes.
        currentScrollValue = bytesView.verticalScrollBar().value()
        offsetView.setPlainText(offsetText)
        offsetView.verticalScrollBar().setValue(currentScrollValue)

    def _buildErrorsTab(self):
        self.errorsView = QPlainTextEdit()
        self.errorsView.setReadOnly(True)
        self.errorsTabIndex = self.tabs.addTab(self.errorsView, "Errors")

    def _buildSuspiciousTab(self):
        self.suspiciousTree = QTreeWidget()
        self.suspiciousTree.setHeaderLabels(["Item"])
        self.suspiciousTree.setHeaderHidden(True)
        self.suspiciousTree.itemDoubleClicked.connect(self._onSuspiciousItemActivated)
        self.suspiciousTabIndex = self.tabs.addTab(self.suspiciousTree, "Suspicious")

    def _buildCommentsTab(self):
        self.commentsTree = QTreeWidget()
        self.commentsTree.setHeaderLabels(["Comment", "Author", "Modified", "Notes"])
        self.commentsTree.setHeaderHidden(True)
        self.commentsTree.setColumnWidth(0, 460)
        self.commentsTree.itemDoubleClicked.connect(self._onCommentItemActivated)
        self.commentsTabIndex = self.tabs.addTab(self.commentsTree, "Comments")

    def _buildAttachmentsTab(self):
        self.attachmentsTree = QTreeWidget()
        self.attachmentsTree.setHeaderLabels(["Attachment", "Size", "MIME Type", "MD5"])
        self.attachmentsTree.setHeaderHidden(True)
        self.attachmentsTree.setColumnWidth(0, 460)
        self.attachmentsTree.itemDoubleClicked.connect(self._onAttachmentItemActivated)
        self.attachmentsTabIndex = self.tabs.addTab(self.attachmentsTree, "Attachments")

    @staticmethod
    def _consoleWelcomeText():
        return (
            "peepdf console - runs the same commands as the interactive "
            "PDFConsole (info, tree, object N, metadata, search, ...).\n"
            'Type a command below and press Enter or click "Run".'
        )

    @staticmethod
    def _changelogPlaceholderText():
        return (
            'Click "Compute Changelog" to see what changed across this '
            "document's incremental updates - added, modified, and "
            "removed objects per version."
            "This walks every object in every version, so it can take "
            "a while on a large, heavily edited PDF."
        )

    def _buildConsoleTab(self):
        container = QWidget()
        layout = QVBoxLayout(container)

        self.consoleOutputView = QPlainTextEdit()
        self.consoleOutputView.setReadOnly(True)
        self.consoleOutputView.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.consoleOutputView.setFont(QFont(MONO_FONT, 10))
        self.consoleOutputView.setPlainText(self._consoleWelcomeText())
        layout.addWidget(self.consoleOutputView)

        inputRow = QHBoxLayout()
        self.consoleInputEdit = QLineEdit()
        self.consoleInputEdit.setFont(QFont(MONO_FONT, 10))
        self.consoleInputEdit.setPlaceholderText(
            "Type a peepdf console command, e.g. object 5"
        )
        self.consoleInputEdit.returnPressed.connect(self._runConsoleCommand)
        self.consoleInputEdit.installEventFilter(self)
        inputRow.addWidget(self.consoleInputEdit)

        runButton = QPushButton("Run")
        runButton.clicked.connect(self._runConsoleCommand)
        inputRow.addWidget(runButton)

        clearButton = QPushButton("Clear")
        clearButton.clicked.connect(self._clearButton)
        inputRow.addWidget(clearButton)

        layout.addLayout(inputRow)

        self.consoleTabIndex = self.tabs.addTab(container, "Console")

    def _clearButton(self):
        self.consoleOutputView.clear
        self.consoleOutputView.setPlainText(self._consoleWelcomeText())

    ## Actions ##

    def showAbout(self):
        aboutBox = QMessageBox(self)
        aboutBox.setWindowTitle(f"About peepdf-3 v{VERSION}")
        aboutBox.setTextFormat(Qt.TextFormat.RichText)
        aboutBox.setText(
            "peepdf-3 GUI<br><br>"
            '<a href="https://github.com/digitalsleuth/peepdf-3">'
            "https://github.com/digitalsleuth/peepdf-3</a>"
        )
        label = aboutBox.findChild(QLabel, "qt_msgbox_label")
        if label is not None:
            label.setOpenExternalLinks(True)
        aboutBox.exec()

    def promptOpenFile(self):
        fileName, _ = QFileDialog.getOpenFileName(
            self, "Open PDF", "", "PDF Files (*.pdf);;All Files (*)"
        )
        if fileName:
            self.open_file(fileName)

    def closeFile(self):
        self._resetDocumentPanels(dropConsole=True)

    def _resetDocumentPanels(self, dropConsole):
        self.pdf = None
        self.fileName = None
        self._lastTreeSnapshot = None
        if dropConsole:
            self.console = None
            self.consoleOutputView.setPlainText(self._consoleWelcomeText())
        self._currentSelection = None
        self.tree.clear()
        self._resetTreeFilter()
        self.infoView.clear()
        self.metadataView.clear()
        self._clearObjectView()
        self.errorsView.clear()
        self.tabs.setTabText(self.errorsTabIndex, "Errors")
        self.suspiciousTree.clear()
        self.suspiciousTree.setHeaderHidden(True)
        self.tabs.setTabText(self.suspiciousTabIndex, "Suspicious")
        self.commentsTree.clear()
        self.commentsTree.setHeaderHidden(True)
        self.tabs.setTabText(self.commentsTabIndex, "Comments")
        self.attachmentsTree.clear()
        self.attachmentsTree.setHeaderHidden(True)
        self.tabs.setTabText(self.attachmentsTabIndex, "Attachments")
        self.versionInfoView.setPlainText(
            "Select a version in the tree on the left to see its summary, "
            'or click "Show All Versions" above to see them all at once.'
        )
        self.metadataView.setPlainText(
            "Load a file to display available file metadata."
        )
        self.infoView.setPlainText("Load a file to display available file info.")
        self.showAllVersionsButton.setEnabled(False)
        if self._changelogProgress is not None:
            self._changelogProgress.close()
            self._changelogProgress = None
        self._activeChangelogWorker = None
        self.changelogView.setPlainText(self._changelogPlaceholderText())
        self.computeChangelogButton.setEnabled(False)
        if self._activeJSAnalysisProcess is not None:
            self._activeJSAnalysisProcess.kill()
            self._activeJSAnalysisProcess = None
        if self._jsAnalysisProgress is not None:
            self._jsAnalysisProgress.close()
            self._jsAnalysisProgress = None
        self._pendingJsErrFile = None
        self._afterJSAnalysis = None
        if self._activeObjectJSProcess is not None:
            self._activeObjectJSProcess.kill()
            self._activeObjectJSProcess = None
        if self._objectJSProgress is not None:
            self._objectJSProgress.close()
            self._objectJSProgress = None
        self.setWindowTitle(f"peepdf-3 v{VERSION}")
        self.statusBar().showMessage("No file open")
        self._updateDecryptActionState()
        pdfCoreModule.pdfFile = None

    def open_file(self, fileName):
        fileName = os.path.abspath(os.path.normpath(fileName))
        if not os.path.exists(fileName):
            QMessageBox.critical(self, "Error", f"File not found:\n{fileName}")
            return
        self._resetDocumentPanels(dropConsole=True)
        worker = _PDFParseWorker(fileName, self)
        self._activeParseWorker = worker
        worker.resultReady.connect(
            lambda ret, pdf, err, w=worker, fn=fileName: self._onParseFinished(
                w, fn, ret, pdf, err
            )
        )
        worker.finished.connect(worker.deleteLater)
        progress = _LoadingDialog("Parsing PDF, please wait...", self)
        progress.canceled.connect(lambda w=worker: self._cancelFileLoad(w))
        self._loadingProgress = progress
        self.statusBar().showMessage(f"Parsing {fileName}...")
        progress.show()
        QApplication.processEvents()
        worker.start()

    def _cancelFileLoad(self, worker):
        if self._activeParseWorker is worker:
            self._activeParseWorker = None
        if self._loadingProgress is not None:
            self._loadingProgress.close()
            self._loadingProgress = None
        self.statusBar().showMessage("File load cancelled")

    def _onParseFinished(self, worker, fileName, ret, pdf, errorMessage):
        if self._activeParseWorker is not worker:
            return
        self._activeParseWorker = None
        if self._loadingProgress is not None:
            self._loadingProgress.close()
            self._loadingProgress = None

        if errorMessage:
            QMessageBox.critical(
                self, "Parse error", f"Failed to parse PDF:\n{errorMessage}"
            )
            self.statusBar().showMessage("No file open")
            return
        if ret == -1 or pdf is None:
            QMessageBox.critical(
                self, "Parse error", "peepdf could not parse this file."
            )
            self.statusBar().showMessage("No file open")
            return

        self.pdf = pdf
        self.fileName = fileName
        self.console = None
        self._currentSelection = None

        self.setWindowTitle(f"peepdf-3 v{VERSION} - {os.path.basename(fileName)}")
        self.statusBar().showMessage(fileName)
        self._updateDecryptActionState()

        self.showAllVersionsButton.setEnabled(True)
        self.computeChangelogButton.setEnabled(True)

        if pdf.isEncrypted():
            self._offerDecrypt()

        self._populateInfoTab()
        self._populateMetadataTab()
        self._populateTree()
        self._setInitialTreeWidth()
        stats = self.pdf.getStats()
        self._populateErrorsTab(stats)
        self._populateSuspiciousTab(stats)
        self._populateCommentsTab()
        self._populateAttachmentsTab()
        self.tabs.setCurrentIndex(0)

    def _offerDecrypt(self):
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Encrypted PDF")
        box.setText("This PDF is encrypted.")
        box.setInformativeText(
            "Decrypt it now to view its actual content, or continue viewing it "
            "in its encrypted state (strings and streams will show as ciphertext).\n\n"
            "You can decrypt it later from File > Decrypt Document."
        )
        decryptButton = box.addButton("Decrypt...", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Continue", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(decryptButton)
        box.exec()
        if box.clickedButton() is decryptButton:
            self._decryptDocument()

    def _updateDecryptActionState(self):
        enabled = self.pdf is not None and self.pdf.isEncrypted()
        self.decryptAction.setEnabled(enabled)
        self.analyseJSAction.setEnabled(self.pdf is not None)
        self.exportCaseReportAction.setEnabled(self.pdf is not None)
        self.verifySignaturesAction.setEnabled(self.pdf is not None)

    def _decryptDocument(self):
        if self.pdf is None or not self.pdf.isEncrypted():
            return
        password, ok = QInputDialog.getText(
            self,
            "Decrypt Document",
            "Enter the user password to decrypt this document\n"
            "(leave blank to try an empty password):",
            QLineEdit.EchoMode.Password,
        )
        if not ok:
            return
        try:
            ret = self.pdf.decrypt(password)
        except Exception as exc:
            QMessageBox.warning(
                self, "Decryption failed", f"Could not decrypt the file:\n{exc}"
            )
            return
        if ret[0] == -1:
            QMessageBox.warning(
                self,
                "Decryption failed",
                f"{ret[1]}\n\nContent will continue to be shown in its original state where possible.",
            )
            return
        self._updateDecryptActionState()
        self._refreshViews()
        QMessageBox.information(
            self, "Decryption succeeded", "The document has been decrypted."
        )

    def _exportCaseReport(self):
        """
        Exports a consolidated case report (hashes, metadata, changelog,
        JS/vuln findings) via the console's 'case_report' command.
        """
        if self.pdf is None or self.fileName is None:
            return
        suggestedName = os.path.splitext(self.fileName)[0] + "-case-report.json"
        saveName, selectedFilter = QFileDialog.getSaveFileName(
            self,
            "Export Case Report",
            suggestedName,
            "JSON Case Report (*.json);;HTML Case Report (*.html)",
        )
        if not saveName:
            return
        useHtml = selectedFilter.startswith("HTML") or saveName.lower().endswith(
            ".html"
        )

        hasJS = any(
            self.pdf.body[version].getContainingJS()
            for version in range(self.pdf.updates + 1)
        )
        if not hasJS or not pdfCoreModule.isManualAnalysis:
            self._writeCaseReport(saveName, useHtml, includeJS=True)
            return

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Export Case Report")
        box.setText("Which JavaScript analysis should be performed for this report?")
        box.setInformativeText(
            "Full: runs full JavaScript analysis now (this executes and "
            "deobfuscates the file's JavaScript in a separate process, and "
            "discards any unsaved console changes), then includes every stage "
            "in the report.\n\n"
            "Summary: runs no further analysis. Lists the objects with "
            "JavaScript and a preview of their original/beautified source.\n\n"
            "None: runs no analysis and leaves the JavaScript findings out.\n\n"
            "The report records what was actually done."
        )
        fullButton = box.addButton("Full", QMessageBox.ButtonRole.YesRole)
        summaryButton = box.addButton("Summary", QMessageBox.ButtonRole.NoRole)
        noneButton = box.addButton("None", QMessageBox.ButtonRole.ActionRole)
        box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(summaryButton)
        box.exec()
        clicked = box.clickedButton()

        if clicked is fullButton:
            # The report is only written if the analysis really completes, so
            # it can never claim an analysis that was cancelled or failed.
            def writeAfterAnalysis(success):
                if success:
                    self._writeCaseReport(saveName, useHtml, includeJS=True)

            self._startJSAnalysis(writeAfterAnalysis)
        elif clicked is summaryButton:
            self._writeCaseReport(saveName, useHtml, includeJS=True)
        elif clicked is noneButton:
            self._writeCaseReport(saveName, useHtml, includeJS=False)
        # Cancel, or the dialog being closed, exports nothing.

    def _writeCaseReport(self, saveName, useHtml, includeJS):
        """
        Writes the report via the console's 'case_report' command.
        """
        options = []
        if not includeJS:
            options.append("nojs")
        if useHtml:
            options.append("html")
        commandText = "case_report " + " ".join([*options, f'"{saveName}"'])
        console = self._ensureConsole()
        output, cmdReturnValue = self._captureConsoleCommand(console, commandText)
        if output:
            self._appendConsoleText(output.rstrip("\n"))
        if cmdReturnValue is False or not os.path.exists(saveName):
            QMessageBox.critical(
                self,
                "Export failed",
                output.strip() if output else "Could not write the case report.",
            )
            return
        QMessageBox.information(
            self,
            "Export complete",
            f"Case report written to:\n{os.path.abspath(os.path.normpath(saveName))}",
        )

    def _verifySignatures(self):
        """Runs the console's 'signatures verbose' command and shows the result."""
        if self.pdf is None:
            return
        console = self._ensureConsole()
        output, _cmdReturnValue = self._captureConsoleCommand(
            console, "signatures verbose"
        )
        self._appendConsoleText((output or "No digital signatures found.").rstrip("\n"))
        self.tabs.setCurrentIndex(self.consoleTabIndex)

    def _analyseJS(self):
        self._startJSAnalysis()

    def _finishJSAnalysis(self, success):
        callback, self._afterJSAnalysis = self._afterJSAnalysis, None
        if callback is not None:
            callback(success)

    def _startJSAnalysis(self, afterAnalysis=None):
        """
        afterAnalysis, if given, is called with True once the analysis has
        completed and the re-analysed document is in place, or with False if
        it was declined, cancelled or failed.
        """
        self._afterJSAnalysis = afterAnalysis
        if self.pdf is None or self.fileName is None:
            self._finishJSAnalysis(False)
            return
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Analyse JS")
        box.setText("Re-analyse this file with full automatic JavaScript execution?")
        box.setInformativeText(
            "This re-parses the file (which can take a while for a large one) "
            "with JS beautification and automatic eval() deobfuscation enabled, "
            "and writes a jserrors log alongside it if anything goes wrong during analysis.\n\n"
            "If the PDF becomes stuck in an infinite loop, the first part "
            "of this analysis runs in a separate process, so clicking "
            "Cancel below will end just that process - the GUI itself stays open.\n\n"
            "Any changes made via the console this session will be discarded."
        )
        analyseButton = box.addButton("Analyse", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(analyseButton)
        box.exec()
        if box.clickedButton() is not analyseButton:
            self._finishJSAnalysis(False)
            return
        absFileName = os.path.abspath(self.fileName)
        timestamp = dt.now(timezone.utc).strftime(DTFMT)
        jsErrFile = f"{absFileName}-{timestamp}-peepdf-jserrors.txt"
        self._pendingJsErrFile = jsErrFile

        process = QProcess(self)
        process.setProgram(sys.executable)
        process.setArguments(
            ["-m", "peepdf.gui._js_subprocess", "probe", absFileName, jsErrFile]
        )
        process.setWorkingDirectory(_ROOT_PATH)
        self._activeJSAnalysisProcess = process
        process.finished.connect(
            lambda code, status, p=process: self._onJSAnalysisProbeFinished(
                p, code, status
            )
        )
        process.finished.connect(process.deleteLater)

        progress = _LoadingDialog("Analysing JavaScript, please wait...", self)
        progress.canceled.connect(lambda p=process: self._cancelJSAnalysis(p))
        self._jsAnalysisProgress = progress

        self.statusBar().showMessage(f"Analysing JS in {self.fileName}...")
        progress.show()
        QApplication.processEvents()
        process.start()

    def _cancelJSAnalysis(self, process):
        if self._activeJSAnalysisProcess is process:
            self._activeJSAnalysisProcess = None
        if self._jsAnalysisProgress is not None:
            self._jsAnalysisProgress.close()
            self._jsAnalysisProgress = None
        self.statusBar().showMessage(self.fileName or "No file open")
        self._pendingJsErrFile = None
        process.kill()
        self._finishJSAnalysis(False)

    def _onJSAnalysisProbeFinished(self, process, exitCode, exitStatus):
        if self._activeJSAnalysisProcess is not process:
            return  # superseded by a cancel, or the file was closed/reopened
        self._activeJSAnalysisProcess = None
        if self._jsAnalysisProgress is not None:
            self._jsAnalysisProgress.close()
            self._jsAnalysisProgress = None

        if exitStatus == QProcess.ExitStatus.CrashExit or exitCode != 0:
            errorOutput = bytes(process.readAllStandardError()).decode(
                "utf-8", errors="replace"
            )
            self._pendingJsErrFile = None
            self.statusBar().showMessage(self.fileName or "No file open")
            QMessageBox.critical(
                self,
                "Analysis error",
                f"Failed to re-analyse the file:\n"
                f"{errorOutput or 'peepdf could not parse this file.'}",
            )
            self._finishJSAnalysis(False)
            return
        self.statusBar().showMessage(f"Analysing JS in {self.fileName}...")
        QApplication.processEvents()
        try:
            ret, pdf = PDFParser().parse(
                self.fileName,
                forceMode=True,
                looseMode=True,
                manualAnalysis=False,
                jsErrFile=self._pendingJsErrFile,
            )
        except Exception as exc:
            self._pendingJsErrFile = None
            self.statusBar().showMessage(self.fileName or "No file open")
            QMessageBox.critical(
                self, "Analysis error", f"Failed to re-analyse the file:\n{exc}"
            )
            self._finishJSAnalysis(False)
            return

        if ret == -1 or pdf is None:
            self._pendingJsErrFile = None
            self.statusBar().showMessage(self.fileName or "No file open")
            QMessageBox.critical(
                self, "Analysis error", "peepdf could not parse this file."
            )
            self._finishJSAnalysis(False)
            return

        self.pdf = pdf
        self.console = None
        self._currentSelection = None
        self.statusBar().showMessage(self.fileName)
        self._updateDecryptActionState()
        self._refreshViews()

        jsErrorsPath = self._pendingJsErrFile
        self._pendingJsErrFile = None
        if jsErrorsPath and os.path.exists(jsErrorsPath):
            QMessageBox.information(
                self,
                "Analysis complete",
                "JS analysis finished. Some JavaScript could not be fully "
                f"analysed; details were written to:\n{jsErrorsPath}",
            )
        else:
            QMessageBox.information(
                self,
                "Analysis complete",
                "JS analysis finished with no errors.",
            )
        self._finishJSAnalysis(True)

    def _refreshViews(self):
        selected = self._currentSelection
        currentTabIndex = self.tabs.currentIndex()
        self._populateInfoTab()
        self._populateMetadataTab()
        self._populateTree()
        stats = self.pdf.getStats()
        self._populateErrorsTab(stats)
        self._populateSuspiciousTab(stats)
        self._populateCommentsTab()
        self._populateAttachmentsTab()
        if selected is not None:
            self._selectTreeObject(*selected)
        self.tabs.setCurrentIndex(currentTabIndex)

    def _selectTreeObject(self, objId, version):
        for i in range(self.tree.topLevelItemCount()):
            versionItem = self.tree.topLevelItem(i)
            for j in range(versionItem.childCount()):
                child = versionItem.child(j)
                data = child.data(0, Qt.ItemDataRole.UserRole)
                if data and data.get("id") == objId and data.get("version") == version:
                    versionItem.setExpanded(True)
                    self.tree.setCurrentItem(child)
                    return
        self._showObject(objId, version)

    ## Console Window ##

    def _ensureConsole(self):
        if self.console is None:
            console = PDFConsole(self.pdf, "", avoidOutputColors=True, isCommand=True)
            console.use_rawinput = False
            self.console = console
        return self.console

    def _runConsoleCommand(self):
        commandText = self.consoleInputEdit.text().strip()
        if not commandText:
            return
        self.consoleInputEdit.clear()
        self._appendConsoleText(f"PPDF> {commandText}")
        self._consoleHistory.append(commandText)
        self._consoleHistoryIndex = len(self._consoleHistory)

        firstWord = commandText.split()[0].lower()
        if firstWord == "clear":
            self.consoleOutputView.clear()
            return
        if firstWord in ("exit", "quit"):
            self._appendConsoleText(
                '[*] "exit"/"quit" have no effect here - use File > Close '
                "to close the document."
            )
            return
        if firstWord == "ocr" and not self._confirmLongOcr():
            self._appendConsoleText("[*] OCR cancelled")
            return

        console = self._ensureConsole()
        output, cmdReturnValue = self._captureConsoleCommand(console, commandText)
        if output:
            self._appendConsoleText(output.rstrip("\n"))

        self.pdf = console.pdfFile
        if self.pdf is None:
            self._resetDocumentPanels(dropConsole=False)
            return
        self.fileName = os.path.abspath(self.pdf.getPath())
        self.setWindowTitle(f"peepdf-3 v{VERSION} - {os.path.basename(self.fileName)}")
        self.statusBar().showMessage(self.fileName)
        self.showAllVersionsButton.setEnabled(True)
        self.computeChangelogButton.setEnabled(True)
        self._updateDecryptActionState()
        if firstWord in _CONSOLE_MUTATING_COMMANDS and cmdReturnValue is not False:
            self._refreshViews()
        if firstWord == "open":
            self._setInitialTreeWidth()
            if self.pdf.isEncrypted():
                self._offerDecrypt()

    def _confirmLongOcr(self):
        pdf = self.console.pdfFile if self.console is not None else self.pdf
        numPages = pdf.getNumPages() if pdf is not None else None
        if numPages is None or numPages <= OCR_PAGE_WARNING_THRESHOLD:
            return True
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("OCR")
        box.setText(f"This file is {numPages} pages long. Run OCR anyway?")
        box.setInformativeText(
            "This may take some time, and the window can't be used until it finishes."
        )
        runButton = box.addButton("Continue", QMessageBox.ButtonRole.AcceptRole)
        cancelButton = box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(cancelButton)
        box.exec()
        return box.clickedButton() is runButton

    @staticmethod
    def _captureConsoleCommand(console, commandText):
        """
        Runs one PDFConsole command, capturing everything it prints.
        Returns (output, cmdReturnValue).
        """

        def _blockedInput(prompt=""):
            raise RuntimeError(
                "This command needs interactive input, which isn't "
                "supported in the GUI console."
            )

        consoleModule = sys.modules[type(console).__module__]

        capturedOutput = io.StringIO()
        originalStdout = sys.stdout
        originalInput = builtins.input
        originalModuleInput = getattr(consoleModule, "input", None)
        originalConsoleStdout = console.stdout
        sys.stdout = capturedOutput
        builtins.input = _blockedInput
        console.stdout = capturedOutput
        if originalModuleInput is not None:
            consoleModule.input = _blockedInput
        cmdReturnValue = None
        try:
            cmdReturnValue = console.onecmd(commandText)
        except Exception as exc:
            capturedOutput.write(f"[!] Error: {exc}\n")
        finally:
            sys.stdout = originalStdout
            builtins.input = originalInput
            console.stdout = originalConsoleStdout
            if originalModuleInput is not None:
                consoleModule.input = originalModuleInput
        return capturedOutput.getvalue(), cmdReturnValue

    def _appendConsoleText(self, text):
        self.consoleOutputView.appendPlainText(text)
        scrollBar = self.consoleOutputView.verticalScrollBar()
        scrollBar.setValue(scrollBar.maximum())

    ## Tab and Data population ##

    def _populateInfoTab(self):
        stats = self.pdf.getStats()
        lines = []
        simpleKeys = (
            "File",
            "MD5",
            "SHA1",
            "SHA256",
            "Size",
            "IDs",
            "Version",
            "Binary",
            "Linearized",
            "Encrypted",
            "Updates",
            "Objects",
            "Streams",
            "URIs",
            "Objects with JS",
            "Comments",
        )
        for key in simpleKeys:
            if key not in stats:
                continue
            if key == "IDs":
                idLines = self._splitMultiline(stats[key])
                lines.append("IDs:")
                lines.extend(f"    {idLine}" for idLine in idLines)
            else:
                lines.append(f"{key}: {stats[key]}")
        lines.append(f"Errors: {len(stats.get('Errors', []))}")
        if stats.get("Encryption Algorithms"):
            algos = ", ".join(
                f"{name} ({bits} bits)" for name, bits in stats["Encryption Algorithms"]
            )
            lines.append(f"Encryption Algorithms: {algos}")

        self.infoView.setPlainText("\n".join(lines))

    def _populateMetadataTab(self):
        lines = []
        anyMetadata = False
        for version in range(self.pdf.getNumUpdates() + 1):
            infoObject = self.pdf.getInfoObject(version)
            metadataObjectIds = self.pdf.getMetadata(version)
            if infoObject is None and not metadataObjectIds:
                continue
            anyMetadata = True
            basicMetadata = self.pdf.getBasicMetadata(version)
            xmp = self.pdf.getXMPMetadata(version)

            lines.append(f"Version {version}:")
            for key, label in (
                ("title", "Title"),
                ("author", "Author"),
                ("creator", "Creator"),
                ("producer", "Producer"),
                ("creation", "Creation date"),
                ("modification", "Modification date"),
                ("subject", "Subject"),
            ):
                if key in basicMetadata:
                    lines.append(f"    {label}: {basicMetadata[key]}")

            discrepancies = basicMetadata.get("discrepancies")
            if discrepancies:
                lines.append("")
                for field, values in discrepancies.items():
                    lines.append(
                        f"    [!] {field.capitalize()} differs between /Info "
                        f"('{values['info']}') and XMP ('{values['xmp']}')"
                    )

            if xmp["documentId"] or xmp["instanceId"] or xmp["originalDocumentId"]:
                lines.append("")
                if xmp["documentId"]:
                    lines.append(f"    XMP DocumentID: {xmp['documentId']}")
                if xmp["instanceId"]:
                    lines.append(f"    XMP InstanceID: {xmp['instanceId']}")
                if xmp["originalDocumentId"]:
                    lines.append(
                        f"    XMP OriginalDocumentID: {xmp['originalDocumentId']}"
                    )

            if xmp["history"]:
                lines.append("")
                lines.append("    XMP edit history:")
                table = PrettyTable(["Action", "When", "Software Agent", "Changed"])
                table.set_style(TableStyle.SINGLE_BORDER)
                table.align = "l"
                for event in xmp["history"]:
                    table.add_row(
                        [
                            event.get("action", ""),
                            event.get("when", ""),
                            event.get("softwareAgent", ""),
                            event.get("changed", ""),
                        ]
                    )
                lines.extend(f"    {line}" for line in str(table).split("\n"))

            embeddedXmp = self.pdf.getEmbeddedXMPMetadata(version, metadataObjectIds)
            if embeddedXmp:
                lines.append("")
                lines.append(
                    "    Embedded resource metadata (objects carrying their own "
                    "separate XMP, e.g. a placed logo image):"
                )
                for entry in embeddedXmp:
                    lines.append(f"        Object {entry['objectId']}:")
                    for key, label in (
                        ("title", "Title"),
                        ("creator", "Creator"),
                        ("creatorTool", "Creator tool"),
                        ("producer", "Producer"),
                        ("createDate", "Creation date"),
                        ("modifyDate", "Modification date"),
                        ("documentId", "DocumentID"),
                        ("instanceId", "InstanceID"),
                        ("originalDocumentId", "OriginalDocumentID"),
                    ):
                        if entry.get(key):
                            lines.append(f"            {label}: {entry[key]}")

            lines.append("")

        pieceInfoEntries = self.pdf.getPieceInfo()
        if pieceInfoEntries:
            anyMetadata = True
            lines.append("PieceInfo (private application metadata):")
            table = PrettyTable(
                [
                    "Object",
                    "Application",
                    "DocumentID",
                    "OriginalDocumentID",
                    "LastModified",
                ]
            )
            table.set_style(TableStyle.SINGLE_BORDER)
            table.align = "l"
            for entry in pieceInfoEntries:
                table.add_row(
                    [
                        entry["objectId"],
                        entry["application"],
                        entry["documentId"] or "-",
                        entry["originalDocumentId"] or "-",
                        entry["lastModified"] or "-",
                    ]
                )
            lines.extend(f"    {line}" for line in str(table).split("\n"))

            findings = PDFConsole._detectPieceInfoInconsistencies(pieceInfoEntries)
            if findings:
                lines.append("")
                for application, field, distinctCount, objIds in findings:
                    fieldLabel = (
                        "DocumentID" if field == "documentId" else "OriginalDocumentID"
                    )
                    lines.append(
                        f"    [!] {application}: {distinctCount} different "
                        f"{fieldLabel} values across objects {objIds} - possible "
                        "mixed-source content"
                    )
            lines.append("")

        if not anyMetadata:
            lines = ["No /Info dictionary or XMP metadata found."]

        self.metadataView.setPlainText("\n".join(lines).rstrip())

    @staticmethod
    def _splitMultiline(value):
        """
        Splits console-formatted multi-line stats
        (embedded newlines/tabs, meant for a terminal) into clean display lines.
        """
        text = str(value).replace("\r\n", "\n").replace("\r", "\n")
        lines = [line.strip() for line in text.split("\n") if line.strip()]
        return lines if lines else ["None"]

    def _populateTree(self):
        self.treeFilterEdit.setEnabled(True)
        numUpdates = self.pdf.getNumUpdates()
        versionTrees = [self.pdf.getTree(version) for version in range(numUpdates + 1)]
        snapshot = tuple(
            (
                catalogId,
                tuple(
                    sorted(
                        (objId, objType)
                        for objId, (objType, _refs) in objectsIn.items()
                    )
                ),
            )
            for catalogId, objectsIn in (vt[0] for vt in versionTrees)
        )
        if snapshot == self._lastTreeSnapshot:
            return
        self._lastTreeSnapshot = snapshot

        self.tree.setSortingEnabled(False)
        self.tree.clear()
        for version, versionTree in enumerate(versionTrees):
            _catalogId, objectsIn = versionTree[0]
            label = (
                "Version 0 (original)"
                if version == 0
                else f"Version {version} (update)"
            )
            versionItem = _ObjectTreeItem([label, ""])
            versionItem.setData(
                0, Qt.ItemDataRole.UserRole, {"kind": "version", "version": version}
            )
            self.tree.addTopLevelItem(versionItem)
            for objId in sorted(objectsIn.keys()):
                objType, _refs = objectsIn[objId]
                child = _ObjectTreeItem([str(objId), objType])
                child.setData(
                    0,
                    Qt.ItemDataRole.UserRole,
                    {"kind": "object", "id": objId, "version": version},
                )
                versionItem.addChild(child)
            versionItem.setExpanded(numUpdates == 0)
        self.tree.expandAll()
        self.tree.resizeColumnToContents(0)
        self.tree.resizeColumnToContents(1)
        for i in range(self.tree.topLevelItemCount()):
            self.tree.topLevelItem(i).setExpanded(numUpdates == 0)
        self.tree.setSortingEnabled(True)
        self.tree.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self._treeExpandedBeforeFilter = None
        if self.treeFilterEdit.text().strip():
            self._applyTreeFilter()

    def _focusTreeFilter(self):
        if self.treeFilterEdit.isEnabled():
            self.treeFilterEdit.setFocus()
            self.treeFilterEdit.selectAll()

    def _onTreeFilterTextChanged(self, _text):
        self._treeFilterTimer.start()

    def _resetTreeFilter(self):
        self._treeFilterTimer.stop()
        self._treeExpandedBeforeFilter = None
        self.treeFilterEdit.blockSignals(True)
        self.treeFilterEdit.clear()
        self.treeFilterEdit.blockSignals(False)
        self.treeFilterEdit.setEnabled(False)
        self.treeFilterLabel.setVisible(False)

    def _applyTreeFilter(self):
        self._treeFilterTimer.stop()
        query = self.treeFilterEdit.text().strip().lower()
        if not query and self._treeExpandedBeforeFilter is None:
            self.treeFilterLabel.setVisible(False)
            return

        versionItems = [
            self.tree.topLevelItem(i) for i in range(self.tree.topLevelItemCount())
        ]
        total = shown = 0
        self.tree.setUpdatesEnabled(False)
        try:
            if not query:
                saved = self._treeExpandedBeforeFilter
                for index, versionItem in enumerate(versionItems):
                    versionItem.setHidden(False)
                    for i in range(versionItem.childCount()):
                        child = versionItem.child(i)
                        if child.isHidden():
                            child.setHidden(False)
                    if saved is not None and index < len(saved):
                        versionItem.setExpanded(saved[index])
                self._treeExpandedBeforeFilter = None
            else:
                if self._treeExpandedBeforeFilter is None:
                    self._treeExpandedBeforeFilter = [
                        item.isExpanded() for item in versionItems
                    ]
                for versionItem in versionItems:
                    anyShown = False
                    for i in range(versionItem.childCount()):
                        child = versionItem.child(i)
                        matches = (
                            query in child.text(0).lower()
                            or query in child.text(1).lower()
                        )
                        if child.isHidden() == matches:
                            child.setHidden(not matches)
                        total += 1
                        if matches:
                            shown += 1
                            anyShown = True
                    versionItem.setHidden(not anyShown)
                    if anyShown:
                        versionItem.setExpanded(True)
        finally:
            self.tree.setUpdatesEnabled(True)

        if query:
            self.treeFilterLabel.setText(
                f"Showing {shown:,} of {total:,} objects"
                if shown
                else "No objects match"
            )
            self.treeFilterLabel.setVisible(True)
        else:
            self.treeFilterLabel.setVisible(False)
            # Leave the selected object in view
            current = self.tree.currentItem()
            if current is not None:
                if current.parent() is not None:
                    current.parent().setExpanded(True)
                self.tree.scrollToItem(current)

    def _selectFirstFilteredObject(self):
        if not self.treeFilterEdit.text().strip():
            return
        self._applyTreeFilter()
        for i in range(self.tree.topLevelItemCount()):
            versionItem = self.tree.topLevelItem(i)
            if versionItem.isHidden():
                continue
            for j in range(versionItem.childCount()):
                child = versionItem.child(j)
                if not child.isHidden():
                    self.tree.setCurrentItem(child)
                    self.tree.setFocus()
                    return

    def _setInitialTreeWidth(self):
        scrollBarExtent = self.tree.style().pixelMetric(
            QStyle.PixelMetric.PM_ScrollBarExtent
        )
        contentWidth = (
            self.tree.columnWidth(0) + self.tree.columnWidth(1) + scrollBarExtent + 4
        )
        splitterWidth = self.mainSplitter.width()
        if splitterWidth > 0:
            self.mainSplitter.setSizes(
                [
                    contentWidth,
                    max(
                        0,
                        splitterWidth - contentWidth - self.mainSplitter.handleWidth(),
                    ),
                ]
            )

    def _computeChangelog(self):
        if self.pdf is None:
            return
        worker = _ChangelogWorker(self.pdf, self)
        self._activeChangelogWorker = worker
        worker.resultReady.connect(
            lambda output, err, w=worker: self._onChangelogFinished(w, output, err)
        )
        worker.finished.connect(worker.deleteLater)

        progress = _LoadingDialog("Computing changelog, please wait...", self)
        progress.canceled.connect(lambda w=worker: self._cancelChangelogCompute(w))
        self._changelogProgress = progress

        self.computeChangelogButton.setEnabled(False)
        progress.show()
        QApplication.processEvents()
        worker.start()

    def _cancelChangelogCompute(self, worker):
        if self._activeChangelogWorker is worker:
            self._activeChangelogWorker = None
        if self._changelogProgress is not None:
            self._changelogProgress.close()
            self._changelogProgress = None
        self.computeChangelogButton.setEnabled(True)

    def _onChangelogFinished(self, worker, output, errorMessage):
        if self._activeChangelogWorker is not worker:
            return  # superseded by a cancel or a newer compute request
        self._activeChangelogWorker = None
        if self._changelogProgress is not None:
            self._changelogProgress.close()
            self._changelogProgress = None
        self.computeChangelogButton.setEnabled(True)
        if errorMessage:
            QMessageBox.critical(
                self, "Error", f"Failed to compute changelog:\n{errorMessage}"
            )
            return
        self.changelogView.setPlainText(
            output.rstrip("\n") if output else "No changelog output."
        )

    def _showVersionInfo(self, version):
        stats = self.pdf.getStats()
        versions = stats.get("Versions", [])
        if version >= len(versions):
            self.versionInfoView.setPlainText(f"Version {version}: not found")
            return
        self.versionInfoView.setPlainText(
            self._formatVersionStats(version, versions[version])
        )
        self.tabs.setCurrentIndex(self.versionInfoTabIndex)

    def _showAllVersionsInfo(self):
        if self.pdf is None:
            return
        stats = self.pdf.getStats()
        versions = stats.get("Versions", [])
        blocks = [
            self._formatVersionStats(version, versionStats)
            for version, versionStats in enumerate(versions)
        ]
        self.versionInfoView.setPlainText("\n\n".join(blocks))
        self.tabs.setCurrentIndex(self.versionInfoTabIndex)

    @staticmethod
    def _formatVersionStats(version, statsVersion):
        """
        Reproduces the version summary shown by the console.
        """
        lines = [f"Version {version}:"]
        lines.append(
            f"\tCatalog: {statsVersion['Catalog'] if statsVersion['Catalog'] is not None else 'No'}"
        )
        lines.append(
            f"\tInfo: {statsVersion['Info'] if statsVersion['Info'] is not None else 'No'}"
        )

        objCount, objList = statsVersion["Objects"]
        lines.append(f"\tObjects ({objCount}): {objList}")

        if statsVersion.get("Compressed Objects") is not None:
            count, objIds = statsVersion["Compressed Objects"]
            lines.append(f"\tCompressed objects ({count}): {objIds}")

        if statsVersion.get("Errors") is not None:
            count, objIds = statsVersion["Errors"]
            lines.append(f"\tErrors ({count}): {objIds}")

        streamCount, streamList = statsVersion["Streams"]
        lines.append(f"\tStreams ({streamCount}): {streamList}")

        if statsVersion.get("Xref Streams") is not None:
            count, objIds = statsVersion["Xref Streams"]
            lines.append(f"\tXref streams ({count}): {objIds}")

        if statsVersion.get("Object Streams") is not None:
            count, objIds = statsVersion["Object Streams"]
            lines.append(f"\tObject streams ({count}): {objIds}")

        if int(streamCount) > 0:
            count, objIds = statsVersion["Encoded"]
            lines.append(f"\tEncoded ({count}): {objIds}")
            if statsVersion.get("Decoding Errors") is not None:
                count, objIds = statsVersion["Decoding Errors"]
                lines.append(f"\tDecoding errors ({count}): {objIds}")

        if statsVersion.get("URIs") is not None:
            count, objIds = statsVersion["URIs"]
            lines.append(f"\tObjects with URIs ({count}): {objIds}")

        if statsVersion.get("Objects with JS code") is not None:
            count, objIds = statsVersion["Objects with JS code"]
            lines.append(f"\tObjects with JS code ({count}): {objIds}")

        actions = statsVersion.get("Actions")
        events = statsVersion.get("Events")
        vulns = statsVersion.get("Vulns")
        elements = statsVersion.get("Elements")
        if any(d is not None for d in (actions, events, vulns, elements)):
            total = 0
            for eachDict in (actions, events, vulns, elements):
                if eachDict is not None:
                    for _, v in eachDict.items():
                        total += len(v)
            lines.append(f"\tSuspicious elements ({total}):")
            if events is not None:
                for event in events:
                    lines.append(
                        f"\t\t{event} ({len(events[event])}): {sorted(events[event])}"
                    )
            if actions is not None:
                for action in actions:
                    lines.append(
                        f"\t\t{action} ({len(actions[action])}): {actions[action]}"
                    )
            if vulns is not None:
                for vuln in vulns:
                    if vuln in vulnsDict:
                        vulnName, vulnCVEList = vulnsDict[vuln]
                        cves = ",".join(vulnCVEList)
                        lines.append(
                            f"\t\t{vulnName} ({cves}) ({len(vulns[vuln])}): {vulns[vuln]}"
                        )
                    else:
                        lines.append(f"\t\t{vuln} ({len(vulns[vuln])}): {vulns[vuln]}")
            if elements is not None:
                for element in elements:
                    if element in vulnsDict:
                        vulnName, vulnCVEList = vulnsDict[element]
                        cves = ",".join(vulnCVEList)
                        lines.append(f"\t\t{vulnName} ({cves}): {elements[element]}")
                    else:
                        lines.append(
                            f"\t\t{element} ({len(elements[element])}): {elements[element]}"
                        )

        urls = statsVersion.get("URLs")
        if urls is not None:
            lines.append("\tFound URLs:")
            for url in urls:
                lines.append(f"\t\t{url}")

        return "\n".join(lines)

    def _populateErrorsTab(self, stats=None):
        if stats is None:
            stats = self.pdf.getStats()
        errors = stats.get("Errors", [])
        self.tabs.setTabText(self.errorsTabIndex, f"Errors ({len(errors)})")
        if errors:
            self.errorsView.setPlainText("\n".join(errors))
        else:
            self.errorsView.setPlainText("No errors reported.")

    def _populateSuspiciousTab(self, stats=None):
        if stats is None:
            stats = self.pdf.getStats()
        self.suspiciousTree.clear()
        totalCount = 0

        def addCategory(parentItems, label, objIds):
            nonlocal totalCount
            if not objIds:
                return
            distinctIds = sorted(set(objIds))
            catItem = QTreeWidgetItem([f"{label} ({len(distinctIds)})", ""])
            for objId in distinctIds:
                leaf = QTreeWidgetItem([f"Object {objId}", str(version)])
                leaf.setData(
                    0, Qt.ItemDataRole.UserRole, {"id": objId, "version": version}
                )
                catItem.addChild(leaf)
            parentItems.append(catItem)
            totalCount += len(distinctIds)

        def describeVulnKey(name):
            if name in vulnsDict:
                vulnName, vulnCVEList = vulnsDict[name]
                cves = ",".join(vulnCVEList)
                return f"{vulnName} ({cves})" if cves else vulnName
            return name

        for version, statsVersion in enumerate(stats.get("Versions", [])):
            versionItems = []

            jsEntry = statsVersion.get("Objects with JS code")
            if jsEntry:
                addCategory(versionItems, "Objects with JS code", jsEntry[1])

            uriEntry = statsVersion.get("URIs")
            if uriEntry:
                addCategory(versionItems, "Objects with URIs", uriEntry[1])

            for label, sourceKey, describe in (
                ("Action", "Actions", lambda n: n),
                ("Event", "Events", lambda n: n),
                ("Vuln", "Vulns", describeVulnKey),
                ("Element", "Elements", describeVulnKey),
            ):
                group = statsVersion.get(sourceKey)
                if not group:
                    continue
                for name, objIds in group.items():
                    addCategory(versionItems, f"{label}: {describe(name)}", objIds)

            if versionItems:
                versionRoot = QTreeWidgetItem([f"Version {version}", ""])
                for item in versionItems:
                    versionRoot.addChild(item)
                self.suspiciousTree.addTopLevelItem(versionRoot)
                versionRoot.setExpanded(True)

        self.tabs.setTabText(self.suspiciousTabIndex, f"Suspicious ({totalCount})")
        if totalCount == 0:
            placeholder = QTreeWidgetItem(["Nothing suspicious found.", ""])
            self.suspiciousTree.addTopLevelItem(placeholder)
        self.suspiciousTree.setHeaderHidden(totalCount == 0)

    def _onSuspiciousItemActivated(self, item, _column):
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data:
            return
        self._selectTreeObject(data["id"], data["version"])

    def _populateCommentsTab(self):
        """
        Annotation comments by page (replies under what they answer), then the
        ones a later version removed and the ones no page lists, then the %
        comments of the file syntax. A double click opens the object.
        """
        self.commentsTree.clear()
        annotations = self.pdf.getComments()
        syntaxComments = self.pdf.getSyntaxComments()
        total = len(annotations) + len(syntaxComments)
        byId = {c["object_id"]: c for c in annotations if c["object_id"] is not None}
        shown = 0

        def objectData(objectId, version):
            return {"id": objectId, "version": version}

        def commentItem(comment, seen):
            nonlocal shown
            shown += 1
            seen.add(id(comment))
            text = f'{comment["subtype"]} {commentObjectTag(comment)}'
            if comment["contents"]:
                text += f': {oneLine(comment["contents"], 100)}'
            item = QTreeWidgetItem(
                [
                    text,
                    comment["author"] or "",
                    comment["modified"] or comment["created"] or "",
                    "; ".join(commentNotes(comment)),
                ]
            )
            item.setToolTip(0, comment["contents"] or comment["rich_text"] or "")
            version = (
                comment["history"][-1]["version"]
                if comment["history"]
                else comment["version"]
            )
            if comment["object_id"] is not None:
                item.setData(
                    0,
                    Qt.ItemDataRole.UserRole,
                    objectData(comment["object_id"], version),
                )
            elif comment["page_object_id"] is not None:
                item.setData(
                    0,
                    Qt.ItemDataRole.UserRole,
                    objectData(comment["page_object_id"], version),
                )
            for replyId in comment["replies"] + comment["group_members"]:
                reply = byId.get(replyId)
                if (
                    reply is not None
                    and id(reply) not in seen
                    and shown < MAX_COMMENT_ROWS
                ):
                    item.addChild(commentItem(reply, seen))
            return item

        def size(item):
            return 1 + sum(size(item.child(i)) for i in range(item.childCount()))

        def category(label, comments):
            node = QTreeWidgetItem([label, "", "", ""])
            seen = set()
            for comment in comments:
                if id(comment) not in seen and shown < MAX_COMMENT_ROWS:
                    node.addChild(commentItem(comment, seen))
            node.setText(
                0,
                f"{label} ({sum(size(node.child(i)) for i in range(node.childCount()))})",
            )
            return node

        roots = [c for c in annotations if c["depth"] == 0]
        if annotations:
            annotationRoot = QTreeWidgetItem(
                [f"Annotations ({len(annotations)})", "", "", ""]
            )
            pages = sorted(
                {
                    c["page"]
                    for c in roots
                    if c["status"] == "present" and c["page"] is not None
                }
            )
            for page in pages:
                annotationRoot.addChild(
                    category(
                        f"Page {page}",
                        [
                            c
                            for c in roots
                            if c["status"] == "present" and c["page"] == page
                        ],
                    )
                )
            for status, label in (
                ("removed", "Removed by a later version"),
                ("orphan", "Not listed on any page"),
            ):
                members = [c for c in roots if c["status"] == status]
                if members:
                    annotationRoot.addChild(category(label, members))
            self.commentsTree.addTopLevelItem(annotationRoot)
            annotationRoot.setExpanded(True)

        if syntaxComments:
            syntaxRoot = QTreeWidgetItem(
                [f"In the file syntax ({len(syntaxComments)})", "", "", ""]
            )
            for comment in syntaxComments:
                if shown >= MAX_COMMENT_ROWS:
                    break
                shown += 1
                where = comment["location"]
                if comment["version"] is not None:
                    where = f'version {comment["version"]}, {where}'
                item = QTreeWidgetItem(
                    [
                        f'Offset {comment["offset"]}: {oneLine(printableText(comment["text"]), 100)}',
                        "",
                        "",
                        where,
                    ]
                )
                item.setToolTip(0, printableText(comment["text"]))
                if comment["object_id"] is not None and comment["version"] is not None:
                    item.setData(
                        0,
                        Qt.ItemDataRole.UserRole,
                        objectData(comment["object_id"], comment["version"]),
                    )
                syntaxRoot.addChild(item)
            self.commentsTree.addTopLevelItem(syntaxRoot)
            syntaxRoot.setExpanded(True)

        if shown < total:
            self.commentsTree.addTopLevelItem(
                QTreeWidgetItem(
                    [
                        f"{total - shown} more not shown: use the comments command",
                        "",
                        "",
                        "",
                    ]
                )
            )
        self.tabs.setTabText(self.commentsTabIndex, f"Comments ({total})")
        if total == 0:
            self.commentsTree.addTopLevelItem(
                QTreeWidgetItem(["No comments found.", "", "", ""])
            )
        self.commentsTree.setHeaderHidden(total == 0)

    def _onCommentItemActivated(self, item, _column):
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data:
            return
        self._selectTreeObject(data["id"], data["version"])

    def _populateAttachmentsTab(self):
        """
        Attachments grouped by where they're reachable from.
        """
        self.attachmentsTree.clear()
        attachments = self.pdf.getAttachments()
        total = len(attachments)

        def attachmentItem(attachment):
            size = attachment["size"]
            sizeText = f"{size:,} bytes" if isinstance(size, int) else "-"
            item = QTreeWidgetItem(
                [
                    attachment["file_name"] or "(unnamed)",
                    sizeText,
                    attachment["mime_type"] or "",
                    attachment["checksum_md5"] or "",
                ]
            )
            tooltipParts = [attachment["location"]]
            if attachment["description"]:
                tooltipParts.append(attachment["description"])
            item.setToolTip(0, "\n".join(tooltipParts))
            if (
                attachment["nav_id"] is not None
                and attachment["nav_version"] is not None
            ):
                item.setData(
                    0,
                    Qt.ItemDataRole.UserRole,
                    {"id": attachment["nav_id"], "version": attachment["nav_version"]},
                )
            return item

        byPage = [a for a in attachments if a["page"] is not None]
        orphanAnnotations = [
            a for a in attachments if a["page"] is None and a["source"] == "annotation"
        ]
        documentLevel = [a for a in attachments if a["source"] == "embedded_files"]

        if byPage:
            for page in sorted({a["page"] for a in byPage}):
                members = [a for a in byPage if a["page"] == page]
                pageNode = QTreeWidgetItem([f"Page {page} ({len(members)})", "", ""])
                for attachment in members:
                    pageNode.addChild(attachmentItem(attachment))
                self.attachmentsTree.addTopLevelItem(pageNode)
                pageNode.setExpanded(True)

        if orphanAnnotations:
            orphanNode = QTreeWidgetItem(
                [f"Not linked to any page ({len(orphanAnnotations)})", "", ""]
            )
            for attachment in orphanAnnotations:
                orphanNode.addChild(attachmentItem(attachment))
            self.attachmentsTree.addTopLevelItem(orphanNode)
            orphanNode.setExpanded(True)

        if documentLevel:
            docNode = QTreeWidgetItem(
                [
                    f"Document-level, no page (Names tree) ({len(documentLevel)})",
                    "",
                    "",
                ]
            )
            for attachment in documentLevel:
                docNode.addChild(attachmentItem(attachment))
            self.attachmentsTree.addTopLevelItem(docNode)
            docNode.setExpanded(True)

        self.tabs.setTabText(self.attachmentsTabIndex, f"Attachments ({total})")
        if total == 0:
            self.attachmentsTree.addTopLevelItem(
                QTreeWidgetItem(["No attachments found.", "", ""])
            )
        self.attachmentsTree.setHeaderHidden(total == 0)

    def _onAttachmentItemActivated(self, item, _column):
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data:
            return
        self._selectTreeObject(data["id"], data["version"])

    ## Object data ##

    def _onTreeContextMenu(self, pos):
        if self.pdf is None:
            return
        item = self.tree.itemAt(pos)
        if item is None:
            return
        data = item.data(0, Qt.ItemDataRole.UserRole) or {}
        if data.get("kind") != "object":
            return
        objId = data["id"]
        version = data["version"]
        obj = self.pdf.getObject(objId, version)
        if obj is None:
            return
        hasJS = obj.containsJS()
        isStream = obj.getType() == "stream"
        if not hasJS and not isStream:
            return
        menu = QMenu(self)
        if hasJS:
            analyseAction = menu.addAction("Analyse JS...")
            analyseAction.triggered.connect(
                lambda checked=False, oid=objId, v=version: self._analyseObjectJS(
                    oid, v
                )
            )
        if isStream:
            extractMenu = menu.addMenu("Extract Stream")
            decodedAction = extractMenu.addAction("Decoded")
            decodedAction.triggered.connect(
                lambda checked=False, oid=objId, v=version: self._extractStream(
                    oid, v, decoded=True
                )
            )
            rawAction = extractMenu.addAction("Raw")
            rawAction.triggered.connect(
                lambda checked=False, oid=objId, v=version: self._extractStream(
                    oid, v, decoded=False
                )
            )
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    def _extractStream(self, objId, version, decoded):
        """
        Saves an object's stream content to a file the user picks.
        Options: Decoded, Raw, file save location.
        """
        if self.pdf is None or self.fileName is None:
            return
        obj = self.pdf.getObject(objId, version)
        if obj is None or obj.getType() != "stream":
            return
        value = obj.getStream() if decoded else obj.getRawStream()
        if decoded and value in (-1, ""):
            QMessageBox.warning(
                self,
                "Extract Stream",
                f"The stream in object {objId} cannot be decoded.",
            )
            return
        if isinstance(value, str):
            value = value.encode("latin-1")

        baseName = os.path.splitext(os.path.basename(self.fileName))[0]
        directory = os.path.dirname(self.fileName)
        defaultName = os.path.join(
            directory, f"object_{objId}_v{version}_{baseName}.stream"
        )

        saveName, _selectedFilter = QFileDialog.getSaveFileName(
            self,
            "Extract Stream",
            defaultName,
            "Stream Files (*.stream);;All Files (*)",
        )
        if not saveName:
            return
        try:
            with open(saveName, "wb") as outFile:
                outFile.write(value)
        except OSError as exc:
            QMessageBox.critical(
                self, "Extract Stream", f"Could not write to {saveName}:\n{exc}"
            )
            return
        self.statusBar().showMessage(f"Stream extracted to {saveName}", 5000)

    def _analyseObjectJS(self, objId, version):
        """
        Runs 'js_analyse object <id> <version>', scoped to just objId,
        in a throwaway child process rather than on a background QThread in this process.
        Running it in a separate process means the analysis process can stop and the GUI
        thread can remain.
        """
        if self.pdf is None or self.fileName is None:
            return
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Analyse JS")
        box.setText(f"Analyse the JavaScript in object {objId} (version {version})?")
        box.setInformativeText(
            "This runs only this object's JavaScript through peepdf's JS "
            "engine, in a separate process, to show the beautified/"
            "deobfuscated code - without re-analysing the rest of the "
            "document.\n\n"
            "If the PDF becomes stuck in an infinite loop, the first part "
            "of this analysis runs in a separate process, so clicking "
            "Cancel below will end just that process - the GUI itself stays open.\n\n"
            "The result is written to the Console tab."
        )
        analyseButton = box.addButton("Analyse", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(analyseButton)
        box.exec()
        if box.clickedButton() is not analyseButton:
            return

        process = QProcess(self)
        process.setProgram(sys.executable)
        process.setArguments(
            [
                "-m",
                "peepdf.gui._js_subprocess",
                "object",
                os.path.abspath(self.fileName),
                str(objId),
                str(version),
            ]
        )
        process.setWorkingDirectory(_ROOT_PATH)
        self._activeObjectJSProcess = process
        process.finished.connect(
            lambda code, status, p=process: self._onObjectJSAnalysisFinished(
                p, objId, code, status
            )
        )
        process.finished.connect(process.deleteLater)

        progress = _LoadingDialog(f"Analysing JavaScript in object {objId}...", self)
        progress.canceled.connect(lambda p=process: self._cancelObjectJSAnalysis(p))
        self._objectJSProgress = progress

        self.statusBar().showMessage(f"Analysing JS in object {objId}...")
        progress.show()
        QApplication.processEvents()
        process.start()

    def _cancelObjectJSAnalysis(self, process):
        if self._activeObjectJSProcess is process:
            self._activeObjectJSProcess = None
        if self._objectJSProgress is not None:
            self._objectJSProgress.close()
            self._objectJSProgress = None
        self.statusBar().showMessage(self.fileName or "No file open")
        process.kill()

    def _onObjectJSAnalysisFinished(self, process, objId, exitCode, exitStatus):
        if self._activeObjectJSProcess is not process:
            return  # superseded by a cancel
        self._activeObjectJSProcess = None
        if self._objectJSProgress is not None:
            self._objectJSProgress.close()
            self._objectJSProgress = None
        self.statusBar().showMessage(self.fileName or "No file open")

        if exitStatus == QProcess.ExitStatus.CrashExit or exitCode != 0:
            errorOutput = bytes(process.readAllStandardError()).decode(
                "utf-8", errors="replace"
            )
            QMessageBox.critical(
                self,
                "Analysis error",
                f"Failed to analyse object {objId}:\n"
                f"{errorOutput or 'The analysis process exited unexpectedly.'}",
            )
            return
        output = bytes(process.readAllStandardOutput()).decode(
            "utf-8", errors="replace"
        )
        self._appendConsoleText(
            (output or f"No JS analysis output for object {objId}.").rstrip("\n")
        )
        self.tabs.setCurrentIndex(self.consoleTabIndex)

    def onTreeSelectionChanged(self):
        items = self.tree.selectedItems()
        if not items:
            return
        data = items[0].data(0, Qt.ItemDataRole.UserRole)
        if not data:
            return
        if data.get("kind") == "version":
            self._currentSelection = None
            self._clearObjectView()
            self._showVersionInfo(data["version"])
        elif data.get("kind") == "object":
            self._currentSelection = (data["id"], data["version"])
            self._showObject(data["id"], data["version"])
            self.tabs.setCurrentWidget(self.objectTabContainer)

    def _clearObjectView(self):
        self.objHeaderLabel.setText("No object selected")
        self.decodedValueView.clear()
        self.rawValueView.clear()
        self._currentRawStream = None
        self._currentDecodedStream = None
        self.hexOffsetView.clear()
        self.hexBytesView.clear()
        self.hexAsciiView.clear()
        self.decodedHexOffsetView.clear()
        self.decodedHexBytesView.clear()
        self.decodedHexAsciiView.clear()
        self.objStatsTable.setRowCount(0)

    def _showObject(self, objId, version):
        obj = self.pdf.getObject(objId, version)
        if obj is None:
            self._clearObjectView()
            self.objHeaderLabel.setText(
                f"Object {objId} (version {version}): not found"
            )
            return

        objType = obj.getType()
        self.objHeaderLabel.setText(
            f"Object {objId}  |  Version {version}  |  Type: {objType}"
        )

        try:
            decodedValue = obj.getValue()
        except Exception as exc:
            decodedValue = f"[!] Error getting decoded value: {exc}"
        try:
            rawValue = obj.getRawValue()
        except Exception as exc:
            rawValue = f"[!] Error getting raw value: {exc}"

        self.decodedValueView.setPlainText(str(decodedValue))
        self.rawValueView.setPlainText(str(rawValue))

        if objType == "stream":
            try:
                rawStream = obj.getRawStream()
            except Exception:
                rawStream = None
            self._currentRawStream = rawStream
            self._setHexColumns(
                self.hexOffsetView, self.hexBytesView, self.hexAsciiView, rawStream
            )
            self.objSubTabs.setTabEnabled(self.rawHexTabIndex, True)

            try:
                decodedStream = obj.getStream()
            except Exception:
                decodedStream = None
            if decodedStream in (-1, ""):
                decodedStream = None
            self._currentDecodedStream = decodedStream
            self._setHexColumns(
                self.decodedHexOffsetView,
                self.decodedHexBytesView,
                self.decodedHexAsciiView,
                decodedStream,
            )
            self.objSubTabs.setTabEnabled(self.decodedHexTabIndex, True)
        else:
            self._currentRawStream = None
            self._currentDecodedStream = None
            self._setHexColumns(
                self.hexOffsetView, self.hexBytesView, self.hexAsciiView, None
            )
            self._setHexColumns(
                self.decodedHexOffsetView,
                self.decodedHexBytesView,
                self.decodedHexAsciiView,
                None,
            )
            self.objSubTabs.setTabEnabled(self.rawHexTabIndex, False)
            self.objSubTabs.setTabEnabled(self.decodedHexTabIndex, False)

        try:
            stats = obj.getStats()
        except Exception:
            stats = {}
        self.objStatsTable.setRowCount(len(stats))
        for row, (key, value) in enumerate(stats.items()):
            self.objStatsTable.setItem(row, 0, QTableWidgetItem(str(key)))
            self.objStatsTable.setItem(
                row, 1, QTableWidgetItem("" if value is None else str(value))
            )
        self.objStatsTable.resizeColumnsToContents()
