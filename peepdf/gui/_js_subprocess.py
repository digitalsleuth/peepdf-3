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
Standalone subprocess entry point for STPyV8-backed JavaScript analysis,
used by the GUI (main_window.py) via QProcess.

STPyV8's V8 engine can only safely execute on a process's main thread - it
segfaults when entered from any other thread. Running JS analysis here, in its
own throwaway process, keeps that risk fully contained.
The GUI's process never touches STPyV8 off its main thread, and a hung analysis
is recovered from by killing this process rather than the whole application.

Usage:
    python -m peepdf.gui._js_subprocess object <fileName> <objId> <version>
    python -m peepdf.gui._js_subprocess probe <fileName> <jsErrFile>

"object" prints the same human-readable analysis text that
'js_analyse object <id> <version>' would, to stdout.

"probe" re-parses <fileName> with automatic JS analysis enabled purely to prove
that it terminates; the caller re-parses it a second time, safely, on its own main
thread once this exits 0.
"""

import sys

try:
    from peepdf.PDFCore import PDFParser
    from peepdf.PDFConsole import PDFConsole
except ModuleNotFoundError:
    from PDFCore import PDFParser
    from PDFConsole import PDFConsole


def _runObject(fileName, objId, version):
    ret, pdf = PDFParser().parse(
        fileName, forceMode=True, looseMode=True, manualAnalysis=True
    )
    if ret == -1 or pdf is None:
        print(f"[!] Error: could not parse {fileName}", file=sys.stderr)
        return 1
    console = PDFConsole(pdf, "", avoidOutputColors=True, isCommand=True)
    console.use_rawinput = False
    console.onecmd(f"js_analyse object {objId} {version}")
    return 0


def _runProbe(fileName, jsErrFile):
    ret, pdf = PDFParser().parse(
        fileName,
        forceMode=True,
        looseMode=True,
        manualAnalysis=False,
        jsErrFile=jsErrFile,
    )
    if ret == -1 or pdf is None:
        print(f"[!] Error: could not parse {fileName}", file=sys.stderr)
        return 1
    return 0


def main(argv):
    usage = (
        "Usage: python -m peepdf.gui._js_subprocess "
        "(object <fileName> <objId> <version>|probe <fileName> <jsErrFile>)"
    )
    if len(argv) < 3:
        print(usage, file=sys.stderr)
        return 2
    mode = argv[0]
    try:
        if mode == "object" and len(argv) == 4:
            return _runObject(argv[1], argv[2], argv[3])
        if mode == "probe" and len(argv) == 3:
            return _runProbe(argv[1], argv[2])
    except Exception as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        return 1
    print(usage, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
