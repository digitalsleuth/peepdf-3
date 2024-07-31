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
    Initial script to launch the tool
"""

import sys
import os
import argparse
import traceback
from datetime import datetime as dt
from operator import attrgetter


try:
    from peepdf.PDFCore import PDFParser, VERSION, PIL_MODULE, EMU_MODULE, JS_MODULE
    from peepdf.PDFUtils import vtcheck, getPeepJSON, getPeepXML, getUpdate
    from peepdf.PDFVulns import vulnsDict
    from peepdf.PDFConsole import PDFConsole
except ModuleNotFoundError:
    from PDFCore import PDFParser, VERSION, PIL_MODULE, EMU_MODULE, JS_MODULE
    from PDFUtils import vtcheck, getPeepJSON, getPeepXML, getUpdate
    from PDFVulns import vulnsDict
    from PDFConsole import PDFConsole

try:
    from colorama import init, Fore, Style

    COLORIZED_OUTPUT = True
except ModuleNotFoundError:
    COLORIZED_OUTPUT = False

VT_KEY = f"YOUR KEY GOES ON LINE 54 OF {__file__}, USE set vt_key yourAPIkey in interactive mode instead of -c, OR use -k yourAPIkey with -c"
DTFMT = "%Y%m%d-%H%M%S"
ERROR_LOG = f"peepdf_errors-{dt.now().strftime(DTFMT)}.txt"


class SortHelp(argparse.HelpFormatter):
    def add_arguments(self, actions):
        actions = sorted(actions, key=attrgetter("option_strings"))
        super().add_arguments(actions)


def main():
    global COLORIZED_OUTPUT
    versionHeader = f"Version: peepdf {VERSION}"
    author = "Jose Miguel Esparza and Corey Forman"
    url = "https://github.com/digitalsleuth/peepdf-3"
    newLine = os.linesep
    currentDir = os.getcwd()
    errorsFile = os.path.join(currentDir, ERROR_LOG)
    peepdfHeader = f"{versionHeader}{newLine * 2}{url}{newLine}{author}{newLine}"
    argsParser = argparse.ArgumentParser(
        usage="peepdf [options] pdf",
        description=versionHeader,
        formatter_class=SortHelp,
    )
    argsParser.add_argument(
        "pdf",
        help="PDF File",
        nargs="?",
    )
    argsParser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        dest="isInteractive",
        default=False,
        help="Sets console mode.",
    )
    argsParser.add_argument(
        "-s",
        "--load-script",
        action="store",
        type=str,
        dest="scriptFile",
        help="Loads the commands stored in the specified file and execute them.",
    )
    argsParser.add_argument(
        "-c",
        "--check-vt",
        action="store_true",
        dest="checkOnVT",
        default=False,
        help="Checks the hash of the PDF file on VirusTotal.",
    )
    argsParser.add_argument(
        "-k",
        "--key",
        dest="vtApiKey",
        default=VT_KEY,
        help="VirusTotal API Key, used with -c/--check-vt",
    )
    argsParser.add_argument(
        "-f",
        "--force-mode",
        action="store_true",
        dest="isForceMode",
        default=False,
        help="Sets force parsing mode to ignore errors.",
    )
    argsParser.add_argument(
        "-l",
        "--loose-mode",
        action="store_true",
        dest="isLooseMode",
        default=False,
        help="Sets loose parsing mode to catch malformed objects.",
    )
    argsParser.add_argument(
        "-m",
        "--manual-analysis",
        action="store_true",
        dest="isManualAnalysis",
        default=False,
        help="Avoids automatic Javascript analysis. Useful with eternal loops like heap spraying.",
    )
    argsParser.add_argument(
        "-g",
        "--grinch-mode",
        action="store_true",
        dest="avoidColors",
        default=False,
        help="Avoids colorized output.",
    )
    argsParser.add_argument(
        "-v",
        "--version",
        action="store_true",
        dest="version",
        default=False,
        help="Shows program's version number.",
    )
    argsParser.add_argument(
        "-x",
        "--xml",
        action="store_true",
        dest="xmlOutput",
        default=False,
        help="Shows the document information in XML format.",
    )
    argsParser.add_argument(
        "-j",
        "--json",
        action="store_true",
        dest="jsonOutput",
        default=False,
        help="Shows the document information in JSON format.",
    )
    argsParser.add_argument(
        "-C",
        "--command",
        action="append",
        type=str,
        dest="commands",
        help="Specifies a command from the interactive console to be executed.",
    )
    argsParser.add_argument(
        "-o",
        "--ocr",
        action="store_true",
        dest="getText",
        help="Extract text from the PDF",
    )
    argsParser.add_argument(
        "-u",
        "--update",
        action="store_true",
        dest="update",
        help="Fetches updates for the Vulnerability List",
    )
    args = argsParser.parse_args()
    numArgs = len(sys.argv) - 1
    stats = ""
    pdf = None
    fileName = None
    statsDict = None
    vtJsonDict = None

    try:
        # Avoid colors in the output
        if not COLORIZED_OUTPUT or args.avoidColors:
            warningColor = ""
            errorColor = ""
            alertColor = ""
            staticColor = ""
            resetColor = ""
        else:
            warningColor = Fore.YELLOW
            errorColor = Fore.RED
            alertColor = Fore.RED
            staticColor = Fore.BLUE
            resetColor = Style.RESET_ALL
        fileName = args.pdf
        if args.version:
            print(peepdfHeader)
        if args.update:
            if numArgs > 1:
                print(
                    "[*] Only one argument required for update, other arguments will be ignored"
                )
            getUpdate()
        else:
            if fileName is not None and not os.path.exists(fileName):
                sys.exit(f'[!] Error: The file "{fileName}" does not exist')
            if numArgs == 2 and fileName is not None:
                if not os.path.exists(fileName):
                    sys.exit(f'[!] Error: The file "{fileName}" does not exist')
            elif numArgs == 2 and (args.isInteractive and args.avoidColors):
                console = PDFConsole(pdf, VT_KEY, args.avoidColors)
                try:
                    console.cmdloop()
                except Exception as exc:
                    errorMessage = "[!] Error: Exception while launching Interactive mode without a PDF file"
                    traceback.print_exc(file=open(errorsFile, "a", encoding="utf-8"))
                    raise Exception("PeepException", "Open an Issue on GitHub") from exc
            elif (numArgs > 4 and not fileName) or (
                numArgs == 0 and not args.isInteractive
            ):
                sys.exit(argsParser.print_help())
            if args.jsonOutput and args.xmlOutput:
                sys.exit("[*] Only one of XML or JSON should be selected")
            if args.scriptFile is not None:
                if not os.path.exists(args.scriptFile):
                    sys.exit(
                        f'[!] Error: The script file "{args.scriptFile}" does not exist'
                    )
            if fileName is not None:
                pdfParser = PDFParser()
                ret, pdf = pdfParser.parse(
                    fileName,
                    args.isForceMode,
                    args.isLooseMode,
                    args.isManualAnalysis,
                )
                if args.getText:
                    output = pdfParser.getText(fileName)
                    sys.stdout.write(f"Text content of: {fileName}{newLine}")
                    sys.stdout.write(output)
                    raise SystemExit(0)
                if args.checkOnVT and not "vt_key" in args.vtApiKey:
                    # Checks the MD5 on VirusTotal
                    vtKey = args.vtApiKey
                    md5Hash = pdf.getMD5()
                    ret = vtcheck(md5Hash, vtKey)
                    if ret[0] == -1:
                        pdf.addError(ret[1])
                        if "not found" in ret[1]:
                            sys.exit(f"[!] Error: {ret[1]} on VirusTotal.")
                    else:
                        vtJsonDict = ret[1]
                        maliciousCount = vtJsonDict["data"]["attributes"][
                            "last_analysis_stats"
                        ]["malicious"]
                        totalCount = 0
                        for result in (
                            "harmless",
                            "suspicious",
                            "malicious",
                            "undetected",
                        ):
                            totalCount += vtJsonDict["data"]["attributes"][
                                "last_analysis_stats"
                            ][result]
                        pdf.setDetectionRate([maliciousCount, totalCount])
                        pdf.setDetectionReport(
                            f'https://www.virustotal.com/gui/file/{vtJsonDict["data"]["attributes"]["sha256"]}'
                        )
                elif args.checkOnVT and "vt_key" in args.vtApiKey:
                    sys.exit(
                        f"[*] Warning: Your API key is not properly set - {VT_KEY}"
                    )
                statsDict = pdf.getStats()

            if args.xmlOutput:
                try:
                    xml = getPeepXML(statsDict, VERSION)
                    xml = xml.decode("latin-1")
                    sys.stdout.write(xml)
                except Exception as exc:
                    errorMessage = "[!] Error: Exception while generating the XML file"
                    traceback.print_exc(file=open(errorsFile, "a", encoding="utf-8"))
                    raise Exception("PeepException", "Open an Issue on GitHub") from exc
            elif args.jsonOutput and not args.commands:
                try:
                    jsonReport = getPeepJSON(statsDict, VERSION)
                    sys.stdout.write(jsonReport)
                except Exception as exc:
                    errorMessage = (
                        "[!] Error: Exception while generating the JSON report"
                    )
                    traceback.print_exc(file=open(errorsFile, "a", encoding="utf-8"))
                    raise Exception("PeepException", "Open an Issue on GitHub") from exc
            else:
                if COLORIZED_OUTPUT and not args.avoidColors:
                    try:
                        init()
                    except:
                        COLORIZED_OUTPUT = False
                if args.scriptFile is not None:
                    if os.path.exists(args.scriptFile):
                        scriptFileObject = open(args.scriptFile, "rb")
                    else:
                        sys.exit(
                            f"[*] Warning: The file {args.scriptFile} cannot be found - check your path and try again!"
                        )
                    console = PDFConsole(
                        pdf, VT_KEY, args.avoidColors, stdin=scriptFileObject
                    )
                    try:
                        console.cmdloop()
                    except Exception as exc:
                        errorMessage = (
                            "[!] Error: Exception not handled using the script mode"
                        )
                        scriptFileObject.close()
                        traceback.print_exc(
                            file=open(errorsFile, "a", encoding="utf-8")
                        )
                        raise Exception(
                            "PeepException", "Open an Issue on GitHub"
                        ) from exc
                elif args.commands is not None:
                    console = PDFConsole(pdf, VT_KEY, args.avoidColors)
                    try:
                        for command in args.commands:
                            console.onecmd(command)
                    except Exception as exc:
                        errorMessage = (
                            "[!] Error: Exception not handled using the script commands"
                        )
                        traceback.print_exc(
                            file=open(errorsFile, "a", encoding="utf-8")
                        )
                        raise Exception(
                            "PeepException", "Open an Issue on GitHub"
                        ) from exc
                else:
                    if statsDict is not None:
                        if COLORIZED_OUTPUT and not args.avoidColors:
                            beforeStaticLabel = staticColor
                        else:
                            beforeStaticLabel = ""

                        if not JS_MODULE:
                            warningMessage = "[*] Warning: STPyV8 is not installed"
                            stats += (
                                f"{warningColor}{warningMessage}{resetColor}{newLine}"
                            )
                        if not EMU_MODULE:
                            warningMessage = "[*] Warning: pylibemu is not installed"
                            stats += (
                                f"{warningColor}{warningMessage}{resetColor}{newLine}"
                            )
                        if not PIL_MODULE:
                            warningMessage = "[*] Warning: Python Imaging Library (PIL) is not installed"
                            stats += (
                                f"{warningColor}{warningMessage}{resetColor}{newLine}"
                            )
                        errors = statsDict["Errors"]
                        for error in errors:
                            if error.find("Decryption error") != -1:
                                stats += f"{errorColor}{error}{resetColor}{newLine}"
                        if stats != "":
                            stats += newLine
                        statsDict = pdf.getStats()
                        latestVersion = len(statsDict["Versions"]) - 1
                        latestMetadata = pdf.getBasicMetadata(latestVersion)
                        stats += f'{beforeStaticLabel}File: {resetColor}{statsDict["File"]}{newLine}'
                        if (
                            "title" in latestMetadata
                            and latestMetadata["title"].isascii()
                        ):
                            stats += f'{beforeStaticLabel}Title: {resetColor}{latestMetadata["title"]}{newLine}'
                        stats += f'{beforeStaticLabel}MD5: {resetColor}{statsDict["MD5"]}{newLine}'
                        stats += f'{beforeStaticLabel}SHA1: {resetColor}{statsDict["SHA1"]}{newLine}'
                        stats += f'{beforeStaticLabel}SHA256: {resetColor}{statsDict["SHA256"]}{newLine}'
                        stats += f'{beforeStaticLabel}Size: {resetColor}{statsDict["Size"]} bytes{newLine}'
                        stats += f'{beforeStaticLabel}IDs: {resetColor}{statsDict["IDs"]}{newLine}'
                        if args.checkOnVT:
                            if statsDict["Detection"] != []:
                                detectionReportInfo = ""
                                if statsDict["Detection"] is not None:
                                    detectionColor = ""
                                    if COLORIZED_OUTPUT and not args.avoidColors:
                                        detectionLevel = statsDict["Detection"][0] / (
                                            statsDict["Detection"][1] / 3
                                        )
                                        if detectionLevel == 0:
                                            detectionColor = alertColor
                                        elif detectionLevel == 1:
                                            detectionColor = warningColor
                                    detectionRate = (
                                        f'{detectionColor}{statsDict["Detection"][0]}'
                                        f'{resetColor}/{statsDict["Detection"][1]}'
                                    )
                                    if statsDict["Detection report"] != "":
                                        detectionReportInfo = (
                                            f"{beforeStaticLabel}Detection report: "
                                            f'{resetColor}{statsDict["Detection report"]}{newLine}'
                                        )
                                else:
                                    detectionRate = "File not found on VirusTotal"
                                stats += f"{beforeStaticLabel}Detection: {resetColor}{detectionRate}{newLine}"
                                stats += detectionReportInfo
                        stats += f'{beforeStaticLabel}PDF Format Version: {resetColor}{statsDict["Version"]}{newLine}'
                        stats += f'{beforeStaticLabel}Binary: {resetColor}{statsDict["Binary"]}{newLine}'
                        stats += f'{beforeStaticLabel}Linearized: {resetColor}{statsDict["Linearized"]}{newLine}'
                        stats += f'{beforeStaticLabel}Encrypted: {resetColor}{statsDict["Encrypted"]}'
                        if statsDict["Encryption Algorithms"] != []:
                            stats += " ("
                            for algorithmInfo in statsDict["Encryption Algorithms"]:
                                stats += (
                                    f"{algorithmInfo[0]} {str(algorithmInfo[1])} bits, "
                                )
                            stats = f"{stats[:-2]})"
                        stats += newLine
                        stats += f'{beforeStaticLabel}Updates: {resetColor}{statsDict["Updates"]}{newLine}'
                        stats += f'{beforeStaticLabel}Objects: {resetColor}{statsDict["Objects"]}{newLine}'
                        stats += f'{beforeStaticLabel}Streams: {resetColor}{statsDict["Streams"]}{newLine}'
                        stats += f'{beforeStaticLabel}URIs: {resetColor}{statsDict["URIs"]}{newLine}'
                        stats += f'{beforeStaticLabel}Comments: {resetColor}{statsDict["Comments"]}{newLine}'
                        stats += f'{beforeStaticLabel}Errors: {resetColor}{str(len(statsDict["Errors"]))}{newLine * 2}'
                        for version in range(len(statsDict["Versions"])):
                            statsVersion = statsDict["Versions"][version]
                            stats += f"{beforeStaticLabel}Version {resetColor}{str(version)}:{newLine}"
                            if statsVersion["Catalog"] is not None:
                                stats += f'{beforeStaticLabel}\tCatalog: {resetColor}{statsVersion["Catalog"]}{newLine}'
                            else:
                                stats += f"{beforeStaticLabel}\tCatalog: {resetColor}No {newLine}"
                            if statsVersion["Info"] is not None:
                                stats += f'{beforeStaticLabel}\tInfo: {resetColor}{statsVersion["Info"]}{newLine}'
                            else:
                                stats += f"{beforeStaticLabel}\tInfo: {resetColor}No {newLine}"
                            stats += (
                                f'{beforeStaticLabel}\tObjects ({statsVersion["Objects"][0]}): '
                                f'{resetColor}{str(statsVersion["Objects"][1])}{newLine}'
                            )
                            if statsVersion["Compressed Objects"] is not None:
                                stats += (
                                    f"{beforeStaticLabel}\tCompressed objects "
                                    f'({statsVersion["Compressed Objects"][0]}): '
                                    f'{resetColor}{str(statsVersion["Compressed Objects"][1])}{newLine}'
                                )
                            if statsVersion["Errors"] is not None:
                                stats += (
                                    f'{beforeStaticLabel}\tErrors ({statsVersion["Errors"][0]}): '
                                    f'{resetColor}{str(statsVersion["Errors"][1])}{newLine}'
                                )
                            stats += (
                                f'{beforeStaticLabel}\tStreams ({statsVersion["Streams"][0]}): '
                                f'{resetColor}{str(statsVersion["Streams"][1])}'
                            )
                            if statsVersion["Xref Streams"] is not None:
                                stats += (
                                    f"{newLine}{beforeStaticLabel}\tXref streams "
                                    f'({statsVersion["Xref Streams"][0]}): {resetColor}'
                                    f'{resetColor}{str(statsVersion["Xref Streams"][1])}'
                                )
                            if statsVersion["Object Streams"] is not None:
                                stats += (
                                    f"{newLine}{beforeStaticLabel}\tObject streams "
                                    f'({statsVersion["Object Streams"][0]}): '
                                    f'{resetColor}{str(statsVersion["Object Streams"][1])}'
                                )
                            if int(statsVersion["Streams"][0]) > 0:
                                stats += (
                                    f"{newLine}{beforeStaticLabel}\tEncoded "
                                    f'({statsVersion["Encoded"][0]}): '
                                    f'{resetColor}{str(statsVersion["Encoded"][1])}'
                                )
                                if statsVersion["Decoding Errors"] is not None:
                                    stats += (
                                        f"{newLine}{beforeStaticLabel}\tDecoding errors "
                                        f'({statsVersion["Decoding Errors"][0]}): '
                                        f'{resetColor}{str(statsVersion["Decoding Errors"][1])}'
                                    )
                            if statsVersion["URIs"] is not None:
                                stats += (
                                    f"{newLine}{beforeStaticLabel}\tObjects with URIs "
                                    f'({statsVersion["URIs"][0]}): '
                                    f'{resetColor}{str(statsVersion["URIs"][1])}'
                                )
                            if COLORIZED_OUTPUT and not args.avoidColors:
                                beforeStaticLabel = warningColor
                            if statsVersion["Objects with JS code"] is not None:
                                stats += (
                                    f"{newLine}{beforeStaticLabel}\tObjects with JS code "
                                    f'({statsVersion["Objects with JS code"][0]}): '
                                    f'{resetColor}{str(statsVersion["Objects with JS code"][1])}'
                                )
                            actions = statsVersion["Actions"]
                            events = statsVersion["Events"]
                            vulns = statsVersion["Vulns"]
                            elements = statsVersion["Elements"]
                            if (
                                events is not None
                                or actions is not None
                                or vulns is not None
                                or elements is not None
                            ):
                                totalSuspicious = 0
                                for eachDict in (actions, events, vulns, elements):
                                    if eachDict is not None:
                                        for _, (_, v) in enumerate(eachDict.items()):
                                            totalSuspicious += len(v)
                                stats += f"{newLine}{beforeStaticLabel}\tSuspicious elements ({totalSuspicious}):{resetColor}{newLine}"
                                if events is not None:
                                    for event in events:
                                        stats += (
                                            f"\t\t{beforeStaticLabel}{event} ({len(events[event])}): "
                                            f"{resetColor}{str(sorted(events[event]))}{newLine}"
                                        )
                                if actions is not None:
                                    for action in actions:
                                        stats += (
                                            f"\t\t{beforeStaticLabel}{action} ({len(actions[action])}): "
                                            f"{resetColor}{str(actions[action])}{newLine}"
                                        )
                                if vulns is not None:
                                    for vuln in vulns:
                                        if vuln in vulnsDict:
                                            vulnName = vulnsDict[vuln][0]
                                            vulnCVEList = vulnsDict[vuln][1]
                                            stats += (
                                                f"\t\t{beforeStaticLabel}{vulnName} ("
                                            )
                                            for vulnCVE in vulnCVEList:
                                                stats += f"{vulnCVE},"
                                            stats = (
                                                f"{stats[:-1]}) ({len(vulns[vuln])}): "
                                                f"{resetColor}{str(vulns[vuln])}{newLine}"
                                            )
                                        else:
                                            stats += (
                                                f"\t\t{beforeStaticLabel}{vuln} ({len(vulns[vuln])}): "
                                                f"{resetColor}{str(vulns[vuln])}{newLine}"
                                            )
                                if elements is not None:
                                    for element in elements:
                                        if element in vulnsDict:
                                            vulnName = vulnsDict[element][0]
                                            vulnCVEList = vulnsDict[element][1]
                                            stats += (
                                                f"\t\t{beforeStaticLabel}{vulnName} ("
                                            )
                                            for vulnCVE in vulnCVEList:
                                                stats += f"{vulnCVE},"
                                            stats = f"{stats[:-1]}): {resetColor}{str(elements[element])}{newLine}"
                                        else:
                                            stats += (
                                                f"\t\t{beforeStaticLabel}{element} ({len(elements[element])}): "
                                                f"{resetColor}{str(elements[element])}{newLine}"
                                            )
                            if COLORIZED_OUTPUT and not args.avoidColors:
                                beforeStaticLabel = staticColor
                            urls = statsVersion["URLs"]
                            if urls is not None:
                                stats += f"{newLine}{beforeStaticLabel}\tFound URLs:{resetColor}{newLine}"
                                for url in urls:
                                    stats += f"\t\t{url}{newLine}"
                            stats += f"{newLine * 2}"
                    if fileName is not None:
                        niceOutput = stats.strip(newLine)
                        niceOutput = niceOutput.replace("\r\n", "\n")
                        niceOutput = niceOutput.replace("\r", "\n")
                        niceOutput += newLine * 2
                        sys.stdout.write(niceOutput)
                    if args.isInteractive:
                        console = PDFConsole(pdf, VT_KEY, args.avoidColors)
                        while not console.leaving:
                            try:
                                console.cmdloop()
                            except KeyboardInterrupt:
                                sys.exit()
                            except:
                                errorMessage = "[!] Error: Exception not handled using the interactive console - please report it to the author."
                                print(
                                    f"{errorColor}{errorMessage}{resetColor}{newLine}"
                                )
                                traceback.print_exc(
                                    file=open(errorsFile, "a", encoding="utf-8")
                                )
    except Exception as e:
        if len(e.args) == 2:
            excName, _ = e.args
        else:
            excName = _ = None
        if excName is None or excName != "PeepException":
            errorMessage = "[!] Error: Exception not handled"
            traceback.print_exc(file=open(errorsFile, "a", encoding="utf-8"))
        print(f"{errorColor}{errorMessage}{resetColor}{newLine}")
    finally:
        if os.path.exists(errorsFile):
            message = (
                f"{newLine}Please don't forget to report the errors found:{newLine * 2}"
            )
            message += (
                f"\t- Create an issue on the project webpage "
                f"(https://github.com/digitalsleuth/peepdf-3){newLine}"
            )
            message = f"{errorColor}{message}{resetColor}"
            sys.exit(message)


if __name__ == "__main__":
    main()
