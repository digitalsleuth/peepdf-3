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
import json
from datetime import datetime as dt


try:
    from peepdf.PDFCore import PDFParser, VERSION
    from peepdf.PDFUtils import (
        vtcheck,
        getPeepJSON,
        getPeepXML,
        getUpdate,
        DTFMT,
        ppdfLog,
    )
    from peepdf.PDFVulns import vulnsDict
    from peepdf.PDFConsole import PDFConsole, EMU_MODULE
    from peepdf.JSAnalysis import JS_MODULE
    from peepdf.PDFFilters import PIL_MODULE
except ModuleNotFoundError:
    from PDFCore import PDFParser, VERSION
    from PDFUtils import vtcheck, getPeepJSON, getPeepXML, getUpdate, DTFMT, ppdfLog
    from PDFVulns import vulnsDict
    from PDFConsole import PDFConsole, EMU_MODULE
    from JSAnalysis import JS_MODULE
    from PDFFilters import PIL_MODULE

try:
    from colorama import init, Fore, Style

    COLORIZED_OUTPUT = True
except ModuleNotFoundError:
    COLORIZED_OUTPUT = False

VT_KEY = f"YOUR KEY GOES ON LINE 64 OF {__file__}, USE set vt_key yourAPIkey in interactive mode instead of -c, OR use -k yourAPIkey with -c"


def main():
    global COLORIZED_OUTPUT
    url = "https://github.com/digitalsleuth/peepdf-3"
    newLine = os.linesep
    versionHeader = f"peepdf v{VERSION} - {url}"
    now = dt.now().strftime(DTFMT)
    argsParser = argparse.ArgumentParser(
        usage="peepdf [options] pdf",
        description=versionHeader,
    )
    argsParser.add_argument(
        "pdf",
        help="PDF File",
        nargs="?",
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
        "-C",
        "--command",
        action="append",
        type=str,
        dest="commands",
        help="Specifies a command from the interactive console to be executed.",
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
        "-g",
        "--grinch-mode",
        action="store_true",
        dest="avoidColors",
        default=False,
        help="Avoids colorized output.",
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
        "-j",
        "--json",
        action="store_true",
        dest="jsonOutput",
        default=False,
        help="Shows the document information in JSON format.",
    )
    argsParser.add_argument(
        "-k",
        "--key",
        dest="vtApiKey",
        default=VT_KEY,
        help="VirusTotal API Key, used with -c/--check-vt",
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
        "-o",
        "--ocr",
        action="store_true",
        dest="getText",
        help="Extract text from the PDF",
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
        "-u",
        "--update",
        action="store_true",
        dest="update",
        help="Fetches updates for the Vulnerability List",
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
        "--log",
        action="store_true",
        dest="log",
        default=False,
        help="Enables logging to file.",
    )
    argsParser.add_argument(
        "--output",
        default=None,
        help="Path to output log file (replaces default log file), requires --log",
    )
    argsParser.add_argument(
        "--now",
        action="store_true",
        dest="use_now",
        default=False,
        help=f"Forces logging to use {now} in the log file name, requires --log",
    )
    argsParser.add_argument(
        "--silent",
        action="store_true",
        dest="silent",
        default=False,
        help="Prevents logging output to stdout.",
    )
    argsParser.add_argument(
        "-v",
        "--version",
        action="store_true",
        dest="version",
        default=False,
        help="Shows program's version number.",
    )
    args = argsParser.parse_args()
    numArgs = len(sys.argv) - 1
    stats = ""
    pdf = None
    fileName = args.pdf
    statsDict = None
    vtJsonDict = None
    log = args.log
    output = args.output
    use_now = args.use_now
    ERROR_LOG = f"peepdf-errors-NOFILE-{now}.txt"
    LOG_FILE = f"peepdf-NOFILE-{now}.txt"
    errorsFile = os.path.join(os.getcwd(), ERROR_LOG)
    errorLogger = None
    jsErrorsFile = None
    no_file = os.path.join(os.getcwd(), "peepdf-NOFILE.txt")
    if use_now or os.path.exists(no_file):
        LOG_FILE = os.path.join(os.getcwd(), f"peepdf-NOFILE-{now}.txt")
    else:
        LOG_FILE = no_file
    base, ext = os.path.splitext(LOG_FILE)
    errorsFile = f"{base}-errors{ext}"
    if fileName is not None and os.path.exists(os.path.abspath(fileName)):
        abs_file = os.path.abspath(fileName)
        std_log = f"{abs_file}-peepdf.txt"
        if use_now or os.path.exists(std_log):
            LOG_FILE = f"{abs_file}-{now}-peepdf.txt"
        else:
            LOG_FILE = std_log
        base, ext = os.path.splitext(LOG_FILE)
        errorsFile = f"{base}-errors{ext}"
        jsErrorsFile = f"{base}-jserrors{ext}"
    elif fileName is not None and not os.path.exists(os.path.abspath(fileName)):
        argsParser.error(f'[!] Error: The file "{fileName}" does not exist')
    if log and output:
        output_dir = os.path.dirname(output)
        if not output_dir:
            target = os.path.join(os.getcwd(), output)
        elif os.path.exists(output_dir):
            target = output
        else:
            argsParser.error(f'[!] Error: The directory "{output_dir}" does not exist')
        outfile, ext = os.path.splitext(target)
        if use_now or (os.path.exists(target) and os.path.isfile(target)):
            LOG_FILE = f"{outfile}-{now}{ext}"
        else:
            LOG_FILE = target
        base, ext = os.path.splitext(LOG_FILE)
        errorsFile = f"{base}-errors{ext}"
        jsErrorsFile = f"{base}-jserrors{ext}"
    if args.isInteractive:
        log = False
        output = None
    logger = ppdfLog(
        log_to_file=log,
        silent=args.silent,
        file=LOG_FILE,
        logger_name="peepdf",
        level="INFO",
    )

    def getErrorLogger():
        errorLogger = ppdfLog(
            log_to_file=log,
            silent=args.silent,
            file=errorsFile,
            logger_name="peepdf-errors",
            level="ERROR",
        )
        return errorLogger

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
        if args.version:
            print(f"peepdf v{VERSION}")
            argsParser.exit()
        if args.update:
            if numArgs > 1:
                print(
                    "[*] Only one argument required for update, other arguments will be ignored"
                )
            getUpdate()
        else:
            if numArgs == 2 and fileName is not None:
                if not os.path.exists(fileName):
                    argsParser.error(f'[!] Error: The file "{fileName}" does not exist')
            elif numArgs == 2 and (args.isInteractive and args.avoidColors):
                console = PDFConsole(pdf, VT_KEY, args.avoidColors)
                console.jsErrorsFile = jsErrorsFile
                try:
                    console.cmdloop()
                except Exception as exc:
                    errorMessage = "[!] Error: Exception while launching Interactive mode without a PDF file"
                    logger.error(errorMessage)
                    logger.error(str(exc))
                    if not errorLogger:
                        errorLogger = getErrorLogger()
                    errorLogger.error(errorMessage)
                    errorLogger.error(str(exc))
                    raise Exception("PeepException", "Open an Issue on GitHub") from exc
            elif (numArgs > 4 and not fileName) or (
                numArgs == 0 and not args.isInteractive
            ):
                sys.exit(argsParser.print_help())
            if args.jsonOutput and args.xmlOutput:
                argsParser.error("[*] Only one of XML or JSON should be selected")
            if args.scriptFile is not None:
                if not os.path.exists(args.scriptFile):
                    argsParser.error(
                        f'[!] Error: The script file "{args.scriptFile}" does not exist'
                    )
            if fileName is not None:
                pdfParser = PDFParser()
                ret, pdf = pdfParser.parse(
                    fileName,
                    args.isForceMode,
                    args.isLooseMode,
                    args.isManualAnalysis,
                    jsErrorsFile,
                )
                if args.getText:
                    text_output = pdfParser.getText(fileName)
                    logger.info(f"Text content of: {fileName}{newLine}")
                    logger.info(text_output)
                    raise SystemExit(0)
                if args.checkOnVT and "vt_key" not in args.vtApiKey:
                    # Checks the MD5 on VirusTotal
                    vtKey = args.vtApiKey
                    md5Hash = pdf.getMD5()
                    ret = vtcheck(md5Hash, vtKey)
                    if ret[0] == -1:
                        pdf.addError(ret[1])
                        if "not found" in ret[1]:
                            argsParser.error(f"[!] Error: {ret[1]} on VirusTotal.")
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
                    argsParser.error(
                        f"[*] Warning: Your API key is not properly set - {VT_KEY}"
                    )
                statsDict = pdf.getStats()

            if args.xmlOutput:
                try:
                    xml = getPeepXML(statsDict, VERSION)
                    xml = xml.decode("latin-1")
                    logger.info(xml)
                except Exception as exc:
                    errorMessage = "[!] Error: Exception while generating the XML file"
                    logger.error(errorMessage)
                    logger.error(str(exc))
                    if not errorLogger:
                        errorLogger = getErrorLogger()
                    errorLogger.error(errorMessage)
                    errorLogger.error(str(exc))
                    raise Exception("PeepException", "Open an Issue on GitHub") from exc
            elif args.jsonOutput and not args.commands:
                try:
                    jsonReport = getPeepJSON(statsDict, VERSION)
                    logger.info(jsonReport)
                except Exception as exc:
                    errorMessage = (
                        "[!] Error: Exception while generating the JSON report"
                    )
                    excMessage = str(exc)
                    json_output = json.dumps(
                        {"error": errorMessage, "exception": excMessage}
                    )
                    logger.error(json_output)
                    if not errorLogger:
                        errorLogger = getErrorLogger()
                    errorLogger.error(json_output)
                    raise Exception("PeepException", "Open an Issue on GitHub") from exc
            else:
                if COLORIZED_OUTPUT and not args.avoidColors:
                    try:
                        init()
                    except:
                        COLORIZED_OUTPUT = False
                if args.scriptFile is not None:
                    if os.path.exists(args.scriptFile):
                        scriptFileObject = open(args.scriptFile, "r")
                    else:
                        argsParser.error(
                            f"[*] Warning: The file {args.scriptFile} cannot be found - check your path and try again!"
                        )
                    console = PDFConsole(
                        pdf, VT_KEY, args.avoidColors, stdin=scriptFileObject
                    )
                    console.jsErrorsFile = jsErrorsFile
                    try:
                        console.cmdloop()
                    except Exception as exc:
                        errorMessage = (
                            "[!] Error: Exception not handled using the script mode"
                        )
                        scriptFileObject.close()
                        logger.error(errorMessage)
                        logger.error(str(exc))
                        if not errorLogger:
                            errorLogger = getErrorLogger()
                        errorLogger.error(errorMessage)
                        errorLogger.error(str(exc))
                        raise Exception(
                            "PeepException", "Open an Issue on GitHub"
                        ) from exc
                elif args.commands is not None:
                    console = PDFConsole(pdf, VT_KEY, args.avoidColors, isCommand=True)
                    console.jsErrorsFile = jsErrorsFile
                    try:
                        for command in args.commands:
                            console.onecmd(command)
                    except Exception as exc:
                        errorMessage = (
                            "[!] Error: Exception not handled using the script commands"
                        )
                        logger.error(errorMessage)
                        logger.error(str(exc))
                        if not errorLogger:
                            errorLogger = getErrorLogger()
                        errorLogger.error(errorMessage)
                        errorLogger.error(str(exc))
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
                        logger.info(niceOutput)
                    if args.isInteractive:
                        console = PDFConsole(pdf, VT_KEY, args.avoidColors)
                        console.jsErrorsFile = jsErrorsFile
                        while not console.leaving:
                            try:
                                console.cmdloop()
                            except KeyboardInterrupt:
                                logger.info("\n")
                            except Exception as exc:
                                errorMessage = "[!] Error: Exception not handled using the interactive console - please report it to the author."
                                print(
                                    f"{errorColor}{errorMessage}{resetColor}{newLine}"
                                )
                                logger.error(errorMessage)
                                logger.error(str(exc))
                                if not errorLogger:
                                    errorLogger = getErrorLogger()
                                errorLogger.error(errorMessage)
                                errorLogger.error(str(exc))
    except Exception as e:
        if len(e.args) == 2:
            excName, _ = e.args
        else:
            excName = _ = None
        if excName is None or excName != "PeepException":
            errorMessage = "[!] Error: Exception not handled"
            logger.error(errorMessage)
            logger.error(str(e))
            if not errorLogger:
                errorLogger = getErrorLogger()
            errorLogger.error(errorMessage)
            errorLogger.error(str(e))
    finally:
        if os.path.exists(errorsFile) and os.path.getsize(errorsFile) != 0:
            message = f"{newLine}Please don't forget to report the errors found in file {errorsFile}:{newLine * 2}"
            message += f"- Create an issue at https://github.com/digitalsleuth/peepdf-3{newLine}"
            message = f"{errorColor}{message}{resetColor}"
            sys.exit(message)


if __name__ == "__main__":
    main()
