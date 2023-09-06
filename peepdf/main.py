#!/usr/bin/env python3

#
# peepdf is a tool to analyse and modify PDF files
#    http://peepdf.eternal-todo.com
#    By Jose Miguel Esparza <jesparza AT eternal-todo.com>
#
#    Copyright (C) 2011-2017 Jose Miguel Esparza
#
#    This file is part of peepdf.
#
#        peepdf is free software: you can redistribute it and/or modify
#        it under the terms of the GNU General Public License as published by
#        the Free Software Foundation, either version 3 of the License, or
#        (at your option) any later version.
#
#        peepdf is distributed in the hope that it will be useful,
#        but WITHOUT ANY WARRANTY; without even the implied warranty of
#        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
#        GNU General Public License for more details.
#
#        You should have received a copy of the GNU General Public License
#        along with peepdf.    If not, see <http://www.gnu.org/licenses/>.
#

"""
    Initial script to launch the tool
"""

import sys
import os
import optparse
import urllib
import hashlib
import traceback
import json
from lxml import etree
from datetime import datetime
try:
    from peepdf.PDFCore import PDFParser, vulnsDict
    from peepdf.PDFUtils import vtcheck
except ModuleNotFoundError:
    from PDFCore import PDFParser, vulnsDict
    from PDFUtils import vtcheck

VT_KEY = "fc90df3f5ac749a94a94cb8bf87e05a681a2eb001aef34b6a0084b8c22c97a64"

try:
    import STPyV8 as PyV8

    JS_MODULE = True
except:
    JS_MODULE = False

try:
    import pylibemu

    EMU_MODULE = True
except:
    EMU_MODULE = False

try:
    from colorama import init, Fore, Back, Style

    COLORIZED_OUTPUT = True
except:
    COLORIZED_OUTPUT = False

try:
    from PIL import Image

    PIL_MODULE = True
except:
    PIL_MODULE = False


def getRepPaths(url, path=""):
    paths = []
    try:
        browsingPage = urllib.request.urlopen(url + path).read()
    except:
        sys.exit(
            f'[!] Connection error while getting browsing page {url}{path}'
        )
    browsingPageObject = json.loads(browsingPage)
    for file in browsingPageObject:
        if file["type"] == "file":
            paths.append(file["path"])
        elif file["type"] == "dir":
            dirPaths = getRepPaths(url, file["path"])
            paths += dirPaths
    return paths


def getLocalFilesInfo(filesList):
    localFilesInfo = {}
    print("[-] Getting local files information...")
    for path in filesList:
        absPeepdfRoot = os.path.dirname(os.path.realpath(sys.argv[0]))
        absFilePath = os.path.join(absPeepdfRoot, path)
        if os.path.exists(absFilePath):
            content = open(absFilePath, "rb").read()
            shaHash = hashlib.sha256(content).hexdigest()
            localFilesInfo[path] = [shaHash, absFilePath]
    print("[+] Done")
    return localFilesInfo


def getPeepXML(statsDict, version):
    root = etree.Element(
        "peepdf_analysis",
        version=f'{version}',
        url="http://peepdf.eternal-todo.com - https://github.com/digitalsleuth/peepdf-3",
        author="Jose Miguel Esparza and Corey Forman",
    )
    analysisDate = etree.SubElement(root, "date")
    analysisDate.text = datetime.today().strftime("%Y-%m-%d %H:%M")
    basicInfo = etree.SubElement(root, "basic")
    fileName = etree.SubElement(basicInfo, "filename")
    fileName.text = statsDict["File"]
    md5 = etree.SubElement(basicInfo, "md5")
    md5.text = statsDict["MD5"]
    sha1 = etree.SubElement(basicInfo, "sha1")
    sha1.text = statsDict["SHA1"]
    sha256 = etree.SubElement(basicInfo, "sha256")
    sha256.text = statsDict["SHA256"]
    size = etree.SubElement(basicInfo, "size")
    size.text = statsDict["Size"]
    detection = etree.SubElement(basicInfo, "detection")
    if statsDict["Detection"]:
        detectionRate = etree.SubElement(detection, "rate")
        detectionRate.text = (
            f'{statsDict["Detection"][0]}/{statsDict["Detection"][1]}'
        )
        detectionReport = etree.SubElement(detection, "report_link")
        detectionReport.text = statsDict["Detection report"]
    version = etree.SubElement(basicInfo, "pdf_version")
    version.text = statsDict["Version"]
    binary = etree.SubElement(basicInfo, "binary", status=statsDict["Binary"].lower())
    linearized = etree.SubElement(
        basicInfo, "linearized", status=statsDict["Linearized"].lower()
    )
    encrypted = etree.SubElement(
        basicInfo, "encrypted", status=statsDict["Encrypted"].lower()
    )
    if statsDict["Encryption Algorithms"]:
        algorithms = etree.SubElement(encrypted, "algorithms")
        for algorithmInfo in statsDict["Encryption Algorithms"]:
            algorithm = etree.SubElement(
                algorithms, "algorithm", bits=str(algorithmInfo[1])
            )
            algorithm.text = algorithmInfo[0]
    updates = etree.SubElement(basicInfo, "updates")
    updates.text = statsDict["Updates"]
    objects = etree.SubElement(basicInfo, "num_objects")
    objects.text = statsDict["Objects"]
    streams = etree.SubElement(basicInfo, "num_streams")
    streams.text = statsDict["Streams"]
    comments = etree.SubElement(basicInfo, "comments")
    comments.text = statsDict["Comments"]
    errors = etree.SubElement(basicInfo, "errors", num=str(len(statsDict["Errors"])))
    for error in statsDict["Errors"]:
        errorMessageXML = etree.SubElement(errors, "error_message")
        errorMessageXML.text = error
    advancedInfo = etree.SubElement(root, "advanced")
    for version in range(len(statsDict["Versions"])):
        statsVersion = statsDict["Versions"][version]
        if version == 0:
            versionType = "original"
        else:
            versionType = "update"
        versionInfo = etree.SubElement(
            advancedInfo, "version", num=str(version), type=versionType
        )
        catalog = etree.SubElement(versionInfo, "catalog")
        if statsVersion["Catalog"] is not None:
            catalog.set("object_id", statsVersion["Catalog"])
        info = etree.SubElement(versionInfo, "info")
        if statsVersion["Info"] is not None:
            info.set("object_id", statsVersion["Info"])
        objects = etree.SubElement(
            versionInfo, "objects", num=statsVersion["Objects"][0]
        )
        for id in statsVersion["Objects"][1]:
            object = etree.SubElement(objects, "object", id=str(id))
            if statsVersion["Compressed Objects"] is not None:
                if id in statsVersion["Compressed Objects"][1]:
                    object.set("compressed", "true")
                else:
                    object.set("compressed", "false")
            if statsVersion["Errors"] is not None:
                if id in statsVersion["Errors"][1]:
                    object.set("errors", "true")
                else:
                    object.set("errors", "false")
        streams = etree.SubElement(
            versionInfo, "streams", num=statsVersion["Streams"][0]
        )
        for id in statsVersion["Streams"][1]:
            stream = etree.SubElement(streams, "stream", id=str(id))
            if statsVersion["Xref Streams"] is not None:
                if id in statsVersion["Xref Streams"][1]:
                    stream.set("xref_stream", "true")
                else:
                    stream.set("xref_stream", "false")
            if statsVersion["Object Streams"] is not None:
                if id in statsVersion["Object Streams"][1]:
                    stream.set("object_stream", "true")
                else:
                    stream.set("object_stream", "false")
            if statsVersion["Encoded"] is not None:
                if id in statsVersion["Encoded"][1]:
                    stream.set("encoded", "true")
                    if statsVersion["Decoding Errors"] is not None:
                        if id in statsVersion["Decoding Errors"][1]:
                            stream.set("decoding_errors", "true")
                        else:
                            stream.set("decoding_errors", "false")
                else:
                    stream.set("encoded", "false")
        jsObjects = etree.SubElement(versionInfo, "js_objects")
        if statsVersion["Objects with JS code"] is not None:
            for id in statsVersion["Objects with JS code"][1]:
                etree.SubElement(jsObjects, "container_object", id=str(id))
        actions = statsVersion["Actions"]
        events = statsVersion["Events"]
        vulns = statsVersion["Vulns"]
        elements = statsVersion["Elements"]
        suspicious = etree.SubElement(versionInfo, "suspicious_elements")
        if events is not None or actions is not None or vulns is not None or elements is not None:
            if events:
                triggers = etree.SubElement(suspicious, "triggers")
                for event in events:
                    trigger = etree.SubElement(triggers, "trigger", name=event)
                    for id in events[event]:
                        etree.SubElement(trigger, "container_object", id=str(id))
            if actions:
                actionsList = etree.SubElement(suspicious, "actions")
                for action in actions:
                    actionInfo = etree.SubElement(actionsList, "action", name=action)
                    for id in actions[action]:
                        etree.SubElement(actionInfo, "container_object", id=str(id))
            if elements:
                elementsList = etree.SubElement(suspicious, "elements")
                for element in elements:
                    elementInfo = etree.SubElement(
                        elementsList, "element", name=element
                    )
                    if element in vulnsDict:
                        vulnName = vulnsDict[element][0]
                        vulnCVEList = vulnsDict[element][1]
                        for vulnCVE in vulnCVEList:
                            cve = etree.SubElement(elementInfo, "cve")
                            cve.text = vulnCVE
                    for id in elements[element]:
                        etree.SubElement(elementInfo, "container_object", id=str(id))
            if vulns:
                vulnsList = etree.SubElement(suspicious, "js_vulns")
                for vuln in vulns:
                    vulnInfo = etree.SubElement(
                        vulnsList, "vulnerable_function", name=vuln
                    )
                    if vuln in vulnsDict:
                        vulnName = vulnsDict[vuln][0]
                        vulnCVEList = vulnsDict[vuln][1]
                        for vulnCVE in vulnCVEList:
                            cve = etree.SubElement(vulnInfo, "cve")
                            cve.text = vulnCVE
                    for id in vulns[vuln]:
                        etree.SubElement(vulnInfo, "container_object", id=str(id))
        urls = statsVersion["URLs"]
        suspiciousURLs = etree.SubElement(versionInfo, "suspicious_urls")
        if urls is not None:
            for url in urls:
                urlInfo = etree.SubElement(suspiciousURLs, "url")
                urlInfo.text = url
    return etree.tostring(root, pretty_print=True)


def getPeepJSON(statsDict, version):
    # peepdf info
    peepdfDict = {
        "version": version,
        "author": "Jose Miguel Esparza and Corey Forman",
        "url": "http://peepdf.eternal-todo.com - https://github.com/digitalsleuth/peepdf-3",
    }
    # Basic info
    basicDict = {}
    basicDict["filename"] = statsDict["File"]
    basicDict["md5"] = statsDict["MD5"]
    basicDict["sha1"] = statsDict["SHA1"]
    basicDict["sha256"] = statsDict["SHA256"]
    basicDict["size"] = int(statsDict["Size"])
    basicDict["detection"] = {}
    if statsDict["Detection"] != [] and statsDict["Detection"] is not None:
        basicDict["detection"][
            "rate"
        ] = f'{statsDict["Detection"][0]}/{statsDict["Detection"][1]}'
        basicDict["detection"]["report_link"] = statsDict["Detection report"]
    basicDict["pdf_version"] = statsDict["Version"]
    basicDict["binary"] = bool(statsDict["Binary"])
    basicDict["linearized"] = bool(statsDict["Linearized"])
    basicDict["encrypted"] = bool(statsDict["Encrypted"])
    basicDict["encryption_algorithms"] = []
    if statsDict["Encryption Algorithms"]:
        for algorithmInfo in statsDict["Encryption Algorithms"]:
            basicDict["encryption_algorithms"].append(
                {"bits": algorithmInfo[1], "algorithm": algorithmInfo[0]}
            )
    basicDict["updates"] = int(statsDict["Updates"])
    basicDict["num_objects"] = int(statsDict["Objects"])
    basicDict["num_streams"] = int(statsDict["Streams"])
    basicDict["comments"] = int(statsDict["Comments"])
    basicDict["errors"] = []
    for error in statsDict["Errors"]:
        basicDict["errors"].append(error)
    # Advanced info
    advancedInfo = []
    for version in range(len(statsDict["Versions"])):
        statsVersion = statsDict["Versions"][version]
        if version == 0:
            versionType = "original"
        else:
            versionType = "update"
        versionInfo = {}
        versionInfo["version_number"] = version
        versionInfo["version_type"] = versionType
        versionInfo["catalog"] = statsVersion["Catalog"]
        versionInfo["info"] = statsVersion["Info"]
        if statsVersion["Objects"] is not None:
            versionInfo["objects"] = statsVersion["Objects"][1]
        else:
            versionInfo["objects"] = []
        if statsVersion["Compressed Objects"] is not None:
            versionInfo["compressed_objects"] = statsVersion["Compressed Objects"][1]
        else:
            versionInfo["compressed_objects"] = []
        if statsVersion["Errors"] is not None:
            versionInfo["error_objects"] = statsVersion["Errors"][1]
        else:
            versionInfo["error_objects"] = []
        if statsVersion["Streams"] is not None:
            versionInfo["streams"] = statsVersion["Streams"][1]
        else:
            versionInfo["streams"] = []
        if statsVersion["Xref Streams"] is not None:
            versionInfo["xref_streams"] = statsVersion["Xref Streams"][1]
        else:
            versionInfo["xref_streams"] = []
        if statsVersion["Encoded"] is not None:
            versionInfo["encoded_streams"] = statsVersion["Encoded"][1]
        else:
            versionInfo["encoded_streams"] = []
        if (
            versionInfo["encoded_streams"]
            and statsVersion["Decoding Errors"] is not None
        ):
            versionInfo["decoding_error_streams"] = statsVersion["Decoding Errors"][1]
        else:
            versionInfo["decoding_error_streams"] = []
        if statsVersion["Objects with JS code"] is not None:
            versionInfo["js_objects"] = statsVersion["Objects with JS code"][1]
        else:
            versionInfo["js_objects"] = []
        elements = statsVersion["Elements"]
        elementArray = []
        if elements:
            for element in elements:
                elementInfo = {"name": element}
                if element in vulnsDict:
                    elementInfo["vuln_name"] = vulnsDict[element][0]
                    elementInfo["vuln_cve_list"] = vulnsDict[element][1]
                elementInfo["objects"] = elements[element]
                elementArray.append(elementInfo)
        vulns = statsVersion["Vulns"]
        vulnArray = []
        if vulns:
            for vuln in vulns:
                vulnInfo = {"name": vuln}
                if vuln in vulnsDict:
                    vulnInfo["vuln_name"] = vulnsDict[vuln][0]
                    vulnInfo["vuln_cve_list"] = vulnsDict[vuln][1]
                vulnInfo["objects"] = vulns[vuln]
                vulnArray.append(vulnInfo)
        versionInfo["suspicious_elements"] = {
            "triggers": statsVersion["Events"],
            "actions": statsVersion["Actions"],
            "elements": elementArray,
            "js_vulns": vulnArray,
            "urls": statsVersion["URLs"],
        }
        versionReport = {"version_info": versionInfo}
        advancedInfo.append(versionReport)
    jsonDict = {
        "peepdf_analysis": {
            "peepdf_info": peepdfDict,
            "date": datetime.today().strftime("%Y-%m-%d %H:%M"),
            "basic": basicDict,
            "advanced": advancedInfo,
        }
    }
    return json.dumps(jsonDict, indent=4, sort_keys=True)


def main():
    global COLORIZED_OUTPUT
    version = "1.0.2"
    versionHeader = f"Version: peepdf {version}"
    author = "Jose Miguel Esparza and Corey Forman"
    email = "peepdf AT eternal-todo.com"
    url = "http://peepdf.eternal-todo.com"
    twitter = "http://twitter.com/EternalTodo"
    peepTwitter = "http://twitter.com/peepdf"
    newLine = os.linesep
    currentDir = os.getcwd()
    absPeepdfRoot = os.path.dirname(os.path.realpath(sys.argv[0]))
    errorsFile = os.path.join(currentDir, "peepdf_errors.txt")
    peepdfHeader = (
        f"{versionHeader}{newLine * 2}{url}{newLine}{peepTwitter}{newLine}{email}"
    )
    f"{newLine * 2}{author}{newLine}{twitter}{newLine}"
    argsParser = optparse.OptionParser(
        usage="Usage: peepdf.py [options] PDF_file", description=versionHeader
    )
    argsParser.add_option(
        "-i",
        "--interactive",
        action="store_true",
        dest="isInteractive",
        default=False,
        help="Sets console mode.",
    )
    argsParser.add_option(
        "-s",
        "--load-script",
        action="store",
        type="string",
        dest="scriptFile",
        help="Loads the commands stored in the specified file and execute them.",
    )
    argsParser.add_option(
        "-c",
        "--check-vt",
        action="store_true",
        dest="checkOnVT",
        default=False,
        help="Checks the hash of the PDF file on VirusTotal.",
    )
    argsParser.add_option(
        "-f",
        "--force-mode",
        action="store_true",
        dest="isForceMode",
        default=False,
        help="Sets force parsing mode to ignore errors.",
    )
    argsParser.add_option(
        "-l",
        "--loose-mode",
        action="store_true",
        dest="isLooseMode",
        default=False,
        help="Sets loose parsing mode to catch malformed objects.",
    )
    argsParser.add_option(
        "-m",
        "--manual-analysis",
        action="store_true",
        dest="isManualAnalysis",
        default=False,
        help="Avoids automatic Javascript analysis. Useful with eternal loops like heap spraying.",
    )
    argsParser.add_option(
        "-g",
        "--grinch-mode",
        action="store_true",
        dest="avoidColors",
        default=False,
        help="Avoids colorized output in the interactive console.",
    )
    argsParser.add_option(
        "-v",
        "--version",
        action="store_true",
        dest="version",
        default=False,
        help="Shows program's version number.",
    )
    argsParser.add_option(
        "-x",
        "--xml",
        action="store_true",
        dest="xmlOutput",
        default=False,
        help="Shows the document information in XML format.",
    )
    argsParser.add_option(
        "-j",
        "--json",
        action="store_true",
        dest="jsonOutput",
        default=False,
        help="Shows the document information in JSON format.",
    )
    argsParser.add_option(
        "-C",
        "--command",
        action="append",
        type="string",
        dest="commands",
        help="Specifies a command from the interactive console to be executed.",
    )
    (options, args) = argsParser.parse_args()

    stats = ""
    pdf = None
    fileName = None
    statsDict = None
    vtJsonDict = None

    try:
        # Avoid colors in the output
        if not COLORIZED_OUTPUT or options.avoidColors:
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
        if options.version:
            print(peepdfHeader)
        else:
            if len(args) == 1:
                fileName = args[0]
                if not os.path.exists(fileName):
                    sys.exit(f'[!] Error: The file "{fileName}" does not exist!')
            elif len(args) > 1 or (len(args) == 0 and not options.isInteractive):
                sys.exit(argsParser.print_help())

            if options.scriptFile is not None:
                if not os.path.exists(options.scriptFile):
                    sys.exit(
                        f'[!] Error: The script file "{options.scriptFile}" does not exist!'
                    )

            if fileName is not None:
                pdfParser = PDFParser()
                ret, pdf = pdfParser.parse(
                    fileName,
                    options.isForceMode,
                    options.isLooseMode,
                    options.isManualAnalysis,
                )
                if options.checkOnVT:
                    # Checks the MD5 on VirusTotal
                    md5Hash = pdf.getMD5()
                    ret = vtcheck(md5Hash, VT_KEY)
                    if ret[0] == -1:
                        pdf.addError(ret[1])
                    else:
                        vtJsonDict = ret[1]
                        if "response_code" in vtJsonDict:
                            if vtJsonDict["response_code"] == 1:
                                if "positives" and "total" in vtJsonDict:
                                    pdf.setDetectionRate(
                                        [vtJsonDict["positives"], vtJsonDict["total"]]
                                    )
                                else:
                                    pdf.addError(
                                        "Missing elements in the response from VirusTotal!!"
                                    )
                                if "permalink" in vtJsonDict:
                                    pdf.setDetectionReport(vtJsonDict["permalink"])
                            else:
                                pdf.setDetectionRate(None)
                        else:
                            pdf.addError("Bad response from VirusTotal!!")
                statsDict = pdf.getStats()

            if options.xmlOutput:
                try:
                    xml = getPeepXML(statsDict, version)
                    xml = xml.decode('latin-1')
                    sys.stdout.write(xml)  ## Check this output and format better
                except:
                    errorMessage = (
                        "[!] Error: Exception while generating the XML file!!"
                    )
                    traceback.print_exc(file=open(errorsFile, "a"))
                    raise Exception("PeepException", "Send me an email ;)")
            elif options.jsonOutput and not options.commands:
                try:
                    jsonReport = getPeepJSON(statsDict, version)
                    sys.stdout.write(jsonReport)
                except:
                    errorMessage = (
                        "[!] Error: Exception while generating the JSON report!!"
                    )
                    traceback.print_exc(file=open(errorsFile, "a"))
                    raise Exception("PeepException", "Send me an email ;)")
            else:
                if COLORIZED_OUTPUT and not options.avoidColors:
                    try:
                        init()
                    except:
                        COLORIZED_OUTPUT = False
                if options.scriptFile is not None:
                    try:
                        from peepdf.PDFConsole import PDFConsole
                    except ModuleNotFoundError:
                        from PDFConsole import PDFConsole
                    scriptFileObject = open(options.scriptFile, "rb")
                    console = PDFConsole(
                        pdf, VT_KEY, options.avoidColors, stdin=scriptFileObject
                    )
                    try:
                        console.cmdloop()
                    except:
                        errorMessage = (
                            "[!] Error: Exception not handled using the batch mode!!"
                        )
                        scriptFileObject.close()
                        traceback.print_exc(file=open(errorsFile, "a"))
                        raise Exception("PeepException", "Send me an email ;)")
                elif options.commands is not None:
                    from peepdf.PDFConsole import PDFConsole

                    console = PDFConsole(pdf, VT_KEY, options.avoidColors)
                    try:
                        for command in options.commands:
                            console.onecmd(command)
                    except:
                        errorMessage = "[!] Error: Exception not handled using the batch commands!!"
                        traceback.print_exc(file=open(errorsFile, "a"))
                        raise Exception("PeepException", "Send me an email ;)")
                else:
                    if statsDict is not None:
                        if COLORIZED_OUTPUT and not options.avoidColors:
                            beforeStaticLabel = staticColor
                        else:
                            beforeStaticLabel = ""

                        if not JS_MODULE:
                            warningMessage = "Warning: PyV8 is not installed!!"
                            stats += (
                                f"{warningColor}{warningMessage}{resetColor}{newLine}"
                            )
                        if not EMU_MODULE:
                            warningMessage = "Warning: pylibemu is not installed!!"
                            stats += (
                                f"{warningColor}{warningMessage}{resetColor}{newLine}"
                            )
                        if not PIL_MODULE:
                            warningMessage = "Warning: Python Imaging Library (PIL) is not installed!!"
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

                        stats += f'{beforeStaticLabel}File: {resetColor}{statsDict["File"]}{newLine}'
                        stats += f'{beforeStaticLabel}MD5: {resetColor}{statsDict["MD5"]}{newLine}'
                        stats += f'{beforeStaticLabel}SHA1: {resetColor}{statsDict["SHA1"]}{newLine}'
                        stats += f'{beforeStaticLabel}SHA256: {resetColor}{statsDict["SHA256"]}{newLine}'
                        stats += f'{beforeStaticLabel}Size: {resetColor}{statsDict["Size"]} bytes{newLine}'
                        if options.checkOnVT:
                            if statsDict["Detection"] != []:
                                detectionReportInfo = ""
                                if statsDict["Detection"] is not None:
                                    detectionColor = ""
                                    if COLORIZED_OUTPUT and not options.avoidColors:
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
                        stats += f'{beforeStaticLabel}Version: {resetColor}{statsDict["Version"]}{newLine}'
                        stats += f'{beforeStaticLabel}Binary: {resetColor}{statsDict["Binary"]}{newLine}'
                        stats += f'{beforeStaticLabel}Linearized: {resetColor}{statsDict["Linearized"]}{newLine}'
                        stats += f'{beforeStaticLabel}Encrypted: {resetColor}{statsDict["Encrypted"]}'
                        if statsDict["Encryption Algorithms"] != []:
                            stats += " ("
                            for algorithmInfo in statsDict["Encryption Algorithms"]:
                                stats += (
                                    f'{algorithmInfo[0]} {str(algorithmInfo[1])} bits, '
                                )
                            stats = f'{stats[:-2]})'
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
                                    f"{beforeStaticLabel}\tCompressed objects  "
                                    f'({statsVersion["Compressed Objects"][0]}): '
                                    f'{resetColor}{str(statsVersion["Compressed Objects"][1])}{newLine}'
                                )
                            if statsVersion["Errors"] is not None:
                                stats += (
                                    f'{beforeStaticLabel}\t\tErrors ({statsVersion["Errors"][0]}): '
                                    f'{resetColor}{str(statsVersion["Errors"][1])}{newLine}'
                                )
                            stats += (
                                f'{beforeStaticLabel}\tStreams ({statsVersion["Streams"][0]}): '
                                f'{resetColor}{str(statsVersion["Streams"][1])}'
                            )
                            if statsVersion["Xref Streams"] is not None:
                                stats += (
                                    f"{newLine}{beforeStaticLabel}\t\tXref streams "
                                    f'({statsVersion["Xref Streams"][0]}): '
                                    f'{resetColor}{str(statsVersion["Xref Streams"][1])}'
                                )
                            if statsVersion["Object Streams"] is not None:
                                stats += (
                                    f"{newLine}{beforeStaticLabel}\t\tObject streams "
                                    f'({statsVersion["Object Streams"][0]}): '
                                    f'{resetColor}{str(statsVersion["Object Streams"][1])}'
                                )
                            if int(statsVersion["Streams"][0]) > 0:
                                stats += (
                                    f"{newLine}{beforeStaticLabel}\t\tEncoded "
                                    f'({statsVersion["Encoded"][0]}): '
                                    f'{resetColor}{str(statsVersion["Encoded"][1])}'
                                )
                                if statsVersion["Decoding Errors"] is not None:
                                    stats += (
                                        f"{newLine}{beforeStaticLabel}\t\tDecoding errors "
                                        f'({statsVersion["Decoding Errors"][0]}): '
                                        f'{resetColor}{str(statsVersion["Decoding Errors"][1])}'
                                    )
                            if statsVersion["URIs"] is not None:
                                stats += (
                                    f"{newLine}{beforeStaticLabel}\tObjects with URIs "
                                    f'({statsVersion["URIs"][0]}): '
                                    f'{resetColor}{str(statsVersion["URIs"][1])}'
                                )
                            if COLORIZED_OUTPUT and not options.avoidColors:
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
                                stats += f"{newLine}{beforeStaticLabel}\tSuspicious elements:{resetColor}{newLine}"
                                if events is not None:
                                    for event in events:
                                        stats += (
                                            f"\t\t{beforeStaticLabel}{event} ({len(events[event])}): "
                                            f"{resetColor}{str(events[event])}{newLine}"
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
                                                f"\t\t{beforeStaticLabel}{element}: "
                                                f"{resetColor}{str(elements[element])}{newLine}"
                                            )
                            if COLORIZED_OUTPUT and not options.avoidColors:
                                beforeStaticLabel = staticColor
                            urls = statsVersion["URLs"]
                            if urls is not None:
                                stats += f"{newLine}{beforeStaticLabel}\tFound URLs:{resetColor}{newLine}"
                                for url in urls:
                                    stats += f"\t\t{url}{newLine}"
                            stats += newLine * 2
                    if fileName is not None:
                        print(stats)
                    if options.isInteractive:
                        try:
                            from peepdf.PDFConsole import PDFConsole
                        except ModuleNotFoundError:
                            from PDFConsole import PDFConsole

                        console = PDFConsole(pdf, VT_KEY, options.avoidColors)
                        while not console.leaving:
                            try:
                                console.cmdloop()
                            except KeyboardInterrupt as e:
                                sys.exit()
                            except:
                                errorMessage = "[!] Error: Exception not handled using the interactive console!! Please, report it to the author!!"
                                print(
                                    f"{errorColor}{errorMessage}{resetColor}{newLine}"
                                )
                                traceback.print_exc(file=open(errorsFile, "a"))
    except Exception as e:
        if len(e.args) == 2:
            excName, excReason = e.args
        else:
            excName = excReason = None
        if excName is None or excName != "PeepException":
            errorMessage = "[!] Error: Exception not handled!!"
            traceback.print_exc(file=open(errorsFile, "a"))
        print(f"{errorColor}{errorMessage}{resetColor}{newLine}")
    finally:
        if os.path.exists(errorsFile):
            message = (
                f"{newLine}Please don't forget to report the errors found:{newLine * 2}"
            )
            message += (
                f'\t- Send the file "{errorsFile}" to the author '
                f"(mailto:peepdfREMOVETHIS@eternal-todo.com){newLine}"
            )
            message += (
                f"\t- And/Or creating an issue on the project webpage "
                f"(https://github.com/jesparza/peepdf/issues){newLine}"
            )
            message = f"{errorColor}{message}{resetColor}"
            sys.exit(message)
if __name__ == "__main__":
    main()