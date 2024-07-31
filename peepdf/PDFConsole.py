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
    Implementation of the interactive console of peepdf
"""

import cmd
import sys
import os
import re
import hashlib
import traceback
import pathlib
from base64 import b64encode, b64decode
from datetime import datetime as dt
from builtins import input
import jsbeautifier
from prettytable import PrettyTable, SINGLE_BORDER

try:
    from peepdf.PDFUtils import (
        getBytesFromFile,
        countArrayElements,
        clearScreen,
        hexToString,
        escapeRegExpString,
        vtcheck,
        countNonPrintableChars,
        getPeepXML,
        getPeepJSON,
    )
    from peepdf.PDFCrypto import xor
    from peepdf.JSAnalysis import isJavascript, analyseJS, unescape
    from peepdf.PDFCore import (
        PDFFile,
        PDFHexString,
        PDFDictionary,
        PDFNum,
        PDFName,
        PDFStream,
        PDFReference,
        PDFString,
        PDFArray,
        PDFBool,
        PDFNull,
        PDFParser,
        VERSION,
        spacesChars,
        delimiterChars,
    )
    from peepdf.PDFFilters import decodeStream, encodeStream
    from peepdf.PDFVulns import vulnsDict
    from peepdf.PDFEnDec import JJDecoder
except ModuleNotFoundError:
    from PDFUtils import (
        getBytesFromFile,
        countArrayElements,
        clearScreen,
        hexToString,
        escapeRegExpString,
        vtcheck,
        countNonPrintableChars,
        getPeepXML,
        getPeepJSON,
    )
    from PDFCrypto import xor
    from JSAnalysis import isJavascript, analyseJS, unescape
    from PDFCore import (
        PDFFile,
        PDFHexString,
        PDFDictionary,
        PDFNum,
        PDFName,
        PDFStream,
        PDFReference,
        PDFString,
        PDFArray,
        PDFBool,
        PDFNull,
        PDFParser,
        VERSION,
        spacesChars,
        delimiterChars,
    )
    from PDFFilters import decodeStream, encodeStream
    from PDFVulns import vulnsDict
    from PDFEnDec import JJDecoder

try:
    from colorama import init, Fore, Style

    COLORIZED_OUTPUT = True
except ModuleNotFoundError:
    COLORIZED_OUTPUT = False

try:
    import STPyV8
    try:
        from peepdf.JSAnalysis import Global
    except ModuleNotFoundError:
        from JSAnalysis import Global
        
    JS_MODULE = True
except ModuleNotFoundError:
    JS_MODULE = False

try:
    import pylibemu

    EMU_MODULE = True
except ModuleNotFoundError:
    EMU_MODULE = False

try:
    import readline

    RL_PROMPT_START_IGNORE = "\001"
    RL_PROMPT_END_IGNORE = "\002"

except ModuleNotFoundError:
    RL_PROMPT_START_IGNORE = RL_PROMPT_END_IGNORE = ""

# File and variable redirections
FILE_WRITE = 1
FILE_ADD = 2
VAR_WRITE = 3
VAR_ADD = 4
DTFMT = "%Y%m%d-%H%M%S"
newLine = os.linesep
filter2RealFilterDict = {
    "b64": "base64",
    "base64": "base64",
    "asciihex": "/ASCIIHexDecode",
    "ahx": "/ASCIIHexDecode",
    "ascii85": "/ASCII85Decode",
    "a85": "/ASCII85Decode",
    "lzw": "/LZWDecode",
    "flatedecode": "/FlateDecode",
    "fl": "/FlateDecode",
    "runlength": "/RunLengthDecode",
    "rl": "/RunLengthDecode",
    "ccittfax": "/CCITTFaxDecode",
    "ccf": "/CCITTFaxDecode",
    "jbig2": "/JBIG2Decode",
    "dct": "/DCTDecode",
    "jpx": "/JPXDecode",
}


class PDFConsole(cmd.Cmd):
    """
    Class of the peepdf interactive console. To see details about commands:
    http://code.google.com/p/peepdf/wiki/Commands
    """

    def __init__(
        self,
        thisPdf,
        vtKey,
        avoidOutputColors=False,
        stdin=None,
        scriptMode=False,
        jsonOutput=False,
    ):
        global COLORIZED_OUTPUT
        cmd.Cmd.__init__(self, stdin=stdin)
        self.warningColor = ""
        self.errorColor = ""
        self.alertColor = ""
        self.staticColor = ""
        self.resetColor = ""
        if not COLORIZED_OUTPUT or avoidOutputColors:
            self.avoidOutputColors = True
        else:
            try:
                init()
                self.warningColor = Fore.YELLOW
                self.errorColor = Fore.RED
                self.alertColor = Fore.RED
                self.staticColor = Fore.BLUE
                self.promptColor = (
                    RL_PROMPT_START_IGNORE + Fore.GREEN + RL_PROMPT_END_IGNORE
                )
                self.resetColor = Style.RESET_ALL
                self.avoidOutputColors = False
            except:
                self.avoidOutputColors = True
                COLORIZED_OUTPUT = False

        if not self.avoidOutputColors:
            self.prompt = (
                self.promptColor
                + "PPDF> "
                + RL_PROMPT_START_IGNORE
                + self.resetColor
                + RL_PROMPT_END_IGNORE
            )
        else:
            self.prompt = "PPDF> "
        self.use_rawinput = True
        if stdin is not None:
            self.use_rawinput = False
            self.prompt = ""
        self.pdfFile = thisPdf
        self.variables = {
            "output": ["stdout", "stdout"],
            "output_limit": [500, 500],
            "malformed_options": [[], []],
            "header_file": [None, None],
            "vt_key": [vtKey, vtKey],
        }
        self.javaScriptContexts = {"global": None}
        self.readOnlyVariables = ["malformed_options", "header_file"]
        self.loggingFile = None
        self.output = None
        self.redirect = None
        self.leaving = False
        self.scriptMode = scriptMode
        self.jsonOutput = jsonOutput
        self.outputVarName = None
        self.outputFileName = None

    def emptyline(self):
        return

    def precmd(self, line):
        if line == "EOF":
            return "exit"
        return line

    def postloop(self):
        if self.use_rawinput:
            print(f"{newLine}[+] Leaving the Peepdf interactive console{newLine}")
        self.leaving = True

    def do_bytes(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file!"
            self.log_output("bytes " + argv, message)
            return False
        byteVal = ""
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("bytes " + argv, message)
            return False
        numArgs = len(args)
        if numArgs in {2, 3}:
            offset = int(args[0])
            size = int(args[1])
            ret = getBytesFromFile(self.pdfFile.getPath(), offset, size)
            if ret[0] == -1:
                message = "[!] Error: The file does not exist"
                self.log_output("bytes " + argv, message)
                return False
            byteVal = ret[1]
            if numArgs == 2:
                self.log_output("bytes " + argv, byteVal, [byteVal], bytesOutput=True)
            else:
                outputFile = args[2]
                with open(outputFile, "wb") as outFile:
                    outFile.write(byteVal)
        else:
            self.help_bytes()

    def help_bytes(self):
        print(f"{newLine}Usage: bytes $offset $num_bytes [$file]")
        print(
            f"{newLine}Shows or stores in the specified file $num_bytes of the file beginning from $offset{newLine}"
        )

    def do_changelog(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("changelog " + argv, message)
            return False
        output = ""
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("changelog " + argv, message)
            return False
        if len(args) == 0:
            version = None
        elif len(args) == 1:
            version = args[0]
        else:
            self.help_changelog()
            return False
        if version is not None and not version.isdigit():
            self.help_changelog()
            return False
        if version is not None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = "[!] Error: The version number is not valid"
                self.log_output("changelog " + argv, message)
                return False
        if version == 0 or (version is None and self.pdfFile.getNumUpdates() == 0):
            message = "[!] No changes"
            self.log_output("changelog " + argv, message)
            return False
        # Getting information about original document
        data = self.pdfFile.getBasicMetadata(0)
        output += f"Original document information: {newLine}"
        if "title" in data and data["title"].isascii():
            output += f'\tTitle: {data["title"]}{newLine}'
        if "author" in data:
            output += f'\tAuthor: {data["author"]}{newLine}'
        if "creator" in data:
            output += f'\tCreator: {data["creator"]}{newLine}'
        if "producer" in data:
            output += f'\tProducer: {data["producer"]}{newLine}'
        if "creation" in data:
            output += f'\tCreation date: {data["creation"]}{newLine}'
        if output != "":
            output += f"{newLine}"

        # Getting changes for versions
        changes = self.pdfFile.getChangeLog(version)
        for k, v in enumerate(changes):
            changelog = v
            if changelog == [[], [], [], []]:
                output += f"No changes in version {str(k + 1)}{newLine}"
            else:
                output += f"Changes in version {str(k + 1)}: {newLine}"
            # Getting modification information
            data = self.pdfFile.getBasicMetadata(k + 1)
            if "title" in data and data["title"].isascii():
                output += f'\tTitle: {data["title"]}{newLine}'
            if "author" in data:
                output += f'\tAuthor: {data["author"]}{newLine}'
            if "creator" in data:
                output += f'\tCreator: {data["creator"]}{newLine}'
            if "producer" in data:
                output += f'\tProducer: {data["producer"]}{newLine}'
            if "modification" in data:
                output += f'\tModification date: {data["modification"]}{newLine}'
            addedObjects = changelog[0]
            modifiedObjects = changelog[1]
            removedObjects = changelog[2]
            notMatchingObjects = changelog[3]
            if addedObjects != []:
                output += f"\tAdded objects: {str(addedObjects)}{newLine}"
            if modifiedObjects != []:
                output += f"\tModified objects: {str(modifiedObjects)}{newLine}"
            if removedObjects != []:
                output += f"\tRemoved objects: {str(removedObjects)}{newLine}"
            if notMatchingObjects != []:
                output += f"\tIncoherent objects: {str(notMatchingObjects)}{newLine}"
            output += newLine
        self.log_output("changelog " + argv, output)

    def help_changelog(self):
        print(f"{newLine}Usage: changelog [$version]")
        print(
            f"{newLine}Shows the changelog of the document or version of the document {newLine}"
        )

    def do_clear(self):
        clearScreen()

    def help_clear(self):
        print(f"{newLine}Usage: clear")
        print(f"Clears the screen{newLine}")

    def do_create(self, argv):
        message = ""
        validCreateTypes = ["pdf", "object_stream"]
        args = self.parseArgs(argv)
        if not args:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("create " + argv, message)
            self.help_create()
            return False
        numArgs = len(args)
        elementType = args[0]
        if elementType not in validCreateTypes:
            self.help_create()
            return False
        if elementType == "pdf":
            content = ""
            validPDFTypes = ["simple", "open_action_js"]
            pdfType = "simple"
            if numArgs > 1:
                pdfType = args[1]
                if pdfType not in validPDFTypes:
                    self.help_create()
                    return False
                if pdfType == "open_action_js":
                    if numArgs > 3:
                        self.help_create()
                        return False
                    if numArgs == 3:
                        jsFile = args[2]
                        if not os.path.exists(jsFile):
                            message = f'[!] Error: The file "{jsFile}" does not exist'
                            self.log_output("create " + argv, message)
                            return False
                        with open(jsFile, "rb") as thisJsFile:
                            content = thisJsFile.read()
                    else:
                        if self.use_rawinput:
                            content = input(
                                f"{newLine}Please specify the Javascript code you want to include "
                                f"in the file (if the code includes EOL character s"
                                f"use a js_file instead): {newLine * 2}"
                            )
                        else:
                            message = "[!] Error: You must specify a Javascript file in script mode"
                            self.log_output("create " + argv, message)
                            return False
                elif pdfType == "simple":
                    if numArgs > 2:
                        self.help_create()
                        return False
            self.pdfFile = PDFFile()
            ret = self.pdfFile.makePDF(pdfType, content)
            if ret[0] == 0:
                message = "[+] PDF structure created successfully"
            else:
                message = (
                    "[!] Error: An error occurred while creating the PDF structure"
                )
            self.log_output("create " + argv, message)
        elif elementType == "object_stream":
            if self.pdfFile is None:
                message = "[!] Error: You must open a file"
                self.log_output("create " + argv, message)
                return False
            version = None
            if numArgs == 2:
                version = args[1]
            elif numArgs > 2:
                self.help_create()
                return False
            if version is not None and not version.isdigit():
                self.help_create()
                return False
            if version is not None:
                version = int(version)
                if version > self.pdfFile.getNumUpdates():
                    message = "[!] Error: The version number is not valid"
                    self.log_output("create " + argv, message)
                    return False
            warning = (
                "[!] Warning: stream objects cannot be compressed. If the Catalog object is compressed"
                " this could lead to corrupted files for Adobe Reader!"
            )
            if self.use_rawinput:
                res = input(
                    f"{warning}{newLine}Which objects do you want to compress? (Valid respones: all | 1-5 | 1,2,5,7,8) "
                )
            else:
                res = "all"
            if res == "all":
                objects = []
            elif res.count("-") == 1:
                limits = res.split("-")
                objects = range(int(limits[0]), int(limits[1]) + 1)
            elif res.find(",") != -1:
                objects = [int(thisId) for thisId in res.split(",")]
            elif res.isdigit():
                objects = [int(res)]
            else:
                message = "[!] Error: The response format is not valid. It should be: all | 1-13 | 1,3,5,8"
                self.log_output("create " + argv, message)
                return False
            ret = self.pdfFile.createObjectStream(version, objectIds=objects)
            if ret[0] == -1:
                error = ret[1]
                if error.find("Error") != -1:
                    message = f"[!] Error: {ret[1]}"
                    self.log_output("create " + argv, message)
                    return False
                message = f"[!] Warning: {ret[1]}"
            thisId = ret[1]
            if thisId is None:
                message = "[!] Error: The object stream has NOT been created"
                self.log_output("create " + argv, message)
                return False
            if message != "":
                message += newLine * 2
            message += "[+] The object stream has been created successfully"
            self.log_output("create " + argv, message)

    def help_create(self):
        print(
            f"{newLine}Usage: create pdf (simple | open_action_js [$js_file]){newLine}"
        )
        print(
            "Creates a new simple PDF file or one with Javascript code to be executed when opening the file.\r"
        )
        print(
            f"It is possible to specify the file where the Javascript code is stored or do it manually.{newLine}"
        )
        print(f"{newLine}Usage: create object_stream [$version]{newLine}")
        print(
            f"Creates an object stream choosing the objects to be compressed. {newLine * 2}"
        )

    def do_decode(self, argv):
        decodedContent = None
        src = None
        offset = 0
        size = 0
        validTypes = ["variable", "file", "raw", "string"]
        notImplementedFilters = ["ccittfax", "ccf", "dct", "jbig2", "jpx"]
        filters = []
        args = self.parseArgs(argv)
        if not args:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("decode " + argv, message)
            self.help_decode()
            return False
        if len(args) > 2:
            srcType = args[0]
            iniFilterArgs = 2
            if srcType not in validTypes:
                self.help_decode()
                return False
            if srcType in {"variable", "file", "string"}:
                src = args[1]
            else:
                if self.pdfFile is None:
                    message = "[!] Error: You must open a file"
                    self.log_output("decode " + argv, message)
                    return False
                if len(args) < 3:
                    self.help_decode()
                    return False
                iniFilterArgs = 3
                offset = args[1]
                size = args[2]
                if not offset.isdigit() or not size.isdigit():
                    message = '[!] Error: "offset" and "num_bytes" must be integers'
                    self.log_output("decode " + argv, message)
                    return False
                offset = int(args[1])
                size = int(args[2])
            for i in range(iniFilterArgs, len(args)):
                fileFilter = args[i].lower()
                if fileFilter not in filter2RealFilterDict:
                    self.help_decode()
                    return False
                if fileFilter in notImplementedFilters:
                    message = f"[!] Error: Filter {fileFilter} not implemented yet!"
                    self.log_output("decode " + argv, message)
                    return False
                filters.append(fileFilter)
        else:
            self.help_decode()
            return False

        if srcType == "variable":
            if src not in self.variables:
                message = "[!] Error: The variable does not exist"
                self.log_output("decode " + argv, message)
                return False
            decodedContent = self.variables[src][0]
        elif srcType == "file":
            if not os.path.exists(src):
                message = "[!] Error: The file does not exist"
                self.log_output("decode " + argv, message)
                return False
            with open(src, "rb") as srcFile:
                decodedContent = srcFile.read()
        elif srcType == "string":
            decodedContent = src
        else:
            ret = getBytesFromFile(self.pdfFile.getPath(), offset, size)
            if ret[0] == -1:
                message = "[!] Error: The file does not exist"
                self.log_output("decode " + argv, message)
                return False
            decodedContent = ret[1]
        if decodedContent == "":
            message = "[!] Error: The content is empty"
            self.log_output("decode " + argv, message)
            return False
        for fileFilter in filters:
            realFilter = filter2RealFilterDict[fileFilter]
            if realFilter == "base64":
                try:
                    decodedContent = b64decode(decodedContent)
                except:
                    message = f"[!] Error: {str(sys.exc_info()[1])}"
                    self.log_output("decode " + argv, message)
                    return False
            else:
                ret = decodeStream(decodedContent, realFilter)
                if ret[0] == -1:
                    message = f"[!] Error: {ret[1]}"
                    self.log_output("decode " + argv, message)
                    return False
                decodedContent = ret[1]
        self.log_output(
            "decode " + argv, decodedContent, [decodedContent], bytesOutput=True
        )

    def help_decode(self):
        print(f"{newLine}Usage: decode variable $var_name $filter1 [$filter2 ...]")
        print("Usage: decode file $file_name $filter1 [$filter2 ...]")
        print("Usage: decode raw $offset $num_bytes $filter1 [$filter2 ...]")
        print(f"Usage: decode string $encoded_string $filter1 [$filter2 ...] {newLine}")
        print(
            "Decodes the content of the specified variable, file or raw bytes using the following filters or algorithms:"
        )
        print("\tbase64,b64: Base64")
        print("\tasciihex,ahx: /ASCIIHexDecode")
        print("\tascii85,a85: /ASCII85Decode")
        print("\tlzw: /LZWDecode")
        print("\tflatedecode,fl: /FlateDecode")
        print("\trunlength,rl: /RunLengthDecode")
        print("\tccittfax,ccf: /CCITTFaxDecode")
        print("\tjbig2: /JBIG2Decode (Not implemented)")
        print("\tdct: /DCTDecode (Not implemented)")
        print(f"\tjpx: /JPXDecode (Not implemented) {newLine}")

    def do_decrypt(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("decrypt " + argv, message)
            return False
        args = self.parseArgs(argv)
        if not args:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("decrypt " + argv, message)
            self.help_decrypt()
            return False
        numArgs = len(args)
        if numArgs == 1:
            password = args[0]
        else:
            self.help_decrypt()
            return False
        ret = self.pdfFile.decrypt(password)
        if ret[0] == -1:
            message = f"[!] Error: {ret[1]}"
        else:
            message = "[+] File decrypted successfully"
        self.log_output("decrypt " + argv, message)

    def help_decrypt(self):
        print(f"{newLine}Usage: decrypt $password")
        print(f"Decrypts the file with the specified password {newLine}")

    def do_embed(self, argv):
        fileType = "application#2Fpdf"
        option = None
        version = None
        fileContent = None
        execute = False
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("embed " + argv, message)
            return False
        args = self.parseArgs(argv)
        if not args:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("embed " + argv, message)
            self.help_embed()
            return False
        numArgs = len(args)
        if numArgs == 1:
            fileName = args[0]
        elif numArgs == 2:
            if args[0] == "-x":
                fileName = args[1]
                execute = True
            else:
                fileName = args[0]
                fileType = args[1]
                if not os.path.exists(fileName):
                    self.help_embed()
                    return False
        elif numArgs == 3:
            option = args[0]
            fileName = args[1]
            fileType = args[2]
            if option != "-x":
                message = "[!] Error: Option not valid"
                self.log_output("embed " + argv, message)
                return False
            execute = True
        else:
            self.help_embed()
            return False

        if not os.path.exists(fileName):
            message = "[!] Error: The file does not exist"
            self.log_output("embed " + argv, message)
            return False
        with open(fileName, "rb") as thisFile:
            fileContent = thisFile.read()
        fileType = fileType.replace("/", "#2F")

        # Check existent /Names in Catalog
        namesDict = None
        namesDictId = None
        namesToFilesDict = None
        namesToFilesDictId = None
        catalogObject = None
        catalogObjectId = None
        catalogIndirectObjects = self.pdfFile.getCatalogObject(indirect=True)
        for i in range(len(catalogIndirectObjects) - 1, -1, -1):
            catalogIndirectObject = catalogIndirectObjects[i]
            if catalogIndirectObject is not None:
                catalogObject = catalogIndirectObject.getObject()
                if catalogObject is not None:
                    catalogObjectId = catalogIndirectObject.getId()
                    catalogObject = catalogIndirectObject.getObject()
                    version = i
                    if catalogObject.hasElement("/Names"):
                        namesDict = catalogObject.getElement("/Names")
                        namesDictType = namesDict.getType()
                        if namesDictType == "reference":
                            namesDictId = namesDict.getId()
                            namesDict = self.pdfFile.getObject(namesDictId, version)
                        elif namesDictType != "dictionary":
                            message = "[!] Error: Bad type for /Names in Catalog"
                            self.log_output("embed " + argv, message)
                            return False
                        if namesDict is not None and namesDict.hasElement(
                            "/EmbeddedFiles"
                        ):
                            namesToFilesDict = namesDict.getElement("/EmbeddedFiles")
                            namesToFilesDictType = namesToFilesDict.getType()
                            if namesToFilesDictType == "reference":
                                namesToFilesDictId = namesToFilesDict.getId()
                                namesToFilesDict = self.pdfFile.getObject(
                                    namesToFilesDictId, version
                                )
                            elif namesToFilesDictType != "dictionary":
                                message = (
                                    "[!] Error: Bad type for /EmbeddedFiles element"
                                )
                                self.log_output("embed " + argv, message)
                                return False
                    break
        if version is None:
            message = "[!] Error: Missing Catalog object"
            self.log_output("embed " + argv, message)
            return False

        hexFileNameObject = PDFHexString(fileName.encode("hex"))
        md5Hash = hashlib.md5(fileContent).hexdigest()
        fileSize = len(fileContent)
        paramsDic = PDFDictionary(
            elements={
                "/Size": PDFNum(str(fileSize)),
                "/Checksum": PDFHexString(md5Hash),
            }
        )
        embeddedFileElements = {
            "/Type": PDFName("EmbeddedFile"),
            "/Subtype": PDFName(fileType),
            "/Params": paramsDic,
            "/Length": PDFNum(str(fileSize)),
        }
        embeddedFileStream = PDFStream(
            rawStream=fileContent, elements=embeddedFileElements
        )
        embeddedFileStream.setElement("/Filter", PDFName("FlateDecode"))
        ret = self.pdfFile.setObject(None, embeddedFileStream, version)
        if ret[0] == -1:
            message = "[!] Error: The embedded stream has not been created"
            self.log_output("embed " + argv, message)
            return False
        embeddedFileStreamId = ret[1][0]
        embeddedListDict = PDFDictionary(
            elements={"/F": PDFReference(str(embeddedFileStreamId))}
        )
        fileSpecDict = PDFDictionary(
            elements={
                "/Type": PDFName("Filespec"),
                "/F": PDFString(fileName),
                "/EF": embeddedListDict,
            }
        )
        ret = self.pdfFile.setObject(None, fileSpecDict, version)
        if ret[0] == -1:
            message = "[!] Error: The Filespec dictionary has not been created"
            self.log_output("embed " + argv, message)
            return False
        fileSpecDictId = ret[1][0]

        if namesToFilesDict is not None:
            if namesToFilesDict.hasElement("/Names"):
                namesToFileArray = namesToFilesDict.getElement("/Names")
                namesToFileArrayType = namesToFileArray.getType()
                if namesToFileArrayType == "reference":
                    namesToFileArrayId = namesToFileArray.getId()
                    namesToFileArray = self.pdfFile.getObject(
                        namesToFileArrayId, version
                    )
                elif namesToFileArrayType != "array":
                    message = "[!] Error: Bad type for /Names in /EmbeddedFiles element"
                    self.log_output("embed " + argv, message)
                    return False
                namesToFileArray.addElement(hexFileNameObject)
                namesToFileArray.addElement(PDFReference(str(fileSpecDictId)))
                if namesToFileArrayType == "reference":
                    self.pdfFile.setObject(
                        namesToFileArrayId, namesToFileArray, version
                    )
                else:
                    namesToFilesDict.setElement("/Names", namesToFileArray)
                    if namesToFilesDictId is not None:
                        ret = self.pdfFile.setObject(
                            namesToFilesDictId, namesToFilesDict, version
                        )
                        if ret[0] == -1:
                            message = "[!] Error: The /EmbeddedFiles dictionary has not been modified"
                            self.log_output("embed " + argv, message)
                            return False
            elif namesToFilesDict.hasElement("/Kids"):
                message = "[!] Error: Children nodes in the /EmbeddedFiles element not supported"
                self.log_output("embed " + argv, message)
                return False
            else:
                namesToFilesDict.setElement(
                    "/Names",
                    PDFArray(
                        elements=[hexFileNameObject, PDFReference(str(fileSpecDictId))]
                    ),
                )
        else:
            namesToFilesDict = PDFDictionary(
                elements={
                    "/Names": PDFArray(
                        elements=[hexFileNameObject, PDFReference(str(fileSpecDictId))]
                    )
                }
            )

        if namesDict is not None:
            if namesToFilesDictId is None:
                namesDict.setElement("/EmbeddedFiles", namesToFilesDict)
                if namesDictId is not None:
                    ret = self.pdfFile.setObject(namesDictId, namesDict, version)
                    if ret[0] == -1:
                        message = (
                            "[!] Error: The /Names dictionary has not been modified"
                        )
                        self.log_output("embed " + argv, message)
                        return False
        else:
            namesDict = PDFDictionary(elements={"/EmbeddedFiles": namesToFilesDict})
        if namesDictId is None:
            catalogObject.setElement("/Names", namesDict)
            ret = self.pdfFile.setObject(catalogObjectId, catalogObject, version)
            if ret[0] == -1:
                message = "[!] Error: The Catalog has not been modified"
                self.log_output("embed " + argv, message)
                return False

        # Checking that the /Contents element is present
        if catalogObject.hasElement("/Pages"):
            pagesObject = catalogObject.getElement("/Pages")
            if pagesObject.getType() == "reference":
                pagesObjectId = pagesObject.getId()
                pagesObject = self.pdfFile.getObject(pagesObjectId, version)
                if pagesObject is not None:
                    if pagesObject.hasElement("/Kids"):
                        kidsObject = pagesObject.getElement("/Kids")
                        if kidsObject is not None:
                            kidsObjectType = kidsObject.getType()
                            if kidsObjectType == "reference":
                                kidsObjectId = kidsObject.getId()
                                kidsObject = self.pdfFile.getObject(
                                    kidsObjectId, version
                                )
                            elif kidsObjectType != "array":
                                message = "[!] Error: Bad type for /Kids element"
                                self.log_output("embed " + argv, message)
                                return False
                            pageObjects = kidsObject.getElements()
                            if len(pageObjects) > 0:
                                firstPageObjectId = None
                                firstPageObject = pageObjects[0]
                                if (
                                    firstPageObject is not None
                                    and firstPageObject.getType() == "reference"
                                ):
                                    firstPageObjectId = firstPageObject.getId()
                                    firstPageObject = self.pdfFile.getObject(
                                        firstPageObjectId, version
                                    )
                                else:
                                    message = "[!] Error: Bad type for /Page reference"
                                    self.log_output("embed " + argv, message)
                                    return False
                                if firstPageObject.getType() == "dictionary":
                                    if not firstPageObject.hasElement("/Contents"):
                                        contentsStream = PDFStream(
                                            rawStream="",
                                            elements={"/Length": PDFNum("0")},
                                        )
                                        ret = self.pdfFile.setObject(
                                            None, contentsStream, version
                                        )
                                        if ret[0] == -1:
                                            message = "[!] Error: The /Contents stream has not been created"
                                            self.log_output("embed " + argv, message)
                                            return False
                                        contentsStreamId = ret[1][0]
                                        firstPageObject.setElement(
                                            "/Contents",
                                            PDFReference(str(contentsStreamId)),
                                        )
                                    # Adding GoToE action
                                    if execute:
                                        targetDict = PDFDictionary(
                                            elements={
                                                "/N": hexFileNameObject,
                                                "/R": PDFName("C"),
                                            }
                                        )
                                        actionGoToEDict = PDFDictionary(
                                            elements={
                                                "/S": PDFName("GoToE"),
                                                "/NewWindow": PDFBool("false"),
                                                "/T": targetDict,
                                            }
                                        )
                                        ret = self.pdfFile.setObject(
                                            None, actionGoToEDict, version
                                        )
                                        if ret[0] == -1:
                                            message = "[!] Error: The /GoToE element has not been created"
                                            self.log_output("embed " + argv, message)
                                            return False
                                        actionGoToEDictId = ret[1][0]
                                        aaDict = PDFDictionary(
                                            elements={
                                                "/O": PDFReference(
                                                    str(actionGoToEDictId)
                                                )
                                            }
                                        )
                                        firstPageObject.setElement("/AA", aaDict)
                                        ret = self.pdfFile.setObject(
                                            firstPageObjectId, firstPageObject, version
                                        )
                                        if ret[0] == -1:
                                            message = "[!] Error: The /Page element has not been modified"
                                            self.log_output("embed " + argv, message)
                                            return False
                                else:
                                    message = "[!] Error: Bad type for /Page element"
                                    self.log_output("embed " + argv, message)
                                    return False
                            else:
                                message = "[!] Error: Missing /Page element"
                                self.log_output("embed " + argv, message)
                                return False
                        else:
                            message = "[!] Error: /Kids element corrupted"
                            self.log_output("embed " + argv, message)
                            return False
                    else:
                        message = "[!] Error: Missing /Kids element"
                        self.log_output("embed " + argv, message)
                        return False
                else:
                    message = "[!] Error: /Pages element corrupted"
                    self.log_output("embed " + argv, message)
                    return False
            else:
                message = "[!] Error: Bad type for /Pages element"
                self.log_output("embed " + argv, message)
                return False
        else:
            message = "[!] Error: Missing /Pages element"
            self.log_output("embed " + argv, message)
            return False

        message = "[+] File embedded successfully"
        self.log_output("open " + argv, message)

    def help_embed(self):
        print(f"{newLine}Usage: embed [-x] $filename [$file_type]")
        print(
            f'Embeds the specified file in the actual PDF file. Default type is "application/pdf". {newLine}'
        )
        print("Options:")
        print(
            f"\t-x: The file is executed when the actual PDF file is opened {newLine}"
        )

    def do_encode(self, argv):
        encodedContent = ""
        src = ""
        offset = 0
        size = 0
        validTypes = ["variable", "file", "raw", "string"]
        notImplementedFilters = [
            "ascii85",
            "a85",
            "runlength",
            "rl",
            "jbig2",
            "jpx",
            "ccittfax",
            "ccf",
            "dct",
        ]
        filters = []
        args = self.parseArgs(argv)
        if not args:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("encode " + argv, message)
            self.help_encode()
            return False
        if len(args) > 2:
            srcType = args[0]
            iniFilterArgs = 2
            if srcType not in validTypes:
                self.help_encode()
                return False
            if srcType in {"variable", "file", "string"}:
                src = args[1]
            else:
                if self.pdfFile is None:
                    message = "[!] Error: You must open a file"
                    self.log_output("decode " + argv, message)
                    return False
                if len(args) < 3:
                    self.help_encode()
                    return False
                iniFilterArgs = 3
                offset = args[1]
                size = args[2]
                if not offset.isdigit() or not size.isdigit():
                    message = '[!] Error: "offset" and "num_bytes" must be integers'
                    self.log_output("encode " + argv, message)
                    return False
                offset = int(args[1])
                size = int(args[1])
            for i in range(iniFilterArgs, len(args)):
                fileFilter = args[i].lower()
                if fileFilter not in filter2RealFilterDict:
                    self.help_encode()
                    return False
                if fileFilter in notImplementedFilters:
                    message = f'[!] Error: Filter "{fileFilter}" not implemented yet'
                    self.log_output("encode " + argv, message)
                    return False
                filters.append(fileFilter)
        else:
            self.help_encode()
            return False

        if srcType == "variable":
            if src not in self.variables:
                message = "[!] Error: The variable does not exist"
                self.log_output("encode " + argv, message)
                return False
            encodedContent = self.variables[src][0]
        elif srcType == "file":
            if not os.path.exists(src):
                message = "[!] Error: The file does not exist"
                self.log_output("encode " + argv, message)
                return False
            with open(src, "rb") as srcFile:
                encodedContent = srcFile.read()
        elif srcType == "string":
            encodedContent = src
        else:
            ret = getBytesFromFile(self.pdfFile.getPath(), offset, size)
            if ret[0] == -1:
                message = "[!] Error: The file does not exist"
                self.log_output("encode " + argv, message)
                return False
            encodedContent = ret[1]
        if encodedContent == "":
            message = "[!] Error: The content is empty"
            self.log_output("encode " + argv, message)
            return False
        for fileFilter in filters:
            realFilter = filter2RealFilterDict[fileFilter]
            if realFilter == "base64":
                encodedContent = b64encode(encodedContent)
            else:
                ret = encodeStream(encodedContent, realFilter)
                if ret[0] == -1:
                    message = f"[!] Error: {ret[1]}"
                    self.log_output("encode " + argv, message)
                    return False
                encodedContent = ret[1]
        self.log_output(
            "encode " + argv, encodedContent, [encodedContent], bytesOutput=True
        )

    def help_encode(self):
        print(f"{newLine}Usage: encode variable $var_name $filter1 [$filter2 ...]")
        print("Usage: encode file $file_name $filter1 [$filter2 ...]")
        print("Usage: encode raw $offset $num_bytes $filter1 [$filter2 ...]")
        print(f"Usage: encode string $my_string $filter1 [$filter2 ...] {newLine}")
        print(
            "Encodes the content of the specified variable, file or raw bytes using the following filters or algorithms:"
        )
        print("\tbase64,b64: Base64")
        print("\tasciihex,ahx: /ASCIIHexDecode")
        print("\tascii85,a85: /ASCII85Decode (Not implemented)")
        print("\tlzw: /LZWDecode")
        print("\tflatedecode,fl: /FlateDecode")
        print("\trunlength,rl: /RunLengthDecode (Not implemented)")
        print("\tccittfax,ccf: /CCITTFaxDecode (Not implemented)")
        print("\tjbig2: /JBIG2Decode (Not implemented)")
        print("\tdct: /DCTDecode (Not implemented)")
        print(f"\tjpx: /JPXDecode (Not implemented) {newLine}")

    def do_encode_strings(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("encode_strings " + argv, message)
            return False
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("encode_strings " + argv, message)
            return False
        if len(args) == 0:
            ret = self.pdfFile.encodeChars()
            if ret[0] == -1:
                message = f"[!] Error: {ret[1]}"
                self.log_output("encode_strings " + argv, message)
                return False
            message = "[+] File encoded successfully"
        elif len(args) == 1 or len(args) == 2:
            if len(args) == 1:
                version = None
            else:
                version = args[1]
            thisId = args[0]
            if (not thisId.isdigit() and thisId != "trailer") or (
                version is not None and not version.isdigit()
            ):
                self.help_encode_strings()
                return False
            if version is not None:
                version = int(version)
                if version > self.pdfFile.getNumUpdates():
                    message = "[!] Error: The version number is not valid"
                    self.log_output("encode_strings " + argv, message)
                    return False
            if thisId == "trailer":
                ret = self.pdfFile.getTrailer(version)
                if (
                    ret is None
                    or ret[1] == []
                    or ret[1] is None
                    or ret[1] == [None, None]
                ):
                    message = "[!] Error: Trailer not found"
                    self.log_output("encode_strings " + argv, message)
                    return False
                trailerArray = ret[1]
                version = ret[0]
                if trailerArray[0] is not None:
                    trailerArray[0].encodeChars()
                    ret = self.pdfFile.setTrailer(trailerArray, version)
                    if ret[0] == -1:
                        message = "[!] Error: There were some problems in the modification process"
                        self.log_output("encode_strings " + argv, message)
                        return False
                    message = "Trailer encoded successfully"
            else:
                thisId = int(thisId)
                obj = self.pdfFile.getObject(thisId, version)
                if obj is None:
                    message = "[!] Error: Object not found"
                    self.log_output("encode_strings " + argv, message)
                    return False
                objectType = obj.getType()
                if objectType not in [
                    "string",
                    "name",
                    "array",
                    "dictionary",
                    "stream",
                ]:
                    message = "[!] Error: This type of object cannot be encoded"
                    self.log_output("encode_strings " + argv, message)
                    return False
                ret = obj.encodeChars()
                if ret[0] == -1:
                    message = f"[!] Error: {ret[1]}"
                    self.log_output("encode_strings " + argv, message)
                    return False
                ret = self.pdfFile.setObject(thisId, obj, version, True)
                if ret[0] == -1:
                    message = "[!] Error: There were some problems in the modification process"
                    self.log_output("encode_strings " + argv, message)
                    return False
                message = "[+] Object encoded successfully"
        else:
            self.help_encode_strings()
            return False
        self.log_output("encode_strings " + argv, message)

    def help_encode_strings(self):
        print(f"{newLine}Usage: encode_strings [$object_id|trailer [$version]]")
        print(
            f"Encodes the strings and names included in the file, object or trailer {newLine}"
        )

    def do_encrypt(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("encrypt " + argv, message)
            return False
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("encrypt " + argv, message)
            return False
        numArgs = len(args)
        if numArgs == 0:
            password = ""
        elif numArgs == 1:
            password = args[0]
        else:
            self.help_encrypt()
            return False
        ret = self.pdfFile.encrypt(password)
        if ret[0] == -1:
            message = f"[!] Error: {ret[1]}"
        else:
            message = "[+] File encrypted successfully"
        self.log_output("encrypt " + argv, message)

    def help_encrypt(self):
        print(f"{newLine}Usage: encrypt [$password]")
        print(f"Encrypts the file with the default or specified password {newLine}")

    def do_errors(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("errors " + argv, message)
            return False
        errors = ""
        errorsArray = []
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("errors " + argv, message)
            return False
        if len(args) == 0:
            errorsArray = self.pdfFile.getErrors()
            for error in errorsArray:
                errors += error
                if error != errorsArray[-1]:
                    errors += newLine
            if errors == "":
                errors = "[+] No errors"
            else:
                errors = self.errorColor + errors + self.resetColor
            self.log_output("errors " + argv, errors)
            return False
        if len(args) == 1:
            version = None
        elif len(args) == 2:
            version = args[1]
        else:
            self.help_errors()
            return False
        thisId = args[0]
        if (not thisId.isdigit() and thisId != "trailer" and thisId != "xref") or (
            version is not None and not version.isdigit()
        ):
            self.help_errors()
            return False
        if version is not None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = "[!] Error: The version number is not valid"
                self.log_output("errors " + argv, message)
                return False
        if thisId == "xref":
            ret = self.pdfFile.getXrefSection(version)
            if ret is None or ret[1] is None or ret[1] == [] or ret[1] == [None, None]:
                message = "[!] Error: xref section not found"
                self.log_output("errors " + argv, message)
                return False
            xrefArray = ret[1]
            if xrefArray[0] is not None:
                errorsArray = xrefArray[0].getErrors()
            if xrefArray[1] is not None:
                errorsArray += xrefArray[1].getErrors()
        elif thisId == "trailer":
            ret = self.pdfFile.getTrailer(version)
            if ret is None or ret[1] is None or ret[1] == [] or ret[1] == [None, None]:
                message = "[!] Error: Trailer not found"
                self.log_output("errors " + argv, message)
                return False
            trailerArray = ret[1]
            if trailerArray[0] is not None:
                errorsArray = trailerArray[0].getErrors()
            if trailerArray[1] is not None:
                errorsArray += trailerArray[1].getErrors()
        else:
            thisId = int(thisId)
            obj = self.pdfFile.getObject(thisId, version)
            if obj is None:
                message = "[!] Error: Object not found"
                self.log_output("errors " + argv, message)
                return False
            errorsArray = obj.getErrors()
        messages, counters = countArrayElements(errorsArray)
        for k, v in enumerate(messages):
            errors += f"{v} ({str(counters[k])}){newLine}"
        if errors == "":
            errors = "[+] No errors"
        else:
            errors = self.errorColor + errors + self.resetColor
        self.log_output("errors " + argv, errors)

    def help_errors(self):
        print(f"{newLine}Usage: errors [$object_id|xref|trailer [$version]]")
        print(
            f"Shows the errors of the file or object (object_id, xref, trailer) {newLine}"
        )

    def do_exit(self, argv):
        return True

    def help_exit(self):
        print(f"{newLine}Usage: exit")
        print(f"Exits from the console {newLine}")

    def do_extract(self, argv):
        validTypes = ["uri", "js"]
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("extract " + argv, message)
            return False
        args = self.parseArgs(argv)
        if not args:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("extract " + argv, message)
            self.help_extract()
            return False
        if len(args) == 1:
            version = None
        elif len(args) == 2:
            version = args[1]
        else:
            self.help_extract()
            return False
        elementType = args[0]
        if not elementType or elementType not in validTypes:
            self.help_extract()
            return False
        if version is not None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = "[!] Error: The version number is not valid"
                self.log_output("extract " + argv, message)
                return False
        # Getting all the elements belonging to the given type
        output = ""
        extractedUrisPerObject = []
        extractedJsPerObject = []
        if elementType == "uri":
            extractedUrisPerObject = self.pdfFile.getURIs(version, perObject=True)
        elif elementType == "js":
            extractedJsPerObject = self.pdfFile.getJavascriptCode(
                version, perObject=True
            )
        for version, result in enumerate(extractedUrisPerObject):
            for extractedUri in result:
                output += f"{extractedUri[1]} {extractedUri[0]}{newLine}"
        if output:
            output += newLine
        for version, result in enumerate(extractedJsPerObject):
            for extractedJs in result:
                output += (
                    f"// peepdf comment: Javascript code located in object {extractedJs[0]} "
                    f"(version {version}){newLine * 2}{extractedJs[1]}{newLine * 2}"
                )
        self.log_output("extract " + argv, output)

    def help_extract(self):
        print(f"{newLine}Usage: extract uri|js [$version]")
        print(
            f"Extracts all the given type elements of the specified version after being decoded and decrypted (if necessary) {newLine}"
        )

    def do_filters(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("errors " + argv, message)
            return False
        message = ""
        value = ""
        filtersArray = []
        notImplementedFilters = [
            "ascii85",
            "a85",
            "runlength",
            "rl",
            "jbig2",
            "jpx",
            "ccittfax",
            "ccf",
            "dct",
        ]
        iniFilterArgs = 1
        filters = []
        args = self.parseArgs(argv)
        if not args:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("filters " + argv, message)
            self.help_filters()
            return False
        if len(args) == 1:
            version = None
        else:
            if args[1].isdigit():
                version = args[1]
                iniFilterArgs = 2
            else:
                version = None
            validFilters = list(filter2RealFilterDict.keys()) + ["none"]
            validFilters.remove("b64")
            validFilters.remove("base64")
            for i in range(iniFilterArgs, len(args)):
                thisFilter = args[i].lower()
                if thisFilter not in validFilters:
                    self.help_filters()
                    return False
                if thisFilter in notImplementedFilters:
                    message = f'[!] Error: Filter "{thisFilter}" not implemented yet'
                    self.log_output("filters " + argv, message)
                    return False
                filters.append(thisFilter)

        thisId = args[0]
        if not thisId.isdigit() or (version is not None and not version.isdigit()):
            self.help_filters()
            return False
        thisId = int(thisId)
        if version is not None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = "[!] Error: The version number is not valid"
                self.log_output("filters " + argv, message)
                return False

        obj = self.pdfFile.getObject(thisId, version)
        if obj is None:
            message = "[!] Error: Object not found"
            self.log_output("filters " + argv, message)
            return False
        if obj.getType() != "stream":
            message = "[!] Error: The object doesn't contain any streams"
            self.log_output("filters " + argv, message)
            return False
        errors = obj.getErrors()
        if not filters:
            if obj.hasElement("/Filter"):
                value = obj.getElementByName("/Filter").getValue()
                if obj.hasElement("/DecodeParms"):
                    parameters = obj.getElementByName("/DecodeParms").getValue()
                    value += " " + parameters
            else:
                message = "[!] Warning: No filters found in the object"
                self.log_output("filters " + argv, message)
                return False
        else:
            value = obj.getStream()
            if value in (-1, ""):
                message = "[!] Error: The stream cannot be decoded"
                self.log_output("filters " + argv, message)
                return False
            if len(filters) == 1:
                if filters[0] == "none":
                    ret = obj.delElement("/Filter")
                else:
                    filtersPDFName = PDFName(filter2RealFilterDict[filters[0]])
                    ret = obj.setElement("/Filter", filtersPDFName)
                if ret[0] == -1:
                    message = f"[!] Error: {ret[1]}"
                    self.log_output("filters " + argv, message)
                    return False
            else:
                while True:
                    if "none" in filters:
                        filters.remove("none")
                    else:
                        break
                filters.reverse()
                for thisFilter in filters:
                    filtersArray.append(PDFName(filter2RealFilterDict[thisFilter]))
                if filtersArray:
                    filtersPDFArray = PDFArray("", filtersArray)
                    ret = obj.setElement("/Filter", filtersPDFArray)
                    if ret[0] == -1:
                        message = f"[!] Error: {ret[1]}"
                        self.log_output("filters " + argv, message)
                        return False
            ret = self.pdfFile.setObject(thisId, obj, version)
            if ret[0] == -1:
                message = f"[!] Error: {ret[1]}"
                self.log_output("filters " + argv, message)
                return False
            value = str(obj.getRawValue())
            newErrors = obj.getErrors()
            if newErrors != errors:
                message = f"[!] Warning: Some errors found in the modification process {newLine}"
        self.log_output("filters " + argv, message + value, [value], bytesOutput=True)

    def help_filters(self):
        print(
            f"{newLine}Usage: filters $object_id [$version] [$filter1 [$filter2 ...]]"
        )
        print(
            "Shows the filters found in the stream object or set the filters in the object (first filter is used first). The valid values for filters are the following:"
        )
        print("\tnone: No filters")
        print("\tasciihex,ahx: /ASCIIHexDecode")
        print("\tascii85,a85: /ASCII85Decode (Not implemented)")
        print("\tlzw: /LZWDecode")
        print("\tflatedecode,fl: /FlateDecode")
        print("\trunlength,rl: /RunLengthDecode (Not implemented)")
        print("\tccittfax,ccf: /CCITTFaxDecode (Not implemented)")
        print("\tjbig2: /JBIG2Decode (Not implemented)")
        print("\tdct: /DCTDecode (Not implemented)")
        print(f"\tjpx: /JPXDecode (Not implemented) {newLine}")

    def do_hash(self, argv):
        content = ""
        srcName = ""
        thisId = ""
        validTypes = [
            "variable",
            "file",
            "raw",
            "object",
            "rawobject",
            "stream",
            "rawstream",
            "string",
        ]
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("hash " + argv, message)
            self.help_hash()
            return False
        if len(args) == 2:
            if args[0] in {"object", "rawobject", "stream", "rawstream"}:
                thisId = args[1]
                version = None
            elif args[0] in {"file", "variable", "string"}:
                srcName = args[1]
            else:
                self.help_hash()
                return False
        elif len(args) == 3:
            if args[0] in {"object", "rawobject", "stream", "rawstream"}:
                thisId = args[1]
                version = args[2]
            elif args[0] == "raw":
                offset = args[1]
                size = args[2]
            else:
                self.help_hash()
                return False
        else:
            self.help_hash()
            return False

        srcType = args[0]
        if srcType not in validTypes:
            self.help_hash()
            return False
        if srcType == "variable":
            if srcName not in self.variables:
                message = "[!] Error: The variable does not exist"
                self.log_output("hash " + argv, message)
                return False
            content = self.variables[srcName][0]
        elif srcType == "file":
            if not os.path.exists(srcName):
                message = "[!] Error: The file does not exist"
                self.log_output("hash " + argv, message)
                return False
            with open(srcName, "rb") as srcFile:
                content = srcFile.read()
        elif srcType == "string":
            content = srcName
        else:
            if self.pdfFile is None:
                message = "[!] Error: You must open a file"
                self.log_output("hash " + argv, message)
                return False
            if srcType == "raw":
                if not offset.isdigit() or not size.isdigit():
                    self.help_hash()
                    return False
                offset = int(offset)
                size = int(size)
                ret = getBytesFromFile(self.pdfFile.getPath(), offset, size)
                if ret[0] == -1:
                    message = "[!] Error: The file does not exist"
                    self.log_output("hash " + argv, message)
                    return False
                content = ret[1]
            else:
                if not thisId.isdigit() or (
                    version is not None and not version.isdigit()
                ):
                    self.help_hash()
                    return False
                thisId = int(thisId)
                if version is not None:
                    version = int(version)
                    if version > self.pdfFile.getNumUpdates():
                        message = "[!] Error: The version number is not valid"
                        self.log_output("hash " + argv, message)
                        return False
                obj = self.pdfFile.getObject(thisId, version)
                if obj is None:
                    message = "[!] Error: Object not found"
                    self.log_output("hash " + argv, message)
                    return False
                if srcType in {"stream", "rawstream"}:
                    if obj.getType() != "stream":
                        message = "[!] Error: The object doesn't contain any stream"
                        self.log_output("hash " + argv, message)
                        return False
                    if srcType == "stream":
                        content = obj.getStream()
                    else:
                        content = obj.getRawStream()
                elif srcType == "object":
                    content = obj.getValue()
                else:
                    content = obj.getRawValue()
        content = str(content)
        md5Hash = hashlib.md5(content.encode()).hexdigest()
        sha1Hash = hashlib.sha1(content.encode()).hexdigest()
        sha256Hash = hashlib.sha256(content.encode()).hexdigest()
        output = f"MD5: {md5Hash}{newLine}SHA1: {sha1Hash}{newLine}SHA256: {sha256Hash}{newLine}"
        self.log_output("hash " + argv, output)

    def help_hash(self):
        print(
            f"{newLine}Usage: hash object|rawobject|stream|rawstream $object_id [$version]"
        )
        print("Usage: hash raw $offset $num_bytes")
        print("Usage: hash file $file_name")
        print("Usage: hash variable $var_name")
        print("Usage: hash string $my_string")
        print(
            f"Generates the hash (MD5/SHA1/SHA256) of the specified source: raw bytes of the file, objects and streams, and the content of files or variables {newLine}"
        )

    def help_help(self):
        print(f"{newLine}Usage: help [$command]")
        print(
            f"Shows the available commands or the usage of the specified command {newLine}"
        )

    def do_info(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("info " + argv, message)
            return False
        stats = ""
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("info " + argv, message)
            return False
        if not self.avoidOutputColors:
            beforeStaticLabel = self.staticColor
        else:
            beforeStaticLabel = ""
        if len(args) == 0:
            statsDict = self.pdfFile.getStats()
            stats += f'{beforeStaticLabel}File: {self.resetColor}{statsDict["File"]}{newLine}'
            stats += (
                f'{beforeStaticLabel}MD5: {self.resetColor}{statsDict["MD5"]}{newLine}'
                f'{beforeStaticLabel}SHA1: {self.resetColor}{statsDict["SHA1"]}{newLine}'
                f'{beforeStaticLabel}SHA256: {self.resetColor}{statsDict["SHA256"]}{newLine}'
                f'{beforeStaticLabel}Size: {self.resetColor}{statsDict["Size"]} bytes{newLine}'
                f'{beforeStaticLabel}IDs: {self.resetColor}{statsDict["IDs"]}{newLine}'
            )
            if statsDict["Detection"] != []:
                detectionReportInfo = ""
                if statsDict["Detection"] is not None:
                    detectionLevel = statsDict["Detection"][0] / (
                        statsDict["Detection"][1] / 3
                    )
                    if detectionLevel == 0:
                        detectionColor = self.alertColor
                    elif detectionLevel == 1:
                        detectionColor = self.warningColor
                    else:
                        detectionColor = ""
                    detectionRate = f"{detectionColor}{statsDict['Detection'][0]}{self.resetColor}/{statsDict['Detection'][1]}"
                    if statsDict["Detection report"] != "":
                        detectionReportInfo = f"{beforeStaticLabel}Detection report: {self.resetColor}{statsDict['Detection report']}{newLine}"
                    else:
                        detectionRate = "File not found on VirusTotal"
                    stats += f"{beforeStaticLabel}Detection: {self.resetColor}{detectionRate}{newLine}{detectionReportInfo}"
            stats += (
                f'{beforeStaticLabel}PDF Format Version: {self.resetColor}{statsDict["Version"]}{newLine}'
                f'{beforeStaticLabel}Binary: {self.resetColor}{statsDict["Binary"]}{newLine}'
                f'{beforeStaticLabel}Linearized: {self.resetColor}{statsDict["Linearized"]}{newLine}'
                f'{beforeStaticLabel}Encrypted: {self.resetColor}{statsDict["Encrypted"]}'
            )
            if statsDict["Encryption Algorithms"] != []:
                stats += " ("
                for algorithmInfo in statsDict["Encryption Algorithms"]:
                    stats += f"{algorithmInfo[0]} {str(algorithmInfo[1])} bits, "
                stats = stats[:-2] + ")"
            stats += (
                f"{newLine}"
                f'{beforeStaticLabel}Updates: {self.resetColor}{statsDict["Updates"]}{newLine}'
                f'{beforeStaticLabel}Objects: {self.resetColor}{statsDict["Objects"]}{newLine}'
                f'{beforeStaticLabel}Streams: {self.resetColor}{statsDict["Streams"]}{newLine}'
                f'{beforeStaticLabel}URIs: {self.resetColor}{statsDict["URIs"]}{newLine}'
                f'{beforeStaticLabel}Comments: {self.resetColor}{statsDict["Comments"]}{newLine}'
                f'{beforeStaticLabel}Errors: {self.resetColor}{str(len(statsDict["Errors"]))}{newLine * 2}'
            )
            for version in range(len(statsDict["Versions"])):
                statsVersion = statsDict["Versions"][version]
                stats += f"{beforeStaticLabel}Version {self.resetColor}{str(version)}: {newLine}"
                if statsVersion["Catalog"] is not None:
                    stats += f'{beforeStaticLabel}\tCatalog: {self.resetColor}{statsVersion["Catalog"]}{newLine}'
                else:
                    stats += (
                        f"{beforeStaticLabel}\tCatalog: {self.resetColor}No {newLine}"
                    )
                if statsVersion["Info"] is not None:
                    stats += f'{beforeStaticLabel}\tInfo: {self.resetColor}{statsVersion["Info"]}{newLine}'
                else:
                    stats += f"{beforeStaticLabel}\tInfo: {self.resetColor}No {newLine}"
                stats += (
                    f'{beforeStaticLabel}\tObjects ({statsVersion["Objects"][0]}): '
                    f'{self.resetColor}{str(statsVersion["Objects"][1])}{newLine}'
                )
                if statsVersion["Compressed Objects"] is not None:
                    stats += (
                        f"{beforeStaticLabel}\tCompressed objects ("
                        f'{statsVersion["Compressed Objects"][0]}): {self.resetColor}'
                        f'{str(statsVersion["Compressed Objects"][1])}{newLine}'
                    )
                if statsVersion["Errors"] is not None:
                    stats += (
                        f'{beforeStaticLabel}\tErrors ({statsVersion["Errors"][0]}): '
                        f'{self.resetColor}{str(statsVersion["Errors"][1])}{newLine}'
                    )
                stats += (
                    f'{beforeStaticLabel}\tStreams ({statsVersion["Streams"][0]}): '
                    f'{self.resetColor}{str(statsVersion["Streams"][1])}'
                )
                if statsVersion["Xref Streams"] is not None:
                    stats += (
                        f"{newLine}{beforeStaticLabel}\tXref streams "
                        f'({statsVersion["Xref Streams"][0]}): '
                        f'{self.resetColor}{str(statsVersion["Xref Streams"][1])}'
                    )
                if statsVersion["Object Streams"] is not None:
                    stats += (
                        f"{newLine}{beforeStaticLabel}\tObject streams ("
                        f'{statsVersion["Object Streams"][0]}): {self.resetColor}'
                        f'{str(statsVersion["Object Streams"][1])}'
                    )
                if int(statsVersion["Streams"][0]) > 0:
                    stats += (
                        f'{newLine}{beforeStaticLabel}\tEncoded ({statsVersion["Encoded"][0]}): '
                        f'{self.resetColor}{str(statsVersion["Encoded"][1])}'
                    )
                    if statsVersion["Decoding Errors"] is not None:
                        stats += (
                            f"{newLine}{beforeStaticLabel}\tDecoding errors ("
                            f'{statsVersion["Decoding Errors"][0]}): '
                            f'{self.resetColor}{str(statsVersion["Decoding Errors"][1])}'
                        )
                if statsVersion["URIs"] is not None:
                    stats += (
                        f"{newLine}{beforeStaticLabel}\tObjects with URIs ("
                        f'{statsVersion["URIs"][0]}): {self.resetColor}{str(statsVersion["URIs"][1])}'
                    )
                if not self.avoidOutputColors:
                    beforeStaticLabel = self.warningColor
                if statsVersion["Objects with JS code"] is not None:
                    stats += (
                        f"{newLine}{beforeStaticLabel}\tObjects with JS code ("
                        f'{statsVersion["Objects with JS code"][0]}): '
                        f'{self.resetColor}{str(statsVersion["Objects with JS code"][1])}'
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
                    stats += f"{newLine}{beforeStaticLabel}\tSuspicious elements ({totalSuspicious}):{self.resetColor}{newLine}"
                    if events is not None:
                        for event in events:
                            stats += (
                                f"\t\t{beforeStaticLabel}{event} ({len(events[event])}): "
                                f"{self.resetColor}{str(sorted(events[event]))}{newLine}"
                            )
                    if actions is not None:
                        for action in actions:
                            stats += (
                                f"\t\t{beforeStaticLabel}{action} ({len(actions[action])}): "
                                f"{self.resetColor}{str(actions[action])}{newLine}"
                            )
                    if vulns is not None:
                        for vuln in vulns:
                            if vuln in vulnsDict:
                                vulnName = vulnsDict[vuln][0]
                                vulnCVEList = vulnsDict[vuln][1]
                                stats += f"\t\t{beforeStaticLabel}{vulnName} ("
                                for vulnCVE in vulnCVEList:
                                    stats += f"{vulnCVE},"
                                stats = (
                                    f"{stats[:-1]}) ({len(vulns[vuln])}): "
                                    f"{self.resetColor}{str(vulns[vuln])}{newLine}"
                                )
                            else:
                                stats += (
                                    f"\t\t{beforeStaticLabel}{vuln} ({len(vulns[vuln])}): "
                                    f"{self.resetColor}{str(vulns[vuln])}{newLine}"
                                )
                    if elements is not None:
                        for element in elements:
                            if element in vulnsDict:
                                vulnName = vulnsDict[element][0]
                                vulnCVEList = vulnsDict[element][1]
                                stats += f"\t\t{beforeStaticLabel}{vulnName} ("
                                for vulnCVE in vulnCVEList:
                                    stats += f"{vulnCVE},"
                                stats += f"{stats[:-1]}): {self.resetColor}{str(elements[element])}{newLine}"
                            else:
                                stats += (
                                    f"\t\t{beforeStaticLabel}{element} ({len(elements[element])}): "
                                    f"{self.resetColor}{str(elements[element])}{newLine}"
                                )
                if not self.avoidOutputColors:
                    beforeStaticLabel = self.staticColor
                urls = statsVersion["URLs"]
                if urls is not None:
                    stats += f"{newLine}{beforeStaticLabel}\tFound URLs:{self.resetColor}{newLine}"
                    for url in urls:
                        stats += f"\t\t{url}{newLine}"
                stats += f"{newLine * 2}"
            self.log_output("info " + argv, stats)
            return False
        if len(args) == 1:
            version = None
        elif len(args) == 2:
            version = args[1]
        else:
            self.help_info()
            return False
        thisId = args[0]
        if (not thisId.isdigit() and thisId != "trailer" and thisId != "xref") or (
            version is not None and not version.isdigit()
        ):
            self.help_info()
            return False
        if version is not None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = "[!] Error: The version number is not valid"
                self.log_output("info " + argv, message)
                return False
        if thisId == "xref":
            statsDict = {}
            ret = self.pdfFile.getXrefSection(version)
            if ret is None or ret[1] is None or ret[1] == [] or ret[1] == [None, None]:
                message = "[!] Error: xref section not found"
                self.log_output("info " + argv, message)
                return False
            xrefArray = ret[1]
            if xrefArray[0] is not None:
                statsDict = xrefArray[0].getStats()
            if xrefArray[1] is not None:
                statsStream = xrefArray[1].getStats()
                for key in statsStream:
                    if not key in statsDict:
                        statsDict[key] = statsStream[key]
            if statsDict["Offset"] is not None:
                stats += f'{beforeStaticLabel}Offset: {self.resetColor}{statsDict["Offset"]}{newLine}'
            stats += f'{beforeStaticLabel}Size: {self.resetColor}{statsDict["Size"]}{newLine}'
            if statsDict["Stream"] is not None:
                stats += f'{beforeStaticLabel}Stream: {self.resetColor}{statsDict["Stream"]}{newLine}'
            else:
                stats += f"{beforeStaticLabel}Stream: {self.resetColor}No {newLine}"
            numSubSections = len(statsDict["Subsections"])
            stats += f"{beforeStaticLabel}Subsections: {self.resetColor}{str(numSubSections)}{newLine}"
            for i in range(numSubSections):
                subStats = statsDict["Subsections"][i]
                stats += (
                    f"{beforeStaticLabel}\tSubsection {self.resetColor}{str(i + 1)}: {newLine}"
                    f'{beforeStaticLabel}\t\tEntries: {self.resetColor}{subStats["Entries"]}{newLine}'
                )
                if subStats["Errors"] is not None:
                    stats += f'{beforeStaticLabel}\t\tErrors: {self.resetColor}{subStats["Errors"]}{newLine}'
            if statsDict["Errors"] is not None:
                stats += f'{beforeStaticLabel}Errors: {self.resetColor}{statsDict["Errors"]}{newLine}'
        elif thisId == "trailer":
            statsDict = {}
            ret = self.pdfFile.getTrailer(version)
            if ret is None or ret[1] is None or ret[1] == [] or ret[1] == [None, None]:
                message = "[!] Error: Trailer not found"
                self.log_output("info " + argv, message)
                return False
            trailerArray = ret[1]
            if trailerArray[0] is not None:
                statsDict = trailerArray[0].getStats()
            if trailerArray[1] is not None:
                statsStream = trailerArray[1].getStats()
                for key in statsStream:
                    if not key in statsDict:
                        statsDict[key] = statsStream[key]
            if statsDict["Offset"] is not None:
                stats += f'{beforeStaticLabel}Offset: {self.resetColor}{statsDict["Offset"]}{newLine}'
            stats += f'{beforeStaticLabel}Size: {self.resetColor}{statsDict["Size"]}{newLine}'
            if statsDict["Stream"] is not None:
                stats += f'{beforeStaticLabel}Stream: {self.resetColor}{statsDict["Stream"]}{newLine}'
            else:
                stats += f"{beforeStaticLabel}Stream: {self.resetColor}No {newLine}"
            stats += f'{beforeStaticLabel}Objects: {statsDict["Objects"]}{newLine}'
            if statsDict["Root Object"] is not None:
                stats += f'{beforeStaticLabel}Root Object: {self.resetColor}{statsDict["Root Object"]}{newLine}'
            else:
                stats += (
                    f"{beforeStaticLabel}Root Object: {self.resetColor}No {newLine}"
                )
            if statsDict["Info Object"] is not None:
                stats += f'{beforeStaticLabel}Info Object: {self.resetColor}{statsDict["Info Object"]}{newLine}'
            else:
                stats += (
                    f"{beforeStaticLabel}Info Object: {self.resetColor}No {newLine}"
                )
            if statsDict["ID"] is not None:
                stats += f'{beforeStaticLabel}ID: {self.resetColor}{statsDict["ID"]}{newLine}'
            if statsDict["Encrypted"]:
                stats += f"{beforeStaticLabel}Encrypted: {self.resetColor}Yes {newLine}"
            else:
                stats += f"{beforeStaticLabel}Encrypted: {self.resetColor}No {newLine}"
            if statsDict["Errors"] is not None:
                stats += f'{beforeStaticLabel}Errors: {self.resetColor}{statsDict["Errors"]}{newLine}'
        else:
            thisId = int(thisId)
            indirectObject = self.pdfFile.getObject(thisId, version, indirect=True)
            if indirectObject is None:
                message = "[!] Error: Object not found"
                self.log_output("info " + argv, message)
                return False
            statsDict = indirectObject.getStats()
            if statsDict["Offset"] is not None:
                stats += f'{beforeStaticLabel}Offset: {self.resetColor}{statsDict["Offset"]}{newLine}'
            stats += (
                f'{beforeStaticLabel}Size: {self.resetColor}{statsDict["Size"]}{newLine}'
                f'{beforeStaticLabel}MD5: {self.resetColor}{statsDict["MD5"]}{newLine}'
                f'{beforeStaticLabel}Object: {self.resetColor}{statsDict["Object"]}{newLine}'
            )
            if statsDict["Object"] in {"dictionary", "stream"}:
                if statsDict["Type"] is not None:
                    stats += f'{beforeStaticLabel}Type: {self.resetColor}{statsDict["Type"]}{newLine}'
                if statsDict["Subtype"] is not None:
                    stats += f'{beforeStaticLabel}Subtype: {self.resetColor}{statsDict["Subtype"]}{newLine}'
                if statsDict["Object"] == "stream":
                    stats += f'{beforeStaticLabel}Stream MD5: {self.resetColor}{statsDict["Stream MD5"]}{newLine}'
                    if statsDict["Stream MD5"] != statsDict["Raw Stream MD5"]:
                        stats += (
                            f"{beforeStaticLabel}Raw Stream MD5: {self.resetColor}"
                            f'{statsDict["Raw Stream MD5"]}{newLine}'
                        )
                    stats += f'{beforeStaticLabel}Length: {self.resetColor}{statsDict["Length"]}{newLine}'
                    if statsDict["Real Length"] is not None:
                        stats += (
                            f"{beforeStaticLabel}Real length: {self.resetColor}"
                            f'{statsDict["Real Length"]}{newLine}'
                        )
                    if statsDict["Encoded"]:
                        stats += f"{beforeStaticLabel}Encoded: {self.resetColor}Yes {newLine}"
                        if statsDict["Stream File"] is not None:
                            stats += (
                                f"{beforeStaticLabel}Stream File: {self.resetColor}"
                                f'{statsDict["Stream File"]}{newLine}'
                            )
                        stats += f'{beforeStaticLabel}Filters: {self.resetColor}{statsDict["Filters"]}{newLine}'
                        if statsDict["Filter Parameters"]:
                            stats += f"{beforeStaticLabel}Filter Parameters: {self.resetColor}Yes {newLine}"
                        else:
                            stats += f"{beforeStaticLabel}Filter Parameters: {self.resetColor}No {newLine}"
                        if statsDict["Decoding Errors"]:
                            stats += f"{beforeStaticLabel}Decoding errors: {self.resetColor}Yes {newLine}"
                        else:
                            stats += f"{beforeStaticLabel}Decoding errors: {self.resetColor}No {newLine}"
                    else:
                        stats += (
                            f"{beforeStaticLabel}Encoded: {self.resetColor}No {newLine}"
                        )
            if statsDict["Object"] != "stream":
                if statsDict["Compressed in"] is not None:
                    stats += (
                        f"{beforeStaticLabel}Compressed in: {self.resetColor}"
                        f'{statsDict["Compressed in"]}{newLine}'
                    )
            if statsDict["Object"] == "dictionary":
                if statsDict["Action type"] is not None:
                    stats += f'{beforeStaticLabel}Action type: {self.resetColor}{statsDict["Action type"]}{newLine}'
            stats += f'{beforeStaticLabel}References: {self.resetColor}{statsDict["References"]}{newLine}'
            if statsDict["JSCode"]:
                stats += f"{beforeStaticLabel}JSCode: {self.resetColor}Yes {newLine}"
                if statsDict["Escaped Bytes"]:
                    stats += f"{beforeStaticLabel}Escaped bytes: {self.resetColor}Yes {newLine}"
                if statsDict["URLs"]:
                    stats += f"{beforeStaticLabel}URLs: {self.resetColor}Yes {newLine}"
            if statsDict["Errors"]:
                if statsDict["Object"] == "stream":
                    stats += f'{beforeStaticLabel}Parsing Errors: {self.resetColor}{statsDict["Errors"]}{newLine}'
                else:
                    stats += f'{beforeStaticLabel}Errors: {self.resetColor}{statsDict["Errors"]}{newLine}'
        self.log_output("info " + argv, stats)

    def help_info(self):
        print(f"{newLine}Usage: info [$object_id|xref|trailer [$version]]")
        print(
            f"Shows information of the file or object ($object_id, xref, trailer) {newLine}"
        )

    def do_js_analyse(self, argv):
        content = ""
        validTypes = ["variable", "file", "object", "string"]
        if not JS_MODULE:
            message = "[!] Error: STPyV8 is not installed"
            self.log_output("js_analyse " + argv, message)
            return False
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("js_analyse " + argv, message)
            return False
        if len(args) == 2:
            version = None
        elif len(args) == 3 and args[0] == "object":
            version = args[2]
        else:
            self.help_js_analyse()
            return False
        srcType = args[0]
        src = args[1]
        if srcType not in validTypes:
            self.help_js_analyse()
            return False
        if srcType == "variable":
            if not src in self.variables:
                message = "[!] Error: The variable does not exist"
                self.log_output("js_analyse " + argv, message)
                return False
            content = self.variables[src][0]
            if not isJavascript(content):
                if self.use_rawinput:
                    res = input(
                        "The variable may not contain Javascript code, do you want to continue? (y/n) "
                    )
                    if res.lower() == "n":
                        message = (
                            "[!] Error: The variable does not contain Javascript code"
                        )
                        self.log_output("js_analyse " + argv, message)
                        return False
                print(
                    f"[!] Warning: The object may not contain Javascript code... {newLine}"
                )
        elif srcType == "file":
            if not os.path.exists(src):
                message = "[!] Error: The file does not exist"
                self.log_output("js_analyse " + argv, message)
                return False
            with open(src, "rb") as srcFile:
                content = srcFile.read()
            if not isJavascript(content):
                if self.use_rawinput:
                    res = input(
                        "The file may not contain Javascript code, do you want to continue? (y/n) "
                    )
                    if res.lower() == "n":
                        message = "[!] Error: The file does not contain Javascript code"
                        self.log_output("js_analyse " + argv, message)
                        return False
                else:
                    print(
                        f"[!] Warning: The object may not contain Javascript code... {newLine}"
                    )
        elif srcType == "object":
            if self.pdfFile is None:
                message = "[!] Error: You must open a file"
                self.log_output("js_analyse " + argv, message)
                return False
            if not src.isdigit() or (version is not None and not version.isdigit()):
                self.help_js_analyse()
                return False
            src = int(src)
            if version is not None:
                version = int(version)
                if version > self.pdfFile.getNumUpdates():
                    message = "[!] Error: The version number is not valid"
                    self.log_output("js_analyse " + argv, message)
                    return False
            obj = self.pdfFile.getObject(src, version)
            if obj is not None:
                if obj.containsJS():
                    content = obj.getJSCode()[0]
                else:
                    if self.use_rawinput:
                        res = input(
                            "The object may not contain Javascript code, do you want to continue? (y/n) "
                        )
                        if res.lower() == "n":
                            message = (
                                "[!] Error: The object does not contain Javascript code"
                            )
                            self.log_output("js_analyse " + argv, message)
                            return False
                    else:
                        print(
                            f"[!] Warning: The object may not contain Javascript code... {newLine}"
                        )
                    objectType = obj.getType()
                    if objectType == "stream":
                        content = obj.getStream()
                    elif objectType in {"dictionary", "array"}:
                        element = obj.getElementByName("/JS")
                        if element:
                            content = element.getValue()
                        else:
                            message = "[!] Error: Target JS not found"
                            self.log_output("js_analyse " + argv, message)
                            return False
                    elif objectType in {"string", "hexstring"}:
                        content = obj.getValue()
                    else:
                        message = "[!] Error: Target not found"
                        self.log_output("js_analyse " + argv, message)
                        return False
            else:
                message = "[!] Error: Object not found"
                self.log_output("js_analyse " + argv, message)
                return False
        else:
            content = src
        content = content.strip()
        (
            jsCode,
            unescapedBytes,
            urlsFound,
            jsErrors,
            self.javaScriptContexts["global"],
        ) = analyseJS(content, self.javaScriptContexts["global"])
        if content not in jsCode:
            jsCode = [content] + jsCode
        jsanalyseOutput = ""
        if jsCode != []:
            jsanalyseOutput += f"{newLine}Javascript code: {newLine}"
            for js in jsCode:
                if js == jsCode[0]:
                    jsanalyseOutput += f'{newLine}{"=" * 20} Original Javascript code {"=" * 20}{newLine * 2}'
                else:
                    jsanalyseOutput += f'{newLine}{"=" * 18} Next stage of Javascript code {"=" * 18}{newLine * 2}'
                jsanalyseOutput += f'{js}{newLine * 2}{"=" * 66}{newLine}'
        if unescapedBytes:
            jsanalyseOutput += f"{newLine * 2}Unescaped bytes: {newLine * 2}"
            for byteVal in unescapedBytes:
                jsanalyseOutput += f"{self.printBytes(byteVal)}{newLine * 2}"
        if urlsFound:
            jsanalyseOutput += f"{newLine * 2}URLs in shellcode: {newLine * 2}"
            for url in urlsFound:
                jsanalyseOutput += f"\t{url}{newLine}"
        if jsErrors:
            jsanalyseOutput += newLine * 2
            for jsError in jsErrors:
                jsanalyseOutput += f"[!] Error analysing Javascript: {jsError}{newLine}"

        self.log_output("js_analyse " + argv, jsanalyseOutput, unescapedBytes)

    def help_js_analyse(self):
        print(f"{newLine}Usage: js_analyse variable $var_name")
        print("Usage: js_analyse file $file_name")
        print("Usage: js_analyse object $object_id [$version]")
        print("Usage: js_analyse string $javascript_code")
        print(
            f"{newLine}Analyses the Javascript code stored in the specified string, variable, file or object {newLine}"
        )

    def do_js_beautify(self, argv):
        content = ""
        validTypes = ["variable", "file", "object", "string"]
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("js_beautify " + argv, message)
            return False
        if len(args) == 2:
            version = None
        elif len(args) == 3 and args[0] == "object":
            version = args[2]
        else:
            self.help_js_beautify()
            return False
        srcType = args[0]
        src = args[1]
        if srcType not in validTypes:
            self.help_js_beautify()
            return False
        if srcType == "variable":
            if not src in self.variables:
                message = "[!] Error: The variable does not exist"
                self.log_output("js_beautify " + argv, message)
                return False
            content = self.variables[src][0]
            if not isJavascript(content):
                if self.use_rawinput:
                    res = input(
                        "The variable may not contain Javascript code, do you want to continue? (y/n) "
                    )
                    if res.lower() == "n":
                        message = (
                            "[!] Error: The variable does not contain Javascript code"
                        )
                        self.log_output("js_beautify " + argv, message)
                        return False
                else:
                    print(
                        f"[!] Warning: the object may not contain Javascript code... {newLine}"
                    )
        elif srcType == "file":
            if not os.path.exists(src):
                message = "[!] Error: The file does not exist"
                self.log_output("js_beautify " + argv, message)
                return False
            with open(src, "rb") as srcFile:
                content = srcFile.read()
            if not isJavascript(content):
                if self.use_rawinput:
                    res = input(
                        "The file may not contain Javascript code, do you want to continue? (y/n) "
                    )
                    if res.lower() == "n":
                        message = "[!] Error: The file does not contain Javascript code"
                        self.log_output("js_beautify " + argv, message)
                        return False
                else:
                    print(
                        f"[!] Warning: the object may not contain Javascript code... {newLine}"
                    )
        elif srcType == "string":
            content = src
        else:
            if self.pdfFile is None:
                message = "[!] Error: You must open a file"
                self.log_output("js_beautify " + argv, message)
                return False
            if not src.isdigit() or (version is not None and not version.isdigit()):
                self.help_js_beautify()
                return False
            src = int(src)
            if version is not None:
                version = int(version)
                if version > self.pdfFile.getNumUpdates():
                    message = "[!] Error: The version number is not valid"
                    self.log_output("js_beautify " + argv, message)
                    return False
            obj = self.pdfFile.getObject(src, version)
            if obj is not None:
                if obj.containsJS():
                    content = obj.getJSCode()[0]
                else:
                    if self.use_rawinput:
                        res = input(
                            "The object may not contain Javascript code, do you want to continue? (y/n) "
                        )
                        if res.lower() == "n":
                            message = (
                                "[!] Error: The object does not contain Javascript code"
                            )
                            self.log_output("js_beautify " + argv, message)
                            return False
                    else:
                        print(
                            f"[!] Warning: the object may not contain Javascript code... {newLine}"
                        )
                    objectType = obj.getType()
                    if objectType == "stream":
                        content = obj.getStream()
                    elif srcType in {"dictionary", "array"}:
                        element = obj.getElementByName("/JS")
                        if element is not None:
                            content = element.getValue()
                        else:
                            message = "[!] Error: Target not found"
                            self.log_output("js_beautify " + argv, message)
                            return False
                    elif srcType in {"string", "hexstring"}:
                        content = obj.getValue()
                    else:
                        message = "[!] Error: Target not found"
                        self.log_output("js_beautify " + argv, message)
                        return False
            else:
                message = "[!] Error: Object not found"
                self.log_output("js_beautify " + argv, message)
                return False

        beautyContent = jsbeautifier.beautify(content)
        self.log_output("js_beautify " + argv, beautyContent)

    def help_js_beautify(self):
        print(f"{newLine}Usage: js_beautify variable $var_name")
        print("Usage: js_beautify file $file_name")
        print("Usage: js_beautify object $object_id [$version]")
        print("Usage: js_beautify string $javascript_code [$version]")
        print(
            f"{newLine}Beautifies the Javascript code stored in the specified variable, file or object {newLine}"
        )

    def do_js_code(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("js_code " + argv, message)
            return False
        consoleOutput = ""
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("js_code " + argv, message)
            return False
        if len(args) == 1:
            version = None
        elif len(args) == 2:
            version = args[1]
        else:
            self.help_js_code()
            return False
        thisId = args[0]
        if not thisId.isdigit() or (version is not None and not version.isdigit()):
            self.help_js_code()
            return False
        thisId = int(thisId)
        if version is not None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = "[!] Error: The version number is not valid"
                self.log_output("js_code " + argv, message)
                return False
        obj = self.pdfFile.getObject(thisId, version)
        if obj is None:
            message = "[!] Error: Object not found"
            self.log_output("js_code " + argv, message)
            return False
        if obj.containsJS():
            jsCode = obj.getJSCode()
            if len(jsCode) > 1:
                if self.use_rawinput:
                    res = input(
                        f"{newLine}There are more than one Javascript code, do you want to see all (1) or just the last one (2)? "
                    )
                else:
                    res = "1"
                if res == "1":
                    for js in jsCode:
                        if js == jsCode[0]:
                            consoleOutput += f'{newLine}{"=" * 20} Original Javascript code {"=" * 20}{newLine}'
                        else:
                            consoleOutput += f'{newLine}{"=" * 18} Next stage of Javascript code {"=" * 18} {newLine}'
                        consoleOutput += f'{js}{newLine}{"=" * 66}{newLine}'
                else:
                    js = jsCode[-1]
                    consoleOutput += f"{newLine}{js}{newLine}"
            elif len(jsCode) == 1:
                consoleOutput += f"{newLine}{jsCode[0]}{newLine}"
            self.log_output("js_code " + argv, consoleOutput)
        else:
            message = "[!] Error: Javascript code not found in this object"
            self.log_output("js_code " + argv, message)

    def help_js_code(self):
        print(f"{newLine}Usage: js_code $object_id [$version]")
        print(f"{newLine}Shows the Javascript code found in the object {newLine}")

    def do_js_eval(self, argv):
        error = ""
        content = ""
        if not JS_MODULE:
            message = "[!] Error: STPyV8 is not installed"
            self.log_output("js_eval " + argv, message)
            return False
        validTypes = ["variable", "file", "object", "string"]
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("js_eval " + argv, message)
            return False
        if len(args) == 2:
            version = None
        elif len(args) == 3 and args[0] == "object":
            version = args[2]
        else:
            self.help_js_eval()
            return False
        srcType = args[0]
        src = args[1]
        if srcType not in validTypes:
            self.help_js_eval()
            return False
        if srcType == "variable":
            if not src in self.variables:
                message = "[!] Error: The variable does not exist"
                self.log_output("js_eval " + argv, message)
                return False
            content = self.variables[src][0]
            if not isJavascript(content):
                if self.use_rawinput:
                    res = input(
                        "The variable may not contain Javascript code, do you want to continue? (y/n) "
                    )
                    if res.lower() == "n":
                        message = (
                            "[!] Error: The variable does not contain Javascript code"
                        )
                        self.log_output("js_eval " + argv, message)
                        return False
                else:
                    print(
                        f"[!] Warning: the object may not contain Javascript code... {newLine}"
                    )
        elif srcType == "file":
            if not os.path.exists(src):
                message = "[!] Error: The file does not exist"
                self.log_output("js_eval " + argv, message)
                return False
            with open(src, "rb") as srcFile:
                content = srcFile.read()
            if not isJavascript(content):
                if self.use_rawinput:
                    res = input(
                        "The file may not contain Javascript code, do you want to continue? (y/n) "
                    )
                    if res.lower() == "n":
                        message = "[!] Error: The file does not contain Javascript code"
                        self.log_output("js_eval " + argv, message)
                        return False
                else:
                    print(
                        f"[!] Warning: the object may not contain Javascript code... {newLine}"
                    )
        elif srcType == "object":
            if self.pdfFile is None:
                message = "[!] Error: You must open a file"
                self.log_output("js_eval " + argv, message)
                return False
            if not src.isdigit() or (version is not None and not version.isdigit()):
                self.help_js_eval()
                return False
            src = int(src)
            if version is not None:
                version = int(version)
                if version > self.pdfFile.getNumUpdates():
                    message = "[!] Error: The version number is not valid"
                    self.log_output("js_eval " + argv, message)
                    return False
            obj = self.pdfFile.getObject(src, version)
            if obj is not None:
                if obj.containsJS():
                    content = obj.getJSCode()[0]
                else:
                    if self.use_rawinput:
                        res = input(
                            "The object may not contain Javascript code, do you want to continue? (y/n) "
                        )
                        if res.lower() == "n":
                            message = (
                                "[!] Error: The object does not contain Javascript code"
                            )
                            self.log_output("js_eval " + argv, message)
                            return False
                    else:
                        print(
                            f"[!] Warning: the object may not contain Javascript code... {newLine}"
                        )
                    objectType = obj.getType()
                    if objectType == "stream":
                        content = obj.getStream()
                    elif srcType in {"dictionary", "array"}:
                        element = obj.getElementByName("/JS")
                        if element is not None:
                            content = element.getValue()
                        else:
                            message = "[!] Error: Target not found"
                            self.log_output("js_eval " + argv, message)
                            return False
                    elif srcType in {"string", "hexstring"}:
                        content = obj.getValue()
                    else:
                        message = "[!] Error: Target not found"
                        self.log_output("js_eval " + argv, message)
                        return False
            else:
                message = "[!] Error: Object not found"
                self.log_output("js_eval " + argv, message)
                return False
        else:
            content = src
        if self.javaScriptContexts["global"] is not None:
            context = self.javaScriptContexts["global"]
        else:
            # Using the global context to hook the eval fucntion and other definitions
            context = STPyV8.JSContext(Global())
            self.javaScriptContexts["global"] = context
        context.enter()
        # Hooking the eval function
        context.eval("eval=evalOverride")
        try:
            context.eval(content)
            evalCode = context.eval("evalCode")
            evalCode = jsbeautifier.beautify(evalCode)
            if evalCode == "":
                self.log_output(
                    "js_eval " + argv,
                    "The Javascript code has been evaluated successfully",
                )
            else:
                self.log_output("js_eval " + argv, evalCode)
        except:
            error = str(sys.exc_info()[1])
            errorFile = f"jserror-{dt.now().strftime(DTFMT)}.log"
            with open(errorFile, "ab") as errorOut:
                errorOut.write(f"{error}{newLine}")

        if error != "":
            self.log_output("js_eval " + argv, "[!] Error: " + error)

    def help_js_eval(self):
        print(f"{newLine}Usage: js_eval variable $var_name")
        print("Usage: js_eval file $file_name")
        print("Usage: js_eval object $object_id [$version]")
        print("Usage: js_eval string $javascript_code")
        print(
            f"{newLine}Evaluates the Javascript code stored in the specified variable, file, object or raw code in a global context {newLine}"
        )

    def do_js_jjdecode(self, argv):
        content = ""
        validTypes = ["variable", "file", "object", "string"]
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("js_jjdecode " + argv, message)
            return False
        if len(args) == 2:
            version = None
        elif len(args) == 3 and args[0] == "object":
            version = args[2]
        else:
            self.help_js_jjdecode()
            return False
        srcType = args[0]
        src = args[1]
        if srcType not in validTypes:
            self.help_js_jjdecode()
            return False
        if srcType == "variable":
            if not src in self.variables:
                message = "[!] Error: The variable does not exist"
                self.log_output("js_jjdecode " + argv, message)
                return False
            content = self.variables[src][0]
            if not isJavascript(content):
                if self.use_rawinput:
                    res = input(
                        "The variable may not contain Javascript code, do you want to continue? (y/n) "
                    )
                    if res.lower() == "n":
                        message = (
                            "[!] Error: The variable does not contain Javascript code"
                        )
                        self.log_output("js_jjdecode " + argv, message)
                        return False
                else:
                    print(
                        f"[!] Warning: the object may not contain Javascript code... {newLine}"
                    )
        elif srcType == "file":
            if not os.path.exists(src):
                message = "[!] Error: The file does not exist"
                self.log_output("js_jjdecode " + argv, message)
                return False
            with open(src, "rb") as srcFile:
                content = srcFile.read()
            if not isJavascript(content):
                if self.use_rawinput:
                    res = input(
                        "The file may not contain Javascript code, do you want to continue? (y/n) "
                    )
                    if res.lower() == "n":
                        message = "[!] Error: The file does not contain Javascript code"
                        self.log_output("js_jjdecode " + argv, message)
                        return False
                else:
                    print(
                        f"[!] Warning: the object may not contain Javascript code... {newLine}"
                    )
        elif srcType == "string":
            content = src
        else:
            if self.pdfFile is None:
                message = "[!] Error: You must open a file"
                self.log_output("js_jjdecode " + argv, message)
                return False
            if not src.isdigit() or (version is not None and not version.isdigit()):
                self.help_js_jjdecode()
                return False
            src = int(src)
            if version is not None:
                version = int(version)
                if version > self.pdfFile.getNumUpdates():
                    message = "[!] Error: The version number is not valid"
                    self.log_output("js_jjdecode " + argv, message)
                    return False
            obj = self.pdfFile.getObject(src, version)
            if obj is not None:
                if obj.containsJS():
                    content = obj.getJSCode()
                    if content:
                        content = content[0]
                    else:
                        message = "[!] Error: JS code object is empty, may be caused by an error during JS analysis"
                        self.log_output("js_jjdecode " + argv, message)
                        return False
                else:
                    if self.use_rawinput:
                        res = input(
                            "The object may not contain Javascript code, do you want to continue? (y/n) "
                        )
                        if res.lower() == "n":
                            message = (
                                "[!] Error: The object does not contain Javascript code"
                            )
                            self.log_output("js_jjdecode " + argv, message)
                            return False
                    else:
                        print(
                            f"[!] Warning: the object may not contain Javascript code... {newLine}"
                        )
                    objectType = obj.getType()
                    if objectType == "stream":
                        content = obj.getStream()
                    elif srcType in {"dictionary", "array"}:
                        element = obj.getElementByName("/JS")
                        if element is not None:
                            content = element.getValue()
                        else:
                            message = "[!] Error: Target not found"
                            self.log_output("js_jjdecode " + argv, message)
                            return False
                    elif srcType in {"string", "hexstring"}:
                        content = obj.getValue()
                    else:
                        message = "[!] Error: Target not found"
                        self.log_output("js_jjdecode " + argv, message)
                        return False
            else:
                message = "[!] Error: Object not found"
                self.log_output("js_jjdecode " + argv, message)
                return False

        jjdecoder = JJDecoder(content)
        try:
            ret = jjdecoder.decode()
        except Exception as e:
            if len(e.args) == 2:
                excName, excReason = e.args
            else:
                excName = excReason = None
            if excName != "JJDecoderException":
                raise
            message = "[!] Error: " + excReason
            self.log_output("js_jjdecode " + argv, message)
            return False
        if ret[0] == 0:
            decodedContent = ret[1]
        else:
            message = "[!] Error: " + ret[1]
            self.log_output("js_jjdecode " + argv, message)
            return False
        self.log_output("js_jjdecode " + argv, decodedContent)

    def help_js_jjdecode(self):
        print(f"{newLine}Usage: js_jjdecode variable $var_name")
        print("Usage: js_jjdecode file $file_name")
        print("Usage: js_jjdecode object $object_id [$version]")
        print("Usage: js_jjdecode string $encoded_js_code [$version]")
        print(
            f"{newLine}Decodes the Javascript code stored in the specified variable, file or object using the jjencode/decode algorithm by Yosuke Hasegawa (http://utf-8.jp/public/jjencode.html) {newLine}"
        )

    def do_js_join(self, argv):
        content = ""
        finalString = ""
        reSeparatedStrings = "[\"'](.*?)[\"']"
        validTypes = ["variable", "file", "string"]
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("js_join " + argv, message)
            return False
        if len(args) != 2:
            self.help_js_join()
            return False
        srcType = args[0]
        src = args[1]
        if srcType not in validTypes:
            self.help_js_join()
            return False
        if srcType == "variable":
            if not src in self.variables:
                message = "[!] Error: The variable does not exist"
                self.log_output("js_join " + argv, message)
                return False
            content = self.variables[src][0]
        elif srcType == "file":
            if not os.path.exists(src):
                message = "[!] Error: The file does not exist"
                self.log_output("js_join " + argv, message)
                return False
            with open(src, "rb") as srcFile:
                content = srcFile.read()
        else:
            content = src
        strings = re.findall(reSeparatedStrings, content)
        if strings == []:
            message = (
                "[!] Error: The variable or file does not contain separated strings"
            )
            self.log_output("js_join " + argv, message)
            return False
        for string in strings:
            finalString += string
        self.log_output("js_join " + argv, finalString)

    def help_js_join(self):
        print(f"{newLine}Usage: js_join variable $var_name")
        print("Usage: js_join file $file_name")
        print("Usage: js_join string $my_string")
        print(
            f"{newLine}Joins some strings separated by quotes and stored in the specified variable or file in a unique one {newLine}"
        )
        print("Example: {newLine}")
        print(f'aux = "%u65"+"54"+"%u74"+"73" {newLine}')
        print(f"> js_join variable aux {newLine}")
        print(f"%u6554%u7473 {newLine}")

    def do_js_unescape(self, argv):
        content = ""
        unescapedOutput = ""
        byteVal = ""
        reUnicodeChars = "([%\]u[0-9a-f]{4})+"
        reHexChars = "(%[0-9a-f]{2})+"
        validTypes = ["variable", "file", "string"]
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("js_unescape " + argv, message)
            return False
        if len(args) != 2:
            self.help_js_unescape()
            return False
        srcType = args[0]
        src = args[1]
        if srcType not in validTypes:
            self.help_js_unescape()
            return False
        if srcType == "variable":
            if not src in self.variables:
                message = "[!] Error: The variable does not exist"
                self.log_output("js_unescape " + argv, message)
                return False
            content = self.variables[src][0]
        elif srcType == "file":
            if not os.path.exists(src):
                message = "[!] Error: The file does not exist"
                self.log_output("js_unescape " + argv, message)
                return False
            with open(src, "rb") as srcFile:
                content = srcFile.read()
        else:
            content = src
        if (
            re.findall(reUnicodeChars, content, re.IGNORECASE) == []
            and re.findall(reHexChars, content, re.IGNORECASE) == []
        ):
            message = "[!] Error: The file does not contain escaped chars"
            self.log_output("js_unescape " + argv, message)
            return False
        ret = unescape(content)
        if ret[0] != -1:
            unescapedBytes = ret[1]
            byteVal = ret[1]
            urlsFound = re.findall("https?://.*$", unescapedBytes, re.DOTALL)
            if unescapedBytes != "":
                unescapedOutput += f"{newLine}Unescaped bytes:{newLine * 2}{self.printBytes(unescapedBytes)}"
            if urlsFound != []:
                unescapedOutput += f"{newLine * 2}URLs in shellcode:{newLine}"
                for url in urlsFound:
                    unescapedOutput += f"\t{url}"
                unescapedOutput += f"{newLine}"
        else:
            message = f"[!] Error: {ret[1]}"
            self.log_output("js_unescape " + argv, message)
            return False
        self.log_output(
            "js_unescape " + argv, unescapedOutput, [byteVal], bytesOutput=True
        )

    def help_js_unescape(self):
        print(f"{newLine}Usage: js_unescape variable $var_name")
        print("Usage: js_unescape file $file_name")
        print("Usage: js_unescape string $escaped_string")
        print(
            f"{newLine}Unescapes the escaped characters stored in the specified variable or file {newLine}"
        )
        print(f"Example: {newLine}")
        print(f'aux = "%u6554%u7473" {newLine}')
        print(f"> js_unescape variable aux {newLine}")
        print(f"54 65 73 74                                       |Test| {newLine}")

    def do_js_vars(self, argv):
        varName = None
        if not JS_MODULE:
            message = "[!] Error: STPyV8 is not installed"
            self.log_output("js_vars " + argv, message)
            return False
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("js_vars " + argv, message)
            return False
        if len(args) > 1:
            self.help_js_vars()
            return False
        if self.javaScriptContexts["global"] is not None:
            context = self.javaScriptContexts["global"]
        else:
            self.log_output(
                "js_vars " + argv,
                '[!] Warning: There is no Javascript context defined. Use "js_eval" or "js_analyse" to create one.',
            )
            return False
        if len(args) == 1:
            varName = args[0]
            if varName in list(context.locals.keys()):
                varContent = context.locals[varName]
                try:
                    self.log_output("js_vars " + argv, str(varContent))
                except:
                    exceptionInfo = traceback.format_exc()
                    if (
                        exceptionInfo.find("Allocation failed - process out of memory")
                        != -1
                    ):
                        message = "[!] Error: The variable is too big to be processed"
                        self.log_output("js_vars " + argv, message)
                        return False
                    raise
            else:
                self.log_output(
                    "js_vars " + argv,
                    "[!] Error: The variable does not exist in the Javascript context.",
                )
        else:
            fixedVars = [
                "evalOverride",
                "hasOwnProperty",
                "isPrototypeOf",
                "toLocaleString",
                "toString",
                "unwatch",
                "valueOf",
                "watch",
            ]
            varArray = list(context.locals.keys())
            for fixedVar in fixedVars:
                varArray.remove(fixedVar)
            self.log_output("js_vars " + argv, str(varArray))

    def help_js_vars(self):
        print(f"{newLine}Usage: js_vars [$var_name]")
        print(
            f"Shows the Javascript variables defined in the execution context or the content of the specified variable {newLine}"
        )

    def do_json(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("json " + argv, message)
            return False
        jsonReport = ""
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("json " + argv, message)
            return False
        if len(args) == 0:
            statsDict = self.pdfFile.getStats()
            jsonReport = getPeepJSON(statsDict, VERSION)
        elif len(args) > 0:
            message = '[!] Error: The "json" command does not require any arguments'
            self.log_output("json " + argv, message)
            return False
        else:
            message = '[!] Error: The "json" command failed.'
            self.log_output("json " + argv, message)
            return False
        self.log_output("json " + argv, jsonReport)

    def help_json(self):
        print(f"{newLine}Usage: json")
        print("Shows the info for the currently loaded file in JSON format")

    def do_log(self, argv):
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("log " + argv, message)
            return False
        numArgs = len(args)
        if numArgs == 0:
            if self.loggingFile is None:
                print(f"{newLine}Not logging now {newLine}")
            else:
                print(f"{newLine}Log file: {self.loggingFile}{newLine}")
        elif numArgs == 1:
            param = args[0]
            if param == "stop":
                self.loggingFile = None
            else:
                self.loggingFile = param
        else:
            self.help_log()
            return False

    def help_log(self):
        print(f"{newLine}Usage: log")
        print(f"Shows the actual state of logging {newLine}")
        print("Usage: log stop")
        print(f"Stops logging {newLine}")
        print("Usage: log $log_file")
        print(f"Starts logging in the specified file {newLine}")

    def do_malformed_output(self, argv):
        malformedOptions = []
        headerFile = None
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("malformed_output " + argv, message)
            return False
        if not args:
            malformedOptions.append(1)
        else:
            for _, v in enumerate(args):
                opt = v
                if opt.isdigit():
                    opt = int(opt)
                    if -1 < opt < 7:
                        if opt == 0:
                            malformedOptions = []
                            headerFile = None
                            break
                        if opt not in malformedOptions and 1 not in malformedOptions:
                            malformedOptions.append(opt)
                    else:
                        self.help_malformed_output()
                        return False
                else:
                    if os.path.exists(opt):
                        headerFile = opt
                        break
                    self.help_malformed_output()
                    return False
        self.variables["malformed_options"] = [malformedOptions, malformedOptions]
        self.variables["header_file"] = [headerFile, headerFile]
        message = "Malformed options successfully enabled"
        self.log_output("malformed_output " + argv, message)

    def help_malformed_output(self):
        print(
            f"{newLine}Usage: malformed_output [$option1 [$option2 ...] [$header_file]] {newLine}"
        )
        print(f"Enables malformed output when saving the file: {newLine}")
        print("\t0: Removes all the malformed options.")
        print("\t1: [header_file]: Enable all the implemented tricks. Default option.")
        print(
            "\t2: [header_file]: Puts the default or specified header before the PDF header."
        )
        print('\t3: Removes all the "endobj" tags.')
        print('\t4: Removes all the "endstream" tags.')
        print('\t5: Removes the "xref" section.')
        print(f"\t6: Bad header: %PDF-1 {newLine}")

    def do_metadata(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("metadata " + argv, message)
            return False
        output = ""
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("metadata " + argv, message)
            return False
        if len(args) == 0:
            version = None
        elif len(args) == 1:
            version = args[0]
        else:
            self.help_metadata()
            return False
        if version is not None and not version.isdigit():
            self.help_metadata()
            return False
        if version is not None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = "[!] Error: The version number is not valid"
                self.log_output("metadata " + argv, message)
                return False
        metadataObjects = self.pdfFile.getMetadata(version)
        if metadataObjects not in ([], [[]]):
            if version is not None:
                metadataObjects = [metadataObjects]
            for k, v in enumerate(metadataObjects):
                objects = v
                if version is not None:
                    k = version
                infoObject = self.pdfFile.getInfoObject(k)
                if infoObject is not None:
                    value = infoObject.getValue()
                    output += f"Info Object in version {str(k)}: {newLine * 2}{value}{newLine * 2}"
                if objects:
                    for thisId in objects:
                        obj = self.pdfFile.getObject(thisId, k)
                        objectType = obj.getType()
                        if objectType in {"dictionary", "stream"}:
                            subType = obj.getElementByName("/Type")
                            if subType != []:
                                subType = subType.getValue()
                                if subType == "/Metadata":
                                    value = obj.getValue()
                                    if value != "":
                                        output += (
                                            f"Object {str(thisId)} in version {str(k)}:"
                                            f" {newLine * 2}{value}{newLine * 2}"
                                        )
            self.log_output("metadata " + argv, output)
        else:
            message = "[!] No metadata found"
            self.log_output("metadata " + argv, message)
            return False

    def help_metadata(self):
        print(f"{newLine}Usage: metadata [$version]")
        print(
            f"Shows the metadata of the document or version of the document {newLine}"
        )

    def do_modify(self, argv):
        ## TODO - maxDepth = 2 - Possibly re-introduce this later
        validModifyTypes = ["object", "stream"]
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("modify " + argv, message)
            return False
        numArgs = len(args)
        if numArgs < 2:
            self.help_modify()
            return False
        elementType = args[0]
        if elementType not in validModifyTypes:
            self.help_modify()
            return False
        # Checking arguments
        thisId = args[1]
        contentFile = None
        if numArgs == 2:
            version = None
        elif numArgs == 3:
            if not os.path.exists(args[2]):
                version = args[2]
            else:
                version = None
                contentFile = args[2]
        elif numArgs == 4:
            version = args[2]
            contentFile = args[3]
            if not os.path.exists(contentFile):
                message = f'[!] Error: The file "{contentFile}" does not exist'
                self.log_output("modify " + argv, message)
                return False
        else:
            self.help_modify()
            return False
        if (not thisId.isdigit() and thisId != "trailer" and thisId != "xref") or (
            version is not None and not version.isdigit()
        ):
            self.help_modify()
            return False
        if version is not None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = "[!] Error: The version number is not valid"
                self.log_output("modify " + argv, message)
                return False
        thisId = int(thisId)
        obj = self.pdfFile.getObject(thisId, version)
        if obj is None:
            message = "[!] Error: Object not found"
            self.log_output("modify " + argv, message)
            return False
        objectType = obj.getType()
        if elementType == "object":
            ret = self.modifyObject(obj, 0, contentFile)
            if ret[0] == -1:
                message = "[!] Error: The object has not been modified"
                self.log_output("modify " + argv, message)
                return False
            obj = ret[1]
        elif elementType == "stream":
            if objectType != "stream":
                message = "[!] Error: The specified object is not an stream object"
                self.log_output("modify " + argv, message)
                return False
            if contentFile is not None:
                with open(contentFile, "rb") as streamOut:
                    streamContent = streamOut.read()
            else:
                if self.use_rawinput:
                    streamContent = input(
                        f"{newLine}Please, specify the stream content"
                        f"(if the content includes EOL characters use a file instead): "
                        f"{newLine * 2}"
                    )
                else:
                    message = "[!] Error: In script mode you must specify a file storing the stream content"
                    self.log_output("modify " + argv, message)
                    return False
            obj.setDecodedStream(streamContent)
        ret = self.pdfFile.setObject(thisId, obj, version, mod=True)
        if ret[0] == -1:
            message = "[!] Error: The object has not been modified"
        else:
            message = "[+] Object modified successfully"
        self.log_output("modify " + argv, message)

    def help_modify(self):
        print(f"{newLine}Usage: modify object|stream $object_id [$version] [$file]")
        print(
            f"Modifies the object or stream specified. It is possible to use a file to retrieve the stream content (ONLY for stream content).{newLine}"
        )

    def do_object(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("object " + argv, message)
            return False
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("object " + argv, message)
            return False
        if len(args) == 1:
            version = None
        elif len(args) == 2:
            version = args[1]
        else:
            self.help_object()
            return False
        thisId = args[0]
        if not thisId.isdigit() or (version is not None and not version.isdigit()):
            self.help_object()
            return False
        thisId = int(thisId)
        if version is not None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = "[!] Error: The version number is not valid"
                self.log_output("object " + argv, message)
                return False
        obj = self.pdfFile.getObject(thisId, version)
        if obj is None:
            message = "[!] Error: Object not found"
            self.log_output("object " + argv, message)
            return False
        value = obj.getValue()
        valueLength = len(value)
        if valueLength > 10000 and self.use_rawinput:
            res = input(
                f"The object is {valueLength} bytes in size. Are you sure you want to display it? (y/n) "
            )
            if res.lower() != "y":
                return
            self.log_output("object " + argv, value)
        else:
            self.log_output("object " + argv, value)

    def help_object(self):
        print(f"{newLine}Usage: object $object_id [$version]")
        print(
            f"Shows the content of the object after being decoded and decrypted.{newLine}"
        )

    def do_objects(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("objects " + argv, message)
            return False
        stats = ""
        args = self.parseArgs(argv)
        if not self.avoidOutputColors:
            beforeStaticLabel = self.staticColor
        else:
            beforeStaticLabel = ""
        statsDict = self.pdfFile.getStats()
        if len(args) == 0:
            for version in range(len(statsDict["Versions"])):
                statsVersion = statsDict["Versions"][version]
                stats += f"{beforeStaticLabel}Version {self.resetColor}{str(version)}: "
                stats += (
                    f'{beforeStaticLabel}Objects ({statsVersion["Objects"][0]}): '
                    f'{self.resetColor}{str(statsVersion["Objects"][1])}{newLine}'
                )
        elif len(args) == 1:
            version = int(args[0])
            if version in range(len(statsDict["Versions"])):
                statsVersion = statsDict["Versions"][version]
                stats += f"{beforeStaticLabel}Version {self.resetColor}{str(version)}: "
                stats += (
                    f'{beforeStaticLabel}Objects ({statsVersion["Objects"][0]}): '
                    f'{self.resetColor}{str(statsVersion["Objects"][1])}{newLine}'
                )
            else:
                message = f"[!] Version {version} does not exist."
                self.log_output("objects " + argv, message)
                return False
        else:
            message = '[!] Error: The "objects" command requires 0 or 1 argument'
            self.log_output("objects " + argv, message)
            return False
        self.log_output("objects " + argv, stats)

    def help_objects(self):
        print(f"{newLine}Usage: objects [version]")
        print(f"Shows all available objects or objects by version.{newLine}")

    def do_ocr(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("ocr " + argv, message)
            return False
        fileName = self.pdfFile.path
        args = self.parseArgs(argv)
        pdfText = PDFParser.getText(self, fileName)
        if pdfText is None:
            message = "[!] Error: No textual content found"
            self.log_output("ocr " + fileName, message)
            return False
        if args != [] and len(args) == 1:
            with open(args[0], "w", encoding="latin-1") as outputFile:
                outputFile.write(pdfText)
                outputFile.close()
            message = f"[+] The content has been written to {outputFile.name}."
            self.log_output("ocr" + argv, message)
        elif len(args) > 1:
            message = (
                "[!] Error: ocr only takes one argument, or none for output to stdout"
            )
            self.log_output("ocr " + argv, message)
            return False
        else:
            self.log_output("ocr " + fileName, pdfText)

    def help_ocr(self):
        print(f"{newLine}Usage: ocr [$output_filename]")
        print(f"Extract text from the PDF, optional output to file. {newLine}")

    def do_offsets(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("offsets " + argv, message)
            return False
        version = None
        offsetsOutput = ""
        offsetsArray = []
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("offsets " + argv, message)
            return False
        numArgs = len(args)
        if numArgs == 0:
            offsetsArray = self.pdfFile.getOffsets()
        elif numArgs == 1:
            version = args[0]
            if not version.isdigit():
                self.help_offsets()
                return False
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = "[!] Error: The version number is not valid"
                self.log_output("offsets " + argv, message)
                return False
            offsetsArray = self.pdfFile.getOffsets(version)
        else:
            self.help_offsets()
            return False

        if version is not None:
            print(f"\rVersion {version}:")
        print(f"{newLine}Start (d)\tEnd (d)\t\tSize (d)\tType and Id\r")
        print(f'{"-" * 9}\t{"-" * 9}\t{"-" * 9}\t{"-" * 20}\r')
        for k, v in enumerate(offsetsArray):
            offsets = v
            if k == 0 and "header" in offsets:
                offset, size = offsets["header"]
                offsetsOutput += f"{offset:08d}\t\t\t\t\tHeader{newLine}"
            elif version is None:
                offsetsOutput += f"{newLine}Version {str(k)}: {newLine * 2}"
            if "objects" in offsets:
                compressedObjects = offsets["compressed"]
                sortedObjectList = sorted(offsets["objects"], key=lambda x: x[1])
                for thisId, offset, size in sortedObjectList:
                    if thisId in compressedObjects:
                        offsetsOutput += (
                            f"{offset:08d}\t{((offset + size) - 1):08d}\t{size:08d}\t"
                            f"Compressed Object {thisId} {newLine}"
                        )
                    else:
                        offsetsOutput += (
                            f"{offset:08d}\t{((offset + size) - 1):08d}\t{size:08d}\t"
                            f"Object {thisId} {newLine}"
                        )
            if offsets["xref"] is not None:
                offset, size = offsets["xref"]
                offsetsOutput += (
                    f"{offset:08d}\t{((offset + size) -1):08d}\t{size:08d}\t"
                    f"XrefSection {newLine}"
                )
            if offsets["trailer"] is not None:
                offset, size = offsets["trailer"]
                offsetsOutput += (
                    f"{offset:08d}\t{((offset + size) - 1):08d}\t{size:08d}\t"
                    f"Trailer {newLine}"
                )
            if offsets["eof"] is not None:
                offset, size = offsets["eof"]
                offsetsOutput += f"{offset:08d}\t\t\t\t\tEOF{newLine}"
        self.log_output("offsets " + argv, offsetsOutput)

    def help_offsets(self):
        print(f"{newLine}Usage: offsets [$version]")
        print(
            f"Shows the physical map of the file or the specified version of the document {newLine}"
        )

    def do_open(self, argv):
        forceMode = False
        looseMode = False

        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("open " + argv, message)
            return False
        numArgs = len(args)
        if numArgs == 1:
            fileName = args[0]
        elif numArgs == 2:
            fileName = args[1]
            args = args[0]
            if (
                len(args) < 2
                or len(args) > 3
                or args[0] != "-"
                or args[1:] not in ["f", "l", "fl", "lf"]
            ):
                self.help_open()
                return False
            if args.find("f") != -1:
                forceMode = True
            if args.find("l") != -1:
                looseMode = True
        else:
            self.help_open()
            return False
        if not os.path.exists(fileName):
            message = "[!] Error: The file does not exist"
            self.log_output("open " + argv, message)
            return False

        if self.pdfFile is not None:
            del self.pdfFile
        pdfParser = PDFParser()
        ret = pdfParser.parse(fileName, forceMode, looseMode)
        if ret != -1:
            message = "[+] File opened succesfully"
            self.pdfFile = ret[1]
        else:
            message = "[!] Error: Opening document failed"
            self.pdfFile = None
        self.log_output("open " + argv, message)
        if not JS_MODULE:
            print(f"Warning: STPyV8 is not installed {newLine}")
        if self.pdfFile is not None:
            self.do_info("")

    def help_open(self):
        print(f"{newLine}Usage: open [-fl] $file_name")
        print(f"Opens and parses the specified file {newLine}")
        print("Options:")
        print("\t-f: Sets force parsing mode to ignore errors")
        print(f"\t-l: Sets loose parsing mode for problematic files {newLine}")

    def do_quit(self, argv):
        return True

    def help_quit(self):
        print(f"{newLine}Usage: quit")
        print(f"Exits from the console {newLine}")

    def do_rawobject(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("rawobject " + argv, message)
            return False
        compressed = False
        rawValue = ""
        offset = 0
        size = 0
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("rawobject " + argv, message)
            return False
        if len(args) == 1:
            version = None
        elif len(args) == 2:
            version = args[1]
        else:
            self.help_rawobject()
            return False
        thisId = args[0]
        if (not thisId.isdigit() and thisId != "trailer" and thisId != "xref") or (
            version is not None and not version.isdigit()
        ):
            self.help_rawobject()
            return False
        if version is not None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = "[!] Error: The version number is not valid"
                self.log_output("rawobject " + argv, message)
                return False
        if thisId == "xref":
            ret = self.pdfFile.getXrefSection(version)
            if ret is None or ret[1] is None or ret[1] == [] or ret[1] == [None, None]:
                message = "[!] Error: xref section not found"
                self.log_output("rawobject " + argv, message)
                return False
            xrefArray = ret[1]
            if xrefArray[0] is not None:
                offset = xrefArray[0].getOffset()
                size = xrefArray[0].getSize()
                rawValue = xrefArray[0].toFile()
        elif thisId == "trailer":
            ret = self.pdfFile.getTrailer(version)
            if ret is None or ret[1] is None or ret[1] == [] or ret[1] == [None, None]:
                message = "[!] Error: Trailer not found"
                self.log_output("rawobject " + argv, message)
                return False
            trailerArray = ret[1]
            if trailerArray[0] is not None:
                offset = trailerArray[0].getOffset()
                size = trailerArray[0].getSize()
                rawValue = trailerArray[0].toFile()
        else:
            thisId = int(thisId)
            indirectObject = self.pdfFile.getObject(thisId, version, indirect=True)
            if indirectObject is None:
                message = "[!] Error: Object not found"
                self.log_output("rawobject " + argv, message)
                return False
            obj = indirectObject.getObject()
            compressed = obj.isCompressed()
            offset = indirectObject.getOffset()
            size = indirectObject.getSize()
            rawValue = str(obj.getRawValue())
        if offset == -1:
            message = "[!] Error: offset cannot be calculated"
            self.log_output("rawobject " + argv, message)
            return False
        filePath = self.pdfFile.getPath()
        if not compressed and filePath != "" and os.path.exists(filePath):
            ret = getBytesFromFile(filePath, offset, size)
            if ret[0] == -1:
                message = "[!] Error: The file does not exist"
                self.log_output("rawobject " + argv, message)
                return False
            rawValue = ret[1]
        self.log_output("rawobject " + argv, rawValue)

    def help_rawobject(self):
        print(f"{newLine}Usage: rawobject [$object_id|xref|trailer [$version]]")
        print(
            f"Shows the content of the object without being decoded or decrypted (object_id, xref, trailer){newLine}"
        )

    def do_rawstream(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("rawstream " + argv, message)
            return False
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("rawstream " + argv, message)
            return False
        if len(args) == 1:
            version = None
        elif len(args) == 2:
            version = args[1]
        else:
            self.help_rawstream()
            return False
        thisId = args[0]
        if not thisId.isdigit() or (version is not None and not version.isdigit()):
            self.help_rawstream()
            return False
        thisId = int(thisId)
        if version is not None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = "[!] Error: The version number is not valid"
                self.log_output("stream " + argv, message)
                return False
        obj = self.pdfFile.getObject(thisId, version)
        if obj is None:
            message = "[!] Error: Object not found"
            self.log_output("stream " + argv, message)
            return False
        if obj.getType() != "stream":
            message = "[!] Error: The object doesn't contain any stream"
            self.log_output("rawstream " + argv, message)
            return False
        value = obj.getRawStream()
        self.log_output("rawstream " + argv, value, [value], bytesOutput=True)

    def help_rawstream(self):
        print(f"{newLine}Usage: rawstream $object_id [$version]")
        print(
            f"Shows the stream content of the specified document version before being decoded and decrypted{newLine}"
        )

    def do_references(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("references " + argv, message)
            return False
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("references " + argv, message)
            return False
        if len(args) == 2:
            version = None
        elif len(args) == 3:
            version = args[2]
        else:
            self.help_references()
            return False
        command = args[0]
        thisId = args[1]
        if (
            not thisId.isdigit()
            or (version is not None and not version.isdigit())
            or (command.lower() != "to" and command.lower() != "in")
        ):
            self.help_references()
            return False
        thisId = int(thisId)
        if version is not None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = "[!] Error: The version number is not valid"
                self.log_output("references " + argv, message)
                return False
        if command.lower() == "to":
            references = self.pdfFile.getReferencesTo(thisId, version)
        else:
            references = self.pdfFile.getReferencesIn(thisId, version)
        if not references:
            references = "No references"
        elif references is None:
            references = "[!] Error: Object not found"
        self.log_output("references " + argv, str(references))

    def help_references(self):
        print(f"{newLine}Usage: references to|in $object_id [$version]")
        print(
            f"Shows the references in the object or to the object in the specified version of the document{newLine}"
        )

    def do_replace(self, argv):
        replaceOutput = ""
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("replace " + argv, message)
            return False
        numArgs = len(args)
        if numArgs not in (3, 4):
            self.help_replace()
            return False
        srcType = args[0]
        if numArgs == 3:
            if srcType != "all":
                self.help_replace()
                return False
            if self.pdfFile is None:
                message = "[!] Error: You must open a file"
                self.log_output("replace " + argv, message)
                return False
            string1 = args[1]
            string2 = args[2]
            ret = self.pdfFile.replace(string1, string2)
            if ret[0] == -1:
                if ret[1] == "String not found":
                    message = "String not found"
                else:
                    message = "[!] Error: The string has not been replaced"
            else:
                message = "[+] The string has been replaced correctly"
        elif numArgs == 4:
            if srcType not in ("variable", "file"):
                self.help_replace()
                return False
            src = args[1]
            string1 = args[2]
            string2 = args[3]
            if srcType == "file":
                if not os.path.exists(src):
                    message = "[!] Error: The file does not exist"
                    self.log_output("replace " + argv, message)
                    return False
                with open(src, "rb") as srcFile:
                    content = srcFile.read()
                if content.find(string1) != -1:
                    replaceOutput = content.replace(string1, string2)
                    try:
                        with open(src, "wb") as outSrc:
                            outSrc.write(replaceOutput)
                    except:
                        message = "[!] Error: The file cannot be modified"
                        self.log_output("replace " + argv, message)
                        return False
                    message = "[+] The string has been replaced correctly"
                else:
                    message = "String not found"
            else:
                if src in self.variables:
                    if self.variables[src][0].find(string1) != -1:
                        replaceOutput = self.variables[src][0].replace(string1, string2)
                        self.variables[src][0] = replaceOutput
                        message = "[+] The string has been replaced correctly"
                    else:
                        message = "String not found"
                else:
                    message = "[!] Error: The variable does not exist"
        self.log_output("replace " + argv, message)

    def help_replace(self):
        print(f"{newLine}Usage: replace all $string1 $string2")
        print(f"Replaces $string1 with $string2 in the whole PDF file {newLine}")
        print("Usage: replace variable $var_name $string1 $string2")
        print(
            f"Replaces $string1 with $string2 in the content of the specified variable{newLine}"
        )
        print("Usage: replace file $file_name $string1 $string2")
        print(
            f"Replaces $string1 with $string2 in the content of the specified file {newLine}"
        )

    def do_reset(self, argv):
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("reset " + argv, message)
            return False
        numArgs = len(args)
        if numArgs == 0:
            clearScreen()
        elif numArgs == 1:
            var = args[0]
            if var in self.variables:
                self.variables[var][0] = self.variables[var][1]
                if var == "output" and (
                    self.variables[var][0] == "file"
                    or self.variables[var][0] == "variable"
                ):
                    message = f'{var} = "{self.output}" ({str(self.variables[var][0])})'
                else:
                    varContent = self.printResult(str(self.variables[var][0]))
                    if varContent == str(self.variables[var][0]):
                        if varContent != "None" and not re.match("\[.*\]", varContent):
                            message = f'{var} = "{varContent}"'
                        else:
                            message = f"{var} = {varContent}"
                    else:
                        message = f"{var} = {newLine}{varContent}"
            else:
                message = "[!] Error: The variable does not exist"
            self.log_output("reset " + argv, message)
        else:
            self.help_reset()

    def help_reset(self):
        print(f"{newLine}Usage: reset")
        print(f"Cleans the console{newLine}")
        print("Usage: reset $var_name")
        print(f"Resets the variable value to the default value if applicable {newLine}")

    def do_save(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("save " + argv, message)
            return False
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("save " + argv, message)
            return False
        numArgs = len(args)
        if numArgs in {0, 1}:
            if numArgs == 0:
                fileName = self.pdfFile.getPath()
            else:
                fileName = args[0]
            ret = self.pdfFile.save(
                fileName,
                malformedOptions=self.variables["malformed_options"][0],
                headerFile=self.variables["header_file"][0],
            )
            if ret[0] == -1:
                message = "[!] Error: Saving failed"
            else:
                message = "[+] File saved succesfully"
            self.log_output("save " + argv, message)
        else:
            self.help_save()

    def help_save(self):
        print(f"{newLine}Usage: save [$file_name]")
        print(f"Saves the file to disk {newLine}")

    def do_save_version(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("save_version " + argv, message)
            return False
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("save_version " + argv, message)
            return False
        numArgs = len(args)
        if numArgs == 2:
            version = args[0]
            fileName = args[1]
            if not version.isdigit():
                self.help_save_version()
                return False
            version = int(version)
            if version < 0 or version > self.pdfFile.getNumUpdates():
                message = "[!] Error: The version number is not valid"
                self.log_output("save_version " + argv, message)
                return False
            currentFilePath = str(pathlib.Path(self.pdfFile.path).parent)
            ret = self.pdfFile.save(
                fileName,
                currentFilePath,
                version,
                malformedOptions=self.variables["malformed_options"][0],
                headerFile=self.variables["header_file"][0],
            )
            if ret[0] == -1:
                message = "[!] Error: Saving failed"
            else:
                message = "[+] Version saved succesfully"
            self.log_output("save_version " + argv, message)
        else:
            self.help_save_version()

    def help_save_version(self):
        print(f"{newLine}Usage: save_version $version $file_name")
        print(f"Saves the selected file version to disk {newLine}")

    def do_sctest(self, argv):
        if not EMU_MODULE:
            message = "[!] Error: pylibemu is not installed"
            self.log_output("sctest " + argv, message)
            return False
        outputBuffer = 2048
        maxSteps = 10000000
        verboseMode = False
        validTypes = ["variable", "file", "raw"]
        byteVal = ""
        src = ""
        offset = 0
        size = 0
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("sctest " + argv, message)
            return False
        if len(args) < 2 or len(args) > 4:
            self.help_sctest()
            return False
        if args[0] == "-v":
            verboseMode = True
            srcType = args[1]
            if len(args) == 2:
                self.help_sctest()
                return False
        else:
            srcType = args[0]
        if srcType not in validTypes:
            self.help_sctest()
            return False

        if srcType == "raw":
            if self.pdfFile is None:
                message = "[!] Error: You must open a file"
                self.log_output("sctest " + argv, message)
                return False
            if verboseMode:
                if len(args) != 4:
                    self.help_sctest()
                    return False
                offset = args[2]
                size = args[3]
            else:
                if len(args) != 3:
                    self.help_sctest()
                    return False
                offset = args[1]
                size = args[2]
            if not offset.isdigit() or not size.isdigit():
                message = (
                    "[!] Error: The offset and the number of bytes must be integers"
                )
                self.log_output("sctest " + argv, message)
                return False
            offset = int(offset)
            size = int(size)
        else:
            if verboseMode:
                if len(args) != 3:
                    self.help_sctest()
                    return False
                src = args[2]
            else:
                if len(args) != 2:
                    self.help_sctest()
                    return False
                src = args[1]

        if srcType == "variable":
            if src not in self.variables:
                message = "[!] Error: The variable does not exist"
                self.log_output("sctest " + argv, message)
                return False
            byteVal = self.variables[src][0]
        elif srcType == "file":
            if not os.path.exists(src):
                message = "[!] Error: The file does not exist"
                self.log_output("sctest " + argv, message)
                return False
            with open(src, "rb") as srcFile:
                byteVal = srcFile.read()
        else:
            ret = getBytesFromFile(self.pdfFile.getPath(), offset, size)
            if ret[0] == -1:
                message = "[!] Error: The file does not exist"
                self.log_output("sctest " + argv, message)
                return False
            byteVal = ret[1]

        if verboseMode:
            emu = pylibemu.Emulator()
        else:
            emu = pylibemu.Emulator(outputBuffer)
        try:
            shellcodeOffset = emu.shellcode_getpc_test(byteVal)
            shellcodeOffset = max(shellcodeOffset, 0)
            emu.prepare(byteVal, shellcodeOffset)
            emu.test(maxSteps)
        except:
            message = "[!] Error: Shellcode emulation failed"
            self.log_output("sctest " + argv, message)
            return False
        if emu.emu_profile_output:
            output = emu.emu_profile_output
        else:
            output = ""
        self.log_output("sctest " + argv, output)

    def help_sctest(self):
        print(f"{newLine}Usage: sctest [-v] variable $var_name")
        print("Usage: sctest [-v] file $file_name")
        print(f"Usage: sctest [-v] raw $offset $num_bytes{newLine}")
        print(
            f"Wrapper of the sctest tool (libemu) to emulate shellcodes. -v = verbose, there may be a lot of data{newLine}"
        )

    def do_search(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("search " + argv, message)
            return False
        output = ""
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("search " + argv, message)
            return False
        if len(args) != 1 and len(args) != 2:
            self.help_search()
            return False
        if len(args) == 1:
            toSearch = args[0]
        elif len(args) == 2:
            if args[0] != "hex":
                self.help_search()
                return False
            toSearch = args[1]
            if re.match("(\\\\x[0-9a-f]{1,2})+", toSearch):
                hexChars = toSearch.split("\\x")
                hexChars.remove("")
                toSearch = ""
                for hexChar in hexChars:
                    if len(hexChar) == 1:
                        hexChar = "0" + hexChar
                    toSearch += hexChar
                ret = hexToString(toSearch)
                if ret[0] == -1:
                    message = f"[!] Error: {ret[1]}"
                    self.log_output("search " + argv, message)
                    return False
                toSearch = ret[1]
            else:
                message = "[!] Error: Bad hexadecimal string"
                self.log_output("search " + argv, message)
                return False
        toSearch = escapeRegExpString(toSearch)
        objects = self.pdfFile.getObjectsByString(toSearch)
        if objects == []:
            output = "Not found"
        else:
            if len(objects) == 1:
                if objects[0] == []:
                    output = "Not found"
                else:
                    output = str(objects[0])
            else:
                for version, result in enumerate(objects):
                    if result:
                        output += (
                            f"{newLine}Version {str(version)}: {str(result)}{newLine}"
                        )
                if output == "":
                    output = "Not found"
                else:
                    output = output[1:-1]
        self.log_output("search " + argv, output)

    def help_search(self):
        print(f"{newLine}Usage: search [hex] $search_term")
        print(
            f"Search the specified string or hexadecimal value in objects (decoded and encrypted streams included){newLine}"
        )
        print(f"Example: search hex \\x34\\x35 {newLine}")

    def do_set(self, argv):
        consoleOutput = ""
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("set " + argv, message)
            return False
        numArgs = len(args)
        if numArgs not in (0, 2):
            self.help_set()
            return False
        if numArgs == 0:
            allVars = list(self.variables.keys())
            for var in allVars:
                varContent = self.printResult(str(self.variables[var][0]))
                if varContent == str(self.variables[var][0]):
                    if (
                        varContent != "None"
                        and not re.match("\[.*\]", varContent)
                        and not varContent.isdigit()
                    ):
                        consoleOutput += f'{var} = "{varContent}" {newLine}'
                    else:
                        consoleOutput += f"{var} = {str(varContent)} {newLine}"
                else:
                    consoleOutput += f"{var} =  {newLine}{varContent}{newLine}"
            print(f"{newLine}{consoleOutput}")
        else:
            varName = args[0]
            value = args[1]
            if varName in self.readOnlyVariables:
                message = "[!] Error: This is a READ ONLY variable"
                self.log_output("set " + argv, message)
                return False
            if varName == "output_limit":
                if not value.isdigit():
                    message = (
                        "[!] Error: The value for this variable must be an integer"
                    )
                    self.log_output("set " + argv, message)
                    return False
                value = int(value)
            if varName in self.variables:
                self.variables[varName][0] = value
            else:
                self.variables[varName] = [value, value]

    def help_set(self):
        print(f"{newLine}Usage: set [$var_name $var_value]")
        print(
            f"Sets the specified variable value or creates one with this value. Without parameters all the variables are shown. {newLine}"
        )
        print(f"Special variables: {newLine}")
        print(
            '\theader_file:\t\tREAD ONLY. Specifies the file header to be used when "malformed_options" are active.'
        )
        print(
            "\tmalformed_options:\tREAD ONLY. Variable to store the malformed options used to save the file."
        )
        print(
            '\toutput:\t\t\tSpecifies where the output of a command will go. Options are "stdout", "file", and "variable". Default is "stdout".'
        )
        print(
            "\toutput_limit:\t\tvariable to specify the maximum number of lines to be shown at once when the output is long (no limit = -1). By default there is no limit."
        )
        print(f"\tvt_key:\t\t\tVirusTotal API key. {newLine}")

    def do_show(self, argv):
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("show " + argv, message)
            return False
        if len(args) != 1:
            self.help_show()
            return False
        var = args[0]
        if not var in self.variables:
            print(f"{newLine}[!] Error: The variable {var} does not exist.{newLine}")
            return False
        if var == "output":
            if self.variables[var][0] == "stdout":
                print(f'{newLine}output = "stdout" {newLine}')
            else:
                if self.variables[var][0] == "file":
                    print(f'{newLine}output = "file"')
                    print(f'fileName = "{self.output}" {newLine}')
                else:
                    print(f'{newLine}output = "variable"')
                    print(f'varName = "{self.output}" {newLine}')
        else:
            varContent = self.printResult(str(self.variables[var][0]))
            print(f"{newLine}{varContent}{newLine}")

    def help_show(self):
        print(f"{newLine}Usage: show $var_name")
        print(f"Shows the value of the specified variable {newLine}")
        print(f"Special variables: {newLine}")
        print("\theader_file\r")
        print("\tmalformed_options\r")
        print("\toutput\r")
        print("\toutput_limit\r")
        print(f"\tvt_key {newLine}")

    def do_stream(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("stream " + argv, message)
            return False
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("stream " + argv, message)
            return False
        if len(args) == 1:
            version = None
        elif len(args) == 2:
            version = args[1]
        else:
            self.help_stream()
            return False
        thisId = args[0]
        if not thisId.isdigit() or (version is not None and not version.isdigit()):
            self.help_stream()
            return False
        thisId = int(thisId)
        if version is not None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = "[!] Error: The version number is not valid"
                self.log_output("stream " + argv, message)
                return False
        obj = self.pdfFile.getObject(thisId, version)
        if obj is None:
            message = "[!] Error: Object not found"
            self.log_output("stream " + argv, message)
            return False
        if obj.getType() != "stream":
            message = "[!] Error: The object doesn't contain any stream"
            self.log_output("stream " + argv, message)
            return False
        value = obj.getStream()
        if value == -1:
            message = "[!] Error: The stream cannot be decoded"
            self.log_output("stream " + argv, message)
            return False
        self.log_output("stream " + argv, value, [value], bytesOutput=True)

    def help_stream(self):
        print(f"{newLine}Usage: stream $object_id [$version]")
        print(
            f"Shows the object stream content of the specified version after being decoded and decrypted (if necessary) {newLine}"
        )

    def do_streams(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("streams " + argv, message)
            return False
        stats = ""
        args = self.parseArgs(argv)
        if not self.avoidOutputColors:
            beforeStaticLabel = self.staticColor
        else:
            beforeStaticLabel = ""
        statsDict = self.pdfFile.getStats()
        if len(args) == 0:
            for version in range(len(statsDict["Versions"])):
                statsVersion = statsDict["Versions"][version]
                stats += f"{beforeStaticLabel}Version {self.resetColor}{str(version)}: "
                stats += (
                    f'{beforeStaticLabel}Streams ({statsVersion["Streams"][0]}): '
                    f'{self.resetColor}{str(statsVersion["Streams"][1])}{newLine}'
                )
        elif len(args) == 1:
            version = int(args[0])
            if version in range(len(statsDict["Versions"])):
                statsVersion = statsDict["Versions"][version]
                stats += f"{beforeStaticLabel}Version {self.resetColor}{str(version)}: "
                stats += (
                    f'{beforeStaticLabel}Streams ({statsVersion["Streams"][0]}): '
                    f'{self.resetColor}{str(statsVersion["Streams"][1])}{newLine}'
                )
            else:
                message = f"[!] Version {version} does not exist."
                self.log_output("streams " + argv, message)
                return False
        else:
            message = '[!] Error: The "streams" command requires 0 or 1 argument'
            self.log_output("streams " + argv, message)
            return False
        self.log_output("streams " + argv, stats)

    def help_streams(self):
        print(f"{newLine}Usage: streams")
        print(f"Shows all available streams.{newLine}")

    def do_tree(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("version " + argv, message)
            return False
        version = None
        treeOutput = ""
        tree = []
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("tree " + argv, message)
            return False
        numArgs = len(args)
        if numArgs == 0:
            tree = self.pdfFile.getTree()
        elif numArgs == 1:
            version = args[0]
            if version is not None and not version.isdigit():
                message = "[!] Error: The version number is not valid"
                self.log_output("tree " + argv, message)
                return False
            version = int(version)
            if version > self.pdfFile.getNumUpdates() or version < 0:
                message = "[!] Error: The version number is not valid"
                self.log_output("tree " + argv, message)
                return False
            tree = self.pdfFile.getTree(version)
        else:
            self.help_tree()
            return False
        for k, v in enumerate(tree):
            nodesPrinted = []
            root = v[0]
            objectsInfo = v[1]
            if k != 0:
                treeOutput += f"{newLine}Version {str(k)}: {newLine * 2}"
            if root is not None:
                nodesPrinted, nodeOutput = self.printTreeNode(
                    root, objectsInfo, nodesPrinted
                )
                treeOutput += nodeOutput
            for obj in objectsInfo:
                nodesPrinted, nodeOutput = self.printTreeNode(
                    obj, objectsInfo, nodesPrinted
                )
                treeOutput += nodeOutput
        self.log_output("tree " + argv, treeOutput)

    def help_tree(self):
        print(f"{newLine}Usage: tree [$version]")
        print(f"Shows the tree graph of the file or specified version {newLine}")

    def do_vtcheck(self, argv):
        content = ""
        srcName = ""
        thisId = ""
        validTypes = [
            "variable",
            "file",
            "raw",
            "object",
            "rawobject",
            "stream",
            "rawstream",
        ]
        # Checking if a VirusTotal API key has been defined
        if "yourAPIkey" in self.variables["vt_key"][0]:
            message = (
                f'[!] Error: The "vt_key" variable has not been set! You need to use your own VirusTotal API key. {newLine * 2}'
                f'Define the variable "vt_key": set vt_key "ENTER_YOUR_API_KEY"{newLine}'
            )
            self.log_output("vtcheck " + argv, message)
            return False
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("vtcheck " + argv, message)
            return False
        if args == []:
            if self.pdfFile is None:
                message = "[!] Error: You must open a file"
                self.log_output("vtcheck " + argv, message)
                return False
            md5Hash = self.pdfFile.getMD5()
        else:
            if len(args) == 2:
                if args[0] in {"object", "rawobject", "stream", "rawstream"}:
                    thisId = args[1]
                    version = None
                elif args[0] == "file" or args[0] == "variable":
                    srcName = args[1]
                else:
                    self.help_vtcheck()
                    return False
            elif len(args) == 3:
                if args[0] in {"object", "rawobject", "stream", "rawstream"}:
                    thisId = args[1]
                    version = args[2]
                elif args[0] == "raw":
                    offset = args[1]
                    size = args[2]
                else:
                    self.help_vtcheck()
                    return False
            else:
                self.help_vtcheck()
                return False

            srcType = args[0]
            if srcType not in validTypes:
                self.help_vtcheck()
                return False
            if srcType == "variable":
                if srcName not in self.variables:
                    message = "[!] Error: The variable does not exist"
                    self.log_output("vtcheck " + argv, message)
                    return False
                content = self.variables[srcName][0]
            elif srcType == "file":
                if not os.path.exists(srcName):
                    message = "[!] Error: The file does not exist"
                    self.log_output("vtcheck " + argv, message)
                    return False
                with open(srcName, "rb") as srcFile:
                    content = srcFile.read()
            else:
                if self.pdfFile is None:
                    message = "[!] Error: You must open a file"
                    self.log_output("vtcheck " + argv, message)
                    return False
                if srcType == "raw":
                    if not offset.isdigit() or not size.isdigit():
                        self.help_vtcheck()
                        return False
                    offset = int(offset)
                    size = int(size)
                    ret = getBytesFromFile(self.pdfFile.getPath(), offset, size)
                    if ret[0] == -1:
                        message = "[!] Error: The file does not exist"
                        self.log_output("vtcheck " + argv, message)
                        return False
                    content = ret[1]
                else:
                    if not thisId.isdigit() or (
                        version is not None and not version.isdigit()
                    ):
                        self.help_vtcheck()
                        return False
                    thisId = int(thisId)
                    if version is not None:
                        version = int(version)
                        if version > self.pdfFile.getNumUpdates():
                            message = "[!] Error: The version number is not valid"
                            self.log_output("vtcheck " + argv, message)
                            return False
                    obj = self.pdfFile.getObject(thisId, version)
                    if obj is None:
                        message = "[!] Error: Object not found"
                        self.log_output("vtcheck " + argv, message)
                        return False
                    if srcType in {"stream", "rawstream"}:
                        if obj.getType() != "stream":
                            message = "[!] Error: The object doesn't contain any stream"
                            self.log_output("vtcheck " + argv, message)
                            return False
                        if srcType == "stream":
                            content = obj.getStream()
                        else:
                            content = obj.getRawStream()
                    elif srcType == "object":
                        content = obj.getValue()
                    else:
                        content = obj.getRawValue()
            content = str(content)
            md5Hash = hashlib.md5(content.encode()).hexdigest()
        # Checks the MD5 on VirusTotal
        ret = vtcheck(md5Hash, self.variables["vt_key"][0])
        if ret[0] == -1:

            message = f"[!] Error: {ret[1]} on VirusTotal"
            self.log_output("vtcheck " + argv, message)
            return False
        jsonDict = ret[1]
        maliciousCount = jsonDict["data"]["attributes"]["last_analysis_stats"][
            "malicious"
        ]
        totalCount = 0
        for result in ("harmless", "suspicious", "malicious", "undetected"):
            totalCount += jsonDict["data"]["attributes"]["last_analysis_stats"][result]
        if (
            "last_analysis_date" in jsonDict["data"]["attributes"]
            and "last_analysis_results" in jsonDict["data"]["attributes"]
            and "links" in jsonDict["data"]
        ):
            unixEpoch = jsonDict["data"]["attributes"]["last_analysis_date"]
            scanResults = jsonDict["data"]["attributes"]["last_analysis_results"]
            selfLink = f'https://www.virustotal.com/gui/file/{jsonDict["data"]["attributes"]["sha256"]}'
            lastAnalysisDate = dt.utcfromtimestamp(unixEpoch).strftime(DTFMT)
            detectionColor = ""
            if args == []:
                self.pdfFile.setDetectionRate([maliciousCount, totalCount])
                self.pdfFile.setDetectionReport(selfLink)
            if not self.avoidOutputColors:
                detectionLevel = maliciousCount / (totalCount / 3)
                if detectionLevel == 0:
                    detectionColor = self.alertColor
                elif detectionLevel >= 1:
                    detectionColor = self.warningColor
            output = (
                f"{self.staticColor}Detection rate: {self.resetColor}{detectionColor}"
                f"{maliciousCount}{self.resetColor}/{totalCount}{newLine}"
                f"{self.staticColor}Last analysis date: {self.resetColor}"
                f"{lastAnalysisDate}{newLine}"
                f"{self.staticColor}Report link: {self.resetColor}"
                f"{selfLink}{newLine}"
            )
            if maliciousCount > 0:

                if len(jsonDict["data"]["attributes"]["names"]) > 0:
                    output += f"{self.staticColor}Names: {self.resetColor}{', '.join(jsonDict['data']['attributes']['names'])}{newLine}"
                output += (
                    f"{self.staticColor}Scan results: {self.resetColor}{newLine * 2}"
                )
                scan_list = []
                scan_list.append(
                    [
                        f"{self.staticColor}Engine{self.resetColor}",
                        f"{self.staticColor}Engine Version{self.resetColor}",
                        f"{self.staticColor}Engine Update{self.resetColor}",
                        f"{self.staticColor}Result{self.resetColor}",
                    ]
                )

                for engine in scanResults:
                    engineResults = scanResults[engine]
                    if (
                        "malicious" in engineResults["category"]
                        and "engine_version" in engineResults
                        and "result" in engineResults
                        and "engine_update" in engineResults
                    ):
                        scan_list.append(
                            [
                                engine,
                                f'{self.resetColor}{engineResults["engine_version"]}',
                                engineResults["engine_update"],
                                f'{self.alertColor}{engineResults["result"]}{self.resetColor}',
                            ]
                        )
                table = PrettyTable(scan_list[0])
                table.set_style(SINGLE_BORDER)
                table.align = "l"
                table.sortby = f"{self.staticColor}Engine{self.resetColor}"
                if len(scan_list) > 1:
                    table.add_rows(scan_list[1:])
                output += str(table)
            elif maliciousCount == 0:
                output += (
                    f"{self.staticColor}Scan results: {self.resetColor}{newLine * 2}"
                )
                output += f"{self.staticColor}No malicious detection for {md5Hash}{self.resetColor}."
            else:
                message = "[!] Error: Missing elements in the response from VirusTotal"
                self.log_output("vtcheck " + argv, message)
                return False
        elif args == []:
            self.pdfFile.setDetectionRate(None)
            output = "File not found on VirusTotal!"
        else:
            message = "[!] Error: Bad response from VirusTotal"
            self.log_output("vtcheck " + argv, message)
            return False
        self.log_output("vtcheck " + argv, output)

    def help_vtcheck(self):
        print(f"{newLine}Usage: vtcheck")
        print("Usage: vtcheck object|rawobject|stream|rawstream $object_id [$version]")
        print("Usage: vtcheck raw $offset $num_bytes")
        print("Usage: vtcheck file $file_name")
        print(f"Usage: vtcheck variable $var_name{newLine}")
        print(
            "Checks the hash of the specified source on VirusTotal: raw bytes of the file, objects and streams, and the content of files or variables."
        )
        print(
            f"If no parameters are specified then the hash of the PDF document will be checked.{newLine}"
        )
        print("[*] NOTE: NO CONTENT IS SENT TO VIRUSTOTAL, JUST THE MD5!")
        print("[*] NOTE: You need a VirusTotal API key to use this command.")
        print(
            f'[*] Set your vt_key in the interactive console by using: "set vt_key YOUR_API_KEY".{newLine}'
        )

    def do_xml(self, argv):
        if self.pdfFile is None:
            message = "[!] Error: You must open a file"
            self.log_output("xml " + argv, message)
            return False
        xmlReport = ""
        args = self.parseArgs(argv)
        if args is None:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("xml " + argv, message)
            return False
        if len(args) == 0:
            statsDict = self.pdfFile.getStats()
            xmlReport = getPeepXML(statsDict, VERSION)
            xmlReport = xmlReport.decode("latin-1")
        elif len(args) > 0:
            message = '[!] Error: The "xml" command does not require any arguments'
            self.log_output("xml " + argv, message)
            return False
        else:
            message = '[!] Error: The "xml" command failed.'
            self.log_output("xml " + argv, message)
            return False
        self.log_output("xml " + argv, xmlReport)

    def help_xml(self):
        print(f"{newLine}Usage: xml")
        print("Shows the info for the currently loaded file in XML format")

    def do_xor(self, argv):
        content = ""
        srcName = ""
        thisId = ""
        validTypes = ["variable", "file", "raw", "stream", "rawstream"]
        args = self.parseArgs(argv)
        if not args:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("xor " + argv, message)
            self.help_xor()
            return False
        srcType = args[0]
        if len(args) == 2:
            if srcType in {"stream", "rawstream"}:
                thisId = args[1]
                version = None
            elif srcType in {"file", "variable"}:
                srcName = args[1]
            else:
                self.help_xor()
                return False
            key = None
        elif len(args) == 3:
            if srcType in {"stream", "rawstream"}:
                thisId = args[1]
                if args[2].find("0x") != -1 or args[2].find("\\x") != -1:
                    version = None
                    key = args[2]
                else:
                    version = args[2]
                    key = None
            elif srcType in {"file", "variable"}:
                srcName = args[1]
                key = args[2]
            elif srcType == "raw":
                offset = args[1]
                size = args[2]
                key = None
            else:
                self.help_xor()
                return False
        elif len(args) == 4:
            if srcType in {"stream", "rawstream"}:
                thisId = args[1]
                version = args[2]
            elif srcType == "raw":
                offset = args[1]
                size = args[2]
            else:
                self.help_xor()
                return False
            key = args[3]
        else:
            self.help_xor()
            return False

        if srcType not in validTypes:
            self.help_xor()
            return False
        if key is not None:
            key = key.replace("0x", "")
            key = key.replace("\\x", "")
            match = re.match("[0-9a-f]{1,2}", key)
            if not match or match.group() != key:
                message = (
                    "[!] Error: The key must be an hexadecimal digit (0x5,0xa1,0x2f...)"
                )
                self.log_output("xor " + argv, message)
                return False
            key = chr(int(key, 16))
        if srcType == "variable":
            if srcName not in self.variables:
                message = "[!] Error: The variable does not exist"
                self.log_output("xor " + argv, message)
                return False
            content = self.variables[srcName][0]
        elif srcType == "file":
            if not os.path.exists(srcName):
                message = "[!] Error: The file does not exist"
                self.log_output("xor " + argv, message)
                return False
            with open(srcName, "rb") as srcFile:
                content = srcFile.read()
        else:
            if self.pdfFile is None:
                message = "[!] Error: You must open a file"
                self.log_output("xor " + argv, message)
                return False
            if srcType == "raw":
                if not offset.isdigit() or not size.isdigit():
                    self.help_xor()
                    return False
                offset = int(offset)
                size = int(size)
                ret = getBytesFromFile(self.pdfFile.getPath(), offset, size)
                if ret[0] == -1:
                    message = "[!] Error: The file does not exist"
                    self.log_output("xor " + argv, message)
                    return False
                content = ret[1]
            else:
                if not thisId.isdigit() or (
                    version is not None and not version.isdigit()
                ):
                    self.help_xor()
                    return False
                thisId = int(thisId)
                if version is not None:
                    version = int(version)
                    if version > self.pdfFile.getNumUpdates():
                        message = "[!] Error: The version number is not valid"
                        self.log_output("xor " + argv, message)
                        return False
                obj = self.pdfFile.getObject(thisId, version)
                if obj is None:
                    message = "[!] Error: Object not found"
                    self.log_output("xor " + argv, message)
                    return False
                if obj.getType() != "stream":
                    message = "[!] Error: The object doesn't contain any stream"
                    self.log_output("xor " + argv, message)
                    return False
                if srcType == "stream":
                    content = obj.getStream()
                else:
                    content = obj.getRawStream()

        content = str(content)
        if content == "":
            message = "[!] Warning: The content is empty"
            self.log_output("xor " + argv, message)
            return False
        if key is not None:
            output = xor(content, key)
        else:
            output = ""
            for i in range(256):
                key = chr(i)
                xored = xor(content, key)
                output += f"[{hex(i)}] {newLine}{xored}{newLine}[/{hex(i)}] {newLine}"
        self.log_output("xor " + argv, output, [output], bytesOutput=True)

    def help_xor(self):
        print(f"{newLine}Usage: xor stream|rawstream $object_id [$version] [$key]")
        print("Usage: xor raw $offset $num_bytes $key")
        print("Usage: xor file $file_name $key")
        print("Usage: xor variable $var_name $key")
        print(
            f"{newLine}Performs an XOR operation using the specified key with the content of the specified file or variable, raw bytes of the file or stream/rawstream."
        )
        print(
            f"If the key is not specified then a bruteforcing XOR is performed.{newLine}"
        )

    def do_xor_search(self, argv):
        content = ""
        srcName = ""
        thisId = ""
        found = False
        decValues = range(256)
        successfullKeys = {}
        caseSensitive = True
        validTypes = ["variable", "file", "raw", "stream", "rawstream"]
        args = self.parseArgs(argv)
        if not args:
            message = "[!] Error: The command line arguments have not been parsed successfully"
            self.log_output("xor_search " + argv, message)
            self.help_xor_search()
            return False
        srcType = args[0]
        if len(args) > 0 and srcType == "-i":
            caseSensitive = False
            args = args[1:]
        if len(args) == 3:
            if srcType in {"stream", "rawstream"}:
                thisId = args[1]
                version = None
            elif srcType in {"file", "variable"}:
                srcName = args[1]
            else:
                self.help_xor_search()
                return False
            string = args[2]
        elif len(args) == 4:
            if srcType in {"stream", "rawstream"}:
                thisId = args[1]
                version = args[2]
            elif srcType == "raw":
                offset = args[1]
                size = args[2]
            else:
                self.help_xor_search()
                return False
            string = args[3]
        else:
            self.help_xor_search()
            return False

        if srcType not in validTypes:
            self.help_xor_search()
            return False
        if srcType == "variable":
            if srcName not in self.variables:
                message = "[!] Error: The variable does not exist"
                self.log_output("xor_search " + argv, message)
                return False
            content = self.variables[srcName][0]
        elif srcType == "file":
            if not os.path.exists(srcName):
                message = "[!] Error: The file does not exist"
                self.log_output("xor_search " + argv, message)
                return False
            with open(srcName, "rb") as srcFile:
                content = srcFile.read()
        else:
            if self.pdfFile is None:
                message = "[!] Error: You must open a file"
                self.log_output("xor_search " + argv, message)
                return False
            if srcType == "raw":
                if not offset.isdigit() or not size.isdigit():
                    self.help_xor_search()
                    return False
                offset = int(offset)
                size = int(size)
                ret = getBytesFromFile(self.pdfFile.getPath(), offset, size)
                if ret[0] == -1:
                    message = "[!] Error: The file does not exist"
                    self.log_output("xor_search " + argv, message)
                    return False
                content = ret[1]
            else:
                if not thisId.isdigit() or (
                    version is not None and not version.isdigit()
                ):
                    self.help_xor_search()
                    return False
                thisId = int(thisId)
                if version is not None:
                    version = int(version)
                    if version > self.pdfFile.getNumUpdates():
                        message = "[!] Error: The version number is not valid"
                        self.log_output("xor_search " + argv, message)
                        return False
                obj = self.pdfFile.getObject(thisId, version)
                if obj is None:
                    message = "[!] Error: Object not found"
                    self.log_output("xor_search " + argv, message)
                    return False
                if obj.getType() != "stream":
                    message = "[!] Error: The object doesn't contain any stream"
                    self.log_output("xor_search " + argv, message)
                    return False
                if srcType == "stream":
                    content = obj.getStream()
                else:
                    content = obj.getRawStream()

        content = str(content)
        if string == "":
            message = "[!] Error: The string cannot be empty"
            self.log_output("xor_search " + argv, message)
            return False
        if content == "":
            message = "[!] Warning: The content is empty"
            self.log_output("xor_search " + argv, message)
            return False
        for i in decValues:
            key = chr(i)
            xored = xor(content, key)
            if caseSensitive:
                matches = re.findall(string, xored)
            else:
                matches = re.findall(string, xored, re.IGNORECASE)
            if matches != []:
                found = True
                auxXored = str(xored)
                offsets = []
                offset = 0
                for m in matches:
                    index = auxXored.find(m)
                    offset += index
                    offsets.append(offset)
                    offset += len(m)
                    auxXored = auxXored[index + len(m) :]
                successfullKeys[hex(i)] = offsets
        if found:
            keys = list(successfullKeys.keys())
            message = f"Pattern found with the following keys: {str(keys)}{newLine * 2}"
            for key in keys:
                message += f'Offsets for key "{str(key)}": {str(successfullKeys[key])}{newLine}'
        else:
            message = "[!] Pattern not found"
        self.log_output("xor_search " + argv, message)

    def help_xor_search(self):
        print(
            f"{newLine}Usage: xor_search [-i] stream|rawstream $object_id [$version] $string_to_search"
        )
        print("Usage: xor_search [-i] raw $offset $num_bytes $string_to_search")
        print("Usage: xor_search [-i] file $file_name $string_to_search")
        print("Usage: xor_search [-i] variable $var_name $string_to_search")
        print(
            f"{newLine}Searches for the specified string in the result of an XOR brute forcing operation with the content of the specified file or variable, "
        )
        print(
            "raw bytes of the file or stream/rawstream. The output shows the offset(s) where the string is found."
        )
        print(
            f"The search is case sensitive, use -i to make it case insensitive.{newLine}"
        )

    def additionRequest(self, isDict: bool = False):
        """
        Method to ask the user if they want to add more entries to the object or not

        @param isDict: Boolean to specify if the added object is a dictionary or not. Default value: False.
        @return: The response chosen by the user
        """
        if not isDict:
            message = f"{newLine}Do you want to add more objects? (y/n) "
        else:
            message = f"{newLine}Do you want to add more entries? (y/n) "
        res = input(message)
        if res.lower() in {"y", "n"}:
            return res.lower()
        return None

    def addObject(self, iteration: int, maxDepth: int = 10):
        """
        Method to add a new object to an array or dictionary

        @param iteration: Integer which specifies the depth of the recursion in the same object
        @param maxDepth: The maximum depth for nested objects. Default value: 10.
        @return: The new object
        """
        dictNumType = {
            "1": "boolean",
            "2": "number",
            "3": "string",
            "4": "hexstring",
            "5": "name",
            "6": "reference",
            "7": "null",
            "8": "array",
            "9": "dictionary",
        }
        if iteration > maxDepth:
            return (-1, "Object too nested")
        message = (
            f"What type of object do you want to include? (1-9) {newLine}"
            f"\t1 - boolean {newLine}"
            f"\t2 - number {newLine}"
            f"\t3 - string {newLine}"
            f"\t4 - hexstring {newLine}"
            f"\t5 - name {newLine}"
            f"\t6 - reference {newLine}"
            f"\t7 - null {newLine}"
            f"\t8 - array {newLine}"
            f"\t9 - dictionary {newLine}"
        )
        res = input(message)
        if not res.isdigit() or int(res) < 1 or int(res) > 9:
            return (-1, "Object type not valid")
        objectType = dictNumType[res]
        if objectType not in ("array", "dictionary"):
            content = input(
                f"{newLine}Please, specify the {objectType} object content: {newLine * 2}"
            )
            content = self.checkInputContent(objectType, content)
            if content is None:
                return (-1, "[!] Error: Content not valid for the object type")
        if objectType == "boolean":
            obj = PDFBool(content)
        elif objectType == "number":
            obj = PDFNum(content)
        elif objectType == "string":
            obj = PDFString(content)
        elif objectType == "hexstring":
            obj = PDFHexString(content)
        elif objectType == "name":
            obj = PDFName(content)
        elif objectType == "reference":
            contentElements = content.split()
            thisId = contentElements[0]
            genNum = contentElements[1]
            obj = PDFReference(thisId, genNum)
        elif objectType == "null":
            obj = PDFNull(content)
        elif objectType == "array":
            elements = []
            print("Please, now specify the elements of the array:")
            while True:
                res = self.additionRequest()
                if res is None:
                    return (-1, "Option not valid")
                if res == "y":
                    ret = self.addObject(iteration + 1)
                    if ret[0] == -1:
                        return ret
                    elements.append(ret[1])
                else:
                    break
            obj = PDFArray(elements=elements)
        elif objectType == "dictionary":
            elements = {}
            print("Please, now specify the elements of the dictionary:")
            while True:
                res = self.additionRequest(isDict=True)
                if res is None:
                    return (-1, "Option not valid")
                if res == "y":
                    key = input("Name object: ")
                    key = self.checkInputContent("name", key)
                    ret = self.addObject(iteration + 1)
                    if ret[0] == -1:
                        return ret
                    elements[key] = ret[1]
                else:
                    break
            obj = PDFDictionary(elements=elements)
        return (0, obj)

    def checkInputContent(self, objectType: str, objectContent):
        """
        Check if the specified content is valid for the specified object type and modify it if possible

        @param objectType: The type of object: number, string, hexstring, name, reference, null
        @param objectContent: The object content
        @return: The content of the object or None if any problems occur
        """
        if objectType == "bool":
            if objectContent.lower() not in ["true", "false"]:
                return None
            objectContent = objectContent.lower()
        elif objectType == "number":
            try:
                if objectContent.find(".") != -1:
                    float(objectContent)
                else:
                    int(objectContent)
            except:
                return None
        elif objectType == "string":
            octalNumbers = re.findall("\\\\(\d{1,3})", objectContent, re.DOTALL)
            for octal in octalNumbers:
                try:
                    chr(int(octal, 8))
                except:
                    return None
        elif objectType == "hexstring":
            objectContent = objectContent.replace("<", "")
            objectContent = objectContent.replace(">", "")
            for i in range(0, len(objectContent), 2):
                try:
                    chr(int(objectContent[i : i + 2], 16))
                except:
                    return None
        elif objectType == "name":
            if objectContent[0] == "/":
                objectContent = objectContent[1:]
            for char in objectContent:
                if char in spacesChars + delimiterChars:
                    return None
            hexNumbers = re.findall(
                "#([0-9a-f]{2})", objectContent, re.DOTALL | re.IGNORECASE
            )
            for hexNumber in hexNumbers:
                try:
                    chr(int(hexNumber, 16))
                except:
                    return None
            objectContent = "/" + objectContent
        elif objectType == "reference":
            if not re.match("\d{1,10}\s\d{1,10}\sR", objectContent, re.IGNORECASE):
                return None
            objectContent = objectContent.replace("r", "R")
        elif objectType == "null":
            if objectContent.lower() != "null":
                return None
            objectContent = objectContent.lower()
        return objectContent

    def log_output(
        self,
        command: str,
        output,
        bytesToSave=None,
        printOutput: bool = True,
        bytesOutput: bool = False,
    ):
        """
        Method to check the commands output and write it to the console and/or files / variables

        @param command: The command launched
        @param output: The output of the command
        @param bytesToSave: A list with the raw bytes which will be stored in a file or variable if a redirection has been set (>,>>,$>,$>>).
        @param printOutput: Boolean to specify if the output will be written to the console or not. Default value: True.
        @param bytesOutput: Boolean to specify if we want to print raw bytes or not. Default value: False.
        """
        if isinstance(output, bytes):
            output = output.decode("latin-1")
        errorIndex = output.find("[!] Error")
        if errorIndex != -1:
            output = (
                output[:errorIndex]
                + self.errorColor
                + output[errorIndex:]
                + self.resetColor
            )
        if bytesOutput and output != "":
            niceOutput = self.printResult(output)
        else:
            niceOutput = output
        niceOutput = niceOutput.strip(newLine)
        niceOutput = niceOutput.replace("\r\n", "\n")
        niceOutput = niceOutput.replace("\r", "\n")
        longOutput = f"{command}{newLine * 2}{niceOutput}{newLine * 2}"
        if self.loggingFile is not None:
            if isinstance(longOutput, str):
                longOutput = longOutput.encode()
            with open(self.loggingFile, "ab") as logFile:
                logFile.write("PPDF> " + longOutput)
        if self.redirect:
            if bytesToSave is None:
                bytesToSave = [niceOutput]
            for k, v in enumerate(bytesToSave):
                byteVal = v
                if (
                    self.redirect in (FILE_WRITE, FILE_ADD)
                ) and self.outputFileName is not None:
                    if k == 0:
                        outFile = str(self.outputFileName)
                    else:
                        outFile = f"{str(self.outputFileName)}_{k}"
                    if self.redirect == FILE_WRITE:
                        if isinstance(byteVal, str):
                            byteVal = byteVal.encode()
                        with open(outFile, "wb") as outputContent:
                            outputContent.write(byteVal)
                        print(f"[+] Content has been written to file {outFile}")
                    elif self.redirect == FILE_ADD:
                        if isinstance(byteVal, str):
                            byteVal = byteVal.encode()
                        with open(outFile, "ab") as outputContent:
                            outputContent.write(byteVal)
                        print(f"[+] Content has been appended to file {outFile}")
                elif (
                    self.redirect in (VAR_WRITE, VAR_ADD)
                ) and self.outputVarName is not None:
                    if k == 0:
                        varName = self.outputVarName
                    else:
                        varName = f"{self.outputVarName}_{k}"
                    if self.redirect == VAR_WRITE:
                        self.variables[varName] = [byteVal, byteVal]
                        print(f"[+] Content has been written to varaible {varName}")
                    elif self.redirect == VAR_ADD:
                        if varName in self.variables:
                            self.variables[varName][0] += byteVal
                            print(
                                f"[+] Content has been appended to varaible {varName}"
                            )
                        else:
                            self.variables[varName] = [byteVal, byteVal]
                            print(
                                f"[+] Content has been appended to varaible {varName}"
                            )
        elif printOutput:
            if niceOutput:
                niceOutput = f"{newLine}{niceOutput}{newLine}"
                if (
                    self.variables["output_limit"][0] is None
                    or self.variables["output_limit"][0] == -1
                    or not self.use_rawinput
                ):
                    print(niceOutput)
                else:
                    limit = int(self.variables["output_limit"][0])
                    lines = niceOutput.split(newLine)
                    while len(lines) > 0:
                        outputStepLines = lines[:limit]
                        lines = lines[limit:]
                        for line in outputStepLines:
                            print(line)
                        if len(lines) == 0:
                            break
                        ch = input(
                            "( Press <enter> to continue or <q><enter> to quit )"
                        )
                        if ch.lower() == "q":
                            break

    def modifyObject(
        self, obj, iteration: int = 0, contentFile: str = None, maxDepth: int = 10
    ):
        """
        Method to modify an existent object

        @param obj: The object to be modified
        @param iteration: Integer which specifies the depth of the recursion in the same object
        @param contentFile: The content of the file storing the stream
        @param maxDepth: The maximum depth for nested objects. Default value: 10.
        @return: The new object
        """
        if iteration > maxDepth:
            return (-1, "Object too nested")
        objectType = obj.getType()
        newObjectType = objectType
        if objectType not in ("array", "stream", "dictionary"):
            if contentFile is not None and iteration == 0:
                with open(contentFile, "rb") as fileContent:
                    content = fileContent.read()
            else:
                if objectType in {"string", "hexstring"}:
                    res = input(
                        newLine
                        + "Do you want to enter an ascii (1) or hexadecimal (2) string? (1/2) "
                    )
                    if res == "1":
                        newObjectType = "string"
                    elif res == "2":
                        newObjectType = "hexstring"
                    else:
                        return (-1, "[!] Error: The string type is not valid")
                elif objectType in {"integer", "real"}:
                    newObjectType = "number"
                if iteration == 0:
                    content = input(
                        f"{newLine}Please specify the {newObjectType} object content "
                        f"(if the content includes EOL characters use a file instead): {newLine * 2}"
                    )
                else:
                    value = obj.getValue()
                    rawValue = str(obj.getRawValue())
                    res = self.modifyRequest(value, rawValue)
                    if res == "d":
                        return (0, None)
                    if res == "m":
                        content = input(
                            f"{newLine}Please specify the {newObjectType} object content: {newLine * 2}"
                        )
                    else:
                        return (0, obj)
                content = self.checkInputContent(newObjectType, content)
                if content is None:
                    return (-1, "[!] Error: Content not valid for the object type")
                if newObjectType != objectType:
                    if newObjectType == "string":
                        obj = PDFString(content)
                    elif newObjectType == "hexstring":
                        obj = PDFHexString(content)
                    elif newObjectType == "number":
                        obj.setValue(content)
                else:
                    obj.setRawValue(content)
        else:
            if objectType == "array":
                newElements = []
                elements = obj.getElements()
                for element in elements:
                    ret = self.modifyObject(element, iteration + 1, maxDepth=maxDepth)
                    if ret[0] == -1:
                        return ret
                    newObject = ret[1]
                    if newObject is not None:
                        newElements.append(newObject)
                while True:
                    res = self.additionRequest()
                    if res is None:
                        return (-1, "Option not valid")
                    if res == "y":
                        ret = self.addObject(iteration + 1)
                        if ret[0] == -1:
                            return ret
                        newElements.append(ret[1])
                    else:
                        break
                obj.setElements(newElements)
            elif objectType in {"dictionary", "stream"}:
                newElements = {}
                elements = obj.getElements()
                if objectType == "stream":
                    if iteration == 0:
                        value = obj.getStream()
                        rawValue = ""
                        ret = self.modifyRequest(value, rawValue, stream=True)
                        if ret == "d":
                            obj.setDecodedStream("")
                        elif ret == "m":
                            if contentFile is not None:
                                with open(contentFile, "rb") as fileContent:
                                    streamContent = fileContent.read()
                            else:
                                streamContent = input(
                                    f"{newLine}Please specify the stream content "
                                    f"(if the content includes EOL characters use a file instead): {newLine * 2}"
                                )
                            obj.setDecodedStream(streamContent)
                    else:
                        return (-1, "Nested streams are not permitted")
                for element in elements:
                    valueObject = elements[element]
                    value = valueObject.getValue()
                    rawValue = valueObject.getRawValue()
                    ret = self.modifyRequest(value, rawValue, element)
                    if ret == "n":
                        newElements[element] = valueObject
                    elif ret == "m":
                        nestRet = self.modifyObject(
                            valueObject, iteration + 1, maxDepth=maxDepth
                        )
                        if nestRet[0] == -1:
                            return nestRet
                        newObject = nestRet[1]
                        newElements[element] = newObject
                while True:
                    res = self.additionRequest(isDict=True)
                    if res is None:
                        return (-1, "Option not valid")
                    if res == "y":
                        key = input("Name object: ")
                        key = self.checkInputContent("name", key)
                        ret = self.addObject(iteration + 1)
                        if ret[0] == -1:
                            return ret
                        newElements[key] = ret[1]
                    else:
                        break
                obj.setElements(newElements)
        return (0, obj)

    def modifyRequest(self, value, rawValue, key=None, stream: bool = False):
        """
        Method to ask the user what he wants to do with the object: modify, delete or nothing.

        @param value: The value of the object.
        @param rawValue: The raw value of the object.
        @param key: The key of a dictionary entry.
        @param stream: Boolean to specify if the object contains a stream or not.
        @return: The response chosen by the user
        """
        message = ""
        if not stream:
            message = newLine
            if key is not None:
                message += f"Key: {key}{newLine}"
            message += f"Raw value: {str(rawValue)}{newLine}"
            if rawValue != value:
                message += f"Value: {str(value)}{newLine}"
        message += f"{newLine}Do you want to modify, delete or make no action"
        if stream:
            message += " in the STREAM"
        message += "? (m/d/n) "
        response = input(message)
        if response.lower() not in ["m", "d", "n"]:
            return None
        if stream and response.lower() == "m":
            print(f"Value: {str(value)}{newLine}")
        return response.lower()

    def parseArgs(self, args: str):
        """
        Method to split up the command arguments by quotes: \'\'\', " or \'

        @param args: The command arguments
        @return: An array with the separated arguments
        """
        redirectSymbols = [">", ">>", "$>", "$>>"]
        self.redirect = None
        self.outputVarName = None
        self.outputFileName = None
        argsArray = []
        while len(args) > 0:
            if args[0] == "'":
                if args[:3] == "'''":
                    index = args[3:].find("'''")
                    if index != -1:
                        arg = args[3 : index + 3]
                        argsArray.append(arg)
                        if len(args) > index + 6:
                            args = args[index + 6 :]
                        else:
                            args = ""
                    else:
                        return None
                else:
                    index = args[1:].find("'")
                    if index != -1:
                        arg = args[1 : index + 1]
                        argsArray.append(arg)
                        if len(args) > index + 2:
                            args = args[index + 2 :]
                        else:
                            args = ""
                    else:
                        return None
            elif args[0] == '"':
                index = args[1:].find('"')
                if index != -1:
                    arg = args[1 : index + 1]
                    argsArray.append(arg)
                    if len(args) > index + 2:
                        args = args[index + 2 :]
                    else:
                        args = ""
                else:
                    return None
            elif args[0] == " ":
                args = args[1:]
            else:
                index = args.find(" ")
                if index != -1:
                    arg = args[:index]
                    argsArray.append(arg)
                    if len(args) > index + 1:
                        args = args[index + 1 :]
                    else:
                        args = ""
                else:
                    argsArray.append(args)
                    args = ""
        if len(argsArray) > 1:
            if argsArray[-2] in redirectSymbols:
                if argsArray[-2] == ">":
                    self.redirect = FILE_WRITE
                    self.outputFileName = argsArray[-1]
                elif argsArray[-2] == ">>":
                    self.redirect = FILE_ADD
                    self.outputFileName = argsArray[-1]
                elif argsArray[-2] == "$>":
                    self.redirect = VAR_WRITE
                    self.outputVarName = argsArray[-1]
                elif argsArray[-2] == "$>>":
                    self.redirect = VAR_ADD
                    self.outputVarName = argsArray[-1]
                argsArray.pop()
                argsArray.pop()
            elif argsArray[-1][:2] == ">>" and len(argsArray[-1]) > 2:
                self.redirect = FILE_ADD
                self.outputFileName = argsArray[-1][2:]
                argsArray.pop()
            elif argsArray[-1][:1] == ">" and len(argsArray[-1]) > 1:
                self.redirect = FILE_WRITE
                self.outputFileName = argsArray[-1][1:]
                argsArray.pop()
            elif argsArray[-1][:3] == "$>>" and len(argsArray[-1]) > 3:
                self.redirect = VAR_ADD
                self.outputVarName = argsArray[-1][3:]
                argsArray.pop()
            elif argsArray[-1][:2] == "$>" and len(argsArray[-1]) > 2:
                self.redirect = VAR_WRITE
                self.outputVarName = argsArray[-1][2:]
                argsArray.pop()
        elif len(argsArray) > 0:
            if argsArray[-1][:2] == ">>" and len(argsArray[-1]) > 2:
                self.redirect = FILE_ADD
                self.outputFileName = argsArray[-1][2:]
                argsArray.pop()
            elif argsArray[-1][:1] == ">" and len(argsArray[-1]) > 1:
                self.redirect = FILE_WRITE
                self.outputFileName = argsArray[-1][1:]
                argsArray.pop()
            elif argsArray[-1][:3] == "$>>" and len(argsArray[-1]) > 3:
                self.redirect = VAR_ADD
                self.outputVarName = argsArray[-1][3:]
                argsArray.pop()
            elif argsArray[-1][:2] == "$>" and len(argsArray[-1]) > 2:
                self.redirect = VAR_WRITE
                self.outputVarName = argsArray[-1][2:]
                argsArray.pop()

        return argsArray

    def printBytes(self, byteVal: str):
        """
        Given a byte string shows the hexadecimal and ascii output in a nice way

        @param byteVal: A string
        @return: String with mixed hexadecimal and ascii strings, like the 'hexdump -C' output
        """
        output = ""
        row = 16
        if byteVal != "":
            k = None
            hexChain = ""
            strings = ""
            for k, v in enumerate(byteVal):
                if ord(v) > 31 and ord(v) < 127:
                    strings += v
                else:
                    strings += "."
                hexChars = hex(ord(v))
                hexChars = hexChars[2:]
                if len(hexChars) == 1:
                    hexChars = "0" + hexChars
                hexChain += hexChars + " "
                if k != 0 and k % row == row - 1:
                    output += f"{hexChain}  |{strings}|{newLine}"
                    hexChain = ""
                    strings = ""
            if k is not None and k % row != 0:
                if hexChain == "":
                    output = output[:-1]
                else:
                    output += f'{hexChain}{(48 - len(hexChain)) * " "}  |{strings + ((16 - len(strings)) * " ")}|'
        return output

    def printResult(self, result: str):
        """
        Given an string returns a mixed hexadecimal-ascii output if there are many non printable characters or the same string in other case

        @param result: A string
        @return: A mixed hexadecimal-ascii output if there are many non printable characters or the input string in other case
        """
        size = len(result)
        num = countNonPrintableChars(result)
        if size / 2 < num:
            return self.printBytes(result)
        return result

    def printTreeNode(
        self,
        node: int,
        nodesInfo: dict,
        expandedNodes: list = None,
        depth: int = 0,
        recursive: bool = True,
    ):
        """
        Given a tree prints the whole tree and its dependencies

        @param node: Root of the tree
        @param nodesInfo: Information abour the nodes of the tree
        @param expandedNodes: Already expanded nodes
        @param depth: Actual depth of the tree
        @param recursive: Boolean to specify if it's a recursive call or not
        @return: A tuple (expandedNodes,output), where expandedNodes is a list with the distinct nodes and output is the string representation of the tree
        """
        if expandedNodes is None:
            expandedNodes = []
        output = ""
        if node in nodesInfo:
            tab = "\t"
            if node not in expandedNodes or (node in expandedNodes and depth > 0):
                output += f"{tab * depth}{nodesInfo[node][0]} ({str(node)}) {newLine}"
            if node not in expandedNodes:
                expandedNodes.append(node)
                children = nodesInfo[node][1]
                if children:
                    for child in children:
                        if child in nodesInfo:
                            childType = nodesInfo[child][0]
                        else:
                            childType = "Unknown"
                        if childType != "Unknown" and recursive:
                            expChildrenNodes, childrenOutput = self.printTreeNode(
                                child, nodesInfo, expandedNodes, depth + 1
                            )
                            output += childrenOutput
                            expandedNodes = expChildrenNodes
                        else:
                            output += f"{tab * (depth + 1)}{childType} ({str(child)}) {newLine}"
                else:
                    return expandedNodes, output
        return expandedNodes, output
