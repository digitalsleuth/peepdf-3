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
    Module with some misc functions
"""

import os, re, html.entities, json, requests
from lxml import etree
from datetime import datetime as dt

try:
    from peepdf.PDFVulns import *
except ModuleNotFoundError:
    from PDFVulns import *

def clearScreen():
    """
    Simple method to clear the screen depending on the OS
    """
    if os.name == "nt":
        os.system("cls")
    elif os.name == "posix":
        os.system("reset")
    elif os.name == "mac":
        os.system("clear")


def countArrayElements(array):
    """
    Simple method to count the repetitions of elements in an array

            @param array: An array of elements
            @return: A tuple (elements,counters), where elements is a list with the distinct elements and counters is the list with the number of times they appear in the array
    """
    elements = []
    counters = []
    for element in array:
        if element in elements:
            indx = elements.index(element)
            counters[indx] += 1
        else:
            elements.append(element)
            counters.append(1)
    return elements, counters


def countNonPrintableChars(string):
    """
    Simple method to return the non printable characters found in an string

            @param string: A string
            @return: Number of non printable characters in the string
    """
    counter = 0
    for i in range(len(string)):
        if ord(string[i]) <= 31 or ord(string[i]) >= 127:
            counter += 1
    return counter


def decodeName(name):
    """
    Decode the given PDF name

            @param name: A PDFName string to decode
            @return: A tuple (status,statusContent), where statusContent is the decoded PDF name in case status = 0 or an error in case status = -1
    """
    decodedName = name
    hexNumbers = re.findall("#([0-9a-f]{2})", name, re.DOTALL | re.IGNORECASE)
    for hexNumber in hexNumbers:
        try:
            decodedName = decodedName.replace("#" + hexNumber, chr(int(hexNumber, 16)))
        except:
            return (-1, "Error decoding name")
    return (0, decodedName)


def decodeString(string):
    """
    Decode the given PDF string

            @param string: A PDFString to decode
            @return A tuple (status,statusContent), where statusContent is the decoded PDF string in case status = 0 or an error in case status = -1
    """
    decodedString = string
    octalNumbers = re.findall("\\\\([0-7]{1-3})", decodedString, re.DOTALL)
    for octal in octalNumbers:
        try:
            decodedString = decodedString.replace("\\\\" + octal, chr(int(octal, 8)))
        except:
            return (-1, "Error decoding string")
    return (0, decodedString)


def encodeName(name):
    """
    Encode the given PDF name

            @param name: A PDFName string to encode
            @return: A tuple (status,statusContent), where statusContent is the encoded PDF name in case status = 0 or an error in case status = -1
    """
    encodedName = ""
    if name[0] == "/":
        name = name[1:]
    for char in name:
        if char == "\0":
            encodedName += char
        else:
            try:
                hex = "%x" % ord(char)
                encodedName += "#" + hex
            except:
                return (-1, "Error encoding name")
    return (0, "/" + encodedName)


def encodeString(string):
    """
    Encode the given PDF string

            @param string: A PDFString to encode
            @return: A tuple (status,statusContent), where statusContent is the encoded PDF string in case status = 0 or an error in case status = -1
    """
    encodedString = ""
    try:
        for char in string:
            octal = "%o" % ord(char)
            encodedString += "\\" + (3 - len(octal)) * "0" + octal
    except:
        return (-1, "Error encoding string")
    return (0, encodedString)


def escapeRegExpString(string):
    """
    Escape the given string to include it as a regular expression

    @param string: A regular expression to be escaped
    @return: Escaped string
    """
    toEscapeChars = ["\\", "(", ")", ".", "|", "^", "$", "*", "+", "?", "[", "]"]
    escapedValue = ""
    for i in range(len(string)):
        if string[i] in toEscapeChars:
            escapedValue += f"\\{string[i]}"
        else:
            escapedValue += string[i]
    return escapedValue


def escapeString(string):
    """
    Escape the given string

            @param string: A string to be escaped
            @return: Escaped string
    """
    toEscapeChars = ["\\", "(", ")"]
    escapedValue = ""
    for i in range(len(string)):
        if string[i] in toEscapeChars and (i == 0 or string[i - 1] != "\\"):
            if string[i] == "\\":
                if len(string) > i + 1 and re.match("[0-7]", string[i + 1]):
                    escapedValue += string[i]
                else:
                    escapedValue += "\\" + string[i]
            else:
                escapedValue += "\\" + string[i]
        elif string[i] == "\r":
            escapedValue += "\\r"
        elif string[i] == "\n":
            escapedValue += "\\n"
        elif string[i] == "\t":
            escapedValue += "\\t"
        elif string[i] == "\b":
            escapedValue += "\\b"
        elif string[i] == "\f":
            escapedValue += "\\f"
        else:
            escapedValue += string[i]
    return escapedValue


def getBitsFromNum(num, bitsPerComponent=8):
    """
    Makes the conversion between number and bits

    @param num: Number to be converted
    @param bitsPerComponent: Number of bits needed to represent a component
    @return: A tuple (status,statusContent), where statusContent is the string containing the resulting bits in case status = 0 or an error in case status = -1
    """
    if not isinstance(num, int):
        return (-1, "num must be an integer")
    if not isinstance(bitsPerComponent, int):
        return (-1, "bitsPerComponent must be an integer")
    try:
        bitsRepresentation = bin(num)
        bitsRepresentation = bitsRepresentation.replace("0b", "")
        mod = len(bitsRepresentation) % 8
        if mod != 0:
            bitsRepresentation = "0" * (8 - mod) + bitsRepresentation
        bitsRepresentation = bitsRepresentation[-1 * bitsPerComponent :]
    except:
        return (-1, "Error in conversion from number to bits")
    return (0, bitsRepresentation)


def getNumsFromBytes(bytes, bitsPerComponent=8):
    """
    Makes the conversion between bytes and numbers, depending on the number of bits used per component.

    @param bytes: String representing the bytes to be converted
    @param bitsPerComponent: Number of bits needed to represent a component
    @return: A tuple (status,statusContent), where statusContent is a list of numbers in case status = 0 or an error in case status = -1
    """
    if not isinstance(bytes, str):
        return (-1, "bytes must be a string")
    if not isinstance(bitsPerComponent, int):
        return (-1, "bitsPerComponent must be an integer")
    outputComponents = []
    bitsStream = ""
    for byte in bytes:
        try:
            bitsRepresentation = bin(ord(byte))
            bitsRepresentation = bitsRepresentation.replace("0b", "")
            bitsRepresentation = (
                "0" * (8 - len(bitsRepresentation)) + bitsRepresentation
            )
            bitsStream += bitsRepresentation
        except:
            return (-1, "Error in conversion from bytes to bits")

    try:
        for i in range(0, len(bitsStream), bitsPerComponent):
            bytes = ""
            bits = bitsStream[i : i + bitsPerComponent]
            num = int(bits, 2)
            outputComponents.append(num)
    except:
        return (-1, "Error in conversion from bits to bytes")
    return (0, outputComponents)


def getBytesFromBits(bitsStream):
    """
    Makes the conversion between bits and bytes.

    @param bitsStream: String representing a chain of bits
    @return: A tuple (status,statusContent), where statusContent is the string containing the resulting bytes in case status = 0 or an error in case status = -1
    """
    if not isinstance(bitsStream, str):
        return (-1, "The bitsStream must be a string")
    bytes = ""
    if re.match("[01]*$", bitsStream):
        try:
            for i in range(0, len(bitsStream), 8):
                bits = bitsStream[i : i + 8]
                byte = chr(int(bits, 2))
                bytes += byte
        except:
            return (-1, "Error in conversion from bits to bytes")
        return (0, bytes)
    else:
        return (-1, "The format of the bit stream is not correct")


def getBytesFromFile(filename, offset, numBytes):
    """
    Returns the number of bytes specified from a file, starting from the offset specified

            @param filename: Name of the file
            @param offset: Bytes offset
            @param numBytes: Number of bytes to retrieve
            @return: A tuple (status,statusContent), where statusContent is the bytes read in case status = 0 or an error in case status = -1
    """
    if not isinstance(offset, int) or not isinstance(numBytes, int):
        return (-1, "The offset and the number of bytes must be integers")
    if os.path.exists(filename):
        fileSize = os.path.getsize(filename)
        bytesFile = open(filename, "rb")
        bytesFile.seek(offset)
        if offset + numBytes > fileSize:
            byteVal = bytesFile.read()
        else:
            byteVal = bytesFile.read(numBytes)
        bytesFile.close()
        return (0, byteVal)
    else:
        return (-1, "File does not exist")


def hexToString(hexString):
    """
    Simple method to convert an hexadecimal string to ascii string

    @param hexString: A string in hexadecimal format
    @return: A tuple (status,statusContent), where statusContent is an ascii string in case status = 0 or an error in case status = -1
    """
    string = ""
    if len(hexString) % 2 != 0:
        hexString = "0" + hexString
    try:
        for i in range(0, len(hexString), 2):
            string += chr(int(hexString[i] + hexString[i + 1], 16))
    except:
        return (-1, "Error in hexadecimal conversion")
    return (0, string)


def numToHex(num, numBytes):
    """
    Given a number returns its hexadecimal format with the specified length, adding '\0' if necessary

            @param num: A number (int)
            @param numBytes: Length of the output (int)
            @return: A tuple (status,statusContent), where statusContent is a number in hexadecimal format in case status = 0 or an error in case status = -1
    """
    hexString = ""
    if not isinstance(num, int):
        return (-1, "Bad number")
    try:
        hexNumber = hex(num)[2:]
        if len(hexNumber) % 2 != 0:
            hexNumber = "0" + hexNumber
        for i in range(0, len(hexNumber) - 1, 2):
            hexString += chr(int(hexNumber[i] + hexNumber[i + 1], 16))
        hexString = "\0" * (numBytes - len(hexString)) + hexString
    except:
        return (-1, "Error in hexadecimal conversion")
    return (0, hexString)


def numToString(num, numDigits):
    """
    Given a number returns its string format with the specified length, adding '0' if necessary

            @param num: A number (int)
            @param numDigits: Length of the output string (int)
            @return: A tuple (status,statusContent), where statusContent is a number in string format in case status = 0 or an error in case status = -1
    """
    if not isinstance(num, int):
        return (-1, "Bad number")
    strNum = str(num)
    if numDigits < len(strNum):
        return (-1, "Bad digit number")
    for i in range(numDigits - len(strNum)):
        strNum = "0" + strNum
    return (0, strNum)


def unescapeHTMLEntities(text):
    """
    Removes HTML or XML character references and entities from a text string.

    @param text The HTML (or XML) source text.
    @return The plain text, as a Unicode string, if necessary.

    Author: Fredrik Lundh
    Source: http://effbot.org/zone/re-sub.htm#unescape-html
    """

    def fixup(m):
        text = m.group(0)
        if text[:2] == "&#":
            # character reference
            try:
                if text[:3] == "&#x":
                    return chr(int(text[3:-1], 16))
                else:
                    return chr(int(text[2:-1]))
            except ValueError:
                pass
        else:
            # named entity
            try:
                text = chr(html.entities.name2codepoint[text[1:-1]])
            except KeyError:
                pass
        return text  # leave as is

    return re.sub(r"&#?\w+;", fixup, text)


def unescapeString(string):
    """
    Unescape the given string

            @param string: An escaped string
            @return: Unescaped string
    """
    toUnescapeChars = ["\\", "(", ")"]
    unescapedValue = ""
    i = 0
    while i < len(string):
        if string[i] == "\\" and i != len(string) - 1:
            if string[i + 1] in toUnescapeChars:
                if string[i + 1] == "\\":
                    unescapedValue += "\\"
                    i += 1
                else:
                    pass
            elif string[i + 1] == "r":
                i += 1
                unescapedValue += "\r"
            elif string[i + 1] == "n":
                i += 1
                unescapedValue += "\n"
            elif string[i + 1] == "t":
                i += 1
                unescapedValue += "\t"
            elif string[i + 1] == "b":
                i += 1
                unescapedValue += "\b"
            elif string[i + 1] == "f":
                i += 1
                unescapedValue += "\f"
            else:
                unescapedValue += string[i]
        else:
            unescapedValue += string[i]
        i += 1
    return unescapedValue


def vtcheck(md5, vtKey):
    """
    Function to check a hash on VirusTotal and get the report summary

    @param md5: The MD5 to check (hexdigest)
    @param vtKey: The VirusTotal API key needed to perform the request
    @return: A dictionary with the result of the request
    """
    vtUrl = f"https://www.virustotal.com/api/v3/files/{md5}"
    headers = {"accept": "application/json", "x-apikey": vtKey}
    try:
        response = requests.get(vtUrl, headers=headers)
        jsonResponse = response.json()
    except:
        return (-1, f"The request to VirusTotal failed")
    try:
        jsonDict = jsonResponse
    except:
        return (
            -1,
            "An error has occurred while parsing the JSON response from VirusTotal",
        )
    return (0, jsonDict)

def getPeepXML(statsDict, VERSION):
    root = etree.Element(
        "peepdf_analysis",
        version=f"{VERSION}",
        url="https://github.com/digitalsleuth/peepdf-3",
        author="Jose Miguel Esparza and Corey Forman",
    )
    analysisDate = etree.SubElement(root, "date")
    analysisDate.text = dt.today().strftime("%Y-%m-%d %H:%M:%S")
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
    if "IDs" in statsDict and statsDict["IDs"] != "\r\n":
        all_ids = "".join(filter(lambda ch: ch not in "\n\r\t", statsDict["IDs"])).replace("]V", "] V")
        all_ids = all_ids.split("Version ")
        for each in all_ids:
            if each == "":
                all_ids.remove(each)
        for each_id in range(len(all_ids)):
            ids = etree.SubElement(basicInfo, f"id{each_id}")
            ids.text = f"Version {all_ids[each_id]}"
    detection = etree.SubElement(basicInfo, "detection")
    if statsDict["Detection"]:
        detectionRate = etree.SubElement(detection, "rate")
        detectionRate.text = f'{statsDict["Detection"][0]}/{statsDict["Detection"][1]}'
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
        if (
            events is not None
            or actions is not None
            or vulns is not None
            or elements is not None
        ):
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


def getPeepJSON(statsDict, VERSION):
    # peepdf info
    peepdfDict = {
        "version": VERSION,
        "author": "Jose Miguel Esparza and Corey Forman",
        "url": "https://github.com/digitalsleuth/peepdf-3",
    }
    # Basic info
    basicDict = {}
    basicDict["filename"] = statsDict["File"]
    basicDict["md5"] = statsDict["MD5"]
    basicDict["sha1"] = statsDict["SHA1"]
    basicDict["sha256"] = statsDict["SHA256"]
    basicDict["size"] = int(statsDict["Size"])
    if statsDict["IDs"] != "\r\n":
        basicDict["ids"] = {}
        ids = statsDict["IDs"].split("\r\n\t")
        for each_id in ids:
            if each_id == '':
                ids.remove(each_id)
        for idx in range(len(ids)):
            ids[idx] = "".join(filter(lambda ch: ch not in "\n\r\t", ids[idx]))
            ids[idx] = ids[idx].split(f"Version {idx}: ")[1]
            basicDict["ids"][f"version_{idx}"] = ids[idx]
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
            "date": dt.today().strftime("%Y-%m-%d %H:%M:%S"),
            "basic": basicDict,
            "advanced": advancedInfo,
        }
    }
    return json.dumps(jsonDict, indent=4, sort_keys=True)

def getUpdate():
    newLine = os.linesep
    branch = "main"
    remoteVersion = ""
    localVersion = vulnsVersion
    repoVersionFile = (
        f"https://raw.githubusercontent.com/digitalsleuth/peepdf-3/{branch}/vulns-ver"
    )
    repoVulnsFile = f"https://raw.githubusercontent.com/digitalsleuth/peepdf-3/{branch}/peepdf/PDFVulns.py"
    print(f"[-] Checking if there are new updates to the Vulnerabilties List")
    try:
        remoteVersion = requests.get(repoVersionFile).text
        remoteVersion = remoteVersion.strip()
    except:
        sys.exit(
            "[!] Error: Connection error while trying to connect with the repository"
        )
    if remoteVersion == "":
        sys.exit("[!] Error: Unable to confirm the version number")
    if localVersion == remoteVersion:
        print(f"[-] Current Version: {localVersion}")
        print(f"[-] Remote Version: {remoteVersion}")
        print(f"[+] No changes{newLine}")
    elif localVersion > remoteVersion:
        print(
            f"[-] Current Version ({localVersion}) is newer than the Remote Version ({remoteVersion})."
        )
    else:
        print(f"[-] Current Version: {localVersion}")
        print(f"[-] Remote Version: {remoteVersion}")
        print(f"[+] Update available")
        print(f"[-] Fetching the update ...")
        try:
            updateContent = requests.get(repoVulnsFile).text
        except:
            sys.exit(
                f"[!] Error: Connection error while trying to fetch the updated PDFVulns.py file{newLine}"
            )
        executingPath = pathlib.Path(__file__).parent.resolve()
        vulnsFile = f"{executingPath}{os.sep}PDFVulns.py"
        if os.path.exists(vulnsFile):
            print(f"[*] File {vulnsFile} exists, overwriting ...")
        else:
            print(f"[*] File {vulnsFile} does not exist, creating ...")
        try:
            with open(vulnsFile, "w") as localVulnsFile:
                localVulnsFile.write(updateContent)
                localVulnsFile.close()
            print(
                f"[+] peepdf Vulnerabilities List updated successfully to {remoteVersion}{newLine}"
            )
        except PermissionError:
            sys.exit(
                f"[!] You do not have permissions to write to {vulnsFile}. Try re-running the command with appropriate permissions"
            )
