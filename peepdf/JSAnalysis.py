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
    This module contains some functions to analyse Javascript code inside the PDF file
"""

import os
import re
import sys
import traceback
from datetime import datetime as dt
import jsbeautifier

try:
    from peepdf.PDFUtils import unescapeHTMLEntities, escapeString
except ModuleNotFoundError:
    from PDFUtils import unescapeHTMLEntities, escapeString

try:
    import STPyV8

    class Global(STPyV8.JSClass):
        """Identifies the STPyV8 JSClass and sets the evalOverride function"""

        evalCode = ""

        def evalOverride(self, expression):
            """Sets how the JS code will be evaluated"""
            self.evalCode += f"\n\n// New evaluated code\n{expression}"

    JS_MODULE = True

except ModuleNotFoundError:
    JS_MODULE = False

DTFMT = "%Y%m%d-%H%M%S"
ERROR_LOG = f"peepdf_jserrors-{dt.now().strftime(DTFMT)}.txt"
currentDir = os.getcwd()
errorsFile = os.path.join(currentDir, ERROR_LOG)
newLine = os.linesep
reJSscript = "<script[^>]*?contentType\s*?=\s*?['\"]application/x-javascript['\"][^>]*?>(.*?)</script>"
preDefinedCode = "var app = this;"


def analyseJS(code: str, context=None, manualAnalysis: bool = False):
    """
    Hooks the eval function and search for obfuscated elements in the Javascript code

    @param code: The Javascript code (string)
    @param context: Context of execution for the JS code
    @param manualAnalysis: Indication if manual analysis is desired (bool)
    @return: List with analysis information of the Javascript code: [JSCode,unescapedBytes,urlsFound,errors,context], where
            JSCode is a list with the several stages Javascript code,
            unescapedBytes is a list with the parameters of unescape functions,
            urlsFound is a list with the URLs found in the unescaped bytes,
            errors is a list of errors,
    """
    errors = []
    jsCode = []
    unescapedBytes = []
    urlsFound = []

    try:
        code = unescapeHTMLEntities(code)
        scriptElements = re.findall(reJSscript, code, re.DOTALL | re.IGNORECASE)
        if scriptElements:
            code = ""
            for scriptElement in scriptElements:
                code += f"{scriptElement}{newLine * 2}"
        code = jsbeautifier.beautify(code)
        jsCode.append(code)

        if code is not None and JS_MODULE and not manualAnalysis:
            if context is None:
                context = STPyV8.JSContext(Global())
            context.enter()
            # Hooking the eval function
            context.eval("eval=evalOverride")
            # context.eval(preDefinedCode)
            while True:
                try:
                    context.eval(code)
                    evalCode = context.eval("evalCode")
                    evalCode = jsbeautifier.beautify(evalCode)
                    if evalCode not in ("", code):
                        code = evalCode
                        jsCode.append(code)
                    else:
                        break
                except:
                    error = str(sys.exc_info()[1])
                    with open(errorsFile, "a", encoding="latin-1") as log_file:
                        log_file.write(f"{error}{newLine}")
                    errors.append(error)
                    break

            if code != "":
                escapedVars = re.findall(
                    "(\w*?)\s*?=\s*?(unescape\((.*?)\))", code, re.DOTALL
                )
                for var in escapedVars:
                    bytesVal = var[2]
                    if bytesVal.find("+") != -1 or bytesVal.find("%") == -1:
                        varContent = getVarContent(code, bytesVal)
                        if len(varContent) > 150:
                            ret = unescape(varContent)
                            if ret[0] != -1:
                                bytesVal = ret[1]
                                urls = re.findall("https?://.*$", bytesVal, re.DOTALL)
                                if bytesVal not in unescapedBytes:
                                    unescapedBytes.append(bytesVal)
                                for url in urls:
                                    if url not in urlsFound:
                                        urlsFound.append(url)
                    else:
                        bytesVal = bytesVal[1:-1]
                        if len(bytesVal) > 150:
                            ret = unescape(bytesVal)
                            if ret[0] != -1:
                                bytesVal = ret[1]
                                urls = re.findall("https?://.*$", bytesVal, re.DOTALL)
                                if bytesVal not in unescapedBytes:
                                    unescapedBytes.append(bytesVal)
                                for url in urls:
                                    if url not in urlsFound:
                                        urlsFound.append(url)
    except:
        with open(errorsFile, "a", encoding="latin-1") as log_file:
            traceback.print_exc(file=log_file)
        errors.append("Unexpected error in the JSAnalysis module!")
    finally:
        for js in jsCode:
            if js is None or js == "":
                jsCode.remove(js)
    return [jsCode, unescapedBytes, urlsFound, errors, context]


def getVarContent(jsCode: str, varContent: str):
    """
    Given the Javascript code and the content of a variable this method tries to obtain the real value of the variable, cleaning expressions like "a = eval; a(js_code);"

    @param jsCode: The Javascript code (string)
    @param varContent: The content of the variable (string)
    @return: A string with real value of the variable
    """
    clearBytes = ""
    varContent = varContent.replace("\n", "")
    varContent = varContent.replace("\r", "")
    varContent = varContent.replace("\t", "")
    varContent = varContent.replace(" ", "")
    parts = varContent.split("+")
    for part in parts:
        if re.match("[\"'].*?[\"']", part, re.DOTALL):
            clearBytes += part[1:-1]
        else:
            part = escapeString(part)
            varContent = re.findall(part + "\s*?=\s*?(.*?)[,;]", jsCode, re.DOTALL)
            if varContent:
                clearBytes += getVarContent(jsCode, varContent[0])
    return clearBytes


def isJavascript(content: str):
    """
    Given a string this method looks for typical Javscript strings and try to identify if the string contains Javascript code or not.

    @param content: A string
    @return: A boolean, True if it seems to contain Javascript code or False in the other case
    """
    jsStrings = [
        "var ",
        ";",
        ")",
        "(",
        "function ",
        "=",
        "{",
        "}",
        "if(",
        "if (",
        "if ",
        "else {",
        "else{",
        "else if",
        "return",
        "while(",
        "while (",
        "while ",
        "for(",
        "for (",
        "for ",
        ",",
        "eval",
    ]
    keyStrings = [";", "(", ")"]
    stringsFound = []
    limit = 15
    minDistinctStringsFound = 5
    minRatio = 10
    results = 0
    length = len(content)
    smallScriptLength = 100

    if re.findall(reJSscript, content, re.DOTALL | re.IGNORECASE):
        return True

    contentAlphaNumeric = any(
        any(char.isalnum() or char.isascii() for char in item) for item in content
    )

    if not contentAlphaNumeric:
        return False
    for char in content:
        if (ord(char) < 32 and char not in ["\n", "\r", "\t", "\f", "\x00"]) or ord(
            char
        ) >= 127:
            return False
    for string in jsStrings:
        cont = content.count(string)
        results += cont
        if cont > 0 and string not in stringsFound:
            stringsFound.append(string)
        elif cont == 0 and string in keyStrings:
            return False

    stringsFoundAlphaNumeric = any(
        any(char.isalnum() and char.isascii() for char in item) for item in stringsFound
    )
    if not stringsFoundAlphaNumeric:
        return False
    numDistinctStringsFound = len(stringsFound)
    ratio = (results * 100.0) / length
    return bool(
        results > limit and numDistinctStringsFound >= minDistinctStringsFound
    ) or (length < smallScriptLength and ratio > minRatio)


def searchObfuscatedFunctions(jsCode: str, function: str):
    """
    Search for obfuscated functions in the Javascript code

    @param jsCode: The Javascript code (string)
    @param function: The function name to look for (string)
    @return: List with obfuscated functions information [functionName,functionCall,containsReturns]
    """
    obfuscatedFunctionsInfo = []
    if jsCode is not None:
        match = re.findall(
            "\W(" + function + "\s{0,5}?\((.*?)\)\s{0,5}?;)", jsCode, re.DOTALL
        )
        if match:
            for m in match:
                if re.findall("return", m[1], re.IGNORECASE):
                    obfuscatedFunctionsInfo.append([function, m, True])
                else:
                    obfuscatedFunctionsInfo.append([function, m, False])
        obfuscatedFunctions = re.findall(
            "\s*?((\w*?)\s*?=\s*?" + function + ")\s*?;", jsCode, re.DOTALL
        )
        for obfuscatedFunction in obfuscatedFunctions:
            obfuscatedElement = obfuscatedFunction[1]
            obfuscatedFunctionsInfo += searchObfuscatedFunctions(
                jsCode, obfuscatedElement
            )
    return obfuscatedFunctionsInfo


def unescape(escapedBytes: str, unicode: bool = True):
    """
    This method unescapes the given string

    @param escapedBytes: A string to unescape
    @param unicode: Bool, if the provided value should be interpreted as unicode
    @return: A tuple (status,statusContent), where statusContent is an unescaped string in case status = 0 or an error in case status = -1
    """
    # TODO: modify to accept a list of escaped strings?
    unescapedBytes = ""
    if unicode:
        unicodePadding = "\x00"
    else:
        unicodePadding = ""
    try:
        if (
            escapedBytes.lower().find("%u") != -1
            or escapedBytes.lower().find("\\u") != -1
            or escapedBytes.find("%") != -1
        ):
            if escapedBytes.lower().find("\\u") != -1:
                splitBytes = escapedBytes.split("\\")
            else:
                splitBytes = escapedBytes.split("%")
            for k, v in enumerate(splitBytes):
                splitByte = v
                if splitByte == "":
                    continue
                if len(splitByte) > 4 and re.match(
                    "u[0-9a-f]{4}", splitByte[:5], re.IGNORECASE
                ):
                    unescapedBytes += chr(int(splitByte[3] + splitByte[4], 16)) + chr(
                        int(splitByte[1] + splitByte[2], 16)
                    )
                    if len(splitByte) > 5:
                        for j in range(5, len(splitByte)):
                            unescapedBytes += splitByte[j] + unicodePadding
                elif len(splitByte) > 1 and re.match(
                    "[0-9a-f]{2}", splitByte[:2], re.IGNORECASE
                ):
                    unescapedBytes += (
                        chr(int(splitByte[0] + splitByte[1], 16)) + unicodePadding
                    )
                    if len(splitByte) > 2:
                        for j in range(2, len(splitByte)):
                            unescapedBytes += splitByte[j] + unicodePadding
                else:
                    if k != 0:
                        unescapedBytes += "%" + unicodePadding
                    for _, v in enumerate(splitByte):
                        unescapedBytes += v + unicodePadding
        else:
            unescapedBytes = escapedBytes
    except:
        return (-1, "[!] Error while unescaping the bytes")
    return (0, unescapedBytes)
