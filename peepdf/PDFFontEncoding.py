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
Decodes PDF page text that is shown through custom font encodings (glyph
codes that don't match the visible character), so the "search" command can
look for the actual displayed text rather than just the raw bytes stored in
content streams.

This is a best-effort text-recovery, not a full font implementation.
"""

import re


def _buildCodecTable(codecName):
    table = {}
    for code in range(256):
        try:
            table[code] = bytes([code]).decode(codecName)
        except UnicodeDecodeError:
            continue
    return table

"""
WinAnsiEncoding and MacRomanEncoding are, for `search` purposes, close
enough matches to common Windows-1252 and Mac OS Roman codecs.
"""
WIN_ANSI_ENCODING = _buildCodecTable("cp1252")
MAC_ROMAN_ENCODING = _buildCodecTable("mac_roman")
STANDARD_ENCODING = {code: chr(code) for code in range(0x20, 0x7F)}
STANDARD_ENCODING[0x27] = "’"  # quoteright
STANDARD_ENCODING[0x60] = "‘"  # quoteleft
_BASE_ENCODING_TABLES = {
    "/WinAnsiEncoding": WIN_ANSI_ENCODING,
    "/MacRomanEncoding": MAC_ROMAN_ENCODING,
    "/StandardEncoding": STANDARD_ENCODING,
    "/MacExpertEncoding": STANDARD_ENCODING,
}

"""
A 'practical' subset of the Adobe Glyph List
https://github.com/adobe-type-tools/agl-aglfn/
"""
AGL_NAMES = {
    "space": " ",
    "exclam": "!",
    "quotedbl": '"',
    "numbersign": "#",
    "dollar": "$",
    "percent": "%",
    "ampersand": "&",
    "quotesingle": "'",
    "parenleft": "(",
    "parenright": ")",
    "asterisk": "*",
    "plus": "+",
    "comma": ",",
    "hyphen": "-",
    "minus": "-",
    "period": ".",
    "slash": "/",
    "colon": ":",
    "semicolon": ";",
    "less": "<",
    "equal": "=",
    "greater": ">",
    "question": "?",
    "at": "@",
    "bracketleft": "[",
    "backslash": "\\",
    "bracketright": "]",
    "asciicircum": "^",
    "underscore": "_",
    "grave": "`",
    "braceleft": "{",
    "bar": "|",
    "braceright": "}",
    "asciitilde": "~",
    "bullet": "•",
    "dagger": "†",
    "daggerdbl": "‡",
    "ellipsis": "…",
    "emdash": "—",
    "endash": "–",
    "florin": "ƒ",
    "guilsinglleft": "‹",
    "guilsinglright": "›",
    "perthousand": "‰",
    "quotedblbase": "„",
    "quotedblleft": "“",
    "quotedblright": "”",
    "quoteleft": "‘",
    "quoteright": "’",
    "quotesinglbase": "‚",
    "trademark": "™",
    "fi": "ﬁ",
    "fl": "ﬂ",
    "degree": "°",
    "plusminus": "±",
    "copyright": "©",
    "registered": "®",
    "cent": "¢",
    "sterling": "£",
    "yen": "¥",
    "section": "§",
    "paragraph": "¶",
    "mu": "µ",
    "ordfeminine": "ª",
    "ordmasculine": "º",
    "onequarter": "¼",
    "onehalf": "½",
    "threequarters": "¾",
    "onesuperior": "¹",
    "twosuperior": "²",
    "threesuperior": "³",
    "multiply": "×",
    "divide": "÷",
    "logicalnot": "¬",
    "germandbls": "ß",
    "ae": "æ",
    "AE": "Æ",
    "oslash": "ø",
    "Oslash": "Ø",
    "eth": "ð",
    "Eth": "Ð",
    "thorn": "þ",
    "Thorn": "Þ",
    "ntilde": "ñ",
    "Ntilde": "Ñ",
    "ccedilla": "ç",
    "Ccedilla": "Ç",
}

_ACCENTED_VOWEL_MARKS = {
    "grave": "̀",
    "acute": "́",
    "circumflex": "̂",
    "tilde": "̃",
    "dieresis": "̈",
    "ring": "̊",
}
_ACCENTED_BASE_UNICODE = {
    "A": "A",
    "E": "E",
    "I": "I",
    "O": "O",
    "U": "U",
    "Y": "Y",
    "a": "a",
    "e": "e",
    "i": "i",
    "o": "o",
    "u": "u",
    "y": "y",
}
_BFCHAR_BLOCK = re.compile(r"beginbfchar(.*?)endbfchar", re.DOTALL)
_BFRANGE_BLOCK = re.compile(r"beginbfrange(.*?)endbfrange", re.DOTALL)
_HEX_TOKEN = re.compile(r"<([0-9A-Fa-f]+)>")
_BFRANGE_ENTRY = re.compile(
    r"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*(\[.*?\]|<[0-9A-Fa-f]+>)", re.DOTALL
)
_STRING_ESCAPES = {
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "b": "\b",
    "f": "\f",
    "(": "(",
    ")": ")",
    "\\": "\\",
}
_NAME_STOP_CHARS = " \t\r\n\f\x00()<>[]{}/%"
_NAME_HEX_ESCAPE = re.compile(r"#([0-9A-Fa-f]{2})")

for _base, _baseChar in _ACCENTED_BASE_UNICODE.items():
    for _markName, _combining in _ACCENTED_VOWEL_MARKS.items():
        _glyphName = f"{_base}{_markName}"
        try:
            import unicodedata

            _composed = unicodedata.normalize("NFC", _baseChar + _combining)
        except Exception:
            continue
        if len(_composed) == 1:
            AGL_NAMES[_glyphName] = _composed

for _letter in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ":
    AGL_NAMES[_letter] = _letter
for _index, _digitName in enumerate(
    ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"]
):
    AGL_NAMES[_digitName] = str(_index)

_HEX_DIGITS = set("0123456789ABCDEFabcdef")


def glyphNameToUnicode(name):
    """
    Resolves a PDF glyph name to the Unicode text it represents,
    using the AGL subset above plus the uniXXXX/uXXXX naming conventions.
    returns None if it can't be resolved.
    """
    if not name:
        return None
    baseName = name.split(".", 1)[0]
    if baseName in AGL_NAMES:
        return AGL_NAMES[baseName]
    if baseName.startswith("uni") and len(baseName) >= 7 and len(baseName) % 4 == 3:
        hexPart = baseName[3:]
        if all(c in _HEX_DIGITS for c in hexPart):
            try:
                return "".join(
                    chr(int(hexPart[i : i + 4], 16)) for i in range(0, len(hexPart), 4)
                )
            except ValueError:
                pass
    if baseName.startswith("u") and 5 <= len(baseName) <= 7:
        hexPart = baseName[1:]
        if all(c in _HEX_DIGITS for c in hexPart):
            try:
                return chr(int(hexPart, 16))
            except ValueError:
                pass
    if len(baseName) == 1:
        return baseName
    return None


def getBaseEncodingTable(baseEncodingName):
    """Returns the 256-entry code to char table for a /BaseEncoding name."""
    return dict(_BASE_ENCODING_TABLES.get(baseEncodingName, STANDARD_ENCODING))


def parseDifferencesTable(differences, baseTable):
    """
    Applies a /Differences array on top of a base code to char table, as per PDF spec.
    each name after a code applies to that code, then the code increments.
    """
    table = dict(baseTable)
    currentCode = 0
    for item in differences:
        if isinstance(item, bool):
            continue
        if isinstance(item, (int, float)):
            currentCode = int(item)
        elif isinstance(item, str):
            unicodeChar = glyphNameToUnicode(item.lstrip("/"))
            if unicodeChar is not None:
                table[currentCode] = unicodeChar
            else:
                table.pop(currentCode, None)
            currentCode += 1
    return table


def _hexToUnicodeString(hexDigits):
    if len(hexDigits) % 2 != 0:
        hexDigits += "0"
    try:
        raw = bytes.fromhex(hexDigits)
    except ValueError:
        return ""
    if len(raw) % 2 != 0:
        raw += b"\x00"
    try:
        return raw.decode("utf-16-be")
    except UnicodeDecodeError:
        return ""


def parseToUnicodeCMap(cmapText):
    """
    Parses the bfchar/bfrange sections of a /ToUnicode CMap stream's decoded
    text into a code(int) to unicode(str) table.
    Returns (None, 1) if no usable mappings were found.
    """
    table = {}
    byteWidths = []
    for match in _BFCHAR_BLOCK.finditer(cmapText):
        tokens = _HEX_TOKEN.findall(match.group(1))
        for i in range(0, len(tokens) - 1, 2):
            srcHex, dstHex = tokens[i], tokens[i + 1]
            byteWidths.append(max(1, len(srcHex) // 2))
            table[int(srcHex, 16)] = _hexToUnicodeString(dstHex)
    for match in _BFRANGE_BLOCK.finditer(cmapText):
        for entry in _BFRANGE_ENTRY.finditer(match.group(1)):
            loHex, hiHex, dst = entry.groups()
            lo, hi = int(loHex, 16), int(hiHex, 16)
            byteWidths.append(max(1, len(loHex) // 2))
            if dst.startswith("["):
                for offset, dstHex in enumerate(_HEX_TOKEN.findall(dst)):
                    code = lo + offset
                    if code > hi:
                        break
                    table[code] = _hexToUnicodeString(dstHex)
            else:
                dstHex = _HEX_TOKEN.match(dst).group(1)
                if len(dstHex) == 4:
                    baseValue = int(dstHex, 16)
                    for code in range(lo, hi + 1):
                        table[code] = chr(baseValue + (code - lo))
                else:
                    decoded = _hexToUnicodeString(dstHex)
                    for code in range(lo, hi + 1):
                        table[code] = decoded
    if not table:
        return None, 1
    byteWidth = max(set(byteWidths), key=byteWidths.count)
    return table, byteWidth


def tokenizeContentStream(content):
    """
    A minimal PDF content-stream tokenizer: enough to track literal/hex
    strings, names, numbers, arrays and operators for text extraction.
    """
    length = len(content)
    i = 0
    while i < length:
        c = content[i]
        if c in " \t\r\n\f\x00":
            i += 1
            continue
        if c == "%":
            while i < length and content[i] not in "\r\n":
                i += 1
            continue
        if c == "(":
            i += 1
            depth = 1
            chars = []
            while i < length and depth > 0:
                ch = content[i]
                if ch == "\\":
                    i += 1
                    if i >= length:
                        break
                    esc = content[i]
                    if esc in _STRING_ESCAPES:
                        chars.append(_STRING_ESCAPES[esc])
                        i += 1
                    elif esc in "01234567":
                        octal = esc
                        i += 1
                        for _ in range(2):
                            if i < length and content[i] in "01234567":
                                octal += content[i]
                                i += 1
                            else:
                                break
                        chars.append(chr(int(octal, 8) & 0xFF))
                    elif esc == "\r":
                        i += 1
                        if i < length and content[i] == "\n":
                            i += 1
                    elif esc == "\n":
                        i += 1
                    else:
                        chars.append(esc)
                        i += 1
                elif ch == "(":
                    depth += 1
                    chars.append(ch)
                    i += 1
                elif ch == ")":
                    depth -= 1
                    i += 1
                    if depth > 0:
                        chars.append(ch)
                else:
                    chars.append(ch)
                    i += 1
            yield ("string", "".join(chars))
            continue
        if c == "<":
            if i + 1 < length and content[i + 1] == "<":
                i += 2
                yield ("dict_start", None)
                continue
            i += 1
            hexChars = []
            while i < length and content[i] != ">":
                if content[i] in _HEX_DIGITS:
                    hexChars.append(content[i])
                i += 1
            i += 1
            hexStr = "".join(hexChars)
            if len(hexStr) % 2 != 0:
                hexStr += "0"
            try:
                decoded = bytes.fromhex(hexStr).decode("latin-1")
            except ValueError:
                decoded = ""
            yield ("hexstring", decoded)
            continue
        if c == ">":
            if i + 1 < length and content[i + 1] == ">":
                i += 2
                yield ("dict_end", None)
                continue
            i += 1
            continue
        if c == "[":
            i += 1
            yield ("array_start", None)
            continue
        if c == "]":
            i += 1
            yield ("array_end", None)
            continue
        if c == "/":
            i += 1
            start = i
            while i < length and content[i] not in _NAME_STOP_CHARS:
                i += 1
            rawName = content[start:i]
            name = _NAME_HEX_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), rawName)
            yield ("name", "/" + name)
            continue
        if c in "{}":
            i += 1
            continue
        if c in "+-." or c.isdigit():
            start = i
            i += 1
            while i < length and (content[i] in "+-." or content[i].isdigit()):
                i += 1
            try:
                yield ("number", float(content[start:i]))
            except ValueError:
                pass
            continue
        start = i
        while i < length and content[i] not in _NAME_STOP_CHARS:
            i += 1
        keyword = content[start:i]
        if keyword == "":
            i += 1
            continue
        if keyword == "BI":
            idIndex = content.find("ID", i)
            if idIndex != -1:
                eiIndex = content.find("EI", idIndex + 2)
                i = eiIndex + 2 if eiIndex != -1 else length
            continue
        yield ("operator", keyword)


def decodeContentStreamText(content, fontTables):
    """
    Walks a decoded content stream's text-showing operators (Tj, TJ, ', ")
    and decodes each string operand through the active font's code to unicode
    table (tracked via Tf), returning the recovered visible text for
    substring searching. Text with no resolvable font table is passed
    through as-is (latin-1), so this fails 'gracefully' rather than losing
    coverage that the plain `search` already provides.

    @param content: Decoded content-stream text (str).
    @param fontTables: dict of resource font name (without "/").
    """
    output = []
    operands = []
    arrayStack = []
    currentTable = None
    currentByteWidth = 1

    def decodeOperand(rawText):
        if currentTable is None:
            return rawText
        pieces = []
        width = currentByteWidth
        for idx in range(0, len(rawText) - width + 1, width):
            chunk = rawText[idx : idx + width]
            code = 0
            for ch in chunk:
                code = (code << 8) | (ord(ch) & 0xFF)
            mapped = currentTable.get(code)
            if mapped is not None:
                pieces.append(mapped)
            elif width == 1:
                pieces.append(chunk)
        return "".join(pieces)

    for kind, value in tokenizeContentStream(content):
        if kind in ("string", "hexstring", "number", "name"):
            (arrayStack[-1] if arrayStack else operands).append((kind, value))
            continue
        if kind == "array_start":
            arrayStack.append([])
            continue
        if kind == "array_end":
            finished = arrayStack.pop() if arrayStack else []
            (arrayStack[-1] if arrayStack else operands).append(("array", finished))
            continue
        if kind in ("dict_start", "dict_end"):
            continue
        if kind == "operator":
            if value == "Tf" and len(operands) >= 2 and operands[-2][0] == "name":
                fontName = operands[-2][1].lstrip("/")
                fontInfo = fontTables.get(fontName)
                if fontInfo is not None:
                    currentTable, currentByteWidth = fontInfo
                else:
                    currentTable, currentByteWidth = None, 1
            elif value in ("Tj", "'", '"'):
                if operands and operands[-1][0] in ("string", "hexstring"):
                    output.append(decodeOperand(operands[-1][1]))
                    output.append(" ")
            elif value == "TJ":
                if operands and operands[-1][0] == "array":
                    for elemKind, elemValue in operands[-1][1]:
                        if elemKind in ("string", "hexstring"):
                            output.append(decodeOperand(elemValue))
                    output.append(" ")
            operands = []
            arrayStack = []
    return "".join(output)
