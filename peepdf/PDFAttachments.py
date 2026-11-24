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
#        the Free Software Foundation, either version 3 of the License,
#        or (at your option) any later version.
#
#        peepdf-3 is distributed in the hope that it will be useful,
#        but WITHOUT ANY WARRANTY; without even the implied warranty of
#        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#        GNU General Public License for more details.
#
#        You should have received a copy of the GNU General Public License
#        along with peepdf-3. If not, see <http://www.gnu.org/licenses/>.

"""
Attachments: a file can be attached either with a /FileAttachment
annotation or an entry in the Catalog's /Names /EmbeddedFiles tree.
This module extracts them and performs local static analysis
(hash, entropy, magic bytes, YARA). No external services are used.
"""

import math
import hashlib
import os
from collections import Counter

try:
    import yara
except ImportError:
    yara = None

try:
    from peepdf.PDFComments import _catalog, _resolve, fileSpecInfo, getComments
except ModuleNotFoundError:
    from PDFComments import _catalog, _resolve, fileSpecInfo, getComments

MAX_NAME_TREE_NODES = 10000
MAX_NAME_TREE_DEPTH = 64

HIGH_ENTROPY_THRESHOLD = 7.5
YARA_TIMEOUT_SECONDS = 30
RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")

EXECUTABLE_TYPES = (
    "Windows PE",
    "Linux ELF",
    "Mach-O Binary",
    "Java Class / Mach-O Universal Binary",
)
COMPRESSED_TYPES = (
    "ZIP Archive",
    "RAR Archive",
    "7-Zip Archive",
    "GZIP Archive",
    "BZIP2 Archive",
    "XZ Archive",
    "PNG Image",
    "JPEG Image",
    "GIF Image",
    "MP3 Audio",
    "OGG Media",
    "FLAC Audio",
    "PDF Document",
)
SCRIPT_EXTENSIONS = (
    ".bat",
    ".cmd",
    ".ps1",
    ".psm1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
    ".sh",
    ".py",
    ".pl",
    ".lnk",
    ".scr",
)
EXECUTABLE_EXTENSIONS = (
    ".exe",
    ".dll",
    ".sys",
    ".com",
    ".msi",
    ".elf",
    ".so",
    ".dylib",
    ".jar",
    ".apk",
)
MACRO_EXTENSIONS = (
    ".docm",
    ".xlsm",
    ".pptm",
    ".dotm",
    ".xltm",
    ".xlam",
    ".doc",
    ".xls",
    ".ppt",
    ".rtf",
)


def _nameTreeEntries(pdfFile, node, version, seen, depth=0):
    """
    Recursively extract entries from a PDF name tree.
    Limits on depth and number of visited nodes prevent excessive
    recursion and repeated processing of cyclic structures.
    """
    if node is None or node.getType() != "dictionary" or depth > MAX_NAME_TREE_DEPTH:
        return []
    key = id(node)
    if key in seen or len(seen) >= MAX_NAME_TREE_NODES:
        return []
    seen.add(key)
    entries = []
    kids, _ = _resolve(pdfFile, node.getElementByName("/Kids"), version)
    if kids is not None and kids.getType() == "array":
        for kid in kids.getElements():
            child, _ = _resolve(pdfFile, kid, version)
            entries.extend(_nameTreeEntries(pdfFile, child, version, seen, depth + 1))
    # A malformed node may have both /Kids and /Names: read both, since
    # an attacker can hide an entry in the part a viewer would skip.
    names, _ = _resolve(pdfFile, node.getElementByName("/Names"), version)
    if names is None or names.getType() != "array":
        return entries
    elements = names.getElements()
    for i in range(0, len(elements) - 1, 2):
        nameObj = elements[i]
        if nameObj is None or nameObj.getType() not in ("string", "hexstring"):
            continue
        entries.append((nameObj.getValue(), elements[i + 1]))
    return entries


def _lastDefiningVersion(pdfFile, objectId, upToVersion):
    """
    Return the most recent PDF revision at or before upToVersion
    which defines objectId.
    """
    if objectId is None:
        return None
    for version in range(upToVersion, -1, -1):
        if pdfFile.body[version].getObject(objectId) is not None:
            return version
    return None


def getEmbeddedFileAttachments(pdfFile, version=None):
    """
    Extract attachments referenced by the Catalog's
    /Names /EmbeddedFiles tree.
    """
    last = pdfFile.updates if version is None else version
    catalog = _catalog(pdfFile, last)
    if catalog is None:
        return []
    names, _ = _resolve(pdfFile, catalog.getElementByName("/Names"), last)
    if names is None or names.getType() != "dictionary":
        return []
    embeddedFilesRoot, _ = _resolve(
        pdfFile, names.getElementByName("/EmbeddedFiles"), last
    )
    if embeddedFilesRoot is None:
        return []
    attachments = []
    for name, valueRef in _nameTreeEntries(pdfFile, embeddedFilesRoot, last, set()):
        spec, specId = _resolve(pdfFile, valueRef, last)
        info = fileSpecInfo(pdfFile, spec, last) or {}
        streamId = info.get("stream_id")
        attachments.append(
            {
                "source": "embedded_files",
                "location": "document (Names tree)",
                "page": None,
                "object_id": specId,
                "name_tree_key": name,
                "nav_id": streamId,
                "nav_version": _lastDefiningVersion(pdfFile, streamId, last),
                **info,
            }
        )
    return attachments


def getAnnotationAttachments(pdfFile, version=None):
    """
    Extract attachments referenced by /FileAttachment annotations.
    """
    last = pdfFile.updates if version is None else version
    attachments = []
    for comment in getComments(pdfFile, version):
        if comment["subtype"] != "FileAttachment":
            continue
        info = comment.get("attachment") or {}
        if comment["status"] == "present":
            location = f'page {comment["page"]}'
        elif comment["status"] == "removed":
            location = (
                f'page {comment["page"]} '
                f'(removed in version {comment["removed_in"]})'
            )
        else:
            location = "orphan annotation (not linked to any page)"
        streamId = info.get("stream_id")
        if streamId is not None:
            navId = streamId
            navVersion = _lastDefiningVersion(pdfFile, streamId, last)
        else:
            navId = comment["object_id"]
            navVersion = (
                comment["history"][-1]["version"]
                if comment["history"]
                else comment["version"]
            )
        attachments.append(
            {
                "source": "annotation",
                "location": location,
                "page": comment["page"],
                "object_id": comment["object_id"],
                "name_tree_key": None,
                "nav_id": navId,
                "nav_version": navVersion,
                **info,
            }
        )
    return attachments


def getAttachments(pdfFile, version=None):
    """
    Return every attachment in the document as of the requested
    PDF revision.
    """
    attachments = getAnnotationAttachments(
        pdfFile, version
    ) + getEmbeddedFileAttachments(pdfFile, version)
    attachments.sort(
        key=lambda attachment: (
            0 if attachment.get("page") is not None else 1,
            attachment.get("page") or 0,
            attachment.get("file_name") or "",
        )
    )
    return attachments


def checkMagicBytes(data):
    """
    Identify the probable file type using magic bytes,
    independently of the file extension.
    """
    if not isinstance(data, (bytes, bytearray)):
        return "Invalid input (expected binary data)"
    if not data:
        return "Empty"
    # "MZ" alone is also plain text: require the PE header pointer
    if data.startswith(b"MZ") and len(data) >= 0x40:
        peOffset = int.from_bytes(data[0x3C:0x40], "little")
        if data[peOffset : peOffset + 4] == b"PE\x00\x00":
            return "Windows PE (.exe/.dll/.sys)"
        return "Windows PE / DOS (MZ header, no valid PE signature)"
    if data.startswith(b"\x7fELF"):
        return "Linux ELF"
    if data.startswith(
        (
            b"\xfe\xed\xfa\xce",
            b"\xfe\xed\xfa\xcf",
            b"\xce\xfa\xed\xfe",
            b"\xcf\xfa\xed\xfe",
        )
    ):
        return "Mach-O Binary"
    if data.startswith(b"\xca\xfe\xba\xbe"):
        return "Java Class / Mach-O Universal Binary"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "OLE2 Compound File (legacy Office / MSI)"
    if data.startswith(b"{\\rt"):
        return "RTF Document"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP Archive / OOXML / JAR / APK"
    if data.startswith((b"PK\x05\x06", b"PK\x07\x08")):
        return "ZIP Archive"
    if data.startswith(b"%PDF-"):
        return "PDF Document"
    if data.startswith(b"Rar!\x1a\x07"):
        return "RAR Archive"
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7-Zip Archive"
    if data.startswith(b"\x1f\x8b"):
        return "GZIP Archive"
    if data.startswith(b"BZh"):
        return "BZIP2 Archive"
    if data.startswith(b"\xfd7zXZ\x00"):
        return "XZ Archive"
    if data.startswith(b"SQLite format 3\x00"):
        return "SQLite Database"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG Image"
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG Image"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "GIF Image"
    # "BM" alone is also plain text: check the declared size field
    if (
        data.startswith(b"BM")
        and len(data) >= 14
        and int.from_bytes(data[2:6], "little") == len(data)
    ):
        return "BMP Image"
    if data.startswith((b"II*\x00", b"MM\x00*")):
        return "TIFF Image"
    if data.startswith(b"\x00\x00\x01\x00"):
        return "ICO Image"
    if data.startswith(b"\x00\x00\x02\x00"):
        return "CUR Image"
    if data.startswith(b"RIFF"):
        return "RIFF Container (WAV/AVI/WEBP)"
    if data.startswith(b"ID3"):
        return "MP3 Audio"
    if data.startswith(b"OggS"):
        return "OGG Media"
    if data.startswith(b"fLaC"):
        return "FLAC Audio"
    if data.startswith(b"#!"):
        return "Script (shebang)"
    if data.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "Windows Shortcut (LNK)"
    return "Unknown / Custom data"


def calculateEntropy(data):
    """
    Calculate Shannon entropy for binary data.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Entropy calculation requires binary data")
    if not data:
        return 0.0
    frequencies = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return round(entropy, 2)


def _extensionRisk(fileName):
    """
    Classify the declared file extension.
    """
    if not fileName:
        return None
    lower = str(fileName).lower().rstrip(". ")
    if lower.endswith(EXECUTABLE_EXTENSIONS):
        return "executable"
    if lower.endswith(SCRIPT_EXTENSIONS):
        return "script"
    if lower.endswith(MACRO_EXTENSIONS):
        return "macro_capable_document"
    return None


_compiledRulesCache = {}


def loadYaraRules(rulesDir=RULES_DIR):
    """
    Compile every .yar/.yara file in rulesDir.
    Each file is checked on its own first, so one broken file does not
    disable all the others. The result is cached per directory.
    Returns (compiledRules, errors) where errors maps file -> message.
    """
    if rulesDir in _compiledRulesCache:
        return _compiledRulesCache[rulesDir]
    errors = {}
    if yara is None:
        result = (None, {"yara": "yara-python is not installed"})
        _compiledRulesCache[rulesDir] = result
        return result
    goodFiles = {}
    if os.path.isdir(rulesDir):
        for filename in sorted(os.listdir(rulesDir)):
            if not filename.lower().endswith((".yar", ".yara")):
                continue
            path = os.path.join(rulesDir, filename)
            try:
                yara.compile(filepath=path, externals={"filepath": ""})
                goodFiles[filename] = path
            except yara.Error as error:
                errors[filename] = str(error)
    compiledRules = None
    if goodFiles:
        try:
            compiledRules = yara.compile(
                filepaths=goodFiles, externals={"filepath": ""}
            )
        except yara.Error as error:
            errors["<combined>"] = str(error)
    result = (compiledRules, errors)
    _compiledRulesCache[rulesDir] = result
    return result


def analyzePayload(
    data,
    compiledRules=None,
    fileName=None,
    declaredSize=None,
    declaredMd5=None,
    yaraErrors=None,
):
    """
    Perform local static security analysis on an extracted payload:
    SHA256/MD5, Shannon entropy, magic bytes, extension checks,
    integrity checks against /Params and local YARA scanning.
    No external API calls are performed.
    """
    if not isinstance(data, (bytes, bytearray)):
        return {
            "status": "error",
            "error": "Payload must be binary data",
            "is_suspicious": None,
        }
    if not data:
        return {"status": "empty", "is_suspicious": None}
    data = bytes(data)
    entropyVal = calculateEntropy(data)
    magicType = checkMagicBytes(data)
    md5 = hashlib.md5(data).hexdigest()

    yaraHits = []
    yaraError = None
    if compiledRules is not None:
        try:
            matches = compiledRules.match(data=data, timeout=YARA_TIMEOUT_SECONDS)
            yaraHits = [f"{m.namespace}:{m.rule}" for m in matches]
            yaraStatus = "scanned"
        except Exception as error:
            yaraStatus = "error"
            yaraError = str(error)
    elif yaraErrors:
        yaraStatus = "error"
    else:
        yaraStatus = "not_configured"
    if yaraErrors:
        if yaraStatus == "scanned":
            yaraStatus = "partial"

    extRisk = _extensionRisk(fileName)
    highRiskType = magicType.startswith(EXECUTABLE_TYPES)
    # High entropy is expected for compressed formats
    highEntropy = entropyVal > HIGH_ENTROPY_THRESHOLD and not magicType.startswith(
        COMPRESSED_TYPES
    )
    # Declared extension does not match the real content
    extensionMismatch = (
        (highRiskType and extRisk != "executable")
        or (magicType == "Script (shebang)" and extRisk != "script")
        or (
            magicType == "PDF Document"
            and fileName is not None
            and not str(fileName).lower().endswith(".pdf")
        )
    )
    sizeMismatch = (
        declaredSize is not None
        and isinstance(declaredSize, int)
        and declaredSize != len(data)
    )
    md5Mismatch = False
    if declaredMd5:
        # /CheckSum is a 16-byte string; it may also arrive already in hex
        declared = declaredMd5
        if isinstance(declared, (bytes, bytearray)):
            declared = bytes(declared).hex()
        elif len(declared) == 16:
            declared = declared.encode("latin-1", "replace").hex()
        md5Mismatch = declared.lower() != md5

    indicators = {
        "high_entropy": highEntropy,
        "high_risk_file_type": highRiskType,
        "risky_extension": extRisk,
        "extension_mismatch": extensionMismatch,
        "size_mismatch": sizeMismatch,
        "checksum_mismatch": md5Mismatch,
        "local_yara_detection": bool(yaraHits),
    }
    triggered = (
        highEntropy
        or highRiskType
        or extRisk is not None
        or extensionMismatch
        or sizeMismatch
        or md5Mismatch
        or bool(yaraHits)
    )
    if triggered:
        isSuspicious = True
    elif yaraStatus in ("error", "not_configured"):
        # Nothing found, but the scan was incomplete: no verdict
        isSuspicious = None
    else:
        isSuspicious = False

    result = {
        "status": "analyzed",
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": md5,
        "entropy": entropyVal,
        "true_file_type": magicType,
        "local_yara_status": yaraStatus,
        "local_yara_matches": yaraHits,
        "indicators": indicators,
        "is_suspicious": isSuspicious,
    }
    if yaraError:
        result["yara_error"] = yaraError
    if yaraErrors:
        result["yara_rule_errors"] = dict(yaraErrors)
    return result


def _getStreamBytes(pdfObj):
    """
    Return the decoded bytes of a PDF stream object.
    Streams without /Filter are already plain data: peepdf's decode()
    returns (-1, 'Not encoded stream') for them, which is not an error.
    """
    if pdfObj.getType() != "stream":
        raise ValueError("Attachment object is not a stream")
    if hasattr(pdfObj, "isEncoded"):
        isEncoded = pdfObj.isEncoded()
    else:
        isEncoded = pdfObj.getElementByName("/Filter") is not None
    if isEncoded:
        decodeResult = pdfObj.decode()
        if not isinstance(decodeResult, tuple) or len(decodeResult) < 2:
            raise ValueError("Unexpected stream decoding result")
        if decodeResult[0] == -1:
            raise ValueError(f"Stream decoding failed: {decodeResult[1]}")
        if getattr(pdfObj, "decodingError", False):
            raise ValueError("Stream decoding failed")
        rawData = pdfObj.decodedStream
    else:
        rawData = pdfObj.decodedStream
        if not rawData and hasattr(pdfObj, "getRawStream"):
            rawData = pdfObj.getRawStream()
    if isinstance(rawData, bytearray):
        return bytes(rawData)
    if isinstance(rawData, str):
        return rawData.encode("latin-1")
    if isinstance(rawData, bytes):
        return rawData
    raise TypeError("Decoded stream is not binary data")


def _declaredParamsSize(pdfFile, streamObj, version):
    """
    Return /Params /Size of an embedded file stream, or None.
    attachment["size"] cannot be used for the comparison: when /Params
    /Size is missing, fileSpecInfo falls back to /Length, which is the
    size of the *encoded* data and differs from the decoded size for
    any compressed stream.
    """
    params, _ = _resolve(pdfFile, streamObj.getElementByName("/Params"), version)
    if params is None or params.getType() != "dictionary":
        return None
    size, _ = _resolve(pdfFile, params.getElementByName("/Size"), version)
    if size is None or size.getType() not in ("integer", "real"):
        return None
    try:
        return int(size.getValue())
    except (TypeError, ValueError):
        return None


def suspiciousLabel(analysis):
    value = analysis.get("is_suspicious")
    if value is True:
        return "YES"
    if value is False:
        return "no"
    return "unknown"


def analyzeAttachments(pdfFile, version=None, rulesDir=RULES_DIR):
    """
    Extract attachments and perform static security analysis
    on each decoded embedded stream.
    YARA rules are compiled locally. No external services
    or online threat intelligence APIs are used.
    """
    compiledRules, yaraErrors = loadYaraRules(rulesDir)
    attachments = getAttachments(pdfFile, version)
    for attachment in attachments:
        streamId = attachment.get("stream_id")
        if streamId is None:
            # there is no embedded data to analyse
            attachment["security_analysis"] = {
                "status": "no_embedded_stream",
                "is_suspicious": None,
            }
            continue
        streamVersion = attachment.get("nav_version")
        if streamVersion is None:
            attachment["security_analysis"] = {
                "status": "error",
                "error": "Stream object not found in any revision",
                "is_suspicious": None,
            }
            continue
        try:
            pdfObj = pdfFile.body[streamVersion].getObject(streamId)
            if pdfObj is None:
                raise ValueError("PDF object not found")
            rawData = _getStreamBytes(pdfObj)
            attachment["security_analysis"] = analyzePayload(
                rawData,
                compiledRules,
                fileName=attachment.get("file_name"),
                declaredSize=_declaredParamsSize(pdfFile, pdfObj, streamVersion),
                declaredMd5=attachment.get("checksum_md5"),
                yaraErrors=yaraErrors,
            )
        except Exception as error:
            analysisError = {
                "status": "error",
                "error": f"Attachment analysis failed: {error}",
                "is_suspicious": None,
            }
            if yaraErrors:
                analysisError["yara_rule_errors"] = dict(yaraErrors)
            attachment["security_analysis"] = analysisError
    return attachments
