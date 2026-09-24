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
Annotation comments: the markup annotations a reviewer adds with who, when, the text, the reply
thread and review state, and whether each is still in the document, was taken
out by a later version, or was never linked to a page at all.
"""

import html
import re
from bisect import bisect_right
from datetime import datetime

MARKUP_SUBTYPES = {
    "Text",
    "FreeText",
    "Line",
    "Square",
    "Circle",
    "Polygon",
    "PolyLine",
    "Highlight",
    "Underline",
    "Squiggly",
    "StrikeOut",
    "Stamp",
    "Caret",
    "Ink",
    "FileAttachment",
    "Sound",
    "Redact",
}

FLAG_NAMES = (
    (1, "Invisible"),
    (2, "Hidden"),
    (4, "Print"),
    (8, "NoZoom"),
    (16, "NoRotate"),
    (32, "NoView"),
    (64, "ReadOnly"),
    (128, "Locked"),
    (256, "ToggleNoView"),
    (512, "LockedContents"),
)

_DATE = re.compile(
    r"\s*(?:D:)?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?"
    r"(?:([Zz])|([+\-])(\d{2})(?:'?(\d{2})'?)?)?"
)

_WHITE = rb"[ \t\r\n\x00\x0c]"
_SYNTAX_TOKEN = re.compile(
    rb"%[^\r\n]*"
    rb"|(\d+)" + _WHITE + rb"+\d+" + _WHITE + rb"+obj\b"
    rb"|\bendobj\b"
    rb"|(?<![A-Za-z/])startxref\b|(?<![A-Za-z/])xref\b|(?<![A-Za-z/])trailer\b"
    rb"|(?<![A-Za-z/])stream(?=[ \t]*(?:\r\n|\r|\n))"
    rb"|\("
)
_STRING_PIECE = re.compile(rb"[()\\]")
_EOF_LINE = re.compile(rb"%%EOF[^\r\n]*")
MAX_COMMENT_TEXT = 1000
MAX_STRAY_PARENTHESES = 50
MAX_STRING_DEPTH = 64


def parsePDFDate(text):
    """
    A PDF date (D:YYYYMMDDHHmmSSOHH'mm') as ISO 8601, or the text itself if it isn't.
    """
    match = _DATE.match(text or "")
    if not match:
        return text or None
    year, month, day, hour, minute, second = (
        int(part) if part else default
        for part, default in zip(match.groups()[:6], (0, 1, 1, 0, 0, 0))
    )
    try:
        stamp = datetime(year, month, day, hour, minute, second)
    except ValueError:
        return text
    result = stamp.isoformat()
    if match.group(7):
        result += "+00:00"
    elif match.group(8):
        result += f"{match.group(8)}{match.group(9)}:{match.group(10) or '00'}"
    return result


def oneLine(text, width=None):
    """
    The text on one line, cut to 'width' with "..." if it is longer
    """
    text = re.sub(r"\s+", " ", text or "").strip()
    if width and len(text) > width:
        text = text[: width - 3] + "..."
    return text


def printableText(text):
    """
    The text with everything but printable ASCII shown as a dot
    """
    return "".join(char if " " <= char <= "~" else "." for char in text)


def commentObjectLabel(comment):
    """
    An "Inline annotation" label for this comment
    """
    return (
        f'Object {comment["object_id"]}'
        if comment["object_id"] is not None
        else "Inline annotation"
    )


def commentObjectTag(comment):
    """
    An "(inline)" tag for this comment
    """
    return (
        f'#{comment["object_id"]}' if comment["object_id"] is not None else "(inline)"
    )


def commentNotes(comment):
    """
    Annotation comment notes
    """
    notes = []
    if comment["status"] == "removed":
        notes.append(f'removed in version {comment["removed_in"]}')
    elif comment["status"] == "orphan":
        notes.append("orphan: no page lists it")
    if "Hidden" in comment["flags"] or "NoView" in comment["flags"]:
        notes.append("hidden")
    if comment["edited"]:
        notes.append(f'edited ({len(comment["history"])} versions)')
    if comment["state"]:
        notes.append(f'{comment["state_model"] or "state"}: {comment["state"]}')
    return notes


def _resolve(pdfFile, element, version):
    if element is None or element == []:
        return None, None
    if element.getType() == "reference":
        return pdfFile.getObjectAtVersion(element.getId(), version), element.getId()
    return element, None


def _text(pdfFile, obj, name, version):
    element, _ = _resolve(pdfFile, obj.getElementByName(name), version)
    if element is None:
        return None
    kind = element.getType()
    if kind == "stream":
        value = element.getStream()
    elif kind in ("string", "hexstring", "name"):
        value = element.getValue()
    else:
        return None
    if isinstance(value, bytes):
        value = value.decode("latin-1")
    return value


def _plainText(rich):
    """
    The text of an /RC value, without its XHTML markup
    """
    if not rich:
        return None
    text = html.unescape(re.sub(r"<[^>]*>", " ", rich))
    return re.sub(r"\s+", " ", text).strip() or None


def _integer(pdfFile, obj, name, version):
    element, _ = _resolve(pdfFile, obj.getElementByName(name), version)
    if element is not None and element.getType() == "integer":
        return element.getRawValue()
    return None


def _catalog(pdfFile, version):
    """
    The catalog as of 'version'.
    A linearized file may name it in one version and define it in another.
    """
    order = (
        [version]
        + list(range(version - 1, -1, -1))
        + list(range(version + 1, pdfFile.updates + 1))
    )
    for v in order:
        catalogId = pdfFile.getCatalogObjectId(v)
        if catalogId is None:
            continue
        catalog = pdfFile.getObjectAtVersion(catalogId, version) or pdfFile.getObject(
            catalogId
        )
        if catalog is not None:
            return catalog
    return None


def _pages(pdfFile, version):
    """
    [(page number, page dictionary, page object id)] in page-tree order.
    Without a tree, every /Type /Page object.
    """
    catalog = _catalog(pdfFile, version)
    root = None
    if catalog is not None:
        root, _ = _resolve(pdfFile, catalog.getElementByName("/Pages"), version)
    pages = []
    if root is not None:
        seen = set()
        stack = [(id(root), root, None)]
        while stack:
            key, node, nodeId = stack.pop()
            if key in seen or node.getType() != "dictionary":
                continue
            seen.add(key)
            kids, _ = _resolve(pdfFile, node.getElementByName("/Kids"), version)
            if kids is not None and kids.getType() == "array":
                children = []
                for kid in kids.getElements():
                    child, childId = _resolve(pdfFile, kid, version)
                    if child is not None:
                        children.append(
                            (
                                childId if childId is not None else id(child),
                                child,
                                childId,
                            )
                        )
                stack.extend(reversed(children))
            else:
                pages.append((len(pages) + 1, node, nodeId))
        return pages
    body = pdfFile.body[version]
    for objectId in sorted(body.objects):
        obj = body.getObject(objectId)
        if obj is not None and obj.getType() == "dictionary":
            kind = obj.getElementByName("/Type")
            if kind and kind != [] and kind.getValue() == "/Page":
                pages.append((len(pages) + 1, obj, objectId))
    return pages


def _linkedAnnotations(pdfFile, version):
    """
    {key: (page number, position on the page, page object id, inline object
    or None)} of what the pages of this 'version' lists, where key is the object id.
    """
    linked = {}
    for number, page, pageId in _pages(pdfFile, version):
        annots, _ = _resolve(pdfFile, page.getElementByName("/Annots"), version)
        if annots is None or annots.getType() != "array":
            continue
        for position, element in enumerate(annots.getElements()):
            if element is None:
                continue
            if element.getType() == "reference":
                linked.setdefault(element.getId(), (number, position, pageId, None))
            elif element.getType() == "dictionary":
                linked.setdefault(
                    ("inline", id(element)), (number, position, pageId, element)
                )
    return linked


def _subtype(obj):
    if obj is None or obj.getType() != "dictionary":
        return None
    subtype = obj.getElementByName("/Subtype")
    if subtype is None or subtype == []:
        return None
    return subtype.getValue().lstrip("/")


def _checksumHex(pdfFile, params, version):
    """
    /Params /CheckSum as a hex string (MD5).
    """
    checksum, _ = _resolve(pdfFile, params.getElementByName("/CheckSum"), version)
    if checksum is None or checksum.getType() not in ("string", "hexstring"):
        return None
    return checksum.getValue() or None


def fileSpecInfo(pdfFile, spec, version):
    info = {
        "file_name": None,
        "description": None,
        "stream_id": None,
        "size": None,
        "mime_type": None,
        "checksum_md5": None,
    }
    if spec is None:
        return info
    if spec.getType() != "dictionary":
        info["file_name"] = (
            spec.getValue() if spec.getType() in ("string", "hexstring") else None
        )
        return info
    info["file_name"] = _text(pdfFile, spec, "/UF", version) or _text(
        pdfFile, spec, "/F", version
    )
    info["description"] = _text(pdfFile, spec, "/Desc", version)
    embedded, _ = _resolve(pdfFile, spec.getElementByName("/EF"), version)
    if embedded is None or embedded.getType() != "dictionary":
        return info
    for key in ("/UF", "/F"):
        stream, streamId = _resolve(pdfFile, embedded.getElementByName(key), version)
        if stream is not None and stream.getType() == "stream":
            info["stream_id"] = streamId
            params, _ = _resolve(pdfFile, stream.getElementByName("/Params"), version)
            if params is not None and params.getType() == "dictionary":
                info["size"] = _integer(pdfFile, params, "/Size", version)
                info["checksum_md5"] = _checksumHex(pdfFile, params, version)
            if info["size"] is None:
                info["size"] = stream.getDeclaredLength()
            subtype = stream.getElementByName("/Subtype")
            if subtype and subtype != []:
                info["mime_type"] = subtype.getValue().lstrip("/").replace("#2F", "/")
            break
    return info


def _attachment(pdfFile, obj, version):
    spec, _ = _resolve(pdfFile, obj.getElementByName("/FS"), version)
    return fileSpecInfo(pdfFile, spec, version)


def _flags(pdfFile, obj, version):
    value = _integer(pdfFile, obj, "/F", version)
    return [name for bit, name in FLAG_NAMES if value and value & bit]


def _rect(pdfFile, obj, version):
    rect, _ = _resolve(pdfFile, obj.getElementByName("/Rect"), version)
    if rect is None or rect.getType() != "array":
        return None
    try:
        return [round(float(element.getValue()), 2) for element in rect.getElements()]
    except (TypeError, ValueError):
        return None


def _describe(pdfFile, objectId, obj, version):
    """
    The comment fields of one annotation dictionary, as of 'version'
    """
    reply, replyId = _resolve(pdfFile, obj.getElementByName("/IRT"), version)
    popup, popupId = _resolve(pdfFile, obj.getElementByName("/Popup"), version)
    replyType = obj.getElementByName("/RT")
    created = _text(pdfFile, obj, "/CreationDate", version)
    modified = _text(pdfFile, obj, "/M", version)
    rich = _text(pdfFile, obj, "/RC", version)
    entry = {
        "object_id": objectId,
        "subtype": _subtype(obj),
        "author": _text(pdfFile, obj, "/T", version),
        "subject": _text(pdfFile, obj, "/Subj", version),
        "contents": _text(pdfFile, obj, "/Contents", version),
        "rich_text": _plainText(rich),
        "created": parsePDFDate(created) if created else None,
        "modified": parsePDFDate(modified) if modified else None,
        "name": _text(pdfFile, obj, "/NM", version),
        "reply_to": replyId if reply is not None else None,
        "reply_type": (
            replyType.getValue().lstrip("/") if replyType and replyType != [] else None
        ),
        "state_model": _text(pdfFile, obj, "/StateModel", version),
        "state": _text(pdfFile, obj, "/State", version),
        "popup_id": popupId if popup is not None else None,
        "rect": _rect(pdfFile, obj, version),
        "flags": _flags(pdfFile, obj, version),
    }
    if entry["subtype"] == "FileAttachment":
        entry["attachment"] = _attachment(pdfFile, obj, version)
    return entry


def _history(pdfFile, objectId, upToVersion):
    """
    Every version that defines the object, oldest first, with what it said at that time
    """
    history = []
    for v in range(upToVersion + 1):
        obj = pdfFile.body[v].getObject(objectId)
        if obj is None or obj.getType() != "dictionary":
            continue
        entry = _describe(pdfFile, objectId, obj, v)
        history.append(
            {
                "version": v,
                "contents": entry["contents"],
                "author": entry["author"],
                "modified": entry["modified"],
                "state": entry["state"],
            }
        )
    return history


def _threads(comments):
    """
    Adds thread_root, depth, replies and group_members to every comment
    """
    byId = {c["object_id"]: c for c in comments if c["object_id"] is not None}
    for comment in comments:
        comment["replies"] = []
        comment["group_members"] = []
    for comment in comments:
        parent = byId.get(comment["reply_to"])
        if parent is not None and parent is not comment:
            key = "group_members" if comment["reply_type"] == "Group" else "replies"
            parent[key].append(comment["object_id"])
    for comment in comments:
        depth, node, seen = 0, comment, {comment["object_id"]}
        while True:
            parent = byId.get(node["reply_to"])
            if parent is None or parent["object_id"] in seen:
                break
            seen.add(parent["object_id"])
            node = parent
            depth += 1
        comment["thread_root"] = node["object_id"]
        comment["depth"] = depth


def getComments(pdfFile, version=None):
    """
    The markup annotations of the document as of 'version', each with a "status":
    "present" (a page lists it),
    "removed" (an earlier version's page listed it, this one doesn't,
    or "orphan" (no version's page ever listed it).
    "version" is the version that first defines it,
    and "history" every definition of it.
    "inline" is True for an annotation written directly inside /Annots rather
    than as an object of its own.
    """
    last = pdfFile.updates if version is None else version
    linked = [_linkedAnnotations(pdfFile, v) for v in range(last + 1)]
    everKeys = set()
    for entries in linked:
        everKeys.update(entries)

    comments = []
    for key in everKeys:
        isInline = isinstance(key, tuple)
        seenAt = [v for v in range(last + 1) if key in linked[v]]
        if isInline:
            describeAt = seenAt[-1]
            obj = linked[describeAt][key][3]
        else:
            describeAt = last
            obj = pdfFile.getObjectAtVersion(key, last)
        if _subtype(obj) not in MARKUP_SUBTYPES:
            continue
        entry = _describe(pdfFile, None if isInline else key, obj, describeAt)
        entry["inline"] = isInline
        if key in linked[last]:
            entry["status"] = "present"
            entry["removed_in"] = None
            entry["page"], entry["position"], entry["page_object_id"], _ = linked[last][
                key
            ]
        else:
            entry["status"] = "removed"
            entry["removed_in"] = next(
                v for v in range(seenAt[0], last + 1) if key not in linked[v]
            )
            entry["page"], entry["position"], entry["page_object_id"], _ = linked[
                seenAt[-1]
            ][key]
        if isInline:
            entry["history"] = [
                {
                    "version": describeAt,
                    "contents": entry["contents"],
                    "author": entry["author"],
                    "modified": entry["modified"],
                    "state": entry["state"],
                }
            ]
            entry["version"] = describeAt
            entry["edited"] = False
        comments.append(entry)

    everObjectIds = {key for key in everKeys if not isinstance(key, tuple)}
    for v in range(last + 1):
        for objectId in pdfFile.body[v].objects:
            if objectId in everObjectIds:
                continue
            obj = pdfFile.getObjectAtVersion(objectId, last)
            if _subtype(obj) not in MARKUP_SUBTYPES:
                continue
            everObjectIds.add(objectId)
            entry = _describe(pdfFile, objectId, obj, last)
            entry.update(
                status="orphan",
                removed_in=None,
                page=None,
                position=None,
                page_object_id=None,
                inline=False,
            )
            comments.append(entry)

    for entry in comments:
        if entry["inline"]:
            continue
        entry["history"] = _history(pdfFile, entry["object_id"], last)
        entry["version"] = entry["history"][0]["version"] if entry["history"] else None
        entry["edited"] = len(entry["history"]) > 1

    _threads(comments)
    order = {"present": 0, "removed": 1, "orphan": 2}
    comments.sort(
        key=lambda c: (
            order[c["status"]],
            c["page"] if c["page"] is not None else 0,
            c["position"] if c["position"] is not None else 0,
            c["object_id"] if c["object_id"] is not None else -1,
        )
    )
    return comments


def _skipString(data, pos):
    """
    Where the literal string that starts just before 'pos' ends, or None when it is never closed or strangely nested
    """
    depth = 1
    while True:
        piece = _STRING_PIECE.search(data, pos)
        if piece is None:
            return None
        char = data[piece.start()]
        if char == 0x5C:  # a backslash takes the next byte with it
            pos = piece.end() + 1
        elif char == 0x28:
            depth += 1
            if depth > MAX_STRING_DEPTH:
                return None
            pos = piece.end()
        else:
            depth -= 1
            pos = piece.end()
            if depth == 0:
                return pos


def _versionEnds(data):
    """
    Where each version ends: the end of the line holding each %%EOF, as the parser splits the file
    """
    return [m.end() for m in _EOF_LINE.finditer(data)]


def scanSyntaxComments(data):
    """
    The % comments of the file, found by reading it as PDF syntax.
    Does not include those inside strings or streams, the %PDF header,
    the binary marker, or any %%EOF.
    """
    ends = _versionEnds(data)
    comments = []
    where, objectId = "between objects", None
    headerSeen = False
    objectSeen = False
    strays = 0
    pos = 0
    length = len(data)
    while pos < length:
        token = _SYNTAX_TOKEN.search(data, pos)
        if token is None:
            break
        text = token.group(0)
        pos = token.end()
        if text[:1] == b"%":
            body = text[1:]
            if body.rstrip(b" \t") == b"%EOF":
                where, objectId = "between objects", None
                continue
            if not headerSeen and (
                body.startswith(b"PDF-") or body.startswith(b"!PS-Adobe-")
            ):
                headerSeen = True
                continue
            if (
                not objectSeen
                and len(body) >= 4
                and all(byte >= 0x80 for byte in body[:4])
            ):
                continue
            version = bisect_right(ends, token.start())
            if ends and version == len(ends):
                version, place = None, "after the last %%EOF"
            else:
                place = where
            comments.append(
                {
                    "offset": token.start(),
                    "length": len(body),
                    "text": body[:MAX_COMMENT_TEXT].decode("latin-1"),
                    "truncated": len(body) > MAX_COMMENT_TEXT,
                    "version": version,
                    "location": place,
                    "object_id": (
                        objectId if place == where and objectId is not None else None
                    ),
                }
            )
        elif token.group(1) is not None:
            objectSeen = True
            objectId = int(token.group(1))
            where = f"object {objectId}"
        elif text == b"endobj":
            where, objectId = "between objects", None
        elif text == b"xref":
            where = "xref table"
        elif text in (b"trailer", b"startxref"):
            where = "trailer"
        elif text == b"stream":
            end = data.find(b"endstream", pos)
            pos = length if end == -1 else end + len(b"endstream")
        elif text == b"(":
            if strays < MAX_STRAY_PARENTHESES:
                end = _skipString(data, pos)
                if end is None:
                    strays += 1
                else:
                    pos = end
    return comments
