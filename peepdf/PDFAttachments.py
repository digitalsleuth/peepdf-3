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
Attachments: A file can be attached either with /FileAttachment annotation,
or an entry in the Catalog's /Names /EmbeddedFiles tree.
"""

try:
    from peepdf.PDFComments import _catalog, _resolve, fileSpecInfo, getComments
except ModuleNotFoundError:
    from PDFComments import _catalog, _resolve, fileSpecInfo, getComments

MAX_NAME_TREE_NODES = 10000
MAX_NAME_TREE_DEPTH = 64


def _nameTreeEntries(pdfFile, node, version, seen, depth=0):
    if node is None or node.getType() != "dictionary" or depth > MAX_NAME_TREE_DEPTH:
        return []
    key = id(node)
    if key in seen or len(seen) >= MAX_NAME_TREE_NODES:
        return []
    seen.add(key)

    kids, _ = _resolve(pdfFile, node.getElementByName("/Kids"), version)
    if kids is not None and kids.getType() == "array":
        entries = []
        for kid in kids.getElements():
            child, _ = _resolve(pdfFile, kid, version)
            entries.extend(_nameTreeEntries(pdfFile, child, version, seen, depth + 1))
        return entries

    names, _ = _resolve(pdfFile, node.getElementByName("/Names"), version)
    if names is None or names.getType() != "array":
        return []
    elements = names.getElements()
    entries = []
    for i in range(0, len(elements) - 1, 2):
        nameObj = elements[i]
        if nameObj is None or nameObj.getType() not in ("string", "hexstring"):
            continue
        entries.append((nameObj.getValue(), elements[i + 1]))
    return entries


def _lastDefiningVersion(pdfFile, objectId, upToVersion):
    """
    The most recent version at or before 'upToVersion' which defines
    objectId, or None.
    """
    if objectId is None:
        return None
    for v in range(upToVersion, -1, -1):
        if pdfFile.body[v].getObject(objectId) is not None:
            return v
    return None


def getEmbeddedFileAttachments(pdfFile, version=None):
    """
    The Catalog's /Names /EmbeddedFiles entries as of 'version'.
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
        info = fileSpecInfo(pdfFile, spec, last)
        navId = specId if specId is not None else info["stream_id"]
        attachments.append(
            {
                "source": "embedded_files",
                "location": "document (Names tree)",
                "page": None,
                "object_id": specId,
                "name_tree_key": name,
                "nav_id": navId,
                "nav_version": _lastDefiningVersion(pdfFile, navId, last),
                **info,
            }
        )
    return attachments


def getAnnotationAttachments(pdfFile, version=None):
    """
    /FileAttachment annotations as of 'version'.
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
                f'page {comment["page"]} (removed in version {comment["removed_in"]})'
            )
        else:
            location = "orphan annotation (not linked to any page)"
        if comment["object_id"] is not None:
            navId = comment["object_id"]
            navVersion = (
                comment["history"][-1]["version"]
                if comment["history"]
                else comment["version"]
            )
        else:
            navId = info.get("stream_id")
            navVersion = _lastDefiningVersion(pdfFile, navId, last)
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
    Every attachment in the document as of 'version'.
    """
    attachments = getAnnotationAttachments(
        pdfFile, version
    ) + getEmbeddedFileAttachments(pdfFile, version)
    attachments.sort(
        key=lambda a: (
            0 if a["page"] is not None else 1,
            a["page"] if a["page"] is not None else 0,
            a["file_name"] or "",
        )
    )
    return attachments
