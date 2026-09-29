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
Image clipping test to see how much of each placed image is actually visible.
ISO 32000-2:2020 - Chapter 8 - Graphics
CTM - Current Transform Matrix
"""

import math

try:
    from peepdf.PDFAttachments import _lastDefiningVersion
    from peepdf.PDFComments import _pages, _resolve
    from peepdf.PDFFontEncoding import tokenizeContentStream
except ModuleNotFoundError:
    from PDFAttachments import _lastDefiningVersion
    from PDFComments import _pages, _resolve
    from PDFFontEncoding import tokenizeContentStream

MAX_FORM_DEPTH = 12
MAX_IMAGES = 20000
CLIPPED_BELOW = 0.999
IDENTITY = (1.0, 0.0, 0.0, 1.0, 0.0, 0.0)  ## Translation and scaling
_PAINT_OPERATORS = {"S", "s", "f", "F", "f*", "B", "B*", "b", "b*", "n"}  ## Tables 50 and 59 - Operator Categories
_UNIT_SQUARE = ((0.0, 0.0), (1.0, 0.0), (1.0, 1.0), (0.0, 1.0))


def _multiply(first, second):
    """
    first applied, then second (PDF row-vector convention)
    """
    a1, b1, c1, d1, e1, f1 = first
    a2, b2, c2, d2, e2, f2 = second
    return (
        a1 * a2 + b1 * c2,
        a1 * b2 + b1 * d2,
        c1 * a2 + d1 * c2,
        c1 * b2 + d1 * d2,
        e1 * a2 + f1 * c2 + e2,
        e1 * b2 + f1 * d2 + f2,
    )


def _apply(matrix, point):
    a, b, c, d, e, f = matrix
    x, y = point
    return (a * x + c * y + e, b * x + d * y + f)


def _area(polygon):
    total = 0.0
    for i, (x1, y1) in enumerate(polygon):
        x2, y2 = polygon[(i + 1) % len(polygon)]
        total += x1 * y2 - x2 * y1
    return total / 2.0


def _counterClockwise(polygon):
    return polygon if _area(polygon) >= 0 else polygon[::-1]


def _clipConvex(subject, clipper):
    """
    Sutherland-Hodgman algorithm - https://en.wikipedia.org/wiki/Sutherland%E2%80%93Hodgman_algorithm
    The part of convex polygon 'subject' inside convex 'clipper'
    """
    output = list(subject)
    clipper = _counterClockwise(clipper)
    for i, start in enumerate(clipper):
        if not output:
            break
        end = clipper[(i + 1) % len(clipper)]

        def side(point):
            return (end[0] - start[0]) * (point[1] - start[1]) - (end[1] - start[1]) * (
                point[0] - start[0]
            )

        source, output = output, []
        for j, current in enumerate(source):
            previous = source[j - 1]
            currentSide, previousSide = side(current), side(previous)
            if currentSide >= 0:
                if previousSide < 0:
                    output.append(_crossing(previous, current, previousSide, currentSide))
                output.append(current)
            elif previousSide >= 0:
                output.append(_crossing(previous, current, previousSide, currentSide))
    return output


def _crossing(p1, p2, side1, side2):
    t = side1 / (side1 - side2)
    return (p1[0] + t * (p2[0] - p1[0]), p1[1] + t * (p2[1] - p1[1]))


def _isConvex(polygon):
    if len(polygon) < 3:
        return False
    sign = 0
    for i in range(len(polygon)):
        ax, ay = polygon[i]
        bx, by = polygon[(i + 1) % len(polygon)]
        cx, cy = polygon[(i + 2) % len(polygon)]
        cross = (bx - ax) * (cy - by) - (by - ay) * (cx - bx)
        if abs(cross) < 1e-9:
            continue
        current = 1 if cross > 0 else -1
        if sign and current != sign:
            return False
        sign = current
    return sign != 0


def _numbers(element):
    """
    The numbers in a PDF array element or None
    """
    if not element or element.getType() != "array":
        return None
    values = []
    for item in element.getElements():
        if item is None or item.getType() not in ("integer", "real"):
            return None
        values.append(float(item.getRawValue()))
    return values


def _rectPolygon(rect, matrix=IDENTITY):
    x0, y0, x1, y1 = rect
    corners = ((x0, y0), (x1, y0), (x1, y1), (x0, y1))
    return [_apply(matrix, corner) for corner in corners]


def _normalRect(values):
    if not values or len(values) < 4:
        return None
    return (
        min(values[0], values[2]),
        min(values[1], values[3]),
        max(values[0], values[2]),
        max(values[1], values[3]),
    )


def _inherited(pdfFile, page, name, version):
    current = page
    for _ in range(32):
        if current is None or current.getType() != "dictionary":
            return None
        element, _id = _resolve(pdfFile, current.getElementByName(name), version)
        if element is not None:
            return element
        current, _id = _resolve(pdfFile, current.getElementByName("/Parent"), version)
    return None


def _streamText(stream):
    try:
        value = stream.getStream()
    except Exception:
        return ""
    if isinstance(value, bytes):
        value = value.decode("latin-1")
    return value if isinstance(value, str) else ""


def _pageContent(pdfFile, page, version):
    contents, _id = _resolve(pdfFile, page.getElementByName("/Contents"), version)
    if contents is None:
        return ""
    if contents.getType() == "stream":
        return _streamText(contents)
    if contents.getType() != "array":
        return ""
    parts = []
    for element in contents.getElements():
        stream, _id = _resolve(pdfFile, element, version)
        if stream is not None and stream.getType() == "stream":
            parts.append(_streamText(stream))
    return "\n".join(parts)


class _State:
    __slots__ = ("ctm", "clips", "unmeasured", "base")

    def __init__(self, ctm=IDENTITY, clips=(), unmeasured=(), base=None):
        self.ctm = ctm
        self.clips = clips
        self.unmeasured = unmeasured
        self.base = ctm if base is None else base

    def copy(self):
        return _State(self.ctm, self.clips, self.unmeasured, self.base)


class _Walker:
    """
    Walking through XObjects and patterns
    """
    def __init__(self, pdfFile, version, pageNumber, results, printBoxes=None):
        self.pdfFile = pdfFile
        self.version = version
        self.pageNumber = pageNumber
        self.results = results
        self.printBoxes = printBoxes or {}
        self.seen = set()

    def _xobjects(self, resources):
        if resources is None or resources.getType() != "dictionary":
            return None
        xobjects, _id = _resolve(
            self.pdfFile, resources.getElementByName("/XObject"), self.version
        )
        if xobjects is None or xobjects.getType() != "dictionary":
            return None
        return xobjects

    def _lookup(self, resources, category, name):
        if resources is None or resources.getType() != "dictionary":
            return None, None
        group, _id = _resolve(self.pdfFile, resources.getElementByName(category), self.version)
        if group is None or group.getType() != "dictionary":
            return None, None
        return _resolve(self.pdfFile, group.getElementByName(name), self.version)

    def run(self, content, resources, state, location, formStack, owner=None):
        if not any(marker in content for marker in ("Do", "BI", "scn", "SCN", "gs")):  ## Table 50 - Operator categories
            return
        xobjects = self._xobjects(resources)
        stack = []
        operands = []
        path = _Path()
        pendingClip = None
        for kind, value in tokenizeContentStream(content, inlineImages=True):
            if kind == "inline_image":
                self._inlineImage(value, state, location, owner)
                operands = []
                continue
            if kind != "operator":
                operands.append((kind, value))
                if len(operands) > 64:
                    del operands[:32]
                continue
            operator = value
            numbers = [v for k, v in operands if k == "number"]
            if operator == "q":
                stack.append(state.copy())
            elif operator == "Q":
                if stack:
                    state = stack.pop()
            elif operator == "cm" and len(numbers) >= 6:
                state.ctm = _multiply(tuple(numbers[-6:]), state.ctm)
            elif operator == "m" and len(numbers) >= 2:
                path.moveTo(_apply(state.ctm, tuple(numbers[-2:])))
            elif operator == "l" and len(numbers) >= 2:
                path.lineTo(_apply(state.ctm, tuple(numbers[-2:])))
            elif operator in ("c", "v", "y"):
                path.curve()
            elif operator == "h":
                pass
            elif operator == "re" and len(numbers) >= 4:
                x, y, w, h = numbers[-4:]
                path.rectangle([_apply(state.ctm, p) for p in ((x, y), (x + w, y), (x + w, y + h), (x, y + h))])
            elif operator in ("W", "W*"):
                pendingClip = True
            elif operator in _PAINT_OPERATORS:
                if pendingClip:
                    self._applyClip(state, path)
                pendingClip = None
                path = _Path()
            elif operator == "Do" and operands and operands[-1][0] == "name" and xobjects is not None:
                self._draw(operands[-1][1], xobjects, resources, state, location, formStack, owner)
            elif operator in ("scn", "SCN") and operands and operands[-1][0] == "name":
                self._pattern(operands[-1][1], resources, state, location, formStack, owner)
            elif operator == "gs" and operands and operands[-1][0] == "name":
                self._softMask(operands[-1][1], resources, state, location, formStack, owner)
            operands = []

    def _applyClip(self, state, path):
        label, polygon = path.asClip()
        if polygon is None:
            state.unmeasured = state.unmeasured + (label,)
        else:
            state.clips = state.clips + ((label, polygon),)

    def _draw(self, name, xobjects, resources, state, location, formStack, owner):
        element = xobjects.getElementByName(name)
        xobject, xobjectId = _resolve(self.pdfFile, element, self.version)
        if xobject is None or xobject.getType() != "stream":
            return
        subtype = xobject.getElementByName("/Subtype")
        subtype = subtype.getValue() if subtype else None
        if subtype == "/Image":
            self._image(xobject, xobjectId, state, location)
        elif subtype == "/Form":
            self.form(xobject, xobjectId, resources, state, location, formStack, owner)

    def _pattern(self, name, resources, state, location, formStack, owner):
        """
        A tiling pattern's cell is clipped to its /BBox..
        Its /Matrix maps into the default space of the stream that uses it.
        """
        pattern, patternId = self._lookup(resources, "/Pattern", name)
        if pattern is None or pattern.getType() != "stream":
            return
        kind = pattern.getElementByName("/PatternType")
        if not kind or kind.getRawValue() != 1:
            return
        key = patternId if patternId is not None else id(pattern)
        marker = ("pattern", key, tuple(round(v, 3) for v in state.base))
        if key in formStack or len(formStack) >= MAX_FORM_DEPTH or marker in self.seen:
            return
        self.seen.add(marker)
        matrix = _numbers(pattern.getElementByName("/Matrix"))
        patternCtm = _multiply(tuple(matrix) if matrix and len(matrix) == 6 else IDENTITY, state.base)
        inner = state.copy()
        inner.ctm = inner.base = patternCtm
        bbox = _normalRect(_numbers(pattern.getElementByName("/BBox")))
        if bbox is not None:
            label = f"pattern object {patternId} /BBox" if patternId is not None else "pattern /BBox"
            inner.clips = inner.clips + ((label, _rectPolygon(bbox, patternCtm)),)
        patternResources, _id = _resolve(self.pdfFile, pattern.getElementByName("/Resources"), self.version)
        where = f"{location}, pattern object {patternId}" if patternId is not None else f"{location}, pattern"
        self.run(
            _streamText(pattern),
            patternResources if patternResources is not None else resources,
            inner,
            where,
            formStack + (key,),
            patternId if patternId is not None else owner,
        )

    def _softMask(self, name, resources, state, location, formStack, owner):
        """
        /ExtGState /SMask /G
        """
        gstate, _id = self._lookup(resources, "/ExtGState", name)
        if gstate is None or gstate.getType() != "dictionary":
            return
        mask, _id = _resolve(self.pdfFile, gstate.getElementByName("/SMask"), self.version)
        if mask is None or mask.getType() != "dictionary":
            return
        group, groupId = _resolve(self.pdfFile, mask.getElementByName("/G"), self.version)
        if group is None or group.getType() != "stream":
            return
        key = groupId if groupId is not None else id(group)
        marker = ("smask", key, tuple(round(v, 3) for v in state.ctm))
        if marker in self.seen:
            return
        self.seen.add(marker)
        self.form(group, groupId, resources, state, f"{location}, soft mask", formStack, owner)

    def form(self, form, formId, parentResources, state, location, formStack, owner=None):
        key = formId if formId is not None else id(form)
        if key in formStack or len(formStack) >= MAX_FORM_DEPTH:
            return
        matrix = _numbers(form.getElementByName("/Matrix"))
        inner = state.copy()
        if matrix and len(matrix) == 6:
            inner.ctm = _multiply(tuple(matrix), inner.ctm)
        inner.base = inner.ctm
        bbox = _normalRect(_numbers(form.getElementByName("/BBox")))
        label = f"form object {formId} /BBox" if formId is not None else "form /BBox"
        if bbox is not None:
            inner.clips = inner.clips + ((label, _rectPolygon(bbox, inner.ctm)),)
        resources, _id = _resolve(self.pdfFile, form.getElementByName("/Resources"), self.version)
        if resources is None:
            resources = parentResources
        where = f"{location}, form object {formId}" if formId is not None else f"{location}, form"
        self.run(
            _streamText(form),
            resources,
            inner,
            where,
            formStack + (key,),
            formId if formId is not None else owner,
        )

    def _image(self, image, imageId, state, location):
        width = image.getElementByName("/Width")
        height = image.getElementByName("/Height")
        filters = image.getElementByName("/Filter")
        self._record(
            "image",
            imageId,
            int(width.getRawValue()) if width and width.getType() == "integer" else None,
            int(height.getRawValue()) if height and height.getType() == "integer" else None,
            filters.getValue() if filters and filters.getType() == "name" else None,
            state,
            location,
            imageId,
        )

    def _inlineImage(self, header, state, location, owner):
        info = _inlineHeader(header)
        self._record(
            "inline",
            None,
            info.get("width"),
            info.get("height"),
            info.get("filter"),
            state,
            f"{location}, inline image",
            owner,
        )

    def _record(self, kind, imageId, widthPx, heightPx, filterName, state, location, navId):
        if len(self.results) >= MAX_IMAGES:
            return
        quad = [_apply(state.ctm, corner) for corner in _UNIT_SQUARE]
        fullArea = abs(_area(quad))
        a, b, c, d, _e, _f = state.ctm
        visible = _counterClockwise(quad)
        clippedBy = []
        if fullArea > 1e-9:
            for label, polygon in state.clips:
                before = abs(_area(visible)) if visible else 0.0
                visible = _clipConvex(visible, polygon) if visible else []
                after = abs(_area(visible)) if len(visible) >= 3 else 0.0
                if before - after > fullArea * 0.0005:
                    clippedBy.append(label)
                if after == 0.0:
                    visible = []
            fraction = (abs(_area(visible)) / fullArea) if len(visible) >= 3 else 0.0
        else:
            fraction = None
        printBoxes = {}
        visibleArea = abs(_area(visible)) if len(visible) >= 3 else 0.0
        if visibleArea > 1e-9:
            for boxName, polygon in self.printBoxes.items():
                inside = _clipConvex(visible, polygon)
                insideFraction = abs(_area(inside)) / visibleArea if len(inside) >= 3 else 0.0
                if insideFraction < CLIPPED_BELOW:
                    printBoxes[boxName] = round(insideFraction, 4)
        self.results.append(
            {
                "kind": kind,
                "page": self.pageNumber,
                "location": location,
                "image_id": imageId,
                "width_px": widthPx,
                "height_px": heightPx,
                "filter": filterName,
                "print_boxes": printBoxes,
                "placed_width_pt": round(math.hypot(a, b), 2),
                "placed_height_pt": round(math.hypot(c, d), 2),
                "visible_fraction": None if fraction is None else round(min(fraction, 1.0), 4),
                "clipped": fraction is not None and fraction < CLIPPED_BELOW,
                "clipped_by": clippedBy,
                "unmeasured_clips": list(state.unmeasured),
                "nav_id": navId,
            }
        )


def _inlineHeader(header):
    """
    width, height, filter between BI and ID
    """
    keys = {
        "/W": "width",
        "/Width": "width",
        "/H": "height",
        "/Height": "height",
        "/F": "filter",
        "/Filter": "filter",
    }
    info = {}
    tokens = list(tokenizeContentStream(header))
    i = 0
    while i < len(tokens):
        kind, value = tokens[i]
        if kind == "name" and i + 1 < len(tokens):
            field = keys.get(value)
            nextKind, nextValue = tokens[i + 1]
            if nextKind == "array_start" and i + 2 < len(tokens):
                nextKind, nextValue = tokens[i + 2]
            if field in ("width", "height") and nextKind == "number":
                info[field] = int(nextValue)
            elif field == "filter" and nextKind == "name":
                info[field] = nextValue
            i += 2
        else:
            i += 1
    return info


class _Path:
    """
    The path being built in page space
    """

    def __init__(self):
        self.subpaths = []
        self.curved = False
        self.fromRect = False

    def moveTo(self, point):
        self.subpaths.append([point])
        self.fromRect = False

    def lineTo(self, point):
        if self.subpaths:
            self.subpaths[-1].append(point)

    def curve(self):
        self.curved = True

    def rectangle(self, corners):
        self.subpaths.append(list(corners))
        self.fromRect = len(self.subpaths) == 1

    def asClip(self):
        """
       Label and polygon
        """
        if self.curved:
            return "clip path with curves", None
        if len(self.subpaths) != 1:
            return "clip path of several subpaths", None
        polygon = self.subpaths[0]
        if len(polygon) > 1 and polygon[0] == polygon[-1]:
            polygon = polygon[:-1]
        if not _isConvex(polygon):
            return "non-convex clip path", None
        return ("clip rectangle" if self.fromRect else "clip polygon"), polygon


def _annotationImages(walker, page):
    pdfFile, version, pageNumber = walker.pdfFile, walker.version, walker.pageNumber
    annots, _id = _resolve(pdfFile, page.getElementByName("/Annots"), version)
    if annots is None or annots.getType() != "array":
        return
    for element in annots.getElements():
        annot, annotId = _resolve(pdfFile, element, version)
        if annot is None or annot.getType() != "dictionary":
            continue
        rect = _normalRect(_numbers(annot.getElementByName("/Rect")))
        appearance, _id = _resolve(pdfFile, annot.getElementByName("/AP"), version)
        if rect is None or appearance is None or appearance.getType() != "dictionary":
            continue
        normal, normalId = _resolve(pdfFile, appearance.getElementByName("/N"), version)
        if normal is not None and normal.getType() == "dictionary":
            states = normal
            chosen = annot.getElementByName("/AS")
            names = [chosen.getValue()] if chosen else list(states.getElements())
            normal, normalId = None, None
            for stateName in names:
                candidate, candidateId = _resolve(pdfFile, states.getElementByName(stateName), version)
                if candidate is not None and candidate.getType() == "stream":
                    normal, normalId = candidate, candidateId
                    break
        if normal is None or normal.getType() != "stream":
            continue
        matrix = _numbers(normal.getElementByName("/Matrix")) or list(IDENTITY)
        bbox = _normalRect(_numbers(normal.getElementByName("/BBox")))
        if bbox is None or len(matrix) != 6:
            continue
        corners = _rectPolygon(bbox, tuple(matrix))
        xs, ys = [p[0] for p in corners], [p[1] for p in corners]
        spanX, spanY = max(xs) - min(xs), max(ys) - min(ys)
        sx = (rect[2] - rect[0]) / spanX if spanX > 1e-9 else 1.0
        sy = (rect[3] - rect[1]) / spanY if spanY > 1e-9 else 1.0
        placement = (sx, 0.0, 0.0, sy, rect[0] - min(xs) * sx, rect[1] - min(ys) * sy)
        where = f"page {pageNumber}, annotation object {annotId}" if annotId is not None else f"page {pageNumber}, annotation"
        state = _State(placement)
        resources, _id = _resolve(pdfFile, normal.getElementByName("/Resources"), version)
        walker.form(normal, normalId, resources, state, where, (), normalId)


def getImageClipping(pdfFile, version=None):
    """
    Every image placed on a page as of 'version', with the fraction of it
    that is inside every clip region
    """
    last = pdfFile.updates if version is None else version
    results = []
    for number, page, pageId in _pages(pdfFile, last):
        if page.getType() != "dictionary":
            continue
        resources = _inherited(pdfFile, page, "/Resources", last)
        state = _State()
        for boxName in ("/CropBox", "/MediaBox"):
            box = _normalRect(_numbers(_inherited(pdfFile, page, boxName, last)))
            if box is not None:
                state.clips = ((f"page {boxName[1:]}", _rectPolygon(box)),)
                break
        printBoxes = {}
        for boxName in ("TrimBox", "BleedBox", "ArtBox"):
            element, _id = _resolve(pdfFile, page.getElementByName("/" + boxName), last)
            box = _normalRect(_numbers(element))
            if box is not None:
                printBoxes[boxName] = _rectPolygon(box)
        walker = _Walker(pdfFile, last, number, results, printBoxes)
        walker.run(_pageContent(pdfFile, page, last), resources, state, f"page {number}", (), pageId)
        _annotationImages(walker, page)
        if len(results) >= MAX_IMAGES:
            break
    for entry in results:
        entry["nav_version"] = _lastDefiningVersion(pdfFile, entry["nav_id"], last)
    return results
