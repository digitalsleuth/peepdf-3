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

from io import BytesIO

try:
    from PIL import Image, ImageChops
except ModuleNotFoundError:
    Image = None

try:
    from peepdf.PDFComments import _resolve
except ModuleNotFoundError:
    from PDFComments import _resolve

COMPONENTS = {
    "/DeviceGray": 1,
    "/CalGray": 1,
    "/DeviceRGB": 3,
    "/CalRGB": 3,
    "/DeviceCMYK": 4,
}
MODES = {1: "L", 3: "RGB", 4: "CMYK"}
ENCODED_FILTERS = ("/DCTDecode", "/JPXDecode")
KEEP_MODES = ("L", "LA", "RGB", "RGBA")


class _Unsupported(Exception):
    pass


def _get(pdfFile, obj, key, version):
    return _resolve(pdfFile, obj.getElementByName(key), version)[0]


def _int(pdfFile, obj, key, version):
    element = _get(pdfFile, obj, key, version)
    if element is not None and element.getType() == "integer":
        return int(element.getRawValue())
    return None


def _name(pdfFile, obj, key, version):
    element = _get(pdfFile, obj, key, version)
    if element is not None and element.getType() == "name":
        return element.getValue()
    return None


def _filterNames(pdfFile, obj, version):
    element = _get(pdfFile, obj, "/Filter", version)
    if element is None:
        return []
    if element.getType() == "name":
        return [element.getValue()]
    if element.getType() != "array":
        return []
    names = []
    for item in element.getElements():
        item = _resolve(pdfFile, item, version)[0]
        names.append(
            item.getValue() if item is not None and item.getType() == "name" else None
        )
    return names


def _bytes(stream):
    data = stream.getStream()
    if data in (-1, None, ""):
        raise _Unsupported("The image data could not be decoded")
    return data.encode("latin-1") if isinstance(data, str) else data


def _inverted(pdfFile, obj, version, components):
    decode = _get(pdfFile, obj, "/Decode", version)
    if decode is None or decode.getType() != "array":
        return False
    values = [
        float(item.getRawValue())
        for item in decode.getElements()
        if item is not None and item.getType() in ("integer", "real")
    ]
    if values == [0.0, 1.0] * components:
        return False
    if values == [1.0, 0.0] * components:
        return True
    raise _Unsupported("Unsupported /Decode array")


def _colorSpace(pdfFile, element, version):
    element = _resolve(pdfFile, element, version)[0]
    if element is None:
        raise _Unsupported("The image has no /ColorSpace")
    if element.getType() == "name":
        family, parts = element.getValue(), []
    elif element.getType() == "array":
        parts = element.getElements()
        family = parts[0].getValue()
    else:
        raise _Unsupported("Unsupported /ColorSpace")
    if family in COMPONENTS:
        return (COMPONENTS[family], None)
    if family == "/ICCBased":
        components = _int(
            pdfFile, _resolve(pdfFile, parts[1], version)[0], "/N", version
        )
        if components in MODES:
            return (components, None)
        raise _Unsupported("Unsupported ICC profile")
    if family == "/Indexed":
        lookup = _resolve(pdfFile, parts[3], version)[0]
        data = _bytes(lookup) if lookup.getType() == "stream" else lookup.getValue()
        return (
            1,
            (
                _colorSpace(pdfFile, parts[1], version)[0],
                int(parts[2].getRawValue()),
                data.encode("latin-1") if isinstance(data, str) else data,
            ),
        )
    raise _Unsupported(f"Unsupported colour space {family}")


def _indexed(indices, palette):
    baseComponents, hival, lookup = palette
    count = min(hival + 1, len(lookup) // baseComponents)
    if count == 0:
        raise _Unsupported("The image palette is empty")
    colors = (
        Image.frombytes(
            MODES[baseComponents], (count, 1), lookup[: count * baseComponents]
        )
        .convert("RGB")
        .tobytes()
    )
    # indices past the palette take its last colour
    picture = Image.frombytes("P", indices.size, indices.tobytes())
    picture.putpalette(colors + colors[-3:] * (256 - count))
    return picture.convert("RGB")


def _packed(data, width, height, bits, indexed):
    data = data[: ((width * bits + 7) // 8) * height]
    if bits == 1:
        picture = Image.frombytes("1", (width, height), data).convert("L")
    else:
        picture = Image.frombytes("L", (width, height), data, "raw", f"L;{bits}")
    # undo the 0..255 scaling when the samples are palette indices
    return (
        picture.point(lambda v: v // (255 // ((1 << bits) - 1))) if indexed else picture
    )


def _samples(pdfFile, image, version, width, height):
    bits = _int(pdfFile, image, "/BitsPerComponent", version)
    if bits not in (1, 2, 4, 8, 16):
        raise _Unsupported("Unsupported /BitsPerComponent")
    components, palette = _colorSpace(
        pdfFile, image.getElementByName("/ColorSpace"), version
    )
    data = _bytes(image)
    if bits == 16:
        data, bits = data[0::2], 8
    if bits == 8:
        picture = Image.frombytes(
            MODES[components], (width, height), data[: width * height * components]
        )
    elif components == 1:
        picture = _packed(data, width, height, bits, palette is not None)
    else:
        raise _Unsupported("Unsupported /BitsPerComponent for this colour space")
    if palette is not None:
        return _indexed(picture, palette)
    if _inverted(pdfFile, image, version, components):
        picture = ImageChops.invert(picture)
    return picture.convert("RGB") if components == 4 else picture


def _stencil(pdfFile, mask, version):
    width = _int(pdfFile, mask, "/Width", version)
    height = _int(pdfFile, mask, "/Height", version)
    if not width or not height:
        raise _Unsupported("The mask has no valid /Width and /Height")
    bits = Image.frombytes(
        "1", (width, height), _bytes(mask)[: ((width + 7) // 8) * height]
    ).convert("L")
    # with the default /Decode a 0 sample paints
    return bits if _inverted(pdfFile, mask, version, 1) else ImageChops.invert(bits)


def _encoded(pdfFile, image, version, filterName):
    picture = Image.open(BytesIO(image.encodedStream.encode("latin-1")))
    picture.load()
    if filterName == "/DCTDecode":
        inverted = _inverted(pdfFile, image, version, len(picture.getbands()))
        # Pillow reads a CMYK JPEG as Adobe-inverted, so the /Decode rule flips
        if inverted != (picture.mode == "CMYK"):
            picture = ImageChops.invert(picture)
    return picture if picture.mode in KEEP_MODES else picture.convert("RGB")


def _base(pdfFile, image, version):
    width = _int(pdfFile, image, "/Width", version)
    height = _int(pdfFile, image, "/Height", version)
    if not width or not height:
        raise _Unsupported("The image has no valid /Width and /Height")
    names = _filterNames(pdfFile, image, version)
    if names and names[-1] in ENCODED_FILTERS:
        if len(names) > 1:
            raise _Unsupported(f"Unsupported filter chain ending in {names[-1]}")
        return _encoded(pdfFile, image, version, names[0])
    stencil = _get(pdfFile, image, "/ImageMask", version)
    if (
        stencil is not None
        and stencil.getType() == "bool"
        and stencil.getValue() == "true"
    ):
        picture = Image.new("L", (width, height), 0)
        picture.putalpha(_stencil(pdfFile, image, version))
        return picture
    return _samples(pdfFile, image, version, width, height)


def _sized(picture, size):
    return picture if picture.size == size else picture.resize(size, Image.BILINEAR)


def _alpha(pdfFile, image, size, version):
    soft = _get(pdfFile, image, "/SMask", version)
    if soft is not None and soft.getType() == "stream":
        return _sized(_base(pdfFile, soft, version).convert("L"), size)
    mask = _get(pdfFile, image, "/Mask", version)
    if mask is not None and mask.getType() == "stream":
        return _sized(_stencil(pdfFile, mask, version), size)
    return None


def extractImage(pdfFile, objId, version=None):
    if Image is None:
        return (-1, "PIL is not installed")
    if pdfFile.isEncrypted():
        return (-1, "The document is encrypted; decrypt it first")
    last = pdfFile.updates if version is None else version
    image = pdfFile.getObjectAtVersion(objId, last)
    if (
        image is None
        or image.getType() != "stream"
        or _name(pdfFile, image, "/Subtype", last) != "/Image"
    ):
        return (-1, f"Object {objId} is not an image")
    try:
        picture = _base(pdfFile, image, last)
        alpha = _alpha(pdfFile, image, picture.size, last)
        if alpha is not None:
            picture.putalpha(alpha)
        return (0, picture)
    except _Unsupported as exc:
        return (-1, str(exc))
    except Exception as exc:
        return (-1, f"Could not build the image: {exc}")
