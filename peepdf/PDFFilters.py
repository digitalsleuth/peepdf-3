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
#
# Some code has been reused and modified from the original by Mathieu Fenniak:
# Parameters management in Flate and LZW algorithms, asciiHexDecode and ascii85Decode
#
# Copyright (c) 2006, Mathieu Fenniak
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# * Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
# * The name of the author may not be used to endorse or promote products
# derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# The ascii85Decode code is part of pdfminer (http://pypi.python.org/pypi/pdfminer/)
#
# Copyright (c) 2004-2010 Yusuke Shinyama <yusuke at cs dot nyu dot edu>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software
# and associated documentation files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or
# substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
# BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# In ASCII85 encoding, every four bytes are encoded with five ASCII
# letters, using 85 different types of characters (as 256**4 < 85**5).
# When the length of the original bytes is not a multiple of 4, a special
# rule is used for round up.
#
# The Adobe's ASCII85 implementation is slightly different from
# its original in handling the last characters.
#
# The sample string is taken from:
# http://en.wikipedia.org/w/index.php?title=Ascii85
# >>> ascii85decode('9jqo^BlbD-BleB1DJ+*+F(f,q')
# 'Man is distinguished'
# >>> ascii85decode('E,9)oF*2M7/c~>')
# 'pleasure.'


"""
Module to manage encoding/decoding in PDF files
"""

import zlib
import struct
import base64
from binascii import hexlify
from io import BytesIO

try:
    from peepdf.PDFEnDec import CCITTFax, compress, lzwdecode
    from peepdf.PDFUtils import getNumsFromBytes, getBytesFromBits, getBitsFromNum
except ModuleNotFoundError:
    from PDFEnDec import CCITTFax, compress, lzwdecode
    from PDFUtils import getNumsFromBytes, getBytesFromBits, getBitsFromNum

try:
    from PIL import Image

    PIL_MODULE = True
except ModuleNotFoundError:
    PIL_MODULE = False


_IMAGE_COLORSPACE_TO_PIL_MODE = {
    "/DeviceGray": "L",
    "/CalGray": "L",
    "/DeviceRGB": "RGB",
    "/CalRGB": "RGB",
    "/DeviceCMYK": "CMYK",
}


def decodeStream(stream, thisFilter, parameters=None):
    """
    Decode the given stream

    @param stream: Stream to be decoded (string)
    @param thisFilter: Filter to apply to decode the stream
    @param parameters: List of PDFObjects containing the parameters for the filter
    @return: A tuple (status, statusContent), where statusContent is the decoded stream in case status = 0 or an error in case status = -1
    """
    if parameters is None:
        parameters = {}
    if thisFilter in {"/ASCIIHexDecode", "/AHx"}:
        ret = asciiHexDecode(stream)
    elif thisFilter in {"/ASCII85Decode", "/A85"}:
        ret = ascii85Decode(stream)
    elif thisFilter in {"/LZWDecode", "/LZW"}:
        ret = lzwDecode(stream, parameters)
    elif thisFilter in {"/FlateDecode", "/Fl"}:
        ret = flateDecode(stream, parameters)
    elif thisFilter in {"/RunLengthDecode", "/RL"}:
        ret = runLengthDecode(stream)
    elif thisFilter in {"/CCITTFaxDecode", "/CCF"}:
        ret = ccittFaxDecode(stream, parameters)
    elif thisFilter == "/JBIG2Decode":
        ret = jbig2Decode(stream, parameters)
    elif thisFilter in {"/DCTDecode", "/DCT"}:
        ret = dctDecode(stream, parameters)
    elif thisFilter == "/JPXDecode":
        ret = jpxDecode(stream, parameters)
    elif thisFilter == "/Crypt":
        ret = crypt(stream, parameters)
    else:
        ret = (-1, f'Unknown filter "{thisFilter}"')
    return ret


def encodeStream(stream, thisFilter, parameters=None):
    """
    Encode the given stream

    @param stream: Stream to be decoded (string)
    @param thisFilter: Filter to apply to decode the stream
    @param parameters: List of PDFObjects containing the parameters for the filter
    @return: A tuple (status,statusContent), where statusContent is the encoded stream in case status = 0 or an error in case status = -1
    """
    if parameters is None:
        parameters = {}
    if thisFilter == "/ASCIIHexDecode":
        ret = asciiHexEncode(stream)
    elif thisFilter == "/ASCII85Decode":
        ret = ascii85Encode(stream)
    elif thisFilter == "/LZWDecode":
        ret = lzwEncode(stream, parameters)
    elif thisFilter == "/FlateDecode":
        ret = flateEncode(stream, parameters)
    elif thisFilter == "/RunLengthDecode":
        ret = runLengthEncode(stream)
    elif thisFilter == "/CCITTFaxDecode":
        ret = ccittFaxEncode(stream, parameters)
    elif thisFilter == "/JBIG2Decode":
        ret = jbig2Encode(stream, parameters)
    elif thisFilter == "/DCTDecode":
        ret = dctEncode(stream, parameters)
    elif thisFilter == "/JPXDecode":
        ret = jpxEncode(stream, parameters)
    elif thisFilter == "/Crypt":
        ret = crypt(stream, parameters)
    else:
        ret = (-1, f'Unknown filter "{thisFilter}"')
    return ret


def ascii85Decode(stream: str):
    """
    Method to decode streams using ASCII85

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the decoded PDF stream in case status = 0 or an error in case status = -1
    """
    n = b = 0
    decodedStream = bytearray()
    try:
        for c in stream:
            if "!" <= c <= "u":
                n += 1
                b = b * 85 + (ord(c) - 33)
                if n == 5:
                    decodedStream += struct.pack(">L", b)
                    n = b = 0
            elif c == "z":
                if n != 0:
                    return (-1, "'z' inside a group is invalid.")
                decodedStream += b"\0\0\0\0"
            elif c == "~":
                if n:
                    for _ in range(5 - n):
                        b = b * 85 + 84
                    decodedStream += struct.pack(">L", b)[: n - 1]
                break
    except Exception as exc:
        return (-1, f"ASCII85 Decoding Error: {exc}")
    return (0, decodedStream.decode("latin-1"))


def ascii85Encode(stream: str):
    """
    Method to encode streams using ASCII85

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the encoded PDF stream in case status = 0 or an error in case status = -1
    """
    if not isinstance(stream, str):
        return (-1, "Input must be a string")
    try:
        byte_data = stream.encode("latin-1")
        encoded = base64.a85encode(byte_data, adobe=False).decode("ascii") + "~"
    except Exception as exc:
        return (-1, f"Encoding error: {exc}")
    return (0, encoded)


def asciiHexDecode(stream):
    """
    Method to decode streams using hexadecimal encoding

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the decoded PDF stream in case status = 0 or an error in case status = -1
    """
    eod = ">"
    decodedChars = []
    char = ""
    index = 0
    while index < len(stream):
        c = stream[index]
        if c == eod:
            if len(decodedChars) % 2 != 0:
                char += "0"
                try:
                    decodedChars.append(chr(int(char, 16)))
                except:
                    return (-1, "Error in hexadecimal conversion")
            break
        if c.isspace():
            index += 1
            continue
        char += c
        if len(char) == 2:
            try:
                decodedChars.append(chr(int(char, 16)))
            except:
                return (-1, "Error in hexadecimal conversion")
            char = ""
        index += 1
    return (0, "".join(decodedChars))


def asciiHexEncode(stream):
    """
    Method to encode streams using hexadecimal encoding

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the encoded PDF stream in case status = 0 or an error in case status = -1
    """
    try:
        encodedStream = hexlify(stream.encode("latin-1")).decode("latin-1")
    except:
        return (-1, "Error in hexadecimal conversion")
    return (0, encodedStream)


def doubleDecode(stream):
    i = 0
    decodedStream = stream.encode()
    while i < 2:
        decodedStream = decodedStream.hex()
        utf8_bytes = bytes.fromhex(decodedStream)
        decode_from_utf8 = utf8_bytes.decode("utf-8")
        decodedStream = decode_from_utf8.encode("latin-1")
        i += 1
    return decodedStream


def flateDecode(stream, parameters):
    """
    Method to decode streams using the Flate algorithm

    @param stream: A PDF stream
    @return: A tuple (status, statusContent), where statusContent is the decoded PDF stream in case status = 0 or an error in case status = -1
    """
    decodedStream = ""
    try:
        doubleDecodedStream = doubleDecode(stream)
        decodedStream = zlib.decompress(doubleDecodedStream).decode("latin-1")
    except:
        pass
    if decodedStream == "":
        try:
            if not isinstance(stream, bytes):
                decodedStream = (zlib.decompress(stream.encode("latin-1"))).decode(
                    "latin-1"
                )
            else:
                decodedStream = zlib.decompress(stream).decode("latin-1")
        except:
            return (-1, "Error decompressing string with FlateDecode")

    if not parameters:
        return (0, decodedStream)
    if "/Predictor" in parameters:
        predictor = parameters["/Predictor"].getRawValue()
    else:
        predictor = 1
    # Columns = number of samples per row
    if "/Columns" in parameters:
        columns = parameters["/Columns"].getRawValue()
    else:
        columns = 1
    # Colors = number of components per sample
    if "/Colors" in parameters:
        colors = parameters["/Colors"].getRawValue()
        colors = max(colors, 1)
    else:
        colors = 1
    # BitsPerComponent: number of bits per color component
    if "/BitsPerComponent" in parameters:
        bits = parameters["/BitsPerComponent"].getRawValue()
        if bits not in [1, 2, 4, 8, 16]:
            bits = 8
    else:
        bits = 8
    if predictor is not None and predictor != 1:
        ret = post_prediction(decodedStream, predictor, columns, colors, bits)
        return ret
    return (0, decodedStream)


def flateEncode(stream, parameters):
    """
    Method to encode streams using the Flate algorithm

    @param stream: A PDF stream
    @return: A tuple (status, statusContent), where statusContent is the encoded PDF stream in case status = 0 or an error in case status = -1
    """
    if not parameters:
        try:
            return (0, zlib.compress(stream.encode("latin-1")).decode("latin-1"))
        except:
            return (-1, "Error compressing string")
    if "/Predictor" in parameters:
        predictor = parameters["/Predictor"].getRawValue()
    else:
        predictor = 1
    # Columns = number of samples per row
    if "/Columns" in parameters:
        columns = parameters["/Columns"].getRawValue()
    else:
        columns = 1
    # Colors = number of components per sample
    if "/Colors" in parameters:
        colors = parameters["/Colors"].getRawValue()
        colors = max(colors, 1)
    else:
        colors = 1
    # BitsPerComponent: number of bits per color component
    if "/BitsPerComponent" in parameters:
        bits = parameters["/BitsPerComponent"].getRawValue()
        if bits not in [1, 2, 4, 8, 16]:
            bits = 8
    else:
        bits = 8
    if predictor is not None and predictor != 1:
        ret = pre_prediction(stream, predictor, columns, colors, bits)
        if ret[0] == -1:
            return ret
        output = ret[1]
    else:
        output = stream
    try:
        return (0, zlib.compress(output.encode("latin-1")).decode("latin-1"))
    except:
        return (-1, "Error compressing string")


def lzwDecode(stream, parameters):
    """
    Method to decode streams using the LZW algorithm

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the decoded PDF stream in case status = 0 or an error in case status = -1
    """
    decodedStream = ""
    try:
        decodedStream = lzwdecode(stream)
    except:
        return (-1, "Error decompressing string with LZW Decode")

    if not parameters:
        return (0, decodedStream)
    if "/Predictor" in parameters:
        predictor = parameters["/Predictor"].getRawValue()
    else:
        predictor = 1
    # Columns = number of samples per row
    if "/Columns" in parameters:
        columns = parameters["/Columns"].getRawValue()
    else:
        columns = 1
    # Colors = number of components per sample
    if "/Colors" in parameters:
        colors = parameters["/Colors"].getRawValue()
        colors = max(colors, 1)
    else:
        colors = 1
    # BitsPerComponent: number of bits per color component
    if "/BitsPerComponent" in parameters:
        bits = parameters["/BitsPerComponent"].getRawValue()
        if bits not in [1, 2, 4, 8, 16]:
            bits = 8
    else:
        bits = 8
    if predictor is not None and predictor != 1:
        ret = post_prediction(decodedStream, predictor, columns, colors, bits)
        return ret
    return (0, decodedStream)


def lzwEncode(stream, parameters):
    """
    Method to encode streams using the LZW algorithm

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the encoded PDF stream in case status = 0 or an error in case status = -1
    """
    encodedStream = b""
    if parameters is None or parameters == {}:
        try:
            generator = compress(stream)
            for c in generator:
                encodedStream += c
            return (0, encodedStream.decode("latin-1"))
        except:
            return (-1, "Error compressing string with LZW Encode")
    else:
        if "/Predictor" in parameters:
            predictor = parameters["/Predictor"].getRawValue()
        else:
            predictor = 1
        # Columns = number of samples per row
        if "/Columns" in parameters:
            columns = parameters["/Columns"].getRawValue()
        else:
            columns = 1
        # Colors = number of components per sample
        if "/Colors" in parameters:
            colors = parameters["/Colors"].getRawValue()
            colors = max(colors, 1)
        else:
            colors = 1
        # BitsPerComponent: number of bits per color component
        if "/BitsPerComponent" in parameters:
            bits = parameters["/BitsPerComponent"].getRawValue()
            if bits not in [1, 2, 4, 8, 16]:
                bits = 8
        else:
            bits = 8
        if predictor is not None and predictor != 1:
            ret = pre_prediction(stream, predictor, columns, colors, bits)
            if ret[0] == -1:
                return ret
            output = ret[1]
        else:
            output = stream
        try:
            generator = compress(output)
            for c in generator:
                encodedStream += c
            return (0, encodedStream.decode("latin-1"))
        except:
            return (-1, "Error compressing string with LZW Encode")


def str_to_bytes(s):
    return [ord(c) for c in s]


def bytes_to_str(b):
    return "".join(chr(x) for x in b)


def pre_prediction(stream, predictor, columns, colors, bits):
    """
    Predictor function to make the stream more predictable and improve compression (PDF Specification)

    @param stream: The stream to be modified
    @param predictor: The type of predictor to apply
    @param columns: Number of samples per row
    @param colors: Number of colors per sample
    @param bits: Number of bits per color
    @return: A tuple (status, statusContent), where statusContent is the modified stream in case status = 0 or an error in case status = -1
    """

    bytesPerComponent = (bits + 7) // 8
    bytesPerPixel = colors * bytesPerComponent
    rowLength = (columns * colors * bits + 7) // 8

    data = str_to_bytes(stream)
    output = []
    if predictor == 2:
        try:
            for row_start in range(0, len(data), rowLength):
                row = data[row_start : row_start + rowLength]
                prev = [0] * len(row)
                for i in range(len(row)):
                    row[i] = (row[i] - prev[i % bytesPerPixel]) % 256
                    prev[i % bytesPerPixel] = (prev[i % bytesPerPixel] + row[i]) % 256
                output.extend(row)
            return (0, bytes_to_str(output))
        except Exception as e:
            return (-1, f"TIFF pre-prediction error: {e}")
    # PNG prediction
    if 10 <= predictor <= 15:
        filter_type = predictor - 10
        try:
            prev_row = [0] * rowLength
            for row_start in range(0, len(data), rowLength):
                row = data[row_start : row_start + rowLength]
                filter_row = [filter_type]

                if filter_type == 0:  # None
                    filter_row += row
                elif filter_type == 1:  # Sub
                    for i in range(len(row)):
                        left = row[i - bytesPerPixel] if i >= bytesPerPixel else 0
                        filter_row.append((row[i] - left) % 256)
                elif filter_type == 2:  # Up
                    for i in range(len(row)):
                        up = prev_row[i]
                        filter_row.append((row[i] - up) % 256)
                elif filter_type == 3:  # Average
                    for i in range(len(row)):
                        left = row[i - bytesPerPixel] if i >= bytesPerPixel else 0
                        up = prev_row[i]
                        avg = (left + up) // 2
                        filter_row.append((row[i] - avg) % 256)
                elif filter_type == 4:  # Paeth

                    def paeth(a, b, c):
                        p = a + b - c
                        pa = abs(p - a)
                        pb = abs(p - b)
                        pc = abs(p - c)
                        if pa <= pb and pa <= pc:
                            return a
                        if pb <= pc:
                            return b
                        return c

                    for i in range(len(row)):
                        left = row[i - bytesPerPixel] if i >= bytesPerPixel else 0
                        up = prev_row[i]
                        up_left = (
                            prev_row[i - bytesPerPixel] if i >= bytesPerPixel else 0
                        )
                        filter_row.append((row[i] - paeth(left, up, up_left)) % 256)
                elif filter_type == 5:
                    filter_row[0] = 0
                    filter_row += row
                else:
                    return (-1, f"Unsupported PNG predictor: {filter_type}")
                output.extend(filter_row)
                prev_row = row
            output_str = bytes_to_str(output)
            return (0, output_str)
        except Exception as e:
            return (-1, f"PNG pre-prediction error: {e}")
    return (-1, f"Unsupported predictor value: {predictor}")


def post_prediction(decodedStream, predictor, columns, colors, bits):
    """
    Predictor function to obtain the real stream, removing the prediction (PDF Specification)

    @param decodedStream: The decoded stream to be modified
    @param predictor: The type of predictor to apply
    @param columns: Number of samples per row
    @param colors: Number of colors per sample
    @param bits: Number of bits per color
    @return: A tuple (status, statusContent), where statusContent is the modified decoded stream in case status = 0 or an error in case status = -1
    """

    output = ""
    bytesPerRow = (colors * bits * columns + 7) // 8

    # TIFF - 2
    # http://www.gnupdf.org/PNG_and_TIFF_Predictors_Filter#TIFF
    if predictor == 2:
        try:
            numRows = len(decodedStream) // bytesPerRow
            bitmask = (1 << bits) - 1
            outputBitsStream = ""
            for rowIndex in range(numRows):
                row = decodedStream[
                    rowIndex * bytesPerRow : (rowIndex + 1) * bytesPerRow
                ]
                ret, colorNums = getNumsFromBytes(row, bits)
                if ret == -1:
                    return (ret, colorNums)
                pixel = [0] * colors
                for i in range(columns):
                    for j in range(colors):
                        idx = i * colors + j
                        if idx >= len(colorNums):
                            return (
                                -1,
                                f"Color data index out of range at row {rowIndex}, col {i}, color {j}",
                            )
                        diffPixel = colorNums[idx]
                        pixel[j] = (pixel[j] + diffPixel) & bitmask
                        ret, outputBits = getBitsFromNum(pixel[j], bits)
                        if ret == -1:
                            return (ret, outputBits)
                        outputBitsStream += outputBits
            ret, output = getBytesFromBits(outputBitsStream)
            return (ret, output) if ret == 0 else (-1, output)
        except Exception as e:
            return (-1, f"TIFF decoding error: {str(e)}")
    # PNG prediction
    # http://www.libpng.org/pub/png/spec/1.2/PNG-Filters.html
    # http://www.gnupdf.org/PNG_and_TIFF_Predictors_Filter#TIFF
    if 10 <= predictor <= 15:
        try:
            bytesPerPixel = (colors * bits + 7) // 8
            rowLength = (colors * bits * columns + 7) // 8
            output_bytes = []
            i = 0
            upRowdata = [0] * rowLength
            data = str_to_bytes(decodedStream)
            while i < len(data):
                filter_type = data[i]
                i += 1
                rowdata = data[i : i + rowLength]
                i += rowLength
                if len(rowdata) != rowLength:
                    return (-1, f"Incomplete PNG row at offset {i}")
                for j in range(len(rowdata)):
                    left = rowdata[j - bytesPerPixel] if j >= bytesPerPixel else 0
                    up = upRowdata[j]
                    up_left = upRowdata[j - bytesPerPixel] if j >= bytesPerPixel else 0

                    if filter_type == 0:  # None
                        pass
                    elif filter_type == 1:  # Sub
                        rowdata[j] = (rowdata[j] + left) % 256
                    elif filter_type == 2:  # Up
                        rowdata[j] = (rowdata[j] + up) % 256
                    elif filter_type == 3:  # Average
                        avg = (left + up) // 2
                        rowdata[j] = (rowdata[j] + avg) % 256
                    elif filter_type == 4:  # Paeth

                        def paeth(a, b, c):
                            p = a + b - c
                            pa = abs(p - a)
                            pb = abs(p - b)
                            pc = abs(p - c)
                            if pa <= pb and pa <= pc:
                                return a
                            if pb <= pc:
                                return b
                            return c

                        pr = paeth(left, up, up_left)
                        rowdata[j] = (rowdata[j] + pr) % 256
                    elif filter_type == 15:
                        pass
                    else:
                        return (-1, f"Unsupported PNG filter type: {filter_type}")
                output_bytes.extend(rowdata)
                upRowdata = rowdata
            output = bytes_to_str(output_bytes)
            return (0, output)
        except Exception as e:
            return (-1, f"PNG Decoding Error: {str(e)}")
    return (-1, f"Unsupported predictor value: {predictor}")


def runLengthDecode(stream):
    """
    Method to decode streams using the Run-Length algorithm

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the decoded PDF stream in case status = 0 or an error in case status = -1
    """
    try:
        stream_bytes = stream.encode("latin-1")
        decoded = bytearray()
        index = 0
        while index < len(stream_bytes):
            length = stream_bytes[index]
            index += 1
            if length == 128:
                break
            if 0 <= length <= 127:
                decoded += stream_bytes[index : index + length + 1]
                index += length + 1
            elif 129 <= length <= 255:
                decoded += stream_bytes[index : index + 1] * (257 - length)
                index += 1
            else:
                return (-1, f"Invalid run-length byte: {length}")
        return (0, decoded.decode("latin-1"))
    except Exception as exc:
        return (-1, f"Error decoding RunLength: {exc}")


def runLengthEncode(stream):
    """
    Method to encode streams using the Run-Length algorithm

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the encoded PDF stream in case status = 0 or an error in case status = -1
    """
    try:
        stream_bytes = stream.encode("latin-1")
        encoded = bytearray()
        i = 0
        length = len(stream_bytes)

        while i < length:
            run_start = i
            run_length = 1
            while (
                i + run_length < length
                and run_length < 128
                and stream_bytes[i] == stream_bytes[i + run_length]
            ):
                run_length += 1
            if run_length > 1:
                encoded.append(257 - run_length)
                encoded.append(stream_bytes[i])
                i += run_length
            else:
                literal_start = i
                literal_run = 1
                i += 1
                while i < length and literal_run < 128:
                    if i + 1 < length and stream_bytes[i] == stream_bytes[i + 1]:
                        break
                    literal_run += 1
                    i += 1
                encoded.append(literal_run - 1)
                encoded += stream_bytes[literal_start : literal_start + literal_run]
        encoded.append(128)
        return (0, encoded.decode("latin-1"))
    except Exception as exc:
        return (-1, f"Error encoding RunLength: {exc}")


def ccittFaxDecode(stream, parameters):
    """
    Method to decode streams using the CCITT facsimile standard

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the decoded PDF stream in case status = 0 or an error in case status = -1
    """
    decodedStream = ""

    if parameters is None or parameters == {}:
        try:
            decodedStream = CCITTFax().decode(stream)
            return (0, decodedStream)
        except:
            return (-1, "Error decompressing string with CCITT Fax Decode")
    else:
        # K = A code identifying the encoding scheme used
        if "/K" in parameters:
            k = parameters["/K"].getRawValue()
            if not isinstance(k, int):
                k = 0
            elif k != 0:
                # Only supported "Group 3, 1-D" encoding (Pure one-dimensional encoding)
                return (-1, "CCITT encoding scheme not supported")
        else:
            k = 0
        # EndOfLine = A flag indicating whether end-of-line bit patterns are required to be present in the encoding.
        if "/EndOfLine" in parameters:
            eol = parameters["/EndOfLine"].getRawValue()
            eol = bool(eol == "true")
        else:
            eol = False
        # EncodedByteAlign = A flag indicating whether the filter expects extra 0 bits before each encoded line so that the line begins on a byte boundary
        if "/EncodedByteAlign" in parameters:
            byteAlign = parameters["/EncodedByteAlign"].getRawValue()
            byteAlign = bool(byteAlign == "true")
        else:
            byteAlign = False
        # Columns = The width of the image in pixels.
        if "/Columns" in parameters:
            columns = parameters["/Columns"].getRawValue()
            if not isinstance(columns, int):
                columns = 1728
        else:
            columns = 1728
        # Rows = The height of the image in scan lines.
        if "/Rows" in parameters:
            rows = parameters["/Rows"].getRawValue()
            if not isinstance(rows, int):
                rows = 0
        else:
            rows = 0
        # EndOfBlock = number of samples per row
        if "/EndOfBlock" in parameters:
            eob = parameters["/EndOfBlock"].getRawValue()
            eob = not bool(eob == "false")
        else:
            eob = True
        # BlackIs1 = A flag indicating whether 1 bits are to be interpreted as black pixels and 0 bits as white pixels
        if "/BlackIs1" in parameters:
            blackIs1 = parameters["/BlackIs1"].getRawValue()
            blackIs1 = bool(blackIs1 == "true")
        else:
            blackIs1 = False
        # DamagedRowsBeforeError = The number of damaged rows of data to be tolerated before an error occurs
        if "/DamagedRowsBeforeError" in parameters:
            damagedRowsBeforeError = parameters["/DamagedRowsBeforeError"].getRawValue()
        else:
            damagedRowsBeforeError = 0
        try:
            decodedStream = CCITTFax().decode(
                stream,
                k,
                eol,
                byteAlign,
                columns,
                rows,
                eob,
                blackIs1,
                damagedRowsBeforeError,
            )
            return (0, decodedStream)
        except:
            return (-1, "Error decompressing string with CCITT Fax Decode")


def ccittFaxEncode(stream, parameters):
    """
    Method to encode streams using the CCITT facsimile standard.
    Only the K=0 (Group 3, pure one-dimensional / Modified Huffman) encoding scheme
    is supported.

    @param stream: Raw bitmap sample data (1 bit per pixel, each row starting on a byte boundary)
    @return: A tuple (status,statusContent), where statusContent is the encoded PDF stream in case status = 0 or an error in case status = -1
    """
    if parameters is None:
        parameters = {}
    if "/K" in parameters:
        k = parameters["/K"].getRawValue()
        if not isinstance(k, int):
            k = 0
        elif k != 0:
            return (-1, "CCITT encoding scheme not supported")
    else:
        k = 0
    if "/EndOfLine" in parameters:
        eol = parameters["/EndOfLine"].getRawValue()
        eol = bool(eol == "true")
    else:
        eol = False
    if "/EncodedByteAlign" in parameters:
        byteAlign = parameters["/EncodedByteAlign"].getRawValue()
        byteAlign = bool(byteAlign == "true")
    else:
        byteAlign = True
    if "/Columns" in parameters:
        columns = parameters["/Columns"].getRawValue()
        if not isinstance(columns, int):
            columns = 1728
    else:
        columns = 1728
    if "/Rows" in parameters:
        rows = parameters["/Rows"].getRawValue()
        if not isinstance(rows, int):
            rows = 0
    else:
        rows = 0
    if "/EndOfBlock" in parameters:
        eob = parameters["/EndOfBlock"].getRawValue()
        eob = not bool(eob == "false")
    else:
        eob = True
    if "/BlackIs1" in parameters:
        blackIs1 = parameters["/BlackIs1"].getRawValue()
        blackIs1 = bool(blackIs1 == "true")
    else:
        blackIs1 = False
    try:
        encodedStream = CCITTFax().encode(
            stream, k, eol, byteAlign, columns, rows, eob, blackIs1
        )
        return (0, encodedStream)
    except Exception as exc:
        return (-1, f"Error compressing string with CCITT Fax Encode: {exc}")


def crypt(stream, parameters):
    """
    Method to encrypt streams using a PDF security handler (NOT IMPLEMENTED YET)

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the encrypted PDF stream in case status = 0 or an error in case status = -1
    """
    if not parameters:
        return (0, stream)
    if "/Name" not in parameters or parameters["/Name"] is None:
        return (0, stream)
    cryptFilterName = parameters["/Name"].getValue()
    if cryptFilterName == "Identity":
        return (0, stream)
    return (-1, "Crypt not supported yet")


def decrypt(stream, parameters):
    """
    Method to decrypt streams using a PDF security handler (NOT IMPLEMENTED YET)

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the decrypted PDF stream in case status = 0 or an error in case status = -1
    """
    if not parameters:
        return (0, stream)
    if "/Name" not in parameters or parameters["/Name"] is None:
        return (0, stream)
    cryptFilterName = parameters["/Name"].getValue()
    if cryptFilterName == "Identity":
        return (0, stream)
    return (-1, "Decrypt not supported yet")


def dctDecode(stream, parameters):
    """
    Method to decode streams using a DCT technique based on the JPEG standard

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the decoded PDF stream in case status = 0 or an error in case status = -1
    """
    if not PIL_MODULE:
        return (-1, "PIL is not installed")
    try:
        rawBytes = stream.encode("latin-1") if isinstance(stream, str) else stream
        image = Image.open(BytesIO(rawBytes))
        decodedStream = image.tobytes()
        return (0, decodedStream.decode("latin-1"))
    except Exception as exc:
        return (-1, f"Error decompressing image data: {exc}")


def dctEncode(stream, parameters):
    """
    Method to encode streams using a DCT technique based on the JPEG standard

    @param stream: Raw, decoded image sample data
    @param parameters: dict expected to contain /Width, /Height, /ColorSpace and /BitsPerComponent PDFObjects
    @return: A tuple (status,statusContent), where statusContent is the encoded PDF stream in case status = 0 or an error in case status = -1
    """
    if not PIL_MODULE:
        return (-1, "PIL is not installed")
    try:
        widthElement = parameters.get("/Width")
        heightElement = parameters.get("/Height")
        if widthElement is None or heightElement is None:
            return (-1, "Missing /Width or /Height, cannot encode as JPEG")
        width = int(widthElement.getRawValue())
        height = int(heightElement.getRawValue())
        bitsElement = parameters.get("/BitsPerComponent")
        bitsPerComponent = (
            int(bitsElement.getRawValue()) if bitsElement is not None else 8
        )
        if bitsPerComponent != 8:
            return (-1, "Only 8-bit-per-component images are supported for DCTEncode")
        colorSpaceElement = parameters.get("/ColorSpace")
        if colorSpaceElement is None:
            colorSpaceName = "/DeviceRGB"
        elif colorSpaceElement.getType() == "name":
            colorSpaceName = colorSpaceElement.getValue()
        else:
            return (-1, "Only simple /ColorSpace names are supported for DCTEncode")
        mode = _IMAGE_COLORSPACE_TO_PIL_MODE.get(colorSpaceName)
        if mode is None:
            return (-1, f'Unsupported /ColorSpace "{colorSpaceName}" for DCTEncode')
        rawBytes = stream.encode("latin-1") if isinstance(stream, str) else stream
        expectedSize = width * height * len(mode)
        if len(rawBytes) < expectedSize:
            return (-1, "Not enough image sample data for the given /Width and /Height")
        image = Image.frombytes(mode, (width, height), rawBytes[:expectedSize])
        buffer = BytesIO()
        image.save(buffer, format="JPEG")
        return (0, buffer.getvalue().decode("latin-1"))
    except Exception as exc:
        return (-1, f"Error compressing image data: {exc}")


def jbig2Decode(stream, parameters):
    """
    Method to decode streams using the JBIG2 standard (NOT IMPLEMENTED YET)

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the decoded PDF stream in case status = 0 or an error in case status = -1
    """
    jbig2_globals = ""
    jbig2_page = ""
    # header = '974A42320D0A1A0A0100000001'
    # JBIG2Globals reference is next. If /JBIGGlobals 1 0 R, then ref 1 contains JBIG2Globals
    # Then content from stream with JBIG2Decode
    # end_of_page = '0000000331000100000000'
    # end_of_file = '00000004330100000000'
    # Concat all together to make full JBIG2 file.
    # return (0, stream.encode().hex())
    return (-1, "Jbig2Decode not supported yet")


def jbig2Encode(stream, parameters):
    """
    Method to encode streams using the JBIG2 standard (NOT IMPLEMENTED YET)

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the encoded PDF stream in case status = 0 or an error in case status = -1
    """
    return (-1, "Jbig2Encode not supported yet")


def jpxDecode(stream, parameters):
    """
    Method to decode streams using the JPEG2000 standard

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the decoded PDF stream in case status = 0 or an error in case status = -1
    """
    if not PIL_MODULE:
        return (-1, "PIL is not installed")
    try:
        rawBytes = stream.encode("latin-1") if isinstance(stream, str) else stream
        image = Image.open(BytesIO(rawBytes))
        decodedStream = image.tobytes()
        return (0, decodedStream.decode("latin-1"))
    except Exception as exc:
        return (-1, f"Error decompressing image data: {exc}")


def jpxEncode(stream, parameters):
    """
    Method to encode streams using the JPEG2000 standard (NOT IMPLEMENTED YET)

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the encoded PDF stream in case status = 0 or an error in case status = -1
    """
    if not PIL_MODULE:
        return (-1, "PIL is not installed")
    try:
        widthElement = parameters.get("/Width")
        heightElement = parameters.get("/Height")
        if widthElement is None or heightElement is None:
            return (-1, "Missing /Width or /Height, cannot encode as JPEG2000")
        width = int(widthElement.getRawValue())
        height = int(heightElement.getRawValue())
        bitsElement = parameters.get("/BitsPerComponent")
        bitsPerComponent = (
            int(bitsElement.getRawValue()) if bitsElement is not None else 8
        )
        if bitsPerComponent != 8:
            return (-1, "Only 8-bit-per-component images are supported for JPXEncode")
        colorSpaceElement = parameters.get("/ColorSpace")
        if colorSpaceElement is None:
            colorSpaceName = "/DeviceRGB"
        elif colorSpaceElement.getType() == "name":
            colorSpaceName = colorSpaceElement.getValue()
        else:
            return (-1, "Only simple /ColorSpace names are supported for JPXEncode")
        mode = _IMAGE_COLORSPACE_TO_PIL_MODE.get(colorSpaceName)
        if mode is None:
            return (-1, f'Unsupported /ColorSpace "{colorSpaceName}" for JPXEncode')
        rawBytes = stream.encode("latin-1") if isinstance(stream, str) else stream
        expectedSize = width * height * len(mode)
        if len(rawBytes) < expectedSize:
            return (-1, "Not enough image sample data for the given /Width and /Height")
        image = Image.frombytes(mode, (width, height), rawBytes[:expectedSize])
        buffer = BytesIO()
        image.save(buffer, format="JPEG2000")
        return (0, buffer.getvalue().decode("latin-1"))
    except Exception as exc:
        return (-1, f"Error compressing image data: {exc}")
