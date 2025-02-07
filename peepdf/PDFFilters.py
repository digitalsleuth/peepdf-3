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


def decodeStream(stream, thisFilter, parameters=None):
    """
    Decode the given stream

    @param stream: Stream to be decoded (string)
    @param thisFilter: Filter to apply to decode the stream
    @param parameters: List of PDFObjects containing the parameters for the filter
    @return: A tuple (status,statusContent), where statusContent is the decoded stream in case status = 0 or an error in case status = -1
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
        ret = jpxDecode(stream)
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
        ret = jpxEncode(stream)
    elif thisFilter == "/Crypt":
        ret = crypt(stream, parameters)
    else:
        ret = (-1, f'Unknown filter "{thisFilter}"')
    return ret


def ascii85Decode(stream):
    """
    Method to decode streams using ASCII85

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the decoded PDF stream in case status = 0 or an error in case status = -1
    """
    n = b = 0
    decodedStream = ""
    try:
        for c in stream:
            if "!" <= c <= "u":
                n += 1
                b = b * 85 + (ord(c) - 33)
                if n == 5:
                    decodedStream += struct.pack(">L", b)
                    n = b = 0
            elif c == "z":
                assert n == 0
                decodedStream += "\0\0\0\0"
            elif c == "~":
                if n:
                    for _ in range(5 - n):
                        b = b * 85 + 84
                    decodedStream += struct.pack(">L", b)[: n - 1]
                break
    except:
        return (-1, "Unspecified error")
    return (0, decodedStream)


def ascii85Encode(stream):
    """
    Method to encode streams using ASCII85 (NOT SUPPORTED YET)

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the encoded PDF stream in case status = 0 or an error in case status = -1
    TODO: use base64 a85 encode and decode
    """

    return (-1, "Ascii85Encode not supported yet")


def asciiHexDecode(stream):
    """
    Method to decode streams using hexadecimal encoding

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the decoded PDF stream in case status = 0 or an error in case status = -1
    """
    eod = ">"
    decodedStream = ""
    char = ""
    index = 0
    while index < len(stream):
        c = stream[index]
        if c == eod:
            if len(decodedStream) % 2 != 0:
                char += "0"
                try:
                    decodedStream += chr(int(char, 16))
                except:
                    return (-1, "Error in hexadecimal conversion")
            break
        if c.isspace():
            index += 1
            continue
        char += c
        if len(char) == 2:
            try:
                decodedStream += chr(int(char, 16))
            except:
                return (-1, "Error in hexadecimal conversion")
            char = ""
        index += 1
    return (0, decodedStream)


def asciiHexEncode(stream):
    """
    Method to encode streams using hexadecimal encoding

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the encoded PDF stream in case status = 0 or an error in case status = -1
    Confirm whether or not Unicode correction is needed here.
    """
    try:
        encodedStream = hexlify(stream.encode()).decode("latin-1")
    except:
        return (-1, "Error in hexadecimal conversion")
    return (0, encodedStream)


def flateDecode(stream, parameters):
    """
    Method to decode streams using the Flate algorithm

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the decoded PDF stream in case status = 0 or an error in case status = -1
    """
    decodedStream = ""
    try:
        if not isinstance(stream, bytes):
            decodedStream = (zlib.decompress(stream.encode("latin-1"))).decode(
                "latin-1"
            )
        else:
            decodedStream = zlib.decompress(stream).decode("latin-1")
    except:
        return (-1, "Error decompressing string")

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
    @return: A tuple (status,statusContent), where statusContent is the encoded PDF stream in case status = 0 or an error in case status = -1
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
        return (-1, "Error decompressing string")

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
    if "/EarlyChange" in parameters:
        earlyChange = parameters["/EarlyChange"].getRawValue()
    else:
        earlyChange = 1
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
    encodedStream = ""
    if parameters is None or parameters == {}:
        try:
            generator = compress(stream)
            for c in generator:
                encodedStream += c
            return (0, encodedStream)
        except:
            return (-1, "Error compressing string")
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
        if "/EarlyChange" in parameters:
            earlyChange = parameters["/EarlyChange"].getRawValue()
        else:
            earlyChange = 1
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
            return (0, encodedStream)
        except:
            return (-1, "Error decompressing string")


def pre_prediction(stream, predictor, columns, colors, bits):
    """
    Predictor function to make the stream more predictable and improve compression (PDF Specification)

    @param stream: The stream to be modified
    @param predictor: The type of predictor to apply
    @param columns: Number of samples per row
    @param colors: Number of colors per sample
    @param bits: Number of bits per color
    @return: A tuple (status,statusContent), where statusContent is the modified stream in case status = 0 or an error in case status = -1
    """

    output = ""
    # TODO: TIFF and more PNG predictions

    # PNG prediction
    if 10 <= predictor <= 15:
        # PNG prediction can vary from row to row
        for row in range(len(stream) / columns):
            rowdata = [ord(x) for x in stream[(row * columns) : ((row + 1) * columns)]]
            filterByte = predictor - 10
            rowdata = [filterByte] + rowdata
            if filterByte == 0:
                pass
            elif filterByte == 1:
                for i in range(len(rowdata) - 1, 1, -1):
                    if rowdata[i] < rowdata[i - 1]:
                        rowdata[i] = rowdata[i] + 256 - rowdata[i - 1]
                    else:
                        rowdata[i] = rowdata[i] - rowdata[i - 1]
            else:
                return (-1, "Unsupported predictor")
            output += "".join([chr(x) for x in rowdata])
        return (0, output)
    return (-1, "Unsupported predictor")


def post_prediction(decodedStream, predictor, columns, colors, bits):
    """
    Predictor function to obtain the real stream, removing the prediction (PDF Specification)

    @param decodedStream: The decoded stream to be modified
    @param predictor: The type of predictor to apply
    @param columns: Number of samples per row
    @param colors: Number of colors per sample
    @param bits: Number of bits per color
    @return: A tuple (status,statusContent), where statusContent is the modified decoded stream in case status = 0 or an error in case status = -1
    """

    output = ""
    bytesPerRow = int((colors * bits * columns + 7) / 8)

    # TIFF - 2
    # http://www.gnupdf.org/PNG_and_TIFF_Predictors_Filter#TIFF
    if predictor == 2:
        numRows = len(decodedStream) / bytesPerRow
        bitmask = 2**bits - 1
        outputBitsStream = ""
        for rowIndex in range(numRows):
            row = decodedStream[
                rowIndex * bytesPerRow : rowIndex * bytesPerRow + bytesPerRow
            ]
            ret, colorNums = getNumsFromBytes(row, bits)
            if ret == -1:
                return (ret, colorNums)
            pixel = [0 for x in range(colors)]
            for i in range(columns):
                for j in range(colors):
                    diffPixel = colorNums[i + j]
                    pixel[j] = (pixel[j] + diffPixel) & bitmask
                    ret, outputBits = getBitsFromNum(pixel[j], bits)
                    if ret == -1:
                        return (ret, outputBits)
                    outputBitsStream += outputBits
        output = getBytesFromBits(outputBitsStream)
        return output
    # PNG prediction
    # http://www.libpng.org/pub/png/spec/1.2/PNG-Filters.html
    # http://www.gnupdf.org/PNG_and_TIFF_Predictors_Filter#TIFF
    if 10 <= predictor <= 15:
        bytesPerRow += 1
        numRows = int((len(decodedStream) + bytesPerRow - 1) / bytesPerRow)
        numSamplesPerRow = columns + 1
        bytesPerSample = int((colors * bits + 7) / 8)
        upRowdata = (0,) * numSamplesPerRow
        for row in range(numRows):
            rowdata = [
                ord(x)
                for x in decodedStream[
                    (row * int(bytesPerRow)) : ((row + 1) * int(bytesPerRow))
                ]
            ]
            # PNG prediction can vary from row to row
            filterByte = rowdata[0]
            rowdata[0] = 0
            if filterByte == 0:
                # None
                pass
            elif filterByte == 1:
                # Sub - 11
                for i in range(1, numSamplesPerRow):
                    if i < bytesPerSample:
                        prevSample = 0
                    else:
                        prevSample = rowdata[i - bytesPerSample]
                    rowdata[i] = int((rowdata[i] + prevSample) % 256)
            elif filterByte == 2:
                # Up - 12
                for i in range(1, numSamplesPerRow):
                    upSample = upRowdata[i]
                    rowdata[i] = int((rowdata[i] + upSample) % 256)
            elif filterByte == 3:
                # Average - 13
                for i in range(1, numSamplesPerRow):
                    upSample = upRowdata[i]
                    if i < bytesPerSample:
                        prevSample = 0
                    else:
                        prevSample = rowdata[i - bytesPerSample]
                    rowdata[i] = int((rowdata[i] + ((prevSample + upSample) / 2)) % 256)
            elif filterByte == 4:
                # Paeth - 14
                for i in range(1, numSamplesPerRow):
                    upSample = upRowdata[i]
                    if i < bytesPerSample:
                        prevSample = 0
                        upPrevSample = 0
                    else:
                        prevSample = rowdata[i - bytesPerSample]
                        upPrevSample = upRowdata[i - bytesPerSample]
                    p = prevSample + upSample - upPrevSample
                    pa = abs(p - prevSample)
                    pb = abs(p - upSample)
                    pc = abs(p - upPrevSample)
                    if pa <= pb and pa <= pc:
                        nearest = prevSample
                    elif pb <= pc:
                        nearest = upSample
                    else:
                        nearest = upPrevSample
                    rowdata[i] = int((rowdata[i] + nearest) % 256)
            else:
                # Optimum - 15
                # return (-1,'Unsupported predictor')
                pass
            upRowdata = rowdata
            output += "".join([chr(x) for x in rowdata[1:]])
        return (0, output)
    return (-1, "Wrong value for predictor")


def runLengthDecode(stream):
    """
    Method to decode streams using the Run-Length algorithm

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the decoded PDF stream in case status = 0 or an error in case status = -1
    """
    decodedStream = ""
    index = 0
    try:
        while index < len(stream):
            length = ord(stream[index])
            if 0 <= length < 128:
                decodedStream += stream[index + 1 : index + length + 2]
                index += length + 2
            elif 128 < length < 256:
                decodedStream += stream[index + 1] * (257 - length)
                index += 2
            else:
                break
    except:
        return (-1, "Error decoding string")
    return (0, decodedStream)


def runLengthEncode(stream):
    """
    Method to encode streams using the Run-Length algorithm (NOT IMPLEMENTED YET)

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the encoded PDF stream in case status = 0 or an error in case status = -1
    """
    return (-1, "RunLengthEncode not supported yet")


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
            return (-1, "Error decompressing string")
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
            return (-1, "Error decompressing string")


def ccittFaxEncode(stream, parameters):
    """
    Method to encode streams using the CCITT facsimile standard (NOT IMPLEMENTED YET)

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the encoded PDF stream in case status = 0 or an error in case status = -1
    """
    return (-1, "CcittFaxEncode not supported yet")


def crypt(stream, parameters):
    """
    Method to encrypt streams using a PDF security handler (NOT IMPLEMENTED YET)

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the encrypted PDF stream in case status = 0 or an error in case status = -1
    """
    if not parameters:
        return (0, stream)
    if not "/Name" in parameters or parameters["/Name"] is None:
        return (0, stream)
    cryptFilterName = parameters["/Name"].getValue()
    if cryptFilterName == "Identity":
        return (0, stream)
    # TODO: algorithm is cryptFilterName, specified in the /CF dictionary
    return (-1, "Crypt not supported yet")


def decrypt(stream, parameters):
    """
    Method to decrypt streams using a PDF security handler (NOT IMPLEMENTED YET)

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the decrypted PDF stream in case status = 0 or an error in case status = -1
    """
    if not parameters:
        return (0, stream)
    if not "/Name" in parameters or parameters["/Name"] is None:
        return (0, stream)
    cryptFilterName = parameters["/Name"].getValue()
    if cryptFilterName == "Identity":
        return (0, stream)
    # TODO: algorithm is cryptFilterName, specified in the /CF dictionary
    return (-1, "Decrypt not supported yet")


def dctDecode(stream, parameters):
    """
    Method to decode streams using a DCT technique based on the JPEG standard (NOT IMPLEMENTED YET)

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the decoded PDF stream in case status = 0 or an error in case status = -1
    """
    decodedStream = ""
    if not PIL_MODULE:
        return (-1, "PIL is not installed")
    try:
        im = Image.open(BytesIO(stream.encode("latin-1")))
        decodedStream = im.tobytes()
        return (0, decodedStream)
    except:
        return (-1, "Error decompressing image data")


def dctEncode(stream, parameters):
    """
    Method to encode streams using a DCT technique based on the JPEG standard (NOT IMPLEMENTED YET)

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the encoded PDF stream in case status = 0 or an error in case status = -1
    """
    return (-1, "DctEncode not supported yet")


def jbig2Decode(stream, parameters):
    """
    Method to decode streams using the JBIG2 standard (NOT IMPLEMENTED YET)

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the decoded PDF stream in case status = 0 or an error in case status = -1
    """
    return (-1, "Jbig2Decode not supported yet")


def jbig2Encode(stream, parameters):
    """
    Method to encode streams using the JBIG2 standard (NOT IMPLEMENTED YET)

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the encoded PDF stream in case status = 0 or an error in case status = -1
    """
    return (-1, "Jbig2Encode not supported yet")


def jpxDecode(stream):
    """
    Method to decode streams using the JPEG2000 standard (NOT IMPLEMENTED YET)

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the decoded PDF stream in case status = 0 or an error in case status = -1
    """
    return (-1, "JpxDecode not supported yet")


def jpxEncode(stream):
    """
    Method to encode streams using the JPEG2000 standard (NOT IMPLEMENTED YET)

    @param stream: A PDF stream
    @return: A tuple (status,statusContent), where statusContent is the encoded PDF stream in case status = 0 or an error in case status = -1
    """
    return (-1, "JpxEncode not supported yet")
