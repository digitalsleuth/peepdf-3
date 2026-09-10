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
ccitt

__author__ = "Binjo"
__version__ = "0.1"
__date__ = "2012-04-08 14:30:05"
---------------------------------

jjdecode

Python version of the jjdecode function written by Syed Zainudeen
http://csc.cs.utm.my/syed/images/files/jjdecode/jjdecode.html
+NCR/CRC! [ReVeRsEr] - crackinglandia@gmail.com
The original algorithm was written in Javascript by Yosuke Hasegawa (http://utf-8.jp/public/jjencode.html)
Modified to integrate it with peepdf

---------------------------------

lzw

Library to encode/decode streams using the LZW algorithm. Mix of third party libraries (python-lzw and pdfminer) with some modifications.

A stream friendly, simple compression library, built around
iterators. See L{compress} for the easiest way to get started.

After the TIFF implementation of LZW, as described at
U{http://www.fileformat.info/format/tiff/corion-lzw.htm}


In an even-nuttier-shell, lzw compresses input bytes with integer
codes. Starting with codes 0-255 that code to themselves, and two
control codes, we work our way through a stream of bytes. When we
encounter a pair of codes c1,c2 we add another entry to our code table
with the lowest available code and the value value(c1) + value(c2)[0]

Of course, there are details :)

The Details
===========

    Our control codes are

        - CLEAR_CODE (codepoint 256). When this code is encountered, we flush
          the codebook and start over.
        - END_OF_INFO_CODE (codepoint 257). This code is reserved for
          encoder/decoders over the integer codepoint stream (like the
          mechanical bit that unpacks bits into codepoints)

    When dealing with bytes, codes are emitted as variable
    length bit strings packed into the stream of bytes.

    codepoints are written with varying length
        - initially 9 bits
        - at 512 entries 10 bits
        - at 1025 entries at 11 bits
        - at 2048 entries 12 bits
        - with max of 4095 entries in a table (including Clear and EOI)

    code points are stored with their MSB in the most significant bit
    available in the output character.

>>> import lzw
>>>
>>> with open("README.txt", "rb") as f:
...     mybytes = f.read()
>>> compressed = b"".join(lzw.compress(mybytes))

__author__ = "Joe Bowers"
__license__ = "MIT License"
__version__ = "0.01.01"
__status__ = "Development"
__email__ = "joerbowers@gmail.com"
__url__ = "http://www.joe-bowers.com/static/lzw"

"""

import re
import struct
from io import StringIO


## START CCITT


class BitWriterException(Exception):
    pass


class BitWriter:
    """
    BitWriter Class
    """

    def __init__(
        self,
    ):
        """
        Init
        """
        self._dataParts = []
        self._last_byte = None
        self._bit_ptr = 0

    @property
    def data(self):
        """
        return self._data
        """
        return "".join(self._dataParts)

    def align_to_byte(self):
        """
        Pads with zero bits up to the next byte boundary, if not already
        aligned on one.
        """
        if self._bit_ptr != 0:
            self.write(0, 8 - self._bit_ptr)

    def write(self, data, length):
        """
        write function
        """
        if not (length >= 0 and (1 << length) > data):
            raise BitWriterException("Invalid data length")

        if length == 8 and not self._last_byte and self._bit_ptr == 0:
            self._dataParts.append(chr(data))
            return

        while length > 0:
            if length >= 8 - self._bit_ptr:
                length -= 8 - self._bit_ptr
                if not self._last_byte:
                    self._last_byte = 0
                self._last_byte |= (data >> length) & ((1 << (8 - self._bit_ptr)) - 1)

                data &= (1 << length) - 1
                self._dataParts.append(chr(self._last_byte))
                self._last_byte = None
                self._bit_ptr = 0
            else:
                if not self._last_byte:
                    self._last_byte = 0
                self._last_byte |= (data & ((1 << length) - 1)) << (
                    8 - self._bit_ptr - length
                )
                self._bit_ptr += length

                if self._bit_ptr == 8:
                    self._dataParts.append(chr(self._last_byte))
                    self._last_byte = None
                    self._bit_ptr = 0

                length = 0


class BitReaderException(Exception):
    pass


class BitReader:
    """
    BitReader Class
    """

    def __init__(self, data):
        """
        Init
        """
        self._data = data
        self._byte_ptr, self._bit_ptr = 0, 0

    def reset(self):
        """
        Set _byte_ptr and _bit_ptr back to zero
        """
        self._byte_ptr, self._bit_ptr = 0, 0

    @property
    def eod_p(self):
        """
        return bool for _byte_ptr location compared to size of _data
        """
        return self._byte_ptr >= len(self._data)

    @property
    def pos(self):
        """
        return sum of bitshifted _byte_ptr value + _bit_ptr
        """
        return (self._byte_ptr << 3) + self._bit_ptr

    @property
    def size(self):
        """
        return bitshifted value of the _data length
        """
        return len(self._data) << 3

    @pos.setter
    def pos(self, bits):
        """
        Set _byte_ptr and _bit_ptr positions if bits is not larger than the size
        """
        if bits > self.size:
            raise BitReaderException("Pointer position out of data")

        pbyte = bits >> 3
        pbit = bits - (pbyte << 3)
        self._byte_ptr, self._bit_ptr = pbyte, pbit

    def peek(self, length):
        """
        Read provided length of data provided it fits within readable boundaries
        """
        if length <= 0:
            raise BitReaderException("Invalid read length")
        if (self.pos + length) > self.size:
            raise BitReaderException("Insufficient data")

        n = 0
        byte_ptr, bit_ptr = self._byte_ptr, self._bit_ptr

        while length > 0:
            byte = ord(self._data[byte_ptr])

            if length > 8 - bit_ptr:
                length -= 8 - bit_ptr
                n |= (byte & ((1 << (8 - bit_ptr)) - 1)) << length

                byte_ptr += 1
                bit_ptr = 0
            else:
                n |= (byte >> (8 - bit_ptr - length)) & ((1 << length) - 1)
                length = 0

        return n

    def read(self, length):
        """
        Return data read and adjust position forward
        """
        n = self.peek(length)
        self.pos += length

        return n


def codeword(bits):
    """return tuple rather than list, since list is not hashable..."""
    return (int(bits, 2), len(bits))


class CCITTFax:
    """
    CCITTFax Class
    """

    EOL = codeword("000000000001")
    RTC = codeword("000000000001" * 6)

    WHITE_TERMINAL_ENCODE_TABLE = {
        0: codeword("00110101"),
        1: codeword("000111"),
        2: codeword("0111"),
        3: codeword("1000"),
        4: codeword("1011"),
        5: codeword("1100"),
        6: codeword("1110"),
        7: codeword("1111"),
        8: codeword("10011"),
        9: codeword("10100"),
        10: codeword("00111"),
        11: codeword("01000"),
        12: codeword("001000"),
        13: codeword("000011"),
        14: codeword("110100"),
        15: codeword("110101"),
        16: codeword("101010"),
        17: codeword("101011"),
        18: codeword("0100111"),
        19: codeword("0001100"),
        20: codeword("0001000"),
        21: codeword("0010111"),
        22: codeword("0000011"),
        23: codeword("0000100"),
        24: codeword("0101000"),
        25: codeword("0101011"),
        26: codeword("0010011"),
        27: codeword("0100100"),
        28: codeword("0011000"),
        29: codeword("00000010"),
        30: codeword("00000011"),
        31: codeword("00011010"),
        32: codeword("00011011"),
        33: codeword("00010010"),
        34: codeword("00010011"),
        35: codeword("00010100"),
        36: codeword("00010101"),
        37: codeword("00010110"),
        38: codeword("00010111"),
        39: codeword("00101000"),
        40: codeword("00101001"),
        41: codeword("00101010"),
        42: codeword("00101011"),
        43: codeword("00101100"),
        44: codeword("00101101"),
        45: codeword("00000100"),
        46: codeword("00000101"),
        47: codeword("00001010"),
        48: codeword("00001011"),
        49: codeword("01010010"),
        50: codeword("01010011"),
        51: codeword("01010100"),
        52: codeword("01010101"),
        53: codeword("00100100"),
        54: codeword("00100101"),
        55: codeword("01011000"),
        56: codeword("01011001"),
        57: codeword("01011010"),
        58: codeword("01011011"),
        59: codeword("01001010"),
        60: codeword("01001011"),
        61: codeword("00110010"),
        62: codeword("00110011"),
        63: codeword("00110100"),
    }

    WHITE_TERMINAL_DECODE_TABLE = dict(
        (v, k) for k, v in WHITE_TERMINAL_ENCODE_TABLE.items()
    )

    BLACK_TERMINAL_ENCODE_TABLE = {
        0: codeword("0000110111"),
        1: codeword("010"),
        2: codeword("11"),
        3: codeword("10"),
        4: codeword("011"),
        5: codeword("0011"),
        6: codeword("0010"),
        7: codeword("00011"),
        8: codeword("000101"),
        9: codeword("000100"),
        10: codeword("0000100"),
        11: codeword("0000101"),
        12: codeword("0000111"),
        13: codeword("00000100"),
        14: codeword("00000111"),
        15: codeword("000011000"),
        16: codeword("0000010111"),
        17: codeword("0000011000"),
        18: codeword("0000001000"),
        19: codeword("00001100111"),
        20: codeword("00001101000"),
        21: codeword("00001101100"),
        22: codeword("00000110111"),
        23: codeword("00000101000"),
        24: codeword("00000010111"),
        25: codeword("00000011000"),
        26: codeword("000011001010"),
        27: codeword("000011001011"),
        28: codeword("000011001100"),
        29: codeword("000011001101"),
        30: codeword("000001101000"),
        31: codeword("000001101001"),
        32: codeword("000001101010"),
        33: codeword("000001101011"),
        34: codeword("000011010010"),
        35: codeword("000011010011"),
        36: codeword("000011010100"),
        37: codeword("000011010101"),
        38: codeword("000011010110"),
        39: codeword("000011010111"),
        40: codeword("000001101100"),
        41: codeword("000001101101"),
        42: codeword("000011011010"),
        43: codeword("000011011011"),
        44: codeword("000001010100"),
        45: codeword("000001010101"),
        46: codeword("000001010110"),
        47: codeword("000001010111"),
        48: codeword("000001100100"),
        49: codeword("000001100101"),
        50: codeword("000001010010"),
        51: codeword("000001010011"),
        52: codeword("000000100100"),
        53: codeword("000000110111"),
        54: codeword("000000111000"),
        55: codeword("000000100111"),
        56: codeword("000000101000"),
        57: codeword("000001011000"),
        58: codeword("000001011001"),
        59: codeword("000000101011"),
        60: codeword("000000101100"),
        61: codeword("000001011010"),
        62: codeword("000001100110"),
        63: codeword("000001100111"),
    }

    BLACK_TERMINAL_DECODE_TABLE = dict(
        (v, k) for k, v in BLACK_TERMINAL_ENCODE_TABLE.items()
    )

    WHITE_CONFIGURATION_ENCODE_TABLE = {
        64: codeword("11011"),
        128: codeword("10010"),
        192: codeword("010111"),
        256: codeword("0110111"),
        320: codeword("00110110"),
        384: codeword("00110111"),
        448: codeword("01100100"),
        512: codeword("01100101"),
        576: codeword("01101000"),
        640: codeword("01100111"),
        704: codeword("011001100"),
        768: codeword("011001101"),
        832: codeword("011010010"),
        896: codeword("011010011"),
        960: codeword("011010100"),
        1024: codeword("011010101"),
        1088: codeword("011010110"),
        1152: codeword("011010111"),
        1216: codeword("011011000"),
        1280: codeword("011011001"),
        1344: codeword("011011010"),
        1408: codeword("011011011"),
        1472: codeword("010011000"),
        1536: codeword("010011001"),
        1600: codeword("010011010"),
        1664: codeword("011000"),
        1728: codeword("010011011"),
        1792: codeword("00000001000"),
        1856: codeword("00000001100"),
        1920: codeword("00000001001"),
        1984: codeword("000000010010"),
        2048: codeword("000000010011"),
        2112: codeword("000000010100"),
        2176: codeword("000000010101"),
        2240: codeword("000000010110"),
        2340: codeword("000000010111"),
        2368: codeword("000000011100"),
        2432: codeword("000000011101"),
        2496: codeword("000000011110"),
        2560: codeword("000000011111"),
    }

    WHITE_CONFIGURATION_DECODE_TABLE = dict(
        (v, k) for k, v in WHITE_CONFIGURATION_ENCODE_TABLE.items()
    )

    BLACK_CONFIGURATION_ENCODE_TABLE = {
        64: codeword("0000001111"),
        128: codeword("000011001000"),
        192: codeword("000011001001"),
        256: codeword("000001011011"),
        320: codeword("000000110011"),
        384: codeword("000000110100"),
        448: codeword("000000110101"),
        512: codeword("0000001101100"),
        576: codeword("0000001101101"),
        640: codeword("0000001001010"),
        704: codeword("0000001001011"),
        768: codeword("0000001001100"),
        832: codeword("0000001001101"),
        896: codeword("0000001110010"),
        960: codeword("0000001110011"),
        1024: codeword("0000001110100"),
        1088: codeword("0000001110101"),
        1152: codeword("0000001110110"),
        1216: codeword("0000001110111"),
        1280: codeword("0000001010010"),
        1344: codeword("0000001010011"),
        1408: codeword("0000001010100"),
        1472: codeword("0000001010101"),
        1536: codeword("0000001011010"),
        1600: codeword("0000001011011"),
        1664: codeword("0000001100100"),
        1728: codeword("0000001100101"),
        1792: codeword("00000001000"),
        1856: codeword("00000001100"),
        1920: codeword("00000001001"),
        1984: codeword("000000010010"),
        2048: codeword("000000010011"),
        2112: codeword("000000010100"),
        2176: codeword("000000010101"),
        2240: codeword("000000010110"),
        2340: codeword("000000010111"),
        2368: codeword("000000011100"),
        2432: codeword("000000011101"),
        2496: codeword("000000011110"),
        2560: codeword("000000011111"),
    }

    BLACK_CONFIGURATION_DECODE_TABLE = dict(
        (v, k) for k, v in BLACK_CONFIGURATION_ENCODE_TABLE.items()
    )

    def __init__(
        self,
    ):
        """
        Init
        """

    def decode(
        self,
        stream,
        k=0,
        eol=False,
        byteAlign=False,
        columns=1728,
        rows=0,
        eob=True,
        blackIs1=False,
        damagedRowsBeforeError=0,
    ):
        """
        Decode provided value, return the decoded BitWriter data
        """
        byteAlign = True

        white = int(not blackIs1)
        bitr = BitReader(stream)
        bitw = BitWriter()
        unlimitedRows = rows <= 0
        while not bitr.eod_p and (unlimitedRows or rows > 0):
            current_color = white
            if byteAlign and bitr.pos % 8 != 0:
                bitr.pos += 8 - (bitr.pos % 8)

            if eob and bitr.peek(self.RTC[1]) == self.RTC[0]:
                bitr.pos += self.RTC[1]
                break

            if bitr.peek(self.EOL[1]) != self.EOL[0]:
                if eol:
                    raise Exception(
                        f"No end-of-line pattern found (at bit pos {bitr.pos}/{bitr.size})"
                    )
            else:
                bitr.pos += self.EOL[1]

            line_length = 0
            while line_length < columns:
                if current_color == white:
                    bit_length = self.get_white_bits(bitr)
                else:
                    bit_length = self.get_black_bits(bitr)
                if bit_length is None:
                    raise Exception(
                        f"Unfinished line (at bit pos {bitr.pos}/{bitr.size}), {bitw.data}"
                    )

                line_length += bit_length
                if line_length > columns:
                    raise Exception(
                        f"Line is too long (at bit pos {bitr.pos}/{bitr.size})"
                    )

                bitw.write((current_color << bit_length) - current_color, bit_length)

                current_color ^= 1

            rows -= 1
        return bitw.data

    def encode(
        self,
        stream,
        k=0,
        eol=False,
        byteAlign=False,
        columns=1728,
        rows=0,
        eob=True,
        blackIs1=False,
    ):
        """
        Only K-=0 (one-dimensional) encoding is supported
        """
        if k != 0:
            raise ValueError("CCITT encoding scheme not supported")
        if columns <= 0:
            raise ValueError("Invalid /Columns value")
        rowStride = (columns + 7) // 8
        if rows <= 0:
            if len(stream) % rowStride != 0:
                raise ValueError("Cannot determine number of rows from data length")
            rows = len(stream) // rowStride

        whiteBitValue = int(not blackIs1)
        bitw = BitWriter()

        for rowIndex in range(rows):
            if byteAlign:
                bitw.align_to_byte()
            if eol:
                bitw.write(self.EOL[0], self.EOL[1])

            rowBytes = stream[rowIndex * rowStride : (rowIndex + 1) * rowStride]
            bitr = BitReader(rowBytes)
            isWhite = True
            remaining = columns
            while remaining > 0:
                currentBitValue = whiteBitValue if isWhite else 1 - whiteBitValue
                runLength = 0
                while runLength < remaining and bitr.peek(1) == currentBitValue:
                    bitr.pos += 1
                    runLength += 1
                self._write_run(bitw, isWhite, runLength)
                remaining -= runLength
                isWhite = not isWhite

        if eob:
            if byteAlign:
                bitw.align_to_byte()
            bitw.write(self.RTC[0], self.RTC[1])

        return bitw.data

    def _write_run(self, bitw, is_white, run_length):
        config_table = (
            self.WHITE_CONFIGURATION_ENCODE_TABLE
            if is_white
            else self.BLACK_CONFIGURATION_ENCODE_TABLE
        )
        term_table = (
            self.WHITE_TERMINAL_ENCODE_TABLE
            if is_white
            else self.BLACK_TERMINAL_ENCODE_TABLE
        )
        remaining = run_length
        while remaining >= 2560:
            code, length = config_table[2560]
            bitw.write(code, length)
            remaining -= 2560
        if remaining >= 64:
            makeup = (remaining // 64) * 64
            code, length = config_table[makeup]
            bitw.write(code, length)
            remaining -= makeup
        code, length = term_table[remaining]
        bitw.write(code, length)

    def get_white_bits(self, bitr):
        """
        Return white bits
        """
        return self.get_color_bits(
            bitr,
            self.WHITE_CONFIGURATION_DECODE_TABLE,
            self.WHITE_TERMINAL_DECODE_TABLE,
        )

    def get_black_bits(self, bitr):
        """
        Return black bits
        """
        return self.get_color_bits(
            bitr,
            self.BLACK_CONFIGURATION_DECODE_TABLE,
            self.BLACK_TERMINAL_DECODE_TABLE,
        )

    def get_color_bits(self, bitr, config_words, term_words):
        """
        Return color bits
        """
        bits = 0
        check_conf = True

        while check_conf:
            check_conf = False

            for i in range(2, 14):
                code = bitr.peek(i)
                config_value = config_words.get((code, i), None)

                if config_value is not None:
                    bitr.pos += i
                    bits += config_value
                    if config_value == 2560:
                        check_conf = True
                    break

            for i in range(2, 14):
                code = bitr.peek(i)
                term_value = term_words.get((code, i), None)

                if term_value is not None:
                    bitr.pos += i
                    bits += term_value

                    return bits

        return None


## END CCITT

## START JJDECODE


class JJDecoder:
    def __init__(self, jj_encoded_data):
        self.encoded_str = jj_encoded_data

    def clean(self):
        self.encoded_str = re.sub(r"^\s+|\s+$", "", self.encoded_str)

    def checkPalindrome(self):
        startpos = -1
        endpos = -1
        gv, gvl = -1, -1

        index = self.encoded_str.find('"\'\\"+\'+",')

        if index == 0:
            startpos = self.encoded_str.find('$$+"\\""+') + 8
            endpos = self.encoded_str.find('"\\"")())()')
            gv = self.encoded_str[index + 9 : self.encoded_str.find("=~[]")]
            gvl = len(gv)
        else:
            gv = self.encoded_str[0 : self.encoded_str.find("=")]
            gvl = len(gv)
            startpos = self.encoded_str.find('"\\""+') + 5
            endpos = self.encoded_str.find('"\\"")())()')

        return (startpos, endpos, gv, gvl)

    def decode(self):
        self.clean()
        startpos, endpos, gv, _ = self.checkPalindrome()

        if startpos == endpos:
            return (-1, "There is no data to decode")

        data = self.encoded_str[startpos:endpos]

        b = [
            "___+",
            "__$+",
            "_$_+",
            "_$$+",
            "$__+",
            "$_$+",
            "$$_+",
            "$$$+",
            "$___+",
            "$__$+",
            "$_$_+",
            "$_$$+",
            "$$__+",
            "$$_$+",
            "$$$_+",
            "$$$$+",
        ]

        str_l = '(![]+"")[' + gv + "._$_]+"
        str_o = gv + "._$+"
        str_t = gv + ".__+"
        str_u = gv + "._+"

        str_hex = gv + "."

        str_s = '"'
        gvsig = gv + "."

        str_quote = '\\\\\\"'
        str_slash = "\\\\\\\\"

        str_lower = '\\\\"+'
        str_upper = '\\\\"+' + gv + "._+"

        str_end = '"+'

        outParts = []
        while data != "":
            # l o t u
            if data.find(str_l) == 0:
                data = data[len(str_l) :]
                outParts.append("l")
                continue
            if data.find(str_o) == 0:
                data = data[len(str_o) :]
                outParts.append("o")
                continue
            if data.find(str_t) == 0:
                data = data[len(str_t) :]
                outParts.append("t")
                continue
            if data.find(str_u) == 0:
                data = data[len(str_u) :]
                outParts.append("u")
                continue

            # 0123456789abcdef
            if data.find(str_hex) == 0:
                data = data[len(str_hex) :]

                for i, entry in enumerate(b):
                    if data.find(entry) == 0:
                        data = data[len(entry) :]
                        outParts.append(f"{i:x}")
                        break
                continue

            # start of s block
            if data.find(str_s) == 0:
                data = data[len(str_s) :]

                # check if "R
                if data.find(str_upper) == 0:  # r4 n >= 128
                    data = data[len(str_upper) :]  # skip sig
                    ch_str = ""
                    for i in range(2):  # shouldn't be more than 2 hex chars
                        # gv + "."+b[ c ]
                        if data.find(gvsig) == 0:
                            data = data[len(gvsig) :]
                            for k, entry in enumerate(b):  # for every entry in b
                                if data.find(entry) == 0:
                                    data = data[len(entry) :]
                                    ch_str = f"{k:x}"
                                    break
                        else:
                            break

                    outParts.append(chr(int(ch_str, 16)))
                    continue

                if data.find(str_lower) == 0:  # r3 check if "R // n < 128
                    data = data[len(str_lower) :]  # skip sig

                    ch_str = ""
                    ch_lotux = ""
                    temp = ""
                    b_checkR1 = 0
                    for j in range(3):  # shouldn't be more than 3 octal chars
                        if j > 1:  # lotu check
                            if data.find(str_l) == 0:
                                data = data[len(str_l) :]
                                ch_lotux = "l"
                                break
                            if data.find(str_o) == 0:
                                data = data[len(str_o) :]
                                ch_lotux = "o"
                                break
                            if data.find(str_t) == 0:
                                data = data[len(str_t) :]
                                ch_lotux = "t"
                                break
                            if data.find(str_u) == 0:
                                data = data[len(str_u) :]
                                ch_lotux = "u"
                                break

                        # gv + "."+b[ c ]
                        if data.find(gvsig) == 0:
                            temp = data[len(gvsig) :]
                            for k in range(8):  # for every entry in b octal
                                if temp.find(b[k]) == 0:
                                    if int(ch_str + str(k), 8) > 128:
                                        b_checkR1 = 1
                                        break

                                    ch_str += str(k)
                                    data = data[len(gvsig) :]  # skip gvsig
                                    data = data[len(b[k]) :]
                                    break

                            if b_checkR1 == 1:
                                if data.find(str_hex) == 0:  # 0123456789abcdef
                                    data = data[len(str_hex) :]
                                    # check every element of hex decode string for a match
                                    for i, entry in enumerate(b):
                                        if data.find(entry) == 0:
                                            data = data[len(entry) :]
                                            ch_lotux = f"{i:x}"
                                            break
                                    break
                        else:
                            break

                    outParts.append(chr(int(ch_str, 8)) + ch_lotux)
                    continue

                # "S ----> "SR or "S+
                # if there is, loop s until R 0r +
                # if there is no matching s block, throw error

                match = 0
                n = None

                # searching for matching pure s block
                while True:
                    n = ord(data[0])
                    if data.find(str_quote) == 0:
                        data = data[len(str_quote) :]
                        outParts.append('"')
                        match += 1
                        continue
                    if data.find(str_slash) == 0:
                        data = data[len(str_slash) :]
                        outParts.append("\\")
                        match += 1
                        continue
                    if data.find(str_end) == 0:  # reached end off S block ? +
                        if match == 0:
                            return (-1, "+ No match S block")
                        data = data[len(str_end) :]
                        break  # step out of the while loop
                    if (
                        data.find(str_upper) == 0
                    ):  # r4 reached end off S block ? - check if "R n >= 128z
                        if match == 0:
                            return (-1, "No match S block n>128")
                        data = data[len(str_upper) :]  # skip sig

                        ch_str = ""
                        ch_lotux = ""

                        for j in range(10):  # shouldn't be more than 10 hex chars
                            if j > 1:  # lotu check
                                if data.find(str_l) == 0:
                                    data = data[len(str_l) :]
                                    ch_lotux = "l"
                                    break
                                if data.find(str_o) == 0:
                                    data = data[len(str_o) :]
                                    ch_lotux = "o"
                                    break
                                if data.find(str_t) == 0:
                                    data = data[len(str_t) :]
                                    ch_lotux = "t"
                                    break
                                if data.find(str_u) == 0:
                                    data = data[len(str_u) :]
                                    ch_lotux = "u"
                                    break

                            # gv + "."+b[ c ]
                            if data.find(gvsig) == 0:
                                data = data[len(gvsig) :]  # skip gvsig
                                for k, entry in enumerate(b):  # for every entry in b
                                    if data.find(entry) == 0:
                                        data = data[len(entry) :]
                                        ch_str += f"{k:x}"
                                        break
                            else:
                                break  # done
                        outParts.append(chr(int(ch_str, 16)))
                        break  # step out of the while loop
                    if data.find(str_lower) == 0:  # r3 check if "R // n < 128
                        if match == 0:
                            return (-1, "No match S block n<128!!")

                        data = data[len(str_lower) :]  # skip sig

                        ch_str = ""
                        ch_lotux = ""
                        temp = ""
                        b_checkR1 = 0

                        for j in range(3):  # shouldn't be more than 3 octal chars
                            if j > 1:  # lotu check
                                if data.find(str_l) == 0:
                                    data = data[len(str_l) :]
                                    ch_lotux = "l"
                                    break
                                if data.find(str_o) == 0:
                                    data = data[len(str_o) :]
                                    ch_lotux = "o"
                                    break
                                if data.find(str_t) == 0:
                                    data = data[len(str_t) :]
                                    ch_lotux = "t"
                                    break
                                if data.find(str_u) == 0:
                                    data = data[len(str_u) :]
                                    ch_lotux = "u"
                                    break

                            # gv + "."+b[ c ]
                            if data.find(gvsig) == 0:
                                temp = data[len(gvsig) :]
                                for k in range(8):  # for every entry in b octal
                                    if temp.find(b[k]) == 0:
                                        if int(ch_str + str(k), 8) > 128:
                                            b_checkR1 = 1
                                            break

                                        ch_str += str(k)
                                        data = data[len(gvsig) :]  # skip gvsig
                                        data = data[len(b[k]) :]
                                        break

                                if b_checkR1 == 1:
                                    if data.find(str_hex) == 0:  # 0123456789abcdef
                                        data = data[len(str_hex) :]
                                        # check every element of hex decode string for a match
                                        for i, entry in enumerate(b):
                                            if data.find(entry) == 0:
                                                data = data[len(entry) :]
                                                ch_lotux = f"{i:x}"
                                                break
                            else:
                                break
                        outParts.append(chr(int(ch_str, 8)) + ch_lotux)
                        break  # step out of the while loop
                    if (
                        (0x21 <= n <= 0x2F)
                        or (0x3A <= n <= 0x40)
                        or (0x5B <= n <= 0x60)
                        or (0x7B <= n <= 0x7F)
                    ):
                        outParts.append(data[0])
                        data = data[1:]
                        match += 1
                continue
            return (-1, "No match in the code!!")
        return (0, "".join(outParts))


## END JJDECODE

## START LZW

CLEAR_CODE = 256
END_OF_INFO_CODE = 257

DEFAULT_MIN_BITS = 9
DEFAULT_MAX_BITS = 12


def compress(plaintext_bytes):
    """
    Given an iterable of bytes, returns a (hopefully shorter) iterable
    of bytes that you can store in a file or pass over the network or
    what-have-you.
    """
    encoder = ByteEncoder()
    return encoder.encodetobytes(plaintext_bytes)


class ByteEncoder:
    """
    Takes a stream of uncompressed bytes and produces a stream of
    compressed bytes. Combines an L{Encoder} with a L{BitPacker}.

    >>> import lzw
    >>>
    >>> enc = lzw.ByteEncoder(12)
    >>> bigstr = b"gabba gabba yo gabba gabba gabba yo gabba gabba gabba yo gabba gabba gabba yo"
    >>> encoding = enc.encodetobytes(bigstr)
    >>> encoded = b"".join( b for b in encoding )
    >>> encoded
    '3\\x98LF#\\x08\\x82\\x05\\x04\\x83\\x1eM\\xf0x\\x1c\\x16\\x1b\\t\\x88C\\xe1q(4"\\x1f\\x17\\x85C#1X\\xec.\\x00'

    """

    def __init__(self, max_width=DEFAULT_MAX_BITS):
        """
        max_width is the maximum width in bits we want to see in the
        output stream of codepoints.
        """
        self._encoder = Encoder(max_code_size=2**max_width)
        self._packer = BitPacker(
            initial_code_size=self._encoder.code_size(), max_width=max_width
        )

    def encodetobytes(self, bytesource):
        """
        Returns an iterator of bytes, adjusting our packed width
        between minwidth and maxwidth when it detects an overflow is
        about to occur.
        """
        codepoints = self._encoder.encode(bytesource)
        codebytes = self._packer.pack(codepoints)

        return codebytes


class BitPacker:
    """
    Translates a stream of lzw codepoints into a variable width packed
    stream of bytes. One of a (potential) set of encoders for a stream
    of LZW codepoints, intended to behave as closely to the TIFF
    variable-width encoding scheme as closely as possible.

    The inbound stream of integer lzw codepoints are packed into
    variable width bit fields, starting at the smallest number of bits
    it can and then increasing the bit width as it anticipates the LZW
    code size growing to overflow.

    This class knows all kinds of intimate things about how it's
    upstream codepoint processors work; it knows the control codes
    CLEAR_CODE and END_OF_INFO_CODE, and (more intimately still), it
    makes assumptions about the rate of growth of it's consumer's
    codebook. This is ok, as long as the underlying encoder/decoders
    don't know any intimate details about their BitPackers/Unpackers
    """

    def __init__(self, initial_code_size, max_width=DEFAULT_MAX_BITS):
        """
        Takes an initial code book size (that is, the count of known
        codes at the beginning of encoding, or after a clear), and the
        maximum code width in bits the downstream decoder is willing to
        read (matching the upstream Encoder's max_code_size).
        """
        self._initial_code_size = initial_code_size
        self._max_width = max_width

    def pack(self, codepoints):
        """
        Given an iterator of integer codepoints, returns an iterator
        over bytes containing the codepoints packed into varying
        lengths, with bit width growing to accommodate an input code
        that it assumes will grow by one entry per codepoint seen.

        Widths will be reset to the given initial_code_size when the
        LZW CLEAR_CODE or END_OF_INFO_CODE code appears in the input,
        and bytes following END_OF_INFO_CODE will be aligned to the
        next byte boundary.

        >>> import lzw
        >>> pkr = lzw.BitPacker(258)
        >>> [ b for b in pkr.pack([ 1, 257]) ] == [ chr(0), chr(0xC0), chr(0x40) ]
        True
        """
        tailbits = []
        codesize = self._initial_code_size

        minwidth = 8
        while (1 << minwidth) < codesize:
            minwidth = minwidth + 1

        nextwidth = minwidth

        for pt in codepoints:
            newbits = inttobits(pt, nextwidth)
            tailbits = tailbits + newbits
            codesize = codesize + 1
            if pt == END_OF_INFO_CODE:
                while len(tailbits) % 8:
                    tailbits.append(0)

            if pt in [CLEAR_CODE, END_OF_INFO_CODE]:
                nextwidth = minwidth
                codesize = self._initial_code_size
            elif nextwidth < self._max_width and codesize >= (2**nextwidth):
                nextwidth = nextwidth + 1

            while len(tailbits) > 8:
                nextbits = tailbits[:8]
                nextbytes = bitstobytes(nextbits)
                for bt in nextbytes:
                    yield struct.pack("B", bt)

                tailbits = tailbits[8:]

        if tailbits:
            tail = bitstobytes(tailbits)
            for bt in tail:
                yield struct.pack("B", bt)


class Encoder:
    """
    Given an iterator of bytes, returns an iterator of integer
    codepoints, suitable for use by L{Decoder}. The core of the
    "compression" side of lzw compression/decompression.
    """

    def __init__(self, max_code_size=(2**DEFAULT_MAX_BITS)):
        """
        When the encoding codebook grows larger than max_code_size,
        the Encoder will clear its codebook and emit a CLEAR_CODE
        """

        self.closed = False

        self._max_code_size = max_code_size
        self._buffer = b""
        self._clear_codes()

        if max_code_size < self.code_size():
            raise ValueError(
                f"Max code size too small, (must be at least {self.code_size()})"
            )

    def code_size(self):
        """
        Returns a count of the known codes, including codes that are
        implicit in the data but have not yet been produced by the
        iterator.
        """
        return len(self._prefixes)

    def flush(self):
        """
        Yields any buffered codepoints, followed by a CLEAR_CODE, and
        clears the codebook as a side effect.
        """
        if self._buffer:
            yield self._prefixes[self._buffer]
            self._buffer = b""

        yield CLEAR_CODE
        self._clear_codes()

    def encode(self, bytesource):
        """
        Given an iterator over bytes, yields the
        corresponding stream of codepoints.
        Will clear the codes at the end of the stream.

        >>> import lzw
        >>> enc = lzw.Encoder()
        >>> [ cp for cp in enc.encode(b"gabba gabba yo gabba") ]
        [103, 97, 98, 98, 97, 32, 258, 260, 262, 121, 111, 263, 259, 261, 256]

        Modified by Jose Miguel Esparza to add support for PDF files encoding
        Modified by Corey Forman to adjust for Python 3
        """
        if isinstance(bytesource, str):
            bytesource = bytesource.encode("latin-1")

        yield CLEAR_CODE
        for b in bytesource:
            byte = b if isinstance(b, bytes) else bytes([b])
            yield from self._encode_byte(byte)

            if self.code_size() >= self._max_code_size:
                yield from self.flush()

        if self._buffer:
            yield self._prefixes[self._buffer]
        yield END_OF_INFO_CODE

    def _encode_byte(self, byte):
        """
        Yields one or zero bytes, AND changes the internal state of
        the codebook and prefix buffer.
        Unless you're in self.encode(), you almost certainly don't
        want to call this.
        """

        new_prefix = self._buffer

        if new_prefix + byte in self._prefixes:
            new_prefix = new_prefix + byte
        elif new_prefix:
            encoded = self._prefixes[new_prefix]
            self._add_code(new_prefix + byte)
            new_prefix = byte

            yield encoded

        self._buffer = new_prefix

    def _clear_codes(self):
        # Teensy hack, CLEAR_CODE and END_OF_INFO_CODE aren't
        # equal to any possible string.

        self._prefixes = dict(
            (struct.pack("B", codept), codept) for codept in range(256)
        )
        self._prefixes[CLEAR_CODE] = CLEAR_CODE
        self._prefixes[END_OF_INFO_CODE] = END_OF_INFO_CODE

    def _add_code(self, newstring):
        self._prefixes[newstring] = len(self._prefixes)


def inttobits(anint, width=None):
    """
    Produces an array of booleans representing the given argument as
    an unsigned integer, MSB first. If width is given, will pad the
    MSBs to the given width (but will NOT truncate overflowing
    results)

    >>> import lzw
    >>> lzw.inttobits(304, width=16)
    [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0]

    """
    remains = anint
    retreverse = []
    while remains:
        retreverse.append(remains & 1)
        remains = remains >> 1

    retreverse.reverse()

    ret = retreverse
    if width is not None:
        ret_head = [0] * (width - len(ret))
        ret = ret_head + ret

    return ret


def bitstobytes(bits):
    """
    Interprets an indexable list of booleans as bits, MSB first, to be
    packed into a list of integers from 0 to 256, MSB first, with LSBs
    zero-padded. Note this padding behavior means that round-trips of
    bytestobits(bitstobytes(x, width=W)) may not yield what you expect
    them to if W % 8 != 0

    Does *NOT* pack the returned values into a bytearray or the like.

    >>> import lzw
    >>> bitstobytes([0, 0, 0, 0, 0, 0, 0, 0, "Yes, I'm True"]) == [ 0x00, 0x80 ]
    True
    >>> bitstobytes([0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0]) == [ 0x01, 0x30 ]
    True
    """
    ret = []
    nextbyte = 0
    nextbit = 7
    for bit in bits:
        if bit:
            nextbyte = nextbyte | (1 << nextbit)

        if nextbit:
            nextbit = nextbit - 1
        else:
            ret.append(nextbyte)
            nextbit = 7
            nextbyte = 0

    if nextbit < 7:
        ret.append(nextbyte)
    return ret


##  LZWDecoder


class LZWDecoder:
    """
    The code below is part of pdfminer (http://pypi.python.org/pypi/pdfminer/)

    Copyright (c) 2004-2010 Yusuke Shinyama <yusuke at cs dot nyu dot edu>

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software
    and associated documentation files (the "Software"), to deal in the Software without
    restriction, including without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
    BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    """

    debug = 0

    def __init__(self, fp):
        self.fp = fp
        self.buff = 0
        self.bpos = 8
        self.nbits = 9
        self.table = None
        self.prevbuf = None

    def readbits(self, bits):
        v = 0
        while 1:
            # the number of remaining bits we can get from the current buffer.
            r = 8 - self.bpos
            if bits <= r:
                # |-----8-bits-----|
                # |-bpos-|-bits-|  |
                # |      |----r----|
                v = (v << bits) | ((self.buff >> (r - bits)) & ((1 << bits) - 1))
                self.bpos += bits
                break
            # |-----8-bits-----|
            # |-bpos-|---bits----...
            # |      |----r----|
            v = (v << r) | (self.buff & ((1 << r) - 1))
            bits -= r
            x = self.fp.read(1)
            if not x:
                raise EOFError
            self.buff = ord(x)
            self.bpos = 0
        return v

    def feed(self, code):
        x = ""
        if code == 256:
            self.table = [chr(c) for c in range(256)]  # 0-255
            self.table.append(None)  # 256
            self.table.append(None)  # 257
            self.prevbuf = ""
            self.nbits = 9
        elif code == 257:
            pass
        elif not self.prevbuf:
            x = self.prevbuf = self.table[code]
        else:
            if code < len(self.table):
                x = self.table[code]
                self.table.append(self.prevbuf + x[0])
            else:
                self.table.append(self.prevbuf + self.prevbuf[0])
                x = self.table[code]
            l = len(self.table)
            if l == 511:
                self.nbits = 10
            elif l == 1023:
                self.nbits = 11
            elif l == 2047:
                self.nbits = 12
            self.prevbuf = x
        return x

    def run(self):
        while 1:
            try:
                code = self.readbits(self.nbits)
            except EOFError:
                break
            x = self.feed(code)
            yield x


def lzwdecode(data):
    """
    >>> lzwdecode('\x80\x0b\x60\x50\x22\x0c\x0c\x85\x01')
    '\x2d\x2d\x2d\x2d\x2d\x41\x2d\x2d\x2d\x42'
    """
    fp = StringIO(data)
    return "".join(LZWDecoder(fp).run())


## END LZW
