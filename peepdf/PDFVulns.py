#! /usr/bin/env python3
# This file is a part of peepdf-3
#
#        peepdf-3 is free software: you can redistribute it and/or modify
#        it under the terms of the GNU General Public License as published by
#        the Free Software Foundation, either version 3 of the License, or
#        (at your option) any later version.
#
#        peepdf is distributed in the hope that it will be useful,
#        but WITHOUT ANY WARRANTY; without even the implied warranty of
#        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#        GNU General Public License for more details.
#
#        You should have received a copy of the GNU General Public License
#        along with peepdf-3. If not, see <http://www.gnu.org/licenses/>.
#

"""
    This module contains the vulnerabilities to analyse for peepdf-3
"""

vulnsVersion = "1.0.0"
jsVulns = [
    "mailto",
    "Collab.collectEmailInfo",
    "util.printf",
    "getAnnots",
    "getIcon",
    "spell.customDictionaryOpen",
    "media.newPlayer",
    "doc.printSeps",
    "app.removeToolButton",
    ".SettingContent",
]
singUniqueName = "CoolType.SING.uniqueName"
bmpVuln = "BMP/RLE heap corruption"
vulnsDict = {
    "mailto": ("mailto", ["CVE-2007-5020"]),
    "Collab.collectEmailInfo": ("Collab.collectEmailInfo", ["CVE-2007-5659"]),
    "util.printf": ("util.printf", ["CVE-2008-2992"]),
    "/JBIG2Decode": ("Adobe JBIG2Decode Heap Corruption", ["CVE-2009-0658"]),
    "getIcon": ("getIcon", ["CVE-2009-0927"]),
    "getAnnots": ("getAnnots", ["CVE-2009-1492"]),
    "spell.customDictionaryOpen": ("spell.customDictionaryOpen", ["CVE-2009-1493"]),
    "media.newPlayer": ("media.newPlayer", ["CVE-2009-4324"]),
    ".rawValue": ("Adobe Acrobat Bundled LibTIFF Integer Overflow", ["CVE-2010-0188"]),
    singUniqueName: (singUniqueName, ["CVE-2010-2883"]),
    "doc.printSeps": ("doc.printSeps", ["CVE-2010-4091"]),
    "/U3D": ("/U3D", ["CVE-2009-3953", "CVE-2009-3959", "CVE-2011-2462"]),
    "/PRC": ("/PRC", ["CVE-2011-4369"]),
    "keep.previous": (
        "Adobe Reader XFA oneOfChild Un-initialized memory vulnerability",
        ["CVE-2013-0640"],
    ),  # https://labs.portcullis.co.uk/blog/cve-2013-0640-adobe-reader-xfa-oneofchild-un-initialized-memory-vulnerability-part-1/
    bmpVuln: (bmpVuln, ["CVE-2013-2729"]),
   "app.removeToolButton": ("app.removeToolButton", ["CVE-2013-3346"]),
   ".SettingContent": (".SettingContent", ["CVE-2018-8414"]),
}

