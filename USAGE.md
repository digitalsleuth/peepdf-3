## Usage

```
usage: peepdf [options] pdf

Version: peepdf 3.0.0

positional arguments:
  pdf                   PDF File

optional arguments:
  -C COMMANDS, --command COMMANDS
                        Specifies a command from the interactive console to be executed.
  -c, --check-vt        Checks the hash of the PDF file on VirusTotal.
  -f, --force-mode      Sets force parsing mode to ignore errors.
  -g, --grinch-mode     Avoids colorized output.
  -h, --help            show this help message and exit
  -i, --interactive     Sets console mode.
  -j, --json            Shows the document information in JSON format.
  -k VTAPIKEY, --key VTAPIKEY
                        VirusTotal API Key, used with -c/--check-vt
  -l, --loose-mode      Sets loose parsing mode to catch malformed objects.
  -m, --manual-analysis
                        Avoids automatic Javascript analysis. Useful with eternal loops like heap spraying.
  -o, --ocr             Extract text from the PDF
  -s SCRIPTFILE, --load-script SCRIPTFILE
                        Loads the commands stored in the specified file and execute them.
  -u, --update          Fetches updates for the Vulnerability List
  -v, --version         Shows program's version number.
  -x, --xml             Shows the document information in XML format.


```
### Ways to use peepdf:
- Basic execution
- Interactive console
- Script mode
- JSON Output
- XML Output
- VirusTotal analysis
- OCR
  
All of them accept parameters to ignore errors and continue with the analysis and deal with malformed objects:

```
    -f: ignores errors and continues with the analysis of the document. It's useful to analyze malicious documents, or when documents contain errors in one or more spots which would prevent normal analysis.

    -l: does not search for the endobj tag during the parsing process, so it can be useful when the analysed document is malformed.
    Also, there are three more parameters:

    -g: avoids colorized output.
    -c: checks the hash of the PDF file on VirusTotal - can be used with -k/ --key to provide the API key at the console instead of setting it manually or in the interactive console.
    -m: avoids performing any automatic Javascript analysis. This can be helpful when the analysis does not end due to a endless loop in the Javascript code.
```
Before executing peepdf it is recommended to check for an update of the PDF Vulnerability List, just in case there are new vulnerabilities reported. See the next section to know how to do it.

### Updating peepdf Vulnerability List

In order to update the PDF Vulnerability List you can just use the -u parameter:
```
$ peepdf -u

[-] Checking if there are new updates to the Vulnerabilities List
[-] Current Version: 1.0.0
[-] Remote Version: 1.0.1
[+] Update available
[-] Fetching the  update ...
[*] File PDFVulns.py exists, overwriting ...
[+] peepdf Vulnerabilities List updated successfully to 1.0.1

If peepdf was installed using sudo privileges, or you do not have permissions to write to the location of PDFVulns.py, then this command may need to be run with sudo privileges.
 ```
### Basic execution

If we only want to know the basic information about objects, streams, vulnerabilities etc, you can simply run the following against your PDF:

```
$ peepdf samplesecured_256bitaes_pdf.pdf

File: samplesecured_256bitaes_pdf.pdf
Title: Microsoft Word - Placeholder Documentation.docx
MD5: abd43766905e12704da9411682681f7e
SHA1: 8c6dcc4bafb23eac83db37e187ec5155b6ac7e8f
SHA256: 15f9cd381e3d87f09c9d3d1a53e23b8d4a57559351de7c7db3d7b8bed7acbe72
Size: 21634 bytes
IDs: 
	Version 0: [ <CC56D8A7F574DE7ED75787D94BF65288> <CC56D8A7F574DE7ED75787D94BF65288> ]

PDF Format Version: 1.7
Binary: True
Linearized: False
Encrypted: True (AES 256 bits)
Updates: 0
Objects: 10
Streams: 7
URIs: 0
Comments: 0
Errors: 0

Version 0:
	Catalog: 21
	Info: 2
	Objects (22): [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 22, 23, 24]
	Compressed objects (12): [3, 4, 13, 8, 9, 17, 10, 11, 19, 12, 7, 6]
	Streams (7): [24, 5, 14, 15, 16, 18, 22]
	Xref streams (1): [24]
	Object streams (1): [22]
	Encoded (7): [24, 5, 14, 15, 16, 18, 22]
```
### Interactive console

To access the interactive console, the best way is to provide the PDF as an argument to the `-i` command at the console:

```
$ peepdf -i sample.pdf

File: samplesecured_256bitaes_pdf.pdf
Title: Microsoft Word - Placeholder Documentation.docx
MD5: abd43766905e12704da9411682681f7e
SHA1: 8c6dcc4bafb23eac83db37e187ec5155b6ac7e8f
SHA256: 15f9cd381e3d87f09c9d3d1a53e23b8d4a57559351de7c7db3d7b8bed7acbe72
Size: 21634 bytes
IDs: 
	Version 0: [ <CC56D8A7F574DE7ED75787D94BF65288> <CC56D8A7F574DE7ED75787D94BF65288> ]

PDF Format Version: 1.7
Binary: True
Linearized: False
Encrypted: True (AES 256 bits)
Updates: 0
Objects: 10
Streams: 7
URIs: 0
Comments: 0
Errors: 0

Version 0:
	Catalog: 21
	Info: 2
	Objects (22): [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 22, 23, 24]
	Compressed objects (12): [3, 4, 13, 8, 9, 17, 10, 11, 19, 12, 7, 6]
	Streams (7): [24, 5, 14, 15, 16, 18, 22]
	Xref streams (1): [24]
	Object streams (1): [22]
	Encoded (7): [24, 5, 14, 15, 16, 18, 22]

PPDF>

```
When we see the **PPDF>** prompt we can launch the different commands:
```
PPDF> help

Documented commands (type help <topic>):
========================================
bytes           exit         js_join           open          set       
changelog       extract      js_unescape       quit          show      
clear           filters      js_vars           rawobject     stream    
create          hash         log               rawstream     streams   
decode          help         malformed_output  references    tree      
decrypt         info         metadata          replace       vtcheck   
embed           js_analyse   modify            reset         xor       
encode          js_beautify  object            save          xor_search
encode_strings  js_code      objects           save_version
encrypt         js_eval      ocr               sctest      
errors          js_jjdecode  offsets           search   
```
It is possible to launch the interactive console without specifying any PDF file: 
```
$ peepdf -i

PPDF> 
```
However, now we cannot use all of the commands until a PDF file has been opened, but we can execute Javascript and shellcodes, encode/decode contents, etc. The available commands will be the following:
```
clear
create
decode
encode
exit
help
js_analyse
js_beautify
js_eval
js_jjdecode
js_join
js_unescape
js_vars
log
malformed_output
open
quit
replace
reset
sctest
set
show
vtcheck
xor
xor_search
```
### Script mode

Instead of executing peepdf with an interactive console, it is also possible to execute it in script mode in order to perform automatic analysis. So after creating a file with the commands we want to execute:
```
$ cat command_file.txt
tree
offsets
```
We can execute peepdf this way:
```
$ peepdf -s command_file.txt sample.pdf

/Catalog (21) 
	/Pages (3) 
		/Page (4) 
			stream (5) 
				Unknown (0) 
			/Pages (3) 
			/R7 (12) 
				/ExtGState (7) 
			dictionary (13) 
				/Font (10) 
					/Encoding (19) 
					/FontDescriptor (11) 
						stream (15) 
					stream (18) 
				/Font (8) 
					/Encoding (17) 
					/FontDescriptor (9) 
						stream (14) 
					stream (16) 
integer (6) 
stream (22) 
	/R7 (12) 
	/Page (4) 
	/FontDescriptor (9) 
	stream (5) 
	/ExtGState (7) 
	stream (14) 
	/Font (10) 
	/Pages (3) 
	/FontDescriptor (11) 
	/Font (8) 
	dictionary (13) 
	stream (16) 
	/Encoding (19) 
	stream (15) 
	/Encoding (17) 
	stream (18) 
/Info (2) 
dictionary (23) 
stream (24) 
	/Info (2) 
	/Catalog (21) 
	dictionary (23) 

Start (d)	End (d)		Size (d)	Type and Id

---------	---------	---------	--------------------

00000000					Header
00000015	00000069	00000055	Object 21 
00000061	00000397	00000337	Object 16 
00000403	00009140	00008738	Object 14 
00009144	00009496	00000353	Object 18 
00009502	00019119	00009618	Object 15 
00019123	00019794	00000672	Object 5 
00019800	00020585	00000786	Object 22 
00019820	00019895	00000076	Compressed Object 3 
00019864	00020046	00000183	Compressed Object 4 
00019999	00020047	00000049	Compressed Object 13 
00020023	00020271	00000249	Compressed Object 8 
00020228	00020447	00000220	Compressed Object 9 
00020401	00020638	00000238	Compressed Object 17 
00020584	00020891	00000308	Object 2 
00020591	00020853	00000263	Compressed Object 10 
00020809	00021033	00000225	Compressed Object 11 
00020944	00021288	00000345	Object 23 
00020986	00021191	00000206	Compressed Object 19 
00021141	00021176	00000036	Compressed Object 12 
00021154	00021203	00000050	Compressed Object 7 
00021179	00021200	00000022	Compressed Object 6 
00021309	00021607	00000299	Object 24 
00021609	00021626	00000018	Trailer 
00021627					EOF

```
### JSON Output

You can obtain the basic information as provided with the `$ peepdf sample.pdf` command and obtain it in a JSON output:
```
$ peepdf -j sampleunsecuredpdf.pdf

{
    "peepdf_analysis": {
        "advanced": [
            {
                "version_info": {
                    "catalog": "1",
                    "compressed_objects": [],
                    "decoding_error_streams": [],
                    "encoded_streams": [
                        16,
                        18,
                        14,
                        15,
                        5
                    ],
                    "error_objects": [],
                    "info": "2",
                    "js_objects": [],
                    "objects": [
                        1,
                        2,
                        3,
                        4,
                        5,
                        6,
                        7,
                        8,
                        9,
                        10,
                        11,
                        12,
                        13,
                        14,
                        15,
                        16,
                        17,
                        18,
                        19
                    ],
                    "streams": [
                        16,
                        18,
                        14,
                        15,
                        5
                    ],
                    "suspicious_elements": {
                        "actions": null,
                        "elements": [],
                        "js_vulns": [],
                        "triggers": null,
                        "urls": null
                    },
                    "version_number": 0,
                    "version_type": "original",
                    "xref_streams": []
                }
            }
        ],
        "basic": {
            "binary": true,
            "comments": 0,
            "detection": {},
            "encrypted": true,
            "encryption_algorithms": [],
            "errors": [],
            "filename": "sampleunsecuredpdf.pdf",
            "ids": {
                "version_0": "[ <CC56D8A7F574DE7ED75787D94BF65288> <CC56D8A7F574DE7ED75787D94BF65288> ]"
            },
            "linearized": true,
            "md5": "514e921f41157625a3036db0e97b0eba",
            "num_objects": 19,
            "num_streams": 5,
            "pdf_version": "1.3",
            "sha1": "546bb73b0e26d444a06b30a3e36b22d38184f0e9",
            "sha256": "5d47ab196e3b05dcf87d4b37aeda45ae362107026844dda9b2a64a6132c76c59",
            "size": 22057,
            "updates": 0
        },
        "date": "2023-12-30 20:07:58",
        "peepdf_info": {
            "author": "Jose Miguel Esparza and Corey Forman",
            "url": "https://github.com/digitalsleuth/peepdf-3",
            "version": "3.0.0"
        }
    }

```

### XML Output

Additionally, it's possible to obtain the same information provided in the basic execution in XML format thanks to the -x option (combined with -fl if needed). The associated DTD can be found at the root of the repo.
```
$ peepdf -x 517fe6ba9417e6c8b4d0a0b3b9c4c9a9
<peepdf_analysis version="3.0.0" url="https://github.com/digitalsleuth/peepdf-3" author="Jose Miguel Esparza and Corey Forman">
  <date>2023-12-30 20:04:44</date>
  <basic>
    <filename>517fe6ba9417e6c8b4d0a0b3b9c4c9a9</filename>
    <md5>2f7cec0f91a5fd23d706dc53a82b2db7</md5>
    <sha1>162e98d89f2ae3b4b469b066ebfe02af22e9b869</sha1>
    <sha256>576a373ccb9b62c3c934abfe1573a87759a2bfe266477155e0e59f336cc28ab4</sha256>
    <size>2333</size>
    <id0>Version 0: [ &lt;de4e269db5990d50542c77c1afd6874e&gt; &lt;de4e269db5990d50542c77c1afd6874e&gt; ]</id0>
    <detection/>
    <pdf_version>1.4</pdf_version>
    <binary status="true"/>
    <linearized status="false"/>
    <encrypted status="false"/>
    <updates>0</updates>
    <num_objects>13</num_objects>
    <num_streams>3</num_streams>
    <comments>0</comments>
    <errors num="0"/>
  </basic>
  <advanced>
    <version num="0" type="original">
      <catalog object_id="12"/>
      <info object_id="13"/>
      <objects num="13">
        <object id="1" errors="false"/>
        <object id="2" errors="false"/>
        <object id="3" errors="false"/>
        <object id="4" errors="false"/>
        <object id="5" errors="false"/>
        <object id="6" errors="false"/>
        <object id="7" errors="false"/>
        <object id="8" errors="false"/>
        <object id="9" errors="false"/>
        <object id="10" errors="false"/>
        <object id="11" errors="false"/>
        <object id="12" errors="true"/>
        <object id="13" errors="false"/>
      </objects>
      <streams num="3">
        <stream id="1" encoded="true"/>
        <stream id="3" encoded="true"/>
        <stream id="6" encoded="true"/>
      </streams>
      <js_objects>
        <container_object id="3"/>
        <container_object id="12"/>
      </js_objects>
      <suspicious_elements>
        <triggers>
          <trigger name="/Names">
            <container_object id="9"/>
            <container_object id="10"/>
            <container_object id="12"/>
          </trigger>
          <trigger name="/OpenAction">
            <container_object id="12"/>
          </trigger>
        </triggers>
        <actions>
          <action name="/JS">
            <container_object id="4"/>
            <container_object id="12"/>
          </action>
          <action name="/JavaScript">
            <container_object id="4"/>
            <container_object id="11"/>
            <container_object id="12"/>
          </action>
        </actions>
        <elements>
          <element name="/EmbeddedFile">
            <container_object id="1"/>
          </element>
          <element name="/EmbeddedFiles">
            <container_object id="11"/>
          </element>
        </elements>
        <js_vulns>
          <vulnerable_function name=".SettingContent">
            <cve>CVE-2018-8414</cve>
            <container_object id="3"/>
          </vulnerable_function>
        </js_vulns>
      </suspicious_elements>
      <suspicious_urls/>
    </version>
  </advanced>
</peepdf_analysis>
```
### VirusTotal Analysis

You can check VirusTotal for any hits on this file with the -c and -k commands, unless you have your API manually added to the `main.py` file under the `VT_KEY` variable.
```
peepdf -c -k <api_key> <filename>

File: 517fe6ba9417e6c8b4d0a0b3b9c4c9a9
MD5: 2f7cec0f91a5fd23d706dc53a82b2db7
SHA1: 162e98d89f2ae3b4b469b066ebfe02af22e9b869
SHA256: 576a373ccb9b62c3c934abfe1573a87759a2bfe266477155e0e59f336cc28ab4
Size: 2333 bytes
IDs:
        Version 0: [ <de4e269db5990d50542c77c1afd6874e> <de4e269db5990d50542c77c1afd6874e> ]

Detection: 40/60
Detection report: https://www.virustotal.com/gui/file/576a373ccb9b62c3c934abfe1573a87759a2bfe266477155e0e59f336cc28ab4
PDF Format Version: 1.4
Binary: True
Linearized: False
Encrypted: False
Updates: 0
Objects: 13
Streams: 3
URIs: 0
Comments: 0
Errors: 0

Version 0:
        Catalog: 12
        Info: 13
        Objects (13): [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        Streams (3): [1, 3, 6]
        Encoded (3): [1, 3, 6]
        Objects with JS code (2): [3, 12]
        Suspicious elements (12):
                /Names (3): [9, 10, 12]
                /OpenAction (1): [12]
                /JS (2): [4, 12]
                /JavaScript (3): [4, 11, 12]
                .SettingContent (CVE-2018-8414) (1): [3]
                /EmbeddedFile (1): [1]
                /EmbeddedFiles (1): [11]

```
### OCR

This option simply extracts any legible text from the PDF document, in the event that it can't be opened and contains pertinent data:
```
$ peepdf -o phishing_email.pdf

I have shared an attachment with you using via Pdf.

 Sign in ​  here with your email to view complete document .

 Thanks

```
