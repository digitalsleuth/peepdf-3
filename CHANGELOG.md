## peepdf 3.0.3, 2024-01-10


	* Fixes:

		- Layout of table from vtcheck now better formatted

	* Changes:

		- New requirement (prettytable) added to pyproject.toml
		- Reorganized the code surrounding the vtcheck and do_vtcheck functions



## peepdf 3.0.2, 2024-01-04


	* Fixes:

		- Fixes incorrect version number



## peepdf 3.0.1, 2024-01-04


	* Fixes:

		- Fixed an issue where the json output wasn't formulated properly based on the differences in CRLF and blanks in the "IDs" field



## peepdf 3.0.0, 2024-01-04


	* Fixes:

		- AES decryption inaccurately determines the default password is incorrect
		- When supplying a file name, previous versions wouldn't check to see if the file existed before attempting actions
		- Parsing of rawobjects only returned identical information instead of actual raw data
		- Fixed an error whereby the ID did not parse correctly when using the `info trailer` command (when the ID is present)
		- Fixed the URL for the VT report, was previously directing to the API call, not the actual standard web location

	* Changes:

		- **NOTE** Removed pylibemu as a requirement to allow an installation on Windows systems. All libemu/pylibemu/sctest functions will still work on linux, provided libemu and pylibemu are installed.
		- Moved the lzw, jjdecode, and ccitt modules to their own encode/decode module, PDFEnDec.py
		- Moved the aes module into PDFCrypto.py
		- Renamed main.py to peepdf.py (to fit better naming structure and usage)
		- Added clarity to the interactive console commands and their outputs (modified help menus, explained outputs)
		- Added feedback to the redirect functions of the interactive console to confirm success / failure of action
		- Modified the error handling and argument parsing on initial launch to better handle multiple arguments

	* New Features:

		- Added a `json` and `xml` option in the interactive console to print the xml and json output of the currently loaded file
		- Added `objects` and `streams` options to the interactive console to show all objects and streams without having to resend the `info` command
		- Added a `clear` command to the interactive console to clear the screen
		- Not previously documented, but an `ocr` command has been added to the command line and interactive shells to extract text from the PDF
		- Added the document "ID" to the XML and JSON outputs
  
  
## peepdf 2.3.0, 2024-01-02


    * Fixes:

        - Fixed an issue whereby a race condition was caused which failed to "decrypt" hexadecimal JS objects when ID values were set to True too soon.


## peepdf 2.2.0, 2023-12-28


	* Fixes:

		- Fixed an error introduced when streamTrailer is None


## peepdf 2.1.0, 2023-12-28


	* Fixes:

		- AES decryption had several type errors (as indicated in Issue #5). These have been fixed.
		- The string for the ID was getting unintentionally decoded from string to hex, leaving an illegible ID string
		- Added error handling for the missing ID from the Trailer

	* Changes:

		- Updated PDFVulns.py to contain the Elements and Actions to be watched
		- The "title" of the document sometimes would contain unusable characters if decryption failed. Now will check for ascii content before outputting title.


## peepdf 2.0.0, 2023-12-11


	* Fixes:

		- Fixed JavaScript detection, whereby if the line contained even one invalid character, the remainder of the line would be ignored.
		- Fixed the incorrect implementation of iterating over .keys(), which subsequently fixed the "filters" option.
		- Filters not parsing correctly, and not providing a nicer output (hex column expanded to fill instead of stop at last character).
		- Changed the initial and do_info output to show full count of Suspicious Elements.
		- Hash values not being calculated properly for the "info" on objects when instantiated as strings.

	* Changes:

		- Updated the VirusTotal API to use API 3.
		- Moved the JS and other vulnerabilities to a separate single file, PDFVulns.py.
		- Changed optparse to argparse for better flexibility and support

	* New Features:

		- If present, the PDF title will be displayed in the output.
		- Added (re-introduced) an "update" feature to update the PDFVulns.py file separately, allowing for updating of list of vulnerabilities without having to re-install peepdf.
		- Added an ocr feature which will extract text from the PDF itself. Allows for additional context during analysis.
		- Added the -k argument at the shell to allow the passing of the VT API Key instead of requiring the python code be modified manually


## peepdf 1.0.9, 2023-09-18


	* Fixes:
		- Attempt to fix continual failures in parsing indirect objects


## peepdf 1.0.8, 2023-09-18


	* Fixes:
		- Fixed an issue with the PDFParser where the function was called incorrectly


## peepdf 1.0.7, 2023-09-18


	* Fixes:
		- Removed suggestion to contact original author with issues, instead direct user to open issues at github.com/digitalsleuth/peepdf-3/issues
		- Add updated author information


## peepdf 1.0.2, 2023-09-06


	* New features:
		- Updated for Python 3
	
	* Fixes:
		- Code cleanup
		- Fixed issues with interactive console not loading
		- Fixed bug where bytes offset was not logging output


## peepdf 0.3 r235, 2014-06-09


    * New features:

		- Added descriptive titles for the vulns found
		- Added detection of CVE-2013-2729 (Adobe Reader BMP/RLE heap corruption)
		- Added support for more than one script block in objects containing Javascript (e.g. XFA objects)
		- Updated colorama to version 3.1 (2014-04-19)
		- Added detection of CVE-2013-3346 (ToolButton Use-After-Free)
		- Added command "js_vars" to show the variables defined in the Javascript context and their content
		- Added command "js_jjdecode" to decode Javascript code using the jjencode algorithm (Thanks to Nahuel Riva @crackinglandia)
		- Added static detection for CVE-2010-0188
		- Added detection for CoolType.dll SING uniqueName vulnerability (CVE-2010-2883). Better late than never ;p
		- Added new command "vtcheck" to check for detection on VirusTotal (API key included)
		- Added option to avoid automatic Javascript analysis (useful with endless loops)
		- Added PyV8 as Javascript engine and removed Spidermonkey (Windows issues).

    * Fixes:

		- Fixed bug when encrypting/decrypting hexadecimal objects (Thanks to Timo Hirvonen for the feedback)
		- Fixed silly bug related to abbreviated PDF Filters
		- Fixed bug related to the GNU readline function not handling correctly colorized prompts
		- Fixed log_output function, it was storing the previous command output instead of the current one
		- Fixed bug in PDFStream to show the stream content when the stream dictionary is empty (Thanks to Nahuel Riva)
		- Fixed Issue 12, related to bad JS code parsing due to HTML entities in the XFA form (Thanks to robomotic)
		- Fixed Issue 10 related to bad error handling in the PDFFile.decrypt() method
		- Fixed Issue 9, related to an uncaught exception when PyV8 is not installed
		- Fixed bug in do_metadata() when objects contain /Metadata but they are not really Metadata objects

	* Others
	
		- Removed the old redirection method using the "set" command, it is useless now with the shell-like redirection (>, >>, $>, $>>)

	* Known issues
	
		- It exists a problem related to the readline module in Mac OS X (it uses editline instead of GNU readline), not handling correctly colorized prompts.


## peepdf Black Hat Vegas (0.2 r156), 2012-07-25


    * New features:

        - Added "grinch mode" execution to avoid colorized output
        - Added more colors in the interactive console output: warning, errors, important information...
        - Changed sctest command, now it's implemented with pylibemu
        - Added decrypt command to parse password protected documents
        - Modified analyseJS() to extract JS code from XDP packets and unescape HTML entities
        - Added function unescapeHTMLEntities() to unescape HTML entities
        - Added AES decryption support (128 and 256 bits).
        - Added hashes in objects information (info $object_id)
        - Added support for decoding CCITTFaxDecode filters (Thanks to @binjo)

    * Fixes:

        - Fix to show decrypt errors
        - Fixed silly bug with /EncryptMetadata element
        - Added missing binary file operations
        - Fixed Issue 5: Resolved false positives when monitoring some elements like actions, events, etc. (Thanks to @hiddenillusion)
        - Bug in PDFStream.decode and PDFStream.encode, dealing with an array of filter parameters (Thanks to @binjo)



## peepdf Black Hat Arsenal (0.1 r92), 2012-03-16


    * New features:

        - Added support for more parameters in Flate/LZW decode (stream filters)
        - Encryption algorithm now showing in document information
        - Added XML output and SHA hash to file information    
        - Improved unescape function to support mixed escaped formats (eg. "%u6734%34%u8790")
        - Added xor and xor_search commands
        - Added easy way of redirect console output (>, >>, $>, $>>)
        - Added xor function by Evan Fosmark
        - Added detection of CVE-2011-4369 (/PRC)
        - Added hash command (Thanks to @binjo for code and comments)
        - Added js_beautify command
        - Update function added
        - Added new vulns and showing information related to non JS vulns
        - Added escape sequence in the limited output
        - Added ascii85 decode from pdfminer to improve code and avoid bugs (Thanks to Brandon Dixon!)
        - Added lzwdecode from pdfminer to improve code and avoid bugs

    * Fixes:

        - Update process rewritten, now based on hashing of files
        - Silly bug in computeUserPass function (Thanks to Christian Martorella!)
        - Added binary mode in files operations
        - Recursion bug in update function
        - Minor bug in do_embed function
        - Bug to support encoding following PDF specifications (Issue 3 by czchen)
        - Bug to handle negative numbers in P element
        - Bug in the xref table when creating a new PDF (Issue 2)
        - Silly bug when parsing filter parameters
        - Bug related to updating objects and statistics of PDF files
        - Some bugs related to offsets calculation
        - Fixed "replace" function in PDFObjectStream
        - Fix in asciiHexDecode filter function



## peepdf 0.1 r15, 2011-05-05


- Initial Release

