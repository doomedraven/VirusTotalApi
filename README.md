VirusTotal public and private APIv2 Full support
===================

This script was made public into the official VT API documentation page.
https://www.virustotal.com/en/documentation/public-api/

Before using the tool you must set your api key in __~.vtapi__ or in __~vtapi.conf__.

* ~.vtapi file content:
```python
[vt]
apikey=your-apikey-here
type=public
intelligence=False
engines= #put there coma separated engine list, or only one, or leave it empty
```
* your type of api access, if private: type=private, if public, you can leave it empty, it will be automatically reconized as public
* if you have access to VT Intelligence, you need set intelligence=True

**Dependencies:**
 *  requests
 *  texttable
 *  python-dateutil

These can be installed via PIP or a package manager.
Example of installing all dependencies using pip:
```python
pip install -r requirements.txt
```

* Thanks to @kellewic and @urbanski
* Special thanks to @Seifreed for testing and reporting bugs

### Example of usage as library can be found [here](https://github.com/doomedraven/VirusTotalApi/wiki)


Few public API functions getted from Chris Clark script<br />
And finally has been added full public and private API support by Andriy Brukhovetskyy (doomedraven)<br />

License: Do whatever you want with it :)<br />


Small manual with examples
http://www.doomedraven.com/2013/11/script-virustotal-public-and-private.html

Some examples:<br />

<pre><code>python vt.py -d google.com

Status:          Domain found in dataset

[+] Passive DNS replication
	2013-10-19 	74.125.142.100
	2013-10-19 	74.125.142.102
	2013-10-19 	74.125.142.139
	2013-10-19 	74.125.193.100
	2013-10-19 	74.125.193.101
	....


python vt.py -u -ur cuatvientos.org
Searching for url(s) report:
	cuatvientos.org

	Scanned on:           2013-10-23 18:11:02
	Detected by:          0 / 47

	Status      : Scan finished, scan information embedded in this object
	Scanned url : http://cuatvientos.org/

	Permanent Link:      https://www.virustotal.com/url/9be15bbec0dacb3ec93c462998e0ea8017efd80353a38882a94e0d5dc906e3dc/analysis/1382551862/


python vt.py -s 0a1ab00a6f0f7f886fa4ff48fc70a953

	Scanned on:           2013-10-20 14:13:11
	Detected by:          15 / 48

	Sophos Detection:     Troj/PDFEx-GD
	Kaspersky Detection:  HEUR:Exploit.Script.Generic
	TrendMicro Detection: HEUR_PDFJS.STREM

	Results for MD5:     0a1ab00a6f0f7f886fa4ff48fc70a953
	Results for SHA1:    0e734df1fbde65db130e4cf23577bdf8fde73ca8
	Results for SHA256:  be9c0025b99f0f8c55f448ba619ba303fc65eba862cac65a00ea83d480e5efec

	Permanent Link:      https://www.virustotal.com/file/be9c0025b99f0f8c55f448ba619ba303fc65eba862cac65a00ea83d480e5efec/analysis/1382278391/
