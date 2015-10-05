VirusTotal public and private APIv2 Full support
===================

This script was made public into the official VT API documentation page.
https://www.virustotal.com/en/documentation/public-api/

Before using the tool you must set your api key near the end of the file or in ~.vtapi.

* ~.vtapi file content:
```python
[vt]
apikey=your-apikey-here
```
**Dependencies:**
 *  requests
 *  texttable
 *  python-dateutils
 
These can be installed via PIP or a package manager.
Example of installing all dependencies using pip:
```python
pip install -r requirements.txt
```

**04.08.2014:**

* Ip search (-i) now can be used scheme search like this http://ip, urlparse will extract domain
* Windows expand user home support added, thanks to @truekonrads

**28.07.2014:**

* Search bug fixed
* Domain search (-d) now can be used scheme search like this http://domain.com, urlparse will extract domain

**26.06.2014:**

* Now show file name when scan/search file
* In file-search option can now be used md5 hash
* Rescan option now support wildcard, for example samples/*, will generate file hash on the fly

**29.04.2014:**

* Bug fix related with csv dumps

**23.03.2014:**

* Table improvement, now result show is more prettiest, column sizes adjustment

**12.03.2014:**

* Added option --csv, which permit dump AVs result into csv file

* Now AVs results are sorted from a to z, to help found more quickly searched AV result

* Added AV version and Last AV signature update

**09.03.2014:**

* Added posibility to scan urls passed in file, filename must be urls_for_scan.txt and one url per line.

  Execution as arg: vt.py -u/-ur urls_for_scan.txt

* Removed limits for 4 urls only with public api

**20.11.2013 Updates:**

* Small bug fixed, when internet connection doesn't work correctly

* Added option for file(s) search, without submitting file.
Now you don't need to get hash of file and search it in VT if you just want to get the report, check option -fs/--file-search

* In search without verbose mode now if someone/all of Kaspersky/Sophos/TrendMicro 
don't have results, you will see detections by others engines

**16.11.2013 Updates:**

* Code optimization/cleaning, and small print fix

**15.11.2013 Updates:**

* Added support for get apikey from file, now you can put is as before into apikey value at line 1409 or put it to config file
if api key not in value , will check by default ~/.vtapi, but you can put it to another file and use -c/--config-file option

* Limit reached issue patched 

special thanks to @kellewic and @urbanski


few public API functions getted from Chris Clark script<br />
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
	
	
usage: value [-h] [-f] [-u] [-ur] [-d] [-i] [-s] [--report-all-info] [-ac]
             [-gc] [--get-comments-before DATE] [-v] [-j] [-r] [--delete]
             [--date DATE] [--period PERIOD] [--repeat REPEAT]
             [--notify-url NOTIFY_URL] [--notify-changes-only]
             [--alexa-domain-info] [--wot-domain-info] [--trendmicro]
             [--websense-threatseeker] [--bitdefender] [--webutation-domain]
             [--detected-urls] [--pcaps] [--detected-downloaded-samples]
             [--undetected-downloaded-samples] [--detected-communicated]
             [--undetected-communicated] [--behaviour] [--behavior-network]
             [--behavior-process] [--behavior-summary] [--pcap] [--download]
             [--clusters] [--distribution-files] [--distribution-urls]
             [--before BEFORE] [--after AFTER] [--reports] [--limit LIMIT]
             [--allinfo] [--massive-download]
             [value [value ...]]

Scan/Search/ReScan/JSON parse

positional arguments:
  value                 Enter the Hash, Path to File(s) or Url(s)

optional arguments:
  -h, --help            show this help message and exit
  -f, --file-scan       File(s) scan, support linux name wildcard, example:
                        /home/user/*malware*, if file was scanned, you will
                        see scan info, for full scan report use verbose mode,
                        and dump if you want save already scanned samples
  -u, --url-scan        Url scan, support space separated list, Max 4 urls (or
                        25 if you have private api)
  -ur, --url-report     Url(s) report, support space separated list, Max 4 (or
                        25 if you have private api) urls, you can use --url-
                        report --url-scan options for analysing url(s) if they
                        are not in VT data base
  -d, --domain-info     Retrieves a report on a given domain (PRIVATE API
                        ONLY! including the information recorded by
                        VirusTotal's Passive DNS infrastructure)
  -i, --ip-info         A valid IPv4 address in dotted quad notation, for the
                        time being only IPv4 addresses are supported.
  -s, --search          A md5/sha1/sha256 hash for which you want to retrieve
                        the most recent report. You may also specify a scan_id
                        (sha256-timestamp as returned by the scan API) to
                        access a specific report. You can also specify a space
                        separated list made up of a combination of hashes and
                        scan_ids Public API up to 4 items/Private API up to 25
                        items, this allows you to perform a batch request with
                        one single call.
  --report-all-info     PRIVATE API ONLY! If specified and set to one, the
                        call will return additional info, other than the
                        antivirus results, on the file being queried. This
                        additional info includes the output of several tools
                        acting on the file (PDFiD, ExifTool, sigcheck, TrID,
                        etc.), metadata regarding VirusTotal submissions
                        (number of unique sources that have sent the file in
                        the past, first seen date, last seen date, etc.), and
                        the output of in-house technologies such as a
                        behavioural sandbox.
  -ac, --add-comment    The actual review, you can tag it using the "#"
                        twitter-like syntax (e.g. #disinfection #zbot) and
                        reference users using the "@" syntax (e.g.
                        @VirusTotalTeam). supported hashes MD5/SHA1/SHA256
  -gc, --get-comments   Either a md5/sha1/sha256 hash of the file or the URL
                        itself you want to retrieve
  --get-comments-before DATE
                        PRIVATE API ONLY! A datetime token that allows you to
                        iterate over all comments on a specific item whenever
                        it has been commented on more than 25 times. Token
                        format 20120725170000 or 2012-07-25 17 00 00 or
                        2012-07-25 17:00:00
  -v, --verbose         Turn on verbosity of VT reports
  -j, --dump            Dumps the full VT report to file (VTDL{md5}.json), if
                        you (re)scan many files/urls, their json data will be
                        dumped to separetad files

Rescan options:
  -r, --rescan          Allows you to rescan files in VirusTotal's file store
                        without having to resubmit them, thus saving
                        bandwidth., support space separated list, MAX 25
                        hashes
  --delete              PRIVATE API ONLY! A md5/sha1/sha256 hash for which you
                        want to delete the scheduled scan
  --date DATE           PRIVATE API ONLY! A Date in one of this formats
                        (example: 20120725170000 or 2012-07-25 17 00 00 or
                        2012-07-25 17:00:00) in which the rescan should be
                        performed. If not specified the rescan will be
                        performed immediately.
  --period PERIOD       PRIVATE API ONLY! Period in days in which the file
                        should be rescanned. If this argument is provided the
                        file will be rescanned periodically every period days,
                        if not, the rescan is performed once and not repated
                        again.
  --repeat REPEAT       PRIVATE API ONLY! Used in conjunction with period to
                        specify the number of times the file should be
                        rescanned. If this argument is provided the file will
                        be rescanned the given amount of times, if not, the
                        file will be rescanned indefinitely.

File scan/Rescan shared options:
  --notify-url NOTIFY_URL
                        PRIVATE API ONLY! An URL where a POST notification
                        should be sent when the scan finishes.
  --notify-changes-only
                        PRIVATE API ONLY! Used in conjunction with --notify-
                        url. Indicates if POST notifications should be sent
                        only if the scan results differ from the previous one.

Domain/IP shared verbose mode options, by default just show resolved IPs/Passive DNS:
  --alexa-domain-info   Just Domain option: Show Alexa domain info
  --wot-domain-info     Just Domain option: Show WOT domain info
  --trendmicro          Just Domain option: Show TrendMicro category info
  --websense-threatseeker
                        Just Domain option: Show Websense ThreatSeeker
                        category
  --bitdefender         Just Domain option: Show BitDefender category
  --webutation-domain   Just Domain option: Show Webutation domain info
  --detected-urls       Just Domain option: Show latest detected URLs
  --pcaps               Just Domain option: Show all pcaps hashes
  --detected-downloaded-samples
                        Domain/Ip options: Show latest detected files that
                        were downloaded from this ip
  --undetected-downloaded-samples
                        Domain/Ip options: Show latest undetected files that
                        were downloaded from this domain/ip
  --detected-communicated
                        Domain/Ip Show latest detected files that communicate
                        with this domain/ip
  --undetected-communicated
                        Domain/Ip Show latest undetected files that
                        communicate with this domain/ip

Behaviour options - PRIVATE API ONLY!:
  --behaviour           The md5/sha1/sha256 hash of the file whose dynamic
                        behavioural report you want to retrieve. VirusTotal
                        runs a distributed setup of Cuckoo sandbox machines
                        that execute the files we receive. Execution is
                        attempted only once, upon first submission to
                        VirusTotal, and only Portable Executables under 10MB
                        in size are ran. The execution of files is a best
                        effort process, hence, there are no guarantees about a
                        report being generated for a given file in our
                        dataset. a file did indeed produce a behavioural
                        report, a summary of it can be obtained by using the
                        file scan lookup call providing the additional HTTP
                        POST parameter allinfo=1. The summary will appear
                        under the behaviour-v1 property of the additional_info
                        field in the JSON report.This API allows you to
                        retrieve the full JSON report of the file's execution
                        as outputted by the Cuckoo JSON report encoder.
  --behavior-network    Show network activity
  --behavior-process    Show processes
  --behavior-summary    Show summary

Additional PRIVATE API options:
  --pcap                The md5/sha1/sha256 hash of the file whose network
                        traffic dump you want to retrieve. Will save as
                        VTDL_{hash}.pcap
  --download            The md5/sha1/sha256 hash of the file you want to
                        download. Will save as VTDL_{hash}.dangerous
  --clusters            A specific day for which we want to access the
                        clustering details, example: 2013-09-10
  --distribution-files  Timestamps are just integer numbers where higher
                        values mean more recent files. Both before and after
                        parameters are optional, if they are not provided the
                        oldest files in the queue are returned in timestamp
                        ascending order.
  --distribution-urls   Timestamps are just integer numbers where higher
                        values mean more recent urls. Both before and after
                        parameters are optional, if they are not provided the
                        oldest urls in the queue are returned in timestamp
                        ascending order.

Distribution options - PRIVATE API ONLY!:
  --before BEFORE       File/Url option. Retrieve files/urls received before
                        the given timestamp, in timestamp descending order.
  --after AFTER         File/Url option. Retrieve files/urls received after
                        the given timestamp, in timestamp ascending order.
  --reports             Include the files' antivirus results in the response.
                        Possible values are 'true' or 'false' (default value
                        is 'false').
  --limit LIMIT         File/Url option. Retrieve limit file items at most
                        (default: 1000).
  --allinfo             will include the results for each particular URL scan
                        (in exactly the same format as the URL scan retrieving
                        API). If the parameter is not specified, each item
                        returned will onlycontain the scanned URL and its
                        detection ratio.
  --massive-download    Show information how to get massive download work

Options -v/--verbose active verbose mode in search, and if you look for domain information,
this will be activate all domain verbose mode options
</code></pre>
 
 Tested on Mac Os X 10.8.5/10.9 and Ubuntu 12.04.4
