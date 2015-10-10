#!/usr/bin/env python2.7

# Full VT APIv2 functions added by Andriy Brukhovetskyy
# doomedraven -  Twitter : @d00m3dr4v3n
# No Licence or warranty expressed or implied, use however you wish!
# For more information look at:
#
# https://www.virustotal.com/en/documentation/public-api
# https://www.virustotal.com/en/documentation/private-api

__author__ = 'Andriy Brukhovetskyy - DoomedRaven'
__version__ = '2.0.9.3'
__license__ = 'For fun :)'

import os
import re
import sys
import csv
import time
import json
import hashlib
import argparse
import requests
import ConfigParser
from glob import glob
from re import match
import texttable as tt
from urlparse import urlparse
from operator import methodcaller
from datetime import datetime
from dateutil.relativedelta import relativedelta

try:
     from requests.packages.urllib3.exceptions import InsecureRequestWarning, InsecurePlatformWarning
     requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
     requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
except (AttributeError, ImportError):
     pass

try:
    import pefile
    import peutils
    PEFILE = True
except ImportError:
    PEFILE = False

try:
    import magic
    MAGIC = True
except:
    MAGIC = False


def private_api_access_error():
    print '\n[!] You don\'t have permission for this operation, Looks like you trying to access to PRIVATE API functions\n'
    sys.exit()

def get_adequate_table_sizes(scans, short=False, short_list=False):

    av_size_f = 14
    result_f = 6
    version_f = 9

    if scans:

        # Result len
        if short:
            av_size = max(
                map(lambda engine:
                    len(engine) if engine is not None and engine in short_list else 0, scans)
                )
            result = max(
                map(lambda engine: len(scans[engine]['result']) if scans[engine].has_key(
                'result') and scans[engine]['result'] is not None and engine in short_list else 0, scans)
            )
            version = max(
                map(lambda engine: len(scans[engine]['version']) if scans[engine].has_key(
                'version') and scans[engine]['version'] is not None and engine in short_list else 0, scans)
            )

        else:
            av_size = max(
                map(
                    lambda engine: len(engine) if engine is not None else 0, scans)
                )
            result = max(
                map(lambda engine: len(scans[engine]['result']) if scans[
                         engine].has_key('result') and scans[engine]['result'] is not None else 0, scans)
                )
            version = max(
                map(lambda engine: len(scans[engine]['version']) if scans[
                          engine].has_key('version') and scans[engine]['version'] is not None else 0, scans)
                )

        if result > result_f:
            result_f = result

        if av_size > av_size_f:
            av_size_f = av_size

        if version > version_f:
            version_f = version

    return av_size_f, result_f, version_f

def pretty_print(block, headers, sizes=False, align=False, email=False):

    tab = tt.Texttable()

    if email:
        tab.set_deco(tt.Texttable.HEADER)

    if isinstance(block, list):
        plist = []

        for line in block:

            if len(headers) == 1:
                plist.append([line])

            else:
                plist.append(
                    map(lambda key: line[key] if line.get(key) else ' -- ', headers)
                    )

        if len(plist) > 1 and isinstance(plist[0], list):
            tab.add_rows(plist)

        else:
            tab.add_row(plist[0])

    else:
        row = map(
            lambda key: block[key] if block.get(key) else ' -- ', headers)
        tab.add_row(row)

    tab.header(headers)

    if not align:
        align = map(lambda key: 'l', headers)

    if sizes:
        tab.set_cols_width(sizes)

    tab.set_cols_align(align)

    print tab.draw()

def pretty_print_special(rows, headers, sizes=False, align=False, email=False):
    tab = tt.Texttable()

    if email:
        tab.set_deco(tt.Texttable.HEADER)

    tab.add_rows(rows)

    if sizes:
        tab.set_cols_width(sizes)

    if align:
        tab.set_cols_align(align)

    tab.header(headers)

    print '\n', tab.draw()

def is_file(value):
    try:
        if isinstance(value, list):

            if os.path.isfile(value[0]):
                return True, value[0]

            else:
                return False, value[0]

        elif isinstance(value, basestring):

            if os.path.isfile(value):
                return True, value

            else:
                return False, value

    except IndexError:
        print '\n[!] You need to provide some arguments\n'
        sys.exit()

def jsondump(jdata, sha1):

    jsondumpfile = open('VTDL_{name}.json'.format(name=sha1), 'w')
    json.dump(jdata, jsondumpfile)
    jsondumpfile.close()

    print '\n\tJSON Written to File -- VTDL_{sha1}.json\n'.format(sha1=sha1)

def load_file(file_path):

    if file_path.endswith('.json'):

        try:
            log = open(file_path, 'r').read()
            jdata = json.loads(log)
            return jdata

        except TypeError:
            print '\n[!] Check your json dump file\n'

def get_detections(scans, **kwargs):

    plist = [[]]

    engines = kwargs.get('engines')
    if engines == []:
      return
    elif isinstance(engines, basestring) and engines.find(',') != -1:
        engines = engines.split(',')
    elif isinstance(engines, basestring):
        engines = [engines]
    else:
        return

    for engine in engines:
        engine = engine.strip()
        if scans.get(engine) and scans[engine].get('result'):
            plist.append([engine,
                          scans[engine]['result'],
                          scans[engine]['version'] if 'version' in scans[engine] and scans[engine]['version'] else ' -- ',
                          scans[engine]['update'] if 'update' in scans[engine] and scans[engine]['update'] else ' -- '
                          ])
    if plist != [[]]:
        av_size, result_size, version = get_adequate_table_sizes(
            scans, True, engines)
        pretty_print_special(plist,
                             ['Vendor name',  'Result',
                                 'Version', 'Last Update'],
                             [av_size, result_size, version, 11],
                             ['r', 'l', 'l', 'c'],
                             False,
                             kwargs.get('email_template')
                             )

def dump_csv(filename, scans):

    f = open('VTDL{0}.csv'.format(filename), 'w')
    writer = csv.writer(f, delimiter=',')
    writer.writerow(
        ('Vendor name', 'Detected', 'Result', 'Version', 'Last Update'))

    for x in sorted(scans):
        writer.writerow([x,
                         'True' if scans[x]['detected'] else 'False', scans[
                             x]['result'] if scans[x]['result'] else ' -- ',
                         scans[x]['version'] if scans[x].has_key(
                             'version') and scans[x]['version'] else ' -- ',
                         scans[x]['update'] if scans[x].has_key(
                             'update') and scans[x]['update'] else ' -- '
                         ])

    f.close()

    print '\n\tCSV file dumped as: VTDL{0}.csv'.format(filename)

def parse_report(jdata, **kwargs):
    filename = ''

    if jdata.get('response_code') != 1:

        if not kwargs.get('not_exit'):
            return False

        else:
            print '\n[-] Status : {info}\n'.format(info=jdata.get('verbose_msg'))
            sys.exit()

    if jdata.get('scan_date'):
        print '\nScanned on : \n\t{0}'.format(jdata.get('scan_date'))
    if jdata.get('total'):
        print '\nDetections:\n\t {positives}/{total} Positives/Total'.format(positives=jdata.get('positives'), total=jdata.get('total'))

    if kwargs.get('url_report'):
        if jdata.get('url'):
            print '\nScanned url :\n\t {url}'.format(url=jdata.get('url'))

    else:
        if not kwargs.get('verbose') and  'scans' in jdata:
            get_detections(jdata['scans'], **kwargs)

        if 'md5' in jdata: print '\n\tResults for MD5    : {0}'.format(jdata.get('md5'))
        if 'sha1' in jdata: print '\tResults for SHA1   : {0}'.format(jdata.get('sha1'))
        if 'sha256' in jdata: print '\tResults for SHA256 : {0}'.format(jdata.get('sha256'))

    if kwargs.get('verbose') == True and jdata.get('scans'):
        print '\nVerbose VirusTotal Information Output:'
        plist = [[]]

        for x in sorted(jdata.get('scans')):
            if jdata['scans'][x].get('detected'):
                plist.append([x,
                          'True',
                          jdata['scans'][x]['result'] if jdata['scans'][x]['result'] else ' -- ',
                          jdata['scans'][x]['version'] if  'version' in jdata['scans'][x] and jdata['scans'][x]['version'] else ' -- ',
                          jdata['scans'][x]['update'] if 'update' in jdata['scans'][x] and jdata['scans'][x]['update'] else ' -- '
                          ])
        av_size, result_size, version = get_adequate_table_sizes(
            jdata['scans'])

        if version == 9:
            version_align = 'c'

        else:
            version_align = 'l'

        pretty_print_special(plist,
                             ['Vendor name', 'Detected', 'Result',
                                 'Version', 'Last Update'],
                             [av_size, 9, result_size, version, 12],
                             ['r', 'c', 'l', version_align, 'c'],
                             False,
                             kwargs.get('email_template')
                             )
        del plist

    if kwargs.get('dump') is True:
        jsondump(jdata, jdata.get('sha1'))

    if kwargs.get('csv') is True:
        filename = jdata.get('scan_id')
        dump_csv(filename, jdata.get('scans'))

    if jdata.get('permalink'):
        print "\n\tPermanent Link : {0}\n".format(jdata.get('permalink'))

    return True

# Static variable decorator for function
def static_var(varname, value):
    def decorate(func):

        setattr(func, varname, value)

        return func

    return decorate

# Track how many times we issue a request
@static_var("counter", 0)
# Track when the first request was sent
@static_var("start_time", 0)
def get_response(url, method="get", **kwargs):

    # Set on first request

    if get_response.start_time == 0:
        get_response.start_time = time.time()

    # Increment every request
    get_response.counter = 1

    jdata = ''
    response = ''

    while True:
        try:
            response = getattr(requests, method)(url, **kwargs)

        except requests.exceptions.ConnectionError:
            print '\n[!] Can\'t resolv hostname, check your internet conection\n'
            sys.exit()

        if response.status_code == 403:
            private_api_access_error()

        if response.status_code != 204 and hasattr(response, 'json'):

            try:
                jdata = response.json()

            except:
                jdata = response.json

            break

        # Determine minimum time we need to wait for limit to reset
        wait_time = 59 - int(time.time() - get_response.start_time)

        if wait_time < 0:
            wait_time = 60

        print "Reached per minute limit of {0:d}; waiting {1:d} seconds\n".format(get_response.counter, wait_time)

        time.sleep(wait_time)

        # Reset static vars
        get_response.counter = 0
        get_response.start_time = 0

    return jdata, response


class vtAPI():

    def __init__(self, apikey):

        self.params = {'apikey': apikey}
        self.base = 'https://www.virustotal.com/vtapi/v2/{}'

    def getReport(self, *args, **kwargs):
        """
        A md5/sha1/sha256 hash will retrieve the most recent report on a given sample. You may also specify a scan_id (sha256-timestamp as returned by the file upload API)
        to access a specific report. You can also specify a CSV list made up of a combination of hashes and scan_ids (up to 4 items or 25 if you have private api with the
        standard request rate), this allows you to perform a batch request with one single call.
        """
        return_json = dict()
        jdatas = list()
        result, name = is_file(kwargs.get('value'))

        if result:
            jdata = load_file(name)
            if isinstance(jdata, list):
                jdatas = jdata
            else:
                jdatas = [jdata]

            kwargs['dump'] = False

        else:

            if isinstance(kwargs.get('value'), list) and len(kwargs.get('value')) == 1:
                pass

            elif isinstance(kwargs.get('value'), basestring):
                kwargs['value'] = [kwargs.get('value')]

            elif len(kwargs.get('value')) > 1 and not isinstance(kwargs.get('value'), basestring):

                if kwargs.get('api_type'):
                    start = -25
                    increment = 25

                else:
                    start = -4
                    increment = 4

                end = 0

                while True:

                    start += increment

                    if len(kwargs.get('value')) > end + increment:
                        end += increment
                    elif len(kwargs('value')) <= end + increment:
                        end = len(kwargs.get('value'))

                    kwargs['value'].append(
                        ' '.join(map(lambda hreport: hreport, kwargs.get('value')[start:end]))
                    )

                    if end == len(kwargs.get('value')):
                        break

            for hashes_report in kwargs.get('value'):
                if (kwargs.get('search_intelligence') or 'search_intelligence' in args):
                    self.params['query'] = [hashes_report]
                    url = self.base.format('file/search')
                else:
                    self.params['resource'] = hashes_report
                    url = self.base.format('file/report')

                if kwargs.get('allinfo'):
                    self.params['allinfo'] = kwargs.get('allinfo')

                jdata, response = get_response(url, params=self.params)

                if kwargs.get('return_raw'):
                    return jdata

                jdatas += jdata

        jdatas = filter(None, jdatas)
        if isinstance(jdatas, list) and jdatas == []:
            if kwargs.get('return_raw'):
                pass
            else:
                print 'Nothing found'
            return

        if  not isinstance(jdata, list):
            jdatas = [jdata]

        for jdata in jdatas:
            if jdata.get('response_code') == 0 or jdata.get('response_code') == -1:
                if kwargs.get('not_exit'):
                    return False

            if kwargs.get('search_intelligence') or 'search_intelligence' in args:

                if kwargs.get('return_json') and (kwargs.get('hashes') or 'hashes' in args):
                    return_json['hashes'] = jdata['hashes']
                else:
                    if 'hashes' in jdata and jdata['hashes']:
                        print '[+] Matched hash(es):'
                        for file_hash in  jdata['hashes']:
                            print '\t{0}'.format(file_hash)

            if kwargs.get('allinfo') == 1:

                if kwargs.get('dump'):
                    jsondump(jdata, name)

                if kwargs.get('verbose'):
                    if jdata.get('md5'):
                        print '\nMD5    : {md5}'.format(md5=jdata.get('md5'))
                    if jdata.get('vhash'):
                        print '\nVHash  : {md5}'.format(md5=jdata.get('vhash'))
                    if jdata.get('sha1'):
                        print 'SHA1   : {sha1}'.format(sha1=jdata.get('sha1'))
                    if jdata.get('sha256'):
                        print 'SHA256 : {sha256}'.format(sha256=jdata.get('sha256'))
                    if jdata.get('ssdeep'):
                        print 'SSDEEP : {ssdeep}'.format(ssdeep=jdata.get('ssdeep'))

                    if jdata.get('scan_date'):
                        print '\nScan  Date     : {scan_date}'.format(scan_date=jdata.get('scan_date'))
                    if jdata.get('first_seen'):
                        print 'First Submission : {first_seen}'.format(first_seen=jdata.get('first_seen'))
                    if jdata.get('last_seen'):
                        print 'Last  Submission : {last_seen}'.format(last_seen=jdata.get('last_seen'))
                    if jdata.get('times_submitted'):
                        print 'Times submitted : {last_seen}'.format(last_seen=jdata.get('times_submitted'))
                    if jdata.get('scan_id'):
                        print 'Scan id: {scan}'.format(scan=jdata['scan_id'])
                    if jdata.get('harmless_votes'):
                        print 'Harmless votes: {harmless}'.format(harmless=jdata['harmless_votes'])
                    if jdata.get('community_reputation'):
                        print 'Community reputation: {community}'.format(community=jdata['community_reputation'])
                    if jdata.get('malicious_votes'):
                        print 'Malicious votes: {community}'.format(community=jdata['malicious_votes'])

                if jdata.get('submission_names') and ((kwargs.get('submission_names') or 'submission_names' in args) or kwargs.get('verbose')):
                  if kwargs.get('return_json'):
                        return_json['submission_names'] =  jdata.get('submission_names')
                  else:
                      print '\nSubmission names:'
                      for name in jdata['submission_names']:
                          print '\t{name}'.format(name=name)

                if jdata.get('ITW_urls') and ((kwargs.get('ITW_urls') or 'ITW_urls' in args) or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json['ITW_urls'] =  jdata.get('ITW_urls')
                    else:
                          print '\nITW urls:'
                          for itw_url in jdata['ITW_urls']:
                              print '\t{itw_url}'.format(itw_url=itw_url)

                if kwargs.get('verbose'):
                    if jdata.get('type') and kwargs.get('verbose'):
                        print '\nFile Type : {type_f}'.format(type_f=jdata['type'])

                    if jdata.get('size') and kwargs.get('verbose'):
                        print 'File Size : {size}'.format(size=jdata['size'])

                    if jdata.get('tags') and kwargs.get('verbose'):
                        print 'Tags: {tags}'.format(tags=', '.join(map(lambda tag: tag, jdata['tags'])))

                    if jdata.get('unique_sources') and kwargs.get('verbose'):
                        print 'Unique sources : {size}'.format(size=jdata['unique_sources'])

                if jdata.get('additional_info') and kwargs.get('verbose'):
                    if jdata['additional_info']['magic']:
                        print '\tMagic : {magic}'.format(magic=jdata['additional_info']['magic'])

                    if jdata['additional_info'].get('trid') and kwargs.get('verbose'):
                        print '\nTrID:'
                        print '\t{trid}'.format(trid=jdata['additional_info']['trid'].replace('\n', '\n\t'))

                    if jdata['additional_info'].get('trendmicro-housecall-heuristic') and kwargs.get('verbose'):
                        print '\tTrendmicro housecall heuristic : {trend}'.format(trend=jdata['additional_info']['trendmicro-housecall-heuristic'])

                    if jdata['additional_info'].get('deepguard') and kwargs.get('verbose'):
                        print '\tDeepguard : {deepguard}'.format(deepguard=jdata['additional_info']['deepguard'])

                    if jdata.get('unique_sources') and kwargs.get('verbose'):
                        print '\tUnique sources : {size}'.format(size=jdata['unique_sources'])

                    if jdata.get('email_parents') and kwargs.get('verbose'):
                        print '\nEmail parents:'
                        for email in jdata['email_parents']:
                            print '\t{email}'.format(email=email)

                    if jdata['additional_info'].get('referers') and kwargs.get('verbose'):
                        print '\nReferers:'
                        for referer in jdata['additional_info']['referers']:
                            print '\t{referer}'.format(referer=referer)

                    if jdata['additional_info'].get('sigcheck') and kwargs.get('verbose'):

                        print '\nPE signature block:'
                        plist = [[]]
                        for sig in jdata['additional_info']['sigcheck']:
                            if isinstance(jdata['additional_info']['sigcheck'][sig], list):
                              for data in  jdata['additional_info']['sigcheck'][sig]:
                                  sub_plist = [[]]
                                  for key in data.keys():
                                      sub_plist.append([key, data[key]])
                                  pretty_print_special(sub_plist, ['Name', 'Value'], False, False, kwargs.get('email_template'))
                                  del sub_plist
                            else:
                                plist.append(
                                    [sig, jdata['additional_info']['sigcheck'][sig].encode('utf-8')] # texttable unicode fail
                                )

                        pretty_print_special(plist, ['Name', 'Value'], False, False, kwargs.get('email_template'))
                        del plist

                    if jdata['additional_info'].get('exiftool') and kwargs.get('verbose'):

                        print '\nExifTool file metadata:'
                        plist = [[]]

                        for exiftool in jdata['additional_info']['exiftool']:
                            plist.append(
                                [exiftool, jdata['additional_info']['exiftool'][exiftool]])

                        pretty_print_special(plist, ['Name', 'Value'], False, False, kwargs.get('email_template'))
                        del plist

                    if jdata['additional_info'].get('sections') and kwargs.get('verbose'):
                        pretty_print_special(jdata['additional_info']['sections'],
                                             ['Name', 'Virtual address', 'Virtual size',
                                                 'Raw size', 'Entropy', 'MD5'],
                                             [10, 10, 10, 10, 10, 35],
                                             ['c', 'c', 'c', 'c', 'c', 'c'],
                                             kwargs.get('email_template')
                                             )

                    if jdata['additional_info'].get('imports') and kwargs.get('verbose'):

                        print '\nImports:'
                        for imported in jdata['additional_info']['imports']:
                            print '\t{0}'.format(imported)
                            for valor in jdata['additional_info']['imports'][imported]:
                                print '\t\t{0}'.format(valor)

                    if jdata['additional_info'].get('compressedview') and ((kwargs.get('compressedview') or 'compressedview' in args) or kwargs.get('verbose')):
                      if return_json.get('return_json'):
                        return_json['compressedview'] = jdata['additional_info']['compressedview']['compressedview']

                      else:
                        print '\nCompressed view:'

                        if jdata['additional_info']['compressedview'].get('children') and ((kwargs.get('children') or 'children' in args) or kwargs.get('verbose')):
                            if kwargs.get('return_json'):
                                return_json['children'] = jdata['additional_info']['compressedview']['children']
                            else:
                                for child in jdata['additional_info']['compressedview'].get('children'):
                                    if child.get('datetime'):
                                        print '\tDatetime: {0}'.format(child['datetime'])
                                    if child.get('detection_ration'):
                                        print '\tDetection ration: \n\tDetected: {0}\n\tTotal {1}'.format(child['detection_ration'][0], child['detection_ration'])
                                    if child.get('filename'):
                                        try:
                                            print '\tFilename: {0}'.format(child['filename'])
                                        except:
                                            try:
                                                print '\tFilename: {0}'.format(child['filename'].encode('utf-8'))
                                            except:
                                                print '\t[-]Name decode error'
                                    if child.get('sha256'):
                                        print '\tsha256: {0}'.format(child['sha256'])
                                    if child.get('size'):
                                        print '\tSize: {0}'.format(child['size'])
                                    if child.get('type'):
                                        print '\tType: {0}'.format(child['type'])

                        if jdata['additional_info']['compressedview'].get('extensions'):
                            print '\nExtensions:'
                            for ext in jdata['additional_info']['compressedview']['extensions']:
                                print '\t', ext, jdata['additional_info']['compressedview']['extensions'][ext]

                        if jdata['additional_info']['compressedview'].get('file_types'):
                            for file_types in jdata['additional_info']['compressedview']['file_types']:
                                print '\t' ,ext, jdata['additional_info']['compressedview']['file_types'][file_types]

                        if jdata['additional_info']['compressedview'].get('tags'):
                            print '\nTags:'
                            for tag in jdata['additional_info']['compressedview']['tags']:
                                print '\t', tag

                        if jdata['additional_info']['compressedview'].get('lowest_datetime'):
                            print '\nLowest datetime: {0}'.format(jdata['additional_info']['compressedview']['lowest_datetime'])

                        if jdata['additional_info']['compressedview'].get('highest_datetime'):
                            print 'Highest datetime: {0}'.format(jdata['additional_info']['compressedview']['highest_datetime'])

                        if jdata['additional_info']['compressedview'].get('num_children'):
                            print 'Num children: {0}'.format(jdata['additional_info']['compressedview']['num_children'])

                        if jdata['additional_info']['compressedview'].get('type'):
                            print 'Type: {0}'.format(jdata['additional_info']['compressedview']['type'])

                        if jdata['additional_info']['compressedview'].get('uncompressed_size'):
                            print 'Uncompressed_size: {0}'.format(jdata['additional_info']['compressedview']['uncompressed_size'])

                        if jdata['additional_info']['compressedview'].get('vhash'):
                            print 'Vhash: {0}'.format(jdata['additional_info']['compressedview']['vhash'])

                    if jdata['additional_info'].get('detailed_email_parents') and ((kwargs.get('detailed_email_parents') or 'detailed_email_parents' in args) or kwargs.get('verbose')):

                        if return_json.get('return_json'):
                            return_json['detailed_email_parents'] = jdata['additional_info']['compressedview']['detailed_email_parents']
                        else:
                            print '\nDetailed email parents:'
                            for email in jdata['additional_info']['detailed_email_parents']:

                                if email.get('subject'):
                                    print '\nSubject:'
                                    print '\t{subject}'.format(subject=email['subject'])

                                if email.get('sender'):
                                    print '\nSender:'
                                    print '\t{sender}'.format(sender=email['sender'])

                                if email.get('receiver'):
                                    print '\nReceiver:'
                                    print '\t{receiver}'.format(receiver=email['receiver'])

                                if email.get('message_id'):
                                    print '\nMessage id:'
                                    print '\t{message_id}'.format(message_id=email['message_id'])

                                if email.get('message'):
                                    print '\nMessage:'
                                    for line in email['message'].split('\n'):
                                        print line.strip()

                if jdata.get('total') and kwargs.get('verbose'):
                    print '\nDetections:\n\t{positives}/{total} Positives/Total\n'.format(positives=jdata['positives'], total=jdata['total'])

                if jdata.get('scans') and kwargs.get('verbose'):

                    plist = [[]]

                    for x in sorted(jdata.get('scans')):
                        if jdata['scans'][x].get('detected'):
                              plist.append([x,
                              'True',
                              jdata['scans'][x]['result'] if jdata['scans'][x]['result'] else ' -- ',
                              jdata['scans'][x]['version'] if  'version' in jdata['scans'][x] and jdata['scans'][x]['version'] else ' -- ',
                              jdata['scans'][x]['update'] if 'update' in jdata['scans'][x] and jdata['scans'][x]['update'] else ' -- '
                              ])

                    av_size, result_size, version = get_adequate_table_sizes(jdata['scans'])

                    if version == 9:
                        version_align = 'c'

                    else:
                        version_align = 'l'

                    pretty_print_special(plist,
                                         ['Vendor name', 'Detected', 'Result',
                                             'Version', 'Last Update'],
                                         [av_size, 9, result_size, version, 12],
                                         ['r', 'c', 'l', version_align, 'c'],
                                         kwargs.get('email_template')
                                         )

                    del plist

                if jdata.get('permalink') and kwargs.get('verbose'):
                    print '\nPermanent link : {permalink}\n'.format(permalink=jdata['permalink'])

            else:
                kwargs.update({'url_report':False})
                result = parse_report(jdata, **kwargs)

        if kwargs.get('return_json'):
            return  return_json
        else:
            return result

    def rescan(self, *args,  **kwargs):

        """
        This API allows you to rescan files in VirusTotal's file store without having to resubmit them, thus saving bandwidth.
        """

        if len(kwargs.get('value')) == 1:
            pass

        elif isinstance(kwargs.get('value'), basestring):
            kwargs['value'] = [kwargs.get('value')]

        elif len(kwargs.get('value')) > 1 and not isinstance(kwargs.get('value'), basestring):

                start = -25
                increment = 25
                end = 0
                hash_rescans = list()

                while True:

                    start += increment

                    if len(kwargs.get('value')) > end + increment:
                        end += increment
                    elif len(kwargs.get('value')) <= end + increment:
                        end = len(kwargs.get('value'))

                    hash_rescans.append(
                        [', '.join(map(lambda hrescan: hrescan, kwargs.get('value')[start:end]))]
                    )

                    if end == len(kwargs.get('value')):
                        break

        url = self.base.format('file/rescan')

        for hash_part in kwargs.get('value'):

            if os.path.exists(hash_part):
                hash_part = [
                    hashlib.md5(open(hash_part, 'rb').read()).hexdigest()]

            self.params['resource'] = hash_part

            if kwargs.get('delete'):
                url = url.format('/delete')

            else:
                if kwargs.get('date'):
                    self.params['date'] = kwargs.get('date')

                if kwargs.get('period'):
                    self.params['period'] = kwargs.get('period')

                    if kwargs.get('repeat'):
                        self.params['repeat'] = kwargs.get('repeat')

                if kwargs.get('notify_url'):
                    self.params['notify_url'] = kwargs.get('notify_url')

                    if kwargs('notify_changes_only'):
                        self.params['notify_changes_only'] = kwargs.get('notify_changes_only')

            jdatas, response = get_response(url, params=self.params, method='post')

            if isinstance(jdatas, list) and not filter(None, jdatas):
                print 'Nothing found'
                return

            if not isinstance(jdatas, list):
                jdatas = [jdatas]

            if kwargs.get('return_raw'):
                return jdatas

            for jdata in jdatas:

                if jdata['response_code'] == 0 or jdata['response_code'] == -1:
                    if jdata.get('verbose_msg'):
                        print '\n[!] Status : {verb_msg}\n'.format(verb_msg=jdata['verbose_msg'])

                else:
                    if jdata.get('sha256'):
                        print '[+] Check rescan result with sha256 in few minuts : \n\tSHA256 : {sha256}'.format(sha256=jdata['sha256'])
                    if jdata.get('permalink'):
                        print '\tPermanent link : {permalink}\n'.format(permalink=jdata['permalink'])

    def fileInfo(self, *args,  **kwargs):
        if PEFILE:
            files = kwargs.get('value')
            for file in files:
                try:
                    pe = pefile.PE(file)
                except pefile.PEFormatError:
                    print '[-] Not PE file'
                    return

                print "\nName: {0}".format(file.split("/")[-1])

                print "\n[+] Hashes"
                print "MD5: {0}".format(pe.sections[0].get_hash_md5())
                print "SHA1: {0}".format(pe.sections[0].get_hash_sha1())
                print "SHA256: {0}".format(pe.sections[0].get_hash_sha256())
                print "SHA512: {0}".format(pe.sections[0].get_hash_sha512())
                print 'ImpHash: {0}'.format(pe.get_imphash())

                if pe.FILE_HEADER.TimeDateStamp:
                    print "\n[+]  Created"
                    val = pe.FILE_HEADER.TimeDateStamp
                    ts = '0x%-8X' % (val)
                    try:
                        ts += ' [%s UTC]' % time.asctime(time.gmtime(val))
                        that_year = time.gmtime(val)[0]
                        this_year = time.gmtime(time.time())[0]
                        if that_year < 2000 or that_year > this_year:
                                ts += " [SUSPICIOUS]"
                    except:
                        ts += ' [SUSPICIOUS]'
                    if ts:
                        print '    ', ts

                if pe.sections:
                    print "\n[+] Sections"
                    for section in pe.sections:
                        print '    {0}: {1}'.format(section.Name, section.SizeOfRawData)

                if pe.DIRECTORY_ENTRY_IMPORT:
                    print "\n[+] Imports"
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                      print '   ', entry.dll
                      for imp in entry.imports:
                        print '\t', hex(imp.address), imp.name

                try:
                    if pe.IMAGE_DIRECTORY_ENTRY_EXPORT.symbols:
                        print "\n[+] Exports"
                        for exp in pe.IMAGE_DIRECTORY_ENTRY_EXPORT.symbols:
                            print hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal
                except:
                    pass

                if MAGIC and pe:
                    try:
                        ms = magic.from_file(file)
                        if ms:
                            print "\n[+] File type"
                            ms = magic.from_file(file)
                            print '    ',ms
                    except:
                        pass

                if kwargs.get('userdb') and os.path.exists(kwargs.get('userdb')):

                    signatures = peutils.SignatureDatabase(kwargs.get('userdb'))
                    if signatures.match(pe, ep_only = True) != None:
                        print "\n[+] Packer"
                        print  '\t', signatures.match(pe, ep_only = True)[0]
                    else:
                        pack = peutils.is_probably_packed(pe)
                        if pack == 1:
                            print "\n[+] Packer"
                            print "\t[+] Based on the sections entropy check! file is possibly packed"

    def fileScan(self, *args,  **kwargs):
        """
        Allows to send a file to be analysed by VirusTotal.
        Before performing your submissions we encourage you to retrieve the latest report on the files,
        if it is recent enough you might want to save time and bandwidth by making use of it. File size limit is 32MB,
        in order to submmit files up to 200MB you must request an special upload URL.

        Before send to scan, file will be checked if not scanned before, for save bandwich and VT resources :)
        """

        result = False

        if len(kwargs.get('value')) == 1 and isinstance(kwargs.get('value'), list):

            if isinstance(kwargs.get('value')[0], basestring):
                pass
            else:
                if os.path.isdir(kwargs.get('value')[0]):
                    files = glob('{files}'.format(files=os.path.join(kwargs.get('value')[0], '*')))
        elif isinstance(kwargs.get('value'), basestring):
            if os.path.isdir(files):
                files = glob('{files}'.format(files=os.path.join(kwargs.get('value'), '*')))

        if kwargs.get('notify_url'):
            self.params['notify_url'] = kwargs.get('notify_url')

            if kwargs.get('notify_changes_only'):
                self.params['notify_changes_only'] = kwargs.get('notify_changes_only')

        url = self.base.format('file/scan')

        if not kwargs.get('scan'):
            for index, c_file in enumerate(kwargs.get('value')):
                if os.path.isfile(c_file):

                   kwargs.get('value')[index] = hashlib.md5(
                        open(c_file, 'rb').read()
                    ).hexdigest()

        kwargs['not_exit'] = True
        hash_list = kwargs.get('value')
        for submit_file in hash_list:
            kwargs.update({'value':submit_file})
            # Check all list of files, not only one
            result = self.getReport(**kwargs)
            if not result and kwargs.get('scan') == True:
                if (os.path.getsize(submit_file) / 1048576) <= 128:
                    if os.path.isfile(submit_file):
                        file_name = os.path.split(submit_file)[-1]
                        files = {"file": (file_name, open(submit_file, 'rb'))}
                        try:
                            jdata, response = get_response(
                                url,
                                files=files,
                                params=self.params,
                                method="post"
                            )

                            if kwargs.get('return_raw'):
                                return jdata

                            if jdata.get('md5'):
                                print '\n\tResults for MD5    : {md5_hash}'.format(md5_hash=jdata['md5'])
                            if jdata.get('sha1'):
                                print '\tResults for SHA1   : {sha1}'.format(sha1=jdata['sha1'])
                            if jdata.get('sha256'):
                                print '\tResults for SHA256 : {sha256}'.format(sha256=jdata['sha256'])

                            if jdata.get('verbose_msg'):
                                print '\n\tStatus         : {verb_msg}'.format(verb_msg=jdata['verbose_msg'])
                            if jdata.get('permalink'):
                                print '\tPermanent link : {permalink}\n'.format(permalink=jdata['permalink'])

                        except UnicodeDecodeError:
                            print '\n[!] Sorry filaname is not utf-8 format, other format not suported at the moment'
                            print '[!] Ignored file: {file}\n'.format(file=submit_file)

                else:
                    print '[!] Ignored file: {file}, size is to big, permitted size is 128Mb'.format(file=submit_file)

            elif not result and kwargs.get('scan') == False:
                print '\nReport for file/hash : {0} not found'.format(submit_file)

    def url_scan_and_report(self, *args,  **kwargs):
        """
        Url scan:
        URLs can also be submitted for scanning. Once again, before performing your submission we encourage you to retrieve the latest report on the URL,
        if it is recent enough you might want to save time and bandwidth by making use of it.

        Url report:
        A URL will retrieve the most recent report on the given URL. You may also specify a scan_id (sha256-timestamp as returned by the URL submission API)
        to access a specific report. At the same time, you can specify a space separated list made up of a combination of hashes and scan_ids so as to perform a batch
        request with one single call (up to 4 resources or 25 if you have private api, per call with the standard request rate).
        """

        url_uploads = []
        result = False
        md5_hash = ''

        if os.path.basename(kwargs.get('value')[0]) != 'urls_for_scan.txt':
            result, name = is_file(kwargs.get('value'))
        else:
            result = False

            if os.path.isfile(kwargs.get('value')[0]):
                urls = open(kwargs('value')[0], 'rb').readlines()

        if result:
            jdata = load_file(name)
            kwargs['dump'] = False
        else:
            if isinstance(kwargs.get('value'), list) and len(kwargs.get('value')) == 1:
                url_uploads = [kwargs.get('value')]
            elif isinstance(kwargs.get('value'), basestring):
                url_uploads = [kwargs.get('value')]
            elif len(kwargs.get('value')) > 1 and not isinstance(kwargs.get('value'), basestring):
                if kwargs.get('api_type'):
                    start = -25
                    increment = 25
                else:
                    start = -4
                    increment = 4
                end = 0

                while True:

                    start += increment

                    if len(urls) > end + increment:
                        end += increment
                    elif len(urls) <= end + increment:
                        end = len(urls)

                    if kwargs.get('key') == 'scan':
                        url_uploads.append(['\n'.join(map(lambda url: url.replace(',', '').strip(), urls[start:end]))])
                    elif kwargs.get('key') == 'report':
                        url_uploads.append(['\n'.join(map(lambda url: url.replace(',', '').strip(), urls[start:end]))])

                    if end == len(urls):
                        break
        cont = 0

        for url_upload in url_uploads:
            cont += 1

            if kwargs.get('key') == 'scan':
                print 'Submitting url(s) for analysis: \n\t{url}'.format(url=url_upload[0].replace(', ', '\n\t'))
                self.params['url'] = url_upload[0]
                url = self.base.format('url/scan')

            elif kwargs.get('key') == 'report':
                print '\nSearching for url(s) report: \n\t{url}'.format(url=url_upload[0].replace(', ', '\n\t'))
                self.params['resource'] = url_upload[0]
                self.params['scan'] = kwargs.get('action')
                url = self.base.format('url/report')

            jdata, response = get_response(url, params=self.params, method="post")

            if kwargs.get('return_raw'):
                return jdata

            if isinstance(jdata, list):

                for jdata_part in jdata:
                    if jdata_part is None:
                        print '[-] Nothing found'

                    elif 'response_code' in jdata_part and jdata_part['response_code'] == 0 or jdata_part['response_code'] == -1:
                        if jdata_part.get('verbose_msg'):
                            print '\n[!] Status : {verb_msg}\n'.format(verb_msg=jdata_part['verbose_msg'])
                    else:
                        if kwargs.get('dump'):
                            md5_hash = hashlib.md5(jdata_part['url']).hexdigest()

                        if kwargs('key') == 'report':
                            kwargs.update({'url_report':True})
                            parse_report(jdata, **kwargs)

                        elif kwargs.get('key') == 'scan':
                            if jdata_part.get('verbose_msg'):
                                print '\n\tStatus : {verb_msg}\t{url}'.format(verb_msg=jdata_part['verbose_msg'], url=jdata_part['url'])
                            if jdata_part.get('permalink'):
                                print '\tPermanent link : {permalink}'.format(permalink=jdata_part['permalink'])

            else:
                if jdata is None:
                    print '[-] Nothing found'
                elif  'response_code' in jdata and jdata['response_code'] == 0 or jdata['response_code'] == -1:
                    if jdata.get('verbose_msg'):
                        print '\n[!] Status : {verb_msg}\n'.format(verb_msg=jdata['verbose_msg'])
                else:
                    if kwargs.get('dump'):
                        md5_hash = hashlib.md5(jdata['url']).hexdigest()
                        jsondump(json, md5_hash)

                    if kwargs.get('key') == 'report':
                        kwargs.update({'url_report': True})
                        parse_report(jdata, **kwargs)
                    elif kwargs.get('key') == 'scan':
                        if jdata.get('verbose_msg'):
                            print '\n\tStatus : {verb_msg}\t{url}'.format(verb_msg=jdata['verbose_msg'], url=jdata['url'])
                        if jdata.get('permalink'):
                            print '\tPermanent link : {permalink}'.format(permalink=jdata['permalink'])

            if cont % 4 == 0:
                print '[+] Sleep 60 seconds between the requests'
                time.sleep(60)

    def getIP(self,  *args, **kwargs):
        """
        A valid IPv4 address in dotted quad notation, for the time being only IPv4 addresses are supported.
        """
        jdatas = list()
        return_json = dict()

        try:
            result, name = is_file(kwargs.get('value')[0])

            if result:
                jdatas = [load_file(name)]
                kwargs['dump'] = False
                md5_hash = ''

        except IndexError:
            print 'Something going wrong'
            return

        if not jdatas:

            if isinstance(kwargs.get('value'), list) and len(kwargs.get('value')) == 1:
                pass
            elif isinstance(kwargs.get('value'), basestring):
                kwargs['value'] = [kwargs.get('value')]

            kwargs['value'] = map(lambda ip: urlparse(ip).netloc if ip.startswith(('http://', 'https://')) else ip, kwargs.get('value'))

            url = self.base.format('ip-address/report')

            for ip in kwargs.get('value'):
                self.params['ip'] = ip

                jdata, response = get_response(url, params=self.params)
                jdatas.append((ip, jdata))

                self.params.pop('ip')

            if kwargs.get('return_raw'):
                return jdatas

        for ip, jdata in jdatas:
            if jdata['response_code'] == 0 or jdata['response_code'] == -1:
                if jdata.get('verbose_msg'):
                    print '\n[-] Status {ip}: {verb_msg}\n'.format(verb_msg=jdata['verbose_msg'], ip=ip)

            elif jdata['response_code'] == 1:
                if jdata.get('verbose_msg'):
                    print '\n[+] IP:', ip

                if jdata.get('asn') and ((kwargs.get('asn') or 'asn' in args) or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'asn':jdata['asn']})
                    else:
                        print '\n[+] ASN: {0}'.format(jdata['asn'])

                if jdata.get('as_owner') and ((kwargs.get('as_owner') or 'as_owner' in args)  or kwargs.get('as_owner')):
                    if kwargs.get('return_json'):
                        return_json.update({'as_owner':jdata['as_owner']})
                    else:
                        print '\n[+] AS owner: {0}'.format(jdata['as_owner'])

                if jdata.get('country') and ((kwargs.get('country') or 'country' in args)  or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'country':jdata['country']})
                    else:
                        print '\n[+] Country: {0}'.format(jdata['country'])

                if kwargs.get('return_json'):
                    return_json.update(self.print_results(jdata, *args, **kwargs))
                else:
                    return_json = self.print_results(jdata, *args, **kwargs)

                if jdata.get('resolutions') and ((kwargs.get('passive_dns') or 'passive_dns' in args) or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'passive_dns':jdata['resolutions']})
                    else:
                        print '\n[+] Lastest domain resolved\n'
                        pretty_print(sorted(jdata['resolutions'], key=methodcaller(
                            'get', 'last_resolved'), reverse=True), ['last_resolved', 'hostname'],
                            False, False, kwargs.get('email_template')
                        )


                if kwargs.get('dump') is True:
                    md5_hash = hashlib.md5(name).hexdigest()
                    jsondump(jdata, md5_hash)

            if kwargs.get('return_json'):
                return return_json

    def getDomain(self, *args,  **kwargs):
        """
        Get domain last scan, detected urls and resolved IPs
        """
        return_json = dict()
        jdatas = list()
        try:
            result, name = is_file(kwargs.get('value')[0])
            if result:
                jdatas = [load_file(name)]
                kwargs['dump'] = False
                md5_hash = ''
        except IndexError:
            print '[-] Something going wrong'
            return
        if not jdatas:
            if isinstance(kwargs.get('value'), list) and len(kwargs.get('value')) == 1:
                    pass
            elif isinstance(kwargs.get('value'), basestring):
                kwargs['value'] = [kwargs.get('value')]

            kwargs['value'] = map(lambda domain: urlparse(domain).netloc.lower() if domain.startswith(('http://', 'https://')) else domain, kwargs.get('value'))

            url = self.base.format("domain/report")

            for domain in kwargs.get('value'):
                self.params['domain'] = domain
                jdata, response = get_response(url, params=self.params)
                jdatas.append((domain, jdata))

            if kwargs.get('return_raw'):
                return jdatas

        for domain, jdata in jdatas:
            if jdata['response_code'] == 0 or jdata['response_code'] == -1:
                if jdata.get('verbose_msg'):
                    print '\n[!] Status : {verb_msg} : {domain}\n'.format(verb_msg=jdata['verbose_msg'], domain=domain)

            if jdata.get('response_code') and jdata['response_code'] == 1:
                if jdata.get('verbose_msg'):
                    print '\n[+] Domain:', domain
                if jdata.get('categories') and ((kwargs.get('categories') or 'categories' in args) or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'categories': jdata['return_json']})
                    else:
                        print '\n[+] Categories'
                        print '\t{0}'.format('\n\t'.join(jdata['categories']))
                if jdata.get('TrendMicro category') and ((kwargs.get('trendmicro') or 'trendmicro' in args) or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'trendmicro': jdata['TrendMicro category']})
                    else:
                        print '\n[+] TrendMicro category'
                        print '\t', jdata['TrendMicro category']
                if jdata.get('Websense ThreatSeeker category') and ((kwargs.get('websense_threatseeker') or 'websense_threatseeker' in args) or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'websense_threatseeker': jdata['Websense ThreatSeeker category']})
                    else:
                        print '\n[+] Websense ThreatSeeker category'
                        print '\t', jdata['Websense ThreatSeeker category']
                if jdata.get('BitDefender category') and ((kwargs.get('bitdefender') or 'bitdefender' in args) or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'bitdefender': jdata['BitDefender category']})
                    else:
                        print '\n[+] BitDefender category'
                        print '\t', jdata['BitDefender category']
                if jdata.get('Dr.Web category') and ((kwargs.get('drweb_cat') or 'drweb_cat' in args) or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'drweb_cat': jdata['Dr.Web category']})
                    else:
                        print '\n[+] Dr.Web category'
                        print '\t', jdata['Dr.Web category']
                if jdata.get('Alexa domain info') and ((kwargs.get('alexa_domain_info') or 'alexa_domain_info' in args) or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'alexa_domain_info': jdata['Alexa domain info']})
                    else:
                        print '\n[+] Alexa domain info'
                        print '\t', jdata['Alexa domain info']
                if jdata.get('Alexa category')  and ((kwargs.get('alexa_cat') or 'alexa_cat' in args) or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'alexa_cat': jdata['Alexa category']})
                    else:
                        print '\n[+] Alexa category'
                        print '\t', jdata['Alexa category']
                if jdata.get('Alexa rank') and ((kwargs.get('alexa_rank') or 'alexa_rank' in args) or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'alexa_rank': jdata['Alexa rank']})
                    else:
                        print '\n[+] Alexa rank:'
                        print '\t', jdata['Alexa rank']
                if jdata.get('Opera domain info') and ((kwargs.get('opera_info') or 'opera_info' in args) or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'opera_info': jdata['Opera domain info']})
                    else:
                        print '\n[+] Opera domain info'
                        print '\t', jdata['Opera domain info']
                if jdata.get('WOT domain info') and ((kwargs.get('wot_domain_info') or 'wot_domain_info' in args) or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'wot_domain_info': jdata['WOT domain info']})
                    else:
                        print '\n[+] WOT domain info'
                        plist = [[]]
                        for jdata_part in jdata['WOT domain info']:
                            plist.append(
                                [jdata_part, jdata['WOT domain info'][jdata_part]])
                        pretty_print_special(
                            plist, ['Name', 'Value'], [25, 20], ['c', 'c'], kwargs.get('email_template'))
                        del plist
                if jdata.get('Webutation domain info') and ((kwargs.get('webutation_domain') or 'webutation_domain' in args) or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'webutation_domain': jdata['Webutation domain info']})
                    else:
                        print "\n[+] Webutation"
                        plist = [[]]
                        for jdata_part in jdata['Webutation domain info']:
                            plist.append(
                                [jdata_part, jdata['Webutation domain info'][jdata_part]]
                                )
                        pretty_print_special(
                            plist, ['Name', 'Value'], [25, 20], ['c', 'c'], kwargs.get('email_template'))
                        del plist
                if jdata.get('whois') and ((kwargs.get('whois') or 'whois' in args) or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'whois': jdata['whois']})
                    else:
                        print '\n[+] Whois data:'
                        print '\t{0}'.format(jdata['whois'].replace('\n', '\n\t'))
                if  jdata.get('whois_timestamp') and ((kwargs.get('whois_timestamp') or 'whois_timestamp' in args) or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'whois_timestamp': jdata['whois_timestamp']})
                    else:
                        print '\n[+] Whois timestamp:'
                        print '\t{0}'.format(datetime.fromtimestamp(float(jdata['whois_timestamp'])).strftime('%Y-%m-%d %H:%M:%S'))

                if kwargs.get('return_json'):
                    return_json.update(self.print_results(jdata, *args, **kwargs))
                else:
                    return_json = self.print_results(jdata, *args, **kwargs)

                if jdata.get('pcaps') and ((kwargs.get('pcaps') or 'pcaps' in args) or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'pcaps': jdata['pcaps']})
                    else:
                        print '\n'
                        pretty_print(jdata['pcaps'], ['pcaps'], [70], ['c'], kwargs.get('email_template'))
                if jdata.get('resolutions') and ((kwargs.get('passive_dns') or 'passive_dns' in args)  or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'passive_dns': jdata['resolutions']})
                    else:
                        print '\n[+] Passive DNS replication\n'
                        pretty_print(sorted(jdata['resolutions'], key=methodcaller(
                            'get', 'last_resolved'), reverse=True),
                            ['last_resolved', 'ip_address'],
                            [25, 20],
                            ['c', 'c'],
                            kwargs.get('email_template')
                            )
                if kwargs.get('walk'):
                    filter_ip = list()
                    for ip in sorted(jdata['resolutions'], key=methodcaller('get', 'last_resolved'), reverse=True):
                        if ip['ip_address'] not in filter_ip:
                            print '\n\n[+] Checking data for ip: {0}'.format(ip['ip_address'])
                            kwargs['value'] = ip['ip_address']
                            self.getIP(**kwargs)
                if jdata.get('subdomains') and ((kwargs.get('subdomains') or 'subdomains' in args) or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'subdomains': jdata['subdomains']})
                    else:
                        print '\n[+] Subdomains:'
                        print '\t{0}'.format('\n\t'.join(jdata['subdomains']))
                if jdata.get('domain_siblings') and ((kwargs.get('domain_siblings') or 'domain_siblings' in args) or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'domain_siblings': jdata['domain_siblings']})
                    else:
                        print '\n[+] Domain siblings:'
                        print '\t{0}'.format('\n\t'.join(jdata['domain_siblings']))
                if kwargs.get('dump') is True:
                    md5_hash = hashlib.md5(name).hexdigest()
                    jsondump(jdata, md5_hash)

            if kwargs.get('return_json'):
                return return_json

    def clusters(self,  *args, **kwargs):

        """
        VirusTotal has built its own in-house file similarity clustering functionality. At present,
        this clustering works only on PE files and is based on a very basic PE feature hash, which
        can be very often confused by certain compression and packing strategies. In other words,
        this clustering logic is no holly grail.

        This API offers a programmatic access to the clustering section of VirusTotal Intelligence:

        https://www.virustotal.com/intelligence/clustering/

        Please note that you must be logged in with a valid VirusTotal Community user with access
        to VirusTotal Intelligence in order to be able to view the clustering listing.

        All of the API responses are JSON objects, if no clusters were identified for the given
        time frame, this JSON will have a response_code property equal to 0, if there was some
        sort of error with your query this code will be set to -1, if your query succeded and
        file similarity clusters were found it will have a value of 1 and the rest of the JSON
        properties will contain the clustering information.
        """

        result, name = is_file(kwargs.get('value')[0])
        if result:
            jdata = load_file(name)
            dump = False
        else:
            url = self.base.format('file/clusters')
            if by_id:
                self.params['query'] = 'cluster:{0}'.format(kwargs.get('value')[0])
            else:
                self.params['date'] = name
            jdata, response = get_response(url, params=self.params)

            if kwargs.get('return_raw'):
                return jdata

        if jdata['response_code'] == 0 or jdata['response_code'] == -1:
            if jdata.get('verbose_msg'):
                print '\n[!] Status : {verb_msg}\n'.format(verb_msg=jdata['verbose_msg'])
            return
        if jdata.get('verbose_msg'):
            print '\nStatus : {verb_msg}'.format(verb_msg=jdata['verbose_msg'])
        if jdata.get('size_top200'):
            print '\n\tSize top 200   : {size_top200}'.format(size_top200=jdata['size_top200'])
        if jdata.get('num_clusters'):
            print '\tNum Clusters   : {num_clusters}'.format(num_clusters=jdata['num_clusters'])
        if jdata.get('num_candidates'):
            print '\tNum Candidates : {num_candidates}'.format(num_candidates=jdata['num_candidates'])
        if jdata.get('clusters'):
            plist = [[]]
            for line in jdata['clusters']:
                plist.append(
                    [line['label'], line['avg_positives'], line['id'], line['size']])

            pretty_print_special(
                plist,
                ['Label', 'AV Detections', 'Id', 'Size'],
                [40, 15, 80, 8],
                ['l', 'c', 'l', 'c'],
                kwargs.get('email_template')
            )

        if dump:
            jsondump(jdata, 'clusters_{0}'.format(name))

    def comment(self, *args,  **kwargs):
        """
        Add comment:
        The actual review, you can tag it using the "#" twitter-like syntax (e.g. #disinfection #zbot) and reference users using the "@" syntax (e.g. @VirusTotalTeam).

        Get comments:
        The application answers with the comments sorted in descending order according to their date. Please note that, for timeout reasons, the application will only
        answer back with at most 25 comments. If the answer contains less than 25 comments it means that there are no more comments for that item. On the other hand,
        if 25 comments were returned you should keep issuing further calls making use of the optional before parameter, this parameter should be fixed to the oldest
        (last in the list) comment's date token, exactly in the same way as returned by your previous API call (e.g. 20120404132340).
        """

        result, name = is_file(kwargs.get('value'))
        if result:
            jdata = load_file(name)
        else:
            value = kwargs.get('value')
            if value[0].startswith('http'):
                    result_hash = re.findall('[\w\d]{64}', value[0], re.I)
                    if result_hash:
                        value = result_hash[0]
                    else:
                        print '[-] Hash not found in url'
                        return

            self.params['resource'] = value
            if kwargs.get('action') == 'add':
                url = self.base.format('comments/put')
                self.params['comment'] = value[1]
                jdata, response = get_response(url, params=self.params, method="post")
                if kwargs['return_raw']:
                    return jdata
            elif kwargs.get('action') == 'get':
                url = self.base.format('comments/get')
                if value[0]:
                    self.params['before'] = kwargs.get('date')
                jdata, response = get_response(url, params=self.params)
                if kwargs.get('return_raw'):
                    return jdata
            else:
                print '\n[!] Support only get/add comments action \n'
                return
        if jdata['response_code'] == 0 or jdata['response_code'] == -1:
            if jdata.get('verbose_msg'):
                print '\n[!] Status : {verb_msg}\n'.format(verb_msg=jdata['verbose_msg'])
            sys.exit()
        if kwargs.get('action') == 'add':
            if jdata.get('verbose_msg'):
                print '\nStatus : {0}\n'.format(jdata['verbose_msg'])
        else:
            if jdata['response_code'] == 0:
                print '\n[!] This analysis doen\'t have any comment\n'
            else:
                if jdata.get('comments'):
                    for comment in jdata['comments']:

                        date_format = time.strptime(
                            comment['date'], '%Y%m%d%H%M%S')
                        date_formated = '{year}:{month}:{day} {hour}:{minuts}:{seconds}'.format(
                            year=date_format.tm_year,
                            month=date_format.tm_mon,
                            day=date_format.tm_mday,
                            hour=date_format.tm_hour,
                            minuts=date_format.tm_min,
                            seconds=date_format.tm_sec
                        )
                        if comment.get('date'):
                            print 'Date    : {0}'.format(date_formated)
                        if comment.get('comment'):
                            print 'Comment : {0}\n'.format(comment['comment'])

    def download(self, *args,  **kwargs):
        """
          About pcaps
          VirusTotal runs a distributed setup of Cuckoo sandbox machines that execute the files we receive.
          Execution is attempted only once, upon first submission to VirusTotal, and only Portable Executables
          under 10MB in size are ran. The execution of files is a best effort process, hence, there are no guarantees
          about a report being generated for a given file in our dataset.

          Files that are successfully executed may communicate with certain network resources, all this communication
          is recorded in a network traffic dump (pcap file). This API allows you to retrieve the network traffic dump
          generated during the file's execution.

          The md5/sha1/sha256 hash of the file whose network traffic dump you want to retrieve.
        """
        response = ''
        super_file_type = kwargs.get('download')

        if isinstance(kwargs.get('value'), list) and len(kwargs.get('value')) == 1:
            pass
        elif isinstance(kwargs.get('value'), basestring):
            kwargs['value'] = [kwargs.get('value')]

        for f_hash in kwargs.get('value'):
            f_hash = f_hash.strip()
            if f_hash != '':
                if f_hash.find(',') != -1:
                    file_type = f_hash.split(',')[-1]
                    f_hash = f_hash.split(',')[0]
                else:
                    file_type = super_file_type

                if f_hash.startswith('http'):
                        result_hash = re.findall('[\w\d]{64}', f_hash, re.I)
                        if result_hash:
                            f_hash = result_hash[0]
                        else:
                            print '[-] Hash not found in url'

                self.params['hash'] = f_hash
                print '\nTrying to download: {0}'.format(f_hash)

                if kwargs.get('api_type'):
                    if file_type not in ('file', 'pcap'):
                        print '\n[!] File_type must be pcap or file\n'
                        return
                    if file_type == 'pcap':
                        url = self.base.format('file/network-traffic')
                    elif file_type == 'file':
                        url = self.base.format('file/download')
                elif kwargs.get('intelligence'):
                    url = 'https://www.virustotal.com/intelligence/download/'
                else:
                    print '[-] You don\'t have permission for download'
                    return

                response = requests.get(url, params=self.params, stream=True)

                if response.status_code == 404:
                        print '\n[!] File not found\n'
                        return
                print '[?] If this is not the same hash, something wrong happend', hashlib.md5(response.content).hexdigest()
                if kwargs.get('name'):
                    name = kwargs.get('name')
                else:
                    name = '{hash}'.format(hash=f_hash)

                sample = ''
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk  and "VirusTotal - Free Online Virus, Malware and URL Scanner" not in response.content and '{"response_code": 0, "hash":' not in response.content: # filter out keep-alive new chunks
                        sample += chunk
                    else:
                        try:
                            json_data = response.json()
                            print '\n\t{0}: {1}'.format(json_data['verbose_msg'], f_hash)
                        except:
                            print '\tFile can\'t be downloaded: {0}'.format(f_hash)
                        return

                if kwargs.get('return_raw'):
                    return sample
                else:
                    dumped = open(name, 'wb')
                    dumped.write(sample)
                    dumped.close()
                    print '\tDownloaded to File -- {name}'.format(name=name)

    def distribution(self, *args,  **kwargs):
        """
        Note that scan items are not kept forever in the distribution queue, they are automatically removed after 6 hours counting from the time
        they were put in the queue. You have a 6 hours time frame to get an item from the queue. The timestamp property value is what you need to
        iterate through your queue using the before and after call parameters.
        """

        jdata = ''
        if kwargs.get('value'):
            result, name = is_file(kwargs.get('value'))
            if result:
                jdata = load_file(name)
                kwargs['dump'] = False
        else:
            if kwargs.get('before'):
                self.params['before'] = kwargs.get('before')
            if kwargs.get('after'):
                self.params['after'] = kwargs.get('after')
            if kwargs.get('limit'):
                self.params['limit'] = kwargs.get('limit')

            if kwargs.get('action') == 'file':
                if kwargs.get('reports'):
                    self.params['reports'] = str(kwargs.get('reports')).lower()
                url = self.base.format('file/distribution')

            elif kwargs.get('action') == 'url':
                if kwargs.get('allinfo'):
                    self.params['allinfo'] = '1'
                url = self.base.format('url/distribution')

            jdata, response = get_response(url, params=self.params)

            if kwargs.get('return_raw'):
                return jdata

        for vt_file in jdata:
                if vt_file.get('response_code') and (vt_file['response_code'] == 0 or vt_file['response_code'] == -1):
                    if jdata.get('verbose_msg'):
                        print '\n[!] Status : {verb_msg}\n'.format(verb_msg=vt_file['verbose_msg'])
                        return

                if kwargs.get('action') == 'file':
                    try:
                        if vt_file.get('name'):
                            print '\n\nName   : {name}'.format(name=vt_file['name'])
                    except UnicodeEncodeError:
                        print ''
                    if vt_file.get('md5'):
                        print 'MD5    : {md5}'.format(md5=vt_file['md5'])
                    if vt_file.get('sha1'):
                        print 'SHA1   : {sha1}'.format(sha1=vt_file['sha1'])
                    if vt_file.get('sha256'):
                        print 'SHA256 : {sha256}'.format(sha256=vt_file['sha256'])
                    if vt_file.get('filetype'):
                        print '\nType   : {filetype}'.format(filetype=vt_file['filetype'])
                    if vt_file.get('size'):
                        print 'Size   : {size}'.format(size=vt_file['size'])
                    if vt_file.get('source_id'):
                        print 'Source Id  : {source_id}'.format(source_id=vt_file['source_id'])
                    if vt_file.get('first_seen'):
                        print 'First Seen : {first_seen}'.format(first_seen=vt_file['first_seen'])
                    if vt_file.get('last_seen'):
                        print 'Last  Seen : {last_seen}'.format(last_seen=vt_file['last_seen'])
                    if vt_file.get('report'):
                        plist = [[]]
                        for key in vt_file['report']:
                            plist.append(
                              [key, 'True' if jdata[0]['report'][key][0] else 'False', jdata[0]['report'][key][1], jdata[0]['report'][key][2]]
                            )
                        pretty_print_special(
                            plist, ['Vendor name', 'Detection', 'Version', 'Update'], False, False, kwargs.get('email_template'))
                    if vt_file.get('link'):
                        print '\nLink : {link}'.format(link=vt_file['link'])

                elif kwargs.get('action') == 'url':
                    if vt_file.get('scan_date'):
                        print '\nScan Date : {scan_date}'.format(scan_date=vt_file['scan_date'])
                    if vt_file.get('last_seen'):
                        print 'Last Seen : {last_seen}'.format(last_seen=vt_file['last_seen'])
                    if vt_file.get('positives') and vt_file.get('total'):
                        print '\nDetections:\n\t{positives}/{total} Positives/Total\n'.format(positives=vt_file['positives'], total=vt_file['total'])
                    if vt_file.get('score'):
                        print 'Score     : {score}'.format(score=vt_file['score'])
                    if vt_file.get('url'):
                        print 'Url       : {url}'.format(url=vt_file['url'])
                    if vt_file.get('timestamp'):
                        print 'Timestamp : {timestamp}'.format(timestamp=vt_file['timestamp'])
                    if vt_file.get('additional_info'):
                        print '\n\nAdditional info:'
                        plist = [[]]

                        for key in vt_file['additional_info']:
                            if isinstance(vt_file['additional_info'][key], dict):
                                plist.append([key, ''.join(map(lambda key_temp:'{key_temp}:{value}\n'.format(
                                    key_temp=key_temp, value=vt_file['additional_info'][key][key_temp]), vt_file['additional_info'][key]))])
                            elif isinstance(vt_file['additional_info'][key], list):
                                plist.append(
                                    [key, '\n'.join(vt_file['additional_info'][key])])
                            else:
                                plist.append([key, vt_file['additional_info'][key]])
                        pretty_print_special(plist, ['Name', 'Value'], [40, 70], False, kwargs.get('email_template'))

                    if vt_file.get('scans'):
                        plist = [[]]
                        for key in vt_file['scans']:
                            plist.append([key, 'True' if vt_file['scans'][key]['detected'] else 'False', vt_file['scans'][key]['result']])

                        pretty_print_special(plist, ['Vendor name', 'Detection', 'Result'], False, False, kwargs.get('email_template'))
                    if vt_file.get('permalink'):
                        print '\nPermanent link : {link}\n'.format(link=vt_file['permalink'])

                if kwargs.get('dump'):
                    jsondump(jdata, 'distribution_{date}'.format(
                        date=time.strftime("%Y-%m-%d"))
                    )

    def behaviour(self, *args,  **kwargs):

        return_json = dict()
        result, name = is_file(kwargs.get('value')[0])

        if result:
            jdata = load_file(name)
            kwargs['dump'] = False

        else:
            self.params['hash'] = kwargs.get('value')[0]
            url = self.base.format('file/behaviour')

            jdata, response = get_response(url, params=self.params)

            if kwargs.get('return_raw'):
                return jdata

        if 'response_code' in jdata and (jdata['response_code'] == 0 or jdata['response_code'] == -1):
            if jdata.get('verbose_msg'):
                print '\n[!] Status : {verb_msg}\n'.format(verb_msg=jdata['verbose_msg'])
            return

        if jdata.get('info') and (kwargs.get('info') or 'info' in args):
            if kwargs.get('return_json'):
                return_json.update({'info': jdata['info']})
            else:
                print '\nInfo\n'

                pretty_print(
                    jdata['info'], ['started', 'ended', 'duration', 'version'])

        if (kwargs.get('behavior_network') or 'behavior_network' in args) or kwargs.get('verbose'):

            print '\nHTTP requests\n'

            if 'behavior-network' in jdata and 'http' in jdata.get('network'):
                if kwargs.get('return_json'):
                    return_json.update({'http':jdata['network']['http']})
                else:

                    for http in jdata['network']['http']:

                        if http.get('uri'):
                            print '\tURL        : {0}'.format(http['uri'])
                        if http.get('host'):
                            print '\tHost       : {0}'.format(http['host'])
                        # if http.get('port') : print 'port       : {0}'.format(http['port'])
                        # if http.get('path') : print 'path       :
                        # {0}'.format(http['path'])
                        if http.get('method'):
                            print '\tMethod     : {0}'.format(http['method'])
                        if http.get('user-agent'):
                            print '\tUser-agent : {0}'.format(http['user-agent'])
                        # if http.get('version') : print 'version    : {0}'.format(http['version'])
                        # if http.get('data')    : print 'data       : {0}'.format(http['data'].replace('\r\n\r\n', '\n\t').replace('\r\n','\n\t\t'))
                        if http.get('body'):
                            print '\tbody hex encoded:\n\t  {}\n'.format(http['body'].encode('hex'))

            if jdata['network']['hosts']:
                if kwargs.get('return_json'):
                    return_json.update({'hosts': jdata['network']['hosts']})
                else:
                    pretty_print(jdata['network']['hosts'], ['hosts'], False, False, kwargs.get('email_template'))

            if jdata['network']['dns']:
                if kwargs.get('return_json'):
                    return_json.update({'dns': jdata['network']['dns']})
                else:
                    print '\nDNS requests\n'
                    pretty_print(jdata['network']['dns'],   ['ip', 'hostname'], False, False, kwargs.get('email_template'))

            if jdata['network']['tcp']:
                if kwargs.get('return_json'):
                    return_json.update({'tcp': jdata['network']['tcp']})
                else:
                    print '\nTCP Connections'

                    unique = []

                    for block in jdata['network']['tcp']:
                        if not [block['src'],  block['dst'], block['sport'], block['dport']] in unique:
                            unique.append(
                                [block['src'], block['dst'], block['sport'], block['dport']]
                            )
                    pretty_print_special(unique,   ['src', 'dst', 'sport', 'dport'], False, False, kwargs.get('email_template'))
                    del unique

            if jdata['network']['udp']:
                if kwargs.get('return_json'):
                    return_json.update({'udp': jdata['network']['udp']})
                else:
                    print '\nUDP Connections'
                    unique = []
                    for block in jdata['network']['udp']:
                        if not [block['src'],  block['dst'], block['sport'], block['dport']] in unique:
                            unique.append(
                                [block['src'], block['dst'], block['sport'], block['dport']]
                                )
                    pretty_print_special(
                      unique,
                      ['src', 'dst', 'sport', 'dport'],
                      False, False,
                      kwargs.get('email_template')
                      )
                    del unique

        if (kwargs.get('behavior_process') or 'behavior_process' in args) or kwargs.get('verbose'):
            print '\n[+] Behavior'
            print '\n[+] Processes'
            if kwargs.get('return_json'):
                    return_json.update({'processes': jdata['behavior']['processes']})
            else:
                for process_id in jdata['behavior']['processes']:

                    plist = []

                    if process_id.get('parent_id'):
                        print '\nParent  Id : {0}'.format(process_id['parent_id'])
                    if process_id.get('process_id'):
                        print 'Process Id : {0}'.format(process_id['process_id'])

                    if process_id.get('first_seen'):

                        date_format = time.strptime(
                            process_id['first_seen'][:14], '%Y%m%d%H%M%S')
                        date_formated = '{year}:{month}:{day} {hour}:{minuts}:{seconds}'.format(year=date_format.tm_year, month=date_format.tm_mon,
                            day=date_format.tm_mday, hour=date_format.tm_hour,
                            minuts=date_format.tm_min, seconds=date_format.tm_sec)
                        print 'First Seen : {0}'.format(date_formated)

                    if process_id.get('process_name'):
                        print '\nProcess Name : {0}'.format(process_id['process_name'])

                    if process_id.get('calls'):
                        for process_part in process_id['calls']:
                            plist = [[]]
                            for key in process_part:
                                if isinstance(process_part[key], list):
                                    if process_part[key] != [] and isinstance(process_part[key][0], dict):
                                        temp_list = []
                                        for part in process_part[key]:
                                            temp_list.append('\n'.join(map(lambda key_temp: '{key_temp}:{value}\n'.format(
                                                key_temp=key_temp, value=part[key_temp]), part.keys())))
                                        plist.append([key, ''.join(temp_list)])
                                        del temp_list
                                    else:
                                        plist.append(
                                            [key, '\n'.join(process_part[key])])

                                elif isinstance(process_part[key], dict):
                                    temp_list = []
                                    for part in process_part[key]:
                                        temp_list += map(lambda key_temp: '{key_temp}:{value}\n'.format(
                                            key_temp=key_temp, value=part[key_temp]), part.keys()
                                        )
                                    plist.append([key, ''.join(temp_list)])
                                    del temp_list
                                else:
                                    plist.append([key, process_part[key]])
                            pretty_print_special(
                                plist, ['Name', 'Value'], [10, 50], False, kwargs.get('email_template'))
                            del plist

                        print '\n' + '=' * 20 + ' FIN ' + '=' * 20

                print '\n[+] Process Tree\n'
                if jdata.get('behavior') and jdata['behavior'].get('processtree'):
                    for tree in jdata['behavior']['processtree']:
                        for key in tree.keys():
                            print '\t{key}:{value}'.format(key=key, value=tree[key])
                    print '\n'

        if (kwargs.get('behavior_summary') or 'behavior_summary' in args) or kwargs.get('verbose'):
            if jdata.get('behavior') and jdata['behavior'].get('summary'):
                if jdata['behavior']['summary'].get('files'):
                    if kwargs.get('return_json'):
                            return_json.update({'files':  jdata['behavior']['summary']['files']})
                    else:
                        if jdata['behavior']['summary']['files']:
                            print '\n[+] Opened files\n'
                            pretty_print(
                                sorted(jdata['behavior']['summary']['files']), ['files'], [100], False, kwargs.get('email_template'))

                if jdata['behavior']['summary'].get('keys'):
                    if kwargs.get('return_json'):
                        return_json.update({'keys':  jdata['behavior']['summary']['keys']})
                    else:
                        print '\n[+] Set keys\n'
                        pretty_print(
                            sorted(jdata['behavior']['summary']['keys']), ['keys'], [100], False, kwargs.get('email_template'))

                if jdata['behavior']['summary'].get('mutexes') is not None and jdata['behavior']['summary']['mutexes'] != [u'(null)'] and jdata['behavior']['summary']['mutexes']:
                    if kwargs.get('return_json'):
                        return_json.update({'mutex':  jdata['behavior']['summary']['mutex']})
                    else:
                        print '\n[+] Created mutexes\n'
                        pretty_print(
                            sorted(jdata['behavior']['summary']['mutexes']), ['mutexes'], [100],
                            False, kwargs.get('email_template')
                            )

        if kwargs.get('dump') is True:
            md5_hash = hashlib.md5(name).hexdigest()
            jsondump(jdata, md5_hash)

        if kwargs.get('return_json'):
            return return_json

    def print_results(self, jdata, *args,  **kwargs):

        if kwargs.get('samples') or 'samples' in args:
              kwargs['detected_downloaded_samples'] = \
              kwargs['undetected_downloaded_samples'] = \
              kwargs['detected_referrer_samples'] = \
              kwargs['undetected_referrer_samples'] = \
              kwargs['detected_communicated'] = \
              kwargs['undetected_communicated'] = True

        return_json = dict()
        if jdata.get('detected_downloaded_samples') and ((kwargs.get('detected_downloaded_samples') or 'detected_downloaded_samples' in args) or kwargs.get('verbose')):
            if kwargs.get('return_json'):
                return_json.update({'detected_downloaded_samples': jdata['detected_downloaded_samples']})
            else:
                print '\n[+] Latest detected files that were downloaded from this domain/ip\n'
                pretty_print(sorted(jdata['detected_downloaded_samples'], key=methodcaller('get', 'date'), reverse=True), [
                             'positives', 'total', 'date', 'sha256'], [15, 10, 20, 70], ['c', 'c', 'c', 'c'], kwargs.get('email_template'))

        if jdata.get('undetected_downloaded_samples') and ((kwargs.get('undetected_downloaded_samples') or 'undetected_downloaded_samples' in args) or kwargs.get('verbose')):
            if kwargs.get('return_json'):
                return_json.update({'undetected_downloaded_samples': jdata['undetected_downloaded_samples']})
            else:
                print '\n[+] Latest undetected files that were downloaded from this domain/ip\n'
                pretty_print(sorted(jdata['undetected_downloaded_samples'], key=methodcaller('get', 'date'), reverse=True), [
                             'positives', 'total', 'date', 'sha256'], [15, 10, 20, 70], ['c', 'c', 'c', 'c'], kwargs.get('email_template'))

        if jdata.get('detected_communicating_samples') and ((kwargs.get('detected_communicated') or 'detected_communicated' in args) or kwargs.get('verbose')):
            if kwargs.get('return_json'):
                return_json.update({'detected_communicating_samples': jdata['detected_communicating_samples']})
            else:
                print '\n[+] Latest detected files that communicate with this domain/ip\n'
                pretty_print(sorted(jdata['detected_communicating_samples'], key=methodcaller('get', 'scan_date'), reverse=True), [
                             'positives', 'total', 'date', 'sha256'], [15, 10, 20, 70], ['c', 'c', 'c', 'c'], kwargs.get('email_template'))

        if jdata.get('undetected_communicating_samples') and ((kwargs.get('undetected_communicating_samples') or 'undetected_communicating_samples' in args) or kwargs.get('verbose')):
            if kwargs.get('return_json'):
                return_json.update({'undetected_communicating_samples': jdata['undetected_communicating_samples']})
            else:
                print '\n[+] Latest undetected files that communicate with this domain/ip\n'
                pretty_print(sorted(jdata['undetected_communicating_samples'], key=methodcaller('get', 'date'), reverse=True), [
                             'positives', 'total', 'date', 'sha256'], [15, 10, 20, 70], ['c', 'c', 'c', 'c'], kwargs.get('email_template'))

        if jdata.get('detected_referrer_samples') and ((kwargs.get('detected_referrer_samples') or 'detected_referrer_samples' in args) or kwargs.get('verbose')):
            if kwargs.get('return_json'):
                return_json.update({'detected_referrer_samples': jdata['detected_referrer_samples']})
            else:
                print '\n[+] Latest detected referrer files\n'
                pretty_print(sorted(jdata['detected_referrer_samples']), [
                             'positives', 'total',  'sha256'], [15, 10, 70], ['c', 'c', 'c'], kwargs.get('email_template'))

        if jdata.get('undetected_referrer_samples') and ((kwargs.get('undetected_referrer_samples') or 'undetected_referrer_samples' in args) or kwargs.get('verbose')):
            if kwargs.get('return_json'):
                return_json.update({'undetected_referrer_samples': jdata['undetected_referrer_samples']})
            else:
                print '\n[+] Latest undetected referrer files\n'
                pretty_print(sorted(jdata['undetected_referrer_samples']), [
                             'positives', 'total',  'sha256'], [15, 10, 70], ['c', 'c', 'c'], kwargs.get('email_template'))

        if jdata.get('detected_urls') and ((kwargs.get('detected_urls') or 'detected_urls' in args) or kwargs.get('verbose')):
            if kwargs.get('return_json'):
                return_json.update({'detected_urls':  jdata['detected_urls']})
            else:
                url_size = max(
                    map(lambda url: len(url['url']), jdata['detected_urls']))

                if url_size > 80:
                    url_size = 80

                print '\n[+] Latest detected URLs\n'
                pretty_print(sorted(jdata['detected_urls'], key=methodcaller('get', 'scan_date'), reverse=True), [
                             'positives', 'total', 'scan_date', 'url'], [9, 5, 20, url_size], ['c', 'c', 'c', 'l'], kwargs.get('email_template'))

        if kwargs.get('return_json'):
            return return_json

def read_conf(config_file = '~/.vtapi'):


      help = '''
                      No API key provided or cannot read ~ /.vtapi. Specify an API key in vt.py or in ~ /.vtapi.
                      Format:
                          [vt]
                          apikey=your-apikey-here
                          type=public #private if you have private api
                          intelligence=False # True if you have access

                      For more information check:
                          https://github.com/doomedraven/VirusTotalApi
                      '''
      apikey = None
      api_type = False
      intelligence = False

      if not config_file:
             for conf in ('.vtapi', 'vtapi.conf'):
                if os.path.exists(os.path.expanduser(conf)):
                  config_file = conf
                  break
      try:
        confpath = os.path.expanduser(config_file)
        if os.path.exists(confpath):
            config = ConfigParser.RawConfigParser()
            config.read(confpath)
            if config.has_option('vt', 'apikey'):
                apikey = config.get('vt', 'apikey')
                if apikey is None:
                    sys.exit(help)
                if config.has_option('vt', 'type'):
                   api_type = config.get('vt', 'type')

                   if  api_type.lower() == 'private':
                        api_type = True
                   else:
                        api_type = False

                if config.has_option('vt', 'intelligence'):
                    intelligence = config.get('vt', 'intelligence')

                if config.has_option('vt', 'engines'):
                    engines = config.get('vt', 'engines')
                else:
                    engines = []
        else:
            sys.exit('\nFile {0} don\'t exists\n'.format(confpath))

      except Exception:
          sys.exit(help)

      return apikey, api_type, intelligence, engines


def main():

    apikey, api_type, intelligence, engines = read_conf()

    opt = argparse.ArgumentParser(
        'value', description='Scan/Search/ReScan/JSON parse')
    opt.add_argument('-fi', '--file-info', action='store_true',
        help='Get PE file info, all data extracted offline, for work you need have installed PEUTILS library')
    opt.add_argument('-udb', '--userdb', action='store',
        help='Path to your userdb file, works with --file-info option only')
    opt.add_argument('value', nargs='*', help='Enter the Hash, Path to File(s) or Url(s)')
    opt.add_argument('-fs', '--file-search', action='store_true',
        help='File(s) search, this option, don\'t upload file to VirusTotal, just search by hash, support linux name wildcard, example: /home/user/*malware*, if file was scanned, you will see scan info, for full scan report use verbose mode, and dump if you want save already scanned samples')
    opt.add_argument('-f',  '--file-scan', action='store_true', dest='files',
        help='File(s) scan, support linux name wildcard, example: /home/user/*malware*, if file was scanned, you will see scan info, for full scan report use verbose mode, and dump if you want save already scanned samples')
    opt.add_argument('-u',  '--url-scan', action='store_true',
        help='Url scan, support space separated list, Max 4 urls (or 25 if you have private api), but you can provide more urls, for example with public api,  5 url - this will do 2 requests first with 4 url and other one with only 1, or you can specify file filename must be urls_for_scan.txt, and one url per line')
    opt.add_argument('-ur', '--url-report', action='store_true',
        help='Url(s) report, support space separated list, Max 4 (or 25 if you have private api) urls, you can use --url-report --url-scan options for analysing url(s) if they are not in VT data base, read previev description about more then max limits or file with urls')
    opt.add_argument('-d', '--domain-info',   action='store_true', dest='domain',
        help='Retrieves a report on a given domain (PRIVATE API ONLY! including the information recorded by VirusTotal\'s Passive DNS infrastructure)')
    opt.add_argument('-i', '--ip-info', action='store_true', dest='ip',
        help='A valid IPv4 address in dotted quad notation, for the time being only IPv4 addresses are supported.')
    opt.add_argument('-w', '--walk', action='store_true', default=False,
        help='Work with domain-info, will walk throuth all detected ips and get information, can be provided ip parameters to get only specific information')
    opt.add_argument('-s', '--search', action='store_true',
        help='A md5/sha1/sha256 hash for which you want to retrieve the most recent report. You may also specify a scan_id (sha256-timestamp as returned by the scan API) to access a specific report. You can also specify a space separated list made up of a combination of hashes and scan_ids Public API up to 4 items/Private API up to 25 items, this allows you to perform a batch request with one single call.')
    opt.add_argument('-si', '--search-intelligence', action='store_true',
        help='Search query, help can be found here - https://www.virustotal.com/intelligence/help/')
    opt.add_argument('-et', '--email-template', action='store_true',
        help='Table format template for email')
    if api_type:
        allinfo_opt = opt.add_argument_group('All information related')
        allinfo_opt.add_argument('-rai', '--report-all-info', action='store_true',
            help='If specified and set to one, the call will return additional info, other than the antivirus results, on the file being queried. This additional info includes the output of several tools acting on the file (PDFiD, ExifTool, sigcheck, TrID, etc.), metadata regarding VirusTotal submissions (number of unique sources that have sent the file in the past, first seen date, last seen date, etc.), and the output of in-house technologies such as a behavioural sandbox.')
        allinfo_opt.add_argument('-itu', '--ITW-urls', action='store_true',
            help='In the wild urls')
        allinfo_opt.add_argument('-cw', '--compressedview', action='store_true',
            help='Contains information about extensions, file_types, tags, lowest and highest datetime, num children detected, type, uncompressed_size, vhash, childrens')
        allinfo_opt.add_argument('-dep', '--detailed-email-parents', action='store_true',
            help='Contains information about emails, as Subject, sender, receiver(s), full email, and email hash to download it')
        allinfo_opt.add_argument('-sn', '--submission_names', action='store_true',
            help='Get all submission name')

    opt.add_argument('-ac', '--add-comment', action='store_true',
        help='The actual review, you can tag it using the "#" twitter-like syntax (e.g. #disinfection #zbot) and reference users using the "@" syntax (e.g. @VirusTotalTeam). supported hashes MD5/SHA1/SHA256')
    opt.add_argument('-gc', '--get-comments', action='store_true',
        help='Either a md5/sha1/sha256 hash of the file or the URL itself you want to retrieve')
    if api_type:
        opt.add_argument('--get-comments-before', action='store', dest='date', default=False,
            help='A datetime token that allows you to iterate over all comments on a specific item whenever it has been commented on more than 25 times. Token format 20120725170000 or 2012-07-25 17 00 00 or 2012-07-25 17:00:00')
    opt.add_argument('-v', '--verbose', action='store_true',
        dest='verbose', help='Turn on verbosity of VT reports')
    opt.add_argument('-j', '--dump',    action='store_true',
        help='Dumps the full VT report to file (VTDL{md5}.json), if you (re)scan many files/urls, their json data will be dumped to separetad files')
    opt.add_argument('--csv', action='store_true', default = False,
        help='Dumps the AV\'s detections to file (VTDL{scan_id}.csv)')
    opt.add_argument('-rr', '--return-raw', action='store_true', default = False,
        help='Return raw json, in case if used as library and want parse in other way')
    opt.add_argument('-rj', '--return-json', action='store_true', default = False,
        help='Return json with parts activated, for example -p for pasive dns, etc')
    opt.add_argument('-V', '--version', action='store_true', default = False,
        help='Show version and exit')
    rescan = opt.add_argument_group('Rescan options')
    rescan.add_argument('-r', '--rescan', action='store_true',
        help='Allows you to rescan files in VirusTotal\'s file store without having to resubmit them, thus saving bandwidth, support space separated list, MAX 25 hashes, can be local files, hashes will be generated on the fly, support linux wildmask')
    if api_type:
        rescan.add_argument('--delete',  action='store_true',
            help='A md5/sha1/sha256 hash for which you want to delete the scheduled scan')
        rescan.add_argument('--date', action='store', dest='date',
            help='A Date in one of this formats (example: 20120725170000 or 2012-07-25 17 00 00 or 2012-07-25 17:00:00) in which the rescan should be performed. If not specified the rescan will be performed immediately.')
        rescan.add_argument('--period', action='store',
            help='Period in days in which the file should be rescanned. If this argument is provided the file will be rescanned periodically every period days, if not, the rescan is performed once and not repated again.')
        rescan.add_argument('--repeat', action='store',
            help='Used in conjunction with period to specify the number of times the file should be rescanned. If this argument is provided the file will be rescanned the given amount of times, if not, the file will be rescanned indefinitely.')
    if api_type:
        scan_rescan = opt.add_argument_group('File scan/Rescan shared options')
        scan_rescan.add_argument('--notify-url', action='store',
            help='An URL where a POST notification should be sent when the scan finishes.')
        scan_rescan.add_argument('--notify-changes-only', action='store_true',
            help='Used in conjunction with --notify-url. Indicates if POST notifications should be sent only if the scan results differ from the previous one.')

    domain_opt = opt.add_argument_group(
        'Domain/IP shared verbose mode options, by default just show resolved IPs/Passive DNS')
    domain_opt.add_argument('-wh',  '--whois', action='store_true', default=False,
        help='Whois data')
    domain_opt.add_argument('-wht',  '--whois-timestamp', action='store_true', default=False,
        help='Whois timestamp')
    domain_opt.add_argument('-pdn',  '--passive-dns', action='store_true', default=False,
        help='Passive DNS resolves')
    domain_opt.add_argument('--asn', action='store_true', default=False,
        help='ASN number')
    domain_opt.add_argument('-aso', '--as-owner', action='store_true', default=False,
        help='AS details')
    domain_opt.add_argument('--country', action='store_true', default=False,
        help='Country')
    domain_opt.add_argument('--subdomains', action='store_true', default=False,
        help='Subdomains')
    domain_opt.add_argument('--domain-siblings', action='store_true', default=False,
        help='Domain siblings')
    domain_opt.add_argument('-cat','--categories', action='store_true', default=False,
        help='Categories')
    domain_opt.add_argument('-alc', '--alexa-cat', action='store_true', default=False,
        help='Alexa category')
    domain_opt.add_argument('-alk', '--alexa-rank', action='store_true', default=False,
        help='Alexa rank')
    domain_opt.add_argument('-opi', '--opera-info', action='store_true', default=False,
        help='Opera info')
    domain_opt.add_argument('--drweb-cat', action='store_true', default=False,
        help='Dr.Web Category')
    domain_opt.add_argument('-adi', '--alexa-domain-info', action='store_true',
        default=False, help='Just Domain option: Show Alexa domain info')
    domain_opt.add_argument('-wdi', '--wot-domain-info', action='store_true',
        default=False, help='Just Domain option: Show WOT domain info')
    domain_opt.add_argument('-tm',  '--trendmicro', action='store_true',
        default=False, help='Just Domain option: Show TrendMicro category info')
    domain_opt.add_argument('-wt',  '--websense-threatseeker', action='store_true',
        default=False, help='Just Domain option: Show Websense ThreatSeeker category')
    domain_opt.add_argument('-bd',  '--bitdefender', action='store_true',
        default=False, help='Just Domain option: Show BitDefender category')
    domain_opt.add_argument('-wd',  '--webutation-domain', action='store_true',
        default=False, help='Just Domain option: Show Webutation domain info')
    domain_opt.add_argument('-du',  '--detected-urls', action='store_true',
        default=False, help='Just Domain option: Show latest detected URLs')
    domain_opt.add_argument('--pcaps', action='store_true',
        default=False, help='Just Domain option: Show all pcaps hashes')
    domain_opt.add_argument('--samples', action='store_true',
        help='Will activate -dds -uds -dc -uc -drs -urs')
    domain_opt.add_argument('-dds', '--detected-downloaded-samples',   action='store_true', default=False,
        help='Domain/Ip options: Show latest detected files that were downloaded from this ip')
    domain_opt.add_argument('-uds', '--undetected-downloaded-samples', action='store_true', default=False,
        help='Domain/Ip options: Show latest undetected files that were downloaded from this domain/ip')
    domain_opt.add_argument('-dc',  '--detected-communicated', action='store_true', default=False,
        help='Domain/Ip Show latest detected files that communicate with this domain/ip')
    domain_opt.add_argument('-uc',  '--undetected-communicated', action='store_true', default=False,
        help='Domain/Ip Show latest undetected files that communicate with this domain/ip')
    domain_opt.add_argument('-drs', '--detected-referrer-samples', action='store_true', default=False,
        help='Undetected referrer samples')
    domain_opt.add_argument('-urs', '--undetected-referrer-samples', action='store_true', default=False,
        help='Undetected referrer samples')

    if api_type:
        behaviour = opt.add_argument_group('Behaviour options')
        behaviour.add_argument('--behaviour', action='store_true',  help='The md5/sha1/sha256 hash of the file whose dynamic behavioural report you want to retrieve.\
            VirusTotal runs a distributed setup of Cuckoo sandbox machines that execute the files we receive. Execution is attempted only once, upon\
            first submission to VirusTotal, and only Portable Executables under 10MB in size are ran. The execution of files is a best effort process,\
            hence, there are no guarantees about a report being generated for a given file in our dataset. a file did indeed produce a behavioural report,\
            a summary of it can be obtained by using the file scan lookup call providing the additional HTTP POST parameter allinfo=1. The summary will\
            appear under the behaviour-v1 property of the additional_info field in the JSON report.This API allows you to retrieve the full JSON report\
            of the file\'s execution as outputted by the Cuckoo JSON report encoder.')
        behaviour.add_argument('-bn', '--behavior-network', action='store_true', help='Show network activity')
        behaviour.add_argument('-bp', '--behavior-process', action='store_true', help='Show processes')
        behaviour.add_argument('-bs', '--behavior-summary', action='store_true', help='Show summary')

    if api_type or intelligence:
        downloads = opt.add_argument_group('Download options')
        downloads.add_argument('-dl', '--download',  dest='download', action='store_const', const='file', default=False,
            help='The md5/sha1/sha256 hash of the file you want to download or txt file with hashes, or hash and type, one by line, for example: hash,pcap or only hash. Will save with hash as name')
        downloads.add_argument('-nm', '--name',  action='store', default=False,
            help='Name with which file will saved when download it')

    if api_type:
        more_private = opt.add_argument_group('Additional options')
        more_private.add_argument('--pcap', dest='download', action='store_const', const='pcap', default=False,
            help='The md5/sha1/sha256 hash of the file whose network traffic dump you want to retrieve. Will save as VTDL_hash.pcap')
        more_private.add_argument('--clusters', action='store_true',
            help='A specific day for which we want to access the clustering details, example: 2013-09-10')
        # more_private.add_argument('--search-by-cluster-id', action='store_true', help=' the id property of each cluster allows users to list files contained in the given cluster, example: vhash 0740361d051)z1e3z 2013-09-10')
        more_private.add_argument('--distribution-files', action='store_true',
            help='Timestamps are just integer numbers where higher values mean more recent files. Both before and after parameters are optional, if they are not provided the oldest files in the queue are returned in timestamp ascending order.')
        more_private.add_argument('--distribution-urls', action='store_true',
            help='Timestamps are just integer numbers where higher values mean more recent urls. Both before and after parameters are optional, if they are not provided the oldest urls in the queue are returned in timestamp ascending order.')
    if api_type:
        dist = opt.add_argument_group('Distribution options')
        dist.add_argument('--before', action='store',
            help='File/Url option. Retrieve files/urls received before the given timestamp, in timestamp descending order.')
        dist.add_argument('--after', action='store',
            help='File/Url option. Retrieve files/urls received after the given timestamp, in timestamp ascending order.')
        dist.add_argument('--reports', action='store_true', default=False,
            help='Include the files\' antivirus results in the response. Possible values are \'true\' or \'false\' (default value is \'false\').')
        dist.add_argument('--limit', action='store',
            help='File/Url option. Retrieve limit file items at most (default: 1000).')
        dist.add_argument('--allinfo', action='store_true',
            help='will include the results for each particular URL scan (in exactly the same format as the URL scan retrieving API). If the parameter is not specified, each item returned will onlycontain the scanned URL and its detection ratio.')
        dist.add_argument('--massive-download', action='store_true',
            default=False, help='Show information how to get massive download work')

    options = opt.parse_args()

    if options.version:
        print 'Version:', __version__
        sys.exit()

    options = vars(options)
    options.update({'intelligence': intelligence})
    options.update({'api_type': api_type})
    options.update({'engines': engines})
    vt = vtAPI(apikey)

    if options.get('date'):
        options['date'] = options['date'].replace( '-', '').replace(':', '').replace(' ', '')

    if options.get('files'):
        options.update({'scan': True})
        vt.fileScan(**options)

    elif options['file_info']:
        vt.fileInfo(**options)

    elif options['file_search']:
        options.update({'scan': False})
        vt.fileScan(**options)

    elif options.get('url_scan') and not options.get('url_report'):
        options.update({'key': 'scan'})
        vt.url_scan_and_report(**options)

    elif options.get('url_report'):
        options.update({'action': 0})

        if options['url_scan']:
            options.update({'action': 1})

        options.update({'key': 'report'})
        vt.url_scan_and_report(**options)

    elif options.get('rescan'):

        if options['date']:

            if len(options['date']) < 14:
                print '\n[!] Date format is: 20120725170000 or 2012-07-25 17 00 00 or 2012-07-25 17:00:00\n'
                sys.exit()

            now = time.strftime("%Y:%m:%d %H:%M:%S")
            if now >= relativedelta(options['date']):
                print '\n[!] Date must be greater then today\n'
                sys.exit()

        vt.rescan(**options)

    elif options.get('domain') or options.get('ip'):

        if options['value'][0].startswith('http'):
            options['value'][0] = urlparse(options['value'][0]).netloc

        if match('\w{1,3}\.\w{1,3}\.\w{1,3}\.\w{1,3}', options['value'][0]):

            #paranoic check :)
            try:
                valid=len(filter(lambda(item):0 <=int(item) <=255, options['value'][0].strip().split("."))) == 4
            except ValueError:
                valid = False

            if valid:
                vt.getIP(**options)

            else:
                vt.getDomain(**options)
        else:
                vt.getDomain(**options)

    elif options.get('report_all_info'):
        options.update({'allinfo': 1})
        vt.getReport(**options)

    elif (options.get('search') or options.get('search_intelligence')) and not options['domain'] and not options['ip'] and not options['url_scan'] and not options['url_report']:
        options.update({'allinfo': 0})
        vt.getReport(**options)

    elif options.get('download'):
        vt.download(**options)

    elif options.get('behaviour'):
        vt.behaviour(**options)

    elif options.get('distribution_files'):
        options.update({'action': 'file'})
        vt.distribution(**options)

    elif options.get('distribution_urls'):
        options.update({'action': 'url'})
        vt.distribution(**options)

    elif options.get('massive_download'):
        print """
                Check download help, if need more advanced download, give me a touch or check this:
                https://www.virustotal.com/es/documentation/scripts/vtfiles.py
              """
        sys.exit()

    elif options.get('add_comment') and len(options.value) == 2:
        options.update({'action': 'add'})
        vt.comment(**options)

    elif options.get('get_comments'):
        options.update({'action': 'get'})
        vt.comment(**options)

    elif options.get('clusters'):
        vt.clusters(**options)

    # elif options.search_by_cluster_id:
    #    vt.clusters(options.value, options.dump, True)

    else:
        sys.exit(opt.print_help())


if __name__ == '__main__':
    main()
