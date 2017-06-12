#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

# Full VT APIv2 functions added by Andriy Brukhovetskyy
# doomedraven -  Twitter : @d00m3dr4v3n
# No Licence or warranty expressed or implied, use however you wish!
# For more information look at:
#
# https://www.virustotal.com/en/documentation/public-api
# https://www.virustotal.com/en/documentation/private-api
# https://www.virustotal.com/intelligence/help/

__author__ = 'Andriy Brukhovetskyy - DoomedRaven'
__version__ = '2.2.12'
__license__ = 'For fun :)'

import os
import re
import ast
import sys
import csv
import time
import json
import email
import base64
import hashlib
import argparse
import requests
import threading
import ConfigParser
from glob import glob
from re import match
from collections import deque
from urlparse import urlparse
from operator import methodcaller
from datetime import datetime
from dateutil.relativedelta import relativedelta

#print mysql style tables
import thirdpart.texttable.texttable as tt
#parse OUTLOOK .msg
try:
    from thirdpart.outlook_parser import OUTLOOK
    OUTLOOK_prsr = True
except ImportError:
    OUTLOOK_prsr = False

try:
    import urllib3
    urllib3.disable_warnings()
    #from requests.packages.urllib3.exceptions import InsecureRequestWarning, InsecurePlatformWarning
    #requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    #requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
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

req_timeout = 60
re_compile_orig = re.compile

class PRINTER(object):

    def print_key(self,  key, indent='\n', separator='[+]'):
        try:
            print '{0}{1} {2}'.format(indent, separator, key.capitalize().replace('_', ' ').replace('-', ' '))
        except:
            pass

    # key:value
    def simple_print(self, block, keys):
        for key in keys:
            if block.get(key) and block[key]:
                self.print_key(key)
                if isinstance(block.get(key), list):
                    print '\t', '\n\t'.join(block.get(key))
                else:
                    print '\t', block.get(key)

    # key:[]
    def list_print(self, block, keys):
        for key in keys:
            if block.get(key) and block[key]:
                self.print_key(key)
                print '\t', '\n\t'.join(block.get(key))

    # key:{subkey:[]}
    def dict_list_print(self, block, keys):
      for key in keys:
        if block.get(key) and block[key]:
            self.print_key(key)
            if isinstance(block.get(key), list):
                for sub_list in block.get(key):
                  if isinstance(sub_list, list):
                      print '\n\t', '\n\t'.join([str(part) for part in sub_list])
                  elif isinstance(sub_list, dict):
                      for sub_key, sub_value in sub_list.items():
                          print '\t', sub_key, sub_value
                      print '\n'

            elif isinstance(block.get(key), dict):
                for sub_key in block.get(key, []):
                    if block[key].get(sub_key, {}):
                        self.print_key(sub_key)
                        for ssub_dict in block[key].get(sub_key, {}):
                          print '\n'
                          for ssub_key, ssub_value in ssub_dict.items():
                              print '\t', ssub_key, ssub_value

    # key:{subkey:{}}
    def dict_print(self, block, keys):
        for key in keys:
            if block.get(key, []):
                self.print_key(key)
                for sub_key, value in block[key].items():
                    if isinstance(value, list):
                        print '\n', sub_key, '\n\t' ,'\n\t'.join(value)
                    else:
                        print '\n', sub_key, '\n\t' ,value

def private_api_access_error():
    print '\n[!] You don\'t have permission for this operation, Looks like you trying to access to PRIVATE API functions\n'
    sys.exit()

def get_sizes(dictionary):
    key_s = 20
    value_s = 20

    key_s = max(map(lambda key: len(key), dictionary.keys()))
    value_s = max(map(lambda value: len(value), dictionary.values()))

    if value_s > 80:
        value_s = 80

    return key_s, value_s

def get_adequate_table_sizes(scans, short=False, short_list=False):

    av_size_f = 14
    result_f = 6
    version_f = 9

    if scans:

        # Result len
        if short:
            av_size = max(map(lambda engine:
                    len(engine) if engine is not None and engine in short_list else 0, scans)
            )
            result = max(map(lambda engine: len(scans[engine]['result']) if scans[engine].has_key(
                'result') and scans[engine]['result'] is not None and engine in short_list else 0, scans)
            )
            version = max(map(lambda engine: len(scans[engine]['version']) if scans[engine].has_key(
                'version') and scans[engine]['version'] is not None and engine in short_list else 0, scans)
            )

        else:
            av_size = max(map(lambda engine: len(engine) if engine is not None else 0, scans))
            result = max(map(lambda engine: len(scans[engine]['result']) if scans[
                engine].has_key('result') and scans[engine]['result'] is not None else 0, scans)
            )
            version = max(map(lambda engine: len(scans[engine]['version']) if scans[
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

    try:
        tab = tt.Texttable()

        if email:
            tab.set_deco(tt.Texttable.HEADER)

        if isinstance(block, list):
            plist = [headers]

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

    except:
        print 'Report me plz'
        print sys.exc_info()

def pretty_print_special(rows, headers, sizes=False, align=False, email=False):

    try:
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

    except:
        print 'Report me plz'
        print sys.exc_info()

def is_file(value):

    # check if is file and if file is json, avoit recognize input file as dumped json

    try:
        if isinstance(value, list):
            if os.path.isfile(value[0]) and value[0].endswith('.json'):
                return True, value[0]

            else:
                return False, value[0]

        elif isinstance(value, basestring):

            if os.path.isfile(value) and value.endswith('.json'):
                return True, value

            else:
                return False, value

    except IndexError:
        print '\n[!] You need to provide some arguments\n'
        sys.exit()

def jsondump(jdata, sha1):

    jsondumpfile = open('VTDL_{name}.json'.format(name=sha1), 'w')
    json.dump(jdata, jsondumpfile, indent=4)
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

    # lower case for easier comparation
    engines = [eng.lower().strip() for eng in engines]
    short_list = list()
    for engine in scans.keys():
        engine = engine.strip()
        if engine.lower() in engines and scans[engine].get('result'):
            short_list.append(engine)
            plist.append([engine,
                          scans[engine]['result'],
                          scans[engine]['version'] if 'version' in scans[engine] and scans[engine]['version'] else ' -- ',
                          scans[engine]['update'] if 'update' in scans[engine] and scans[engine]['update'] else ' -- '
                          ])

    if plist != [[]]:
        av_size, result_size, version = get_adequate_table_sizes(
            scans, True, short_list)
        pretty_print_special(plist,
                ['Vendor name',  'Result', 'Version', 'Last Update'],
                [av_size, result_size, version, 11],
                ['r', 'l', 'l', 'c'],
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
            return
            #sys.exit()

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
        if plist != [[]]:
            pretty_print_special(plist,
                ['Vendor name', 'Detected', 'Result', 'Version', 'Last Update'],
                [av_size, 9, result_size, version, 12],
                ['r', 'c', 'l', version_align, 'c'],
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
    kwargs['timeout'] = req_timeout

    while True:
        try:
            response = getattr(requests, method)(url, **kwargs)

        except requests.exceptions.ConnectionError:
            print '\n[!] Some network connection happend, check your internet conection, or it can be VT API server side issue\n'
            return {}, ''

        if response:
            if response.status_code == 403:
                private_api_access_error()

            if response.status_code != 204 and hasattr(response, 'json'):

                try:
                    jdata = response.json()

                except:
                    jdata = response.json

                break
        else:
            return {}, ''
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


class vtAPI(PRINTER):

    def __init__(self, apikey):

        super(PRINTER, self).__init__()

        self.params = {'apikey': apikey}
        self.base = 'https://www.virustotal.com/vtapi/v2/{0}'

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
            jdatas = load_file(name)
            if isinstance(jdatas, list):
                jdatas = jdatas
            else:
                jdatas = [jdatas]


            kwargs['dump'] = False

        else:

            if isinstance(kwargs.get('value'), list) and len(kwargs.get('value')) == 1:
                pass

            elif isinstance(kwargs.get('value'), basestring):
                kwargs['value'] = [kwargs.get('value')]

            #ToDo support for private api and up to 25 hashes

            for hashes_report in kwargs.get('value'):
                if os.path.isfile(hashes_report):
                    print '\nCalculating hash for:', hashes_report
                    hashes_report = hashlib.sha256(open(hashes_report, 'rb').read()).hexdigest()
                    #print '\n\t Hash is:', hashes_report

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

                jdatas.append(jdata)

        if isinstance(jdatas, list) and jdatas == []:
            if kwargs.get('return_raw'):
                pass
            else:
                print 'Nothing found'
            return

        if  not isinstance(jdatas, list):
            jdatas = [jdatas]

        for jdata in jdatas:
            if isinstance(jdata, dict):
                if jdata.get('response_code') == 0 or jdata.get('response_code') == -1:
                    if kwargs.get('not_exit'):
                        return False

                if kwargs.get('search_intelligence') or 'search_intelligence' in args:

                    if kwargs.get('return_json') and (kwargs.get('hashes') or 'hashes' in args):
                        return_json['hashes'] = jdata.get('hashes')
                    else:
                        if 'hashes' in jdata and jdata['hashes']:
                            print '[+] Matched hash(es):'
                            for file_hash in jdata['hashes']:
                                print '\t{0}'.format(file_hash)
                            if kwargs.get('download'):
                                kwargs.update({'value':jdata['hashes'], 'download':'file'})
                                self.download(**kwargs)

                if kwargs.get('allinfo') == 1:

                    if kwargs.get('dump'):
                        jsondump(jdata, name)

                    if kwargs.get('verbose'):

                        basic_file_info_list = (
                          'md5',
                          'sha1',
                          'sha256',
                          'ssdeep',
                          'scan_date',
                          'first_seen',
                          'last_seen',
                          'times_submitted',
                          'scan_id',
                          'harmless_votes',
                          'community_reputation',
                          'malicious_votes',
                        )

                        self.simple_print(jdata, basic_file_info_list)
                        self.list_print(jdata, ['submission_names'])

                    if jdata.get('ITW_urls') and ((kwargs.get('ITW_urls') or 'ITW_urls' in args) or kwargs.get('verbose')):
                        if kwargs.get('return_json'):
                            return_json['ITW_urls'] =  jdata.get('ITW_urls')
                        else:
                              self.list_print(jdata, 'ITW_urls')

                    if kwargs.get('verbose'):
                        file_info_list = (
                            'type',
                            'size',
                            'tags',
                            'unique_sources',
                        )
                        self.simple_print(jdata,file_info_list)

                    if jdata.get('additional_info'):
                        simple_list = (
                            'magic',
                            'first_seen_itw',
                            'trendmicro-housecall-heuristic',
                            'deepguard',
                            'unique_sources',
                            'trid',
                            'pe-timestamp'
                        )

                        list_list = (
                            'compressed_parents',
                        )

                        dict_keys = (
                          'pe-overlay',
                          'pe-resource-langs',
                          'pe-resource-types',
                          'pe-resource-list',
                        )

                        dict_list_keys = (
                          'sections',
                        )

                        if kwargs.get('verbose'):
                            self.simple_print(jdata['additional_info'], simple_list)
                            self.list_print(jdata['additional_info'], list_list)
                            self.dict_print(jdata['additional_info'], dict_keys)
                            self.dict_list_print(jdata['additional_info'], dict_list_keys)

                        if jdata['additional_info'].get('rombioscheck') and ((kwargs.get('rombioscheck_info') or 'rombioscheck_info' in args) or kwargs.get('verbose')):
                            if kwargs.get('return_json'):
                                return_json['rombioscheck'] = jdata['additional_info'].get('rombioscheck')
                            else:
                                print '\n[+] RomBiosCheck:'
                                print '\t'

                                # this removes code duplication
                                simple_list = (
                                    'contained_hash',
                                    'executable_file',
                                    'firmware_volume_count',
                                    'max_tree_level', 'format',
                                    'raw_objects',
                                    'raw_sections',
                                    'section_count',
                                    'vhash',
                                    'win32_file',
                                )

                                list_keys = (
                                    'acpi_tables',
                                    'nvar_variable_names',
                                    'tags'
                                )

                                double_list = (
                                    'apple_data',
                                    'manufacturer_candidates'
                                )

                                self.simple_print(jdata['additional_info']['rombioscheck'], simple_list)
                                self.list_print(jdata['additional_info']['rombioscheck'], list_keys)

                                for key in double_list:
                                  if jdata['additional_info']['rombioscheck'].get(key) and kwargs.get('verbose'):
                                      self.print_key(key)
                                      for block in  jdata['additional_info']['rombioscheck'].get(key):
                                          print '\t', block[0], ':', block[1]

                                simple_dict = (
                                    'smbios_data',
                                    'biosinformation',
                                    'systeminformation'
                                )

                                for key in simple_dict:
                                  if jdata['additional_info']['rombioscheck'].get(key) and kwargs.get('verbose'):
                                      self.print_key(key)
                                      plist = [[]]
                                      for sub_key, value in  jdata['additional_info']['rombioscheck'].get(key).items():
                                          if isinstance(value, list):
                                              value = '\n'.join(value)
                                          plist.append([sub_key, str(value).replace(',', '\n')])

                                      if plist != [[]]:
                                          pretty_print_special(plist, ['Key', 'Value'], False, ['r', 'l'], kwargs.get('email_template'))
                                      del plist

                                dict_keys = (
                                    'option_roms',
                                    'certs'
                                )

                                for key in dict_keys:
                                    if jdata['additional_info']['rombioscheck'].get(key) and kwargs.get('verbose'):
                                        self.print_key(key)

                                        for block in jdata['additional_info']['rombioscheck'].get(key, {}):
                                            plist = [[]]
                                            for key, value in block.items():
                                                if isinstance(value, list):
                                                    value = '\n'.join(value)
                                                plist.append([key, str(value).replace(',', '\n')])

                                            if plist != [[]]:
                                                pretty_print_special(plist, ['Key', 'Value'], False, ['r', 'l'], kwargs.get('email_template'))
                                            del plist

                                complex_dict = (
                                  'win32children',
                                  'children'
                                )

                                for key in complex_dict:
                                    if jdata['additional_info']['rombioscheck'].get(key) and kwargs.get('verbose'):
                                        self.print_key(key)

                                        for cert in jdata['additional_info']['rombioscheck'].get(key, {}):
                                            plist = [[]]
                                            for key, value in cert.items():
                                                if key == 'detection_ratio':
                                                    value = '/'.join([str(num) for num in value])
                                                if key in ('tags', 'imports'):
                                                    value = '\n'.join(value)
                                                if key == 'certs':

                                                    certs = list()
                                                    for certificates in value:
                                                        for sub_key, sub_value in certificates.items():
                                                            if sub_key == 'subject':
                                                                certs.append('{0}: {1}\n\n----------------'.format(sub_key, sub_value))
                                                            else:
                                                                certs.append('{0}: {1}'.format(sub_key, sub_value))
                                                    value = '\n'.join(certs)
                                                plist.append([key, value])

                                        if plist != [[]]:
                                            pretty_print_special(plist, ['Key', 'Value'], [20, 64], ['r', 'l'], kwargs.get('email_template'))

                                        del plist

                        if jdata['additional_info'].get('rombios_generator') and ((kwargs.get('rombios_generator_info') or 'rombios_generator_info' in args) or kwargs.get('verbose')):

                            if kwargs.get('return_json'):
                                return_json['rombios_generator'] = jdata['additional_info'].get('rombios_generator')
                            else:
                                print '\n[+] RomBios Generator:'
                                dict_keys = (
                                        'source',
                                )

                                for key in dict_keys:
                                    if jdata['additional_info']['rombios_generator'].get(key) and kwargs.get('verbose'):
                                        self.print_key(key)
                                        plist = [[]]
                                        for key, value in jdata['additional_info']['rombios_generator'].get(key, {}).items():
                                            if isinstance(value, list):
                                                value = '\n'.join(value)
                                            plist.append([key, str(value).replace(',', '\n')])

                                        if plist != [[]]:
                                            pretty_print_special(plist, ['Key', 'Value'], False, ['r', 'l'], kwargs.get('email_template'))

                                        del plist


                                if jdata['additional_info']['rombios_generator'].get('diff') and kwargs.get('verbose'):
                                    pass
                                    """
                                    ToDo
                                     #u'additional_info.rombios_generator.diff.contained',
                                     #u'additional_info.rombios_generator.diff.missing_children',
                                     #u'additional_info.rombios_generator.diff.missing_nvar',
                                    """



                        if jdata['additional_info'].get('debcheck') and ((kwargs.get('debcheck_info') or 'debcheck_info' in args) or kwargs.get('verbose')):
                            if kwargs.get('return_json'):
                                return_json['debcheck'] = jdata['additional_info'].get('debcheck')
                            else:
                                print '\n[+] DebCheck'
                                simple_list = (
                                    'vhash',
                                    'tags'

                                )

                                dict_list = (
                                    'structural_metadata',
                                    'control_metadata',
                                    'control_scripts'
                                )

                                complicated_dict_list = (
                                    'children',
                                )

                                for key in simple_list:
                                    if jdata['additional_info']['debcheck'].get(key):
                                        self.print_key(key)
                                        if isinstance(jdata['additional_info']['debcheck'].get(key), list):
                                                print '\t', '\n\t'.join(jdata['additional_info']['debcheck'].get(key))
                                        elif isinstance(jdata['additional_info']['debcheck'].get(key), basestring):
                                            print '\t', jdata['additional_info']['debcheck'].get(key)

                                for key in dict_list:
                                    if jdata['additional_info']['debcheck'].get(key):
                                        self.print_key(key)
                                        plist = [[]]
                                        for sub_key, value in jdata['additional_info']['debcheck'][key].items():
                                            plist.append([sub_key, value])

                                        if plist != [[]]:
                                            pretty_print_special(plist, ['Key', 'Value'], False, ['r', 'l'], kwargs.get('email_template'))

                                        del plist

                                for key in complicated_dict_list:
                                    if jdata['additional_info']['debcheck'].get(key):
                                        self.print_key(key)
                                        for block in jdata['additional_info']['debcheck'].get(key, {}):
                                            for sub_key, sub_value in block.items():
                                                if sub_key == 'detection_ratio':
                                                    sub_value = '/'.join([str(ssub) for ssub in sub_value])
                                                print '\t', sub_key, ':', sub_value
                                            print '\n'

                        if jdata['additional_info'].get('androguard') and ((kwargs.get('androidguard_info') or 'androidguard_info' in args) or kwargs.get('verbose')):
                            if kwargs.get('return_json'):
                                return_json['androguard'] = jdata['additional_info'].get('androguard')
                            else:
                                print '\n[+] AndroidGuard'
                                simple_list = (
                                        'AndroguardVersion',
                                        'AndroidApplication',
                                        'AndroidApplicationError',
                                        'AndroidApplicationInfo',
                                        'AndroidVersionCode',
                                        'AndroidVersionName',
                                        'VTAndroidInfo',
                                        'Main Activity',
                                        'MinSdkVersion',
                                        'TargetSdkVersion',
                                        'Package',
                                        'SourceFile',
                                )
                                list_list = (
                                    'Libraries',
                                    'Activities',
                                    'StringsInformation'
                                )

                                dict_list = (
                                    'Permissions',
                                    'RiskIndicator',
                                )

                                self.simple_print(jdata['additional_info']['androguard'], simple_list)
                                self.list_print(jdata['additional_info']['androguard'], list_list)
                                self.dict_print(jdata['additional_info']['androguard'], dict_list)

                                #certificates info
                                cert_list = (
                                    'Subject',
                                    'validto',
                                    'serialnumber',
                                    'thumbprint',
                                    'validfrom',
                                    'Issuer'
                                )

                                if jdata['additional_info']['androguard'].get('certificate'):
                                    for key in cert_list:
                                        if jdata['additional_info']['androguard']['certificate'].get(key):
                                            self.print_key(key)
                                            if key in ('Subject', 'Issuer'):
                                                for sub_key, sub_value in jdata['additional_info']['androguard']['certificate'].get(key).items():
                                                    print '\t', sub_key, ':', sub_value
                                            else:
                                                print '\t',  jdata['additional_info']['androguard']['certificate'].get(key)

                                if jdata['additional_info']['androguard'].get('intent-filters'):
                                    print '\n[+]', 'Intent-filters'
                                    for key in jdata['additional_info']['androguard'].get('intent-filters'):
                                        print '\t', key
                                        for sub_key in jdata['additional_info']['androguard']['intent-filters'].get(key, {}):
                                            print '\n\t\t', sub_key
                                            for ssub_key in jdata['additional_info']['androguard']['intent-filters'][key].get(sub_key):
                                                print '\n\t\t\t', ssub_key
                                                print '\n\t\t\t\t',  '\n\t\t\t\t'.join(jdata['additional_info']['androguard']['intent-filters'][key][sub_key].get(ssub_key))

                                """
                                ToDo
                                 u'additional_info.androguard.Providers',
                                 u'additional_info.androguard.Receivers',
                                 u'additional_info.androguard.Services',
                                 """

                        if jdata.get('email_parents') and kwargs.get('verbose'):
                            print '\n[+] Email parents:'
                            for email in jdata['email_parents']:
                                print '\t{email}'.format(email=email)

                        if jdata['additional_info'].get('referers') and kwargs.get('verbose'):
                            print '\n[+] Referers:'
                            print '\t', '\n\t'.join(jdata['additional_info']['referers'])

                        # IDS, splited to be easily getted throw imported vt as library
                        ids = (
                          'suricata',
                          'snort'
                        )
                        for key in ids:
                            if jdata['additional_info'].get(key) and (kwargs.get(key) or key in args) or kwargs.get('verbose'):
                                if kwargs.get('return_json'):
                                    return_json[key] = jdata['additional_info'].get(key)
                                else:
                                    if jdata['additional_info'].get(key, ''):
                                        self.print_key(key)
                                        for rule in jdata['additional_info'].get(key):
                                            print '\nRule:', rule
                                            print '\tAlert\n\t\t', jdata['additional_info'][key][rule]['alert']
                                            print '\tClassification\n\t\t', jdata['additional_info'][key][rule]['classification']
                                            print '\tDescription:'
                                            for desc in jdata['additional_info'][key][rule]['destinations']:
                                                print '\t\t', desc

                        if jdata['additional_info'].get('traffic_inspection') and (kwargs.get('traffic_inspection') or 'traffic_inspection' in args) or kwargs.get('verbose'):
                            if kwargs.get('return_json'):
                                return_json['traffic_inspection'] = jdata['additional_info'].get('traffic_inspection')
                            else:
                                if jdata['additional_info'].get('traffic_inspection'):
                                    print '\n[+] Traffic inspection'
                                    for proto in jdata['additional_info'].get('traffic_inspection'):
                                        print '\tProtocol:', proto
                                        for block in jdata['additional_info'].get('traffic_inspection')[proto]:
                                            plist = [[]]
                                            for key, value in block.items():
                                                plist.append([key, str(value)])

                                            if plist != [[]]:
                                                pretty_print_special(plist, ['Key', 'Value'], False, ['r', 'l'], kwargs.get('email_template'))

                                            del plist

                        if jdata['additional_info'].get('wireshark') and (kwargs.get('wireshark_info') or 'wireshark_info' in args) or kwargs.get('verbose'):
                            if kwargs.get('return_json'):
                                return_json['wireshark'] = jdata['additional_info'].get('wireshark')
                            else:
                                if jdata['additional_info'].get('wireshark', {}):
                                    print '\n[+] Wireshark:'
                                    if jdata['additional_info'].get('wireshark', {}).get('pcap'):
                                        plist = [[]]
                                        for key, value in jdata['additional_info'].get('wireshark', {}).get('pcap').items():
                                            plist.append([key, value])

                                        if plist != [[]]:
                                            pretty_print_special(plist, ['Key', 'Value'], False, ['c', 'l'], kwargs.get('email_template'))

                                        del plist

                                    if jdata['additional_info'].get('wireshark', {}).get('dns'):
                                        print '\n[+] DNS'
                                        plist = [[]]
                                        key_s, value_s = get_sizes(jdata['additional_info'].get('wireshark'))
                                        for domain in  jdata['additional_info'].get('wireshark').get('dns'):
                                            plist.append([domain[0], '\n\t'.join(domain[1])])

                                        if plist != [[]]:
                                            pretty_print_special(plist, ['Domain', 'IP(s)'], False, ['r', 'l'], kwargs.get('email_template'))

                                        del plist

                        if jdata['additional_info'].get('behaviour-v1'):


                            dict_keys = (
                                'mutex',
                            )

                            if kwargs.get('verbose'):
                                self.dict_list_print(jdata['additional_info']['behaviour-v1'], dict_keys)
                                if jdata['additional_info']['behaviour-v1'].get('tags'):
                                    print '\n[+] Tags:'
                                    for tag in jdata['additional_info']['behaviour-v1'].get('tags'):
                                        print '\t', tag

                            if jdata['additional_info']['behaviour-v1'].get('dropped_files') and kwargs.get('verbose'):
                                print '\n[+] Dropped files:'

                                plist = [[]]

                                for files in jdata['additional_info']['behaviour-v1'].get('dropped_files'):
                                    plist.append([files.get('hash'), files.get('filename')])

                                if plist != [[]]:
                                    pretty_print_special(plist, ['Hash(sha256?)', 'Filename'], [64, 50], ['c', 'l'], kwargs.get('email_template'))

                                del plist


                            if jdata['additional_info']['behaviour-v1'].get('network', {}) and kwargs.get('verbose'):
                                print '\n[+] Network'
                                network_list = (
                                    'tcp',
                                    'udp'
                                )
                                for key in network_list:
                                    if jdata['additional_info']['behaviour-v1']['network'].get(key):
                                        plist = [[]]
                                        [plist.append([ip]) for ip in jdata['additional_info']['behaviour-v1']['network'].get(key)]
                                        pretty_print_special(plist, [key.upper()], False, False, kwargs.get('email_template'))


                            # ToDo hosts

                            if jdata['additional_info']['behaviour-v1']['network'].get('dns') and kwargs.get('verbose'):
                                print '\n[+] DNS:'
                                plist = [[]]
                                for block in  jdata['additional_info']['behaviour-v1']['network'].get('dns'):
                                    plist.append([block.get('ip'), block.get('hostname')])
                                pretty_print_special(plist, ['Ip', 'Hostname'], False, False, kwargs.get('email_template'))

                            #if jdata['additional_info']['behaviour-v1']['network'].get('http'):
                            #    print '\n[+] HTTP:', jdata['additional_info']['behaviour-v1']['network'].get('http')

                            if jdata['additional_info']['behaviour-v1'].get('codesign') and kwargs.get('verbose'):
                                print '\n[+] Codesign:\n\t',jdata['additional_info']['behaviour-v1'].get('codesign').replace('\n', '\n\t')

                            if jdata['additional_info']['behaviour-v1'].get('process') and kwargs.get('verbose'):
                                dict_keys = (
                                    'injected',
                                    'shellcmds',
                                    'terminated',
                                    'tree'
                                )
                                print '\n[+] Process'
                                self.dict_list_print(jdata['additional_info']['behaviour-v1']['process'], dict_keys)

                            if jdata['additional_info']['behaviour-v1'].get('registry') and kwargs.get('verbose'):
                                dict_keys = (
                                    'deleted',
                                    'set'
                                )
                                #print '\n[+] Registry'
                                #self.dict_list_print(jdata['additional_info']['behaviour-v1']['registry'], dict_keys)

                            if jdata['additional_info']['behaviour-v1'].get('windows') and kwargs.get('verbose'):
                                dict_keys = (
                                    'windows',
                                    'runtime-dlls',
                                    'hooking',
                                    'filesystem'
                                )
                                self.dict_list_print(jdata['additional_info']['behaviour-v1'], dict_keys)
                                """ToDo
                                u'additional_info.behaviour-v1.extra',
                                 u'additional_info.behaviour-v1.hosts_file',
                                 u'additional_info.behaviour-v1.registry.deleted',
                                 u'additional_info.behaviour-v1.registry.set',
                                 u'additional_info.behaviour-v1.service.controlled',
                                 u'additional_info.behaviour-v1.service.created',
                                 u'additional_info.behaviour-v1.service.deleted',
                                 u'additional_info.behaviour-v1.service.opened',
                                 u'additional_info.behaviour-v1.service.opened-managers',
                                 u'additional_info.behaviour-v1.service.started',

                                """

                            if kwargs.get('verbose'):
                                simple_list = (
                                    'knockknock',
                                    'tun_time',
                                    'internal_tags',
                                    'num_screenshots',
                                    'version'
                                )
                                self.simple_print(jdata['additional_info']['behaviour-v1'], simple_list)

                            if jdata['additional_info']['behaviour-v1'].get('signals') and kwargs.get('verbose'):
                                print '\n[+] Signals:'

                                plist = [[]]

                                for signals in jdata['additional_info']['behaviour-v1'].get('signals'):
                                    plist.append(
                                        [signals.get('cmd'), signals.get('target'), signals.get('signo'), signals.get('pid'), signals.get('walltimestamp'), signals.get('execname')])

                                if plist != [[]]:
                                    pretty_print_special(plist, ['CMD', 'Target', 'Signo', 'PID', 'WallTimeStamp', 'ExecName'], False, False, kwargs.get('email_template'))

                                del plist

                            if jdata['additional_info']['behaviour-v1'].get('filesystem') and kwargs.get('verbose'):
                                print '\n[+] Filesystem:',
                                if jdata['additional_info']['behaviour-v1']['filesystem'].get('opened'):

                                    plist = [[]]

                                    for fs_open in jdata['additional_info']['behaviour-v1']['filesystem'].get('opened'):
                                        plist.append(
                                            [fs_open.get('success'), fs_open.get('execname'), fs_open.get('path')])

                                    if plist != [[]]:
                                        pretty_print_special(plist, ['Success', 'ExecName', 'Path'], [8, 20, 80], ['c', 'c', 'l'], kwargs.get('email_template'))

                                    del plist
                            if jdata['additional_info']['behaviour-v1'].get('output'):
                                print '\n[+] Output:', jdata['additional_info']['behaviour-v1'].get('output')

                        if jdata['additional_info'].get('sigcheck') and kwargs.get('verbose'):

                            print '\n[+] PE signature block:'
                            plist = [[]]
                            for sig in jdata['additional_info']['sigcheck']:
                                if isinstance(jdata['additional_info']['sigcheck'][sig], list):
                                  self.print_key(sig)
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
                            self.dict_print(jdata['additional_info'], ['exiftool'])

                        if jdata['additional_info'].get('imports') and kwargs.get('verbose'):
                            self.dict_print(jdata['additional_info'], ['imports'])

                        if jdata['additional_info'].get('dmgcheck') and kwargs.get('verbose'):
                            print '\n[+] dmgCheck:'

                            if jdata['additional_info']['dmgcheck'].get('plst_keys'):
                                print '\n[+] plst_keys:'
                                for key in jdata['additional_info']['dmgcheck']['plst_keys']:
                                    print '\t', key

                            if jdata['additional_info']['dmgcheck'].get('plst'):
                                plist = [[]]

                                for plst in jdata['additional_info']['dmgcheck']['plst']:
                                    plist.append(
                                        [plst.get('attributes'), plst.get('name')])

                                if plist != [[]]:
                                    pretty_print_special(plist, ['Attributes', 'Name'], False, False, kwargs.get('email_template'))
                                del plist

                            dmgcheck_list = (
                                'xml_offset',
                                'xml_length',
                                'data_fork_offset',
                                'running_data_fork_offset',
                                'rsrc_fork_offset',
                            )

                            if jdata['additional_info']['dmgcheck'].get('resourcefork_keys'):
                                print '\n[+] resourcefork keys:'
                                for key in jdata['additional_info']['dmgcheck']['resourcefork_keys']:
                                    print '\t', key

                            if jdata['additional_info']['dmgcheck'].get('blkx'):
                                print '\n[+] blkx:'
                                plist = [[]]

                                for blkx in  jdata['additional_info']['dmgcheck']['blkx']:
                                    plist.append(
                                        [blkx.get('attributes'), blkx.get('name')])

                                if plist != [[]]:
                                    pretty_print_special(plist, ['Attributes', 'Name'], False, False, kwargs.get('email_template'))

                                del plist

                            if jdata['additional_info']['dmgcheck'].get('iso') and jdata['additional_info']['dmgcheck']['iso'].get('volume_data', {}):
                                print '\n[+] Volume data'
                                plist = [[]]
                                for key, value in jdata['additional_info']['dmgcheck']['iso'].get('volume_data', {}).items():
                                    plist.append([key, value])

                                if plist != [[]]:
                                    pretty_print_special(plist, ['Key', 'Value'], [22, 80], ['r', 'l', ], kwargs.get('email_template'))

                                del plist

                            hfs_dict_list = (
                                'executables',
                                'bundles',
                                'main_executable',
                            )

                            # ToDo
                            #  dmgcheck.iso.unreadable_files

                            for pattern in ('hfs', 'iso'):
                                for key in hfs_dict_list:
                                    if jdata['additional_info']['dmgcheck'].get(pattern):
                                        if jdata['additional_info']['dmgcheck'][pattern].get(key):
                                            self.print_key(key)
                                            plist = [[]]

                                            if key in ('main_executable', 'volume_data'):
                                                jdata['additional_info']['dmgcheck'][pattern][key] = [jdata['additional_info']['dmgcheck'][pattern][key]]

                                            for executables in jdata['additional_info']['dmgcheck'][pattern].get(key, ''):
                                                detection = executables.get('detection_ratio')
                                                detection = '{0}:{1}'.format(detection[0], detection[1])
                                                plist.append(
                                                    [detection, executables.get('id'), executables.get('size', '-'), executables.get('sha256'), executables.get('path')])
                                            if plist != [[]]:
                                                pretty_print_special(plist, ['Detection', 'Id', 'Size', 'sha256', 'Path'], [10, 10, 10, 64, 50], ['c', 'c', 'c', 'c', 'l'], kwargs.get('email_template'))

                                            del plist

                                hfs_list = (
                                        'num_files',
                                        'unreadable_files',
                                        'dmg'
                                )

                                for key in hfs_list:
                                    if jdata['additional_info']['dmgcheck'][pattern].get(key):
                                        self.print_key(key)
                                        print '\t', jdata['additional_info']['dmgcheck'][pattern][key]

                                if jdata['additional_info']['dmgcheck'][pattern].get('info_plist', ''):
                                    print '\n[+] Info plist: '
                                    for key, value in jdata['additional_info']['dmgcheck'][pattern]['info_plist'].items():
                                        if isinstance(value, dict):
                                            print '\t', key, ':'
                                            for subkey, subvalue in value.items():
                                                print '\t\t', subkey, ':', subvalue
                                        else:
                                            print '\t', key, ':', value

                        if jdata['additional_info'].get('compressedview') and ((kwargs.get('compressedview') or 'compressedview' in args) or kwargs.get('verbose')):
                          if kwargs.get('return_json'):
                            return_json['compressedview'] = jdata['additional_info']['compressedview']['compressedview']

                          else:
                            print '\n[+] Compressed view:'
                            if jdata['additional_info']['compressedview'].get('children') and ((kwargs.get('children') or 'children' in args) or kwargs.get('verbose')):
                                if kwargs.get('return_json'):
                                    return_json['compresedview_children'] = jdata['additional_info']['compressedview']['children']
                                else:
                                    compressedview_list = ('datetime', 'detection_ratio', 'filename', 'sha256', 'size', 'type')
                                    for child in jdata['additional_info']['compressedview'].get('children'):
                                        print '\n'
                                        for key in compressedview_list:
                                            if child.get(key):
                                                self.print_key(key, indent='', separator='')
                                                if key == 'detection_ratio':
                                                    print '\t{0}/{1}'.format(child[key][0], child[key][1])
                                                elif key == 'filename':
                                                    try:
                                                        print '\t', child[key]
                                                    except:
                                                        try:
                                                            print '\t', child[key].encode('utf-8')
                                                        except:
                                                            print '\t[-]Name decode error'
                                                else:
                                                    print '\t', child.get(key)

                            if jdata['additional_info']['compressedview'].get('extensions'):
                                print '\n[+] Extensions:'
                                for ext in jdata['additional_info']['compressedview']['extensions']:
                                    print '\t', ext, jdata['additional_info']['compressedview']['extensions'][ext]

                            if jdata['additional_info']['compressedview'].get('file_types'):
                                print '\n[+] FileTypes'
                                for file_types in jdata['additional_info']['compressedview']['file_types']:
                                    print '\t' ,file_types, jdata['additional_info']['compressedview']['file_types'][file_types]

                            if jdata['additional_info']['compressedview'].get('tags'):
                                print '\n[+] Tags:'
                                for tag in jdata['additional_info']['compressedview']['tags']:
                                    print '\t', tag

                            compressedview_add_list = (
                                'lowest_datetime',
                                'highest_datetime',
                                'num_children',
                                'type',
                                'uncompressed_size',
                                'vhash'
                            )

                            self.simple_print(jdata['additional_info']['compressedview'], compressedview_add_list)

                        if jdata['additional_info'].get('detailed_email_parents') and ((kwargs.get('detailed_email_parents') or 'detailed_email_parents' in args) or kwargs.get('verbose')):

                            if kwargs.get('return_json') and  (kwargs.get('original-email') or 'original-email' in args):
                                return_json['detailed_email_parents'] = jdata['additional_info']['detailed_email_parents']
                            else:
                                if not kwargs.get('return_json'):
                                    print '\nDetailed email parents:'
                                for email in jdata['additional_info']['detailed_email_parents']:
                                    if kwargs.get('email_original'):
                                        kwargs['value'] = [email.get('message_id')]
                                        parsed = self.parse_email(**kwargs)
                                        if parsed:
                                            return_json.setdefault('emails', [])
                                            if kwargs.get('return_json'):
                                                return_json['emails'].append(parsed)

                                    else:
                                        email_list = (
                                            'subject',
                                            'sender',
                                            'receiver',
                                            'message_id',

                                        )
                                        for key in email_list:
                                            if email.get(key):
                                                self.print_key(key, indent='\n', separator='')
                                                print '\t', email[key]

                                        if email.get('message'):
                                            print '\nMessage:'
                                            if email['message'] is not None:
                                              for line in email['message'].split('\n'):
                                                  print line.strip()

                    if jdata.get('total') and kwargs.get('verbose'):
                        print '\n[+] Detections:\n\t{positives}/{total} Positives/Total\n'.format(positives=jdata['positives'], total=jdata['total'])

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

                        if plist != [[]]:
                            pretty_print_special(plist,
                                ['Vendor name', 'Detected', 'Result', 'Version', 'Last Update'],
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

                    if kwargs.get('notify_changes_only'):
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

                if jdata.get('response_code', 0) == 0 or jdata.get('response_code', -1) == -1:
                    if jdata.get('verbose_msg'):
                        print '\n[!] Status : {verb_msg}\n'.format(verb_msg=jdata['verbose_msg'])

                else:
                    if jdata.get('sha256'):
                        print '[+] Check rescan result with sha256 in few minutes : \n\tSHA256 : {sha256}'.format(sha256=jdata['sha256'])
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
                try:
                    print 'ImpHash: {0}'.format(pe.get_imphash())
                except:
                    pass

                print "\n[+] Protections:"
                print "\tASLR:", bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040)
                print "\tDEP:", bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100)
                print "\tSEG:", bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0400)
                print "\tCFG:", bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x4000)

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
            if os.path.isdir(kwargs.get('value')[0]):
                # ToDo os.walk for Marc
                kwargs['value'] = glob(os.path.join(kwargs.get('value')[0], '*'))
                if kwargs.get('file_scan_recursive'):
                    all_files = list()
                    for path, dirs, files in os.walk(kwargs['value']):
                        for file in files:
                          all_files.append(os.path.join(path, file))
                    kwargs['value'] = all_files

        if kwargs.get('notify_url'):
            self.params['notify_url'] = kwargs.get('notify_url')

            if kwargs.get('notify_changes_only'):
                self.params['notify_changes_only'] = kwargs.get('notify_changes_only')

        url = self.base.format('file/scan')

        if not kwargs.get('scan'):
            for index, c_file in enumerate(kwargs.get('value')):
                if os.path.isfile(c_file):
                    if  (os.path.getsize(c_file) / 1048576) <= 128:
                        kwargs.get('value')[index] = hashlib.md5(open(c_file, 'rb').read()).hexdigest()
                    else:
                        print '[!] Ignored file: {file}, size is to big, permitted size is 128Mb'.format(file=c_file)

        kwargs['not_exit'] = True
        hash_list = kwargs.get('value')
        for submit_file in hash_list:
            kwargs.update({'value':submit_file})
            # Check all list of files, not only one
            result = self.getReport(**kwargs)
            if not result and kwargs.get('scan') == True:
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

                        simple_list = (
                            'md5',
                            'sha1',
                            'sha256',
                            'verbose_msg',
                            'permalink'
                        )

                        self.simple_print(jdata, simple_list)

                    except UnicodeDecodeError:
                        print '\n[!] Sorry filaname is not utf-8 format, other format not suported at the moment'
                        print '[!] Ignored file: {file}\n'.format(file=submit_file)

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

        url_uploads = list()
        result = False
        md5_hash = ''
        urls = list()
        if kwargs.get('value')[0].endswith('.json'):
            result, name = is_file(kwargs.get('value'))

        if result:
            jdata = load_file(name)
            kwargs['dump'] = False
        else:
            if isinstance(kwargs.get('value'), list) and len(kwargs.get('value')) == 1:
                if os.path.isfile(kwargs.get('value')[0]):
                    url_uploads = open(kwargs.get('value')[0], 'rb').readlines()
                else:
                    url_uploads = kwargs.get('value')
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

                    if len(kwargs.get('value')) > end + increment:
                        end += increment
                    elif len(kwargs.get('value')) <= end + increment:
                        end = len(kwargs.get('value'))

                    if kwargs.get('key') == 'scan':
                        url_uploads.append(['\n'.join(map(lambda url: url.replace(',', '').strip(), kwargs.get('value')[start:end]))])
                    elif kwargs.get('key') == 'report':
                        url_uploads.append(['\n'.join(map(lambda url: url.replace(',', '').strip(), kwargs.get('value')[start:end]))])

                    if end == len(kwargs.get('value')):
                        break
        cont = 0
        for url_upload in url_uploads:
            cont += 1
            to_show = url_upload
            if isinstance(url_upload, list) and "\n" in url_upload[0]:
                to_show = url_upload[0].split("\n")

            if kwargs.get('key') == 'scan':
                print 'Submitting url(s) for analysis: \n\t{url}'.format(url="\n\t".join(to_show))
                self.params['url'] = url_upload
                url = self.base.format('url/scan')

            elif kwargs.get('key') == 'report':
                print '\nSearching for url(s) report: \n\t{url}'.format(url="\n\t".join(to_show))
                self.params['resource'] = url_upload
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

                        if kwargs.get('key') == 'report':
                            kwargs.update({'url_report':True})
                            parse_report(jdata_part, **kwargs)

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
            if jdata.get('response_code', "") == 0 or jdata.get('response_code', -1) == -1:
                if jdata.get('verbose_msg'):
                    print '\n[-] Status {ip}: {verb_msg}\n'.format(verb_msg=jdata['verbose_msg'], ip=ip)

            elif jdata['response_code'] == 1:
                if jdata.get('verbose_msg') and not (kwargs.get('return_json') or kwargs.get('return_raw')) and kwargs.get('verbose'):
                    print '\n[+] IP:', ip

                simple_list = (
                    'asn',
                    'as_owner',
                    'country',
                )

                for key in simple_list:
                    if jdata.get(key) and ((kwargs.get(key) or key in args) or kwargs.get('verbose')):
                        if kwargs.get('return_json'):
                            return_json.update({key:jdata[key]})
                        else:
                            self.print_key(key, indent='\n', separator='[+]')
                            print '\t', jdata.get(key)

                if kwargs.get('return_json'):
                    return_json.update(self.detected_samples(jdata, *args, **kwargs))
                else:
                    return_json = self.detected_samples(jdata, *args, **kwargs)

                if jdata.get('resolutions') and ((kwargs.get('resolutions') or 'resolutions' in args) or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'resolutions':jdata['resolutions']})
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
            if isinstance(kwargs.get('value'), list) and len(kwargs.get('value')) == 1 and \
                os.path.exists(kwargs.get("value")[0]) and kwargs.get("value")[0].endswith(".txt"):
                kwargs["value"] = [domain.strip() for domain in open(kwargs.get("value")[0], "rb").readlines()]
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
            if jdata.get('response_code', 0) == 0 or jdata.get('response_code') == -1:
                if jdata.get('verbose_msg'):
                    print '\n[!] Status : {verb_msg} : {domain}\n'.format(verb_msg=jdata['verbose_msg'], domain=domain)

            if jdata.get('response_code') and jdata['response_code'] == 1:
                if jdata.get('verbose_msg') and not (kwargs.get('return_json') or kwargs.get('return_raw')) and kwargs.get('verbose'):
                    print '\n[+] Domain:', domain

                single_dict = (
                    'categories',
                    'TrendMicro category',
                    'Dr.Web category',
                    'BitDefender category',
                    'Websense ThreatSeeker category',
                    'Alexa category',
                    'Alexa domain info',
                    'Alexa rank',
                    'Opera domain info',
                    'subdomains',
                    'domain_siblings',
                )

                complicated_dict = (
                     'WOT domain info',
                     'Webutation domain info',
                     'resolutions'
                )

                for key in single_dict:
                    if jdata.get(key) and ((kwargs.get(key) or key in args) or kwargs.get('verbose')):
                        if kwargs.get('return_json'):
                            return_json.update({key: jdata[key]})
                        else:
                            self.print_key(key)
                            if isinstance(jdata[key], list):
                                print '\t', '\n\t'.join(jdata[key])
                            elif key == 'whois_timestamp':
                                print '\t{0}'.format(datetime.fromtimestamp(float(jdata[key])).strftime('%Y-%m-%d %H:%M:%S'))
                            else:
                                print '\t{0}'.format(jdata[key])

                for key in complicated_dict:
                    if jdata.get(key) and ((kwargs.get(key) or key in args) or kwargs.get('verbose')):
                        if kwargs.get('return_json'):
                            return_json.update({key: jdata[key]})
                        else:
                            self.print_key(key)
                            plist = [[]]
                            for jdata_part in jdata[key]:
                                if isinstance(jdata_part, basestring):
                                    plist.append([jdata_part, jdata[key][jdata_part]])
                                elif isinstance(jdata_part, dict):
                                    plist.append(jdata_part.values())
                            pretty_print_special(plist, ['Name', 'Value'], [25, 20], ['c', 'c'], kwargs.get('email_template'))
                            del plist

                if jdata.get('whois') and ((kwargs.get('whois') or 'whois' in args) or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'whois': jdata['whois']})
                    else:
                        print '\n[+] Whois data:\n'
                        try:
                            print '\t', jdata['whois'].replace('\n', '\n\t')
                        except:
                            try:
                                print '\t', jdata['whois'].encode('utf-8', 'replace').replace('\n', '\n\t')
                            except:
                                print 'Old version of python has some problems with converting chars to ansii'

                if kwargs.get('return_json'):
                    return_json.update(self.detected_samples(jdata, *args, **kwargs))
                else:
                    return_json = self.detected_samples(jdata, *args, **kwargs)

                if jdata.get('pcaps') and ((kwargs.get('pcaps') or 'pcaps' in args) or kwargs.get('verbose')):
                    if kwargs.get('return_json'):
                        return_json.update({'pcaps': jdata['pcaps']})
                    else:
                        print '\n'
                        pretty_print(jdata['pcaps'], ['pcaps'], [70], ['c'], kwargs.get('email_template'))

                if jdata.get('resolutions') and ((kwargs.get('resolutions') or 'resolutions' in args)  or kwargs.get('verbose')):
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

                if kwargs.get('walk') and jdata.get('resolutions'):
                    filter_ip = list()
                    for ip in sorted(jdata['resolutions'], key=methodcaller('get', 'last_resolved'), reverse=True):
                        if ip['ip_address'] not in filter_ip:
                            print '\n\n[+] Checking data for ip: {0}'.format(ip['ip_address'])
                            kwargs['value'] = ip['ip_address']
                            self.getIP(**kwargs)

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

        if jdata.get('response_code', 0) == 0 or jdata.get('response_code', -1) == -1:
            if jdata.get('verbose_msg'):
                print '\n[!] Status : {verb_msg}\n'.format(verb_msg=jdata['verbose_msg'])
            return
        if jdata.get('verbose_msg'):
            print '\nStatus : {verb_msg}'.format(verb_msg=jdata['verbose_msg'])

        simple_list = (
            'size_top200',
            'num_clusters',
        )

        self.simple_print(jdata, simple_list, indent='\n\t')
        for key in simple_list:
            if jdata.get(key):
                self.print_key(key, indent='\n\t')
                print '\n\t', jdata.get(key)

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

            elif kwargs.get('action') == 'get':
                url = self.base.format('comments/get')
                if value[0]:
                    self.params['before'] = kwargs.get('date')
                jdata, response = get_response(url, params=self.params)

            else:
                print '\n[!] Support only get/add comments action \n'
                return

        if kwargs.get('return_raw'):
            return jdata

        if jdata.get('response_code', 0) == 0 or jdata.get('response_code',-1) == -1:
            if jdata.get('verbose_msg'):
                print '\n[!] Status : {verb_msg}\n'.format(verb_msg=jdata['verbose_msg'])
            return
            #sys.exit()
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
                        date_formated = '{year}:{month}:{day} {hour}:{minutes}:{seconds}'.format(
                            year=date_format.tm_year,
                            month=date_format.tm_mon,
                            day=date_format.tm_mday,
                            hour=date_format.tm_hour,
                            minutes=date_format.tm_min,
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
        super_file_type = kwargs.get("download")

        if isinstance(kwargs.get("value"), list) and len(kwargs.get("value")) == 1:
            if os.path.exists(kwargs.get("value")[0]) and kwargs.get("value")[0].endswith(".txt"):
                kwargs["value"] = [dl_hash.strip() for dl_hash in open(kwargs.get("value")[0], "rb").readlines()]
        elif isinstance(kwargs.get("value"), basestring):
            kwargs["value"] = [kwargs.get("value")]

        kwargs["value"] = deque(kwargs["value"])
        threads = kwargs.get("download_threads", 5)
        if len(kwargs["value"]) < threads:
            threads = len(kwargs["value"])

        threads_list = list()

        self.downloaded_to_return = dict()
        self._stop = threading.Event()
        self._stop.set()

        for worked in xrange(threads):
            thread = threading.Thread(target=self.__downloader, args=args, kwargs=kwargs)
            thread.daemon = True
            thread.start()

            threads_list.append(thread)

        while kwargs["value"]:
            time.sleep(1)

        self._stop.clear()

        for thread in threads_list:
            thread.join()

        if kwargs.get("return_raw", False):
            return self.downloaded_to_return

    def __name_auxiliar(self, *args, **kwargs):
        name = kwargs.get('name')
        file_type = kwargs.get('download')
        print file_type
        if os.path.exists(name):
            for i in xrange(9999999999999):
                if not os.path.exists('{}_{}'.format(name, i)):
                    name = '{}_{}'.format(name, i)
                    break
        return name

    def __downloader(self, *args,  **kwargs):
            """
                Auxiliar threaded downloader
            """

            super_file_type = kwargs.get('download')
            while kwargs['value'] and self._stop.is_set():
                try:
                    f_hash = kwargs['value'].pop()
                    f_hash = f_hash.strip()
                    if f_hash != '':

                        if f_hash.find(',') != -1:
                            file_type = f_hash.split(',')[-1]
                            f_hash = f_hash.split(',')[0]
                        else:
                            file_type = super_file_type

                        file_type = kwargs.get('download')
                        if f_hash.startswith('http'):
                                result_hash = re.findall('[\w\d]{64}', f_hash, re.I)
                                if result_hash:
                                    f_hash = result_hash[0]
                                else:
                                    print '[-] Hash not found in url'

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
                        params = dict()
                        params["apikey"] = self.params["apikey"]
                        params["hash"] = f_hash
                        response = requests.get(url, params=params)
                        if response:
                            if response.status_code == 404:
                                    print '\n[!] File not found - {0}\n'.format(f_hash)

                            if response.status_code == 200:
                                if kwargs.get('name', ""):
                                    name = self.__name_auxiliar(*args, **kwargs)
                                else:
                                    name = '{hash}'.format(hash=f_hash)
                                if file_type == "pcap":
                                    name += ".pcap"
                                if "VirusTotal - Free Online Virus, Malware and URL Scanner" in response.content and \
                                   '{"response_code": 0, "hash":' not in response.content: # filter out keep-alive new chunks
                                        try:
                                            json_data = response.json()
                                            print '\n\t{0}: {1}'.format(json_data['verbose_msg'], f_hash)
                                        except:
                                            print '\tFile can\'t be downloaded: {0}'.format(f_hash)
                                #Sanity checks
                                downloaded_hash = ''
                                if len(f_hash) == 32:
                                    downloaded_hash = hashlib.md5(response.content).hexdigest()
                                elif len(f_hash) == 40:
                                    downloaded_hash = hashlib.sha1(response.content).hexdigest()
                                elif len(f_hash) == 64:
                                    downloaded_hash = hashlib.sha256(response.content).hexdigest()

                                if f_hash != downloaded_hash:
                                    print '[-] Downloaded content has not the same hash as requested'
                                if kwargs.get('return_raw'):
                                    self.downloaded_to_return.setdefault(f_hash, response.content)
                                else:
                                    dumped = open(name, 'wb')
                                    dumped.write(response.content)
                                    dumped.close()
                                    print '\tDownloaded to File -- {name}'.format(name=name)
                        else:
                             self.downloaded_to_return.setdefault(f_hash, 'failed')
                except:
                    self._stop.set()
    # normal email attachment extractor
    def __email_parse_attachment(self, message_part):

        attachment = ''
        filename = ''
        size = ''
        content_type = ''
        sha256_hash = ''
        sha1_hash = ''
        md5_hash = ''

        if message_part.get_filename():
            filename = message_part.get_filename()
            content_type = message_part.get_content_type()
            attachment = message_part.get_payload(decode=True)
            if attachment:
                size = len(attachment)
                sha256_hash = hashlib.sha256(attachment).hexdigest()
                sha1_hash = hashlib.sha1(attachment).hexdigest()
                md5_hash = hashlib.md5(attachment).hexdigest()

        return attachment, filename, size, content_type, sha256_hash, sha1_hash, md5_hash

    def __email_print(self, email_dict, email_id, *args, **kwargs):

            if len(email_id) >=64:
                # in case if you pass full email instead of hash
                email_id = hashlib.sha256(email_id).hexdigest()

            print '\n[+] Details of email: {0}'.format(email_id)
            plist = [[]]

            if 'Attachments' in email_dict:
                for i, part in  enumerate(email_dict['Attachments']):
                    path_where_save = kwargs.get('save_attachment')
                    if path_where_save:
                        if not os.path.exists(path_where_save):
                            os.makedirs(path_where_save)
                        print '[+] Saving attachment with hash: {0}'.format(email_dict['Attachments'][i]['sha256'])
                        dump_file = open(os.path.join(path_where_save, email_dict['Attachments'][i]['sha256']), 'wb')
                        # ToDo improve this
                        """
                        if email_dict['Attachments'][i]['attachment'].startswith("filename="):
                            attach_parts = email_dict['Attachments'][i]['attachment'].split("\r\n\r\n")
                            if len(attach_parts) >= 2:
                                email_dict['Attachments'][i]['attachment'] = base64.b64decode(attach_parts[1])
                        """
                        dump_file.write(email_dict['Attachments'][i]['attachment'])
                        dump_file.close()

                    del email_dict['Attachments'][i]['attachment']

            key_s, value_s = get_sizes(email_dict)

            for k,v in sorted(email_dict.items()):
                if k == 'Attachments':
                  line = ''
                  for part in email_dict['Attachments']:
                        #to have order
                        for value in ('md5', 'sha1', 'sha256', 'name', 'size', 'content_type'):
                            if value == "name":
                                try:
                                    line += '{0} : {1}\n'.format(value, part.get(value, "").encode("utf-8", "replace"))
                                except Exception as e:
                                    print(value, e)
                            else:
                                 line += '{0} : {1}\n'.format(value, part.get(value, ""))

                  plist.append([k,line])
                else:
                    plist.append([k,v])

            if plist != [[]]:
                pretty_print_special(
                plist,
                ['Key', 'Value'],
                [key_s, value_s],
                ['r', 'l'],
                kwargs.get('email_template')
            )

    def __download_email(self, email_id, *args, **kwargs):
        original_email = ''
        original_email = self.download(**{
              'value':[email_id],
              'api_type':kwargs.get('api_type'),
              'download':'file',
              'intelligence':kwargs.get('intelligence'),
              'return_raw':True,
        })

        return original_email

    def email_remove_bad_char(self, email):
        ''' I saw few emails which start with ">" and they not parsed correctly'''

        if email.startswith('>'):
            email = email[1:]

        return email

    def parse_email(self, *args,  **kwargs):

        msg = ''
        email_dict = dict()

        def re_compile_our(pattern):
            return re_compile_orig(pattern.replace("?P<end>--", "?P<end>--+"))

        if kwargs.get('value'):
            result, name = is_file(kwargs.get('value'))
            if result:
                msg = load_file(name)
                kwargs['dump'] = False

        for email_id in kwargs.get('value'):
            if os.path.exists(email_id):
                email_id = open(email_id, 'rb').read()
            else:
                if email_id.startswith('http'):
                    email_id = re.findall('[\w\d]{64}', email_id, re.I)
                    if email_id:
                        email_id = email_id[0]
                    else:
                        print '[-] Hash not found in url'

            if len(email_id) in (32, 40, 64): # md5, sha1, sha256
                email_id = self.__download_email(email_id, *args, **kwargs)
            if isinstance(email_id, basestring):
                email_id = {"email":email_id}
            try:
                for email__id in email_id:
                    email__id = email_id[email__id]
                    email__id = self.email_remove_bad_char(email__id)
                    # save
                    if kwargs.get('download'):
                        if kwargs.get('name'):
                            self.__name_auxiliar(*args, **kwargs)
                        else:
                            name = hashlib.sha256(email__id).hexdigest() + '.eml'

                        #save email
                        save_email = open(name, 'wb')
                        save_email.write(email__id)
                        save_email.close()

                    re.compile = re_compile_our
                    msg = email.message_from_string(email__id)
                    re.compile = re_compile_orig

            except Exception as e:
                print e
                return ''

            if msg:
                email_dict = dict()
                email_dict.setdefault("email_id", hashlib.sha256(email__id).hexdigest())
                email_dict['Attachments'] = list()
                for k, v in msg.items():
                   email_dict[k] = v

                for part in msg.walk():
                    attachment, name, size, content_type, sha256_hash, sha1_hash, md5_hash = self.__email_parse_attachment(part)
                    if attachment:
                        email_dict['Attachments'].append({
                            'attachment': attachment,
                            'name': name,
                            'size': size,
                            'content_type': content_type,
                            'sha256': sha256_hash,
                            'sha1': sha1_hash,
                            'md5': md5_hash
                        })

                    elif part.get_content_type() == "text/plain":
                        email_dict['Body'] = part.get_payload(decode=True)
                    elif part.get_content_type() == "text/html":
                        email_dict['Body_html'] = part.get_payload(decode=True)

                if not kwargs.get('return_json'):
                    self.__email_print(email_dict, hashlib.sha256(email__id).hexdigest(), *args, **kwargs)

        return email_dict

    def parse_email_outlook(self, *args, **kwargs):

        if OUTLOOK_prsr:
            email_dict = dict()
            for email_id in kwargs.get('value'):
                if len(email_id) in (32, 40, 64): # md5, sha1, sha256
                    email_id = self.__download_email(email_id, *args, **kwargs)
                else:
                    email_id = dict()
                    for value in kwargs.get('value'):
                        email_id.update({value: value})
                try:
                    for email_hash in email_id:
                        if kwargs.get('download', False):

                            if kwargs.get('name'):
                                self.__name_auxiliar(args, kwargs)
                            else:
                                name = hashlib.sha256(email_id).hexdigest() + '.eml'

                            #save email
                            save_email = open(name, 'wb')
                            save_email.write(email_id[email_hash])
                            save_email.close()

                        msg = OUTLOOK(email_id[email_hash])
                        email_dict.update(msg.parse_outlook_email())

                        if not kwargs.get('return_json'):
                            self.__email_print(email_dict, email_id[email_hash], *args, **kwargs)

                except IOError:
                    return {'status':'Not OLE file'}

            if  kwargs.get('return_json'):
                return email_dict

        return {'status':'missed library'}

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

        simple_list = (
            'md5',
            'sha1',
            'sha256',
            'pe-imphash',
            'authentihash',
            'size',
            'filetype',
            'peid'
            'source_id',
            'first_seen',
            'last_seen',
            'scan_date',
            'score',
            'timestamp',
            'url',
            'pe-entry-point',
            'pe-machine-type'
        )

        for vt_file in jdata:
            if vt_file.get('response_code') and (vt_file['response_code'] == 0 or vt_file['response_code'] == -1):
                if jdata.get('verbose_msg'):
                    print '\n[!] Status : {verb_msg}\n'.format(verb_msg=vt_file['verbose_msg'])
                    return

            if kwargs.get('action') == 'file':
                self.simple_print(vt_file, simple_list)

                if vt_file.get('report'):
                    plist = [[]]
                    for key in vt_file['report']:
                        plist.append(
                        [key, 'True' if jdata[0]['report'][key][0] else 'False', jdata[0]['report'][key][1], jdata[0]['report'][key][2]])
                        pretty_print_special(plist, ['Vendor name', 'Detection', 'Version', 'Update'], False, False, kwargs.get('email_template'))

                if vt_file.get('link'):
                    print '\nLink : {link}'.format(link=vt_file['link'])

            elif kwargs.get('action') == 'url':

                for key in simple_list:
                    if vt_file.get(key):
                        try:
                            self.print_key(key, indent='\n\n', separator='')
                            print vt_file[key]
                        except UnicodeEncodeError:
                            print ''
                print '\nDetections:\n\t{positives}/{total} Positives/Total\n'.format(positives=vt_file.get('positives', 0), total=vt_file.get('total'))

                if vt_file.get('additional_info'):
                    print '\n\nAdditional info:'
                    plist = [[]]

                    for key in vt_file.get('additional_info'):
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

                        if plist != [[]]:
                            pretty_print_special(plist, ['Vendor name', 'Detection', 'Result'], False, False, kwargs.get('email_template'))

                        if vt_file.get('permalink'):
                            print '\nPermanent link : {link}\n'.format(link=vt_file['permalink'])

            if kwargs.get('dump'):
                jsondump(jdata, 'distribution_{date}'.format(
                    date=time.strftime("%Y-%m-%d"))
                )

    def behaviour(self, *args,  **kwargs):

        # ToDo
        """
        [u'behavior.processes',
         u'behavior.processtree',
         u'info.started',
         u'info.version',
         u'network.dns',
         u'network.hosts',
         u'network.http',
         u'network.tcp',
         u'network.udp']
        """

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
                pretty_print(jdata['info'], ['started', 'ended', 'duration', 'version'])

        if (kwargs.get('behavior_network') or 'behavior_network' in args) or kwargs.get('verbose'):

            if jdata.get('network'):
                print '\nHTTP requests\n'
                if 'behavior-network' in jdata and 'http' in jdata.get('network'):
                    if kwargs.get('return_json'):
                        return_json.update({'http':jdata['network']['http']})
                    else:
                        simple_list = (
                            'uri',
                            'host',
                            'port',
                            'path',
                            'method',
                            'user-agent',
                            'version',
                            'data'
                        )

                        for http in jdata['network']['http']:
                            self.simple_print(http, simple_list)
                            # if http.get('data')    : print 'data       : {0}'.format(http['data'].replace('\r\n\r\n', '\n\t').replace('\r\n','\n\t\t'))
                            if http.get('body'):
                                print '\tbody hex encoded:\n\t  {}\n'.format(http['body'].encode('hex'))

                if jdata['network'].get('hosts'):
                    if kwargs.get('return_json'):
                        return_json.update({'hosts': jdata['network']['hosts']})
                    else:
                        pretty_print(jdata['network']['hosts'], ['hosts'], False, False, kwargs.get('email_template'))

                if jdata['network'].get('dns'):
                    if kwargs.get('return_json'):
                        return_json.update({'dns': jdata['network']['dns']})
                    else:
                        print '\nDNS requests\n'
                        pretty_print(jdata['network']['dns'], ['ip', 'hostname'], False, False, kwargs.get('email_template'))


                simple_list = (
                    'tcp',
                    'upd'
                )
                for key in simple_list:
                    if jdata['network'].get(key):
                        if kwargs.get('return_json'):
                            return_json.update({key: jdata['network'][key]})
                        else:
                            print '\n{0} Connections'.format(key.upper())

                            unique = []

                            for block in jdata['network'][key]:
                                if not [block['src'],  block['dst'], block['sport'], block['dport']] in unique:
                                    unique.append([block['src'], block['dst'], block['sport'], block['dport']])
                            pretty_print_special(unique,   ['src', 'dst', 'sport', 'dport'], False, False, kwargs.get('email_template'))
                            del unique

        if (kwargs.get('behavior_process') or 'behavior_process' in args) or kwargs.get('verbose'):
            if jdata.get('behaviour'):
                print '\n[+] Behavior'
                print '\n[+] Processes'
                if kwargs.get('return_json'):
                        return_json.update({'processes': jdata['behavior']['processes']})
                else:
                    for process_id in jdata['behavior']['processes']:

                        plist = []

                        simple_list = (
                            'parent_id',
                            'process_id',
                            'process_name'
                        )
                        self.simple_print(process_id, keys)

                        if process_id.get('first_seen'):
                            print 'First Seen : {0}'.format(datetime.strptime(process_id['first_seen'][:14], '%Y%m%d%H%M%S').strftime('%Y:%m:%d %H:%M:%S'))

                        if process_id.get('calls'):
                            for process_part in process_id['calls']:
                                plist = [[]]
                                for key in process_part:
                                    if isinstance(process_part[key], list):
                                        if process_part[key] != [] and isinstance(process_part[key][0], dict):
                                            temp_list = []
                                            for part in process_part[key]:
                                                temp_list.append('\n'.join(map(lambda key_temp: '{key_temp}:{value}\n'.format(key_temp=key_temp, value=part[key_temp]), part.keys())))
                                            plist.append([key, ''.join(temp_list)])
                                            del temp_list
                                        else:
                                            plist.append([key, '\n'.join(process_part[key])])

                                    elif isinstance(process_part[key], dict):
                                        temp_list = []
                                        for part in process_part[key]:
                                            temp_list += map(lambda key_temp: '{key_temp}:{value}\n'.format(key_temp=key_temp, value=part[key_temp]), part.keys())
                                        plist.append([key, ''.join(temp_list)])
                                        del temp_list
                                    else:
                                        plist.append([key, process_part[key]])
                                pretty_print_special(plist, ['Name', 'Value'], [10, 50], False, kwargs.get('email_template'))
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

                simple_tt_list = (
                    'files',
                    'keys',
                    'mutexes'
                )

                for key in simple_tt_list:
                    if jdata['behavior']['summary'].get(key):
                        if kwargs.get('return_json'):
                                return_json.update({key:  jdata['behavior']['summary'][key]})
                        else:
                            if jdata['behavior']['summary']['files']:
                                self.simple_print(jdata['behavior']['summary'], [key])

        if kwargs.get('dump') is True:
            md5_hash = hashlib.md5(name).hexdigest()
            jsondump(jdata, md5_hash)

        if kwargs.get('return_json'):
            return return_json

    def detected_samples(self, jdata, *args,  **kwargs):

        if kwargs.get('samples') or 'samples' in args:
              kwargs['detected_downloaded_samples'] = \
              kwargs['undetected_downloaded_samples'] = \
              kwargs['detected_referrer_samples'] = \
              kwargs['undetected_referrer_samples'] = \
              kwargs['detected_communicated'] = \
              kwargs['undetected_communicated'] = True


        simple_list = (
            'detected_downloaded_samples',
            'undetected_downloaded_samples',
            'detected_communicating_samples',
            'undetected_communicating_samples',
            'detected_referrer_samples',
            'undetected_referrer_samples',
        )

        return_json = dict()

        for key in simple_list:
            if jdata.get(key) and ((kwargs.get(key) or 'key' in args) or kwargs.get('verbose')):
                if kwargs.get('return_json'):
                    return_json.update({key: jdata[key]})
                else:
                    self.print_key(key, indent='\n', separator='[+]')
                    print '\n'
                    pretty_print(sorted(jdata[key], key=methodcaller('get', 'date'), reverse=True), [
                                 'positives', 'total', 'date', 'sha256'], [15, 10, 20, 70], ['c', 'c', 'c', 'c'], kwargs.get('email_template'))

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

def create_config_file(paths):
    path = False
    conf_template = """
[vt]
apikey={}
type={}
intelligence={}
    """

    while True:

        print("[+] Config setup start")
        for key, value in paths.items():
            print("\t[{}] {}".format(key, value))
        path = raw_input("[+] Select option, where you want to create config, or type custom path:")
        path = path.strip()
        if path.isdigit():
            path = int(path)
        if path in paths:
            path = os.path.expanduser(paths[path])
        else:
            print("[-] Incorrect config path")
            continue
        apikey = raw_input("[+] Provide your apikey:")
        type_key = raw_input("[+] Your apikey is pubic/private:")
        intelligence = raw_input("[+] You have access to VT intelligence True/False:")
        try:
            tmp = open(path, "wb")
            tmp.write(conf_template.format(apikey.strip(), type_key.strip(), intelligence.strip()))
            tmp.close()
            print("[+] Config created at: {}".format(path))
            break
        except Exception as e:
            print(e)

    return path

def read_conf(config_file = False):
      vt_config = {'intelligence': False, 'apikey': '', 'type': False}
      paths = {
        0:'.vtapi',
        1:'vtapi.conf',
        2:'~/.vtapi',
        3:'~/vtapi.conf'
        }
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

      if not config_file:
          # config in home or in local dirrectory
          for conf in paths.values():
              if os.path.exists(os.path.expanduser(conf)):
                  config_file = conf
                  break

      if not config_file:
        config_file = create_config_file(paths)

      try:
        confpath = os.path.expanduser(config_file)
        if os.path.exists(confpath):
            config = ConfigParser.RawConfigParser()
            config.read(confpath)
            if config.has_section('vt'):
                vt_config = dict(config.items('vt'))
                if not vt_config.get('apikey'):
                  sys.exit(help)
        else:
            sys.exit('\nFile {0} don\'t exists\n'.format(confpath))

      except Exception:
          sys.exit(help)

      for key in vt_config:
          #backward compartibility
          if key == 'type':
              if vt_config[key].lower() == 'private':
                  apitype = True
              else:
                  apitype = False
              key  = 'api_type'
              vt_config[key] = apitype
              del vt_config['type']
              del apitype

          if vt_config[key] in ('False', 'True'):
              vt_config[key] = ast.literal_eval(vt_config[key])

      return vt_config

def main():

    vt_config = read_conf()

    if vt_config.get('timeout'):
        global req_timeout
        req_timeout = int(vt_config.get('timeout'))

    opt = argparse.ArgumentParser('value', description='Scan/Search/ReScan/JSON parse')
    opt.add_argument('-fi', '--file-info', action='store_true', help='Get PE file info, all data extracted offline, for work you need have installed PEUTILS library')
    opt.add_argument('-udb', '--userdb', action='store', help='Path to your userdb file, works with --file-info option only')
    opt.add_argument('value', nargs='*', help='Enter the Hash, Path to File(s) or Url(s)')
    opt.add_argument('-fs', '--file-search', action='store_true', help='File(s) search, this option, don\'t upload file to VirusTotal, just search by hash, support linux name wildcard, example: /home/user/*malware*, if file was scanned, you will see scan info, for full scan report use verbose mode, and dump if you want save already scanned samples')
    opt.add_argument('-f',  '--file-scan', action='store_true', dest='files',  help='File(s) scan, support linux name wildcard, example: /home/user/*malware*, if file was scanned, you will see scan info, for full scan report use verbose mode, and dump if you want save already scanned samples')
    opt.add_argument('-fr',  '--file-scan-recursive', action='store_true', dest='files',  help='Recursive dir walk, use this insted of --file-scan if you want recursive')
    opt.add_argument('-u',  '--url-scan', action='store_true', help='Url scan, support space separated list, Max 4 urls (or 25 if you have private api), but you can provide more urls, for example with public api,  5 url - this will do 2 requests first with 4 url and other one with only 1, or you can specify file filename with one url per line')
    opt.add_argument('-ur', '--url-report', action='store_true', help='Url(s) report, support space separated list, Max 4 (or 25 if you have private api) urls, you can use --url-report --url-scan options for analysing url(s) if they are not in VT data base, read previev description about more then max limits or file with urls')
    opt.add_argument('-d', '--domain-info',   action='store_true', dest='domain', help='Retrieves a report on a given domain (PRIVATE API ONLY! including the information recorded by VirusTotal\'s Passive DNS infrastructure)')
    opt.add_argument('-i', '--ip-info', action='store_true', dest='ip', help='A valid IPv4 address in dotted quad notation, for the time being only IPv4 addresses are supported.')
    opt.add_argument('-w', '--walk', action='store_true', default=False, help='Work with domain-info, will walk throuth all detected ips and get information, can be provided ip parameters to get only specific information')
    opt.add_argument('-s', '--search', action='store_true',  help='A md5/sha1/sha256 hash for which you want to retrieve the most recent report. You may also specify a scan_id (sha256-timestamp as returned by the scan API) to access a specific report. You can also specify a space separated list made up of a combination of hashes and scan_ids Public API up to 4 items/Private API up to 25 items, this allows you to perform a batch request with one single call.')
    opt.add_argument('-si', '--search-intelligence', action='store_true', help='Search query, help can be found here - https://www.virustotal.com/intelligence/help/')
    opt.add_argument('-et', '--email-template', action='store_true', help='Table format template for email')

    if vt_config.get('api_type'):
        allinfo_opt = opt.add_argument_group('All information related')
        allinfo_opt.add_argument('-rai', '--report-all-info', action='store_true', help='If specified and set to one, the call will return additional info, other than the antivirus results, on the file being queried. This additional info includes the output of several tools acting on the file (PDFiD, ExifTool, sigcheck, TrID, etc.), metadata regarding VirusTotal submissions (number of unique sources that have sent the file in the past, first seen date, last seen date, etc.), and the output of in-house technologies such as a behavioural sandbox.')
        allinfo_opt.add_argument('-itu', '--ITW-urls', action='store_true', help='In the wild urls')
        allinfo_opt.add_argument('-cw', '--compressedview', action='store_true', help='Contains information about extensions, file_types, tags, lowest and highest datetime, num children detected, type, uncompressed_size, vhash, childrens')
        allinfo_opt.add_argument('-dep', '--detailed-email-parents', action='store_true', help='Contains information about emails, as Subject, sender, receiver(s), full email, and email hash to download it')
        allinfo_opt.add_argument('-eo', '--email-original', default=False, action='store_true', help='Will retreive original email and process it')
        allinfo_opt.add_argument('-snr', '--snort', action='store_true', help='Get Snort results')
        allinfo_opt.add_argument('-srct', '--suricata', action='store_true', help='Get Suricata results')
        allinfo_opt.add_argument('-tir', '--traffic-inspection', action='store_true', help='Get Traffic inspection info')
        allinfo_opt.add_argument('-wir', '--wireshark-info', action='store_true', help='Get Wireshark info')
        allinfo_opt.add_argument('-rbgi', '--rombios-generator-info', action='store_true', help='Get RomBios generator info')
        allinfo_opt.add_argument('-rbi', '--rombioscheck-info', action='store_true', help='Get RomBiosCheck info')
        allinfo_opt.add_argument('-agi', '--androidguard-info', action='store_true', help='Get AndroidGuard info')
        allinfo_opt.add_argument('-dbc', '--debcheck-info', action='store_true', help='Get DebCheck info, also include ios IPA')

    opt.add_argument('-ac', '--add-comment', action='store_true', help='The actual review, you can tag it using the "#" twitter-like syntax (e.g. #disinfection #zbot) and reference users using the "@" syntax (e.g. @VirusTotalTeam). supported hashes MD5/SHA1/SHA256')
    opt.add_argument('-gc', '--get-comments', action='store_true', help='Either a md5/sha1/sha256 hash of the file or the URL itself you want to retrieve')

    if vt_config.get('api_type'):
        opt.add_argument('--get-comments-before', action='store', dest='date', default=False, help='A datetime token that allows you to iterate over all comments on a specific item whenever it has been commented on more than 25 times. Token format 20120725170000 or 2012-07-25 17 00 00 or 2012-07-25 17:00:00')
    opt.add_argument('-v', '--verbose', action='store_true', dest='verbose', help='Turn on verbosity of VT reports')
    opt.add_argument('-j', '--dump',    action='store_true', help='Dumps the full VT report to file (VTDL{md5}.json), if you (re)scan many files/urls, their json data will be dumped to separetad files')
    opt.add_argument('--csv', action='store_true', default = False, help='Dumps the AV\'s detections to file (VTDL{scan_id}.csv)')
    opt.add_argument('-rr', '--return-raw', action='store_true', default = False, help='Return raw json, in case if used as library and want parse in other way')
    opt.add_argument('-rj', '--return-json', action='store_true', default = False, help='Return json with parts activated, for example -p for pasive dns, etc')
    opt.add_argument('-V', '--version', action='store_true', default = False,  help='Show version and exit')

    rescan = opt.add_argument_group('Rescan options')
    rescan.add_argument('-r', '--rescan', action='store_true', help='Allows you to rescan files in VirusTotal\'s file store without having to resubmit them, thus saving bandwidth, support space separated list, MAX 25 hashes, can be local files, hashes will be generated on the fly, support linux wildmask')
    if vt_config.get('api_type'):
        rescan.add_argument('--delete',  action='store_true',help='A md5/sha1/sha256 hash for which you want to delete the scheduled scan')
        rescan.add_argument('--date', action='store', dest='date',help='A Date in one of this formats (example: 20120725170000 or 2012-07-25 17 00 00 or 2012-07-25 17:00:00) in which the rescan should be performed. If not specified the rescan will be performed immediately.')
        rescan.add_argument('--period', action='store',help='Period in days in which the file should be rescanned. If this argument is provided the file will be rescanned periodically every period days, if not, the rescan is performed once and not repated again.')
        rescan.add_argument('--repeat', action='store',help='Used in conjunction with period to specify the number of times the file should be rescanned. If this argument is provided the file will be rescanned the given amount of times, if not, the file will be rescanned indefinitely.')

    if vt_config.get('api_type'):
        scan_rescan = opt.add_argument_group('File scan/Rescan shared options')
        scan_rescan.add_argument('--notify-url', action='store', help='An URL where a POST notification should be sent when the scan finishes.')
        scan_rescan.add_argument('--notify-changes-only', action='store_true', help='Used in conjunction with --notify-url. Indicates if POST notifications should be sent only if the scan results differ from the previous one.')

    domain_opt = opt.add_argument_group(
        'Domain/IP shared verbose mode options, by default just show resolved IPs/Passive DNS')
    domain_opt.add_argument('-wh',  '--whois', action='store_true', default=False, help='Whois data')
    domain_opt.add_argument('-wht',  '--whois-timestamp', action='store_true', default=False, help='Whois timestamp')
    domain_opt.add_argument('-pdns',  '--resolutions', action='store_true', default=False, help='Passive DNS resolves')
    domain_opt.add_argument('--asn', action='store_true', default=False, help='ASN number')
    domain_opt.add_argument('-aso', '--as-owner', action='store_true', default=False, help='AS details')
    domain_opt.add_argument('--country', action='store_true', default=False, help='Country')
    domain_opt.add_argument('--subdomains', action='store_true', default=False, help='Subdomains')
    domain_opt.add_argument('--domain-siblings', action='store_true', default=False, help='Domain siblings')
    domain_opt.add_argument('-cat','--categories', action='store_true', default=False, help='Categories')
    domain_opt.add_argument('-alc', '--alexa-cat', action='store_true', default=False, help='Alexa category')
    domain_opt.add_argument('-alk', '--alexa-rank', action='store_true', default=False, help='Alexa rank')
    domain_opt.add_argument('-opi', '--opera-info', action='store_true', default=False, help='Opera info')
    domain_opt.add_argument('--drweb-cat', action='store_true', default=False, help='Dr.Web Category')
    domain_opt.add_argument('-adi', '--alexa-domain-info', action='store_true', default=False, help='Just Domain option: Show Alexa domain info')
    domain_opt.add_argument('-wdi', '--wot-domain-info', action='store_true', default=False, help='Just Domain option: Show WOT domain info')
    domain_opt.add_argument('-tm',  '--trendmicro', action='store_true', default=False, help='Just Domain option: Show TrendMicro category info')
    domain_opt.add_argument('-wt',  '--websense-threatseeker', action='store_true', default=False, help='Just Domain option: Show Websense ThreatSeeker category')
    domain_opt.add_argument('-bd',  '--bitdefender', action='store_true', default=False, help='Just Domain option: Show BitDefender category')
    domain_opt.add_argument('-wd',  '--webutation-domain', action='store_true', default=False, help='Just Domain option: Show Webutation domain info')
    domain_opt.add_argument('-du',  '--detected-urls', action='store_true', default=False, help='Just Domain option: Show latest detected URLs')
    domain_opt.add_argument('--pcaps', action='store_true', default=False, help='Just Domain option: Show all pcaps hashes')
    domain_opt.add_argument('--samples', action='store_true', help='Will activate -dds -uds -dc -uc -drs -urs')
    domain_opt.add_argument('-dds', '--detected-downloaded-samples',   action='store_true', default=False, help='Domain/Ip options: Show latest detected files that were downloaded from this ip')
    domain_opt.add_argument('-uds', '--undetected-downloaded-samples', action='store_true', default=False, help='Domain/Ip options: Show latest undetected files that were downloaded from this domain/ip')
    domain_opt.add_argument('-dc',  '--detected-communicated', action='store_true', default=False, help='Domain/Ip Show latest detected files that communicate with this domain/ip')
    domain_opt.add_argument('-uc',  '--undetected-communicated', action='store_true', default=False, help='Domain/Ip Show latest undetected files that communicate with this domain/ip')
    domain_opt.add_argument('-drs', '--detected-referrer-samples', action='store_true', default=False, help='Undetected referrer samples')
    domain_opt.add_argument('-urs', '--undetected-referrer-samples', action='store_true', default=False, help='Undetected referrer samples')

    email_opt = opt.add_argument_group('Process emails')
    email_opt.add_argument('-pe', '--parse-email', action='store_true', default=False, help='Parse email, can be string or file')
    email_opt.add_argument('-esa', '--save-attachment', action='store', default=False, help='Save email attachment, path where to store')
    email_opt.add_argument('-peo', '--parse-email-outlook', action='store_true', default=False, help='Parse outlook .msg, can be string or file')

    if vt_config.get('api_type'):
        behaviour = opt.add_argument_group('Behaviour options')
        behaviour.add_argument('--behaviour', action='store_true',  help='The md5/sha1/sha256 hash of the file whose dynamic behavioural report you want to retrieve.\
            VirusTotal runs a distributed setup of Cuckoo sandbox machines that execute the files we receive. Execution is attempted only once, upon\
            first submission to VirusTotal, and only Portable Executables under 10MB in size are ran. The execution of files is a best effort process,\
            hence, there are no guarantees about a report being generated for a given file in our dataset. a file did indeed produce a behavioural report,\
            a summary of it can be obtained by using the file scan lookup call providing the additional HTTP POST parameter allinfo=1. The summary will\
            appear under the behaviour-v1 property of the additional_info field in the JSON report.This API allows you to retrieve the full JSON report\
            of the files execution as outputted by the Cuckoo JSON report encoder.')
        behaviour.add_argument('-bn', '--behavior-network', action='store_true', help='Show network activity')
        behaviour.add_argument('-bp', '--behavior-process', action='store_true', help='Show processes')
        behaviour.add_argument('-bs', '--behavior-summary', action='store_true', help='Show summary')

    if vt_config.get('api_type') or vt_config.get('intelligence'):
        downloads = opt.add_argument_group('Download options')
        downloads.add_argument('-dl', '--download',  dest='download', action='store_const', const='file', default=False, help='The md5/sha1/sha256 hash of the file you want to download or txt file with .txt extension, with hashes, or hash and type, one by line, for example: hash,pcap or only hash. Will save with hash as name, can be space separated list of hashes to download')
        downloads.add_argument('-nm', '--name',  action='store', default="", help='Name with which file will saved when download it')
        downloads.add_argument('-dt', '--download-threads',  action='store', default=5, type=int, help='Number of simultaneous downloaders')

    if vt_config.get('api_type'):
        more_private = opt.add_argument_group('Additional options')
        more_private.add_argument('--pcap', dest='download', action='store_const', const='pcap', default=False, help='The md5/sha1/sha256 hash of the file whose network traffic dump you want to retrieve. Will save as hash.pcap')
        more_private.add_argument('--clusters', action='store_true',help='A specific day for which we want to access the clustering details, example: 2013-09-10')
        # more_private.add_argument('--search-by-cluster-id', action='store_true', help=' the id property of each cluster allows users to list files contained in the given cluster, example: vhash 0740361d051)z1e3z 2013-09-10')
        more_private.add_argument('--distribution-files', action='store_true', help='Timestamps are just integer numbers where higher values mean more recent files. Both before and after parameters are optional, if they are not provided the oldest files in the queue are returned in timestamp ascending order.')
        more_private.add_argument('--distribution-urls', action='store_true', help='Timestamps are just integer numbers where higher values mean more recent urls. Both before and after parameters are optional, if they are not provided the oldest urls in the queue are returned in timestamp ascending order.')

    if vt_config.get('api_type'):
        dist = opt.add_argument_group('Distribution options')
        dist.add_argument('--before', action='store', help='File/Url option. Retrieve files/urls received before the given timestamp, in timestamp descending order.')
        dist.add_argument('--after', action='store', help='File/Url option. Retrieve files/urls received after the given timestamp, in timestamp ascending order.')
        dist.add_argument('--reports', action='store_true', default=False, help='Include the files\' antivirus results in the response. Possible values are \'true\' or \'false\' (default value is \'false\').')
        dist.add_argument('--limit', action='store', help='File/Url option. Retrieve limit file items at most (default: 1000).')
        dist.add_argument('--allinfo', action='store_true', help='will include the results for each particular URL scan (in exactly the same format as the URL scan retrieving API). If the parameter is not specified, each item returned will onlycontain the scanned URL and its detection ratio.')

    options = opt.parse_args()

    if options.version:
        print 'Version:', __version__
        print 'Current path:', os.path.dirname(os.path.realpath(__file__))
        sys.exit()

    options = vars(options)

    vt = vtAPI(vt_config.get('apikey'))

    options.update(vt_config)

    if options.get('date', ""):
        options['date'] = options['date'].replace( '-', '').replace(':', '').replace(' ', '')

    if options.get('files') or options.get('file_scan_recursive'):
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

        if options.get('date', ""):

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
            vt.getIP(**options)

        else:
            vt.getDomain(**options)

    elif options.get('report_all_info'):
        options.update({'allinfo': 1})
        vt.getReport(**options)

    elif (options.get('search') or options.get('search_intelligence')) and \
          not options['domain'] and not options['ip'] and not options['url_scan'] and \
          not options['url_report']:
        options.update({'allinfo': 0})
        vt.getReport(**options)

    elif options.get('download') and not (options.get('parse_email') or options.get('parse_email_outlook')):
        vt.download(**options)

    elif options.get('parse_email'):
        vt.parse_email(**options)

    elif options.get('parse_email_outlook'):
        vt.parse_email_outlook(**options)

    elif options.get('behaviour'):
        vt.behaviour(**options)

    elif options.get('distribution_files'):
        options.update({'action': 'file'})
        vt.distribution(**options)

    elif options.get('distribution_urls'):
        options.update({'action': 'url'})
        vt.distribution(**options)

    elif options.get('add_comment') and len(options['value']) == 2:
        options.update({'action': 'add'})
        vt.comment(**options)

    elif options.get('get_comments'):
        options.update({'action': 'get'})
        vt.comment(**options)

    elif options.get('clusters'):
        vt.clusters(**options)

    # elif options.search_by_cluster_id:
    #    vt.clusters(options.value, options.dump, True)

if __name__ == '__main__':
    main()
