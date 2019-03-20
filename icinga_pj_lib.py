#!/usr/bin/python
import sys
import os
import atexit
import subprocess
import logging
import simplejson as json
import urllib
import requests
from time import asctime
from pprint import pformat
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

DEBUG = True

POST_HEADERS = {'content-type': 'application/json', 'Accept': 'application/json'}
APIHOST = 'https://icinga.tld.com:5665'
APIOBJURL = '/v1/objects/'
APIHOSTURL = '/v1/objects/hosts/'
APIACTIONSURL = '/v1/actions/'
RESULTHOST = 'dummy.master'
RESULTSVC = 'svcdiscovery'
RESULTPOSTURL = '/v1/actions/process-check-result?service=%s!%s'
APIUSER = 'root'
APIPW = 'SECRET'
SVCMANAGEURL = '/v1/objects/services/%s!%s'


#LOGFORMAT = '%(asctime)s %(levelname)s: %(message)s'
logger = logging.getLogger(__name__)

# Ignore SSL for now
SSL_VERIFY = False 

def get_json(location):
    """
    Performs a GET using the passed URL location
    """
    try:
        r = requests.get(location, auth=(APIUSER, APIPW), verify=SSL_VERIFY)
        return r.json()
    except:
        logger.warning('Failed to get data from %s : %s' % (location, sys.exc_info()))
        update_exitstat(2, 'Error in get request from: %s; exc: %s' % (location, sys.exc_info()))

def del_json(location):
    """
    Performs a delete using the passed URL location
    """
    try:
        r = requests.delete(location, auth=(APIUSER, APIPW), verify=SSL_VERIFY, headers=POST_HEADERS)
        return r
    except:
        logger.warning('Failed to delete data from %s : %s' % (location, sys.exc_info()))
        update_exitstat(2, 'Error in delete request from: %s; exc: %s' % (location, sys.exc_info()))

def post_json(location, json_data):
    """
    Performs a POST and passes the data to the URL location
    """
    result = requests.post(
    location,
    data=json_data,
    auth=(APIUSER, APIPW),
    verify=SSL_VERIFY,
    headers=POST_HEADERS)

    if result.status_code not in (200,201):
        logger.warning('Error code %s: ; from: %s; data: %s, %s' % ( result.status_code, location, json_data, result._content ) )
        update_exitstat(2, 'Error code %s: ; from: %s; data: %s, %s' % ( result.status_code, location, json_data, result._content ))
    return result.json()

def put_json(location, json_data):
    """
    Performs a POST and passes the data to the URL location
    """
    try:
        result = requests.put(
        location,
        data=json_data,
        auth=(APIUSER, APIPW),
        verify=SSL_VERIFY,
        headers=POST_HEADERS)
    except:
        logger.warning('Failed to put data from %s : %s' % (location, sys.exc_info()))
        update_exitstat(2, 'Error in put request from: %s; exc: %s' % (location, sys.exc_info()))
        return False
    return result

def create_service(host, svcname, svcdata):
    svcdata = json.dumps(svcdata) # {'templates': TEMPLATENAMES, 'attrs': {'zone': checkzone,'vars': svcvars }}
    putlocation = APIHOST + SVCMANAGEURL % (host, svc)
    resp = put_json(putlocation, svcdata)
    if resp.status_code not in (200,201):
        logger.warning('Error from %s; code %s: %s' % ( putlocation, resp.status_code, resp._content ))
        return False
    return True

def delete_service(host, svcname):
    delurl = APIHOST + SVCMANAGEURL % (host, svcname) + '?cascade=1'
    delresp = del_json(delurl)
    if delresp.status_code > 299 or delresp.status_code < 200:
        logger.warning('Failed to delete from %s; %s' % (delurl, delresp.content))
        return False
    logger.info('Service %s delete from %s: %s\n' %(svcname, host, delresp))
    return True

def restart_icinga():
    resp = post_json(APIHOST + APIACTIONSURL + 'restart-process?pretty=1', '')

def check_result_post(exit_status, plugin_output, needreload=False):
    if not plugin_output:
        plugin_output = "Success! at %s" % asctime()
    resultdata = { "exit_status": exit_status, "plugin_output": plugin_output, "performance_data": [ "" ], "check_source": RESULTHOST }
    url = APIHOST + RESULTPOSTURL % (RESULTHOST, RESULTSVC)
    #result = post_json(url, json.dumps(resultdata))
    #logger.debug("posting status of discovery to connected service %s!%s in icinga: %s" % (RESULTHOST,RESULTSVC,result))
    print plugin_output
    if needreload:
        restart_icinga()
    sys.exit(exit_status)

def get_attr(obj_name, obj_type, attr_name):
    ''' Get hold of an attribute for a config object
    /v1/objects/<type> URL endpoint. <type> ->  plural name object type
    imit the output to specific attributes using the attrs URL parameter:
    filter -> ?host=localhost
    '''
    url = APIHOST + APIOBJURL + obj_type + '/' + obj_name
    if attr_name:
        url = APIHOST + APIOBJURL + obj_type + '/' + obj_name + '?' + urllib.urlencode({ 'attrs' : attr_name})
    response = get_json(url)
    logger.debug("getting attr from %s: %s " % (url, response))
    return response

def get_host_zone(hostname):
    try:
        return get_attr(hostname, 'hosts', 'zone')['results'][0]['attrs']['zone']
    except KeyError:
        return None
    
def get_host_services(hostname):
    url =  APIHOST + APIOBJURL + 'services' + '?' + urllib.urlencode({ 'filter' : 'host.name=="%s"' % hostname})
    return get_json(url)['results']
    
if __name__ in '__main__':
	main()

