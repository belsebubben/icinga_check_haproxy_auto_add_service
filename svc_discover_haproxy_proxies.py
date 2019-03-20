#!/usr/bin/python
import sys
import csv
import os
import logging
import simplejson as json
import urllib
import requests
from time import sleep, strptime, localtime, strftime
#import pdb
from pprint import pformat
sys.path.insert(0, '/usr/lib64/nagios/plugins/')
from icinga_autolib import *
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

DEBUG = False

PROXIESURL =  'http://%s:9001/;csv;norefresh'
HASTATSURL = 'http://%s:9001/haproxy?stats'

# checks template and settings
SVCVARS = {}
SVCDISCOVERTAG = {'svcdiscovery': True}
SVCVARS.update(SVCDISCOVERTAG)
TEMPLATENAMES = ['haproxy-status']
SERVICEPREFIX = 'haproxy-'

# Logging
LOGFORMAT = '%(asctime)s %(levelname)s: %(message)s'
svclogger = logging.getLogger("svc.svcdiscover")
loglevel = logging.INFO
if DEBUG:
    loglevel = logging.DEBUG
    LOGFORMAT = '%(asctime)s %(levelname)s: %(message)s line: %(lineno)d'

svcsvclogger = logging.StreamHandler(stream=sys.stderr)
svclogger.setLevel(loglevel)
formatter = logging.Formatter(LOGFORMAT)
svcsvclogger.setFormatter(formatter)
svclogger.addHandler(svcsvclogger)
svclogger.debug("Debugging enabled")
logger.addHandler(svcsvclogger)

plugin_output=""
exit_status=0
reload_required=0
def update_exitstat(code, text, reload_counter):
    global exit_status, plugin_output, reload_required
    reload_required += reload_counter
    exit_status=(max(exit_status,code))
    plugin_output += text + '; '

def flush_services(server, services):
    '''flush_services(nameofhost, svcdata) will return a list of configured
    services and also remove the ones not existing but configured to be
    monitored
    '''
    try:
        autosvcs = [svc['attrs']['name'] for svc in get_host_services(server)\
                if svc['attrs']['vars'] and 'svcdiscovery' in svc['attrs']['vars'].keys()]
        #the machines services as they are presently configured in icinga
        hostservices = set([str(svc) for svc in autosvcs if SERVICEPREFIX in svc])
    except:
        svclogger.warning('Failed service list processing for %s: %s' % (host, sys.exc_info()))

    services_to_remove = hostservices - services
    services_to_add = services - hostservices
    logger.debug('Services to add %s\n\n' % services_to_add)
    logger.debug('Services to remove %s\n\n' % services_to_remove)

    for svc in services_to_remove:
        logger.debug('Removing service:%s\n' % svc)
        delete_service(server, svc)
    return services_to_add

def create_service(server, svcdef, svc):
    putlocation = APIHOST + SVCMANAGEURL % (server, svc)
    svcdef = json.dumps(svcdef)
    svclogger.debug('\n# Adding service: %s; location: %s\n' % (svc, putlocation))
    resp = put_json(putlocation, svcdef)
    if resp.status_code not in (200,201):
        update_exitstat(1,'Error from %s; code %s: %s' % (putlocation, resp.status_code, resp._content), 0)
    else:
        update_exitstat(0, 'Created service: %s at: %s' % (svc, server), 1)
    svclogger.debug('response from %s: %s' %(putlocation, resp))

def add_services(server, zone, services_to_add):
    for svc in services_to_add:
        svcvars = SVCVARS
        svcvars.update({'updated': strftime('%Y-%m-%d %H:%M:%S')})
        svcvars.update({'hastats_proxy': svc})
        svcvars.update({'hastats_url': HASTATSURL % server})
        svcdef = {'templates': TEMPLATENAMES, 'attrs': {'zone': zone,'vars': svcvars}}
        create_service(server, svcdef, svc)

def get_services(server):
    url = PROXIESURL % server
    try:
        urldata = urllib.urlopen(url)
    except:
        update_exitstat(2, 'Error getting data from %s: %s' % (url, sys.exc_info()), 0)
        svclogger.fatal('Error getting data from %s: %s' % (url, sys.exc_info() ))
    csvdata = csv.reader(urldata)
    services = set([SERVICEPREFIX + svc[0] for svc in csvdata])
    services.discard('haproxy-# pxname')
    svclogger.debug('services: %s' % services)
    return services

def main():
    server = sys.argv[1]
    zone = get_host_zone(server)
    services = get_services(server)
    services_to_add = flush_services(server,services)
    add_services(server, zone, services_to_add)
    check_result_post(exit_status, plugin_output, reload_required > 0)

if __name__ in '__main__':
    main()
