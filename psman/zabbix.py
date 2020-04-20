#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""zabbix to interface with zabbix via pyzabbix.

"""

import argparse
import inspect
import re
import urllib3

from pyzabbix import ZabbixAPI

ZABBIX_URL = ''
ZABBIX_USER = ''
ZABBIX_PW = ''

class Zabbix:
    def __init__(self, url, user, pw):
        self.zapi = ZabbixAPI(url)
        self.zapi.session.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        try:
            self.zapi.login(user, pw)
        except:
            print("oops, login failed")

    def getitemValue(self, itemid, hostids='13286'):
        result = self.zapi.item.get(hostids=hostids,
                                    filter={"itemid": itemid},
                                    output=["itemid",
                                            "name",
                                            "lastvalue",
                                            "lastclock"])
        print(result)
        (clock, value) = ('', '')
        if len(result):
            (clock, value) = (result[0]['lastclock'], result[0]['lastvalue'])
        print (clock, value)
        return  (clock, value)

    def getitemHistoryValue(self, itemid, hostids,
                            time_from, time_till, history=3):
        """
        history
        Possible values:
        0 - numeric float;
        1 - character;
        2 - log;
        3 - numeric unsigned;
        4 - text.
        """
        result = self.zapi.history.get(hostids=hostids,
                                       filter={"itemid": itemid},
                                       time_from=time_from,
                                       time_till=time_till,
                                       output='extend',
                                       history=history)
        return  result

    def getitemHistoryAvg(self, itemid, hostids,
                          time_from, time_till, history=3):
        """
        history
        Possible values:
        0 - numeric float;
        1 - character;
        2 - log;
        3 - numeric unsigned;
        4 - text.
        """
        result = self.zapi.history.get(hostids=hostids,
                                       filter={"itemid": itemid},
                                       time_from=time_from,
                                       time_till=time_till,
                                       output='extend',
                                       history=history)
        avg = 0
        if len(result):
            values = [int(i['value']) for i in result]
            avg = sum(values)/len(values)
        return  avg

      #@staticmethod
    def getitemIDbyName(self, name, hostids='13286'):
        result = self.zapi.item.get(hostids=hostids,
                                    filter={"name": name},
                                    output=["itemid", "lastvalue"])
        print (result)
        item_id = ''
        if len(result):
            item_id = result[0]['itemid']
        return  item_id

    def getitemIDbyKey(self, name, hostids='13286'):
        result = self.zapi.item.get(hostids=hostids,
                                    filter={"key_": name},
                                    output=["itemid", "lastvalue"])
        item_id = ''
        if len(result):
            item_id = result[0]['itemid']
        return  item_id

    def list_hosts(self):
        prog = re.compile(r"^vm:(\w+)-(\w+)-(\w+)-(\w+)$")
        hosts = [[h["hostid"], h["name"]] for h in
                 self.zapi.host.get(output=["hostid", "name"])
                 if prog.match(h["name"])]
        #for h in hosts:
        #  print (h)
        return hosts

    def get_hostidbyname(self, h):
        hosts = self.zapi.host.get(output=["id"], search={"name":h})
        #print (hosts)
        if len(hosts) == 1:
            return hosts[0]["hostid"]
        else:
            return None
        #print (hosts)
    def get_hostidbyserial(self, s):
        hosts = self.zapi.host.get(output=["id"], searchInventory={"serialno_a":s})
        if len(hosts) == 1:
            return hosts[0]["hostid"]
        else:
            return None
  
    def inventory_update(self, host, f, v):
        #h = self.get_hostidbyname(host)
        h = self.get_hostidbyserial(host)
        if h:
            print ("updating inventory for host:" + host)
            self.zapi.host.update(hostid=h["hostid"],
                                  inventory={"location": "test"})
        else:
            print ("host:"+host+" is not found")
  


class Main(Zabbix):
    def __init__(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        for name in dir(self):
            if not name.startswith("_"):
                p = subparsers.add_parser(name)
                method = getattr(self, name)
                argnames = inspect.getargspec(method).args[1:]
                for argname in argnames:
                    p.add_argument(argname)
                p.set_defaults(func=method, argnames=argnames)
        self.args = parser.parse_args()
        
        # initialize zabbix object
        Zabbix.__init__(self, ZABBIX_URL, ZABBIX_USER, ZABBIX_PW)

    def __call__(self):
        try:
            a = self.args
            callargs = [getattr(a, name) for name in a.argnames]
            return self.args.func(*callargs)

        except Exception as err:
            print (str(err))


if __name__ == "__main__":
    main = Main()
    main()
