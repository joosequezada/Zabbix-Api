#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json


class ZabbixAPI:

    def __init__(self,
                 server,
                 username,
                 password,
                 headers={'Content-Type': 'application/json'},
                 version="2.0"
                 ):

        self.url = "http://" + server + "/api_jsonrpc.php"
        self.headers = headers
        self.username = username
        self.password = password
        self.version = version

    def login(self):

        login = json.dumps({

            "jsonrpc": self.version,
            "method": "user.login",
            "params": {
                "user": self.username,
                "password": self.password
            },
            "id": 1,
        }
        )

        r = requests.get(self.url, headers=self.headers, data=login)
        info = r.json()
        return info

    def logout(self, auth_code):
        self.auth_code = auth_code

        logout = json.dumps({

            "jsonrpc": self.version,
            "method": "user.logout",
            "params": [],
            "id": 1,
            "auth": self.auth_code
        })

        r = requests.get(self.url, headers=self.headers, data=logout)
        info = r.json()
        return info["result"]

    def get_hosts(self, auth_code):

        self.auth_code = auth_code

        data = json.dumps({
            "jsonrpc": self.version,
            "method": "host.get",
            "params": {
                "output": [
                      "extend",
                      "groupid",
                      "name",
                ]
            },
            "id": 2,
            "auth": self.auth_code,
        })

        r = requests.get(self.url, headers=self.headers, data=data)
        info = r.json()
        return info['result']

    def get_hostgroups(self, auth_code):
        self.auth_code = auth_code

        data = json.dumps({

            "jsonrpc": self.version,
            "method": "hostgroup.get",
            "params": {
                "output":
                    "extend",
            },
            "auth": self.auth_code,
            "id": 1
        })

        r = requests.get(self.url, headers=self.headers, data=data)
        info = r.json()
        return info

    def host_interface(self, auth_code, hostid):
        self.auth_code = auth_code
        self.hostid = hostid

        data = json.dumps({

            "jsonrpc": self.version,
            "method": "hostinterface.get",
            "params": {
                "output": "extend",
                "hostids": self.hostid,
            },
            "auth": self.auth_code,
            "id": 1,
        })

        r = requests.get(self.url, headers=self.headers, data=data)
        info = r.json()
        return info['result']


zabbix = ZabbixAPI(server="192.168.33.10",
                   username="zabbix-api",
                   password="zabbix")

api_info = zabbix.login()
auth_code = api_info.get('result')
all_hosts = zabbix.get_hosts(auth_code)
all_hostgroups = zabbix.get_hostgroups(auth_code)

print("API Version: {version}\
       \nAuthentication Code: {code}\
       \nSession Id: {id}\n".format(code=api_info.get('result'),
                                    version=api_info.get('jsonrpc'),
                                    id=api_info.get('id')))
count = []
for host in all_hosts:
    count.append(host['name'])

print("Total Hosts: {total} \n".format(total=len(count)))


for host in all_hosts:
    hostid = host['hostid']
    interfaces = zabbix.host_interface(auth_code, hostid)
    for interface in interfaces:
        if interface['useip'] == '1':
            print("Host Id:", host['hostid'],
                  "\tHost name:", host['name'],
                  "Interface: ", interface['ip'])
        else:
            print("Host Id:", host['hostid'],
                  "\tHost name:", host['name'],
                  "Interface: ", interface['dns'])

print(" ")

for group in all_hostgroups['result']:
    print("Group Id:", group['groupid'], "\tGroup name:", group['name'])

print(" ")

auth_logout = zabbix.logout(auth_code)
print("User logout: {} \n".format(auth_logout))
