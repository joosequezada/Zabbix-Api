#!/usr/bin/env python3

import requests
import json

url = "http://192.168.33.10/api_jsonrpc.php"

headers = {'Content-Type': 'application/json'}


def user_api_login(username, password, version="2.0"):

    login = json.dumps({

        "jsonrpc": version,
        "method": "user.login",
        "params": {
            "user": username,
            "password": password
        },
        "id": 1,
    }
    )

    r = requests.get(url, headers=headers, data=login)
    info = r.json()
    return info["result"]


def user_api_logout(auth_code, version="2.0"):

    logout = json.dumps({

        "jsonrpc": version,
        "method": "user.logout",
        "params": [],
        "id": 1,
        "auth": auth_code
    })

    r = requests.get(url, headers=headers, data=logout)
    info = r.json()
    return info["result"]


def get_zabbix_hosts(auth_code):

    data = json.dumps({

        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {
            "output": [
                  "extend",
                  "groupid",
                  "name",
            ]
        },
        "id": 2,
        "auth": auth_code,
    })

    r = requests.get(url, headers=headers, data=data)
    info = r.json()
    return info


def get_zabbix_hostgroup(auth_code):

    data = json.dumps({

        "jsonrpc": "2.0",
        "method": "hostgroup.get",
        "params": {
            "output":
                "extend",
        },
        "auth": auth_code,
        "id": 1
    })

    r = requests.get(url, headers=headers, data=data)
    info = r.json()
    return info


auth_code = user_api_login(username="zabbix-api", password="zabbix")
all_hosts = get_zabbix_hosts(auth_code)
all_hostgroups = get_zabbix_hostgroup(auth_code)
auth_logout = user_api_logout(auth_code)

print("Authentication Code: {} \n".format(auth_code))
print("User logout: {} \n".format(auth_logout))

for host in all_hosts['result']:
    print("Host ID:", host['hostid'], "\tHost name:", host['name'])

for group in all_hostgroups['result']:
    print("Group ID:", group['groupid'], "\tGroup name:", group['name'])

