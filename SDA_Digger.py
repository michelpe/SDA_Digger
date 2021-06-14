"""Copyright (c) 2021 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""
import sys
import getopt
import os
import re
import DNAC_Connector
import json
import AnalysisCore
import ParseCommands
import Analysis
from getpass import getpass
import ParseBundle

edge_cmd_list = [["show lisp session", "show lisp instance * ethernet database", "sh lisp instance-id * ipv4 database",
                  "sh lisp instance-id * ipv6 database", "show device-tracking database"]
                 ]
session_cmd_list = [
    ["show lisp session", "show lisp instance * ethernet database", "sh lisp instance-id * ipv4 database",
     "sh lisp instance-id * ipv6 database"]]

cts_cmd_list = [
    "sh cts environment", "sh cts role-based counters", "sh cts role-based permissions",
    "sh cts rbacl", "sh cts authorization entries"]
auth_cmd_list = [
    "show access-session method dot1x details",
    "show access-session method mab details", "sh device-tracking database", "show aaa servers"]

db_cmd_list = ["show lisp instance-id * ethernet database", "show lisp instance-id * ipv4 database",
               "show lisp instance-id * ipv6 database"]

mc_cmd_list = ["show lisp instance-id * ethernet map-cache", "show lisp instance-id * ipv4 map-cache",
               "show lisp instance-id * ipv6 map-cache"]


def BuildIdlist(dnac, dnac_core, roles):
    devices = {}
    for role in roles:
        if dnac_core.get(["devices", dnac.fabric, role]) is not None:
            devices.update(dnac_core.get(["devices", dnac.fabric, role]))
    devid = []
    for device in devices.keys():
        devid.append(devices[device]["id"])
    return devid


def printraw(ret):
    answer = input("Analysis complete, print outputs y/n:")
    if answer == "y":
        for responses in ret:
            print(f"***********{responses['host']}**********")
            print(f"{responses['output']}")
    return


def check_dev(dnac, dnac_core, fabric, dev):
    resp = dnac.geturl(f"/dna/intent/api/v1/business/sda/device?deviceIPAddress={dev['managementIpAddress']}")
    if "response" in resp.keys():
        if resp['response']['status'] == "success":
            roles = resp['response']['roles']
            print(f"{dev['hostname']} has role(s) {resp['response']['roles']}")
            resp = dnac.geturl(f"/dna/intent/api/v1/network-device?managementIpAddress={dev['managementIpAddress']}")
            dnac.devices[dev['hostname']] = resp.get("response")
            # print(dev["hostname"])
            # print (resp['response'][0]['reachabilityStatus'])
            if len(roles) > 0:
                uuid = resp['response'][0]['id']
                for role in roles:
                    dnac_core.add(["devices", fabric, role, dev['managementIpAddress'],
                                   {"name": dev["hostname"], "IOS": dev['softwareVersion'], "id": uuid,
                                    "roles": roles, "reachability": dev['reachabilityStatus']}])
                    dnac_core.add(["Global", "Devices", dev["hostname"], {"IP Address": dev["managementIpAddress"]}])
                    dnac.topo['devices'][uuid] = dev['hostname']
                    dnac.topo['hostnames'][dev['hostname']] = uuid
                    dnac.topo['ip2uuid'][dev["managementIpAddress"]] = uuid
                    dnac.topo['reach'][uuid] = dev['reachabilityStatus']
                    if dev['reachabilityStatus'] == "Unreachable":
                        print(f"{dev['hostname']} is in state {dev['reachabilityStatus']}")
    else:
        print(f"Error retrieving SDA API calls needed, possible DNAC version 1.x used")
        exit()
    return


def build_hierarch(dnac, dnac_core):
    resp = dnac.geturl("/dna/intent/api/v1/site")
    sites = resp["response"]
    site_view = []
    dnac.topo = {'sites': {}, 'fabrics': {}, 'devices': {}, 'ip2uuid': {}, 'reach': {}, 'hostnames': {}}
    for site in sites:
        if 'parentId' in site.keys():
            site_view.append(site['siteNameHierarchy'])
            dnac.topo['sites'][site['siteNameHierarchy']] = site['id']
    site_view.sort()
    print("Discovered Areas/Buildings/floors:")
    [print(x) for x in site_view]
    fabric_list = []
    for site in site_view:
        resp = dnac.geturl(f"/dna/intent/api/v1/business/sda/fabric-site?siteNameHierarchy={site.replace(' ', '+')}")
        if resp['status'] == "success":
            fabric_list.append(resp['fabricName'])
            dnac.topo['fabrics'][resp['fabricName']] = {"site": site, "id": dnac.topo['sites'][site]}
            dnac_core.add(["topology", site, {"fabric": dnac.topo['fabrics'][resp['fabricName']]}])


def find_wlc(dnac, dnac_core, resp):
    site = resp.get("site")
    if site is None:
        return
    response = site.get("response")
    if response is None:
        return
    for responses in response:
        addinfo = responses.get("additionalInfo")
        if addinfo is not None:
            for namespaces in addinfo:
                attributes = namespaces.get("attributes")
                if attributes is not None:
                    primarywlc = attributes.get("primaryWlc")
                    if primarywlc is not None:
                        dnac.wlc["uuid"] = primarywlc
                        dnac.topo['reach'][primarywlc] = "Reachable"

    if dnac.wlc.get("uuid") is not None:
        resp = dnac.geturl(f"/dna/intent/api/v1/network-device/{dnac.wlc.get('uuid')}")
        response = resp.get("response")
        if dnac.debug is True:
            print(response)
        if response is not None:
            for key in response.keys():
                dnac.wlc[key] = response[key]
        print(f"Found Wireless LAN Controller {dnac.wlc.get('hostname')} in fabric {dnac.fabric}")
        dnac.topo["devices"][dnac.wlc[key]] = dnac.wlc.get('hostname')
        resp = dnac.geturl(f"/dna/intent/api/v1/network-device/{dnac.wlc.get('uuid')}/config")
        ParseCommands.ParseWLCConfig(resp["response"], dnac.wlc.get('hostname'), dnac_core)

    return


def check_fabric(fabric, dnac, dnac_core):
    #   for fabric in fabric_list:
    print(f"Discovered devices in Fabric {fabric} :")
    resp = dnac.geturl(f"/dna/intent/api/v1/membership/{dnac.topo['fabrics'][fabric]['id']}")
    devices = resp['device']
    find_wlc(dnac, dnac_core, resp)
    [[check_dev(dnac, dnac_core, fabric, y) for y in x.get('response')] for x in devices]
    print(f"Importing CP information for fabric {fabric}")
    cp = dnac_core.get(["devices", fabric, "MAPSERVER"])
    if cp is None:
        print("no CP found, exciting")
        return
    for cp_node in cp:
        ret = dnac.command_run(["show lisp site", "show lisp session", "show lisp instance * ethernet server",
                                "sh lisp instance-id * ethernet server address-resolution",
                                "show lisp instance-id * ipv4 database",
                                "show lisp instance-id * ipv6 database", "show lisp instance-id * ethernet database"],
                               [cp[cp_node]["id"]])
        for responses in ret:
            # print (responses["output"])
            ParseCommands.ParseSingleDev(responses["output"], responses["host"], dnac_core)
        print(f"Completed {cp_node} ")
    edges = []
    edge = {}
    if dnac_core.get(["devices", fabric, "EDGENODE"]) is not None:
        edge.update(dnac_core.get(["devices", fabric, "EDGENODE"]))
    if dnac_core.get(["devices", fabric, "BORDERNODE"]) is not None:
        edge.update(dnac_core.get(["devices", fabric, "BORDERNODE"]))
    if dnac_core.get(["devices", fabric, "MAPSERVER"]) is not None:
        edge.update(dnac_core.get(["devices", fabric, "MAPSERVER"]))
    print(f"Importing configurations for fabric {fabric}")
    for edge_dev in edge:
        edges.append(edge[edge_dev]["id"])
        eid = edge[edge_dev]["id"]
        resp = dnac.geturl(f"/dna/intent/api/v1/network-device/{eid}/config")
        ParseCommands.ParseConfig(resp["response"], edge[edge_dev]["name"], dnac_core)
    Analysis.Config2Fabric(dnac, dnac_core)
    Analysis.CP2Fabric(dnac, dnac_core)
    return


def Build_Lisp_Fabric(dnac, dnac_core, fabric):
    #print (fabric)
    if len(dnac.topo['fabrics']) == 1:
        print("Only one fabric found, proceeding")
        for fabric in dnac.topo['fabrics']:
            check_fabric(fabric, dnac, dnac_core)
            dnac.fabric = fabric
    elif len(dnac.topo['fabrics']) > 1:
        while True:
            if fabric is None:
                print("Found Fabrics:")
                for fabrics in dnac.topo['fabrics'].keys():
                    print(fabrics)
                fabric = input(f"Which fabric should be used: ")
            if fabric not in dnac.topo['fabrics'].keys():
                print(f"Fabric: {fabric} not found")
                fabric = None
            if fabric in dnac.topo['fabrics'].keys():
                dnac.fabric = fabric
                check_fabric(fabric, dnac, dnac_core)
                break
    else:
        print(f"No fabrics found, exiting")
        exit()
    # print(dnac_core.printit())


def SessionAnalysis(dnac, dnac_core):
    edge = dnac_core.get(["devices", dnac.fabric, "EDGENODE"])
    print(f"Importing basic edge information for fabric {dnac.fabric}")
    edges = []
    i = 0
    t = 0
    for edge_dev in edge:
        edges.append(edge[edge_dev]["id"])
        eid = edge[edge_dev]["id"]
        resp = dnac.geturl(f"/dna/intent/api/v1/network-device/{eid}/config")
        # print(edge[edge_dev])
        ParseCommands.ParseConfig(resp["response"], edge[edge_dev]["name"], dnac_core)
        i = i + 1
        t = t + 1
        if len(edges) > 100 or i == len(edge):
            for cmd in session_cmd_list:
                ret = dnac.command_run(cmd, edges)
                for responses in ret:
                    ParseCommands.ParseSingleDev(responses["output"], responses["host"], dnac_core)
            print(f"Completed import on {t} edges , total imported {i}")
            t = 0
            edges = []
    Analysis.CheckLispSession(dnac, dnac_core)
    printraw(ret)
    return


def CTSAnalysis(dnac, dnac_core):
    edge = dnac_core.get(["devices", dnac.fabric, "EDGENODE"])
    print(f"Importing basic edge information for fabric {dnac.fabric}")
    edges = []
    for edge_dev in edge:
        edges.append(edge[edge_dev]["id"])
    mergedlist = []
    mergedlist.extend(auth_cmd_list)
    mergedlist.extend(cts_cmd_list)
    ret = dnac.command_run(mergedlist, edges)
    for responses in ret:
        ParseCommands.ParseSingleDev(responses["output"], responses["host"], dnac_core)
    Analysis.CheckAuth(dnac, dnac_core)
    Analysis.CheckCTS(dnac, dnac_core)
    printraw(ret)
    return


def DatabaseAnalysis(dnac, dnac_core):
    # data_core = AnalysisCore.Analysis_Core()
    edge = dnac_core.get(["devices", dnac.fabric, "EDGENODE"])
    print(f"Importing basic edge information for fabric {dnac.fabric}")
    edges = []
    for edge_dev in edge:
        edges.append(edge[edge_dev]["id"])
    if len(edges) > 0:
        ret = dnac.command_run(db_cmd_list, edges)
        for responses in ret:
            ParseCommands.ParseSingleDev(responses["output"], responses["host"], dnac_core)
        print(f"Completed import on {len(edges)} edges")
    failed = Analysis.LispDBAnalysis(dnac, dnac_core)
    printraw(ret)
    return


def MapCacheAnalysis(dnac, dnac_core):
    devices_id_list = BuildIdlist(dnac, dnac_core, ["EDGENODE", "BORDERNODE"])
    if len(devices_id_list) > 0:
        ret = dnac.command_run(mc_cmd_list, devices_id_list)
        for responses in ret:
            ParseCommands.ParseSingleDev(responses["output"], responses["host"], dnac_core)
    Analysis.CheckEdgeMC(dnac, dnac_core)
    printraw(ret)
    return


def ReachabilityAnalysis(dnac, dnac_core):
    devices_id_list = BuildIdlist(dnac, dnac_core, ["EDGENODE", "BORDERNODE"])
    if len(devices_id_list) > 0:
        ret = dnac.command_run(["show ip route", "show clns neigh detail", "show bfd neigh detail"], devices_id_list)
        for responses in ret:
            ParseCommands.ParseSingleDev(responses["output"], responses["host"], dnac_core)
    Analysis.CheckRLOCreach(dnac, dnac_core)
    printraw(ret)
    return


def McastUnderlay(dnac, dnac_core):
    devices_id_list = BuildIdlist(dnac, dnac_core, ["EDGENODE"])
    instances = dnac_core.get(["fabric", "configured instances"])
    mcastunder = []
    for instance in instances:
        if instances[instance]["broadcast"] not in mcastunder and re.match(r"\d.\d.\d.\d.",
                                                                           instances[instance]["broadcast"]):
            mcastunder.append(instances[instance]["broadcast"])
    mcastcmds = ["show spanning-tree summary"]
    for mcastgroups in mcastunder:
        mcastcmds.append(f"show ip mroute {mcastgroups}")
        mcastcmds.append(f"show ip mfib {mcastgroups}")
        mcastcmds.append(f"show device-tracking database")
        mcastcmds.append(f"show mac address-table")
    if len(devices_id_list) > 0:
        ret = dnac.command_run(mcastcmds, devices_id_list)
        for responses in ret:
            ParseCommands.ParseSingleDev(responses["output"], responses["host"], dnac_core)
    Analysis.UnderlayMcastAnalysis(dnac, dnac_core, mcastunder)
    printraw(ret)
    return


def Menu(dnac, dnac_core):
    while True:
        print(f"\n\n\nPlease choose one of the following options:")
        print(f"1: LISP Session analysis")
        print(f"2: LISP Database consistency")
        print(f"3: LISP Map cache consistency")
        print(f"4: IP reachability checks")
        print(f"5: Authentication and CTS enviroment checking")
        print(f"6: Data Collection based on Endpoint")
        print(f"7: IP Multicast Underlay checks")
        print(f"d: Dump Datastructures")
        print(f"r: New Fabric Selection")
        print(f"q: Quit")
        choice = input("Choice:").lower()
        if choice == "1":
            SessionAnalysis(dnac, dnac_core)
        elif choice == "2":
            DatabaseAnalysis(dnac, dnac_core)
        elif choice == "3":
            MapCacheAnalysis(dnac, dnac_core)
        elif choice == "4":
            ReachabilityAnalysis(dnac, dnac_core)
        elif choice == "5":
            CTSAnalysis(dnac, dnac_core)
        elif choice == "7":
            McastUnderlay(dnac, dnac_core)
        elif choice == "d":
            print(dnac_core.printit())
        elif choice == "r":
            return
        elif choice == "q":
            exit()
        elif choice == "6":
            Analysis.Digger(dnac, dnac_core)


def main(argv):
    dnac = None
    username = None
    password = None
    fabric = None
    logdir = None
    debug = False
    try:
        opts, args = getopt.getopt(argv, "hxd:u:p:f:d:l:b:", ["directory="])
    except getopt.GetoptError:
        print('SDA_Digger.py -d <DNAC IP> -u <username> -p <password> -f <fabric> -l <logdirectory>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('SDA_Digger.py -d <DNAC IP> -u <username> -p <password> -f <fabric> -l <logdirectory>')
            sys.exit()
        elif opt == "-d":
            dnac = arg
        elif opt == "-x":
            debug = True
        elif opt in "-u":
            username = arg
        elif opt in "-p":
            password = arg
        elif opt in "-f":
            fabric = arg
        elif opt in "-l":
            logdir = arg
        elif opt in "-b":
            inputdir = arg
            dnac_core = AnalysisCore.Analysis_Core()
            ParseBundle.ParseBundle(dnac_core, inputdir)
            exit()
    if dnac is None:
        dnac = input("DNAC IP address :")
    if username is None:
        username = input("username :")
    if password is None:
        password = getpass()
    dnac = DNAC_Connector.DnacCon(dnac, username, password, logdir)
    if debug is True:
        dnac.debug = True
    while True:
        dnac_core = AnalysisCore.Analysis_Core()
        build_hierarch(dnac, dnac_core)
        Build_Lisp_Fabric(dnac, dnac_core, fabric)
        Menu(dnac, dnac_core)
    return


if __name__ == "__main__":
    main(sys.argv[1:])
