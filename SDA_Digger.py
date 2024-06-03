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
from DiggerInOut import *

edge_cmd_list = [["show lisp session", "show lisp instance * ethernet database", "sh lisp instance-id * ipv4 database",
                  "sh lisp instance-id * ipv6 database", "show device-tracking database"]
                 ]
session_cmd_list = [
    "show lisp session", "show lisp instance * ethernet database", "sh lisp instance-id * ipv4 database",
    "sh lisp instance-id * ipv6 database"]

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

wlc_cmd_list = ["show ap summary", "show fabric ap summary", "show fabric wlan summary",
                "sh wireless fabric client summary ", "sh wireless fabric summary "]
apedge_cmd_list = ["show access-tunnel summary"]

EDGEROLES = ["EDGENODE", "EDGE NODE"]
BORDERROLES = ["BORDER NODE", "BORDERNODE"]
MSROLES = ["MAPSERVER", "CONTROL PLANE"]


def build_and_choose(choices, what):
    if len(choices) == 1:
        return (choices[0])
    dig_out_function(f"Available {what}:")
    choice_table = {}
    for x, choice in enumerate(choices):
        dig_out_function(f"{x}: {choice}")
        choice_table[x] = choice
    while True:
        userchoice = dig_in_function(f"Which {what} should be used : ")
        if userchoice.isnumeric():
            if int(userchoice) in choice_table.keys():
                return choice_table[int(userchoice)]





def BuildIdlist(dnac, dnac_core, roles):
    devices = {}
    for role in roles:
        if dnac_core.get(["devices", dnac.fabric, role]) is not None:
            devices.update(dnac_core.get(["devices", dnac.fabric, role]))
    devid = []
    for device in devices.keys():
        devid.append(devices[device]["id"])
    return devid


def dig_out_functionraw(ret, dnac):
    if dnac.bypassprint is True:
        return
    answer = dig_in_function("Analysis complete, display outputs y/n:")
    if answer == "y":
        devices = dig_in_function("Enter for all devices or specify host:")
        for responses in ret:
            if len(devices) < 3 or devices.lower() == responses['host'].lower():
                dig_out_function(f"***********{responses['host']}**********")
                dig_out_function(f"{responses['output']}")
    return


def check_dev(dnac, dnac_core, fabric, dev):
    resp = dnac.geturl(f"/dna/intent/api/v1/business/sda/device?deviceIPAddress={dev['managementIpAddress']}")
    if "status" in resp.keys():
        if resp["status"] == "failed":
            resp = dnac.geturl(
                f"/dna/intent/api/v1/business/sda/device?deviceManagementIpAddress={dev['managementIpAddress']}")
            # recreateing hierachie compatigle with pre 2.2.3
            resp["response"] = resp
            if resp["status"] == "failed":
                resp = dnac.geturl(
                    f"/dna/intent/api/v1/business/sda/device/role?deviceManagementIpAddress={dev['managementIpAddress']}")
                # Fixing changes that came in 2.3.3.x and later
                resp["response"] = resp
    uuid = dev['instanceUuid']
    dnac.topo['devices'][uuid] = dev['hostname']
    dnac.topo['hostnames'][dev['hostname']] = uuid
    dnac.topo['ip2uuid'][dev["managementIpAddress"]] = uuid
    dnac.topo['reach'][uuid] = dev['reachabilityStatus']
    if re.match(r".*9[235]\d\d.*", dev['type']):
        dnac.topo['stack'][uuid] = "stackable"
    elif re.match(r".*9[46]\d\d.*", dev['type']):
        dnac.topo['stack'][uuid] = "chassis"
    else:
        dnac.topo['stack'][uuid] = "other"
    if dev['reachabilityStatus'] == "Unreachable":
        dig_out_function(f"{dev['hostname']} is in state {dev['reachabilityStatus']}")
    if "response" in resp.keys():
        if resp['response']['status'] == "success":
            troles = resp['response']['roles']
            roles = []
            for trole in troles:
                if trole.upper() in MSROLES:
                    roles.append("MAPSERVER")
                if trole.upper() in BORDERROLES:
                    roles.append("BORDERNODE")
                if trole.upper() in EDGEROLES:
                    roles.append("EDGENODE")
            dig_out_function(f"{dev['hostname']} has role(s) {roles}")
            resp = dnac.geturl(f"/dna/intent/api/v1/network-device?managementIpAddress={dev['managementIpAddress']}")
            dnac.devices[dev['hostname']] = resp.get("response")
            # dig_out_function(dev["hostname"])
            # dig_out_function (resp['response'][0]['reachabilityStatus'])
            if len(roles) > 0:
                uuid = resp['response'][0]['id']
                for role in roles:
                    dnac_core.add(["devices", fabric, role, dev['managementIpAddress'],
                                   {"name": dev["hostname"], "IOS": dev['softwareVersion'], "id": uuid,
                                    "roles": roles, "reachability": dev['reachabilityStatus'], "type": dev['type']}])
                    dnac_core.add(["Global", "Devices", dev["hostname"], {"IP Address": dev["managementIpAddress"]}])
        else:
            # API not reporting pure border nodes with edge api call, checking if device is border node
            resp = dnac.geturl(
                f"/dna/intent/api/v1/business/sda/border-device?deviceIPAddress={dev['managementIpAddress']}")
            if "id" in resp.keys():
                roles = ["BORDERNODE"]
                role = "BORDERNODE"
                dnac_core.add(["devices", fabric, role, dev['managementIpAddress'],
                               {"name": dev["hostname"], "IOS": dev['softwareVersion'], "id": uuid,
                                "roles": roles, "reachability": dev['reachabilityStatus'], "type": dev['type']}])
                dnac_core.add(["Global", "Devices", dev["hostname"], {"IP Address": dev["managementIpAddress"]}])
                dig_out_function(f"{dev['hostname']} has role(s) {roles}")
    else:
        dig_out_function(f"Error retrieving SDA API calls needed, possible DNAC version 1.x used")
        exit()
    return

def build_hierarch(dnac, dnac_core):
    resp = dnac.geturl("/dna/intent/api/v1/site")
    sites = resp["response"]
    site_view = []
    fabsites = []
    fabric_list = []
    fabname = ""
    dnac.topo = {'sites': {}, 'fabrics': {}, 'devices': {}, 'ip2uuid': {}, 'reach': {}, 'hostnames': {}, 'stack': {}}

    for site in sites:
        if 'parentId' in site.keys():
            type = "unknown"
            for attrs in site['additionalInfo']:
                if 'type' in attrs['attributes'].keys():
                    type = attrs['attributes']['type']
            site_view.append(site['siteNameHierarchy'])
            dnac.topo['sites'][site['siteNameHierarchy']] = site['id']
    site_view.sort()
    dig_out_function("Discovered Areas/Buildings/floors:")
    [dig_out_function(x) for x in site_view]
    if dnac.clisite is not None:
        if dnac.clisite in site_view:
            site_view = [dnac.clisite]
        else:
            dig_out_function(f"{dnac.clisite} not found , exiting")
            exit()
    found_sites = []
    for site in site_view:
        parent = "/".join(site.split("/")[:-1])
        if parent not in found_sites:
            resp = dnac.geturl(f"/dna/intent/api/v1/business/sda/fabric-site?siteNameHierarchy={site.replace(' ', '+')}")
            if resp['status'] == "success":
                fabname = ["Default LAN Fabric"]
                if "fabricSiteName" in resp.keys():
                    fabric_list.append(resp['fabricSiteName'])
                    fabname = resp['fabricSiteName']
                elif "fabricName" in resp.keys():
                    fabric_list.append(resp['fabricName'])
                    fabname = resp['fabricName']
                if fabname is not None:
                    fabsites.append({"fabric": fabname, "site": site, "id": dnac.topo['sites'][site]})
                    found_sites.append(site)
        else:
            found_sites.append(site)
    if len(fabric_list) == 0:
       if dnac.clifabric is not None and dnac.clisite is not None:
           fabname = dnac.clifabric
           site = dnac.clisite
       else:
           dig_out_function(f"No fabrics found using dynamic discover, please use -s <site> -f <fabric> ")
    fabric_list=list(set(fabric_list))
    if dnac.clifabric is not None:
        if dnac.clifabric not in fabric_list:
            dig_out_function(f"Fabric {dnac.clifabric} not found")
            exit()
    else:
        fabname = build_and_choose(fabric_list,"fabric")
    fab_site_list = {}
    for raw_site in fabsites:
        if raw_site['fabric'] == fabname:
            fab_site_list[raw_site["site"]]=raw_site["id"]
    if dnac.clisite is None:
        site=build_and_choose(fab_site_list.keys(),"site")
    elif dnac.clisite in fab_site_list.keys():
        site=dnac.clisite
    else:
        dig_out_function(f"site {dnac.clisite} not found ")
        exit()
    dnac.fabric = fabname
    dnac.topo['fabrics'][fabname] = {"site": site, "id": dnac.topo['sites'][site]}
    dnac_core.add(["topology", site, {"fabric": dnac.topo['fabrics'][fabname]}])
    check_fabric(fabname, dnac, dnac_core)
    return



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
        key = ""
        resp = dnac.geturl(f"/dna/intent/api/v1/network-device/{dnac.wlc.get('uuid')}")
        response = resp.get("response")
        if dnac.debug is True:
            dig_out_function(response)
        if response is not None:
            for key in response.keys():
                dnac.wlc[key] = response[key]
        dig_out_function(f"Found Wireless LAN Controller {dnac.wlc.get('hostname')} in fabric {dnac.fabric}")
        dnac.topo["devices"][dnac.wlc[key]] = dnac.wlc.get('hostname')
        resp = dnac.geturl(f"/dna/intent/api/v1/network-device/{dnac.wlc.get('uuid')}/config")
        ParseCommands.ParseWLCConfig(resp["response"], dnac.wlc.get('hostname'), dnac_core)

    return

def check_site_fabric(fabric,dnac,dnac_core):
    sites = dnac_core.get(["fabsites", fabric])
    if sites is None:
        check_fabric(fabric, dnac, dnac_core)
    else:
       dig_out_function(f"Found  sites for Fabric {fabric} :")
       site_list={}
       for x,site in enumerate(sites):
           site_list[x]=site
           dig_out_function(f"{x}:{site}")
       while True:
           if len(site.keys())==1:
               sitenr=1
           else:
               sitenr = dig_in_function("Which site should be used:")
           if sitenr.isnumeric():
              site_nr = int(sitenr)
              if (site_nr >= 0) and (site_nr < len(sites)):
                  site = site_list[site_nr]
                  break
              else:
                  dig_out_function(f"invalid site id")
                  exit()
           else:
               dig_out_function(f"invalid site id")
               exit()
    dnac.topo['fabrics'][fabric] = {"site": site, "id": dnac.topo['sites'][site]}
    dnac_core.add(["topology", site, {"fabric": dnac.topo['fabrics'][fabric]}])
    dnac.fabric = fabric
    check_fabric(fabric, dnac, dnac_core)
    return

def check_fabric(fabric, dnac, dnac_core):
    #   for fabric in fabric_list:
    dig_out_function(f"Discovered devices in Fabric {fabric} :")
    resp = dnac.geturl(f"/dna/intent/api/v1/membership/{dnac.topo['fabrics'][fabric]['id']}")
    devices = resp['device']
    find_wlc(dnac, dnac_core, resp)
    [[check_dev(dnac, dnac_core, fabric, y) for y in x.get('response')] for x in devices]
    dig_out_function(f"Importing CP information for fabric {fabric}")
    cp = dnac_core.get(["devices", fabric, "MAPSERVER"])
    if cp is None:
        dig_out_function("no CP found, exciting")
        return
    for cp_node in cp:
        ret = dnac.command_run(["show lisp site", "show lisp session", "show lisp instance * ethernet server",
                                "sh lisp instance-id * ethernet server address-resolution",
                                "show lisp instance-id * ipv4 database",
                                "show lisp instance-id * ipv6 database", "show lisp instance-id * ethernet database"],
                               [cp[cp_node]["id"]])
        for responses in ret:
            # dig_out_function (responses["output"])
            ParseCommands.ParseSingleDev(responses["output"], responses["host"], dnac_core)
        dig_out_function(f"Completed {cp_node} ")
    edges = []
    edge = {}
    if dnac_core.get(["devices", fabric, "EDGENODE"]) is not None:
        edge.update(dnac_core.get(["devices", fabric, "EDGENODE"]))
    if dnac_core.get(["devices", fabric, "BORDERNODE"]) is not None:
        edge.update(dnac_core.get(["devices", fabric, "BORDERNODE"]))
    if dnac_core.get(["devices", fabric, "MAPSERVER"]) is not None:
        edge.update(dnac_core.get(["devices", fabric, "MAPSERVER"]))
    dig_out_function(f"Importing configurations for fabric {fabric}")
    for edge_dev in edge:
        edges.append(edge[edge_dev]["id"])
        eid = edge[edge_dev]["id"]
        resp = dnac.geturl(f"/dna/intent/api/v1/network-device/{eid}/config")
        ParseCommands.ParseConfig(resp["response"], edge[edge_dev]["name"], dnac_core)
    Analysis.Config2Fabric(dnac, dnac_core)
    Analysis.CP2Fabric(dnac, dnac_core)

    return


def Check_L3IF(dnac, dnac_core):
    ids = BuildIdlist(dnac, dnac_core, ["EDGENODE"])
    for leid in ids:
        Analysis.Cat9_L3_Check(dnac, dnac_core, leid)
    return


def SessionAnalysis(dnac, dnac_core):
    ids = BuildIdlist(dnac, dnac_core, ["BORDERNODE", "EDGENODE"])
    ret = dnac.command_run(session_cmd_list, ids)
    for responses in ret:
        ParseCommands.ParseSingleDev(responses["output"], responses["host"], dnac_core)
    Analysis.CheckLispSession(dnac, dnac_core)
    dig_out_functionraw(ret, dnac)
    return


def CTSAnalysis(dnac, dnac_core):
    edge = dnac_core.get(["devices", dnac.fabric, "EDGENODE"])
    dig_out_function(f"Importing basic edge information for fabric {dnac.fabric}")
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
    dig_out_functionraw(ret, dnac)
    return


def DatabaseAnalysis(dnac, dnac_core):
    # data_core = AnalysisCore.Analysis_Core()
    edge = dnac_core.get(["devices", dnac.fabric, "EDGENODE"])
    if edge is None:
        edge = {}
    else:
        dig_out_function(f"Importing basic edge information for fabric {dnac.fabric}")
    ret = []
    edges = []
    for edge_dev in edge:
        edges.append(edge[edge_dev]["id"])
    if len(edges) > 0:
        ret = dnac.command_run(db_cmd_list, edges)
        for responses in ret:
            ParseCommands.ParseSingleDev(responses["output"], responses["host"], dnac_core)
        dig_out_function(f"Completed import on {len(edges)} edges")
    failed = Analysis.LispDBAnalysis(dnac, dnac_core)
    dig_out_functionraw(ret, dnac)
    return


def MapCacheAnalysis(dnac, dnac_core):
    ret = []
    devices_id_list = BuildIdlist(dnac, dnac_core, ["EDGENODE", "BORDERNODE"])
    if len(devices_id_list) > 0:
        ret = dnac.command_run(mc_cmd_list, devices_id_list)
        for responses in ret:
            ParseCommands.ParseSingleDev(responses["output"], responses["host"], dnac_core)
    Analysis.CheckEdgeMC(dnac, dnac_core)
    dig_out_functionraw(ret, dnac)
    return


def ReachabilityAnalysis(dnac, dnac_core):
    ret = []
    devices_id_list = BuildIdlist(dnac, dnac_core, ["EDGENODE", "BORDERNODE"])
    if len(devices_id_list) > 0:
        ret = dnac.command_run(["show ip route", "show clns neigh detail", "show bfd neigh detail"], devices_id_list)
        for responses in ret:
            ParseCommands.ParseSingleDev(responses["output"], responses["host"], dnac_core)
    Analysis.CheckRLOCreach(dnac, dnac_core)
    dig_out_functionraw(ret, dnac)
    return


def McastUnderlay(dnac, dnac_core):
    ret = []
    devices_id_list = BuildIdlist(dnac, dnac_core, ["EDGENODE", "BORDERNODE"])
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
        mcastcmds.append(f"show ip pim neighbor")
        mcastcmds.append(f"show spanning-tree summary")
    if len(devices_id_list) > 0:
        ret = dnac.command_run(mcastcmds, devices_id_list)
        for responses in ret:
            ParseCommands.ParseSingleDev(responses["output"], responses["host"], dnac_core)
    Analysis.UnderlayMcastAnalysis(dnac, dnac_core, mcastunder)
    dig_out_functionraw(ret, dnac)
    return


def WirelessAP(dnac, dnac_core):
    ret = []
    full_ret = []
    wlcid = dnac.wlc.get("uuid")
    if wlcid is None:
        dig_out_function("No WLC found")
        return
    # Assuming for now WLC is IOS-XE based, add check later
    ret = dnac.command_run(wlc_cmd_list, [wlcid])
    for responses in ret:
        ParseCommands.ParseSingleDev(responses["output"], responses["host"], dnac_core)
    full_ret.extend(ret)
    devices_id_list = BuildIdlist(dnac, dnac_core, ["EDGENODE"])
    ret = dnac.command_run(apedge_cmd_list, devices_id_list)
    for responses in ret:
        ParseCommands.ParseSingleDev(responses["output"], responses["host"], dnac_core)
    full_ret.extend(ret)
    dig_out_functionraw(full_ret, dnac)
    return


def Menu(dnac, dnac_core):
    while True:
        dig_out_function(f"\n\n\nPlease choose one of the following options:")
        dig_out_function(f"1: LISP Session analysis")
        dig_out_function(f"2: LISP Database consistency")
        dig_out_function(f"3: LISP Map cache consistency")
        dig_out_function(f"4: IP reachability checks")
        dig_out_function(f"5: Authentication and CTS enviroment checking")
        dig_out_function(f"6: Data Collection based on Endpoint")
        dig_out_function(f"7: IP Multicast Underlay checks")
        dig_out_function(f"a: Perform All Analysis checks")
        dig_out_function(f"d: Dump Datastructures")
        dig_out_function(f"r: New Fabric Selection")
        dig_out_function(f"q: Quit")
        choice = dig_in_function("Choice:").lower()
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
        elif choice == "8":
            WirelessAP(dnac, dnac_core)
        elif choice == "d":
            dig_out_function(dnac_core.printit())
        elif choice == "r":
            return
        elif choice == "q":
            exit()
        elif choice == "6":
            Analysis.Digger(dnac, dnac_core)
        elif choice == "a":
            dnac.bypassprint = True
            SessionAnalysis(dnac, dnac_core)
            DatabaseAnalysis(dnac, dnac_core)
            MapCacheAnalysis(dnac, dnac_core)
            ReachabilityAnalysis(dnac, dnac_core)
            CTSAnalysis(dnac, dnac_core)
            McastUnderlay(dnac, dnac_core)


def main(argv):
    dnac = None
    username = None
    password = None
    fabric = None
    logdir = None
    debug = False
    dig_out_function(f"Starting SDA Digger tool")
    try:
        opts, args = getopt.getopt(argv, "hxgd:u:s:p:f:d:l:b:e:", ["directory="])
    except getopt.GetoptError:
        dig_out_function(
            'SDA_Digger.py -g -d <DNAC IP> -u <user> -p <password> -f <fabric> -l <logdirectory> -b <bundle directory>')
        dig_out_function(
            f"Feedback/comments/bug reports : Sda_digger@protonmail.com or https://github.com/michelpe/SDA_Digger\n\n")
        sys.exit(2)
    esc_option = None
    site = None
    fabric = None
    gui = False
    for opt, arg in opts:
        if opt == '-h':
            dig_out_function(
                'SDA_Digger.py -g -d <DNAC IP> -u <username> -p <password> -f <fabric> -l <logdirectory> -b <bundle '
                'directory>')
            dig_out_function(
                f"Feedback/comments/bug reports : Sda_digger@protonmail.com or "
                f"https://github.com/michelpe/SDA_Digger\n\n")
            sys.exit()
        elif opt == "-d":
            dnac = arg
        elif opt == "-g":
            gui = True
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
        elif opt in "-e":
            esc_option = arg
        elif opt in "-s":
            site = arg
        elif opt in "-b":
            inputdir = arg
            dnac_core = AnalysisCore.Analysis_Core()
            ParseBundle.ParseBundle(dnac_core, inputdir, debug)
            exit()
    if dnac is None:
        dnac = dig_in_function("DNAC IP address :")
    if username is None:
        username = dig_in_function("username :")
    if password is None:
        password = getpass()
    if gui:
        dig_out_function("Launching GUI")
        dig_gui_enable()
    dnac = DNAC_Connector.DnacCon(dnac, username, password, logdir)
    dnac.clisite = site
    dnac.clifabric = fabric
    if debug is True:
        dnac.debug = True
    while True:
        dnac_core = AnalysisCore.Analysis_Core()
        build_hierarch(dnac, dnac_core)
        if esc_option is not None:
            if esc_option == "l3eif":
                dig_out_function("Performing L3 LEAD index analysis")
                Check_L3IF(dnac, dnac_core)
        Menu(dnac, dnac_core)
    return


if __name__ == "__main__":
    main(sys.argv[1:])
