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

edge_cmd_list = [["show lisp session", "show lisp instance * ethernet database","sh lisp instance-id * ipv4 database","sh lisp instance-id * ipv6 database","show device-tracking database"]
                 ]

def check_dev(dnac,dnac_core,fabric,dev):
    resp = dnac.geturl(f"/dna/intent/api/v1/business/sda/device?deviceIPAddress={dev['managementIpAddress']}")
    if resp['response']['status']=="success":
        roles = resp['response']['roles']
        print(f"{dev['hostname']} has role(s) {resp['response']['roles']}")
        resp = dnac.geturl(f"/dna/intent/api/v1/network-device?managementIpAddress={dev['managementIpAddress']}")
        #print(dev["hostname"])
        if len(roles) > 0:
            uuid=resp['response'][0]['id']
            for role in roles:
                dnac_core.add(["devices",fabric,role,dev['managementIpAddress'],{"name":dev["hostname"],"IOS":dev['softwareVersion'],"id":uuid, "roles":roles}])
                dnac_core.add(["Global","Devices",dev["hostname"],{"IP Address":dev["managementIpAddress"]}])
                dnac.topo['devices'][uuid]=dev['hostname']
                dnac.topo['ip2uuid'][dev["managementIpAddress"]]=uuid
    return

def build_hierarch(dnac,dnac_core):
    resp = dnac.geturl("/dna/intent/api/v1/site")
    sites = resp["response"]
    site_view =[]
    dnac.topo = {}
    dnac.topo['sites']={}
    dnac.topo['fabrics']={}
    dnac.topo['devices']={}
    dnac.topo['ip2uuid']={}
    for site in sites:
        if 'parentId' in site.keys():
            site_view.append(site['siteNameHierarchy'])
            dnac.topo['sites'][site['siteNameHierarchy']]=site['id']
    site_view.sort()
    print ("Discovered Areas/Buildings/floors:")
    [print (x)  for x in site_view]
    fabric_list = []
    for site in site_view:
        resp=dnac.geturl(f"/dna/intent/api/v1/business/sda/fabric-site?siteNameHierarchy={site.replace(' ','+')}")
        if resp['status'] == "success" :
            fabric_list.append(resp['fabricName'])
            dnac.topo['fabrics'][resp['fabricName']] = {"site":site,"id":dnac.topo['sites'][site]}
            dnac_core.add(["topology",site,{"fabric":dnac.topo['fabrics'][resp['fabricName']]}])

    for fabric in fabric_list:
        print (f"Discovered devices in Fabric {fabric} :")
        resp = dnac.geturl(f"/dna/intent/api/v1/membership/{dnac.topo['fabrics'][fabric]['id']}")
        devices = resp['device']
        #print (resp['site']['response'][0]["additionalInfo"][3]["attributes"]["primaryWlc"])
        [[ check_dev(dnac,dnac_core,fabric,y) for y in x['response']] for x in devices]

def check_fabric(fabric,dnac,dnac_core):
    print (f"Importing CP information for fabric {fabric}")
    cp=dnac_core.get(["devices",fabric,"MAPSERVER"])
    if cp is None:
        print("no CP found, exciting")
        return
    for cp_node in cp:
        ret = dnac.command_run(["show lisp site","show lisp session","show lisp instance * ethernet server","sh lisp instance-id * ethernet server address-resolution"],[cp[cp_node]["id"]])
        for responses in ret:
            #print (responses["output"])
            ParseCommands.ParseSingleDev(responses["output"],responses["host"],dnac_core)
        ret = dnac.command_run(["show lisp instance-id * ipv4 database","show lisp instance-id * ipv6 database","show lisp instance-id * ethernet database" ], [cp[cp_node]["id"]])
        for responses in ret:
            # print (responses["output"])
            ParseCommands.ParseSingleDev(responses["output"], responses["host"], dnac_core)
        print(f"Completed {responses['host']} ")
    edge = dnac_core.get(["devices", fabric, "EDGENODE"])
    print(f"Importing basic edge information for fabric {fabric}")
    edges = []
    i=0
    t=0
    for edge_dev in edge:
        edges.append(edge[edge_dev]["id"])
        eid =edge[edge_dev]["id"]
        resp = dnac.geturl(f"/dna/intent/api/v1/network-device/{eid}/config")
        #print(edge[edge_dev])
        ParseCommands.ParseConfig(resp["response"], edge[edge_dev]["name"],dnac_core)
        i=i+1
        t=t+1
        if len(edges) >4 or i == len(edge):
            for cmd in edge_cmd_list:
                ret = dnac.command_run(cmd, edges)
                for responses in ret:
                    ParseCommands.ParseSingleDev(responses["output"], responses["host"], dnac_core)
            print (f"Completed import on {t} edges , total imported {i}")
            t=0
            edges=[]
    Analysis.DatabaseTooFabric(dnac,dnac_core)
    Analysis.CPTooFabric(dnac,dnac_core)
    return

def Build_Lisp_Fabric(dnac,dnac_core):
    if len(dnac.topo['fabrics']) == 1:
        print("Only one fabric found, proceeding")
        for fabric in dnac.topo['fabrics']:
            check_fabric(fabric, dnac, dnac_core)
            dnac.fabric=fabric
    elif len(dnac.topo['fabrics']) > 1:
        print("more then one fabric! lets do them all (yes am lazy :) ")
        for fabric in dnac.topo['fabrics']:
            check_fabric(fabric, dnac, dnac_core)
    else:
        print(f"No fabrics found, exiting")
    #print(dnac_core.printit())

def Eth_Host_Check(dnac,dnac_core,host):
    print ("*"*80)
    print (f"Verifying Connectivity for {host}")
    loc = dnac_core.get(["fabric"])
    hosttotal=host+'/48'
    debug_core = AnalysisCore.Analysis_Core()
    for instances in loc.keys():
       if dnac_core.get(["fabric",instances,hosttotal]) is not None:
           lispinstance=instances
           lisprloc = dnac_core.get(['fabric',instances,hosttotal])['RLOC']
           rlocuid=dnac.topo['ip2uuid'][lisprloc]
           devname=dnac.topo['devices'][rlocuid]
           print(f"Found {host} in LISP Instance {lispinstance} on device {devname} ({lisprloc})")

           ret = dnac.command_run([f"show lisp instance-id {lispinstance} ethernet database {host}",
                                   f"show lisp instance-id {lispinstance} ethernet database address-resolution {host}",
                                   f"show device-tracking database mac {host}",
                                   f"show lisp instance-id {lispinstance} ethernet database wlc {host}"],
                                  [rlocuid])
           for responses in ret:
               print (responses["output"])
               ParseCommands.ParseSingleDev(responses["output"], responses["host"], debug_core)
           ret = dnac.command_run([f"show mac address-table address {host}",
                                   f"show access-session mac {host} detail"],
                                  [rlocuid])
           for responses in ret:
               print(responses["output"])
               ParseCommands.ParseSingleDev(responses["output"], responses["host"], debug_core)
    #print(debug_core.printit())
    iplayer=debug_core.get(["Global","Device-tracking",devname])
    if iplayer is None:
        print ("No corresponding Layer 3 Entries found")
    for vlan in iplayer.keys():
        for ipaddress in iplayer[vlan].keys():
            if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",ipaddress):
                l3inst= debug_core.get(["lisp", "AR",devname,lispinstance,host,ipaddress])
                if l3inst is None:
                    l3inst ="*"
                else:
                    l3inst = l3inst["l3instance"]
                print(f"{ipaddress} found in vlan {vlan} on interface {iplayer[vlan][ipaddress]['interface']}")
                vrfi = dnac_core.get(["lisp","svi_interface",devname,f"Vlan{vlan}"])
                if vrfi is None:
                    print("Unable to determine IP routing table, aborting")
                else:
                   vrfinf = vrfi["vrf"]
                   if vrfinf == "Global Routing Table":
                       vrfadd=""
                   else:
                       vrfadd =f"vrf {vrfinf}"
                   ret = dnac.command_run([f"show ip cef {vrfadd} {ipaddress} internal",
                                            f"show ip route {vrfadd} {ipaddress}",
                                            f"show ip arp {vrfadd}",
                                            f"show lisp instance-id {l3inst} ipv4 database {ipaddress}/32",
                                            f"show lisp instance-id {l3inst} ipv4 map-cache {ipaddress}"],
                                           [rlocuid])
                   for responses in ret:
                        print(responses["output"])
                        #ParseCommands.ParseSingleDev(responses["output"], responses["host"], debug_core)
                   fabric=dnac.fabric
                   cp = dnac_core.get(["devices", dnac.fabric, "MAPSERVER"])
                   if cp is None:
                       print("no CP found, exciting")
                       return
                   for cp_node in cp:
                       print ("*"*80)
                       print (f"Analazing CP nodes for {ipaddress} and {host}")
                       ret = dnac.command_run(
                           [f"sh lisp instance-id {lispinstance} ethernet server {host} ", f"sh lisp instance-id {lispinstance} ethernet server {host} registration last 10",
                            f"sh lisp instance-id {lispinstance} ethernet server address-resolution {ipaddress}",
                            f"sh lisp instance-id {ipaddress} site instance-id {l3inst}"]
                            , [cp[cp_node]["id"]])
                       for responses in ret:
                           print (responses["output"])
                           #ParseCommands.ParseSingleDev(responses["output"], responses["host"], dnac_core)

            else:
                print(f"skipping IPv6 address {ipaddress} for now(not yet supported)")


    return

def main(argv):
    dnac=input ("DNAC IP address :")
    username = input("username :")
    password = getpass()
    dnac = DNAC_Connector.DnacCon(dnac, username, password)
    dnac_core = AnalysisCore.Analysis_Core()
    build_hierarch(dnac,dnac_core)
    Build_Lisp_Fabric(dnac,dnac_core)
    while True:
        macaddress= input ("please give the mac address:")
        if macaddress == "quit":
            break
        elif re.match(r".{4}\..{4}\..{4}",macaddress):
            Eth_Host_Check(dnac,dnac_core,macaddress)
        else:
            print("Please enter quite or mac address in xxxx.xxxx.xxxx format")
    return

if __name__ == "__main__":
   main(sys.argv[1:])
