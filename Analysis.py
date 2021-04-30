import AnalysisCore
from Loggin import *
import re
import collections
import ipaddress
import json


def build_edge_list():
    devices = dnac_core.get(["lisp", "roles"])
    edge_list = []
    if devices is None:
        return edge_list
    for device in devices.keys():
        if devices[device]["Border"] is False and devices[device]["CP"] is False and devices[device]["XTR"] is True:
            edge_list.append(device)
    return edge_list


def build_fabric_list():
    devices = dnac_core.get(["lisp", "roles"])
    edge_list = []
    if devices is None:
        return edge_list
    for device in devices.keys():
        if devices[device]["Border"] == True or devices[device]["XTR"] == True:
            edge_list.append(device)
    return edge_list


def db2ip(device):
    dbentries = dnac_core.get(["lisp", "database", device])
    if type(dbentries) is dict:
        for instance in dbentries:
            for eid in dbentries[instance]:
                if "RLOC" in dbentries[instance][eid].keys():
                    #  print (dbentries[instance][eid]["RLOC"])
                    return dbentries[instance][eid]["RLOC"]

    return None


def findip():
    devices = dnac_core.get(["Global", "Devices"])
    for device in devices:
        if "IP Address" not in devices[device].keys():
            tdict = devices[device]
            IP = db2ip(device)
            if IP:
                AnalysisCore.modify(["Global", "Devices", device], 'IP Address', IP)
                LogIt(f"Notice: Extracted IP address {IP} from Database for {device}", 7)
    return


def IP2name(device):
    devices = dnac_core.get(["Global", "Devices", device])
    if devices is not None:
        return devices['IP Address']
    return None


def FindName(ipaddress):
    devices = dnac_core.get(["Global", "Devices"])
    for device in devices:
        if device.get("IP Address") == ipaddress:
            return device["Name"]
    return None


''' Gets wireless info from edge devices to check '''


def BuildWireless():
    wireless = dnac_core.get(["lisp", "wireless"])
    if wireless is None:
        return
    nodes = wireless.keys()
    for node in nodes:
        nodewireless = wireless[node]
        linstances = nodewireless.keys()
        for linstance in linstances:
            nodeeid = nodewireless[linstance]
            weids = nodeeid.keys()
            for weid in weids:
                ueid = nodeeid[weid]
                if ueid["Type"] == "AP":
                    LogIt(f"Notice: AP {weid} signalled by WLC present on {node}", 7)
                    AnalysisCore.add(("fabric", "ap", weid, {"Node": node, "Instance": linstance}))
    return


''' Gets site information to determine devices running as MSMR'''


def CheckCP():
    CPnodes = dnac_core.get(["lisp", "site"])
    if CPnodes is None:
        LogIt(
            f"Error: No LISP Control Plane Information found ,parsing results may be inconclusive", 1)
        return
    statecps = 0
    cpfabric = {}
    allid = set()
    for ar in CPnodes.keys():
        areid = CPnodes[ar]
        for nodes in areid.keys():
            node = areid[nodes]
            statecps = statecps + 1
            for lispinst in node.keys():
                instanceinfo = node[lispinst]
                for eidsp in instanceinfo.keys():
                    who = instanceinfo[eidsp]["Last Register"].split(':')[0]
                    state = instanceinfo[eidsp]["Status"]
                    if re.match(r"^ye.*", state):
                        # LogIt(f"{ar} {nodes} {lispinst} {eidsp} {who} {state}",10)
                        rl = dnac_core.get(["fabric", ar, lispinst, eidsp])
                        if rl is None:
                            AnalysisCore.add(("fabric", ar, lispinst, eidsp, {"Register": [who]}))
                        else:
                            if who in rl["Register"]:
                                pass
                            else:
                                rlr = rl["Register"]
                                new = [*rlr, who]
                                LogIt(
                                    f"Error: {lispinst}:{eidsp} mismatch between CP nodes, showing RLOC as {rlr} and [{who}]",
                                    1)
                                AnalysisCore.add(("fabric", ar, lispinst, eidsp, {"Register": new}))
                    own = dnac_core.get(["Global", "IP", who])
                    if who == "--":
                        pass
                    elif own is None:
                        mac = eidsp[:-3]
                        if dnac_core.get(["fabric", "ap", eidsp[:-3]]) is None:
                            LogIt(
                                f"Error: Registrar {who} not part of captured info or invalid,unable to check {lispinst}:{eidsp} ",
                                3)
                    else:
                        reger = dnac_core.get(["lisp", "database", own["Hostname"], lispinst, eidsp])
                        if reger is None:
                            regrole = dnac_core.get(["lisp", "roles", own["Hostname"]])
                            if regrole is None:
                                LogIt(
                                    f"Error: {lispinst}:{eidsp} not found in LISP database on {who}, not a parsed edge device ",
                                    3)
                            else:
                                if regrole["Border"] is True:
                                    LogIt(
                                        f"Debug: {lispinst}:{eidsp} not found in LISP database on {who} with role Border, possible Layer 2 Border config present ",
                                        10)
                                else:
                                    LogIt(f"Error: {lispinst}:{eidsp} not found in LISP database on {who}", 3)
                        else:
                            LogIt(f"Debug: {lispinst}:{eidsp} match found in LISP database on {who}", 90)
                            pass

    return


''' Gets Database information to determine Edge Devices'''

def LispDBAnalysis(dnac,dnac_core):
    statdevs = 0
    statteids = 0
    stateid = 0
    statfail = 0
    localstat = 0
    failedeid = []
    lispdb = dnac_core.get(["lisp", "database"])
    cpnodes = dnac_core.get(["lisp", "site", "ip"]).keys() #Assuming all CP nodes have IP
    if lispdb is None:
        LogIt(
            f"Error: No LISP Database entries found to parse", 1)
        return
    #print (print(json.dumps(lispdb, indent=4)))
    for edgename in lispdb.keys():
        statdevs = statdevs + 1
        edgeip = dnac_core.get(["Global", "Devices", edgename]).get("IP Address")
        for edgeinstance in lispdb.get(edgename):
            if re.match(r"^8", edgeinstance):
                edgeinstanceaf = "ethernet"
            else:
                edgeinstanceaf = "ip"
            local_macs = dnac_core.get(["lisp", "svi_interface", edgename])
            local_addr = []
            if local_macs is not None:
                for locals in local_macs:
                    for vals in local_macs[locals].keys():
                        local_addr.append(local_macs[locals][vals])
            else:
                local_addr = []
            #print(lispdb.get(edgename).get(edgeinstance).keys())
            for edgeeid in lispdb.get(edgename).get(edgeinstance).keys():
                #print (edgeeid)
                if lispdb.get(edgename).get(edgeinstance).get(edgeeid).get("eSource") is not "dynamic-eid":
                    edgeeid = edgeeid.split(",")[0]
                    if edgeeid.split('/')[0] in local_addr:
                        #print(  f"Debug: {edgename} {edgeinstance} {edgeeid} {edgeinstanceaf} is local address")
                        localstat=localstat+1
                    else:
                        success = True
                        for cp in cpnodes:
                            if edgeeid in dnac_core.get(["lisp", "site", edgeinstanceaf,cp,edgeinstance]).keys():
                                #print(f"LISP Database Analysis: found {edgeeid} on CP node {cp}")
                                rloc = dnac_core.get(["lisp", "site", edgeinstanceaf,cp,edgeinstance,edgeeid]).get('Last Register').split(':')[0]
                                if rloc == edgeip:
                                    pass
                                elif rloc == "--":
                                    pass
                                else:
                                    success = False
                                    print(f"LISP Database Analysis: {edgeeid} : In LISP database on {edgename}({edgeip}) CP node: {cp} reports RLOC {rloc} ")
                                    failedeid.append(edgeeid)
                        if success == False:
                            statfail = statfail + 1
                        else:
                            stateid = stateid + 1
    print(f"LISP Database Analysis: Number of EID checked {stateid}, failed {statfail}")
    print(f"LISP Database Analysis: Number of Local EID {localstat}")
    print(f"LISP Database Analysis: Number of Devices checked {statdevs}")
    return failedeid






def CheckEdgeDB():
    statdevs = 0
    statteids = 0
    stateids = 0
    statfail = 0
    lispdb = dnac_core.get(["lisp", "database"])
    if lispdb is None:
        LogIt(
            f"Error: No LISP Database entries found to parse", 1)
        return
    for edgename in lispdb.keys():
        statdevs = statdevs + 1
        edgeip = dnac_core.get(["Global", "Devices", edgename]).get("IP Address")
        for edgeinstance in lispdb.get(edgename):
            if re.match(r"^8", edgeinstance):
                edgeinstanceaf = "ethernet"
            else:
                edgeinstanceaf = "ip"
            for edgeeid in lispdb.get(edgename).get(edgeinstance).keys():
                cpinfo = dnac_core.get(["fabric", edgeinstanceaf, edgeinstance, edgeeid, "Register"])
                statteids = statteids + 1
                if cpinfo is None:
                    if 'skip' not in lispdb.get(edgename).get(edgeinstance).get(edgeeid).get(edgeip).get("Source"):
                        local_macs = dnac_core.get(["lisp", "svi_interface", edgename])
                        local_addr = []
                        for locals in local_macs:
                            for vals in local_macs[locals].keys():
                                local_addr.append(local_macs[locals][vals])
                        if edgeeid.split('/')[0] in local_addr:
                            LogIt(
                                f"Warning: {edgename} {edgeinstance} {edgeeid} {edgeinstanceaf} not present on CP nodes, is local address",
                                10)
                        else:
                            print(
                                f"Database Analysis:{edgename} has {edgeinstance} {edgeeid} {edgeinstanceaf} , not present on CP nodes ")
                            statfail = statfail + 1
                else:
                    if edgeip in cpinfo:
                        LogIt(
                            f"Debug: {edgename} {edgeip} {edgeinstance} {edgeeid} {edgeinstanceaf}  present on CP nodes",
                            99)
                    else:
                        LogIt(
                            f"Debug: {edgename} {edgeip} {edgeinstance} {edgeeid} {edgeinstanceaf} not showing as RLOC on CP nodes but RLOC is {cpinfo}",
                            4)
                        statfail = statfail + 1

    LogIt(f"LISP Database Analysis : Found {statteids} database entries on {statdevs} devices with {statfail} failures",
          0)
    return


def CheckEdgeMC():
    lispmc = dnac_core.get(["lisp", "map-cache"])
    # print(lispmc)
    statdevs = 0
    statteids = 0
    stateids = 0
    statfail = 0
    if lispmc is None:
        LogIt(
            f"Error: No LISP Map Cache entries found to parse", 1)
        return
    for edgename in lispmc.keys():
        statdevs = statdevs + 1
        edgeip = dnac_core.get(["Global", "Devices", edgename]).get("IP Address")
        for edgeinstance in lispmc.get(edgename):
            if re.match(r"^8", edgeinstance):
                edgeinstanceaf = "ethernet"
            else:
                edgeinstanceaf = "ip"
            for mcentry in lispmc[edgename][edgeinstance].keys():
                statteids = statteids + 1
                if lispmc[edgename][edgeinstance][mcentry]["State"] == "complete":
                    stateids = stateids + 1
                    cpinfo = dnac_core.get(["fabric", edgeinstance, mcentry, "RLOC"])
                    if cpinfo is None:
                        print(
                            f"Map Cache Analysis : Device:{edgename} reporting {edgeinstance}:{mcentry} with RLOC {lispmc[edgename][edgeinstance][mcentry]['RLOC']}" +
                            f" in map-cache entry not present on CP nodes. Expires in {lispmc[edgename][edgeinstance][mcentry]['Expired']} " +
                            f"Uptime: {lispmc[edgename][edgeinstance][mcentry]['Uptime']} ")
                        statfail = statfail + 1
                        pass
                    else:
                        if lispmc[edgename][edgeinstance][mcentry]["RLOC"] in cpinfo:
                            LogIt(
                                f"Map Cache Analysis : Device:{edgename} reporting {edgeinstance}:{mcentry} with RLOC {lispmc[edgename][edgeinstance][mcentry]['RLOC']} in map cache consistent with CP info RLOC  {cpinfo}",
                                20)
                        else:
                            print(
                                f"Map Cache Analysis : Device:{edgename} reporting {edgeinstance}:{mcentry} with RLOC {lispmc[edgename][edgeinstance][mcentry]['RLOC']} in map cache inconsistent with CP info RLOC  {cpinfo}")
                            statfail = statfail + 1
                elif lispmc[edgename][edgeinstance][mcentry]["State"] == "drop":
                    # print(f"{lispmc[edgename][edgeinstance][mcentry]}   {mcentry}")
                    pass
                elif re.match(r"^Negative", lispmc[edgename][edgeinstance][mcentry]['RLOC']):
                    # print(f"{lispmc[edgename][edgeinstance][mcentry]}   {mcentry}")
                    pass
    LogIt(
        f"Map Cache Analysis : Found {statteids} entries, verified {stateids} entry on {statdevs} devices with {statfail} failures",
        0)
    return


def Stats():
    devices = dnac_core.get(["lisp", "roles"])
    if devices is None:
        print(f"No fabric devices found, not printing stats")
        return

    totaldevices = len(devices.keys())
    totalborder = totalcp = totaledge = totalcpborder = 0
    print(f"Number of Fabric Devices parsed : {totaldevices}")
    for fabricdev in devices.keys():
        if (devices[fabricdev]['CP']) and (devices[fabricdev]['Border']):
            totalcpborder = totalcpborder + 1
        elif (devices[fabricdev]['CP']):
            totalcp = totalcp + 1
        elif (devices[fabricdev]['Border']):
            totalborder = totalborder + 1
        elif (devices[fabricdev]['XTR']):
            totaledge = totaledge + 1
        else:
            print("uh,dunno!" + devices[fabricdev])
    aps = dnac_core.get(["fabric", "ap"])
    if aps is None:
        totalap = 0
    else:
        totalap = len(aps.keys())
    print(f"Number of Border/CP nodes       : {totalcpborder}")
    print(f"Number of CP nodes              : {totalcp}")
    print(f"Number of Border nodes          : {totalborder}")
    print(f"Number of edge nodes            : {totaledge}")
    print(f"Number of Fabric Enabled AP     : {totalap}")
    return


def CheckRLOCreach():
    devices = dnac_core.get(["lisp", "roles"])
    if devices is None:
        return
    rlocips = []
    rlocnames = []
    reachfail = reachsuccess = 0
    reachtotal = 0
    for lispdevice in devices:
        reachtotal = reachtotal + 1
        if devices[lispdevice]['Border'] or devices[lispdevice]['XTR']:
            devi = dnac_core.get(["Global", "Devices", lispdevice])
            if devi is not None:
                rlocips.append(devi["IP Address"])
                rlocnames.append(lispdevice)
    iptables = dnac_core.get(["Global", "routing"])
    for lispdevice in rlocnames:
        iptable = set(iptables[lispdevice]["Global"])
        if set(rlocips).issubset(iptable):
            reachsuccess = reachsuccess + 1
            pass
        else:
            reachfail = reachfail + 1
            t = iptable.copy()
            t.intersection_update(set(rlocips))
            print(f"Reachability Analysis: {lispdevice} missing /32 reachability to :  {set(rlocips).difference(t)}")
    print(
        f"Reachability Analysis: Fabric Devices with full reachabily {reachsuccess}, devices without full reachability {reachfail}," +
        f" not checked {reachtotal - (reachsuccess + reachfail)}")
    return


def CheckLispSession(dnac,dnac_core):
    edgenodes = dnac_core.get(["devices", dnac.fabric, "EDGENODE"])
    borders = dnac_core.get(["devices", dnac.fabric, "BORDERNODE"])
    cpnodes = dnac_core.get(["devices", dnac.fabric, "MAPSERVER"])
    devices = []
    cp_nodes = []
    if cpnodes is None:
        print (f"no devices found in fabric {dnac.fabric} exiting")
        exit()
    for cp in cpnodes:
        #print (cpnodes[cp]["name"])
        cp_nodes.append(cpnodes[cp]["name"])
    for border in borders:
        #print(borders[border]["name"])
        devices.append(borders[border]["name"])
    for edge in edgenodes:
        #print(edgenodes[edge]["name"])
        devices.append(edgenodes[edge]["name"])
    esession = fsession = fails = 0
    for device in set(devices):
        sesdb = dnac_core.get(['lisp', 'session', device]).keys()
        for session in cpnodes:
            cpname = dnac_core.get(['devices',dnac.fabric,'MAPSERVER',session])["name"]
            if session not in sesdb:
                if cpname == device:
                    pass
                else:
                    fsession = fsession + 1
                    print(f"Session Analysis: CP session to {cpname} not present on {device}")
            else:
                print(f"Session Analysis: CP session to {cpname} present on {device}")
                esession = esession + 1
                if dnac_core.get(['lisp', 'session', device]).get(session).get('status') == "Down":
                    if dnac_core.get(['lisp', 'database', device]) is None:
                        print(f"Informational:Session Down on device {device} but no Database entries found")
                    else:
                        print(f"Session Analysis: {device} has LISP session in Down state to {cpname} with Database Entries present")
                        fails = fails + 1
    print(
        f"Session Analysis: Checked LISP sessions on {len(devices)} nodes towards {len(cpnodes)} CP nodes. Found {esession} sessions, missing {fsession}, failures {fails}")
    return


def CheckAccessTunnels():
    successap = successdevice = faileddevice = 0
    apinfo = dnac_core.get(['Access-Tunnel', 'Summary'])
    if apinfo is None:
        return
    for apdevice in apinfo:
        apcount = len(apinfo[apdevice].keys())
        fapcount = int(dnac_core.get(['Access-Tunnel', 'F0', 'Count', apdevice, 'Number'])['Tunnel Count'])
        rapcount = int(dnac_core.get(['Access-Tunnel', 'R0', 'Count', apdevice, 'Number'])['Tunnel Count'])
        if apcount == fapcount and apcount == rapcount:
            successap = successap + apcount
            successdevice = successdevice + 1
            pass
        else:
            print(
                f"AccessTunnel Analysis: Device {apdevice} has {apcount} Access Tunnels but showns  {rapcount} on R0 and {fapcount} on F0 ")
            faileddevice = faileddevice + 1
    print(
        f"Access Tunnel Analysis: verified {successdevice + faileddevice} nodes with {successap} AccessTunnels verified " +
        f"and {faileddevice} nodes with failures")
    return


def CheckCTS(dnac, dnac_core):
    ctsdevs = ctsfailed = 0
    ctsinfo = dnac_core.get(["Authentication", "CTS", "Devices"])
    if ctsinfo is None:
        return
    for ctsdevice in ctsinfo.keys():
        state = ctsinfo.get(ctsdevice).get("State")
        ctsdevs = ctsdevs + 1
        if state == "COMPLETE":
            pass
        else:
            print(f"CTS Enviroment error: CTS enviroment data not complete on {ctsdevice} state is {state}")
            ctsfailed = ctsfailed + 1
    print(
        f"CTS Analysis: verified CTS on {ctsdevs} nodes, {ctsfailed} failures found")
    return


def checksvi():
    devices = dnac_core.get(["lisp", "roles"])
    good_svi = bad_svi = 0
    if devices is None:
        return
    edgelist = []
    svilist = []
    for device in devices.keys():
        if devices[device]["Border"] == False and devices[device]["CP"] == False and devices[device]["XTR"] == True:
            svi_info = dnac_core.get(["lisp", "svi_interface", device])
            for svi in svi_info.keys():
                svilist.append(json.dumps(svi_info))
            edgelist.append(device)
    best_svi = collections.Counter(svilist).most_common(1)[0][0]
    for device in edgelist:
        svi_info = dnac_core.get(["lisp", "svi_interface", device])
        if json.dumps(svi_info) == best_svi:
            good_svi = good_svi + 1
        else:
            print(
                f"SVI Analysis: Device {device} has inconsistent Interface Vlan configuration with all other edge devices")
            bad_svi = bad_svi + 1
    print(f"SVI Analysis: Analyzed Interface Vlan config on {bad_svi + good_svi} , found inconsistency on {bad_svi} ")
    return


def check_locals(svi, sifs, device):
    succes = mismatch = notfound = 0
    local_svis = {}
    local_sifs = {}
    for vlans in sifs.keys():
        for IPs in sifs[vlans].keys():
            if sifs[vlans][IPs]["source"] == "L":
                local_sifs[vlans] = {"mac": sifs[vlans][IPs]["mac"], "IP": IPs}
    for svis in svi.keys():
        svi_id = re.findall(r"\d{4}$", svis)[0]
        local_sifs.get(svi_id)
        if local_sifs.get(svi_id) is None:
            print(f"Device-tracking analysis: No Device-Tracking local entry for SVI Vlan{svi_id} on {device}")
            notfound = notfound + 1
        else:
            if local_sifs.get(svi_id)["mac"] == svi[f"Vlan{svi_id}"]["mac"]:
                succes = succes + 1
            else:
                print(
                    f"Device-tracking analysis: Mismatch between Device Tracking and SVI configuration for Vlan{svi_id} on {device}")
                mismatch = mismatch + 1
    return succes, notfound, mismatch


def check_dt():
    devices = build_edge_list()
    succes = mismatch = notfound = 0
    total_succes = total_mismatch = total_notfound = 0
    for device in devices:
        svi_info = dnac_core.get(["lisp", "svi_interface", device])
        dt_info = dnac_core.get(["Global", "Device-tracking", device])
        if svi_info is None or dt_info is None:
            print(f"Device-tracking analysis:missing info to validate SVI to Device-Tracking for node: {device}")
            mismatch = succes = 0
            notfound = 1
        else:
            succes, notfound, mismatch = check_locals(svi_info, dt_info, device)
        total_succes = total_succes + succes
        total_notfound = notfound + total_notfound
        total_mismatch = mismatch + total_mismatch
    print(
        f"Device-tracking analysis: Verified {len(devices)} edge devices with SVI info, {total_succes} success, {total_mismatch} mismatches {total_notfound} info missing")
    return


def check_MTU():
    mtus = []
    badmtu = goodmtu = 0
    devices = build_fabric_list()
    for device in devices:
        MTU = dnac_core.get(["Global", "MTU", device])
        if MTU is None:
            print(f"MTU Analysis: System MTU not configured on device {device}")
        else:
            mtus.append(MTU["MTU"])
    best_mtu = collections.Counter(mtus).most_common(1)[0][0]
    if int(best_mtu) < 2000:
        print(f"MTU Analysis: System MTU {best_mtu} used in fabric lower then 2000")
    for device in devices:
        MTU = dnac_core.get(["Global", "MTU", device])
        if MTU is not None:
            if MTU["MTU"] == best_mtu:
                goodmtu = goodmtu + 1
            else:
                badmtu = badmtu + 1
                print(
                    f"MTU Analysis: System MTU on device {device} is {MTU['MTU']} inconsistent with most used MTU {best_mtu}")
    print(
        f"MTU Analysis: System MTU in fabric {best_mtu}, configured on {goodmtu} devices, misconfigured on {badmtu} devices")


def CheckAuth(dnac,dnac_core):
    apipa = noip = okip = total = not_authenticated = 0
    auth_db = dnac_core.get(["Global", "Authentication"])
    if auth_db is None:
        return
    for device in auth_db.keys():
        for interface in auth_db[device].keys():
            for mac in auth_db[device][interface].keys():
                if auth_db[device][interface][mac].get("Status") == "Authorized" \
                        or ((auth_db[device][interface][mac].get("Status") == "Unauthorized") and
                            (re.match(r".*Open", auth_db[device][interface][mac].get("Current Policy")))):
                    total = total + 1
                    ipv4 = auth_db[device][interface][mac].get("IPv4 Address")
                    ipv6 = auth_db[device][interface][mac].get("IPv6 Address")
                    if ipv4 == "Unknown":
                        print(
                            f"Authentication Analysis: client {mac} on {interface} {device} not showing an IPv4 Address")
                        noip = noip + 1
                    elif re.match(r"169.254", ipv4):
                        print(
                            f"Authentication Analysis: client {mac} on {interface} {device} using an APIPA IPv4 Address")
                        apipa = apipa + 1
                    else:
                        okip = okip + 1
                else:
                    not_authenticated = not_authenticated + 1
    print(f"Authentication Analysis: Verified {total} sessions on {len(auth_db.keys())} edges",
          f"found {okip} complete sessions, {noip} without an IP address and {apipa} with an APIPA IP address")
    print(f"Authentication Analysis: Found {not_authenticated} Failed Authentication sessions")

    return


def DatabaseTooFabric(dnac, dnac_core):
    statdevs = 0
    deids = 0
    ieids = 0
    leids = 0
    stateids = 0
    statfail = 0
    lispdb = dnac_core.get(["lisp", "database"])
    print(lispdb)
    if lispdb is None:
        LogIt(
            f"Error: No LISP Database entries found to parse", 1)
        return
    for edgename in lispdb.keys():
        statdevs = statdevs + 1
        edgeip = dnac_core.get(["Global", "Devices", edgename]).get("IP Address")
        for edgeinstance in lispdb.get(edgename):
            if re.match(r"^8", edgeinstance):
                edgeinstanceaf = "ethernet"
            else:
                edgeinstanceaf = "ip"
            for edgeeid in lispdb.get(edgename).get(edgeinstance).keys():
                eidinfo = dnac_core.get(["lisp", "database", edgename, edgeinstance, edgeeid])
                if eidinfo is None:
                    print("Error! what to do , what to do, we have an error. Panic!!!!!!")
                else:
                    eidsource = eidinfo["eSource"]
                    eidtype = eidinfo["eSource"]
                    rloc = eidinfo["RLOC"][0]
                    print(f"{rloc.keys()} {eidtype} {eidsource} {edgeeid}")
                    eidtest = dnac_core.get(["fabric", edgeinstance, edgeeid])
                    local_macs = dnac_core.get(["lisp", "svi_interface", edgename])
                    if local_macs is None:
                        local_macs = []
                    local_addr = []
                    for locals in local_macs:
                        for vals in local_macs[locals].keys():
                            local_addr.append(local_macs[locals][vals])
                    if edgeeid.split('/')[0] in local_addr:
                        eidtest = 'local'
                    if eidtest is None:
                        dnac_core.add(
                            ["fabric", edgeinstance, edgeeid, {"RLOC": rloc, "source": eidsource, "type": eidtype}])
                        if eidtype == "dynamic-eid":
                            deids = deids + 1
                        elif eidtype == "route-import,":
                            ieids = ieids + 1
                        elif re.match(r"^other.*", eidtype):
                            leids = leids + 1
                        stateids = stateids + 1
                    elif eidtest is 'local':
                        pass
                    else:
                        LogIt(
                            f"Debug:LISP Database Analysis: Duplicate Entry {edgeeid} {edgeinstance} on {rloc},likely SVI IP and Mac, to be improved soon!",
                            10)
                        statfail = statfail + 1
    print(f"LISP Database Analysis: Parsed {statfail + stateids} entries with {statfail} failures")
    print(f"LISP Database Analysis: {deids} Dynamic eids, {ieids} imported eids, {leids} local configured eids")
    return


def CPTooFabric(dnac, dnac_core):
    CPnodes = dnac_core.get(["lisp", "site"])
    if CPnodes is None:
        LogIt(
            f"Error: No LISP Control Plane Information found ,parsing results may be inconclusive", 1)
        return
    statecps = 0
    cpfabric = {}
    allid = set()
    for ar in CPnodes.keys():
        areid = CPnodes[ar]
        for nodes in areid.keys():
            node = areid[nodes]
            statecps = statecps + 1
            for lispinst in node.keys():
                instanceinfo = node[lispinst]
                for eidsp in instanceinfo.keys():
                    who = instanceinfo[eidsp]["Last Register"].split(':')[0]
                    state = instanceinfo[eidsp]["Status"]
                    # print (f"{eidsp} {lispinst} {who}")
                    dbinfo = dnac_core.get(["fabric", lispinst, eidsp])
                    if who == "--":
                        pass
                    elif dbinfo is None:
                        if re.match(r"yes", state):
                            LogIt(f"Notice:{eidsp} in {lispinst} not found in analyzed lisp databases, RLOC is {who}",
                                  11)
                        else:
                            LogIt(f"Debug:{eidsp} in {lispinst} not found state is {state},ignoring", 11)
                    else:
                        if who == dbinfo['RLOC']:
                            LogIt(f"Debug:{eidsp} {lispinst} {who} matches RLOC in LISP DB on {dbinfo['RLOC']}", 20)
                        else:
                            print(
                                f"CP Analysis:CP {nodes} reporting for {eidsp}:{lispinst} RLOC {who} but is present on  {dbinfo['RLOC']}")


def CP2Fabric(dnac, dnac_core):
    CPnodes = dnac_core.get(["lisp", "site"])
    if CPnodes is None:
        LogIt(
            f"Error: No LISP Control Plane Information found ,parsing results may be inconclusive", 1)
        return
    statecps = 0
    cpfabric = {}
    allid = set()
    for ar in CPnodes.keys():
        areid = CPnodes[ar]
        for nodes in areid.keys():
            node = areid[nodes]
            statecps = statecps + 1
            for lispinst in node.keys():
                instanceinfo = node[lispinst]
                for eidsp in instanceinfo.keys():
                    who = instanceinfo[eidsp]["Last Register"].split(':')[0]
                    state = instanceinfo[eidsp]["Status"]
                    # print (f"{eidsp} {lispinst} {who}{state}")
                    dnac_core.add(
                        ["fabric", lispinst, eidsp, {"RLOC": who, "state": state}])
    return


def BuildFabric(dnac, dnac_core):
    #   findip()
    print("*" * 80)
    DatabaseTooFabric(dnac, dnac_core)
    print("*" * 80)
    CPTooFabric(dnac, dnac_core)
    return
