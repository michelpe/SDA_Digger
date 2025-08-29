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

import AnalysisCore
import re
from ParseLisp import *
from ParseGeneric import *


def version(output, key, hostname, dnac_core):
    return


def ParseAP(output, key, hostname, dnac_core):
    return


def splititup(output, divider):
    i = [num
         for num, line in enumerate(output)
         if re.match(divider, line)]
    i.append(len(output))
    return [output[i[num]:i[num + 1]]
            for num, t in enumerate(i[:-1])]


def IPRoute(output, hostname, dnac_core):
    route_types = ["C", "S", "L", "O", "B", "D", "i", "EX", "R", "M", "E2", "E1", "N1", "N2", "IL1", "IL2", "IA", "SU"]
    iproute = []
    for line in output:
        splitline = line.split()
        if len(splitline) > 1:
            if splitline[0] in route_types:
                for splits in splitline:
                    ipadd = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", splits)
                    if len(ipadd) > 0:
                        iproute.append(ipadd[0].split('/')[0])
    if len(iproute) > 0:
        dnac_core.add(["Global", "routing", hostname, {"Global": iproute}])
    return

def CTSEnv(output, hostname, dnac_core):
    for line in output:
        splitline = line.split()
        if len(splitline) > 0:
            if re.match(r"^Current state", line):
                ctsstate = splitline[-1]
                tdict = {"State": ctsstate}
                dnac_core.add(["Authentication", "CTS", "Devices", hostname, tdict])
    return


def ParseLoop0(output, hostname, dnac_core):
    for lines in output:
        if re.match(r"^ ip address", lines):
            ip = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", lines)
            if len(ip) > 1:
                if (dnac_core.get(["Global", "Devices", hostname, 'IP Address'])) is None:
                    dnac_core.modify(["Global", "Devices", hostname], 'IP Address', ip[0])
    return


def IPMRoute(output, hostname, dnac_core):
    sourceip = destip = flags = rp = None
    Out = False
    egress = []
    for line in output:
        splitline = line.split()
        if re.match(r"^\(.*", line):
            sourceip = splitline[0].strip('(,')
            destip = splitline[1].strip('),')
            flags = splitline[-1]
            if sourceip == '*':
                rp = splitline[-3]
        elif re.match(r".*Incoming interface:.*", line):
            rpf = splitline[-1]
            incoming = splitline[2]
            if re.match(r".*Registering.*", line):
                rpf = splitline[6]
                if len(splitline) > 7:
                    rpf = f"{splitline[6]} {splitline[7]}"
        elif re.match(r".*Outgoing interface list:.*", line):
            Out = True
        elif len(splitline) < 2 and sourceip is not None:
            Out = False
            dnac_core.add(["Global", "underlay mroute", destip, hostname, sourceip,
                           {"RPF": rpf, "flags": flags, "incoming": incoming, "egress": egress, "RP": rp}])
            egress = []
            sourceip = destip = flags = None
        elif Out is True:
            egress.append({splitline[0]: {"Mode": splitline[1], "age": splitline[2]}})
    return


def IPMFib(output, hostname, dnac_core):
    return


def ParseIP(output, key, hostname, dnac_core):
    # print(key)
    if len(key) > 1:
        if re.match(r"route.*", key[1]):
            IPRoute(output, hostname, dnac_core)
        elif re.match(r"mroute.*", key[1]):
            IPMRoute(output, hostname, dnac_core)
        elif re.match(r"mfib.*", key[1]):
            IPMFib(output, hostname, dnac_core)


def ParseCTS(output, key, hostname, dnac_core):
    # print(key)
    if len(key) > 1:
        if re.match(r"env.*", key[1]):
            CTSEnv(output, hostname, dnac_core)
    return


def parse_svi(output, hostname, dnac_core):
    vlan = mac = ip = ""
    tdict = {}
    for line in output:
        splitted = line.split()
        if re.match(r"^interface Vlan[12]\d{3}", line):
            tdict["vrf"] = "Global Routing Table"
            vlan = splitted[-1]
        elif re.match(r"^ mac-address", line):
            tdict["mac"] = splitted[-1]
        elif re.match(r"^ ip address", line):
            tdict["ip"] = splitted[-2]
        elif re.match(r"^ ipv6 address", line):
            tdict["ipv6"] = splitted[-1].split('/')[0]
        elif re.match(r"^ vrf forwarding", line):
            tdict["vrf"] = splitted[-1]
        elif re.match(r"^ lisp mobility", line):
            dnac_core.add(["lisp", "svi_interface", hostname, vlan, tdict])
    return


def ParseMTU(output, hostname, dnac_core):
    MTU = output.split()[-1]
    dnac_core.add(["Global", "MTU", hostname, {"MTU": MTU}])
    return


def ParseWLCConfig(output, hostname, dnac_core):
    tdict = {"interfaces": {}}
    output = re.split(r"\n", output)
    splits = splititup(output, "^!")
    ips = set()
    for splitted in splits:
        if len(splitted) > 1:
            if re.match(r"^interface ", splitted[1]):
                interface = splitted[1].split()[-1]
                for line in splitted[1:]:
                    if (r".*ip address \d.*}"):
                        section = line.split()
                        if len(section) == 4:
                            tdict["interfaces"][interface] = section[2]
                            ips.add(section[2])
            elif re.match(r"^ap ", splitted[1]):
                print(splitted[1:])
    for line in output:
        if re.match(r" *wireless management interface", line):
            tdict["management"] = line.split()[-1]
    dnac_core.add(["Global", "WLC_Config", hostname, tdict])
    dnac_core.add(["lisp", "wlcip", {"ip addresses": list(ips)}])
    return


def ParseConfig(output, hostname, dnac_core):
    if type(output) != list:
        output = re.split(r"\n", output)
    splits = splititup(output, "^!")
    # print (splits[0])
    for splitted in splits:
        # print(f"dd{splitted}")
        if len(splitted) > 1:
            if re.match(r"^router lisp", splitted[1]):
                ParseLispConfig(splitted[1:], hostname, dnac_core)
            elif re.match(r"^interface Loopback0", splitted[1]):
                ParseLoop0(splitted[1:], hostname, dnac_core)
            elif re.match(r"^interface Vlan[12]\d{3}", splitted[1]):
                parse_svi(splitted[1:], hostname, dnac_core)
            # Going through part that was splitted to find one line configs like system mtu
            else:
                for line in splitted:
                    if re.match(r"^system mtu", line):
                        ParseMTU(line, hostname, dnac_core)

    return


def ParseDT(output, key, hostname, dnac_core):
    start_dts = ["L", "API", "ND", "DH4", "ARP", "DH6"]
    for lines in output:
        line_split = lines.split()
        if len(line_split) > 1:
            if line_split[0] in start_dts:
                dnac_core.add(
                    ["Global", "Device-tracking", hostname, line_split[4], line_split[1], {"mac": line_split[2],
                                                                                           "source": line_split[0],
                                                                                           "interface": line_split[3],
                                                                                           "vlan": line_split[4],
                                                                                           "age": line_split[6],
                                                                                           "state": line_split[7]}])
    return


def ParseMac(output, key, hostname, dnac_core):
    tdict = {}
    for lines in output:
        line_split = lines.split()
        if len(line_split) > 3:
            if re.match(r"[12]\d\d\d", line_split[0]):
                dnac_core.add(["Global", "mac", hostname, line_split[0], line_split[1],
                               {"Source": line_split[2], "Int": line_split[3]}])


def ParseAccess(output, key, hostname, dnac_core):
    tdict = {}
    Acc_fields = ["Interface", "MAC Address", "User-Name", "Status", "IPv4 Address", "Oper host mode",
                  "Session timeout",
                  "Device-type", "Device-name", "Domain", "Current Policy"]
    if len(key) > 2:
        for line in (output):
            splitted = line.split(":")
            splitted[0] = splitted[0].strip()
            if len(splitted) > 0:
                if splitted[0] in Acc_fields:
                    tdict[splitted[0]] = splitted[-1].strip()
                elif re.match(r"IPv6 Address", splitted[0]):
                    tdict["IPv6 Address"] = line.split()[2]
                elif re.match(r"dot1x", splitted[0]):
                    tdict["dot1x"] = ' '.join(line.split()[1:])
                elif re.match(r"mab", splitted[0]):
                    tdict["mab"] = ' '.join(line.split()[1:])
                    dnac_core.add(
                        ["Global", "Authentication", hostname, tdict["Interface"], tdict["MAC Address"], tdict])
                    tdict = {}
    return


def ParseBFDdetail(output, key, hostname, dnac_core):
    fake_handle = 10000
    for lines in output:
        splitline = lines.split()
        if len(splitline) > 0:
            if re.match(r"^IPv4 Sessions", lines):
                handle = fake_handle
                fake_handle = fake_handle + 1
                tset = {}
            elif re.match(r"\d{0,3}\.\d{0,3}\.\d{0,3}.\.\d{0,3}.", splitline[0]):
                tset["neighbor"] = splitline[0]
                tset["interface"] = splitline[-1]
                tset["State"] = splitline[-2]
            elif re.match(r"^handle", splitline[0].lower()):
                handle = splitline[-1]
            elif re.match(r"uptime", splitline[0].lower()):
                tset["uptime"] = splitline[-1]
                dnac_core.add(["Global", "bfd", hostname, handle, tset])
    return


def ParseBFD(output, key, hostname, dnac_core):
    if key[-1] == "detail":
        ParseBFDdetail(output, key, hostname, dnac_core)
        return
    return


def ParseAAA(output, key, hostname, dnac_core):
    for line in output:
        pass
    return

def ParseSoftwareFedL3ifm(output, key, hostname, dnac_core):
    for lines in output:
        if (re.match(r"^0x.*",lines)):
            line= lines.split()
            dnac_core.add(["Global", "platform","software-fed","l3ifm", hostname, line[0], {"if":line[1],"ifmid":line[2],"interface":line[3]}])

def ParseSoftwareFed(output, key, hostname, dnac_core):
    if key[-1]=="l3if-le":
        ParseSoftwareFedL3ifm(output, key, hostname, dnac_core)
    return

def ParseHardwareAbstraction(output, key, hostname, dnac_core):
    le_id=key[-2]
    for line in output:
        splitline=line.split()
        for splits in splitline:
            if re.match(r"index0.*",splits):
                dnac_core.add(["Global", "platform","hardware-fed","abstraction",hostname,le_id,{"index0":splits.split(":")[-1]}])
    return


def ParsePlatform(output, key, hostname, dnac_core):
    if len(key) < 3:
         return
    if key[1] == "software" :
        if  key[2] == "fed":
            ParseSoftwareFed(output, key, hostname, dnac_core)
        elif key[2] == "access-tunnel":
            ParsePlatAccessTunnel(output,key,hostname,dnac_core)
    elif key[1] == "hardware":
        if "abstraction" in key:
            ParseHardwareAbstraction(output, key, hostname, dnac_core)
    return


def ParseFabricAP(output, key, hostname, dnac_core):
    startfound = False
    for line in output:
        if re.match(r"-------------.*",line):
            startfound = True
        elif startfound is True:
            linesplit = line.split()
            if len(linesplit) > 7 :
                dnac_core.add(["Global", "ap-wlc", hostname, linesplit[-6],{"Name":linesplit[0],"State":linesplit[-1],
                "Country":linesplit[-3],"Location":linesplit[-4],"Radio-mac":linesplit[-5],"Base-mac":linesplit[-6],
                "Model":linesplit[2],"IP":linesplit[-2],"Radios":linesplit[1]}])
    return

def ParseFabricWlan(output, key, hostname, dnac_core):
    startfound = False
    for line in output:
        if re.match(r"-------------.*",line):
            startfound = True
        elif startfound is True:
            linesplit = line.split()
            if len(linesplit) > 3:
                dnac_core.add(["Global", "wlan-wlc",hostname,linesplit[0],{"SSID":linesplit[2],"Profile":linesplit[1],
                               "State":linesplit[-1]}])

def ParseFabricClient(output, key, hostname, dnac_core):
    startfound = False
    for line in output:
        if re.match(r"-------------.*",line):
            startfound = True
        elif startfound is True:
            linesplit = line.split()
            if len(linesplit) > 4:
                dnac_core.add(["Global","fabric-wclient",linesplit[1],linesplit[2],linesplit[0],{"state":linesplit[-3],
                              "method":linesplit[-1],"Protocol":linesplit[-2]}])
    return



def ParseAccessTunnel(output, key, hostname, dnac_core):
    accesstunnels ={}
    for line in output:
        linesplit=line.split()
        if len(linesplit)>1:
            if re.match(r"^Ac\d.*",linesplit[0]):
                if re.match(r".*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*",linesplit[1]):
                    accesstunnels[linesplit[0]]={"FE_IP":linesplit[1],"AP_IP":linesplit[2],"Port":linesplit[-1]}
                else:
                    if (accesstunnels.get(linesplit[0])) is not None:
                        accesstunnels[linesplit[0]]["Uptime"]=" ".join(linesplit[2:])
                    dnac_core.add(["Global","AccessTunnel",hostname,linesplit[0],accesstunnels[linesplit[0]]])


def ParsePlatAccessTunnel(output, key, hostname, dnac_core):
    startfound = False
    if key[-1].upper() == "F0" or key [-1].upper() == "R0":
        proc_loc = key[-1].upper()
        for line in output:
            if re.match(r".*Invalid input detected at.*", line):
                dnac_core.add(["Global", "PlatformAccessTunnel", hostname, "failed",proc_loc,{"cli":key}])
            elif re.match(r"-------------.*", line):
                startfound = True
            elif startfound is True:
                linesplit = line.split()
                if len(linesplit)>1:
                    if re.match(r"^Ac\d*",linesplit[0]):
                        dnac_core.add(["Global", "PlatformAccessTunnel", hostname,proc_loc, linesplit[0],
                                       {"FE_IP":linesplit[1],"AP_IP":linesplit[2],"IF_ID":linesplit[5]}])


def ParseWireless(output, key, hostname, dnac_core):
    if key[1] == "fabric":
        if key[2] == "client":
            ParseFabricClient(output, key, hostname, dnac_core)
    return


def ParseFabric(output, key, hostname, dnac_core):
    if key[1]=="ap":
        ParseFabricAP(output, key, hostname, dnac_core)
    if key[1]=="wlan":
        ParseFabricWlan(output, key, hostname, dnac_core)
    return


def ParseSingleDev(output, hostname, dnac_core):
    command = re.split(r"\n", output)[0]
    output = re.split(r"\n", output)
    splitkey = re.split(r'\s', command)
    # print(splitkey)
    if len(splitkey) > 1:
        if re.match(r"[Vv]er.*", splitkey[1]):
            version(output, splitkey[1:], hostname, dnac_core)
        elif re.match(r"lisp.*", splitkey[1]):
            lisp(output, splitkey[1:], hostname, dnac_core)
        elif re.match(r"ip", splitkey[1]):
            ParseIP(output, splitkey[1:], hostname, dnac_core)
        elif re.match(r"cts", splitkey[1]):
            ParseCTS(output, splitkey[1:], hostname, dnac_core)
        elif re.match(r"running", splitkey[1]):
            ParseConfig(output, hostname, dnac_core)
        elif re.match(r"access-tunnel", splitkey[1]):
            ParseAccessTunnel(output, splitkey[1:], hostname,dnac_core)
        elif re.match(r"device-tracking", splitkey[1]):
            ParseDT(output, splitkey[1:], hostname, dnac_core)
        elif re.match(r"wireless", splitkey[1]):
            ParseWireless(output, splitkey[1:], hostname, dnac_core)
        elif re.match(r"wireless", splitkey[1]):
            ParseAP(output, splitkey[1:], hostname, dnac_core)
        elif re.match(r"access-session", splitkey[1]):
            ParseAccess(output, splitkey[1:], hostname, dnac_core)
        elif re.match(r"mac", splitkey[1]):
            ParseMac(output, splitkey[1:], hostname, dnac_core)
        elif re.match(r"bfd", splitkey[1]):
            ParseBFD(output, splitkey[1:], hostname, dnac_core)
        elif re.match(r"aaa", splitkey[1]):
            ParseAAA(output, splitkey[1:], hostname, dnac_core)
        elif re.match(r"platform", splitkey[1]):
            ParsePlatform(output, splitkey[1:], hostname, dnac_core)
        elif re.match(r"fabric", splitkey[1]):
            ParseFabric(output, splitkey[1:], hostname, dnac_core)
        elif len(splitkey) > 6:
            if re.match(r"access-tunnel", splitkey[3]):
                # ParseAccessTunnel(output, splitkey[1:], hostname,dnac_core)
                pass


def ParseCommand(fabriccli, dnac_core):
    for key in fabriccli.keys():
        tdict = {}
        tdict = {"Name": key}
        dnac_core.add(["Global", "Devices", key, tdict])
        print(fabriccli[key])
        ParseSingleDev(fabriccli[key], key, dnac_core)
        exit()
    return
