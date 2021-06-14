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

import re
import AnalysisCore
from ParseLisp import *


def splititup(output, divider):
    i = [num
         for num, line in enumerate(output)
         if re.match(divider, line)]
    i.append(len(output))
    return [output[i[num]:i[num + 1]]
            for num, t in enumerate(i[:-1])]


def IPRoute(output, hostname):
    iproute = []
    for line in output:
        splitline = line.split()
        ipadd = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/32", line)
        if len(ipadd) > 0:
            iproute.append(ipadd[0].split('/')[0])
        if len(splitline) > 0:
            if splitline[0] == "C":
                # Check for Loopback0
                if splitline[-1] == "Loopback0":
                    ip = splitline[1].split("/")[0]
                    AnalysisCore.modify(["Global", "Devices", hostname], 'IP Address', ip)
                    AnalysisCore.add2(["Global", "IP", ip, {"Hostname": hostname}])
    if len(iproute) > 0:
        AnalysisCore.add2(["Global", "routing", hostname, {"Global": iproute}])
    return


def CTSEnv(output, hostname, dnac_core):
    for line in output:
        splitline = line.split()
        if len(splitline) > 0:
            if re.match(r"^Current state", line):
                ctsstate = splitline[-1]
                if ctsstate != "COMPLETE":
                    tdict = {"State": ctsstate}
                    dnac_core.add(["Authentication", "CTS", "Devices", hostname, tdict])
    return


def ParseLoop0(output, hostname):
    for lines in output:
        if re.match(r"^ ip address", lines):
            ip = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", lines)
            if len(ip) > 1:
                if (AnalysisCore.get(["Global", "Devices", hostname, 'IP Address'])) is None:
                    AnalysisCore.modify(["Global", "Devices", hostname], 'IP Address', ip[0])
    return


def ParseIP(output, key, hostname):
    # print(key)
    if len(key) > 1:
        if re.match(r"route.*", key[1]):
            IPRoute(output, hostname)


def ParseCTS(output, key, hostname, dnac_core):
    # print(key)
    if len(key) > 1:
        if re.match(r"env.*", key[1]):
            CTSEnv(output, hostname, dnac_core)
    return


def parse_svi(output, hostname):
    vlan = ""
    tdict = {}
    for line in output:
        splitted = line.split()
        if re.match(r"^interface Vlan[12]\d{3}", line):
            vlan = splitted[-1]
        elif re.match(r"^ mac-address", line):
            tdict["mac"] = splitted[-1]
        elif re.match(r"^ ip address", line):
            tdict["ip"] = splitted[-2]
        elif re.match(r"^ ipv6 address", line):
            tdict["ipv6"] = splitted[-1].split('/')[0]
        elif re.match(r"^ lisp mobility", line):
            AnalysisCore.add2(["lisp", "svi_interface", hostname, vlan, tdict])
    return


def ParseMTU(output, hostname):
    mtu = output.split()[-1]
    AnalysisCore.add2(["Global", "MTU", hostname, {"MTU": mtu}])
    return


def ParseConfig(output, key, hostname, dnac_core):
    splits = splititup(output, "^!")
    for splitted in splits:
        if len(splitted) > 1:
            if re.match(r"^router lisp", splitted[1]):
                ParseLispConfig(splitted[1:], hostname)
            elif re.match(r"^interface Loopback0", splitted[1]):
                ParseLoop0(splitted[1:], hostname)
            elif re.match(r"^interface Vlan[12]\d{3}", splitted[1]):
                parse_svi(splitted[1:], hostname)
            # Going through part that was splitted to find one line configs like system mtu
            else:
                for line in splitted:
                    if re.match(r"^system mtu", line):
                        ParseMTU(line, hostname)

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
                                                                                           "age": line_split[6],
                                                                                           "state": line_split[7]}])
    return
