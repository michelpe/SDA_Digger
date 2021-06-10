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
import SDA_Digger
import random


def parsetext1(dir, file):
    content = []
    pline = ""
    scount = 0
    cli = {}
    fd = open(dir + "/" + file, "r")
    hostname = re.split("\.", file)[0]
    fcont = fd.readlines()
    for line in fcont:
        line.strip("\n")
        if re.match(r"^\S*[Ss]how\s*", line):
            if len(content) >= 0:
                cli.update({pline: content})
                pline = line
            content = []
        else:
            content.append(line)
    if len(content) >= 0:
        cli.update({pline: content})
        print(pline)
    return {hostname: cli}

def parsetext(dir, file,dnac_core):
    fd = open(dir + "/" + file, "r")
    hostname = file.split(".")[0]
    parsed = []
    cmd = ""
    tdict = {"Name": hostname}
    dnac_core.add(["Global", "Devices", hostname, tdict])
    input = fd.readlines()
    for count,line in enumerate(input):
     if re.match(r"^\S*[Ss]ho\s*", line):
         if len(cmd) > 0:
            parsed.append(cmd)
         cmd = line.split('#')[-1]
     else:
         cmd= "".join([cmd,line])
    if len(cmd) > 0:
        parsed.append(cmd)
    for command in parsed:
        if re.match(r".*\n.*",command):
          ParseCommands.ParseSingleDev(command, hostname, dnac_core)
    return

#Using Bundle no data been pulled from DNAC. Creating Dummy data to run analysis scripts
def build_dnac_data(dnac,dnac_core):
    devs = dnac_core.get(["lisp","roles"])
    if devs is None:
        print("Device configuration not parsed to determine device roles, exiting")
        exit()
    borders = []
    cp = []
    edges = []
    devis ={}
    #print(devs)
    for devices in devs.keys():
        devis[devices]={}
        devis[devices]["uuid"]=int(random.randint(1000000000,9000000000))
        devis[devices]["ip"]=dnac_core.get(["Global","Devices",devices]).get("IP Address")
        if devs[devices]["Border"] is True:
            borders.append(devices)
        if devs[devices]["CP"] is True:
            cp.append(devices)
        if devs[devices]["XTR"] is True:
            edges.append(devices)
    #dnac_core.printit()
    for cpnode in cp:
        dnac_core.add(["devices", dnac.fabric, "MAPSERVER", devis[cpnode]['ip'],
                       {"name": cpnode, "id": devis[cpnode]["uuid"]}])
    for border in borders:
        dnac_core.add(["devices", dnac.fabric, "BORDERNODE", devis[border]['ip'],
                       {"name": border, "id": devis[border]["uuid"]}])
    for edge in edges:
        dnac_core.add(["devices", dnac.fabric, "EDGENODE", devis[edge]['ip'],
                       {"name": edge, "id": devis[edge]["uuid"]}])
    return

def ParseBundle(dnac_core,dir):
    dnac = DNAC_Connector.DnacCon("non-interactive", "", "","")
    files = os.listdir(dir)
    if files is None:
        return
    #fabriccli = {}
    for file in files:
        if re.match(r".*\.txt$", file):
            parsetext(dir, file,dnac_core)
    build_dnac_data(dnac,dnac_core)
    Analysis.Config2Fabric(dnac, dnac_core)
    Analysis.CP2Fabric(dnac, dnac_core)
    Analysis.CheckLispSession(dnac,dnac_core)
    Analysis.LispDBAnalysis(dnac,dnac_core)
    Analysis.CheckEdgeMC(dnac,dnac_core)
    #Analysis.check_MTU(dnac,dnac_core)
    #Analysis.check_dt(dnac,dnac_core)
    Analysis.CheckAuth(dnac,dnac_core)
    Analysis.CheckRLOCreach(dnac,dnac_core)
    Analysis.CheckCTS(dnac,dnac_core)
    #Analysis.checksvi(dnac,dnac_core)
    #dnac_core.printit()
    return


