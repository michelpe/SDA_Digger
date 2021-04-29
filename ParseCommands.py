import AnalysisCore
import re

from ParseLisp import *
from ParseGeneric import *
from ParseAccessTunnel import *


def version(output, key, hostname):
    return

def ParseWireless(output, key, hostname):
    return


def ParseAP(output, key, hostname):
    return


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
                    LogIt(f"Notice: Extracted IP address {ip} from IP routing table for {hostname}", 7)
    if len(iproute) > 0:
        AnalysisCore.add2(["Global", "routing", hostname, {"Global": iproute}])
    return


def CTSEnv(output, hostname,dnac_core):
    for line in output:
        splitline = line.split()
        if len(splitline) > 0:
            if re.match(r"^Current state", line):
                ctsstate = splitline[-1]
                if ctsstate != "COMPLETE":
                    LogIt(f"Error: CTS Enviroment in state {ctsstate}  on device {hostname}", 10)
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
                    LogIt(f"Notice: Extracted IP address {ip[0]} from config for {hostname}", 7)
    return


def ParseIP(output, key, hostname,dnac_core):
    # print(key)
    if len(key) > 1:
        if re.match(r"route.*", key[1]):
            IPRoute(output, hostname)


def ParseCTS(output, key, hostname,dnac_core):
    #print(key)
    if len(key) > 1:
        if re.match(r"env.*", key[1]):
            CTSEnv(output, hostname,dnac_core)
    return

def parse_svi(output,hostname,dnac_core):
    vlan = mac = ip = ""
    tdict= {}
    for line in output:
        splitted = line.split()
        if re.match(r"^interface Vlan[12]\d{3}", line):
          tdict["vrf"] = "Global Routing Table"
          vlan = splitted[-1]
        elif re.match(r"^ mac-address", line):
          tdict["mac"] = splitted[-1]
        elif re.match(r"^ ip address", line):
          tdict["ip"] = splitted [-2]
        elif re.match(r"^ ipv6 address", line):
          tdict["ipv6"] = splitted[-1].split('/')[0]
        elif re.match(r"^ vrf forwarding", line):
          tdict["vrf"] = splitted[-1]
        elif re.match(r"^ lisp mobility", line):
            dnac_core.add(["lisp","svi_interface",hostname,vlan,tdict])
    return


def ParseMTU(output,hostname,dnac_core):
    MTU=output.split()[-1]
    dnac_core.add(["Global","MTU", hostname,{"MTU": MTU}])
    return


def ParseConfig(output, hostname,dnac_core):
    output = re.split(r"\n", output)
    splits = splititup(output, "^!")
    #print (splits[0])
    for splitted in splits:
        #print(f"dd{splitted}")
        if len(splitted) > 1:
            if re.match(r"^router lisp", splitted[1]):
                pass
                #ParseLispConfig(splitted[1:], hostname,dnac_core)
  #          elif re.match(r"^interface Loopback0", splitted[1]):
  #              ParseLoop0(splitted[1:], hostname,dnac_core)
            elif re.match(r"^interface Vlan[12]\d{3}", splitted[1]):
                parse_svi(splitted[1:],hostname,dnac_core)
            #Going through part that was splitted to find one line configs like system mtu
            else:
                for line in splitted:
                    if re.match(r"^system mtu",line):
                        ParseMTU(line,hostname,dnac_core)

    return

def ParseDT(output, key, hostname,dnac_core):
    start_dts=["L","API","ND","DH4","ARP","DH6"]
    for lines in output:
        line_split = lines.split()
        if len(line_split)>1:
            if line_split[0] in start_dts:
                dnac_core.add(["Global","Device-tracking",hostname,line_split[4],line_split[1],{"mac":line_split[2],
                                   "source":line_split[0],"interface":line_split[3],"vlan":line_split[4],"age":line_split[6],
                                   "state":line_split[7]}])
    return





def ParseAccess(output, key, hostname,dnac_core):
    tdict={}
    Acc_fields=["Interface","MAC Address","User-Name","Status","IPv4 Address","Oper host mode","Session timeout",
                "Device-type","Device-name","Domain","Current Policy"]
    if len(key)>2:
      for line in (output):
          splitted=line.split(":")
          splitted[0]=splitted[0].strip()
          if len(splitted) > 0:
             if splitted[0] in Acc_fields:
                tdict[splitted[0]]=splitted[-1].strip()
             elif re.match(r"IPv6 Address",splitted[0]):
                tdict["IPv6 Address"]=line.split()[2]
             elif re.match(r"dot1x",splitted[0]):
                 tdict["dot1x"] = ' '.join(line.split()[1:])
             elif re.match(r"mab",splitted[0]):
                 tdict["mab"] = ' '.join(line.split()[1:])
                 dnac_core.add(["Global", "Authentication",hostname,tdict["Interface"],tdict["MAC Address"],tdict])
                 tdict={}
    return


def ParseSingleDev(output, hostname,dnac_core):
        command = re.split (r"\n", output)[0]
        output = re.split(r"\n",output)
        splitkey = re.split(r'\s', command)
        #print(splitkey)
        if len(splitkey) > 1:
            if re.match(r"[Vv]er.*", splitkey[1]):
                version(output, splitkey[1:], hostname,dnac_core)
            elif re.match(r"lisp.*", splitkey[1]):
                lisp(output, splitkey[1:], hostname,dnac_core)
            elif re.match(r"ip", splitkey[1]):
                ParseIP(output, splitkey[1:], hostname,dnac_core)
            elif re.match(r"cts", splitkey[1]):
                ParseCTS(output, splitkey[1:],hostname,dnac_core)
            elif re.match(r"running", splitkey[1]):
                ParseConfig(output, splitkey[1:], hostname,dnac_core)
            elif re.match(r"access-tunnel", splitkey[1]):
                ParseAccessTunnel(output, splitkey[1:], hostname,dnac_core)
            elif re.match(r"device-tracking", splitkey[1]):
                ParseDT(output, splitkey[1:], hostname,dnac_core)
            elif re.match(r"wireless", splitkey[1]):
                ParseWireless(output, splitkey[1:], hostname,dnac_core)
            elif re.match(r"wireless", splitkey[1]):
                ParseAP(output, splitkey[1:], hostname,dnac_core)
            elif re.match(r"access-session", splitkey[1]):
                ParseAccess(output, splitkey[1:], hostname,dnac_core)
            elif len(splitkey) > 6:
                if re.match(r"access-tunnel", splitkey[3]):
                    ParseAccessTunnel(output, splitkey[1:], hostname,dnac_core)


def ParseCommand(fabriccli):
    for key in fabriccli.keys():
        tdict = {}
        tdict = {"Name": key}
        AnalysisCore.add(["Global", "Devices", key, tdict])
        ParseSingleDev(fabriccli[key], key)
    return
