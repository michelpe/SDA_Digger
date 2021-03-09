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
