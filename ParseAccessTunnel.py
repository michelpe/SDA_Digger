import re
import AnalysisCore
from Loggin import *
import json


def AccessTunnelSummary(output, hostname):
    tdict = dict()
    for lines in output:
        splitline = lines.split()
        if len(splitline) > 1:
            if re.match(r"Number", splitline[0]):
                LogIt("Notice: The Number of Access Tunnels on Device %s is %s" % (hostname, splitline[6]), 7)
            elif re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", splitline[1]):
                tdict[splitline[0]] = {"SrcIP": splitline[1], "DestIP": splitline[3]}
    if len(tdict) > 0:
        AnalysisCore.add2(["Access-Tunnel", "Summary", hostname, tdict])


def AccessTunnelF0(output, hostname):
    tdict = dict()
    for lines in output:
        splitline = lines.split()
        if len(splitline) > 1:
            if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", splitline[1]):
                tdict[splitline[0]] = {"Name": splitline[0], "SrcIP": splitline[1], "DestIP": splitline[2],
                                       "Iif_id": splitline[5]}
    if len(tdict) > 0:
        AnalysisCore.add2(["Access-Tunnel", "F0", hostname, tdict])


def AccessTunnelR0(output, hostname):
    tdict = dict()
    for lines in output:
        splitline = lines.split()
        if len(splitline) > 1:
            if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", splitline[1]):
                tdict[splitline[0]] = {"Name": splitline[0], "SrcIP": splitline[1], "DestIP": splitline[2],
                                       "Iif_id": splitline[5]}
    if len(tdict) > 0:
        AnalysisCore.add2(["Access-Tunnel", "R0", hostname, tdict])


def AccessTunnelF0Count(output, hostname):
    tdict = dict()
    for lines in output:
        splitline = lines.split()
        if len(splitline) > 1:
            tdict[splitline[0]] = {"Tunnel Count": splitline[-1]}
    if len(tdict) > 0:
        AnalysisCore.add2(["Access-Tunnel", "F0", "Count", hostname, tdict])


def AccessTunnelR0Count(output, hostname):
    tdict = dict()
    for lines in output:
        splitline = lines.split()
        if len(splitline) > 1:
            tdict[splitline[0]] = {"Tunnel Count": splitline[-1]}
    if len(tdict) > 0:
        AnalysisCore.add2(["Access-Tunnel", "R0", "Count", hostname, tdict])


def AccessTunnelF0Stat(output, hostname):
    tdict = dict()
    for lines in output:
        splitline = lines.split()
        #       if len(splitline) > 1:
        if len(splitline) > 1 and re.match(r"[0-9]", splitline[-1]):
            tdict[splitline[0]] = {"Counter": splitline[0], "Success/Failure": splitline[-1]}
    if len(tdict) > 0:
        AnalysisCore.add2(["Access-Tunnel", "F0", "Statistics", hostname, tdict])


def AccessTunnelR0Stat(output, hostname):
    tdict = dict()
    for lines in output:
        splitline = lines.split()
        #        if len(splitline) > 1:
        if len(splitline) > 1 and re.match(r"[0-9]", splitline[-1]):
            tdict[splitline[0]] = {"Counter": splitline[0], "Success/Failure": splitline[-1]}
    if len(tdict) > 0:
        AnalysisCore.add2(["Access-Tunnel", "R0", "Statistics", hostname, tdict])


def ParseAccessTunnel(output, key, hostname):
    if len(key) > 1:
        if re.match(r"access-tunnel", key[0]):
            AccessTunnelSummary(output, hostname)
        elif len(key) >= 6:
            if re.match(r"F0", key[5]):
                if re.match(r"statistics", key[6]):
                    AccessTunnelF0Stat(output, hostname)
                elif len(key) > 7 and re.match(r"count", key[7]):
                    AccessTunnelF0Count(output, hostname)
                elif re.match(r"", key[6]):
                    AccessTunnelF0(output, hostname)
            elif re.match(r"R0", key[5]):
                if re.match(r"statistics", key[6]):
                    AccessTunnelR0Stat(output, hostname)
                elif len(key) > 7 and re.match(r"count", key[7]):
                    AccessTunnelR0Count(output, hostname)
                elif re.match(r"", key[6]):
                    AccessTunnelR0(output, hostname)
    return
