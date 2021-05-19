import re
import AnalysisCore
from Loggin import *
import json


def splititup(output, divider):
    i = [num
         for num, line in enumerate(output)
         if re.match(divider, line)]
    i.append(len(output))
    return [output[i[num]:i[num + 1]]
            for num, t in enumerate(i[:-1])]


def LispMapCache(output, hostname, dnac_core):
    splits = (splititup(output, "^Output"))
    for spli in splits:
        linstance = str.split(spli[0])[-1]
        leid = ""
        if len(spli) > 0:
            for eid in spli[1:]:
                lsp = eid.split()
                # print(lsp)
                tdict = {}
                if len(lsp) > 1:
                    if re.match(r".*\,", lsp[0]):
                        leid = lsp[0].strip(',')
                        lutime = lsp[2]
                        lexpire = lsp[4]
                        laction = "na"
                        if len(lsp) > 7:
                            laction = lsp[7]
                        lsource = lsp[6]
                    elif re.match(r"^\d*\.\d*\.\d*\.\d*$", lsp[0]) or re.match(r"Encap.*", lsp[0]) or re.match(
                            r"Negat.*", lsp[0]):
                        lestate = lsp[3:]
                        lrloc = lsp[0]
                        if lsp[0] == "Encapsulating" or lsp[0] == "Negative":
                            lrloc = eid.strip()
                        tdict = {"RLOC": lrloc, "Source": lsource, "State": laction, "Uptime": lutime,
                                 "Expired": lexpire}
                        dnac_core.add(["lisp", "map-cache", hostname, linstance, leid, tdict])


def LispDatabase(output, hostname, instance, AF, dnac_core):
    splits = []
    if instance == "*":
        splits = (splititup(output, "^[Oo]utput"))
    else:
        splits.append(output)
    for spli in splits:
        linstance = str.split(spli[0])[-1]
        leid = ""
        if len(spli) > 0:
            for eid in spli[1:]:
                lsp = eid.split()
                tdict = {}
                if len(lsp) > 1:
                    if re.match(r".*\,", lsp[0]):
                        leid = lsp[0].strip(',')
                        lsource = lsp[1:]

                        if re.match(".*Inactive.*", lsp[1]):
                            ldrange = "na"
                        else:
                            ldrange = lsp[2]
                    elif re.match(r"^\d*\.\d*\.\d*\.\d*$", lsp[0]):
                        lestate = lsp[3:]
                        #                       print (lsp)
                        tdict = {"Conf": lsp[2], "Source": lsource, "Dyn EID": ldrange, "State": lestate, "AF": AF,
                                 "RLOC": lsp[0]}
                        dnac_core.add(["lisp", "database", hostname, linstance, leid, tdict])

    return


def LispDatabase1(output, hostname, instance, AF, dnac_core):
    rloc = []
    set = {}
    tdict = {}
    eid = None
    next_ip = ""
    for lines in output:
        splitline = lines.split()
        if re.match(r"^Output", lines):
            instance = splitline[-1]
        elif re.match(r".*locator-set.*", lines):
            if eid is not None:
                dnac_core.add(["lisp", "database", hostname, instance, eid, tdict])
                eid = None
                next_ip = ""
                tset = {}
                break
            eid = splitline[0]
            if splitline[1] == "route-import":
                tdict["eSource"] = "route-import"
            elif splitline[1] == "import":
                tdict["eSource"] = "site-registration"
            elif splitline[1] == "dynamic-eid":
                tdict["eSource"] = "dynamic-eid"
            else:
                tdict["eSource"] = f"other {splitline[1:]}"
        elif re.match(r"^ ", lines):
            if re.match(r"^\d*\.\d*\.\d*\.\d*$", splitline[0]):
                if next_ip == "Server":
                    server = splitline[0]
                else:
                    rloc.append({splitline[0]: {"Conf": splitline[2], "eSource": splitline[3:]}})
                    tdict["RLOC"] = rloc
        elif re.match(r"^ Locator", lines):
            next_ip = "Locator"
        else:
            tdict["Other"] = lines
    if eid is not None:
        dnac_core.add(["lisp", "database", hostname, instance, eid, tdict])
    return


def LispDatabaseAR(output, hostname, dnac_core, instance):
    tdict = dict()
    l2instance = 0
    if instance == "*":
        splits = (splititup(output, "^LISP ETR Address Resolution "))
    else:
        splits = [output]
    for split in splits:
        l2instance = str.split(split[0])[-1]
        for line in split:
            if re.match(r"^\w{4}\.\w{4}.\w{4}", line):
                linesplit = line.split()
                leid = linesplit[0]
                l3instance = linesplit[2]
                l3eid = linesplit[1].split('/')[0]
                tdict = {"l3instance": l3instance}
                dnac_core.add(["lisp", "AR", hostname, leid, l3eid, tdict])
    return


def LispDatabaseWLC(output, hostname, dnac_core):
    tdict = dict()
    linstance = 0
    for lines in output:
        splitline = lines.split()
        if re.match(r"Output for router", lines):
            if linstance != 0:
                if len(tdict) != 0:
                    dnac_core.add(["lisp", "wireless", hostname, linstance, tdict])
                    linstance = splitline[-1]
                    tdict = dict()
            else:
                linstance = splitline[-1]
        elif re.match(r"Hardware Address", lines):
            hardware = splitline[-1]
        elif re.match(r"Sources", lines):
            sources = splitline[-1]
        elif re.match(r"Source MS", lines):
            sourcems = splitline[-1]
        elif re.match(r"RLOC", lines):
            rloc = splitline[-1]
        elif re.match(r"Up", lines):
            uptime = splitline[-1]
        elif re.match(r"Type", lines):
            etype = splitline[-1]
        elif re.match(r"Metadata", lines):
            tdict[hardware] = {"sources": sources, "MS": sourcems, "RLOC": rloc, "Uptime": uptime, "Type": etype}
    if len(tdict) > 0:
        dnac_core.add(["lisp", "wireless", hostname, linstance, tdict])
    return


def LispSession(output, hostname, dnac_core):
    tdict = dict()
    for lines in output:
        splitline = lines.split()
        if len(splitline) > 1:
            if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", splitline[0]):
                tlisp = splitline[0].split(":")
                tdict[tlisp[0]] = {"status": splitline[1], "age": splitline[2], "port": tlisp[-1]}
    #                if re.match(r"[Uu][Pp]", splitline[1]):
    #                    LogIt("Notice: Lisp Session to %s is %s on device %s" % (splitline[0], splitline[1], hostname), 7)
    #                else:
    #                    LogIt("Error: Lisp Session to %s is %s on device %s" % (splitline[0], splitline[1], hostname), 7)
    if len(tdict) != 0:
        dnac_core.add(["lisp", "session", hostname, tdict])


def LispSite(output, hostname, dnac_core):
    tdict = dict()
    instance = 0
    for lines in output:
        splitline = lines.split()
        if len(splitline) > 4 and re.search(r"4\d\d\d", lines):
            if instance == 0:
                instance = splitline[-2]
            elif instance != splitline[-2]:
                dnac_core.add(["lisp", "site", "ip", hostname, instance, tdict])
                tdict = dict()
                instance = splitline[-2]
            tdict[splitline[-1]] = {"Last Register": splitline[-3], "Status": splitline[-4], "Last Time": splitline[-5]}
    if len(tdict) > 0:
        dnac_core.add(["lisp", "site", "ip", hostname, instance, tdict])


def LispEthServer(output, hostname, dnac_core):
    tdict = dict()
    instance = 0
    for lines in output:
        splitline = lines.split()
        if len(splitline) > 4 and re.match(r".*\..*\..*\/48", splitline[-1]):
            if instance == 0:
                instance = splitline[-2]
            elif instance != splitline[-2]:
                dnac_core.add(["lisp", "site", "ethernet", hostname, instance, tdict])
                tdict = dict()
                instance = splitline[-2]
            tdict[splitline[-1]] = {"Last Register": splitline[-3], "Status": splitline[-4], "Last Time": splitline[-5]}
    if len(tdict) > 0:
        dnac_core.add(["lisp", "site", "ethernet", hostname, instance, tdict])
        # print(f"{instance}{tdict}")
    return


def LispEthServerAR(output, hostname, dnac_core):
    return


def lisp(output, key, hostname, dnac_core):
    # print (key)
    if len(key) > 1:
        if re.match(r"session", key[1]):
            LispSession(output, hostname, dnac_core)
        elif re.match(r"site", key[1]):
            LispSite(output, hostname, dnac_core)
        elif re.match(r"instance", key[1]):
            if len(key) >= 5:
                if "database" in key:
                    if "address-resolution" in key:
                        LispDatabaseAR(output, hostname, dnac_core, key[2])
                    elif "wlc" in key:
                        LispDatabaseWLC(output, hostname, dnac_core)
                    else:
                        LispDatabase(output, hostname, key[2], key[3], dnac_core)
                elif re.match(r"map-cache", key[4]):
                    LispMapCache(output, hostname, dnac_core)
                elif re.match(r"server", key[4]):
                    if re.match(r"address-.*", key[-1]):
                        LispEthServerAR(output, hostname, dnac_core)
                    else:
                        LispEthServer(output, hostname, dnac_core)

    return


def ParseLispConfig(output, hostname,dnac_core):
    splits = splititup(output, "^ !")
    role = {"Border": False, "CP": False, "XTR": False}
    instance = ""
    bcast = ""
    eidtype = ""
    eidvalue = ""
    for splitted in splits:
        if len(splitted) > 1:
            for splited in splitted:
                splitup=splited.split()
                if (re.match(r"^ site", splited)):
                    role["CP"] = True
                elif (re.match(r".*proxy-etr.*", splited)) or (re.match(r".*route-import database", splited)):
                    role["Border"] = True
                elif re.match(r".*database-mapping", splited):
                    role["XTR"] = True
                elif re.match(r".*instance-id \d\d\d\d",splited):
                    instance=splitup[-1]
                elif re.match(r".*broadcast-underlay", splited):
                    bcast=splitup[-1]
                elif re.match(r".*eid-table", splited):
                    eidvalue=splitup[-1]
                    eidtype =splitup[-2]
                elif re.match(r".* service ",splited):
                    AF=splitup[-1]
                elif re.match(r".*exit-instance-id", splited):
                    dnac_core.add(["lisp", "config", hostname, "instances", instance,{"broadcast":bcast,"type":eidtype,"value":eidvalue,"AF":AF}])
                    instance = ""
                    bcast = ""
                    eidtype = ""
                    eidvalue= ""
    dnac_core.add(["lisp", "roles", hostname, role])
    LogIt(f"Debug: Device {hostname} assigned roles {role}", 10)

    return
