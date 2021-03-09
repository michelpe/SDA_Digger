import json
from Loggin import LogIt

class Analysis_Core:
    def __init__(self):
        self.Parsed = {}


    def nesting(self,tdt, clist):
        # print(f"{tdt} {type(clist)}\n")
        if type(clist[0]) is dict:
            tdt = clist
            return
        if clist[0] in tdt.keys():
            pass
        else:
            if type(clist[1]) is dict:
                tdt[clist[0]] = clist[1]
                return
            else:
                tdt[clist[0]] = {clist[1]: {}}
        if len(clist) > 2:
            nesting(tdt[clist[0]], clist[1:])
        else:
            tdt[clist[0]] = clist[1]
        return


    def oneup(self,tdict, uplevel):
        ttdict = {}
        ttdict = {uplevel: tdict}
        return ttdict


    def buildstruct(self,clist):
        tdict = clist[-1]
        for i in range(len(clist) - 2, 0, -1):
            tdict = self.oneup(tdict, clist[i])
        return tdict

        '''Add function , interface to be called to safely add a leaf to the parsed structure'''

    def add(self,clist):
        #print(f"test....{self.Parsed}")
        t = self.get(clist[:-1])
        #print(f"command {t} {clist[:-1]}")
        if t is not None:
            print(f"Debug:duplicate entry, {clist} ")
            return
        tlist = []
        tdict = {}
        for i, commands in enumerate(clist):
            tlist.append(commands)
            if  self.get(tlist) is None:
                # print(f"{tlist} {clist[:-1]}  is empty could append dict here")
                tdict = self.buildstruct(clist[i:])
                ttdict = self.get(tlist[:-1])
                ttdict.update({commands: tdict})
                # print(f"************** {ttdict} {commands} return")
                return
            else:
                # print(f"{tlist}  {clist[:-1]} is not empty ")
                tdict = self.get(tlist[:-1])
                if commands in tdict.keys():
                    # print(f"{commands} found in keys")
                    pass
                else:
                    # print(f"{commands} not found in keys {clist[:-1]}, it new!")
                    tdict = self.buildstruct(clist[i:])
                    ttdict = self.get(tlist[:-1])
                    ttdict[commands] = tdict


    def modify(self,clist, label, value):
        oldval = self.get(clist)
        oldval[label] = value
        passalong = [*clist, oldval]
        self.add(passalong)
        return




        '''Dump the Parsed table for viewing'''


    def printit(self):

        print("\n" + "*" * 80)
        print("          Raw Data:")
        print(json.dumps(self.Parsed, indent=4))


    def get(self,clist):
        tdt = self.Parsed
        for clis in clist:
            if clis in tdt.keys():
                tdt = tdt[clis]
            else:
                return None

        return tdt
