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

import json
import sys


class Analysis_Core:
    def __init__(self):
        self.Parsed = {}
        self.rootpoint = None
        self.depth = 0
        self.iterlist = []
        self.value = None

#setiter function must be be called to setup iter function so that depth rootpoint is set
    def setiter(self, rootpoint, depth):
        self.rootpoint = rootpoint
        self.depth = depth - 1
        self.iterlist = list(range(depth))
        self.value = None

#recursive function to go through the nested dict structure and yield when reaching the depth
    def print_nested_dict(self, d, levl):
        if levl == self.depth:
            for key, value in d.items():
                self.iterlist[levl] = key
                yield self.iterlist, value
        else:
            for key, value in d.items():
                self.iterlist[levl] = key
                if isinstance(value, dict) and self.depth > levl:
                    for retvalues in self.print_nested_dict(value, levl + 1):
                        yield retvalues

#iter function , needs setting of rootpoint and depth so the class can be iterated over
    def __iter__(self):
        for keylist, value in self.print_nested_dict(self.get(self.rootpoint), 0):
            yield keylist, value
        return

    def nesting(self, tdt, clist):
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
            self.nesting(tdt[clist[0]], clist[1:])
        else:
            tdt[clist[0]] = clist[1]
        return

    def oneup(self, tdict, uplevel):
        ttdict = {}
        ttdict = {uplevel: tdict}
        return ttdict

    def buildstruct(self, clist):
        tdict = clist[-1]
        for i in range(len(clist) - 2, 0, -1):
            tdict = self.oneup(tdict, clist[i])
        return tdict

        '''Add function , interface to be called to safely add a leaf to the parsed structure'''

    def add(self, clist):
        # print(f"test....{self.Parsed}")
        t = self.get(clist[:-1])
        # print(f"command {t} {clist[:-1]}")
        if t is not None:
            return
        tlist = []
        tdict = {}
        for i, commands in enumerate(clist):
            tlist.append(commands)
            if self.get(tlist) is None:
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

    def modify(self, clist, label, value):
        oldval = self.get(clist)
        oldval[label] = value
        passalong = [*clist, oldval]
        self.add(passalong)
        return

    # Function to print out data structure as formatted json
    def printit(self):
        print("\n" + "*" * 80)
        print("          Raw Data:")
        print(json.dumps(self.Parsed, indent=4))
        return

    def get(self, clist):
        tdt = self.Parsed
        for clis in clist:
            if clis in tdt.keys():
                tdt = tdt[clis]
            else:
                return None
        return tdt

    def save(self, file):
        with open(file, "w") as outfile:
            outfile.write(json.dumps(self.Parsed))
        print(f"Exported {sys.getsizeof(self.Parsed)} bytes from datastore to {file}")
        return

    def load(self, file):
        with open(file, "r") as infile:
            self.Parsed = json.load(infile)
        print(f"Imported {sys.getsizeof(self.Parsed)} bytes from {file} into data store")
        return
