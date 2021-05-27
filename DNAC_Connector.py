import base64
import ssl
import http.client
import json
import time
import os


class DnacCon:
    server = None
    username = None
    password = None
    token = None
    logdir = None

    def __init__(self, server, user, pword,directory):
        self.DNAC = server
        self.username = user
        self.password = pword
        self.get_token()
        self.topo = {}
        self.connect = None
        self.fabric = ""
        self.wlc = {}
        self.devices = {}
        self.debug = False
        self.crunnerretry = 0
        time.localtime()
        self.logdir = f"log{time.localtime().tm_mon}{time.localtime().tm_mday}_{time.localtime().tm_hour}" \
                      f"{time.localtime().tm_min}"
        if directory is not None:
            self.logdir = os.path.join(directory,self.logdir)
        else:
            self.logdir = os.path.join(os.getcwd(), self.logdir)
        if os.path.exists(self.logdir):
            # directory already exists. appending outputs
            pass
        else:
            os.makedirs(self.logdir)
        print(f"Storing outputs in directory {self.logdir}")

    def connect_dnac(self, http_action, http_url, http_headers):
        http_headers['X-auth-token'] = self.token
        # print (http_headers)
        return

    def get_token(self):
        self.token = None
        authraw = self.username + ":" + self.password
        auth64 = base64.b64encode(authraw.encode("utf-8")).decode("utf-8")

        try:
            self.conn = http.client.HTTPSConnection(self.DNAC, context=ssl._create_unverified_context())
        except:
            print(f"error connecting to server {self.DNAC}")
            exit()

        headers = {
            'content-type': "application/json",
            'authorization': f"Basic {auth64}"
        }
        try:
            # print(headers)
            self.conn.request("POST", f"https://{self.DNAC}/api/system/v1/auth/token", headers=headers)
            # print (headers)
        except:
            print(f"Error connecting to server {self.DNAC}, exiting")
            exit()

        res = self.conn.getresponse()

        if res.status == 200:
            data = json.loads(res.read())
            self.token = data["Token"]
            print(f"Connection established to {self.DNAC}")
        elif res.status == 401:
            print(f"Incorrect Username/Password supplied, unable to login to DNAC")
            print(res.status)
            exit(0)
        else:
            print(f"Error {res.status} encountered when trying to retrieve token")
            exit(0)
        self.connect_dnac("t", "t", headers)
        return

    def open_channel(self):
        if self.token is None:
            self.get_token()
        return

    def geturl(self, url):
        headers = {
            'content-type': "application/json",
            'x-auth-token': self.token
        }
        realurl = f"https://{self.DNAC}{url}"
        try:
            # conn = http.client.HTTPSConnection(self.DNAC, context=ssl._create_unverified_context())
            self.conn.request("GET", realurl, headers=headers)
            # print (realurl)
        except:
            print(f"Error connecting to server {self.DNAC}, exiting")
            exit()
        while True:
            try:
                res = self.conn.getresponse()
            except:
                self.conn = http.client.HTTPSConnection(self.DNAC, context=ssl._create_unverified_context())
                self.conn.request("GET", realurl, headers=headers)
                print(f"Reopening https connection")
            else:
                # print (res.status)
                if res.status == 404:
                    ret = (res.read())
                    print(
                        f"Internal Error encountered {ret} (bapi errors often resolved by disabling/enabling the RESTAPI bundle under platform/manager")
                if res.status == 401:
                    ret = (res.read())
                    self.get_token()
                elif res.status == 429:
                    print(f"Exceeded limit for API calls calling {url}, pausing for 60 seconds")
                    time.sleep(60)
                    print(f"Reopening https connection to {self.DNAC} after pausing")
                    self.conn = http.client.HTTPSConnection(self.DNAC, context=ssl._create_unverified_context())
                    self.conn.request("GET", realurl, headers=headers)
                elif res.status > 299:
                    print(f"{res.status} error encountered when trying to get {url}")
                    print(f"{res.read()}")
                    exit(0)
                else:
                    break
        return json.loads(res.read())

    def post(self, url, payload):
        # print (f"executing {url} with {payload}")
        header = {
            'content-type': "application/json",
            'X-Auth-Token': self.token
        }
        jpay = json.dumps(payload)
        try:
            # conn = http.client.HTTPSConnection(self.DNAC, context=ssl._create_unverified_context())
            self.conn.request("POST", f"https://{self.DNAC}{url}", jpay, headers=header)
        except:
            print(f"Error connecting to server {self.DNAC},  exiting")
            exit()
        res = self.conn.getresponse()
        return json.loads(res.read())

    def command_run_batch(self, commands, devs):
        i=0
        payload = {'commands': commands, 'deviceUuids': devs}
        ret = []
        # print (payload)
        self.conn = http.client.HTTPSConnection(self.DNAC, context=ssl._create_unverified_context())
        resp = self.post("/dna/intent/api/v1/network-device-poller/cli/read-request", payload)
        if "response" not in resp.keys():
            print(resp)
        if 'errorCode' in resp["response"].keys():
            print(f"Encountered unexpected error: {resp['response']['errorCode']} : {resp['response']['message']}")
            exit()
        tresp = self.geturl(resp["response"]["url"])
        while "endTime" not in tresp["response"].keys():
            i=i+1
            time.sleep(1)
            if i % 5 == 0:
                print(f"o",end="")
            tresp = self.geturl(resp["response"]["url"])
            if i > 300 :
                print(f"Timeout exceeded, exiting")
                exit()
        if i>30:
            print(f"\nNotice: Slow response from DNAC running Command runner, response took {i} seconds)")
        fileId = json.loads(tresp["response"]["progress"])
        fresp = self.geturl(f"/dna/intent/api/v1/file/{fileId['fileId']}")
        # print (fresp)
        for single_resp in fresp:
            res_name = self.topo["devices"][single_resp['deviceUuid']]
            for responses in single_resp['commandResponses']:
                if responses == "SUCCESS":
                    for command in single_resp['commandResponses']['SUCCESS']:
                        output = single_resp['commandResponses']['SUCCESS'][command]
                        ret.append({"host": res_name, "output": output})
                else:
                    for command in single_resp['commandResponses']['FAILURE']:
                        for failed_cli in single_resp['commandResponses']["FAILURE"].keys():
                            if self.debug is True:
                                print (f"Failed command : {failed_cli}")
                        #print(single_resp['commandResponses']["FAILURE"])
                    pass
        combined = {}
        olddir = os.getcwd()
        os.chdir(self.logdir)
        for res in ret:
            if res["host"] in combined.keys():
                combined[res["host"]].append(res["output"])
            else:
                combined[res["host"]] = [res["output"]]
        for outhosts in combined.keys():
            fd = open(f"{outhosts}.txt", "a+")
            for outs in combined[outhosts]:
                fd.write(outs)
            fd.close()
        os.chdir(olddir)
        return ret

    def command_run_dev_batch(self, commands, devs):
        tret = []
        i=0
        t=0
        cmds = []
        for cmd in commands:
            cmds.append(cmd)
            i = i + 1
            t = t + 1
            if len(cmds) > 3 or i == len(commands):
                print(f".",end="")
                tret.extend(self.command_run_batch(cmds, devs))
                t = 0
                cmds=[]
        return tret

    def update_reachable(self):
       tre = self.geturl("/dna/intent/api/v1/network-device?reachabilityStatus=Unreachable")
       response=tre['response']
       unreach_ids = set()
       for un_devs in response:
           unreach_ids.add(un_devs['id'])
       for device in self.topo['reach'].keys():
           if device in unreach_ids:
               self.topo['reach']=="Unreachable"
           else:
               self.topo['reach']=="Reachable"
       return


    def command_run(self, commands, devs):
        ttret = []
        if self.crunnerretry > 10 :
            return None
        print(f"Requesting {len(commands)} commands on {len(devs)} device(s) via {self.DNAC}")
        self.update_reachable()
        tret = []
        ttret = []
        i=0
        t=0
        devices = []
        devicenames = set()
        for dev in devs:
            if self.topo['reach'][dev].lower()!="unreachable":
                devices.append(dev)
                devicenames.add(self.topo['devices'][dev])
                i = i + 1
                t = t + 1
                if len(devices) > 4 or i == len(devs):
                    tret.extend(self.command_run_dev_batch(commands, devices))
                    t = 0
                    devices=[]
            else:
                print(f"skipping device {self.topo['devices'][dev]} in state {self.topo['reach'][dev]}")
        sucdevs= set()
        for tre in tret:
            succeshost =tre.get('host')
            if succeshost not in sucdevs and not None:
                sucdevs.add(succeshost)
        sucset=devicenames.difference(sucdevs)
        if len(sucset) >0:
            print(f"Command runner failed on {len(sucset)} devices {sucset} retrying")
            retrydevs = []
            for devs in sucset:
                self.crunnerretry = self.crunnerretry + 1
                retrydevs.append(self.topo['hostnames'][devs])
            resp=self.command_run(commands,retrydevs)
            if resp is not None:
                tret.extend(resp)
        self.crunnerretry = self.crunnerretry -1
        if self.crunnerretry < 1 :
            print ("\nCompleted")
            self.crunnerretry = 0
        if tret is None:
            tret["response"]={}
        return tret

