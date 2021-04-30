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

    def __init__(self, server, user, pword):
        self.DNAC = server
        self.username = user
        self.password = pword
        self.get_token()
        self.topo = {}
        self.connect = None
        self.fabric = ""
        self.wlc = {}
        self.devices = {}
        time.localtime()
        self.logdir = f"log{time.localtime().tm_mon}{time.localtime().tm_mday}_{time.localtime().tm_hour}" \
                      f"{time.localtime().tm_min}"
        if os.path.exists(self.logdir):
            # directory already exists. appending outputs
            pass
        else:
            os.makedirs(self.logdir)
        print(f"Storing outputs in directory {os.path.join(os.getcwd(), self.logdir)}")

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
        payload = {'commands': commands, 'deviceUuids': devs}
        ret = []
        # print (payload)
        self.conn = http.client.HTTPSConnection(self.DNAC, context=ssl._create_unverified_context())
        resp = self.post("/dna/intent/api/v1/network-device-poller/cli/read-request", payload)
        if "response" not in resp.keys():
            print(resp)
        tresp = self.geturl(resp["response"]["url"])
        while "endTime" not in tresp["response"].keys():
            time.sleep(1)
            tresp = self.geturl(resp["response"]["url"])
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
                            print (f"Failed command : {failed_cli}")
                        #print(single_resp['commandResponses']["FAILURE"].keys())

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
                #print (f"{devs} {cmds}")
                t = 0
                cmds=[]
        return tret


    def command_run(self, commands, devs):
        print(f"Requesting {len(commands)} commands on {len(devs)} device(s) via {self.DNAC}")
        tret = []
        i=0
        t=0
        devices = []
        for dev in devs:
            devices.append(dev)
            i = i + 1
            t = t + 1
            if len(devices) > 4 or i == len(devs):

                tret.extend(self.command_run_dev_batch(commands, devices))
                t = 0
                devices=[]
        print(f" Completed")
        return tret

