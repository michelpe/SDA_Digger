import base64
import ssl
import http.client
import json
import time

class DnacCon:
    server = None
    username= None
    password = None
    token = None

    def __init__(self, server, user, pword):
        self.DNAC = server
        self.username = user
        self.password = pword
        self.get_token()
        self.topo={}
        self.connect= None
        #print(self.token)

    def connect_dnac(self,http_action,http_url,http_headers):
        http_headers['X-auth-token']=self.token
        #print (http_headers)
        return

    def get_token(self):
        self.token=None
        authraw=self.username+":"+self.password
        auth64=base64.b64encode(authraw.encode("utf-8")).decode("utf-8")
        print (self.username)
        print (self.password)
        print(auth64)
        try:
            self.conn = http.client.HTTPSConnection(self.DNAC,context = ssl._create_unverified_context())
        except:
            print(f"error connecting to server {self.DNAC}")
            exit()

        headers = {
         'content-type': "application/json",
         'authorization': f"Basic {auth64}"
        }
        try:
            #print(headers)
            self.conn.request("POST", f"https://{self.DNAC}/api/system/v1/auth/token", headers=headers)
            print (headers)
        except:
            print(f"Error connecting to server {self.DNAC}, exiting")
            exit()

        res = self.conn.getresponse()

        if res.status == 200:
            data = json.loads(res.read())
            self.token=data["Token"]
            print(f"Connection established to {self.DNAC}")
        elif res.status == 401:
            print(f"Incorrect Username/Password supplied, unable to login to DNAC")
            print(res.status)
            exit(0)
        else:
            print (f"Error {res.status} encountered when trying to retrieve token")
            exit(0)
        self.connect_dnac("t","t",headers)
        return

    def open_channel(self):
        if self.token is None:
           self.get_token()
        return

    def geturl(self,url):
        headers = {
            'content-type': "application/json",
            'x-auth-token': self.token
        }
        realurl = f"https://{self.DNAC}{url}"
        try:
            #conn = http.client.HTTPSConnection(self.DNAC, context=ssl._create_unverified_context())
            self.conn.request("GET", realurl, headers=headers)
            #print (realurl)
        except:
            print(f"Error connecting to server {self.DNAC}, exiting")
            exit()
        res = self.conn.getresponse()
        #print (res.status)
        return json.loads(res.read())

    def post(self,url,payload):
        #print (f"executing {url} with {payload}")
        header = {
            'content-type': "application/json",
            'X-Auth-Token': self.token
        }
        jpay = json.dumps (payload)
        try:
            #conn = http.client.HTTPSConnection(self.DNAC, context=ssl._create_unverified_context())
            self.conn.request("POST", f"https://{self.DNAC}{url}",jpay,headers=header)
        except:
            print(f"Error connecting to server {self.DNAC},  exiting")
            exit()
        res = self.conn.getresponse()
        return json.loads(res.read())

    def command_run(self,commands, devs):
        payload = {'commands': commands, 'deviceUuids': devs}
        ret = []
        #print (payload)
        resp = self.post("/dna/intent/api/v1/network-device-poller/cli/read-request",payload)
        #print(resp)
        tresp = self.geturl(resp["response"]["url"])
        while "endTime" not in tresp["response"].keys():
            time.sleep(1)
            tresp = self.geturl(resp["response"]["url"])
        fileId = json.loads(tresp["response"]["progress"])
        fresp = self.geturl(f"/dna/intent/api/v1/file/{fileId['fileId']}")
        #print (fresp)
        for single_resp in fresp:
            res_name =self.topo["devices"][single_resp['deviceUuid']]
            for responses in single_resp['commandResponses']:
                if responses == "SUCCESS":
                   for command in single_resp['commandResponses']['SUCCESS']:
                       output = single_resp['commandResponses']['SUCCESS'][command]
                       ret.append({"host":res_name,"output":output})
                else:
                    pass
        return ret