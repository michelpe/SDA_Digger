SDA Digger , a tool to help with troubleshooting an SDA Fabric.

Purpose:

SDA Digger allows for users to interact with an Software Defined Access Fabric devices
through a Cisco DNA Center. The tool is designed to assist with troubleshooting
an SD Access Fabric by gathering a number of command outputs. 

One part of the tool is a consistency checker. By running a number of commands on 
all the components inside the SDA fabric a complete view of the fabric is being
build. By using multiple outputs on multiple devices consistency checks are performed
to ensure that different components and different parts of the fabric have a unified
view of how the fabric should be. If any inconsintency is being detected this will be flagged

It also looks for some known problem patterns and will alert when detected. For example
if an Endpoint is detected on the fabric but no IP address, or an APIPA address is detected
a warning is being flagged. Similarly, it does this for other features used inside
the fabric

The other part of the tool allows a deep dive in regard to an endpoint. An endpoint
can be choosen inside the fabric, and a set of commands is run to gather additional
details with regards to that endpoint. Commands are run on the Edge node the client is,
the CP nodes and the border nodes. This would allow for a lot of information quickly been
able to be gathered to further troubleshoot issues if an issue might be found with an endpoint.

The outputs from the devices taken by the tool are saved into the log files for later analysis.

Installation:

The python scripts are working on Python 3.7 and higher and should not need
any additional packages installed apart from the default packages included

It requires that Cisco DNAC is at least version 2.0 to be able to use some API calls
that are required. It also utilizes the Command Runner functionality of Cisco DNA Center
to collect outputs from the SDA fabric devices to fulfill its analysis.

To install the script download the .zip file containing all related files or clone
the repository using "gh repo clone michelpe/SDA_Digger"

When going into the directory the files are being extracted into it the SDA_Digger can be ran
using: python SDA_Digger.py

Example:
MICHELPE-LAPTOP:SDA_Digger michelpe$ python3 SDA_Digger.py 

Alternatively python3 might need to be run. Use python --version to ensure the python version 
is version 3.7 or higher

Using SDA Digger:

SDA Digger is a python script that can be run on any OS as long as Python3.7 or higher is 
installed. To execute the script run the main script with :

python SDA_Digger 

CLI Options:
-d [IP Address of DNAC]
-u [username]
-p [password] 
-f [fabric] 
-l [logdirectory]
-b [Directory with extraced MRE Bundle files]

To run the tool a recent version of Python is required (minimal version 3.7)

- LISP Session analysis
  Checks if LISP sessions are in the expected states on all Fabric devices.
- LISP Database consistency
  Checks the information from the Control Plane nodes and the other Fabric Devices.
  Verifies that if endpoints are registered are on edge/border devices they also correctly
  are being shown on the Control Plane nodes
- LISP Map cache consistency
  Checks the LISP map cache on all devices and compares all completed entries
  against the CP information to confirm consistency inside the fabric.
  LISP Map cache entries are based upon cache entries. So some benign errors could be shown
  for destinations that might have roamed or have left the fabric.
- IP reachability checks:
  Checks the IP routing tables on all devices to make sure there is /32 reachability
  between all devices. In recent versions of Cisco DNA Center the requirement has been
  changed to /24 reachability. Thus, some benign errors could be shown 
- Authentication and CTS environment checking.
  Check on all edge devices the CTS environment. 
  Ensures CTS environment is correctly download to all edge devices
  Also verifies the Authentication sessions on all devices to look for devices
  that would not have gotten an IP address or  IP address in the APIPA IP range.
- IP Multicast Underlay checks.
  Performs a check to check what Underlay Multicast groups are in used
  by SDA and verifies if the edge devices are correctly shown as sources
  in the group. In cases where it not it verifies if any endpoints
  are present inside the IP Pools in those groups.    
- Data Collection based on Endpoint.
  Performs data collection based upon an endpoint. Data collection is done on 
  the edge the endpoint is located, CP nodes , border nodes and WLC. 
  Outputs are shown on screen and kept in the log files
  The commands executed from the dig_command.txt file which needs to be present 
  in the directory the file is in. The $variable commands inside the dig_command.txt
  are replaced with the values (if known) to be executed
- Using the -b option a non-interactive analysis of a bundle file
  from the DNAC Network Reasoner Fabric Data Collection tool. 
  Bundle files need to be extracted in current release
  Parsing and analysis is limited in current version
  

Example:

MICHELPE-LAPTOP:SDA_Digger michelpe$ python3 SDA_Digger.py 
DNAC IP address :sandboxdnac.cisco.com
username :devnetuser
Password: 
Connection established to sandboxdnac.cisco.com
Storing outputs in directory /Users/michelpe/SDA_Digger/log69_1447
Discovered Areas/Buildings/floors:
Global/Luxembourg
Global/Luxembourg/LUX
Only one fabric found, proceeding
Discovered devices in Fabric test :
Importing CP information for fabric test
no CP found, exciting



Please choose one of the following options:
1: LISP Session analysis
2: LISP Database consistency
3: LISP Map cache consistency
4: IP reachability checks
5: Authentication and CTS enviroment checking
6: Data Collection based on Endpoint
7: IP Multicast Underlay checks
d: Dump Datastructures
r: New Fabric Selection
q: Quit
Choice:


[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/michelpe/SDA_Digger)