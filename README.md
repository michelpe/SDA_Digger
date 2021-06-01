SDA Digger allows for users to interact with an Software Defined Access Fabric devices
through a Cisco DNA Center.

It requires that Cisco DNAC is at least version 2.0 to be able to use some of the API calls
that are required. It also utilizes the Command Runner functionality of Cisco DNA Center
to collect outputs from the SDA fabric devices to fullfill its analysis.

The tool lets users 1) do certain checks on the SDA Fabric or 2) do a deep dive on certain
endpoints to help troubleshoot certain issues.

Usage Guideline:
python SDA_Digger 

CLI Options:
-d [IP Address of DNAC]
-u [username]
-p [password] 
-f [fabric] 
-l [logdirectory]

To run the tool a recent verion of Python is required (minimal version 3.7)

- LISP Session analysis
  Checks if LISP sessions are in the expected states on all Fabric devices.
- LISP Database consistency
  Checks the information from the Control Plane nodes and the other Fabric Devices.
  Verifies that if endpoints are registered are on edge/border devices they also correctly
  are being shown on the Control Plane nodes
- LISP Map cache consistency
  Checks the LISP map cache on all devices and compares all completed entries
  against the CP information to confirm consistency inside the fabric.
  LISP Map cahce entries are based upon cache entries. So some benign errors could be shown
  for destinations that might have roamed or have left the fabric.
- IP reachability checks
  Checks the IP routing tables on all devices to make sure ther is /32 reachability
  between all devices. In recent versions of Cisco DNA Center the requirement has been
  changed to /24 reachability. Thus some benign errors could be shown 
- Authentication and CTS enviroment checking
  Check on all edge devices the CTS environment. 
  Ensures CTS enviroment is correctly download to all edge devices
  Also verifies the Authentication sessions on all devices to look for devices
  that would not have gotten an IP address or an IP address in the APIPA IP range.
- IP Multicast Underlay checks
  Performs checks to check what Underlay Multicast groups are in used
  by SDA and verifies if the edge devices are correctly shown as sources
  in the group. In cases where it not it verifies if any endpoints
  are present inside the IP Pools in those groups.    
- Data Collection based on Endpoint
  Performs data collection based upon an endpoint. Data collection is done on 
  the edge choosen, CP nodes , border nodes and WLC. 
  Outputs are shown on screen and kept in the log files
  The commands executed from the dig_command.txt file which needs to be present 
  in the directory the file is in. The $variable commands inside the dig_command.txt
  are replaced with the values (if known) to be executed
  
