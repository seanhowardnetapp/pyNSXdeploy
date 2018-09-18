#!/usr/bin/env python3

"""
Orignal configure_nsx_manager.py script written by Sean Howard
hows@netapp.com

This script will do the following:
1.	register NSX Manager with vCenter
2.	register NSX Manager with the Lookup Service (usually also vcenter, but if there is an external PSC use that)
3.	deploy 3 NSX controllers to the specified cluster (usually management cluster)
4.	prepare the specified cluster(s) for DFW
5.	prepare the specified cluster(s) for VXLAN / multi-vtep using IPs/VLAN information supplied
6.	configure a transport zone, segment id pools, and everything else needed to start building logical switches

Assumptions and Design Decisions this script makes for you
1.	Multi-VTEP and route by SRC ID for VXLAN.  No LACP.
2.	MTU of 9000 for VXLAN
3.	Controller VM and hostnames will be set for you
4.	Everything will live in a single, standard Transport Zone called "Primary"
5.	This transport zone will be bound to a single specified DVS.  If this DVS does not have exactly 2 10Gbit uplinks, the script will fail.
6.	Segment IDs for VXLAN will be 5000-10000
7.	Replication type for VXLAN will be Unicast (maybe we'll expand the script to include a hybrid & multicast option later)
8.	CDO mode will not be enabled
9.	No example DFW Rules, Logical Switches, ESGs, or DLRs will be created (likely we'll add this in the future as an option)

Example with parameters:
python3 ./configure_nsx_manager.py -nsx_manager_address 10.217.88.110 -nsx_manager_username admin -nsx_manager_password NetApp123\!NetApp123\! -s 10.217.91.253 -u administrator@vsphere.local -p Password@123 -S -VTEP_IP_Range 10.217.88.155-10.217.88.158,10.217.88.160-10.217.88.165 -VTEP_Mask /22 -VTEP_Gateway 10.217.91.254 -VTEP_DNS 8.8.8.8,8.8.8.4 -VTEP_domain lab.local -lookup_service_address 10.217.91.253 -VTEP_VLAN_ID 0 -Controller_IP_Range 10.217.88.166-10.217.88.168 -Controller_Mask /22 -Controller_Gateway 10.217.91.254 -Controller_Cluster Management -Controller_DNS 8.8.8.8,8.8.8.4 -Controller_domain lab.local -Controller_Datastores nfsdatastore -Controller_Network NSX_Controllers -Controller_Password NetApp123\!NetApp123\! -DVS Management_Cluster -cluster_prep_list Compute
"""

import ssl
import atexit
import os
import os.path
import ssl
import sys
import ipaddress
import re
import socket
import hashlib
import base64
import time

from http.client import HTTPSConnection

from tools import cli

from pyvim.connect import SmartConnectNoSSL, Disconnect
from pyVmomi import vim, vmodl


__author__ = 'hows@netapp.com'

ip_mask_re = re.compile("/\d{1,2}")

def setup_args():
    parser = cli.build_arg_parser()
    parser.add_argument('-d', '--datacenter',
                        help='Name of datacenter to use. '
                                'Defaults to first.')
    parser.add_argument('-nsx_manager_username', '--nsx_manager_username',
                        help='An account in the NSX manager database that has admin rights - generally it is simply called admin')
    parser.add_argument('-nsx_manager_password', '--nsx_manager_password',
                        help='Password for the aforementioned NSX admin account')
    parser.add_argument('-nsx_manager_address', '--nsx_manager_address',
                        help='FQDN or IP of NSX Manager')
    parser.add_argument('-lookup_service_address', '--lookup_service_address',
                        help='FQDN or IP of the Lookup Service host you want to register NSX Manager to - this is usually the vCenter itself unless you have an external PSC')
    parser.add_argument('-cluster_prep_list', '--cluster_prep_list',
                        help='comma separated list of cluster names that you want prepared for NSX')
    parser.add_argument('-VTEP_IP_Range', '--VTEP_IP_Range',
                        help='specified in the format 192.168.0.1-192.168.0.10.  You can specify multiple ranges separated by commas.  You must supply a minimum of 2 IPs per host that is being prepared for NSX')
    parser.add_argument('-VTEP_Mask', '--VTEP_Mask',
                        help='specified in the format 255.255.255.0')
    parser.add_argument('-VTEP_Gateway', '--VTEP_Gateway',
                        help='specified in the format 192.168.0.254')
    parser.add_argument('-VTEP_DNS', '--VTEP_DNS',
                        help='comma separated list of DNS servers you want the VTEPs to use')
    parser.add_argument('-VTEP_domain', '--VTEP_domain',
                        help='search domain you want the VTEPs to use, specified as something like mydomain.local')
    parser.add_argument('-VTEP_VLAN_ID', '--VTEP_VLAN_ID',
                        help='enter 0 if you wish to use the default VLAN')
    parser.add_argument('-Controller_IP_Range', '--Controller_IP_Range',
                        help='specified in the format 192.168.0.1-192.168.0.10. You must supply a minimum of 3 IPs total.')
    parser.add_argument('-Controller_Mask', '--Controller_Mask',
                        help='specified in the format 255.255.255.0')
    parser.add_argument('-Controller_Gateway', '--Controller_Gateway',
                        help='specified in the format 192.168.0.254')
    parser.add_argument('-Controller_Cluster', '--Controller_Cluster',
                        help='name of the cluster you wish to deploy the 3 NSX controllers to.  Generally your management cluster.')
    parser.add_argument('-Controller_DNS', '--Controller_DNS',
                        help='comma separated list of DNS servers you want the Controllers to use')
    parser.add_argument('-Controller_domain', '--Controller_domain',
                        help='search domain you want the Controllers to use, specified as something like mydomain.local')
    parser.add_argument('-Controller_Datastores', '--Controller_Datastores',
                        help='comma separated list of the datastores you want the 3 NSX controllers to deploy to.  Ideally this would be three different shared (i.e. not local host) datastores.')
    parser.add_argument('-Controller_Network', '--Controller_Network',
                        help='Network you want the Controller VMs to connect to.  This must be a VM network on a DVS')
    parser.add_argument('-Controller_Password', '--Controller_Password',
                        help='Password you want the controllers to use for their admin accounts.  Must be complex and at least 12 characters.')
    parser.add_argument('-DVS', '--DVS',
                        help='name of the Distributed Virtual Switch you wish to bind the VXLAN transport zone to')
    return(parser.parse_args())

def main():
    args = setup_args()

    #disable SSL certificate verification since most customers aren't going to set their NSX Manager up with a trusted CA

    if (not os.environ.get('PYTHONHTTPSVERIFY', '') and
        getattr(ssl, '_create_unverified_context', None)):
        ssl._create_default_https_context = ssl._create_unverified_context

    #set up common variables
    credstring = (args.nsx_manager_username + ":" + args.nsx_manager_password)
    creds = base64.b64encode(credstring.encode()).decode('ascii')

    headers = {'Content-Type' : 'application/xml','Authorization' : 'Basic ' + creds }
    nsx_manager_address = args.nsx_manager_address

    print(headers)

    #connect to vcenter via SOAP
    try:
        si = SmartConnectNoSSL(host=args.host,
                                user=args.user,
                                pwd=args.password,
                                port=args.port)
        atexit.register(Disconnect, si)
    except:
        print("Unable to connect to %s" % args.host)
        return 1

    if args.datacenter:
        dc = get_dc(si, args.datacenter)
    else:
        dc = si.content.rootFolder.childEntity[0]

    # this is a testing statement to be removed later
    # it just proves we successfully pulled something from vcenter via SOAP
    print("Datacenter in use:")
    print(dc)

    # register with SSO
    register_sso_status = register_nsx_with_lookup_service(headers, args.nsx_manager_address, args.lookup_service_address, args.user, args.password)
    print(*register_sso_status)

    # register with vCenter
    register_vcenter_status = register_nsx_with_vcenter(headers, args.nsx_manager_address, args.host, args.user, args.password)
    print(*register_vcenter_status)
    
    # set the segment id range
    segment_id_status = set_segment_id_range(headers,args.nsx_manager_address)
    print(*segment_id_status)

    # create the IP Pool VTEP-Pool
    num_hosts = 2 #hard set the num_hosts to 2 for now until I can create the function to figure that out

    vtep_ip_pool_status = create_vtep_ip_pool(nsx_manager_address,headers,args.VTEP_IP_Range,args.VTEP_Mask,args.VTEP_Gateway,num_hosts,args.VTEP_DNS,args.VTEP_domain)
    vtep_ip_pool_id = vtep_ip_pool_status[1]
    print(*vtep_ip_pool_status)

    # create the IP Pool Controller-Pool
    controller_ip_pool_status = create_controller_ip_pool(nsx_manager_address,headers,args.Controller_IP_Range,args.Controller_Mask,args.Controller_Gateway,args.Controller_DNS,args.Controller_domain)
    controller_ip_pool_id = controller_ip_pool_status[1]
    print(*controller_ip_pool_status)
    print(controller_ip_pool_id)

    # Deploy three NSX controllers
    nsx_controller_status = deploy_nsx_controllers(headers, nsx_manager_address, args.Controller_Cluster, args.Controller_Datastores, args.Controller_Network, args.Controller_Password, controller_ip_pool_id, dc, si)


def set_segment_id_range(headers,nsx_manager_address):

    segment_begin=5000
    segment_end=10000
    segment_name="Segment 1"
    segment_desc="Range 1"

    xml_string="""
    <segmentRange>
        <name>{0}</name>
        <desc>{1}</desc>
        <begin>{2}</begin>
        <end>{3}</end>
    </segmentRange>
    """.format(segment_name,segment_desc,segment_begin,segment_end)

    print("Setting the VNI Segment ID Range to 5000-10000...")

    conn = HTTPSConnection(nsx_manager_address)
    conn.request('POST', 'https://' + nsx_manager_address + '/api/2.0/vdn/config/segments',xml_string,headers)

    response = conn.getresponse()

    if response.status != 201:
        print (str(response.status) + " Segment ID Range not created, one must already exist")
        return -1, response.read()
    else:
        print (str(response.status) + " Segment ID Range created successfully")
        return 0, response.read()


def register_nsx_with_lookup_service(headers, nsx_manager_address, lookup_service_address, vcenter_username, vcenter_password):

    thumbprint = get_sha1_thumbprint(lookup_service_address)

    lookup_service_url = 'https://' + lookup_service_address + ':443/lookupservice/sdk'

    xml_string = """
        <ssoConfig>
          <ssoLookupServiceUrl>{0}</ssoLookupServiceUrl>
          <ssoAdminUsername>{1}</ssoAdminUsername>
          <ssoAdminUserpassword>{2}</ssoAdminUserpassword>
          <certificateThumbprint>{3}</certificateThumbprint>
        </ssoConfig>
        """.format(lookup_service_url, vcenter_username, vcenter_password, thumbprint)

    print("Registering NSX Manager with the SSO Lookup Service...")

    conn = HTTPSConnection(nsx_manager_address)
    conn.request('POST', 'https://' + nsx_manager_address + '/api/2.0/services/ssoconfig', xml_string, headers)

    response = conn.getresponse()

    if response.status != 200:
        print(str(response.status) + " Lookup service did not register.  Maybe it already is?")
        return -1, response.read()
    else:
        print(str(response.status) + " Lookup service registered successfully")
        return 0, response.read()


def register_nsx_with_vcenter(headers, nsx_manager_address, vcenter_address, vcenter_username, vcenter_password):

    thumbprint = get_sha256_thumbprint(vcenter_address)

    xml_string = """
        <vcInfo>
          <ipAddress>{0}</ipAddress>
          <userName>{1}</userName>
          <password>{2}</password>
          <certificateThumbprint>{3}</certificateThumbprint>
          <assignRoleToUser>true</assignRoleToUser>
          <pluginDownloadServer></pluginDownloadServer>
          <pluginDownloadPort></pluginDownloadPort>
        </vcInfo>
        """.format(vcenter_address, vcenter_username, vcenter_password, thumbprint)

    print("Registering NSX Manager with vCenter...")


    conn = HTTPSConnection(nsx_manager_address)
    conn.request('PUT', 'https://' + nsx_manager_address + '/api/2.0/services/vcconfig', xml_string, headers)

    response = conn.getresponse()

    if response.status != 200:
        print(str(response.status) + " vCenter not registered.  Maybe it already is?")
        return -1, response.read()
    else:
        print(str(response.status) + " vCenter server registered successfully")
        return 0, response.read()

def deploy_nsx_controllers(headers, nsx_manager_address, controller_cluster, controller_datastores, controller_network, controller_password, controller_ip_pool_id, dc, si):

    # coming soon
    # deploy 3 NSX controllers to whatever datacenter and cluster you specified by name, error out if it can't find it
    # deploy controller 1 to the first datastore in the controller_datastores list, 2 to the second, 3 to the third
    # hard name the controller VM and hostnames "nsx-controller-1", "nsx-controller-2", "nsx-controller-3"
    # use the IP pool called "Controller-Pool", created by the create_controller_pool function [obv this must be called later]
    # connect all three controllers to the controller_network specified
    # wait for 10 minutes between each controller deployment (it won't let you do multiple in parallel)


    controller_network_id = str(get_network(si, dc, controller_network)).replace('vim.dvs.DistributedVirtualPortgroup:','')
    controller_network_id = controller_network_id.replace("'","")
    resource_pool_id = str(get_cluster_rp(dc, controller_cluster)).replace('vim.ResourcePool:','')
    resource_pool_id = resource_pool_id.replace("'","")
    controller_ip_pool_id = controller_ip_pool_id.decode('utf-8')

    print(controller_ip_pool_id)

    controller_datastore_ids = []
    controller_datastore_list = controller_datastores.split(',')

    if len(controller_datastore_list) == 1 :
        firstdatastore = controller_datastore_list[0]
        controller_datastore_list.append(firstdatastore)
        controller_datastore_list.append(firstdatastore)

    elif len(controller_datastore_list) == 2 :
        seconddatastore = controller_datastore_list[1]
        controller_datastore_list.append(seconddatastore)

    for datastore in controller_datastore_list:
        datastore_id = str(get_ds(dc,datastore)).replace('vim.Datastore:','')
        datastore_id = datastore_id.replace("'","")
        print("->" + datastore_id + "<-")

        controller_datastore_ids.append(datastore_id)


    xml_string= """
    <controllerSpec>
      <name>{0}</name>
      <description>nsx-controller</description>
      <ipPoolId>{1}</ipPoolId>
      <resourcePoolId>{2}</resourcePoolId>
        <datastoreId>{3}</datastoreId>
      <networkId>{4}</networkId>
      <password>{5}</password>
     </controllerSpec>
    """.format('NSX-Controller-1',controller_ip_pool_id,resource_pool_id,controller_datastore_ids[0],controller_network_id,controller_password)


    print("Beginning first NSX controller deployment.  This may take a while...")
    print(xml_string)

    conn = HTTPSConnection(nsx_manager_address)
    conn.request('POST', 'https://' + nsx_manager_address + '/api/2.0/vdn/controller', xml_string, headers)

    response = conn.getresponse()
    jobid = (response.read()).decode('utf-8')
    print (">" + jobid + "<")

    print("waiting 10 minutes...")
    time.sleep(600)



    xml_string = """
       <controllerSpec>
         <name>{0}</name>
         <description>nsx-controller</description>
         <ipPoolId>{1}</ipPoolId>
         <resourcePoolId>{2}</resourcePoolId>
           <datastoreId>{3}</datastoreId>
         <networkId>{4}</networkId>
         <password>{5}</password>
        </controllerSpec>
       """.format('NSX-Controller-2', controller_ip_pool_id, resource_pool_id, controller_datastore_ids[1], controller_network_id, controller_password)

    print("Beginning second NSX controller deployment.  This may take a while...")
    print(xml_string)

    conn = HTTPSConnection(nsx_manager_address)
    conn.request('POST', 'https://' + nsx_manager_address + '/api/2.0/vdn/controller', xml_string, headers)

    response = conn.getresponse()
    jobid = (response.read()).decode('utf-8')
    print(">" + jobid + "<")

    print("waiting 10 minutes...")
    time.sleep(600)



    xml_string = """
           <controllerSpec>
             <name>{0}</name>
             <description>nsx-controller</description>
             <ipPoolId>{1}</ipPoolId>
             <resourcePoolId>{2}</resourcePoolId>
               <datastoreId>{3}</datastoreId>
             <networkId>{4}</networkId>
             <password>{5}</password>
            </controllerSpec>
           """.format('NSX-Controller-3', controller_ip_pool_id, resource_pool_id, controller_datastore_ids[2], controller_network_id, controller_password)

    print("Beginning third NSX controller deployment.  This may take a while...")
    print(xml_string)

    conn = HTTPSConnection(nsx_manager_address)
    conn.request('POST', 'https://' + nsx_manager_address + '/api/2.0/vdn/controller', xml_string, headers)

    response = conn.getresponse()
    jobid = (response.read()).decode('utf-8')
    print(">" + jobid + "<")


    return 0

#def prepare_clusters_for_dfw(headers, nsx_manager_address, cluster_prep_list):

    # coming soon
    # just do the basic VIB install against the specified clusters

#def prepare_clusters_for_vxlan(headers, nsx_manager_address, cluster_prep_list, dvs_name, vtep_vlan_id):

    # coming soon
    # configure VXLAN on the specified clusters
    # you must have run prepare_clusters_for_dfw, check_dvs, and create_vtep_ip_pool first
    # use the IP pool called VTEP-Pool
    # use multi-vtep / route by src id teaming policy

#def create_transport_zone(headers, nsx_manager_address, dvs_name, cluster_prep_list):

    # coming soon
    # create a local transport zone called "Primary"
    # set replication type to Unicast
    # bind the clusters in cluster_prep_list to it

#def check_dvs(si, dvs_name, vtep_vlan_id, cluster_prep_list):

    # coming soon
    # 1. Check via SOAP to make sure the DVS has exactly two uplinks, and that they are both the same speed (i.e. none of this mixed uplinks thing)
    # 2. Hit the dvs health check via SOAP to check the following:
    #    a.  MTU is at least 9000 on the actual links
    #    b.  The links are NOT in any kind of LACP bundle
    #    c.  The VLAN specified in args.VTEP_VLAN_ID is actually tagged on both links - unless they specify 0 for the VLAN ID
    # 3. Check via SOAP to make sure the DVS has an overall MTU set of 9000
    # 4. Check via SOAP to make sure all of the clusters specified in args.cluster_prep_list are actually bound to the dvs

def create_vtep_ip_pool(nsx_manager_address, headers, ip_pool_list, ip_pool_mask, ip_pool_gateway, number_of_hosts, ip_pool_dns, dns_suffix):

    # get list of dns addresses
    vtep_dns_list = ip_pool_dns.split(",")

    # validate dns addresses
    for r in vtep_dns_list:
        if not ip_valid(r):
            return -1, "Invalid DNS address in ip_pool_dns {0}".format(r)

    # get pool list ranges
    vtep_range = ip_pool_list.split(',')

    # count of ip addresses
    host_count = 0

    # validate pool ranges and compute number of addresses
    for r in vtep_range:
        try:
            ip = r.split("-")
            ip_start = int(ipaddress.IPv4Address(ip[0]))  # start address
            ip_end = int(ipaddress.IPv4Address(ip[1]))  # end address
            host_count += (ip_end - ip_start) + 1  # increment host count
        except ipaddress.AddressValueError:
            return -1, "invalid IP range in ip_pool_list {0}".format(r)

    # validate number of hosts vs number_of_hosts argument
    if host_count < (2 * number_of_hosts):
        return -1, "count of ip addresses ({0}) < (number_of_hosts ({1}) * 2)".format(host_count, number_of_hosts)

    # validate the mask
    if not ip_mask_valid(ip_pool_mask):
        return -1, "Invalid ip_pool_mask {0}".format(ip_pool_mask)
    else:
        # remove the leading /
        vtep_mask = ip_pool_mask[1:]

    # validate gateway
    if ip_valid(ip_pool_gateway):
        vtep_gateway = ipaddress.IPv4Address(ip_pool_gateway)
    else:
        return -1, "Invalid ip_pool_gateway {0}".format(ip_pool_gateway)

    # format xml string header
    xml_string = """
    <ipamAddressPool>
      <name>VTEP-Pool</name>
      <prefixLength>{0}</prefixLength>
      <gateway>{1}</gateway>
      <dnsSuffix>{2}</dnsSuffix>
    """.format(vtep_mask, vtep_gateway, dns_suffix)

    # add dns server(s)
    dns_count = 1
    for dns in vtep_dns_list:
        xml_string += "  <dnsServer{0}>{1}</dnsServer{0}>\n".format(dns_count, dns)
        dns_count += 1

    # add ip ranges
    xml_string += "  <ipRanges>\n"
    for r in vtep_range:
        ip = r.split('-')
        xml_string += "    <ipRangeDto>\n"
        xml_string += "      <startAddress>{0}</startAddress>\n".format(ip[0])
        xml_string += "      <endAddress>{0}</endAddress>\n".format(ip[1])
        xml_string += "    </ipRangeDto>\n"
    xml_string += "  </ipRanges>\n"
    xml_string += "</ipamAddressPool>"

    print("Creating IP pool VTEP-Pool...")


    conn = HTTPSConnection(nsx_manager_address)
    conn.request('POST', 'https://' + nsx_manager_address + '/api/2.0/services/ipam/pools/scope/globalroot-0', xml_string, headers)

    response = conn.getresponse()

    if response.status != 201:
        print(str(response.status) + " IP Pool VTEP-Pool not created")
        return -1, response.read()
    else:
        print(str(response.status) + " IP Pool VTEP-Pool created successfully")
        return 0, response.read()


def create_controller_ip_pool(nsx_manager_address, headers, ip_pool_list, ip_pool_mask, ip_pool_gateway, ip_pool_dns, ip_pool_suffix):

    # same deal as the create_vtep_ip_pool, but we just need 3 for the controllers

    # get list of dns addresses
    vtep_dns_list = ip_pool_dns.split(",")

    # validate dns addresses
    for r in vtep_dns_list:
        if not ip_valid(r):
            return -1, "Invalid DNS address in ip_pool_dns {0}".format(r)

    # get pool list ranges
    vtep_range = ip_pool_list.split(',')

    # count of ip addresses
    host_count = 0

    # validate pool ranges and compute number of addresses
    for r in vtep_range:
        try:
            ip = r.split("-")
            ip_start = int(ipaddress.IPv4Address(ip[0]))  # start address
            ip_end = int(ipaddress.IPv4Address(ip[1]))  # end address
            host_count += (ip_end - ip_start) + 1  # increment host count
        except ipaddress.AddressValueError:
            return -1, "invalid IP range in ip_pool_list {0}".format(r)

    # validate number of hosts vs number_of_hosts argument
    if host_count < 3:
        return -1, "count of ip addresses ({0}) < 3".format(host_count)

    # validate the mask
    if not ip_mask_valid(ip_pool_mask):
        return -1, "Invalid ip_pool_mask {0}".format(ip_pool_mask)
    else:
        # remove the leading /
        vtep_mask = ip_pool_mask[1:]

    # validate gateway
    if ip_valid(ip_pool_gateway):
        vtep_gateway = ipaddress.IPv4Address(ip_pool_gateway)
    else:
        return -1, "Invalid ip_pool_gateway {0}".format(ip_pool_gateway)

    # format xml string header
    xml_string = """
       <ipamAddressPool>
         <name>Controller-Pool</name>
         <prefixLength>{0}</prefixLength>
         <gateway>{1}</gateway>
         <dnsSuffix>{2}</dnsSuffix>
       """.format(vtep_mask, vtep_gateway, ip_pool_suffix)

    # add dns server(s)
    dns_count = 1
    for dns in vtep_dns_list:
        xml_string += "  <dnsServer{0}>{1}</dnsServer{0}>\n".format(dns_count, dns)
        dns_count += 1

    # add ip ranges
    xml_string += "  <ipRanges>\n"
    for r in vtep_range:
        ip = r.split('-')
        xml_string += "    <ipRangeDto>\n"
        xml_string += "      <startAddress>{0}</startAddress>\n".format(ip[0])
        xml_string += "      <endAddress>{0}</endAddress>\n".format(ip[1])
        xml_string += "    </ipRangeDto>\n"
    xml_string += "  </ipRanges>\n"
    xml_string += "</ipamAddressPool>"

    print("Creating IP pool Controller-Pool...")

    conn = HTTPSConnection(nsx_manager_address)
    conn.request('POST', 'https://' + nsx_manager_address + '/api/2.0/services/ipam/pools/scope/globalroot-0',
                 xml_string, headers)

    response = conn.getresponse()

    if response.status != 201:
        print(str(response.status) + " IP Pool Controller-Pool not created")
        return -1, response.read()
    else:
        print(str(response.status) + " IP Pool Controller-Pool created successfully")
        return 0, response.read()



def ip_mask_valid(mask):
    """
    validate an ip CIDR mask
    :param mask:
    :return: boolean true if valid
    """
    # must match / and 1 or 2 digits, and not longer than 3 characters
    return ip_mask_re.match(mask) and (len(mask) <= 3)

def ip_valid(ip_address):
    """
    valid the ip address string by converting it
    doesn't need to keep the result, exception handles it
    :param ip_address:
    :return:
    """
    try:
        ipaddress.IPv4Address(ip_address)
        return True
    except ipaddress.AddressValueError:
        return False

def get_sha1_thumbprint(vcenter_address):

    thumbprint = "not found"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    wrappedSocket = ssl.wrap_socket(sock)

    try:
        wrappedSocket.connect((vcenter_address, 443))
    except:
        response = False
    else:

        thumb_sha1 = hashlib.sha1(wrappedSocket.getpeercert(True)).hexdigest()
        thumbprint = (':'.join(thumb_sha1[i:i + 2] for i in range(0, len(thumb_sha1), 2))).upper()

    wrappedSocket.close()

    return thumbprint

def get_sha256_thumbprint(vcenter_address):

    thumbprint = "not found"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    wrappedSocket = ssl.wrap_socket(sock)

    try:
        wrappedSocket.connect((vcenter_address, 443))
    except:
        response = False
    else:

        thumb_sha256 = hashlib.sha256(wrappedSocket.getpeercert(True)).hexdigest()
        thumbprint = (':'.join(thumb_sha256[i:i + 2] for i in range(0, len(thumb_sha256), 2))).upper()

    wrappedSocket.close()

    return thumbprint


def get_cluster_rp(dc, name):
    """
    Get a cluster by its name
    """
    cluster_list = dc.hostFolder.childEntity
    cluster_obj = get_obj_in_list(name, cluster_list)

    return cluster_obj.resourcePool

def get_network(si, dc, name):
    """
    Get a network by its name
    """
    viewManager = si.content.viewManager
    containerView = viewManager.CreateContainerView(dc, [vim.Network],
                                                    True)
    try:
        for network in containerView.view:
            print(network.name)
            if network.name == name:
                return network
    finally:
        containerView.Destroy()
    raise Exception("Failed to find network %s in datacenter %s" %
                    (name, dc.name))

def get_dc(si, name):
    """
    Get a datacenter by its name.
    """
    for dc in si.content.rootFolder.childEntity:
        if dc.name == name:
            return dc
    raise Exception('Failed to find datacenter named %s' % name)

def get_ds(dc, name):
    """
    Pick a datastore by its name.
    """
    for ds in dc.datastore:
        try:
            if ds.name == name:
                return ds
        except:  # Ignore datastores that have issues
            pass
    raise Exception("Failed to find %s on datacenter %s" % (name, dc.name))

def get_obj_in_list(obj_name, obj_list):
    """
    Gets an object out of a list (obj_list) whos name matches obj_name.
    """
    for o in obj_list:
        if o.name == obj_name:
            return o
    print("Unable to find object by the name of %s in list:\n%s" %
          (o.name, map(lambda o: o.name, obj_list)))
    exit(1)


if __name__ == "__main__":
    exit(main())