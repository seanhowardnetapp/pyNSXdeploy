#!/usr/bin/env python

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
"""

import ssl
import atexit
import os
import os.path
import ssl
import sys
import base64

from http.client import HTTPSConnection

from tools import cli


from pyVim.connect import SmartConnectNoSSL, Disconnect
from pyVmomi import vim, vmodl


__author__ = 'hows@netapp.com'


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

    #set the segment id range
    set_segment_id_range(headers,args.nsx_manager_address)

def set_segment_id_range(headers,nsx_manager_address):

    # uncomment this to print the current segment id situation for debugging purposes
    # conn = HTTPSConnection(nsx_manager_address)
    # conn.request('GET', 'https://' + nsx_manager_address + '/api/2.0/vdn/config/segments/','',headers)
    # response = conn.getresponse()
    # print (str(response.status))
    # print (str(response.read()))

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
    else:
            print (str(response.status) + " Segment ID Range created successfully")
    return

def register_nsx_with_vcenter(headers, nsx_manager_address, vcenter_address):
    # coming soon

def register_nsx_with_lookup_service(headers, nsx_manager_address, lookup_service_address):
    # coming soon

def deploy_nsx_controllers(headers, nsx_manager_address, controller_cluster, controller_datastores, controller_network, dc):

    # coming soon
    # deploy 3 NSX controllers to whatever datacenter and cluster you specified by name, error out if it can't find it
    # deploy controller 1 to the first datastore in the controller_datastores list, 2 to the second, 3 to the third
    # hard name the controller VM and hostnames "nsx-controller-1", "nsx-controller-2", "nsx-controller-3"
    # use the IP pool called "Controller-Pool", created by the create_controller_pool function [obv this must be called later]
    # connect all three controllers to the controller_network specified
    # wait for 5-10 minutes between each controller deployment (it won't let you do multiple in parallel)
    # there is an API method to get the progress percentage for a currently deploying controller.  maybe sample that and print it every minute?
    # check the comm channel health of the controllers and only exit this function successfully once all three are green

def prepare_clusters_for_dfw(headers, nsx_manager_address, cluster_prep_list):

    # coming soon
    # just do the basic VIB install against the specified clusters

def prepare_clusters_for_vxlan(headers, nsx_manager_address, cluster_prep_list, dvs_name, vtep_vlan_id):

    # coming soon
    # configure VXLAN on the specified clusters
    # you must have run prepare_clusters_for_dfw, check_dvs, and create_vtep_ip_pool first
    # use the IP pool called VTEP-Pool
    # use multi-vtep / route by src id teaming policy

def create_transport_zone(headers, nsx_manager_address, dvs_name, cluster_prep_list):

    # coming soon
    # create a local transport zone called "Primary"
    # set replication type to Unicast
    # bind the clusters in cluster_prep_list to it

def check_dvs(si, dvs_name, vtep_vlan_id, cluster_prep_list):

    # coming soon
    # 1. Check via SOAP to make sure the DVS has exactly two uplinks, and that they are both the same speed (i.e. none of this mixed uplinks thing)
    # 2. Hit the dvs health check via SOAP to check the following:
    #    a.  MTU is at least 9000 on the actual links
    #    b.  The links are NOT in any kind of LACP bundle
    #    c.  The VLAN specified in args.VTEP_VLAN_ID is actually tagged on both links - unless they specify 0 for the VLAN ID
    # 3. Check via SOAP to make sure the DVS has an overall MTU set of 9000
    # 4. Check via SOAP to make sure all of the clusters specified in args.cluster_prep_list are actually bound to the dvs

def create_vtep_ip_pool(headers, nsx_manager_address, ip_pool_string, ip_pool_mask, ip_pool_gateway, number_of_hosts, ip_pool_dns, ip_pool_suffix):

    # coming soon
    # description of inputs
    # ip_pool_string = coming from CLI argument.  Specified in the format 192.168.0.1-192.168.0.10.  multiple ranges can be specified, use comma to separate i.e 192.168.0.1-192.168.0.10,192.168.0.50-192.168.0.60
    # ip_pool_mask = coming from CLI argument.  Specified in CIDR format (i.e. /24, /29, etc)
    # ip_pool_gateway = coming from CLI argument.  Specified as 192.168.0.254
    # number_of_hosts = count the total number of IPs across the specified range(s) and it must be at least 2x this variable.  error out if they provided fewer than this number
    # ip_pool_dns = comma separated list of DNS server IPs

    # variables and string manipulations
    # vtep_mask = ip_pool_mask, but reformatted as the CIDR format without the slash.  so /24 converts to 24, etc.
    # vtep_gateway = ip_pool_gateway, but validated so its really formatted as a full ip address
    # vtep_suffix = ip_pool_suffix, but validated so its a real domain name and not some bs, i.e. mydomain.local or similar
    # vtep_dns_1 = first value from ip_pool_dns
    # vtep_dns_2 = second value from ip_pool_dns (if present, if not leave blank)
    # vtep_range_1_start_ip = first IP from the first range
    # vtep_range_1_end_ip = last IP from the first range
    # vtep_range_2_start_ip = first IP from the first range
    # vtep_range_2_end_ip = last IP from the first range
    # ... you'll need to make as many of these as there are specified ranges in ip_pool_string, not sure of the best way to go about it

    # outputs
    # XML formatted multiline string that looks something like the following:

    # < ipamAddressPool >
    # < name > VTEP - Pool < / name >
    # < prefixLength > {vtep_mask} < / prefixLength >
    # < gateway > {vtep_gateway} < / gateway >
    # < dnsSuffix > {vtep_suffix} < / dnsSuffix >
    # < dnsServer1 > {vtep_dns_1} < / dnsServer1 >
    # < dnsServer2 > {vtep_dns_2} < / dnsServer2 >
    # < ipRanges >
    #  < ipRangeDto >
    # < startAddress > {vtep_range_1_start_ip} < / startAddress >
    # < endAddress > {vtep_range_1_end_ip} < / endAddress >
    # < / ipRangeDto >
    # < ipRangeDto >
    # < startAddress > {vtep_range_2_start_ip} < / startAddress >
    # < endAddress > {vtep_range_2_end_ip} < / endAddress >
    # < / ipRangeDto >
    # < / ipRanges >
    # < / ipamAddressPool >

def create_controller_ip_pool(headers, nsx_manager_address, ip_pool_string, ip_pool_mask, ip_pool_gateway, number_of_hosts, ip_pool_dns, ip_pool_suffix):

    # same deal as the create_vtep_ip_pool, but we just need 3 for the controllers

if __name__ == "__main__":
    exit(main())