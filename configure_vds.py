#!/usr/bin/env python3


"""
Orignal configure_nsx_manager.py script written by Sean Howard
hows@netapp.com
https://github.com/seanhowardnetapp/pyNSXdeploy/


Arguments
---------
-s [vcenter FQDN or IP]
-u [vcenter administrator username - usually administrator@vsphere.local]
-p [vcenter administrator password]
-S [tells it to ignore SSL errors, you probably want this]
-d [datacenter you want to use.  optional - it will just use the first one if you don't specify]

"""

import atexit
import argparse
import time

from pyvim.connect import SmartConnectNoSSL, Disconnect
from pyVmomi import vim, vmodl


def setup_args():

    parser = argparse.ArgumentParser(
        description='Arguments needed to configure vCenter')

    # because -h is reserved for 'help' we use -s for service
    parser.add_argument('-s', '--host',
                        required=True,
                        action='store',
                        help='vSphere service to connect to')

    # because we want -p for password, we use -o for port
    parser.add_argument('-o', '--port',
                        type=int,
                        default=443,
                        action='store',
                        help='Port to connect on')

    parser.add_argument('-u', '--user',
                        required=True,
                        action='store',
                        help='User name to use when connecting to host')

    parser.add_argument('-p', '--password',
                        required=True,
                        action='store',
                        help='Password to use when connecting to host')

    parser.add_argument('-S', '--disable_ssl_verification',
                        required=False,
                        action='store_true',
                        help='Disable ssl host certificate verification')

    parser.add_argument('-d', '--datacenter',
                        help='Name of datacenter to use. '
                                'Defaults to first.')

    return(parser.parse_args())



def main():
    args = setup_args()
    try:
        si = SmartConnectNoSSL(host=args.host,
                               user=args.user,
                               pwd=args.password,
                               port=args.port)
        atexit.register(Disconnect, si)
    except:
        print("Unable to connect to %s" % args.host)
        return 1



    ''' Obtain DVS, cluster, and DC information and set up variables '''

    if args.datacenter:
        dc = get_dc(si, args.datacenter)
    else:
        dc = si.content.rootFolder.childEntity[0]

    dvswitchinfo = list_dvswitches(si)
    number_of_dvswitches = dvswitchinfo[0]
    dvswitchname = dvswitchinfo[1]

    clusterinfo = list_clusters(si)
    number_of_clusters = clusterinfo[0]
    clustername = clusterinfo[1]

    network_folder = dc.networkFolder

    ''' Check to see if there is more than one DVS, if so, cancel execution.  This means it is not a fresh environment out of NDE '''

    if number_of_dvswitches > 1:
        print("More than one Distributed Virtual Switch is detected in this environment.  This script is meant to be run immediately after NDE.  Exiting...")
        return 1

    ''' Check to see if there is more than one Cluster, if so, cancel execution.  This means it is not a fresh environment out of NDE '''

    if number_of_clusters > 1:
        print("More than one Cluster is detected in this environment.  This script is meant to be run immediately after NDE.  Exiting...")
        return 1

    ''' Build a dictionary of the objects for all the port groups '''
    portgroup_info = list_portgroups_initial(si)
    portgroup_moref_dict = portgroup_info[0]
    portgroup_name_flag = portgroup_info[1]
    portgroup_uplink_object = portgroup_moref_dict.get("NetApp HCI Uplinks")

    ''' Check to see if the portgroup_name_flag is nonzero.  If so, it means list_portgroups() found a portgroup name that shouldn't exist.  Again this means its not a fresh from NDE setup '''

    if portgroup_name_flag == 1:
        print("Found a portgroup name that should not exist.  This script is meant to be run immediately after NDE.  Exiting...")
        print("Offending Portgroup: " + portgroup_info[2])
        return 1

    ''' Get the VLAN ID from iSCSI-A'''
    vlan_id_from_iscsi_a = obtain_vlan_id_from_portgroup(portgroup_moref_dict.get("iSCSI-A"))

    ''' Temporarily rename the iSCSI port Groups on the Management DVS'''
    temporary_rename_of_iscsi_portgroups(si)

    ''' Rename the one DVS we have now to "NetApp HCI Management" and rename its uplinks to "NetApp HCI Management Uplinks" '''
    rename_management_dvs(dvswitchinfo[2],portgroup_uplink_object)

    ''' Create a dvs called "NetApp HCI Storage" and attach it to the cluster'''
    storage_dvswitch_object = create_dvSwitch(si,network_folder,clusterinfo[2],"NetApp HCI Storage")

    ''' Create a dvs called "NetApp HCI Compute" and attach it to the cluster'''
    compute_dvswitch_object = create_dvSwitch(si,network_folder,clusterinfo[2],"NetApp HCI Compute")

    ''' Rename the uplink portgroups '''
    rename_uplink_portgroups(si)

    ''' Add iSCSI-A and iSCSI-B to the storage DVS '''
    add_dvPort_group(si, storage_dvswitch_object, "iSCSI-A", vlan_id_from_iscsi_a)
    add_dvPort_group(si, storage_dvswitch_object, "iSCSI-B", vlan_id_from_iscsi_a)


def obtain_vlan_id_from_portgroup(portgroup_object):
    return portgroup_object.config.defaultPortConfig.vlan.vlanId


def rename_uplink_portgroups(si):
    content = si.RetrieveContent()

    for portgroup in _get_vim_objects(content, vim.dvs.DistributedVirtualPortgroup):
        if portgroup.name[:16] == "NetApp HCI Compu":
            task = portgroup.Rename("NetApp HCI Compute Uplinks")
            print("Changing Uplink Port Group Name to 'NetApp HCI Compute Uplinks'")

        if portgroup.name[:16] == "NetApp HCI Stora":
            task = portgroup.Rename("NetApp HCI Storage Uplinks")
            print("Changing Uplink Port Group Name to 'NetApp HCI Storage Uplinks'")


def temporary_rename_of_iscsi_portgroups(si):
    content = si.RetrieveContent()

    for portgroup in _get_vim_objects(content, vim.dvs.DistributedVirtualPortgroup):
        if portgroup.name == "iSCSI-A":
            task = portgroup.Rename("iSCSI-A_1")
            print("Temporarily renaming portgroup iSCSI-A to iSCSI-A_1")

        if portgroup.name == "iSCSI-B":
            task = portgroup.Rename("iSCSI-B_1")
            print("Temporarily renaming portgroup iSCSI-B to iSCSI-B_1")


def rename_management_dvs(dvs_object,portgroup_uplink_object):
    print("Renaming " + dvs_object.name + " to NetApp HCI Management...")
    task = dvs_object.Rename("NetApp HCI Management")
    print("Renaming " + portgroup_uplink_object.name + " to NetApp HCI Management Uplinks...")
    task = portgroup_uplink_object.Rename("NetApp HCI Management Uplinks")


def create_dvSwitch(si, network_folder, cluster, dvswitchname):
    content = si.RetrieveContent()
    dvs_host_configs = []
    uplink_port_names = []
    dvs_create_spec = vim.DistributedVirtualSwitch.CreateSpec()
    dvs_config_spec = vim.VmwareDistributedVirtualSwitch.ConfigSpec()
    dvs_config_spec.name = dvswitchname
    dvs_config_spec.maxMtu = 9000
    dvs_config_spec.uplinkPortPolicy = vim.DistributedVirtualSwitch.NameArrayUplinkPortPolicy()

    hosts = cluster.host

    if dvswitchname == "NetApp HCI Storage":
        uplink_port_names.append("NetApp_HCI_Storage_vmnic5")
        uplink_port_names.append("NetApp_HCI_Storage_vmnic1")

    if dvswitchname == "NetApp HCI Compute":
        uplink_port_names.append("NetApp_HCI_Virtualization_vmnic0")
        uplink_port_names.append("NetApp_HCI_Virtualization_vmnic4")

    for host in hosts:
        dvs_config_spec.uplinkPortPolicy.uplinkPortName = uplink_port_names
        dvs_config_spec.maxPorts = 60000
        dvs_host_config = vim.dvs.HostMember.ConfigSpec()
        dvs_host_config.operation = vim.ConfigSpecOperation.add
        dvs_host_config.host = host
        dvs_host_configs.append(dvs_host_config)
        dvs_config_spec.host = dvs_host_configs

    dvs_create_spec.configSpec = dvs_config_spec
    dvs_create_spec.productInfo = vim.dvs.ProductSpec(version='6.5.0')

    task = network_folder.CreateDVS_Task(dvs_create_spec)
    print("Creating new DVS", dvswitchname)

    time.sleep(5)

    return get_obj(content, [vim.DistributedVirtualSwitch], dvswitchname)


def add_dvPort_group(si, dv_switch, portgroupname, vlanid):
    dv_pg_spec = vim.dvs.DistributedVirtualPortgroup.ConfigSpec()
    dv_pg_spec.name = portgroupname
    dv_pg_spec.numPorts = 32
    dv_pg_spec.type = vim.dvs.DistributedVirtualPortgroup.PortgroupType.earlyBinding

    dv_pg_spec.defaultPortConfig = vim.dvs.VmwareDistributedVirtualSwitch.VmwarePortConfigPolicy()
    dv_pg_spec.defaultPortConfig.securityPolicy = vim.dvs.VmwareDistributedVirtualSwitch.SecurityPolicy()

    dv_pg_spec.defaultPortConfig.vlan = vim.dvs.VmwareDistributedVirtualSwitch.VlanIdSpec()
    dv_pg_spec.defaultPortConfig.vlan.vlanId = vlanid
    dv_pg_spec.defaultPortConfig.securityPolicy.allowPromiscuous = vim.BoolPolicy(value=False)
    dv_pg_spec.defaultPortConfig.securityPolicy.forgedTransmits = vim.BoolPolicy(value=False)

    dv_pg_spec.defaultPortConfig.vlan.inherited = False
    dv_pg_spec.defaultPortConfig.securityPolicy.macChanges = vim.BoolPolicy(value=False)
    dv_pg_spec.defaultPortConfig.securityPolicy.inherited = False

    if portgroupname == "iSCSI-A":
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy = vim.dvs.VmwareDistributedVirtualSwitch.UplinkPortTeamingPolicy()
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy.policy = vim.StringPolicy(value="failover_explicit")
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy.uplinkPortOrder = vim.dvs.VmwareDistributedVirtualSwitch.UplinkPortOrderPolicy()
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy.uplinkPortOrder.activeUplinkPort = "NetApp_HCI_Storage_vmnic5"
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy.uplinkPortOrder.standbyUplinkPort = []

    if portgroupname == "iSCSI-B":
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy = vim.dvs.VmwareDistributedVirtualSwitch.UplinkPortTeamingPolicy()
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy.policy = vim.StringPolicy(value="failover_explicit")
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy.uplinkPortOrder = vim.dvs.VmwareDistributedVirtualSwitch.UplinkPortOrderPolicy()
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy.uplinkPortOrder.activeUplinkPort = "NetApp_HCI_Storage_vmnic1"
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy.uplinkPortOrder.standbyUplinkPort = []

    """ hang on to this
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy = vim.dvs.VmwareDistributedVirtualSwitch.UplinkPortTeamingPolicy()
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy.policy = vim.StringPolicy(value="loadbalance_loadbased")
    """

    task = dv_switch.AddDVPortgroup_Task([dv_pg_spec])
    time.sleep(5)

    print("Successfully created DV Port Group", portgroupname)

def get_obj(content, vimtype, name):

    ''' Get the vsphere object associated with a given text name '''
    obj = None
    container = content.viewManager.CreateContainerView(content.rootFolder, vimtype, True)
    for c in container.view:
        if c.name == name:
            obj = c
            break
    return obj


def list_portgroups_initial(si):
    content = si.RetrieveContent()
    portgroup_moref_dict = dict()
    portgroup_name_flag = 0
    offending_portgroup = "none"

    for portgroup in _get_vim_objects(content, vim.dvs.DistributedVirtualPortgroup):

        portgroup_moref_dict[portgroup.name] = portgroup

        ''' Check to see that the port group is one that should exist, if you find a weird one, set the flag'''
        if portgroup.name != "NetApp HCI Uplinks" and portgroup.name != "VM_Network" and portgroup.name != "HCI_Internal_vCenter_Network" and portgroup.name != "HCI_Internal_OTS_Network" and portgroup.name != "HCI_Internal_mNode_Network" and portgroup.name != "vMotion" and portgroup.name != "Management Network" and portgroup.name != "iSCSI-A" and portgroup.name != "iSCSI-B":
            portgroup_name_flag=1
            offending_portgroup=portgroup.name

    return (portgroup_moref_dict,portgroup_name_flag,offending_portgroup)


def list_dvswitches(si):
    content = si.RetrieveContent()

    number_of_dvswitches = len(_get_vim_objects(content, vim.dvs.VmwareDistributedVirtualSwitch))
    dvswitchname = ""
    dvswitchmorefraw = ""

    for dvswitch in _get_vim_objects(content, vim.dvs.VmwareDistributedVirtualSwitch):
        dvswitchname = dvswitch.name
        dvswitchmorefraw = dvswitch

    return (number_of_dvswitches,dvswitchname,dvswitchmorefraw)


def list_clusters(si):
    content = si.RetrieveContent()

    number_of_clusters = len(_get_vim_objects(content, vim.ClusterComputeResource))
    clustername = ""
    clustermorefraw = ""

    for cluster in _get_vim_objects(content, vim.ClusterComputeResource):
        clustername = cluster.name
        clustermorefraw = cluster

    return (number_of_clusters,clustername,clustermorefraw)


def _get_vim_objects(content, vim_type):
    """Get vim objects of a given type."""
    return [item for item in content.viewManager.CreateContainerView(
        content.rootFolder, [vim_type], recursive=True
    ).view]


def get_dc(si, name):
    """
    Get a datacenter by its name.
    """
    for dc in si.content.rootFolder.childEntity:
        if dc.name == name:
            return dc

if __name__ == "__main__":
    exit(main())
