#!/usr/bin/env python3


"""
Orignal configure_vds.py script written by Sean Howard
hows@netapp.com
https://github.com/seanhowardnetapp/pyNSXdeploy/

This script will only work right if run immediately after NDE on a 6 cable setup.  The idea is to break up the single
big vswitch into 3 separate ones each with 2 cables.

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

    return (parser.parse_args())


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

    ''' Check to see if there is more than one DVS, if so, cancel execution.  This means it is not a fresh environment 
    out of NDE '''

    if number_of_dvswitches > 1:
        print(
            "More than one Distributed Virtual Switch is detected in this environment.  This script is meant to be run "
            "immediately after NDE.  Exiting...")
        return 1

    ''' Check to see if there is more than one Cluster, if so, cancel execution.  This means it is not a fresh 
    environment out of NDE '''

    if number_of_clusters > 1:
        print(
            "More than one Cluster is detected in this environment.  This script is meant to be run immediately after "
            "NDE.  Exiting...")
        return 1

    ''' Build a dictionary of the objects for all the port groups '''
    portgroup_info = list_portgroups_initial(si)
    portgroup_moref_dict = portgroup_info[0]
    portgroup_name_flag = portgroup_info[1]

    ''' Check to see if the portgroup_name_flag is nonzero.  If so, it means list_portgroups() found a portgroup name 
    that shouldn't exist.  Again this means its not a fresh from NDE setup '''

    if portgroup_name_flag == 1:
        print(
            "Found a portgroup name that should not exist.  This script is meant to be run immediately after NDE.  "
            "Exiting...")
        print("Offending Portgroup: " + portgroup_info[2])
        return 1

    ''' Get the VLAN ID from iSCSI-A'''
    vlan_id_from_iscsi_a = obtain_vlan_id_from_portgroup(portgroup_moref_dict.get("iSCSI-A"))

    ''' Temporarily rename the iSCSI port Groups on the Management DVS '''
    temporary_rename_of_iscsi_portgroups(si)

    ''' Get the VLAN ID from vMotion'''
    vlan_id_from_vmotion = obtain_vlan_id_from_portgroup(portgroup_moref_dict.get("vMotion"))

    ''' Temporarily rename the vMotion port group on the Management DVS '''
    temporary_rename_of_vmotion_portgroup(si)

    ''' Get the VLAN ID from VM Network'''
    vlan_id_from_vm = obtain_vlan_id_from_portgroup(portgroup_moref_dict.get("VM_Network"))

    ''' Temporarily rename the VM_Network port group on the Management DVS '''
    temporary_rename_of_vm_portgroup(si)

    ''' Get the VLAN ID from the C&C PGs'''
    vlan_id_from_Management_Network = obtain_vlan_id_from_portgroup(portgroup_moref_dict.get("Management Network"))
    vlan_id_from_HCI_Internal_vCenter_Network = obtain_vlan_id_from_portgroup(
        portgroup_moref_dict.get("HCI_Internal_vCenter_Network"))
    vlan_id_from_HCI_Internal_mNode_Network = obtain_vlan_id_from_portgroup(
        portgroup_moref_dict.get("HCI_Internal_mNode_Network"))
    vlan_id_from_HCI_Internal_OTS_Network = obtain_vlan_id_from_portgroup(
        portgroup_moref_dict.get("HCI_Internal_OTS_Network"))

    ''' Temporarily rename the C&C port groups on the Management DVS '''
    temporary_rename_of_cc_portgroups(si)

    ''' Create a dvs called "NetApp HCI Management" and attach it to the cluster '''
    management_dvswitch_object = create_dvSwitch(si, network_folder, clusterinfo[2], "NetApp HCI Management")

    ''' Create a dvs called "NetApp HCI Storage" and attach it to the cluster '''
    storage_dvswitch_object = create_dvSwitch(si, network_folder, clusterinfo[2], "NetApp HCI Storage")

    ''' Create a dvs called "NetApp HCI Compute" and attach it to the cluster '''
    compute_dvswitch_object = create_dvSwitch(si, network_folder, clusterinfo[2], "NetApp HCI Compute")

    ''' Rename the uplink portgroups '''
    rename_uplink_portgroups(si)

    ''' Add iSCSI-A and iSCSI-B to the storage DVS '''
    add_dvPort_group(si, storage_dvswitch_object, "iSCSI-A", vlan_id_from_iscsi_a)
    add_dvPort_group(si, storage_dvswitch_object, "iSCSI-B", vlan_id_from_iscsi_a)

    ''' Add vMotion to the Compute DVS '''
    add_dvPort_group(si, compute_dvswitch_object, "vMotion", vlan_id_from_vmotion)

    ''' Add VM_Network to the Compute DVS '''
    add_dvPort_group(si, compute_dvswitch_object, "VM_Network", vlan_id_from_vm)

    ''' Add Management Network to the Management DVS'''
    add_dvPort_group(si, management_dvswitch_object, "Management Network", vlan_id_from_Management_Network)

    ''' Add C&C port groups '''
    add_dvPort_group(si, management_dvswitch_object, "HCI_Internal_vCenter_Network",
                     vlan_id_from_HCI_Internal_vCenter_Network)
    add_dvPort_group(si, management_dvswitch_object, "HCI_Internal_OTS_Network", vlan_id_from_HCI_Internal_OTS_Network)
    add_dvPort_group(si, management_dvswitch_object, "HCI_Internal_mNode_Network",
                     vlan_id_from_HCI_Internal_mNode_Network)

    ''' Now its time to move the VMkernel IPs over to the new port groups'''

    content = si.RetrieveContent()

    """ move vmnic3 to the new Management DVS """
    source_dvswitch = get_obj(content, [vim.DistributedVirtualSwitch], "NetApp HCI VDS")
    target_dvswitch = get_obj(content, [vim.DistributedVirtualSwitch], "NetApp HCI Management")

    for entity in dc.hostFolder.childEntity:
        for host in entity.host:
            print("Migrating vmnic3 on host:", host.name)
            time.sleep(5)
            unassign_pnic_list = ["vmnic0", "vmnic1", "vmnic2", "vmnic4", "vmnic5"]
            unassign_pnic(source_dvswitch, host, unassign_pnic_list)
            time.sleep(5)
            assign_pnic_list = ["vmnic3"]
            assign_pnic(target_dvswitch, host, assign_pnic_list)
            time.sleep(5)

    ''' relocate the c&c vms '''
    list_of_vms_to_relocate = ["NetApp-Management-Node", "vCenter-Server-Appliance",
                               "File Services powered by ONTAP-01"]

    for vmname in list_of_vms_to_relocate:
        vm = get_obj(content, [vim.VirtualMachine], vmname)
        vmtype = str(type(vm))

        if vmtype == "<class 'pyVmomi.VmomiSupport.vim.VirtualMachine'>" and vmname == "vCenter-Server-Appliance":
            network = get_obj(content, [vim.DistributedVirtualPortgroup], "HCI_Internal_vCenter_Network")
            move_vm(vm, network)
            print("Successfully moved", vmname, "to new Management DVS")

        if vmtype == "<class 'pyVmomi.VmomiSupport.vim.VirtualMachine'>" and vmname == "NetApp-Management-Node":
            network = get_obj(content, [vim.DistributedVirtualPortgroup], "HCI_Internal_mNode_Network")
            move_vm(vm, network)
            print("Successfully moved", vmname, "to new Management DVS")

        if vmtype == "<class 'pyVmomi.VmomiSupport.vim.VirtualMachine'>" and vmname == "File Services powered by ONTAP-01":
            network = get_obj(content, [vim.DistributedVirtualPortgroup], "HCI_Internal_OTS_Network")
            move_vm(vm, network)
            print("Successfully moved", vmname, "to new Management DVS")

        time.sleep(5)

    target_portgroup = get_obj(content, [vim.DistributedVirtualPortgroup], "Management Network")

    for entity in dc.hostFolder.childEntity:
        for host in entity.host:
            print("Migrating vmnic2 / vmk0 on host:", host.name)
            migrate_vmk(host, target_portgroup, target_dvswitch, "vmk0")
            time.sleep(5)
            unassign_pnic_list = ["vmnic0", "vmnic1", "vmnic4", "vmnic5"]
            unassign_pnic(source_dvswitch, host, unassign_pnic_list)
            time.sleep(5)
            assign_pnic_list = ["vmnic2", "vmnic3"]
            assign_pnic(target_dvswitch, host, assign_pnic_list)
            time.sleep(5)

    ''' Move vmnic5 and its associated vmk to the storage dvs'''

    source_dvswitch = get_obj(content, [vim.DistributedVirtualSwitch], "NetApp HCI VDS")
    target_dvswitch = get_obj(content, [vim.DistributedVirtualSwitch], "NetApp HCI Storage")
    target_portgroup = get_obj(content, [vim.DistributedVirtualPortgroup], "iSCSI-A")

    for entity in dc.hostFolder.childEntity:
        for host in entity.host:
            print("Migrating vmnic5 / vmk1 on host:", host.name)
            migrate_vmk(host, target_portgroup, target_dvswitch, "vmk1")
            time.sleep(5)
            unassign_pnic_list = ["vmnic0", "vmnic1", "vmnic4"]
            unassign_pnic(source_dvswitch, host, unassign_pnic_list)
            time.sleep(5)
            assign_pnic_list = ["vmnic5"]
            assign_pnic(target_dvswitch, host, assign_pnic_list)
            time.sleep(5)

    ''' Move vmnic1 and its associated vmk to the storage dvs'''

    source_dvswitch = get_obj(content, [vim.DistributedVirtualSwitch], "NetApp HCI VDS")
    target_dvswitch = get_obj(content, [vim.DistributedVirtualSwitch], "NetApp HCI Storage")
    target_portgroup = get_obj(content, [vim.DistributedVirtualPortgroup], "iSCSI-B")

    for entity in dc.hostFolder.childEntity:
        for host in entity.host:
            print("Migrating vmnic1 / vmk2 on host:", host.name)
            migrate_vmk(host, target_portgroup, target_dvswitch, "vmk2")
            time.sleep(5)
            unassign_pnic_list = ["vmnic0", "vmnic4"]
            unassign_pnic(source_dvswitch, host, unassign_pnic_list)
            time.sleep(5)
            assign_pnic_list = ["vmnic5", "vmnic1"]
            assign_pnic(target_dvswitch, host, assign_pnic_list)
            time.sleep(5)

    """ Move vmnic0 and its associated vmk to the compute dvs"""

    source_dvswitch = get_obj(content, [vim.DistributedVirtualSwitch], "NetApp HCI VDS")
    target_dvswitch = get_obj(content, [vim.DistributedVirtualSwitch], "NetApp HCI Compute")
    target_portgroup = get_obj(content, [vim.DistributedVirtualPortgroup], "vMotion")

    for entity in dc.hostFolder.childEntity:
        for host in entity.host:
            print("Migrating vmnic0 / vmk3 on host:", host.name)
            migrate_vmk(host, target_portgroup, target_dvswitch, "vmk3")
            time.sleep(5)
            unassign_pnic_list = ["vmnic4"]
            unassign_pnic(source_dvswitch, host, unassign_pnic_list)
            time.sleep(5)
            assign_pnic_list = ["vmnic0"]
            assign_pnic(target_dvswitch, host, assign_pnic_list)
            time.sleep(5)

    """ Move vmnic4 to the compute dvs"""

    source_dvswitch = get_obj(content, [vim.DistributedVirtualSwitch], "NetApp HCI VDS")
    target_dvswitch = get_obj(content, [vim.DistributedVirtualSwitch], "NetApp HCI Compute")

    for entity in dc.hostFolder.childEntity:
        for host in entity.host:
            print("Migrating vmnic4 on host:", host.name)
            time.sleep(5)
            unassign_pnic_list = []
            unassign_pnic(source_dvswitch, host, unassign_pnic_list)
            time.sleep(5)
            assign_pnic_list = ["vmnic0", "vmnic4"]
            assign_pnic(target_dvswitch, host, assign_pnic_list)
            time.sleep(5)

    """
    clean up the old port groups

    list_of_pgs_to_delete = ["iSCSI-A_1","iSCSI-B_1","vMotion_1","VM_Network_1","HCI_Internal_vCenter_Network_1","HCI_Internal_mNode_Network_1","HCI_Internal_OTS_Network_1","Management Network_1"]

    for pgname in list_of_pgs_to_delete:
        pg = get_obj(content, [vim.DistributedVirtualPortgroup], pgname)
        delete_portgroup(pg)
        print("Deleted portgroup", pgname)
    """

    delete_dvs(dvswitchinfo[2])

    print("DVS reconfiguration complete.")


def delete_portgroup(pg):
    task = pg.Destroy_Task()


def delete_dvs(dvs):
    task = dvs.Destroy_Task()


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

        if portgroup.name[:16] == "NetApp HCI Manag":
            task = portgroup.Rename("NetApp HCI Management Uplinks")
            print("Changing Uplink Port Group Name to 'NetApp HCI Management Uplinks'")


def temporary_rename_of_iscsi_portgroups(si):
    content = si.RetrieveContent()

    for portgroup in _get_vim_objects(content, vim.dvs.DistributedVirtualPortgroup):
        if portgroup.name == "iSCSI-A":
            task = portgroup.Rename("iSCSI-A_1")
            print("Temporarily renaming portgroup iSCSI-A to iSCSI-A_1")

        if portgroup.name == "iSCSI-B":
            task = portgroup.Rename("iSCSI-B_1")
            print("Temporarily renaming portgroup iSCSI-B to iSCSI-B_1")


def temporary_rename_of_vmotion_portgroup(si):
    content = si.RetrieveContent()

    for portgroup in _get_vim_objects(content, vim.dvs.DistributedVirtualPortgroup):
        if portgroup.name == "vMotion":
            task = portgroup.Rename("vMotion_1")
            print("Temporarily renaming portgroup vMotion to vMotion_1")


def temporary_rename_of_vm_portgroup(si):
    content = si.RetrieveContent()

    for portgroup in _get_vim_objects(content, vim.dvs.DistributedVirtualPortgroup):
        if portgroup.name == "VM_Network":
            task = portgroup.Rename("VM_Network_1")
            print("Temporarily renaming VM_Network to VM_Network_1")


def temporary_rename_of_cc_portgroups(si):
    content = si.RetrieveContent()

    for portgroup in _get_vim_objects(content, vim.dvs.DistributedVirtualPortgroup):
        if portgroup.name == "HCI_Internal_vCenter_Network":
            task = portgroup.Rename("HCI_Internal_vCenter_Network_1")
            print("Temporarily renaming HCI_Internal_vCenter_Network to HCI_Internal_vCenter_Network_1")

    for portgroup in _get_vim_objects(content, vim.dvs.DistributedVirtualPortgroup):
        if portgroup.name == "HCI_Internal_OTS_Network":
            task = portgroup.Rename("HCI_Internal_OTS_Network_1")
            print("Temporarily renaming HCI_Internal_OTS_Network to HCI_Internal_OTS_Network_1")

    for portgroup in _get_vim_objects(content, vim.dvs.DistributedVirtualPortgroup):
        if portgroup.name == "HCI_Internal_mNode_Network":
            task = portgroup.Rename("HCI_Internal_mNode_Network_1")
            print("Temporarily renaming HCI_Internal_mNode_Network to HCI_Internal_mNode_Network_1")

    for portgroup in _get_vim_objects(content, vim.dvs.DistributedVirtualPortgroup):
        if portgroup.name == "Management Network":
            task = portgroup.Rename("Management Network_1")
            print("Temporarily renaming Management Network to Management Network_1")


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
        uplink_port_names.append("NetApp_HCI_Compute_vmnic0")
        uplink_port_names.append("NetApp_HCI_Compute_vmnic4")

    if dvswitchname == "NetApp HCI Management":
        uplink_port_names.append("NetApp_HCI_Management_vmnic2")
        uplink_port_names.append("NetApp_HCI_Management_vmnic3")

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

    if portgroupname == "vMotion":
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy = vim.dvs.VmwareDistributedVirtualSwitch.UplinkPortTeamingPolicy()
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy.policy = vim.StringPolicy(value="loadbalance_loadbased")

    if portgroupname == "HCI_Internal_vCenter_Network":
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy = vim.dvs.VmwareDistributedVirtualSwitch.UplinkPortTeamingPolicy()
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy.policy = vim.StringPolicy(value="loadbalance_loadbased")

    if portgroupname == "HCI_Internal_OTS_Network":
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy = vim.dvs.VmwareDistributedVirtualSwitch.UplinkPortTeamingPolicy()
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy.policy = vim.StringPolicy(value="loadbalance_loadbased")

    if portgroupname == "HCI_Internal_mNode_Network":
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy = vim.dvs.VmwareDistributedVirtualSwitch.UplinkPortTeamingPolicy()
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy.policy = vim.StringPolicy(value="loadbalance_loadbased")

    if portgroupname == "Management Network":
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy = vim.dvs.VmwareDistributedVirtualSwitch.UplinkPortTeamingPolicy()
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy.policy = vim.StringPolicy(value="loadbalance_loadbased")
        dv_pg_spec.numPorts = 512

    if portgroupname == "VM_Network":
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy = vim.dvs.VmwareDistributedVirtualSwitch.UplinkPortTeamingPolicy()
        dv_pg_spec.defaultPortConfig.uplinkTeamingPolicy.policy = vim.StringPolicy(value="loadbalance_loadbased")
        dv_pg_spec.numPorts = 512

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
        if portgroup.name != "NetApp HCI Uplinks" and portgroup.name != "VM_Network" and portgroup.name != "HCI_Internal_vCenter_Network" and portgroup.name != "HCI_Internal_OTS_Network" and portgroup.name != "HCI_Internal_mNode_Network" and portgroup.name != "vMotion" and portgroup.name != "Management Network" and portgroup.name != "iSCSI-A" and portgroup.name != "iSCSI-B" and portgroup.name != "vCenter_Recovery_PG":
            portgroup_name_flag = 1
            offending_portgroup = portgroup.name

    return (portgroup_moref_dict, portgroup_name_flag, offending_portgroup)


def list_dvswitches(si):
    content = si.RetrieveContent()

    number_of_dvswitches = len(_get_vim_objects(content, vim.dvs.VmwareDistributedVirtualSwitch))
    dvswitchname = ""
    dvswitchmorefraw = ""

    for dvswitch in _get_vim_objects(content, vim.dvs.VmwareDistributedVirtualSwitch):
        dvswitchname = dvswitch.name
        dvswitchmorefraw = dvswitch

    return (number_of_dvswitches, dvswitchname, dvswitchmorefraw)


def list_clusters(si):
    content = si.RetrieveContent()

    number_of_clusters = len(_get_vim_objects(content, vim.ClusterComputeResource))
    clustername = ""
    clustermorefraw = ""

    for cluster in _get_vim_objects(content, vim.ClusterComputeResource):
        clustername = cluster.name
        clustermorefraw = cluster

    return (number_of_clusters, clustername, clustermorefraw)


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


def create_host_vnic_config(target_portgroup, target_dvswitch, vmk):
    host_vnic_config = vim.host.VirtualNic.Config()
    host_vnic_config.spec = vim.host.VirtualNic.Specification()

    host_vnic_config.changeOperation = "edit"
    host_vnic_config.device = vmk
    host_vnic_config.portgroup = ""
    host_vnic_config.spec.distributedVirtualPort = vim.dvs.PortConnection()
    host_vnic_config.spec.distributedVirtualPort.switchUuid = target_dvswitch.uuid
    host_vnic_config.spec.distributedVirtualPort.portgroupKey = target_portgroup.key

    '''
    if vmk == "vmk3":
        host_vnic_config.spec.netStackInstanceKey = "vmotion"
    '''

    return host_vnic_config


def migrate_vmk(host, target_portgroup, target_dvswitch, vmk):
    host_network_system = host.configManager.networkSystem
    config = vim.host.NetworkConfig()
    config.vnic = [create_host_vnic_config(target_portgroup, target_dvswitch, vmk)]
    host_network_system.UpdateNetworkConfig(config, "modify")


def assign_pnic(dvs, host, pnic_device_list):
    dvs_config_spec = vim.DistributedVirtualSwitch.ConfigSpec()
    dvs_config_spec.configVersion = dvs.config.configVersion
    dvs_host_configs = []
    dvs_host_config = vim.dvs.HostMember.ConfigSpec()
    dvs_host_config.operation = vim.ConfigSpecOperation.edit
    dvs_host_config.backing = vim.dvs.HostMember.PnicBacking()

    for pnic in pnic_device_list:
        dvs_host_config.backing.pnicSpec.append(vim.dvs.HostMember.PnicSpec(pnicDevice=pnic))

    dvs_host_config.host = host
    dvs_host_configs.append(dvs_host_config)
    dvs_config_spec.host = dvs_host_configs
    task = dvs.ReconfigureDvs_Task(dvs_config_spec)


def unassign_pnic(dvs, host, pnic_device_list):
    dvs_config_spec = vim.DistributedVirtualSwitch.ConfigSpec()
    dvs_config_spec.configVersion = dvs.config.configVersion
    dvs_host_configs = []
    dvs_host_config = vim.dvs.HostMember.ConfigSpec()
    dvs_host_config.operation = vim.ConfigSpecOperation.edit
    dvs_host_config.backing = vim.dvs.HostMember.PnicBacking()

    for pnic in pnic_device_list:
        dvs_host_config.backing.pnicSpec.append(vim.dvs.HostMember.PnicSpec(pnicDevice=pnic))

    dvs_host_config.host = host
    dvs_host_configs.append(dvs_host_config)
    dvs_config_spec.host = dvs_host_configs
    task = dvs.ReconfigureDvs_Task(dvs_config_spec)


def move_vm(vm, network):
    device_change = []

    for device in vm.config.hardware.device:
        if isinstance(device, vim.vm.device.VirtualEthernetCard):
            nicspec = vim.vm.device.VirtualDeviceSpec()
            nicspec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
            nicspec.device = device
            nicspec.device.wakeOnLanEnabled = True

            dvs_port_connection = vim.dvs.PortConnection()
            dvs_port_connection.portgroupKey = network.key
            dvs_port_connection.switchUuid = network.config.distributedVirtualSwitch.uuid
            nicspec.device.backing = vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo()
            nicspec.device.backing.port = dvs_port_connection

            nicspec.device.connectable = vim.vm.device.VirtualDevice.ConnectInfo()
            nicspec.device.connectable.connected = True
            nicspec.device.connectable.startConnected = True
            nicspec.device.connectable.allowGuestControl = True
            device_change.append(nicspec)
            break

    config_spec = vim.vm.ConfigSpec(deviceChange=device_change)
    task = vm.ReconfigVM_Task(config_spec)


if __name__ == "__main__":
    exit(main())
