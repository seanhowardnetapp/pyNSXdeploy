#!/usr/bin/env python3

"""
Orignal deploy_ova.py script written by Nathan Prziborowski
Github: https://github.com/prziborowski

This code is released under the terms of the Apache 2
http://www.apache.org/licenses/LICENSE-2.0.html

Modified by Sean Howard
hows@netapp.com

Modified deploy_nsx_manager.py version as follows

    1. adds arguments needed to do the internal config of the NSX Manager (10 additional arguments now required)
    2. added the ability to map the deployed VM to a network specified by name (it just went to the default network before)
    3. now allows you to specify the VM name in the inventory, before it just got "NSX Manager" from the OVF file
    4. changed it so you now specify the cluster to deploy NSX manager to, not the resource pool
    
    
Arguments
---------
-s [vcenter FQDN or IP] 
-u [vcenter administrator username] 
-p [vcenter administrator password] 
-S [tells it to ignore SSL errors, you probably want this]
--ova-path [path on your local machine to nsx_manager ova file] 
-ds [datastore name to deploy OVA to]
-cluster [name of cluster you want NSX Manager to deploy to]
-vsm_cli_passwd_0 [CLI password for NSX Manager - must be 13 or more chars]
-vsm_cli_en_passwd_0 [CLI enable pwd for NSX manager - must be 13 or more chars]
-vsm_hostname [hostname for nsx manager]
-vsm_ip_0 [IPv4 address for NSX manager]
-vsm_netmask_0 [IPv4 subnet mask for NSX manager]
-vsm_gateway_0 [Default Gateway for NSX Manager]
-vsm_ntp_0 [NTP Server NSX manager should use]
-vsm_dns1_0 [comma separated list of DNS servers for NSX manager to use]
-map_eth0_to_network [name of network the NSX manager's management interface should bind to]


example for deploying it to my lab from a windows box
-----------------------------------------------------
deploy_nsx_manager.py ^
-s 10.217.91.253 ^
-u admin@vsphere.local ^
-p sC!8NyRAmzPh ^
-S ^
-ds nfs ^
--ova-path "VMware-NSX-Manager-6.4.1-8599035.ova" ^
-vsm_cli_passwd_0 NetApp123!NetApp123! ^
-vsm_cli_en_passwd_0 NetApp123!Netapp123! ^
-vsm_hostname nsxmanager1 ^
-vsm_ip_0 10.217.88.100 ^
-vsm_netmask_0 255.255.252.0 ^
-vsm_gateway_0 10.217.91.254 ^
-vsm_ntp_0 199.38.183.232 ^
-vsm_dns1_0 8.8.8.8,8.8.8.4 ^
-map_eth0_to_network "VM Network" ^
-vmname "NSX-Manager-1" ^
-cluster Management

"""

import atexit
import os
import os.path
import ssl
import sys
import tarfile
import time

from threading import Timer
from argparse import ArgumentParser
from getpass import getpass
from six.moves.urllib.request import Request, urlopen

from tools import cli

from pyvim.connect import SmartConnectNoSSL, Disconnect
from pyVmomi import vim, vmodl


def setup_args():
    parser = cli.build_arg_parser()
    parser.add_argument('--ova-path',
                        help='Path to the OVA file, can be local or a URL.')
    parser.add_argument('-d', '--datacenter',
                        help='Name of datacenter to search on. '
                             'Defaults to first.')
    parser.add_argument('-ds', '--datastore',
                        help='Name of datastore to use. '
                             'Defaults to largest free space in datacenter.')
    parser.add_argument('-vsm_cli_passwd_0', '--vsm_cli_passwd_0',
                        help='CLI password for NSX Manager - must be 13 or more chars')
    parser.add_argument('-vsm_cli_en_passwd_0', '--vsm_cli_en_passwd_0',
                        help='CLI enable password for NSX Manager - must be 13 or more chars')
    parser.add_argument('-vsm_hostname', '--vsm_hostname',
                        help='hostname for nsx manager')
    parser.add_argument('-vsm_ip_0', '--vsm_ip_0',
                        help='IPv4 address for NSX manager')
    parser.add_argument('-vsm_netmask_0', '--vsm_netmask_0',
                        help='IPv4 subnet mask for NSX manager')
    parser.add_argument('-vsm_gateway_0', '--vsm_gateway_0',
                        help='Default Gateway for NSX Manager')
    parser.add_argument('-vsm_ntp_0', '--vsm_ntp_0',
                        help='NTP Server NSX manager should use')
    parser.add_argument('-vsm_dns1_0', '--vsm_dns1_0',
                        help='comma separated list of DNS servers for NSX manager to use')
    parser.add_argument('-map_eth0_to_network', '--map_eth0_to_network',
                        help='Name of port group to bind NSX Managers IPV4 interface to')
    parser.add_argument('-vmname','--vmname',
                        help='Name of the NSX Manager VM in the vCenter inventory')
    parser.add_argument('-cluster','--cluster',
                        help='Name of the cluster you wish to deploy NSX Manager to')
    return cli.prompt_for_password(parser.parse_args())


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

    if args.datacenter:
        dc = get_dc(si, args.datacenter)
    else:
        dc = si.content.rootFolder.childEntity[0]

    if args.datastore:
        ds = get_ds(dc, args.datastore)
    else:
        ds = get_largest_free_ds(dc)

    ovf_handle = OvfHandler(args.ova_path)

    ovfManager = si.content.ovfManager

    propertyMappingDict={'vsm_cli_passwd_0':args.vsm_cli_passwd_0,'vsm_cli_en_passwd_0':args.vsm_cli_en_passwd_0,'vsm_hostname':args.vsm_hostname,'vsm_ip_0':args.vsm_ip_0,'vsm_netmask_0':args.vsm_netmask_0,'vsm_gateway_0':args.vsm_gateway_0,'vsm_ntp_0':args.vsm_ntp_0,'vsm_dns1_0':args.vsm_dns1_0}

    mapping = []
    for k in propertyMappingDict:
        v = propertyMappingDict[k]
        mapping.append(vim.KeyValue(key=k, value=v))

    network = get_network(si, dc, args.map_eth0_to_network)
    cluster_rp = get_cluster(si, dc, args.cluster)

    network_map = vim.OvfManager.NetworkMapping()
    network_map.name = 'Management Network'
    network_map.network = network

    cisp = vim.OvfManager.CreateImportSpecParams(propertyMapping=mapping,entityName=args.vmname)
    cisp.networkMapping.append(network_map)

    cisr = ovfManager.CreateImportSpec(ovf_handle.get_descriptor(),
                                       cluster_rp, ds, cisp)

    # These errors might be handleable by supporting the parameters in
    # CreateImportSpecParams
    if len(cisr.error):
        print("The following errors will prevent import of this OVA:")
        for error in cisr.error:
            print("%s" % error)
        return 1

    ovf_handle.set_spec(cisr)

    lease = cluster_rp.ImportVApp(cisr.importSpec, dc.vmFolder)

    while lease.state == vim.HttpNfcLease.State.initializing:
        print("Waiting for lease to be ready...")
        time.sleep(1)

    if lease.state == vim.HttpNfcLease.State.error:
        print("Lease error: %s" % lease.error)
        return 1
    if lease.state == vim.HttpNfcLease.State.done:
        return 0

    print("Starting deploy...")

    ovf_handle.upload_disks(lease, args.host)

    # Wait a little bit then try to power nsx manager on

    time.sleep(60)
    vmnames = args.vmname
    content = si.content
    objView = content.viewManager.CreateContainerView(content.rootFolder,
                                                      [vim.VirtualMachine],
                                                      True)
    vmList = objView.view
    objView.Destroy()

    tasks = [vm.PowerOn() for vm in vmList if vm.name in vmnames]

    print("done")
    
    
def get_cluster(si, dc, name):
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


def get_largest_free_ds(dc):
    """
    Pick the datastore that is accessible with the largest free space.
    """
    largest = None
    largestFree = 0
    for ds in dc.datastore:
        try:
            freeSpace = ds.summary.freeSpace
            if freeSpace > largestFree and ds.summary.accessible:
                largestFree = freeSpace
                largest = ds
        except:  # Ignore datastores that have issues
            pass
    if largest is None:
        raise Exception('Failed to find any free datastores on %s' % dc.name)
    return largest


def get_tarfile_size(tarfile):
    """
    Determine the size of a file inside the tarball.
    If the object has a size attribute, use that. Otherwise seek to the end
    and report that.
    """
    if hasattr(tarfile, 'size'):
        return tarfile.size
    size = tarfile.seek(0, 2)
    tarfile.seek(0, 0)
    return size

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

class OvfHandler(object):
    """
    OvfHandler handles most of the OVA operations.
    It processes the tarfile, matches disk keys to files and
    uploads the disks, while keeping the progress up to date for the lease.
    """
    def __init__(self, ovafile):
        """
        Performs necessary initialization, opening the OVA file,
        processing the files and reading the embedded ovf file.
        """
        self.handle = self._create_file_handle(ovafile)
        self.tarfile = tarfile.open(fileobj=self.handle)
        ovffilename = list(filter(lambda x: x.endswith(".ovf"),
                                  self.tarfile.getnames()))[0]
        ovffile = self.tarfile.extractfile(ovffilename)
        self.descriptor = ovffile.read().decode()

    def _create_file_handle(self, entry):
        """
        A simple mechanism to pick whether the file is local or not.
        This is not very robust.
        """
        if os.path.exists(entry):
            return FileHandle(entry)
        else:
            return WebHandle(entry)

    def get_descriptor(self):
        return self.descriptor

    def set_spec(self, spec):
        """
        The import spec is needed for later matching disks keys with
        file names.
        """
        self.spec = spec

    def get_disk(self, fileItem, lease):
        """
        Does translation for disk key to file name, returning a file handle.
        """
        ovffilename = list(filter(lambda x: x == fileItem.path,
                                  self.tarfile.getnames()))[0]
        return self.tarfile.extractfile(ovffilename)

    def get_device_url(self, fileItem, lease):
        for deviceUrl in lease.info.deviceUrl:
            if deviceUrl.importKey == fileItem.deviceId:
                return deviceUrl
        raise Exception("Failed to find deviceUrl for file %s" % fileItem.path)

    def upload_disks(self, lease, host):
        """
        Uploads all the disks, with a progress keep-alive.
        """
        self.lease = lease
        try:
            self.start_timer()
            for fileItem in self.spec.fileItem:
                self.upload_disk(fileItem, lease, host)
            lease.Complete()
            print("Finished deploy successfully.")
            return 0
        except vmodl.MethodFault as e:
            print("Hit an error in upload: %s" % e)
            lease.Abort(e)
        except Exception as e:
            print("Lease: %s" % lease.info)
            print("Hit an error in upload: %s" % e)
            lease.Abort(vmodl.fault.SystemError(reason=str(e)))
            raise
        return 1

    def upload_disk(self, fileItem, lease, host):
        """
        Upload an individual disk. Passes the file handle of the
        disk directly to the urlopen request.
        """
        ovffile = self.get_disk(fileItem, lease)
        if ovffile is None:
            return
        deviceUrl = self.get_device_url(fileItem, lease)
        url = deviceUrl.url.replace('*', host)
        headers = {'Content-length': get_tarfile_size(ovffile)}
        if hasattr(ssl, '_create_unverified_context'):
            sslContext = ssl._create_unverified_context()
        else:
            sslContext = None
        req = Request(url, ovffile, headers)
        urlopen(req, context=sslContext)

    def start_timer(self):
        """
        A simple way to keep updating progress while the disks are transferred.
        """
        Timer(5, self.timer).start()

    def timer(self):
        """
        Update the progress and reschedule the timer if not complete.
        """
        try:
            prog = self.handle.progress()
            self.lease.Progress(prog)
            if self.lease.state not in [vim.HttpNfcLease.State.done,
                                        vim.HttpNfcLease.State.error]:
                self.start_timer()
            sys.stderr.write("Progress: %d%%\r" % prog)
        except:  # Any exception means we should stop updating progress.
            pass


class FileHandle(object):
    def __init__(self, filename):
        self.filename = filename
        self.fh = open(filename, 'rb')

        self.st_size = os.stat(filename).st_size
        self.offset = 0

    def __del__(self):
        self.fh.close()

    def tell(self):
        return self.fh.tell()

    def seek(self, offset, whence=0):
        if whence == 0:
            self.offset = offset
        elif whence == 1:
            self.offset += offset
        elif whence == 2:
            self.offset = self.st_size - offset

        return self.fh.seek(offset, whence)

    def seekable(self):
        return True

    def read(self, amount):
        self.offset += amount
        result = self.fh.read(amount)
        return result

    # A slightly more accurate percentage
    def progress(self):
        return int(100.0 * self.offset / self.st_size)


class WebHandle(object):
    def __init__(self, url):
        self.url = url
        r = urlopen(url)
        if r.code != 200:
            raise FileNotFoundError(url)
        self.headers = self._headers_to_dict(r)
        if 'accept-ranges' not in self.headers:
            raise Exception("Site does not accept ranges")
        self.st_size = int(self.headers['content-length'])
        self.offset = 0

    def _headers_to_dict(self, r):
        result = {}
        if hasattr(r, 'getheaders'):
            for n, v in r.getheaders():
                result[n.lower()] = v.strip()
        else:
            for line in r.info().headers:
                if line.find(':') != -1:
                    n, v = line.split(': ', 1)
                    result[n.lower()] = v.strip()
        return result

    def tell(self):
        return self.offset

    def seek(self, offset, whence=0):
        if whence == 0:
            self.offset = offset
        elif whence == 1:
            self.offset += offset
        elif whence == 2:
            self.offset = self.st_size - offset
        return self.offset

    def seekable(self):
        return True

    def read(self, amount):
        start = self.offset
        end = self.offset + amount - 1
        req = Request(self.url,
                      headers={'Range': 'bytes=%d-%d' % (start, end)})
        r = urlopen(req)
        self.offset += amount
        result = r.read(amount)
        r.close()
        return result

    # A slightly more accurate percentage
    def progress(self):
        return int(100.0 * self.offset / self.st_size)


if __name__ == "__main__":
    exit(main())
