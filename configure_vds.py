#!/usr/bin/env python3


"""
Orignal configure_nsx_manager.py script written by Sean Howard
hows@netapp.com
https://github.com/seanhowardnetapp/pyNSXdeploy/


Arguments
---------
-s [vcenter FQDN or IP]
-u [vcenter administrator username]
-p [vcenter administrator password]
-S [tells it to ignore SSL errors, you probably want this]


"""

import atexit
import argparse

from pyVim.connect import SmartConnectNoSSL, Disconnect
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

    if args.datacenter:
        dc = get_dc(si, args.datacenter)
    else:
        dc = si.content.rootFolder.childEntity[0]

    print("Datacenter: " + dc)
    print("DVS(es): ")

    content = si.RetrieveContent()
    for host in self._get_vim_objects(content, vim.dvs.VmwareDistributedVirtualSwitch):
        for vswitch in host.config.network.vswitch:
            print(vswitch.name)


def _get_vim_objects(content, vim_type):
    """Get vim objects of a given type."""
    return [item for item in content.viewManager.CreateContainerView(
        content.rootFolder, [vim_type], recursive=True
    ).view]


if __name__ == "__main__":
    exit(main())
