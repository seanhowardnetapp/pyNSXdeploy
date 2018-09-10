import sys
import ipaddress
import re

# regex to validate ip mask
ip_mask_re = re.compile("/\d{1,2}")


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


# not sure how to validate this
def domain_name_valid(domain_name):
    """
    validate a domain name
    :param domain_name:
    :return:
    """
    return len(domain_name) > 0


def create_vtep_ip_pool(ip_pool_list, ip_pool_mask, ip_pool_gateway, number_of_hosts, ip_pool_dns, ip_pool_suffix):

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

    # validate suffix (need more info here)
    if domain_name_valid(ip_pool_suffix):
        vtep_suffix = ip_pool_suffix
    else:
        return -1, "Invalid ip_pool_suffix {0}".format(ip_pool_suffix)

    # validate ip addresses
    # print("prefix  : ", vtep_mask)
    # print("gateway : ", vtep_gateway)
    # print("dns suf : ", vtep_suffix)

    # print("dns srv : ", vtep_dns_list)
    # print("ip rng  : ", vtep_range)

    # format xml string header
    xml_string = """
<ipamAddressPool>
  <name>VTEP-Pool</name>
  <prefixLength>{0}</prefixLength>
  <gateway>{1}</gateway>
  <dnsSuffix>{2}</dnsSuffix>
""".format(vtep_mask, vtep_gateway, vtep_suffix)

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
    xml_string += "<ipamAddressPool>"

    return 0, xml_string


def main(argv):
    status, xml_string = create_vtep_ip_pool("192.168.0.1-192.168.0.10,192.168.1.1-192.168.1.5",
                                             "/24",
                                             "192.168.0.254",
                                             7,
                                             "1.1.1.1,8.8.8.9",
                                             "google.com"
                                             )

    # status == 0 is success, status == -1 means validation failed
    if status == 0:
        # xml_string is valid
        print(xml_string)
    else:
        # xml_string contains error message
        print("ERROR : {0}".format( xml_string))


if __name__ == "__main__":
    main(sys.argv);