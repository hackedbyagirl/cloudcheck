import ipaddress

def ip_network_parents(ip, include_self=False):
    net = ipaddress.ip_network(ip, strict=False)
    for i in range(net.prefixlen - (0 if include_self else 1), -1, -1):
        parent_net = ipaddress.ip_network(f"{net.network_address}/{i}", strict=False)
        yield parent_net

