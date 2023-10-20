#!/usr/bin/env python3

import argparse
import sys
import json
import traceback
from threading import Lock
from datetime import datetime
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .providers import *
from .helpers import ip_network_parents

import logging

log = logging.getLogger("cloudcheck")


json_path = Path(__file__).parent.parent / "cloud_providers.json"


class CloudProviders:
    def __init__(self, *args, **kwargs):
        self.providers = dict()
        try:
            with open(json_path) as f:
                self.json = json.load(f)
        except Exception:
            self.json = {}
        provider_classes = CloudProvider.__subclasses__()
        self.now = datetime.now().isoformat()
        with ThreadPoolExecutor(max_workers=len(provider_classes)) as e:
            for p in provider_classes:
                e.submit(self._get_provider, p, *args, **kwargs)
        self.providers = OrderedDict(sorted(self.providers.items()))

    def _get_provider(self, p, *args, **kwargs):
        try:
            provider = p(*args, **kwargs)
            self.providers[provider.name] = provider
            if not provider.name in self.json:
                self.json[provider.name] = {}
            json_ranges = self.json[provider.name].get("cidrs", [])
            if provider.ranges.cidrs:
                self.json[provider.name]["last_updated"] = self.now
                self.json[provider.name]["provider_type"] = provider.provider_type
                self.json[provider.name]["cidrs"] = sorted(
                    str(r) for r in provider.ranges
                )
            else:
                provider.ranges = CidrRanges(json_ranges)
        except Exception as e:
            log.warning(
                f"Error getting provider {p.name}: {e}: {traceback.format_exc()}"
            )

    def check(self, ip):
        for net in ip_network_parents(ip):
            for provider in self.providers.values():
                if net in provider:
                    return provider.name, provider.provider_type, net
        return (None, None, None)

    def __iter__(self):
        yield from self.providers.values()


cloudprovider_lock = Lock()
providers = None


def check(ip):
    global providers
    with cloudprovider_lock:
        if providers is None:
            providers = CloudProviders()
    return providers.check(ip)


def refresh_json():
    global providers
    if providers is None:
        providers = CloudProviders()
    with open(json_path, "w") as f:
        json.dump(providers.json, f, sort_keys=True, indent=4)


def read_file(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f]


def main():
    parser = argparse.ArgumentParser(description='Cloud IP checker.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help='File containing IPs to check.')
    group.add_argument('-H', '--host', help='Single host IP to check.')
    parser.add_argument('-o', '--output', help='Output file to save data.')
    args = parser.parse_args()

    if args.file:
        ips = read_file(args.file)
    else:
        ips = [args.host]

    results = {
        "cloud_hosts": [],
        "non_cloud_hosts": []
    }

    for ip in ips:
        provider, provider_type, subnet = check(ip)
        if provider:
            results["cloud_hosts"].append({
                "ip": ip,
                "provider": provider,
                "provider_type": provider_type,
                "subnet": str(subnet)  # convert to string
            })
        else:
            results["non_cloud_hosts"].append(ip)

    print(json.dumps(results, indent=4))

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=4)

    for host in results["cloud_hosts"]:
        print(f"{host['ip']} belongs to {host['provider']} ({host['provider_type']}) ({host['subnet']})")

if __name__ == "__main__":
    main()