#!/usr/bin/env python3

# Standard Library Imports
import argparse
import json
import logging
import traceback
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from threading import Lock

# Third-party Imports
# (if there are any)

# Internal Imports
from .providers import *
from .helpers import ip_network_parents

# Constants
JSON_PATH = Path(__file__).parent.parent / "cloud_providers.json"
LOG = logging.getLogger("cloudcheck")

# Initialize logging (example)
logging.basicConfig(level=logging.INFO)


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


class ResultsProcessor:
    def __init__(self):
        self.results = {
            "cloud_hosts": [],
            "non_cloud_hosts": []
        }

    def process(self, ip, provider, provider_type, subnet):
        if provider:
            self.results["cloud_hosts"].append({
                "ip": ip,
                "provider": provider,
                "provider_type": provider_type,
                "subnet": str(subnet)
            })
        else:
            self.results["non_cloud_hosts"].append(ip)

    def save_to_file(self, output_path):
        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=4)

    def display(self):
        print(json.dumps(self.results, indent=4))


def read_file(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f]


def main():
    # Argument Parsing
    parser = argparse.ArgumentParser(description='Cloud IP checker.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help='File containing IPs to check.')
    group.add_argument('-H', '--host', help='Single host IP to check.')
    parser.add_argument('-o', '--output', help='Output file to save data.')
    args = parser.parse_args()

    # Initialize Results Processor
    results_processor = ResultsProcessor()

    # Process IPs
    ips = read_file(args.file) if args.file else [args.host]
    for ip in ips:
        provider, provider_type, subnet = check(ip)
        results_processor.process(ip, provider, provider_type, subnet)

    # Display and Save Results
    results_processor.display()
    if args.output:
        results_processor.save_to_file(args.output)


if __name__ == "__main__":
    main()