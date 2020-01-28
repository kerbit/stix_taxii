"""
HAILATAXII FEED
 - TAXII 1.0
 - http://hailataxii.com/taxii-discovery-service
 - poll data from HAILATAXII & save it to local stroage
"""

from cabby import create_client
from stix.core import STIXPackage

from pathlib import Path
import pprint
import io
import re

def create_haila_client():
    print("[+] Create client")
    client = create_client('hailataxii.com', use_https=False, discovery_path='/taxii-discovery-service')
    return client

def discover_services(client):
    print("[+] Discover Service")
    ss = client.discover_services()
    for s in ss:
        print("\t{}\t\t{}".format(s.address, s.type))
    print()
    return ss

def discover_collections(client):
    print ("[+] Discover Collection")
    collection_names = []

    collections = client.get_collections(uri='http://hailataxii.com/taxii-data')
    for collection in collections:
        collection_names.append(collection.name)
        print("\t", collection.name)
    print()

    collection_names = [
     # 'guest.dshield_BlockList',
     # 'guest.CyberCrime_Tracker',
     # 'guest.MalwareDomainList_Hostlist',
     # 'guest.EmergingThreats_rules',
     # 'guest.Abuse_ch',
     # 'guest.Lehigh_edu',
     # 'guest.phishtank_com',
     # 'guest.blutmagie_de_torExits',
     'guest.dataForLast_7daysOnly',
     ]

    return collection_names

def poll_collections(client, collection_names):
    print("[+] Polling collections")
    for collection_name in collection_names:
        print("\t", collection_name, end="\t")
        content_blocks = client.poll(collection_name=collection_name)

        i = 0
        directory = "DUMMY_STRING"
        for content_block in content_blocks:
            i += 1
            content = (content_block.content).decode('utf-8')
            # package = STIXPackage.from_xml(io.StringIO(content))
            # print(content)

            if i % 10000 == 1:
                print(i, end=" ")
                directory =  "D:/stix_data/collections" + collection_name + "/" + str(i // 10000).zfill(6)
                Path(directory).mkdir(parents=True, exist_ok=True)

            m = re.findall(r"<\w+:\w+ id=\"[^\"]+\"", content)
            if m:
                m2 = re.findall(r"(?<=\").*(?=\")", m[0])
                if m2:
                    object_id = m2[0].replace(":", "_")
                    with open(directory + "/" + object_id + ".xml", "w") as f:
                        f.write(content)
        print("(", i, ")")


def main():
    client = create_haila_client()
    services = discover_services(client)
    collection_names = discover_collections(client)
    poll_collections(client, collection_names)

if __name__ == '__main__':
    main()
