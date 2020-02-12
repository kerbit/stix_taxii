"""
MITRE FEED
 - TAXII 2.0
 - https://cti-taxii.mitre.org/taxii/
 - LATEST: 2019-10-23T14:26:33.079Z
""" 		

from stix2 import TAXIICollectionSource
from stix2.workbench import *
from taxii2client import Server, Collection
from collections import Counter
from stix2 import Filter

from stix2.v20.sdo import *
from stix2.v21.sdo import *

import pprint
import pymysql
import datetime
import json

def server_info(server):
	server_info = dict()
	server_info['title'] = server.title
	server_info['description'] = server.description
	server_info['url'] = server.url
	server_info['api_roots'] = [x.title for x in server.api_roots]
	server_info['contact'] = server.contact

	for _ in server_info:
		print("\t{}\t{}".format(_.ljust(30), server_info[_]))
	print()

	return server_info

def api_roots_info(api_roots):
	api_roots_info = dict()
	for api_root in api_roots:
		api_roots_info[api_root.title] = {
			'description': api_root.description,
			'max_content_length': api_root.max_content_length,
			'collections': [x.title for x in api_root.collections]
		}

	for _ in api_roots_info:
		print("\t{}".format(_.ljust(30)))
		for __ in api_roots_info[_]:
			print("\t\t{}\t{}".format(__.ljust(30), api_roots_info[_][__]))
		print()

	return api_roots_info

def collection_info(collection):
	collection_info = dict()
	collection_info['id'] = collection.id
	collection_info['title'] = collection.title
	collection_info['description'] = collection.description
	collection_info['can_write'] = collection.can_write
	collection_info['can_read'] = collection.can_read
	collection_info['media_types'] = collection.media_types

	for _ in collection_info:		
		print("\t\t{}\t{}".format(_.ljust(15), collection_info[_]))

	return collection_info

def check_stix_object_type():
	types = dict()
	a = c = c2 = i = i2 = i3 = m = o = r = t = t2 = v = None

	try:
		a = attack_patterns()
		types["attack_patterns"] = a
	except:
		pass

	try:	
		c = campaigns()
		types["campaigns"] = c
	except:
		pass

	try:
		c2 = courses_of_action()
		types["courses_of_action"] = c2
	except:
		pass

	try:

		i = identities()
		types["identities"] = i
	except:
		pass

	try:
		i2 = indicators()
		types["indicators"] = i2
	except:
		pass
		
	try:
		i3 = intrusion_sets()
		types["intrusion_sets"] = i3
	except:
		pass
		
	try:
		m = malware()
		types["malware"] = m
	except:
		pass
		
	try:
		o = observed_data()
		types["observed_data"] = o
	except:
		pass
		
	try:
		r = reports()
		types["reports"] = r
	except:
		pass
		
	try:
		t = threat_actors()
		types["threat_actors"] = t
	except:
		pass
		
	try:
		t2 = tools()
		types["tools"] = t2
	except:
		pass
		
	try:
		v = vulnerabilties()
		types["vulnerabilites"] = v
	except:
		pass

	return types

def make_mitre_taxii_client():
	s = Server("https://cti-taxii.mitre.org/taxii/")
	return s

def get_api_roots(client):
	api_roots = client.api_roots
	return api_roots

def get_collections(api_roots):
	for api_root in api_roots:
		collections = api_root.collections
		for c in collections:
			print("\tCOLLECTION:", c.title)
			c_info = collection_info(c)

			response = c.get_objects()
			with open("D:/stix2_data_mitre/" + c.title + '.json', "w") as f:
				json.dump(response, f)

def main():
	# MAKE CLIENT
	print("MAKE CLIENT")
	client = make_mitre_taxii_client()
	s_info = server_info(client)

	# GET API ROOTS
	print("\nGET API ROOTS")
	api_roots = get_api_roots(client)
	ar_info = api_roots_info(api_roots)

	# GET COLLECTIONS
	print ("\nGET COLLECTIONS")
	collections = get_collections(api_roots)

if __name__ == '__main__':
	main()
