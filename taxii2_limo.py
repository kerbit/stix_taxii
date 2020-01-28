"""
LIMO FEED
 - TAXII 2.0
 - https://limo.anomali.com/api/v1/taxii2/taxii/
 - OLDEST: 2016-02-26 18:10:27.380000+00:00
""" 		

from stix2 import TAXIICollectionSource, Filter
from stix2.workbench import *
from taxii2client import Server, Collection
from collections import Counter

from stix2.v20.sdo import *
from stix2.v21.sdo import *

import pprint
import pymysql
import datetime

db = pymysql.connect(host='127.0.0.1', port=3306, user='root', password='yeonseok', db='stix2', charset='utf8')
cur = db.cursor()
db_format = {
 'attack_pattern': ['name', 
 					'description', 
 					'kill_chain_phases'],
 'campaign': ['name',
              'description',
              'aliases',
              'first_seen',
              'last_seen',
              'objective'],
 'common': ['id',
            'created_by_ref',
            'created',
            'modified',
            'labels',
            'external_references'],
 'course_of_action': ['name', 'description', 'action'],
 'identity': ['name',
              'description',
              'identity_class',
              'sectors',
              'contact_information'],
 'indicator': ['name',
               'description',
               'pattern',
               'valid_from',
               'valid_until',
               'kill_chain_phases'],
 'intrusion_set': ['name',
                   'description',
                   'aliases',
                   'first_seen',
                   'last_seen',
                   'goals',
                   'resource_level',
                   'primary_motivation',
                   'secondary_motivations'],
 'malware': ['name', 
 			'description', 
 			'kill_chain_phases'],
 'observed_data': ['first_observed',
                   'last_observed',
                   'number_observed',
                   'objects'],
 'report': ['name', 
 			'description', 
 			'published', 
 			'object_refs'],
 'threat_actor': ['name',
                  'description',
                  'aliases',
                  'roles',
                  'goals',
                  'sophistication',
                  'resource_level',
                  'primary_motivation',
                  'secondary_motivations',
                  'personal_motivations'],
 'tool': ['name', 
 		'description', 
 		'kill_chain_phases', 
 		'tool_version'],
 'vulnerability': ['name', 
 					'description'
 					]
 }

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

def make_limo_taxii_client():
	s = Server("https://limo.anomali.com/api/v1/taxii2/taxii/", user='guest', password='guest')
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

			tc_source = TAXIICollectionSource(c)
			add_data_source(tc_source)
			stix_objects = check_stix_object_type()
			print("\t\tDATA =>", list(stix_objects.keys()) , end='\n')

			# SRO
			_objects = c.get_objects()
			objects = _objects['objects']
			for o in objects:
				if o['type'] == 'relationship':
						sql = """
								INSERT IGNORE INTO sro_relationship(source_ref, target_ref, relationship_type)
						 		values (%s, %s, %s)
						 	  """
						cur.execute(sql, (o['source_ref'], o['target_ref'], o['relationship_type']))
						db.commit()


			# SDO
			for stix_object_type in stix_objects:
				print("\t\t\t", stix_object_type, len(stix_objects[stix_object_type]))
				for o in stix_objects[stix_object_type]:
					TYPE = str(type(o))
					cols = []
					table = "sdo_"
					if "AttackPattern" in TYPE:
						cols = db_format['attack_pattern']
						table += 'attack_pattern'

					elif "Campaign" in TYPE:
						cols = db_format['campaign']
						table += 'campaign'

					elif "CourseOfAction" in TYPE:
						cols = db_format['course_of_action']
						table += 'course_of_action'

					elif "Identity" in TYPE:
						cols = db_format['identity']
						table += 'identity'

					elif "Indicator" in TYPE:
						cols = db_format['indicator']
						table += 'indicator'

					elif "IntrusionSet" in TYPE:
						cols = db_format['intrusion_set']
						table += 'intrusion_set'

					elif "Malware" in TYPE:
						cols = db_format['malware']
						table += 'malware'

					elif "ObservedData" in TYPE:
						cols = db_format['observed_data']
						table += 'observed_data'

					elif "Report" in TYPE:
						cols = db_format['report']
						table += 'report'

					elif "ThreatActor" in TYPE:
						cols = db_format['threat_actor']
						table += 'threat_actor'

					elif "Tool" in TYPE:
						cols = db_format['tool']
						table += 'tool'

					elif "Vulnerability" in TYPE:
						cols = db_format['vulnerability']
						table += 'vulnerability'

					else:
						continue

					sql = "INSERT IGNORE INTO %s (%s) VALUES(%s)" % (
						table, 
						", ".join(cols + db_format['common']), 
						", ".join(["\"" + pymysql.escape_string(str(o.get(c, "None"))) + "\"" for c in cols + db_format['common']]))

					cur.execute(sql)
					db.commit()
					
def main():
	# MAKE CLIENT
	print("MAKE CLIENT")
	client = make_limo_taxii_client()
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
