import os
import re
import pprint
import pickle
import datetime

from stix2elevator import elevate_file
from stix2elevator.options import initialize_options

import subprocess
import json

collection_dirs_1 = [
	'D:/stix_data/collections/guest.dshield_BlockList',
	'D:/stix_data/collections/guest.CyberCrime_Tracker',
	'D:/stix_data/collections/guest.MalwareDomainList_Hostlist',
	'D:/stix_data/collections/guest.EmergingThreats_rules',
	'D:/stix_data/collections/guest.Abuse_ch',
	'D:/stix_data/collections/guest.Lehigh_edu',
]

collection_dir_2 = [
	'D:/stix_data/collections/guest.blutmagie_de_torExits',
	'D:/stix_data/collections/guest.dataForLast_7daysOnly',
	'D:/stix_data/collections/guest.phishtank_com',
]

def search(dir_name):
    file_names = os.listdir(dir_name)
    return list(map(lambda x: os.path.join(dir_name, x).replace("\\", "/"), file_names))

def find_file_name(full_file_name):
	file_name = full_file_name.split("/")[-1]
	return file_name

def find_object_type(full_file_name):
	file_name = full_file_name.split("/")[-1]
	object_type = file_name.split("-")[0]
	return object_type

def get_id_idref_relations(full_file_names):
	id_idref_relations = dict()
	for full_file_name in full_file_names:
		with open(full_file_name, "r") as f:
			content = f.read()
			m = re.findall(r"<\w+:\w+ idref=\"[^\"]+\"", content)
			if m:
				id_type = find_object_type(full_file_name)
				# print("\t", id_type)
				id_file_name = find_file_name(full_file_name)

				id_refs = []
				for _m in m:
					m2 = re.findall(r"(?<=\").*(?=\")", _m)
					if m2:
						object_id = m2[0].replace(":", "_")
						idref_type = find_object_type(object_id)
						# print("\t\t", idref_type)
						idref_file_name = object_id + ".xml"
						id_refs.append(idref_file_name)
				id_idref_relations[id_file_name] = id_refs
	# pprint.pprint(id_idref_relations)
	return id_idref_relations

def get_final_relations(id_idref_relations):
	relations = dict()
	for id in id_idref_relations:
		if "indicator" in id:
			indicated_ids = dict()
			# print("Indicator_ID:", id)

			# INDICATOR'S RELATION
			for id_ref in id_idref_relations[id]:
				if "Observable" in id_ref:
					child_observables = id_idref_relations.get(id_ref, [])

					# COMPOSITE OBSERVABLES
					if child_observables:
						indicated_ids['observable_ref'] = id_ref
						# print("\tObservables_ID:", id_ref)
						indicated_ids['observables'] = child_observables
						# for child_observable in child_observables:
							# print("\t\tObservable_ID:", child_observable)
						
					# NOT COMPOSITE OBSERVABLES
					else:
						indicated_ids['observable_ref'] = ""
						indicated_ids['observables'] = [id_ref]

				elif "ttp" in id_ref:
					indicated_ids['ttp'] = id_ref
					# print("\tttp_ID:", id_ref)
					# 
			relations[id] = indicated_ids
	return relations

def preprocess(full_file_names):
	# GET ID_IDREF_RELATIONS
	id_idref_relations = get_id_idref_relations(full_file_names)
	
	# GET FINAL RELATIONS
	final_relations = get_final_relations(id_idref_relations)

	return final_relations

def do_files_exist(files):
	for file in files:
		# IF FILE = "", PASS
		if file and not os.path.exists(file):
			return False
	return True

def get_indicator_content(indicator_file):
	with open(indicator_file, "r") as f:
		content = f.read()
		m = re.compile(r"<stix:STIX_Package.*(?=>)").findall(content)
		package_head = m[0]

		m2 = re.compile(r"<stix:STIX_Header>.*(?=</stix:STIX_Package>)", re.DOTALL).findall(content)
		package_body = m2[0]

		return package_head, package_body

def get_observable_ref_fraction(observable_ref_file):
	# IF COMPOSITE OBSERVABLE,
	if observable_ref_file:
		with open(observable_ref_file, "r") as f1:
			content1 = f1.read()
			m = re.compile(r"<stix:Observables.*</stix:Observables>", re.DOTALL).findall(content1)
			observable_ref_fraction = m[0]
			# print(m[0])
		return observable_ref_fraction
	else:
		return ""

def get_ttp_fraction(ttp_file):
	with open(ttp_file, "r") as f2:
		content2 = f2.read()
		m = re.compile(r"<stix:TTPs.*</stix:TTPs>", re.DOTALL).findall(content2)
		ttp_fraction =  m[0]

		m2 = re.compile(r"xmlns:ttp=\"[^\"]+\"").findall(content2)
		ttp_ns = m2[0]

		# print(m2[0])
		# print(m[0])
	return ttp_ns, ttp_fraction

def get_observable_fraction(observable_file, is_first):
	with open(observable_file, "r") as f3:
		content3 = f3.read()

		_ = re.compile(r"(?<=cybox:Properties xsi:type=\").*(?=:)").findall(content3)
		cybox_type = _[0]

		m2 = re.compile(r"xmlns:" + cybox_type + "=\"[^\"]+\"").findall(content3)
		observable_ns = m2[0]
		
		if "category=\"asn\"" in content3:
			return observable_ns, ""

		m = None
		# FOR FIRST OBSERVAble
		if is_first:
			m = re.compile(r"<stix:Observables.*(?=</stix:Observables>)", re.DOTALL).findall(content3)
		# n th OBSERVABLES (n > 1)
		else:
			m = re.compile(r"<cybox:Observable.*</cybox:Observable>", re.DOTALL).findall(content3)
		observable_fraction = m[0]

		# print(m2[0])
		# print(m[0])
		# print()

	return observable_ns, observable_fraction

def dir_1_main(is_preprocessed):
	for collection_dir, idx in zip(collection_dirs_1, range(len(collection_dirs_1))):
		full_file_names = search(collection_dir)
		print("#{}: ".format(idx + 1) + collection_dir)
		print("[MAKE_RELATIONS] file #: {}".format(len(full_file_names)))

		preprocessed_relations = None
		if not is_preprocessed:
			preprocessed_relations = preprocess(full_file_names)
			with open("D:/stix_data/relations/" + collection_dir.split("/")[-1] + "_relation.txt", "wb") as f:
				pickle.dump(preprocessed_relations, f)
		else:
			with open("D:/stix_data/relations/" + collection_dir.split("/")[-1] + "_relation.txt", "rb") as f:
				preprocessed_relations = pickle.load(f)

		print("[READ_RELATIONS] relation #: {}".format(len(preprocessed_relations)))
		temp_prg = -1
		for indicator, idx in zip(preprocessed_relations, range(len(preprocessed_relations))):
			# PROGRESS STATUS
			prg = 100 * (idx + 1) // len(preprocessed_relations)
			if prg != temp_prg and prg % 5 == 0:
				print("{}% DONE ({})".format(prg, datetime.datetime.now()))
				temp_prg = prg

			# FIND FILES
			relation = preprocessed_relations[indicator]

			indicator_id = indicator
			observable_ref = relation['observable_ref']
			observables = relation['observables']
			ttp_id = relation['ttp']

			indicator_file = collection_dir + "/" + indicator_id
			
			if observable_ref: # COMPOSTIE OBSERVABLES
				observable_ref_file = collection_dir + "/" + observable_ref
			else: # NO COMPOSITE OBSERVABLES
				observable_ref_file = ""

			observable_files = [collection_dir + "/" + x for x in observables]
			ttp_file = collection_dir + "/" + ttp_id
			
			needed_files = [observable_ref_file, ttp_file] + observable_files
			if do_files_exist(needed_files):
				ns_fractions = []

				ttp_fraction = ""
				observable_ref_fraction = ""
				observable_fraction =""

				# TTP_FRACTION
				ttp_ns, ttp_fraction = get_ttp_fraction(ttp_file)
				# ns_fractions.append(ttp_ns)

				# OBSERVABLE_COMPOSITION_FRACTION
				observable_ref_fraction = get_observable_ref_fraction(observable_ref_file)
				
				# OBSERVABLE_FRACTIONS
				for observable_file in observable_files:
					observable_ns, observable_temp_fraction = get_observable_fraction(observable_file, is_first=False if observable_fraction else True)					
					ns_fractions.append(observable_ns)
					observable_fraction += observable_temp_fraction + "\n"
				observable_fraction += "\n\t</stix:Observables>"

				fractions = "\n" + ttp_fraction + "\n" + observable_ref_fraction + "\n" + observable_fraction
				fractions += "\n" + "</stix:STIX_Package>"
				ns_fractions = " " + " ".join(list(set(ns_fractions))) + ">\n"

				# MAKE FINAL
				package_head, package_body = get_indicator_content(indicator_file)
				new_package_head = package_head + ns_fractions
				new_package_body = package_body + fractions
				new_package = new_package_head + new_package_body
				# print(new_package)

				temp_file_name = "D:/stix2_data/" + collection_dir.split("/")[-1] + ".xml"
				with open(temp_file_name, "w") as f:
					f.write(new_package)

				proc = subprocess.Popen(["stix2_elevator", "-d DISABLE", "-s", temp_file_name], stdout=subprocess.PIPE, shell=True)
				out, err = proc.communicate()

				match = re.compile(r"{.*", re.DOTALL).findall(out.decode("UTF-8"))
				if match:
					stix2_data = json.loads(match[0])
					stix2_id = stix2_data['id']
					
					result_file_name = "D:/stix2_data/collections/" + collection_dir.split("/")[-1] + "/" + stix2_id
					with open(result_file_name, "w") as f:
						f.write(match[0])
				else:
					print("\t[WARNING] {} is passed. Conversion failed".format(indicator_id))
					break
			else:
				print("\t[WARNING] {} is passed. Something is missing".format(indicator_id))
		print()

def dir_2_main():
	pass
	"""
	for collection_dir, idx in zip(collection_dirs_1, range(len(collection_dirs_1))):
		file_names = search(collection_dir)
		print("#{}: ".format(idx) + collection_dir + " ({})".format(len(file_names)))
		
		for file_name in file_names:
			with open(file_name, "r") as f:
				content = f.read()
				m = re.findall(r"<\w+:\w+ idref=\"[^\"]+\"", content)
				if m:
					id_type = find_object_type(file_name)
					# print("\t", id_type)

					id_refs = []
					for _m in m:
						m2 = re.findall(r"(?<=\").*(?=\")", _m)
						if m2:
							object_id = m2[0].replace(":", "_")
							idref_type = find_object_type(object_id)
							id_refs.append(idref_type)
							# print("\t\t", idref_type)
					id_idref_pattern.add((id_type, tuple(id_refs)))
		
		for p in id_idref_pattern:
			if p[0] != 'opensource_Observable':
				print(p)
				print()
		print()

	"""

def main():
	print("-"*20 + "dir_1 main START" + "-"*20)
	dir_1_main(is_preprocessed=True)
	print("-"*21 + "dir_1 main END" + "-"*21)
	print()

	print("-"*20 + "dir_2 main START" + "-"*20)
	dir_2_main()
	print("-"*21 + "dir_2 main END" + "-"*21)
	print()

if __name__ == '__main__':
	main()

