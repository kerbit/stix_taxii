import os
import re
import pprint
import pickle
import json
import datetime

from stix2elevator import elevate_file
from stix2elevator.options import initialize_options

import subprocess
import json
from pathlib import Path

collection_dirs_1 = [
	'D:/stix_data/collections/guest.dshield_BlockList',
	'D:/stix_data/collections/guest.CyberCrime_Tracker',
	'D:/stix_data/collections/guest.MalwareDomainList_Hostlist',
	'D:/stix_data/collections/guest.EmergingThreats_rules',
	'D:/stix_data/collections/guest.Abuse_ch',
	'D:/stix_data/collections/guest.Lehigh_edu',
]

collection_dirs_2 = [
	'D:/stix_data/collections/guest.phishtank_com',
	'D:/stix_data/collections/guest.blutmagie_de_torExits',
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

# get_id_idref_relations_1() + sub-directory traverse
def get_id_idref_relations_2(full_file_names):
	id_idref_relations = dict()
	for sub_file_name in full_file_names:
		print("\t\t", sub_file_name, "len:", len(id_idref_relations))
		for full_file_name in search(sub_file_name):
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
					# id_idref_relations[sub_file_name.split('/')[-1] + '/' + id_file_name] = id_refs
					# print(sub_file_name.split('/')[-1] + '/' + id_file_name)
					
					# i: INDEX FOR SUBFILE, o: OBJECTS THAT RELATES TO id_file_name FILE
					i = sub_file_name.split('/')[-1]
					id_idref_relations[id_file_name] = {"i": i, "o": id_refs} 
	return id_idref_relations

def get_final_relations(id_idref_relations):
	relations_total_len = len(id_idref_relations)
	relations = dict()

	for id, cnt in zip(id_idref_relations, range(relations_total_len)):
		if "indicator" in id:
			indicated_ids = dict()
			indicated_ids['observable'] = []
			indicated_ids['ttp'] = []

			# INDICATOR'S RELATION
			for id_ref in id_idref_relations[id]:
				if "Observable" in id_ref:
					child_observables = id_idref_relations.get(id_ref, [])

					# COMPOSITE OBSERVABLES
					if child_observables:
						indicated_ids['observable'].append({
							"o_ref": id_ref,
							"o": [x for x in child_observables]
						})
						
					# NOT COMPOSITE OBSERVABLES
					else:
						indicated_ids['observable'].append({
							"o_ref": "",
							"o": [id_ref]
							})

				elif "ttp" in id_ref:
					indicated_ids['ttp'].append(id_ref)

			relations[id] = indicated_ids
	return relations

def get_final_relations_2(collection_dir, id_idref_relations):
	relations_total_len = len(id_idref_relations)
	FILE_TREE = dict()
	relations = dict()

	print("\t\tMAKE FILE TREE START")
	for p, d, f in os.walk(collection_dir):
		for _ in f:
			FILE_TREE[_] = os.path.join(p, _).replace("\\", "/").split("/")[-2]
	print("\t\tMAKE FILE TREE END")

	for id, cnt in zip(id_idref_relations, range(relations_total_len)):
		if cnt % 100000 == 0:
			print("\t\t", cnt, relations_total_len, datetime.datetime.now())
		if "indicator" in id:
			indicated_ids = dict()
			indicated_ids['observable'] = []
			indicated_ids['ttp'] = []

			# INDICATOR'S RELATION
			for id_ref in id_idref_relations[id]['o']:
				if "Observable" in id_ref:
					
					child_observables = id_idref_relations.get(id_ref, [])

					# COMPOSITE OBSERVABLES
					if child_observables:
						child_idx = id_idref_relations[id_ref]['i']
						indicated_ids['observable'].append({
							"o_ref": child_idx + "/" + id_ref,
							"o": [get_idx(FILE_TREE, x) for x in child_observables['o']]
						})
						
					# NOT COMPOSITE OBSERVABLES
					else:
						indicated_ids['observable'].append({
							"o_ref": "",
							"o": [get_idx(FILE_TREE, id_ref)]
							})

				elif "ttp" in id_ref:
					indicated_ids['ttp'].append(get_idx(FILE_TREE, id_ref))
					# print("\tttp_ID:", id_ref)
			
			indicator_idx = id_idref_relations[id]['i']
			relations[indicator_idx + "/" + id] = indicated_ids
	return relations

def preprocess(full_file_names):
	# GET ID_IDREF_RELATIONS
	id_idref_relations = get_id_idref_relations(full_file_names)
	
	# GET FINAL RELATIONS
	final_relations = get_final_relations(id_idref_relations)

	return final_relations

def preprocess_2(collection_dir, full_file_names):
	# GET ID_IDREF_RELATIONS
	# id_idref_relations = get_id_idref_relations_2(full_file_names)
	print("\tGET ID-IDREF RELATION DONE")

	collection_name = collection_dir.split("/")[-1]
	# with open("D:/stix2_data/relations/" + collection_name + "_temp.txt", "w") as f:
		# json.dump(id_idref_relations, f)

	with open("D:/stix2_data/relations/" + collection_name + "_temp.txt", "r") as f:
		id_idref_relations = json.load(f)

	# GET FINAL RELATIONS
	final_relations = get_final_relations_2(collection_dir, id_idref_relations)
	print("\tGET FINAL RELATION DONE")

	return final_relations

def do_files_exist(files):
	for file in files:
		# IF FILE = "", PASS
		if file and "DUMMY_DIR" not in file:
			if not os.path.exists(file):
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
	try:
		# IF COMPOSITE OBSERVABLE,
		if observable_ref_file:
			with open(observable_ref_file, "r") as f1:
				content1 = f1.read()
				m = re.compile(r"<cybox:Observable_Composition.*</cybox:Observable_Composition>", re.DOTALL).findall(content1)
				observable_ref_fraction = m[0]
				# print(m[0])
			return observable_ref_fraction
		else:
			return ""
	except Exception as e:
		raise e

def get_ttp_fraction(ttp_file):
	try:
		with open(ttp_file, "r") as f2:
			content2 = f2.read()
			m = re.compile(r"(?<=<stix:TTPs).*(?=</stix:TTPs>)", re.DOTALL).findall(content2)
			ttp_fraction =  m[0]

			m2 = re.compile(r"xmlns:ttp=\"[^\"]+\"").findall(content2)
			ttp_ns = m2[0]
			# print(m2[0])
			# print(m[0])
		return ttp_ns, ttp_fraction
	except Exception as e:
		raise e

def get_observable_fraction(observable_file, is_first):
	try:
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
	except Exception as e:
		raise e

def get_idx(FILE_TREE, file_name):
	idx = FILE_TREE.get(file_name, "FILE_NOT_FOUND")
	return idx + "/" + file_name

def set_observable_ref_content(package_body, observable_ref_fractions):
	p_body = package_body
	match = re.compile(r"<indicator:Observable idref=.*>").findall(p_body)
	for m in match:
		for observable_ref_fraction in observable_ref_fractions:
			if observable_ref_fraction[0] in m.replace(":", "_"):
				p_body = p_body.replace(m, m.replace("idref", "id") + "\n" + observable_ref_fraction[1])
	return p_body

def dir_1_main(is_preprocessed):
	for collection_dir, collection_idx in zip(collection_dirs_1, range(len(collection_dirs_1))):
		print("#{}: ".format(collection_idx + 1) + collection_dir)
		full_file_names = search(collection_dir)
		print("[MAKE_RELATIONS] file #: approximately {}".format(len(full_file_names)))

		preprocessed_relations = None
		if not is_preprocessed:
			preprocessed_relations = preprocess(full_file_names)
			with open("D:/stix2_data/relations/" + collection_dir.split("/")[-1] + "_relation.txt", "w") as f:
				json.dump(preprocessed_relations, f)
		else:
			with open("D:/stix2_data/relations/" + collection_dir.split("/")[-1] + "_relation.txt", "r") as f:
				preprocessed_relations = json.load(f)
		print("[READ_RELATIONS] relation #: {}".format(len(preprocessed_relations)))

		temp_dir_name = collection_dir.split("/")[-1].split(".")[-1] + "_stix1"
		temp_prg = -1
		for indicator, idx in zip(preprocessed_relations, range(len(preprocessed_relations))):
			# PROGRESS STATUS
			prg = 100 * (idx + 1) // len(preprocessed_relations)
			if prg != temp_prg and prg % 5 == 0:
				print("{}% DONE ({}/{}) ({})".format(prg, idx, len(preprocessed_relations), datetime.datetime.now()))
				temp_prg = prg

			# FIND FILES
			relation = preprocessed_relations[indicator]

			indicator_id = indicator
			ttp_ids = relation['ttp']
			observable_ids = relation['observable']

			indicator_file = collection_dir + "/" + indicator_id
			ttp_files = [collection_dir + "/" + x for x in ttp_ids]

			observable_ref_files = []
			observable_files = []
			for observable_id in observable_ids:
				if observable_id.get('o_ref', False):
					observable_ref_files.append(collection_dir + "/" + observable_id['o_ref'])
				for o in observable_id.get('o', []):
					observable_files.append(collection_dir + "/" + o)
			
			ns_fractions = []
			ttp_fractions = ""
			observable_fractions =""
			observable_ref_fractions = []

			try:
				# TTP_FRACTION
				ttp_fractions += "\n\t<stix:TTPs>"
				for ttp_file in ttp_files:
					ttp_ns, ttp_fraction = get_ttp_fraction(ttp_file)
					ttp_fractions += ttp_fraction + "\n"
				ttp_fractions += "\n\t</stix:TTPs>"

				# OBSERVABLE_FRACTIONS
				for observable_file in observable_files:
					observable_ns, observable_fraction = get_observable_fraction(observable_file, is_first=False if observable_fractions else True)					
					ns_fractions.append(observable_ns)
					observable_fractions += "\t" + observable_fraction
				observable_fractions += "\t</stix:Observables>"

				# OBSERVABLE_COMPOSITION_FRACTION
				for observable_ref_file in observable_ref_files:
					observable_ref_file_name = observable_ref_file.split("/")[-1][:-4]
					observable_ref_fractions.append((observable_ref_file_name, get_observable_ref_fraction(observable_ref_file)))
			except Exception as e:
				print(e)
				continue

			fractions = "\n" + ttp_fractions + "\n" + observable_fractions
			fractions += "\n" + "</stix:STIX_Package>"
			ns_fractions = " " + " ".join(list(set(ns_fractions))) + ">\n"

			# MAKE FINAL
			package_head, package_body = get_indicator_content(indicator_file)

			if observable_ref_fractions:
				package_body = set_observable_ref_content(package_body, observable_ref_fractions)
			new_package_head = package_head + ns_fractions
			new_package_body = package_body + fractions
			new_package = new_package_head + new_package_body

			# MAKE DIRECTORY
			temp_dir =  "D:/stix2_data/" + temp_dir_name + "/"
			new_temp_dir = temp_dir + str(idx // 10000).zfill(4)
			if idx % 10000 == 0:
				Path(new_temp_dir).mkdir(parents=True, exist_ok=True)
			temp_file = new_temp_dir + "/" + str(idx) + ".xml"
			with open(temp_file, "w") as f:
				f.write(new_package)
		print()

def dir_2_main(is_preprocessed):
	for collection_dir, collection_idx in zip(collection_dirs_2, range(len(collection_dirs_2))):
		print("#{}: ".format(collection_idx + 1) + collection_dir)
		full_file_names = search(collection_dir)
		print("[MAKE_RELATIONS] file #: approximately {}".format(len(full_file_names) * 10000))

		preprocessed_relations = None
		if not is_preprocessed:
			preprocessed_relations = preprocess_2(collection_dir, full_file_names)
			with open("D:/stix2_data/relations/" + collection_dir.split("/")[-1] + "_relation.txt", "w") as f:
				json.dump(preprocessed_relations, f)
		else:
			with open("D:/stix2_data/relations/" + collection_dir.split("/")[-1] + "_relation.txt", "r") as f:
				preprocessed_relations = json.load(f)
		print("[READ_RELATIONS] relation #: {}".format(len(preprocessed_relations)))

		# FOR Splitting the directory per 30,000 files
		temp_dir_name = collection_dir.split("/")[-1].split(".")[-1] + "_stix1"
		temp_prg = -1
		for indicator, idx in zip(preprocessed_relations, range(len(preprocessed_relations))):
			# PROGRESS STATUS
			prg = 100 * (idx + 1) // len(preprocessed_relations)
			if prg != temp_prg and prg % 5 == 0:
				print("{}% DONE ({}/{}) ({})".format(prg, idx, len(preprocessed_relations), datetime.datetime.now()))
				temp_prg = prg			

			# FIND FILES
			relation = preprocessed_relations[indicator]
			
			indicator_id_with_idx = indicator
			ttp_ids_with_idx = relation['ttp']
			observable_ids_with_idx = relation['observable']

			indicator_file = collection_dir + "/" + indicator_id_with_idx
			ttp_files = [collection_dir + "/" + x for x in ttp_ids_with_idx]

			observable_ref_files = []
			observable_files = []
			for observable_id_with_idx in observable_ids_with_idx:
				if observable_id_with_idx.get('o_ref', False):
					observable_ref_files.append(collection_dir + "/" + observable_id_with_idx['o_ref'])
				for o in observable_id_with_idx.get('o', []):
					observable_files.append(collection_dir + "/" + o)
			
			ns_fractions = []
			ttp_fractions = ""
			observable_fractions =""
			observable_ref_fractions = []

			try:
				# TTP_FRACTION
				ttp_fractions += "\n\t<stix:TTPs>"
				for ttp_file in ttp_files:
					ttp_ns, ttp_fraction = get_ttp_fraction(ttp_file)
					ttp_fractions += ttp_fraction + "\n"
				ttp_fractions += "\n\t</stix:TTPs>"

				# OBSERVABLE_FRACTIONS
				for observable_file in observable_files:
					observable_ns, observable_fraction = get_observable_fraction(observable_file, is_first=False if observable_fractions else True)					
					ns_fractions.append(observable_ns)
					observable_fractions += "\t" + observable_fraction
				observable_fractions += "\t</stix:Observables>"

				# OBSERVABLE_COMPOSITION_FRACTION
				for observable_ref_file in observable_ref_files:
					observable_ref_file_name = observable_ref_file.split("/")[-1][:-4]
					observable_ref_fractions.append((observable_ref_file_name, get_observable_ref_fraction(observable_ref_file)))
			except Exception as e:
				print(e)
				continue

			fractions = "\n" + ttp_fractions + "\n" + observable_fractions
			fractions += "\n" + "</stix:STIX_Package>"
			ns_fractions = " " + " ".join(list(set(ns_fractions))) + ">\n"

			# MAKE FINAL
			package_head, package_body = get_indicator_content(indicator_file)

			if observable_ref_fractions:
				package_body = set_observable_ref_content(package_body, observable_ref_fractions)
			new_package_head = package_head + ns_fractions
			new_package_body = package_body + fractions
			new_package = new_package_head + new_package_body
			# print(new_package)

			# MAKE DIRECTORY
			temp_dir =  "D:/stix2_data/" + temp_dir_name + "/"
			new_temp_dir = temp_dir + str(idx // 10000).zfill(4)
			if idx % 10000 == 0:
				Path(new_temp_dir).mkdir(parents=True, exist_ok=True)
			temp_file = new_temp_dir + "/" + str(idx) + ".xml"
			with open(temp_file, "w") as f:
				f.write(new_package)
		print()

def main():
	print("-"*20 + "dir_1 main START" + "-"*20)
	dir_1_main(is_preprocessed=False)
	print("-"*21 + "dir_1 main END" + "-"*21)
	print()

	print("-"*20 + "dir_2 main START" + "-"*20)
	# dir_2_main(is_preprocessed=False)
	print("-"*21 + "dir_2 main END" + "-"*21)
	print()

if __name__ == '__main__':
	main()

