from stix2elevator import *
from stix2elevator.options import *
import re
import datetime
from pathlib import Path
import sys

collection_dirs_1 = [
	('D:/stix2_data/CyberCrime_Tracker_stix1', 'guest.CyberCrime_Tracker'),
	('D:/stix2_data/MalwareDomainList_Hostlist_stix1', 'guest.MalwareDomainList_Hostlist'),
	('D:/stix2_data/EmergingThreats_rules_stix1', 'guest.EmergingThreats_rules'),
	('D:/stix2_data/Abuse_ch_stix1', 'guest.Abuse_ch'),
]

collection_dirs_2 = [
	('D:/stix2_data/Lehigh_edu_stix1', 'guest.Lehigh_edu'),
	# ('D:/stix2_data/blutmagie_de_torExits_stix1', 'guest.blutmagie_de_torExits'),
	# ('D:/stix2_data/phishtank_com_stix1', 'guest.phishtank_com')
]

def main_1():
	initialize_options()
	set_option_value('silent', True)
	set_option_value('validator_args', '-q')
	# set_option_value('disable', '213')

	for collection_dir, collection_name in collection_dirs_1:
		print("{} ({})".format(collection_name, datetime.datetime.now()))

		file_names = []
		for p, d, f in os.walk(collection_dir, topdown=True):
			for _ in f:
				file_name = os.path.join(p, _).replace("\\", "/")
				file_names.append(file_name)
				
		for idx, file_name in zip(range(len(file_names)), file_names):
			with open(file_name, 'r') as f:
				file_content = f.read()
			result = elevate_string(file_content)

			match = re.compile(r"(?<=\"id\": \").*(?=\")").findall(result)
			stix2_id = match[0]

			result_file_name = "D:/stix2_data/collections/" + collection_name + "/" + str(idx // 10000).zfill(4) + "/"
			if idx % 10000 == 0:
				print("{}, {}: {}".format(idx, file_name, datetime.datetime.now()))
				Path(result_file_name).mkdir(parents=True, exist_ok=True)
			with open(result_file_name + stix2_id, "w") as f:
				f.write(result)

def main_2(start):
	initialize_options()
	set_option_value('silent', True)
	set_option_value('validator_args', '-q')
	# set_option_value('disable', '213')

	for collection_dir, collection_name in collection_dirs_2:
		print("{} ({})".format(collection_name, datetime.datetime.now()))

		file_names = []
		for p, d, f in os.walk(collection_dir, topdown=True):
			for _ in f:
				file_name = os.path.join(p, _).replace("\\", "/")
				file_names.append(file_name)
				
		for idx, file_name in zip(range(len(file_names)), file_names):
			if idx < int(start):
				continue
			if idx >= int(start) + 10000:
				return
			# result = elevate_file(file_name)
			
			with open(file_name, 'r') as f:
				file_content = f.read()
			result = elevate_string(file_content)

			match = re.compile(r"(?<=\"id\": \").*(?=\")").findall(result)
			stix2_id = match[0]

			result_file_name = "D:/stix2_data/collections/" + collection_name + "/" + str(idx // 10000).zfill(4) + "/"
			if idx % 10000 == 0:
				print("{}, {}: {}".format(idx, file_name, datetime.datetime.now()))
				Path(result_file_name).mkdir(parents=True, exist_ok=True)
			with open(result_file_name + stix2_id, "w") as f:
				f.write(result)

if __name__ == '__main__':
	# main_1()
	main_2(sys.argv[1])