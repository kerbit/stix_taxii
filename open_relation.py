import json
import pprint

with open("D:/stix2_data/relations/guest.blutmagie_de_torExits_temp.txt", "r") as f:
	relation = json.load(f)

for r in relation:
	print(r)
	print("\t", relation[r])