import pickle

with open("D:/stix2_data/relations/guest.blutmagie_de_torExits_relation.txt", "rb") as f:
	relations = pickle.load(f)

result = []
for r in relations:
	result_keys = list(relations[r].keys())
	if result_keys not in result:
		result.append(result_keys)

print(result)


with open("D:/stix2_data/relations/guest.phishtank_com_relation.txt", "rb") as f:
	relations = pickle.load(f)

result = []
for r in relations:
	result_keys = list(relations[r].keys())
	if result_keys not in result:
		result.append(result_keys)

print(result)
