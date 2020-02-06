from stix2elevator import elevate_file
from stix2elevator.options import *
import re
import datetime
from pathlib import Path

collection_dirs_2 = [
	('D:/stix2_data/blutmagie_de_torExits_stix1', 'guest.blutmagie_de_torExits'),
	('D:/stix2_data/phishtank_com_stix1', 'guest.phishtank_com')
]
def main():
	initialize_options()
	set_option_value('silent', True)
	set_option_value('validator_args', '-q')
	# set_option_value('disable', '213')

	for collection_dir, collection_name in collection_dirs_2:
		idx = 0
		for p, d, f in os.walk(collection_dir, topdown=True):
			for _ in f:
				if idx % 1000 == 0:
					print("{}, {}: {}".format(idx, _, datetime.datetime.now()))

				file_name = os.path.join(p, _).replace("\\", "/")
				result = elevate_file(file_name)

				match = re.compile(r"(?<=\"id\": \").*(?=\")").findall(result)
				stix2_id = match[0]
				result_file_name = "D:/stix2_data/collections/" + collection_name + "/" + str(idx // 30000).zfill(4) + "/"
				if idx % 30000 == 0:
					Path(result_file_name).mkdir(parents=True, exist_ok=True)
				with open(result_file_name + stix2_id, "w") as f:
					f.write(match[0])
				idx += 1

if __name__ == '__main__':
	main()