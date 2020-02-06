from pathlib import Path
import os
import time


def walk(collection_name, file_name):
	for p, d, f in os.walk(collection_name):
		for _ in f:
			if _ == file_name:
				return "/".join(os.path.join(p, _).replace("\\", "/").split("/")[-2:])

def get_idx(collection_name, file_name):
	if file_name:
		file_name_with_idx = []
		res = Path(collection_name).rglob(file_name)

		for r in res:
			file_name_with_idx.append(str(r).replace("\\", "/"))
		if file_name_with_idx:
			temp = file_name_with_idx[0].split("/")
			return temp[-2] + "/" + temp[-1]
		else:
			return "DUMMY_DIR"
	else:
		return "DUMMY_DIR"

def main():
	start = time.time()
	print(walk('D:/stix_data/collections/guest.phishtank_com', 'opensource_Observable-90783020-2c91-491f-baaf-1b98fef83190.xml'))
	print("walk():", time.time() - start)

	start = time.time()
	print(get_idx('D:/stix_data/collections/guest.phishtank_com', 'opensource_Observable-90783020-2c91-491f-baaf-1b98fef83190.xml'))
	print("walk():", time.time() - start)


if __name__ == '__main__':
	main()



