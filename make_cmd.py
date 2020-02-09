cmd = ""
for i in range(0, 12):
	cmd += "python taxii1_haila_real_elevate.py " + str(i * 10000)
	cmd += " & "

print(cmd)