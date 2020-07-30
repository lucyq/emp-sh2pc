import os,codecs

num_rows = 100
FILE_NAME = "phase1_test_tokens.txt"
with open(FILE_NAME, "w") as f:
	for _ in range(num_rows):
		myhex = codecs.encode(os.urandom(96), 'hex').decode()
		f.write(myhex + "\n")
