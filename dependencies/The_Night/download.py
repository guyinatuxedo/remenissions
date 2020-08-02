import os
import requests
import zstandard


# The list of libc versions we are going to download
libcList = [ "libc6-amd64_2.10.1-0ubuntu15_i386",
"libc6-amd64_2.10.1-0ubuntu19_i386",
"libc6-amd64_2.11.1-0ubuntu7.11_i386",
"libc6-amd64_2.11.1-0ubuntu7.12_i386",
"libc6-amd64_2.11.1-0ubuntu7.21_i386",
"libc6-amd64_2.11.1-0ubuntu7_i386",
"libc6-amd64_2.12.1-0ubuntu10.4_i386",
"libc6-amd64_2.12.1-0ubuntu6_i386",
"libc6-amd64_2.13-0ubuntu13.2_i386",
"libc6-amd64_2.13-0ubuntu13_i386",
"libc6-amd64_2.13-20ubuntu5.2_i386",
"libc6-amd64_2.13-20ubuntu5.3_i386",
"libc6-amd64_2.13-20ubuntu5_i386",
"libc6-amd64_2.15-0ubuntu10.18_i386",
"libc6-amd64_2.15-0ubuntu10_i386",
"libc6-amd64_2.15-0ubuntu20.2_i386",
"libc6-amd64_2.15-0ubuntu20_i386",
"libc6-amd64_2.17-0ubuntu5.1_i386",
"libc6-amd64_2.17-0ubuntu5_i386",
"libc6-amd64_2.17-93ubuntu4_i386",
"libc6-amd64_2.19-0ubuntu6.14_i386",
"libc6-amd64_2.19-0ubuntu6.15_i386",
"libc6-amd64_2.19-0ubuntu6_i386",
"libc6-amd64_2.19-10ubuntu2.3_i386",
"libc6-amd64_2.19-10ubuntu2_i386",
"libc6-amd64_2.21-0ubuntu4.3_i386",
"libc6-amd64_2.21-0ubuntu4_i386",
"libc6-amd64_2.23-0ubuntu10_i386",
"libc6-amd64_2.23-0ubuntu11_i386",
"libc6-amd64_2.23-0ubuntu3_i386",
"libc6-amd64_2.24-3ubuntu1_i386",
"libc6-amd64_2.24-3ubuntu2.2_i386",
"libc6-amd64_2.24-9ubuntu2.2_i386",
"libc6-amd64_2.24-9ubuntu2_i386",
"libc6-amd64_2.26-0ubuntu2.1_i386",
"libc6-amd64_2.26-0ubuntu2_i386",
"libc6-amd64_2.27-3ubuntu1_i386",
"libc6-amd64_2.28-0ubuntu1_i386",
"libc6-amd64_2.29-0ubuntu2_i386",
"libc6-amd64_2.3.5-1ubuntu12.5.10.1_i386",
"libc6-amd64_2.3.5-1ubuntu12_i386",
"libc6-amd64_2.3.6-0ubuntu20.6_i386",
"libc6-amd64_2.3.6-0ubuntu20_i386",
"libc6-amd64_2.30-0ubuntu2_i386",
"libc6-amd64_2.30-0ubuntu3_i386",
"libc6-amd64_2.4-1ubuntu12.3_i386",
"libc6-amd64_2.4-1ubuntu12_i386",
"libc6-amd64_2.5-0ubuntu14_i386",
"libc6-amd64_2.6.1-1ubuntu10_i386",
"libc6-amd64_2.6.1-1ubuntu9_i386",
"libc6-amd64_2.7-10ubuntu3_i386",
"libc6-amd64_2.7-10ubuntu8.3_i386",
"libc6-amd64_2.8~20080505-0ubuntu7_i386",
"libc6-amd64_2.8~20080505-0ubuntu9_i386",
"libc6-amd64_2.9-4ubuntu6.3_i386",
"libc6-amd64_2.9-4ubuntu6_i386",
"libc6-i386_2.10.1-0ubuntu15_amd64",
"libc6-i386_2.10.1-0ubuntu19_amd64",
"libc6-i386_2.11.1-0ubuntu7.11_amd64",
"libc6-i386_2.11.1-0ubuntu7.12_amd64",
"libc6-i386_2.11.1-0ubuntu7.21_amd64",
"libc6-i386_2.11.1-0ubuntu7_amd64",
"libc6-i386_2.12.1-0ubuntu10.4_amd64",
"libc6-i386_2.12.1-0ubuntu6_amd64",
"libc6-i386_2.13-0ubuntu13.2_amd64",
"libc6-i386_2.13-0ubuntu13_amd64",
"libc6-i386_2.13-20ubuntu5.2_amd64",
"libc6-i386_2.13-20ubuntu5.3_amd64",
"libc6-i386_2.13-20ubuntu5_amd64",
"libc6-i386_2.15-0ubuntu10.18_amd64",
"libc6-i386_2.15-0ubuntu10_amd64",
"libc6-i386_2.15-0ubuntu20.2_amd64",
"libc6-i386_2.15-0ubuntu20_amd64",
"libc6-i386_2.17-0ubuntu5.1_amd64",
"libc6-i386_2.17-0ubuntu5_amd64",
"libc6-i386_2.17-93ubuntu4_amd64",
"libc6-i386_2.19-0ubuntu6.14_amd64",
"libc6-i386_2.19-0ubuntu6.15_amd64",
"libc6-i386_2.19-0ubuntu6_amd64",
"libc6-i386_2.19-10ubuntu2.3_amd64",
"libc6-i386_2.19-10ubuntu2_amd64",
"libc6-i386_2.21-0ubuntu4.3_amd64",
"libc6-i386_2.21-0ubuntu4_amd64",
"libc6-i386_2.23-0ubuntu10_amd64",
"libc6-i386_2.23-0ubuntu11_amd64",
"libc6-i386_2.23-0ubuntu3_amd64",
"libc6-i386_2.24-3ubuntu1_amd64",
"libc6-i386_2.24-3ubuntu2.2_amd64",
"libc6-i386_2.24-9ubuntu2.2_amd64",
"libc6-i386_2.24-9ubuntu2_amd64",
"libc6-i386_2.26-0ubuntu2.1_amd64",
"libc6-i386_2.26-0ubuntu2_amd64",
"libc6-i386_2.27-3ubuntu1_amd64",
"libc6-i386_2.28-0ubuntu1_amd64",
"libc6-i386_2.29-0ubuntu2_amd64",
"libc6-i386_2.3.6-0ubuntu20.6_amd64",
"libc6-i386_2.3.6-0ubuntu20_amd64",
"libc6-i386_2.30-0ubuntu2_amd64",
"libc6-i386_2.30-0ubuntu3_amd64",
"libc6-i386_2.4-1ubuntu12.3_amd64",
"libc6-i386_2.4-1ubuntu12_amd64",
"libc6-i386_2.5-0ubuntu14_amd64",
"libc6-i386_2.6.1-1ubuntu10_amd64",
"libc6-i386_2.6.1-1ubuntu9_amd64",
"libc6-i386_2.7-10ubuntu3_amd64",
"libc6-i386_2.7-10ubuntu8.3_amd64",
"libc6-i386_2.8~20080505-0ubuntu7_amd64",
"libc6-i386_2.8~20080505-0ubuntu9_amd64",
"libc6-i386_2.9-4ubuntu6.3_amd64",
"libc6-i386_2.9-4ubuntu6_amd64",
"libc6_2.10.1-0ubuntu15_amd64",
"libc6_2.10.1-0ubuntu15_i386",
"libc6_2.10.1-0ubuntu19_amd64",
"libc6_2.10.1-0ubuntu19_i386",
"libc6_2.11.1-0ubuntu7.11_amd64",
"libc6_2.11.1-0ubuntu7.11_i386",
"libc6_2.11.1-0ubuntu7.12_amd64",
"libc6_2.11.1-0ubuntu7.12_i386",
"libc6_2.11.1-0ubuntu7.21_amd64",
"libc6_2.11.1-0ubuntu7.21_i386",
"libc6_2.11.1-0ubuntu7_amd64",
"libc6_2.11.1-0ubuntu7_i386",
"libc6_2.12.1-0ubuntu10.4_amd64",
"libc6_2.12.1-0ubuntu10.4_i386",
"libc6_2.12.1-0ubuntu6_amd64",
"libc6_2.12.1-0ubuntu6_i386",
"libc6_2.13-0ubuntu13.2_amd64",
"libc6_2.13-0ubuntu13.2_i386",
"libc6_2.13-0ubuntu13_amd64",
"libc6_2.13-0ubuntu13_i386",
"libc6_2.13-20ubuntu5.2_amd64",
"libc6_2.13-20ubuntu5.2_i386",
"libc6_2.13-20ubuntu5.3_amd64",
"libc6_2.13-20ubuntu5.3_i386",
"libc6_2.13-20ubuntu5_amd64",
"libc6_2.13-20ubuntu5_i386",
"libc6_2.15-0ubuntu10.18_amd64",
"libc6_2.15-0ubuntu10.18_i386",
"libc6_2.15-0ubuntu10_amd64",
"libc6_2.15-0ubuntu10_i386",
"libc6_2.15-0ubuntu20.2_amd64",
"libc6_2.15-0ubuntu20.2_i386",
"libc6_2.15-0ubuntu20_amd64",
"libc6_2.15-0ubuntu20_i386",
"libc6_2.17-0ubuntu5.1_amd64",
"libc6_2.17-0ubuntu5.1_i386",
"libc6_2.17-0ubuntu5_amd64",
"libc6_2.17-0ubuntu5_i386",
"libc6_2.17-93ubuntu4_amd64",
"libc6_2.17-93ubuntu4_i386",
"libc6_2.19-0ubuntu6.14_amd64",
"libc6_2.19-0ubuntu6.14_i386",
"libc6_2.19-0ubuntu6.15_amd64",
"libc6_2.19-0ubuntu6.15_i386",
"libc6_2.19-0ubuntu6_amd64",
"libc6_2.19-0ubuntu6_i386",
"libc6_2.19-10ubuntu2.3_amd64",
"libc6_2.19-10ubuntu2.3_i386",
"libc6_2.19-10ubuntu2_amd64",
"libc6_2.19-10ubuntu2_i386",
"libc6_2.21-0ubuntu4.3_amd64",
"libc6_2.21-0ubuntu4.3_i386",
"libc6_2.21-0ubuntu4_amd64",
"libc6_2.21-0ubuntu4_i386",
"libc6_2.23-0ubuntu10_amd64",
"libc6_2.23-0ubuntu10_i386",
"libc6_2.23-0ubuntu11_amd64",
"libc6_2.23-0ubuntu11_i386",
"libc6_2.23-0ubuntu3_amd64",
"libc6_2.23-0ubuntu3_i386",
"libc6_2.24-3ubuntu1_amd64",
"libc6_2.24-3ubuntu1_i386",
"libc6_2.24-3ubuntu2.2_amd64",
"libc6_2.24-3ubuntu2.2_i386",
"libc6_2.24-9ubuntu2.2_amd64",
"libc6_2.24-9ubuntu2.2_i386",
"libc6_2.24-9ubuntu2_amd64",
"libc6_2.24-9ubuntu2_i386",
"libc6_2.26-0ubuntu2.1_amd64",
"libc6_2.26-0ubuntu2.1_i386",
"libc6_2.26-0ubuntu2_amd64",
"libc6_2.26-0ubuntu2_i386",
"libc6_2.27-3ubuntu1_amd64",
"libc6_2.27-3ubuntu1_i386",
"libc6_2.28-0ubuntu1_amd64",
"libc6_2.28-0ubuntu1_i386",
"libc6_2.29-0ubuntu2_amd64",
"libc6_2.29-0ubuntu2_i386",
"libc6_2.3.2.ds1-13ubuntu2.2_amd64",
"libc6_2.3.2.ds1-13ubuntu2.2_amd64_2",
"libc6_2.3.2.ds1-13ubuntu2.2_i386",
"libc6_2.3.2.ds1-13ubuntu2.2_i386_2",
"libc6_2.3.2.ds1-13ubuntu2.3_amd64",
"libc6_2.3.2.ds1-13ubuntu2.3_amd64_2",
"libc6_2.3.2.ds1-13ubuntu2.3_i386",
"libc6_2.3.2.ds1-13ubuntu2.3_i386_2",
"libc6_2.3.2.ds1-13ubuntu2_amd64",
"libc6_2.3.2.ds1-13ubuntu2_amd64_2",
"libc6_2.3.2.ds1-13ubuntu2_i386",
"libc6_2.3.2.ds1-13ubuntu2_i386_2",
"libc6_2.3.2.ds1-20ubuntu13_amd64",
"libc6_2.3.2.ds1-20ubuntu13_i386",
"libc6_2.3.2.ds1-20ubuntu13_i386_2",
"libc6_2.3.2.ds1-20ubuntu15_amd64",
"libc6_2.3.2.ds1-20ubuntu15_i386",
"libc6_2.3.2.ds1-20ubuntu15_i386_2",
"libc6_2.3.5-1ubuntu12.5.10.1_amd64",
"libc6_2.3.5-1ubuntu12.5.10.1_i386",
"libc6_2.3.5-1ubuntu12.5.10.1_i386_2",
"libc6_2.3.5-1ubuntu12_amd64",
"libc6_2.3.5-1ubuntu12_i386",
"libc6_2.3.5-1ubuntu12_i386_2",
"libc6_2.3.6-0ubuntu20.6_amd64",
"libc6_2.3.6-0ubuntu20.6_i386",
"libc6_2.3.6-0ubuntu20.6_i386_2",
"libc6_2.3.6-0ubuntu20_amd64",
"libc6_2.3.6-0ubuntu20_i386",
"libc6_2.3.6-0ubuntu20_i386_2",
"libc6_2.30-0ubuntu2_amd64",
"libc6_2.30-0ubuntu2_i386",
"libc6_2.30-0ubuntu3_amd64",
"libc6_2.30-0ubuntu3_i386",
"libc6_2.4-1ubuntu12.3_amd64",
"libc6_2.4-1ubuntu12.3_i386",
"libc6_2.4-1ubuntu12_amd64",
"libc6_2.4-1ubuntu12_i386",
"libc6_2.5-0ubuntu14_amd64",
"libc6_2.5-0ubuntu14_i386",
"libc6_2.6.1-1ubuntu10_amd64",
"libc6_2.6.1-1ubuntu10_i386",
"libc6_2.6.1-1ubuntu9_amd64",
"libc6_2.6.1-1ubuntu9_i386",
"libc6_2.7-10ubuntu3_amd64",
"libc6_2.7-10ubuntu3_i386",
"libc6_2.7-10ubuntu8.3_amd64",
"libc6_2.7-10ubuntu8.3_i386",
"libc6_2.8~20080505-0ubuntu7_amd64",
"libc6_2.8~20080505-0ubuntu7_i386",
"libc6_2.8~20080505-0ubuntu9_amd64",
"libc6_2.8~20080505-0ubuntu9_i386",
"libc6_2.9-4ubuntu6.3_amd64",
"libc6_2.9-4ubuntu6.3_i386",
"libc6_2.9-4ubuntu6_amd64",
"libc6_2.9-4ubuntu6_i386"]

# A function to ensure the directories we need are installed
def make_directories():
	if os.path.isdir("libcs") == False:
		os.mkdir("libcs")
	if os.path.isdir("symbols") == False:
		os.mkdir("symbols")

# Download all of the libcs from https://libc.blukat.me
def grab_libcs():
	decompressor = zstandard.ZstdDecompressor()
	for i in libcList:
		i += ".so"
		print("Downloading: %s" % i)
		try:
			url = "https://github.com/monik3r/libcFun/raw/master/libcs_compressed/%s.zst" % i
			libc_data = requests.get(url).content
			file = open("libcs/%s" % i, "wb")
			decompressed_libc = decompressor.decompress(libc_data)
			file.write(decompressed_libc)
			file.close()
		except:
			print("Could not download: %s" % i)

# Parse the symbols out from the libcs using readelf
def parse_symbols():
	for libc in libcList:
		print("parsing: %s" % libc)
		libc += ".so"
		cmd = "readelf -Ws libcs/" + libc
		symbols = os.popen(cmd).read()
		symbols = symbols.split('\n')
		symbols = symbols[3:]
		formatted_symbols = []
		for i in symbols:
			parsed = ' '.join(i.split()).split(' ')
			if len(parsed) > 7:
				symbol = parsed[7].split("@@")[0] + " " + parsed[1]
				formatted_symbols.append(symbol)
		print("symbols/output-symbols-%s" % libc)
		file  = open("symbols/output-symbols-" + libc, "w")
		file .write('\n'.join(formatted_symbols))
		file .close()

def write_install_dir():
	install_dir = os.getcwd()

	# Read the code file
	thenight_file = open("thenight/thenight.py", "r")
	thenight_code = thenight_file.readlines()
	thenight_file.close()

	# Write the install directory
	thenight_code[5] = 'INSTALL_DIRECTORY = "%s/"\n' % install_dir

	# Write the code file
	thenight_write_file = open("thenight/thenight.py", "w")
	thenight_write_file.writelines(thenight_code)
	thenight_write_file.close()



	
if __name__ == "__main__":
	make_directories()
	grab_libcs()
	parse_symbols()
	write_install_dir()
