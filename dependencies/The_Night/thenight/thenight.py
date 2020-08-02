"""Module for Remote Libc Identification"""

import os
import pickle

INSTALL_DIRECTORY = ""

def symbol_type_check(inp_symbol):
	"""Check/Convert the symbol type for/to str"""
	if isinstance(inp_symbol, str):
		return inp_symbol
	if isinstance(inp_symbol, bytes):
		return inp_symbol.decode("utf-8")
	raise TypeError("Symbols must be either str or bytes.")


def look_libc_offset(symbol_0: str, symbol_1: str, file: str) -> int:
	"""Check if individual libc file is a possible match"""
	libc_file = open(INSTALL_DIRECTORY + "symbols/" + file, "r")

	symbol_0_found = False
	symbol_1_found = False

	offset = 0

	# Find the symbol offsets for this libc
	for line in libc_file:
		if symbol_0_found == symbol_1_found == True:
			break
		if symbol_0 in line:
			if line.split(" ")[0] == symbol_0:
				offset_0 = int(line.split(" ")[1], 16)
				symbol_0_found = True
		if symbol_1 in line:
			if line.split(" ")[0] == symbol_1:
				offset_1 = int(line.split(" ")[1], 16)
				symbol_1_found = True

	# Calculate the offset for the symbols for this libc
	if symbol_0_found == symbol_1_found == True:
		offset = offset_0 - offset_1

	return offset

def find_libc_version(symbol_0: str, addr_0: int, symbol_1: str, addr_1: int):
	"""Find the all the possible libc matches"""

	# Ensure input values are correct type
	if not isinstance(addr_0, int) or not isinstance(addr_1, int):
		raise TypeError("Addresses must be integers.")

	symbol_0 = symbol_type_check(symbol_0)
	symbol_1 = symbol_type_check(symbol_1)

	# Calculate what the offset for the symbols will be
	addr_offset = addr_0 - addr_1

	print("Offset:   %s" % hex(addr_offset))
	print("Symbol_0:  %s" % str(symbol_0))
	print("Symbol_1:  %s" % str(symbol_1))
	print("Address0: %s" % hex(addr_0))
	print("Address1: %s" % hex(addr_1))

	# Iterate through all of the symbol files
	# Checking to see which ones are possible matches
	files = os.listdir(INSTALL_DIRECTORY + "symbols/")
	for i in files:
		libc_offset = look_libc_offset(symbol_0, symbol_1, i)
		if libc_offset == addr_offset:
			print("Possible libc: %s" % i)

def find_libc_version_automated(symbol_0: str, addr_0: int, symbol_1: str, addr_1: int):
	"""Find the all the possible libc matches"""

	# Ensure input values are correct type
	if not isinstance(addr_0, int) or not isinstance(addr_1, int):
		raise TypeError("Addresses must be integers.")

	symbol_0 = symbol_type_check(symbol_0)
	symbol_1 = symbol_type_check(symbol_1)

	# Calculate what the offset for the symbols will be
	addr_offset = addr_0 - addr_1

	# Iterate through all of the symbol files
	# Checking to see which ones are possible matches
	output_file = open("TheNight-Out", "wb")
	files = os.listdir(INSTALL_DIRECTORY + "symbols/")
	for i in files:
		libc_offset = look_libc_offset(symbol_0, symbol_1, i)
		if libc_offset == addr_offset:
			pickle.dump(i, output_file)
	output_file.close()
