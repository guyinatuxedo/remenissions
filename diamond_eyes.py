"""Python module to wrap gdb-gef for dynamic analysis"""

#from pwn import *


from functools import wraps
import errno
import os
import sys
import signal
import time
import argparse
import pickle

from pwn import process



'''
+-----------------------------------------------------------+
|				        Constants				            |
+-----------------------------------------------------------+
'''

HEX_CHARS = [
				0x30, 
				0x31, 
				0x32, 
				0x33, 
				0x34, 
				0x35, 
				0x36, 
				0x37, 
				0x38, 
				0x39, 
				0x41, 
				0x42, 
				0x43, 
				0x44, 
				0x45, 
				0x46, 
				0x61, 
				0x62, 
				0x63, 
				0x64, 
				0x65, 
				0x66
			]

RECV_PROMPT = b"DiamondEyes"
TIMEOUT_SECONDS = 10

'''
+-----------------------------------------------------------+
|				          Utils				                |
+-----------------------------------------------------------+
'''


def help_function():
	"""A Function to display help"""
	print("Checkout the git repo")
	sys.exit(0)

def int_to_string(value):
	"""Integer to bytes conversion"""
	hex_string = hex(value)[2:]
	if len(hex_string) % 2 != 00:
		hex_string = "0" + hex_string
	string = ""
	for i in range(0, (int(len(hex_string) / 2))):
		current_byte = "0x" + hex_string[(i*2)] + hex_string[(i*2) + 1]
		string += chr(int(current_byte, 16))
	string = bytes(string, encoding='utf-8')
	return string

def parse_0x(string):
	"""Parse string that begins with 0x"""
	start_index = string.find(b"0x")

	string_len = len(string)
	index = start_index + 2
	found_end = False
	while not found_end:

		if string[index] in HEX_CHARS:
			index = index + 1
			if index >= (string_len - 1):
				found_end = True
		else:
			found_end = True

	hex_string = string[start_index:index + 1]

	hex_value = int(hex_string, 16)

	return hex_value

def get_nth_byte(value, n_byte):
	"""Get the nth byte byte of an integer"""
	byte = (value & ((0xff) << (n_byte*8)))
	byte = (byte >> (n_byte*8))
	return byte

def strip_continuing(output):
	"""Strip string 'Continuing' from string"""
	string = b"Continuing.\n"
	string_len = len(string)
	new_index = output.find(string)
	return output[new_index + string_len:]

def does_string_have_numbers(string):
	"""Check if string contains hex characters"""
	for i in range(0, len(string)):
		if is_hex_ascii_character(string[i]):
			return True
	return False

def is_hex_ascii_character(char):
	"""Check if a character is in the ascii hex range"""
	char = char
	if 0x39 >= char >= 0x30:
		return True

	elif 0x46 >= char >= 0x41:
		return True

	elif 0x66 >= char >= 0x61:
		return True

	return False

def adjust_mem_region(mem_region, area_start, area_end):
	"""Adjust the bounds of a memory region"""
	if mem_region["start"] > area_start:
		mem_region["start"] = area_start
	if mem_region["end"] < area_end:
		mem_region["end"] = area_end

def grab_hex_strings(string):
	"""Grab hex substrings from string"""
	hex_strings = []
	str_len = len(string)
	i = 0
	while i < str_len:
		if string[i] in HEX_CHARS:
			j = i + 1
			while j < str_len:
				if string[j] not in HEX_CHARS:
					break
				j += 1
			hex_string = string[i:j]
			hex_strings.append(int("0x%s" % hex_string.decode("utf-8"), 16))
			i = j + 1
		else:
			i += 1
	return hex_strings

class TimeoutError(Exception):
	"""A class for timeouts"""
	pass

def timeout(seconds=10, error_message=os.strerror(errno.ETIME)):
	"""A function for handling timeouts"""
	def decorator(func):
		def _handle_timeout(signum, frame):
			raise TimeoutError(error_message)

		def wrapper(*args, **kwargs):
			signal.signal(signal.SIGALRM, _handle_timeout)
			signal.alarm(seconds)
			try:
				result = func(*args, **kwargs)
			finally:
				signal.alarm(0)
			return result

		return wraps(func)(wrapper)
	return decorator

'''
+-----------------------------------------------------------+
|				   Dyanmic Analyzer Class				    |
+-----------------------------------------------------------+
'''

class DynamicAnalyzer():
	"""Our class for dynamic analysis"""

	def __init__(self):
		"""Initialize a dynamic analyzer class"""
		self.input_size = 10

		self.target_binary = ""
		self.output_file = None
		self.target = None

		self.last_input = None
		self.saved_outputs = []
		self.input_analysis = []

		self.architecture = "64"


		self.first_byte = 0x21
		self.second_byte = 0x21

		self.inputs = []

		self.cmd = None
		self.crash_analysis = []

		self.bug_found = False
		self.report_bugs = True

		self.stack = {"start": 0xffffffffffffffff, "end": 0x0, "region": "stack"}
		self.libc = {"start": 0xffffffffffffffff, "end": 0x0, "region": "libc"}
		self.pie = {"start": 0xffffffffffffffff, "end": 0x0, "region": "pie"}
		self.mem_regions = {"stack": self.stack, "libc": self.libc, "pie": self.pie}

	def main_loop(self):
		"""The main loop for analysis"""
		self.reset_input()
		i = 1
		output = self.get_output()
		self.run_cmd()
		
		exited = False
		while not exited:
			while output:
				self.process_output(output)
				if (b"exited normally" in output) or (b"not being run" in output):
					return
				i += 1
				
				self.target.sendline(b"c")
				output = self.get_output()
			self.send_input()
			output = old_output = self.get_output()
			while output:
				output = self.get_output()
			output = old_output

	def get_first_stack_ptr(self, offset=None):
		"""Get the first stack pointer from the top of the stack"""
		if offset is None:
			offset = 0
		if self.architecture == "32":
			while offset < 100:
				current_value = self.get_esp_offset(offset)
				if (self.is_stack_address(current_value)):
					return current_value, offset
				offset += 4

		elif self.architecture == "64":
			while offset < 200:
				current_value = self.get_rsp_offset(offset)
				if self.is_stack_address(current_value):
					return current_value, offset
				offset += 8

	def get_first_libc_ptr(self, offset = None):
		"""Get the first libc pointer from the top of the stack"""
		if offset is None:
			offset = 0
		if self.architecture == "32":
			while offset < 100:
				current_value = self.get_esp_offset(offset)
				if (self.is_libc_address(current_value)):
					return current_value, offset
				offset += 4
		elif self.architecture == "64":
			while offset < 200:
				current_value = self.get_rsp_offset(offset)
				if self.is_libc_address(current_value):
					return current_value, offset
				offset += 8

	def get_first_pie_ptr(self, offset = None):
		"""Get the first pie pointer from the top of the stack"""
		if offset is None:
			offset = 0
		if self.architecture == "32":
			while offset < 100:
				current_value = self.get_esp_offset(offset)
				if (self.is_pie_address(current_value)):
					return current_value, offset
				offset += 4

		elif self.architecture == "64":
			while offset < 500:
				current_value = self.get_rsp_offset(offset)
				if (self.is_pie_address(current_value)):
					return current_value, offset
				offset += 8

	def get_rsp_offset(self, offset):
		"""Get value of rsp+offset dereferenced"""
		cmd = bytes("x/g $rsp+%s" % hex(offset), encoding='utf-8')
		output = self.send_cmd(cmd)
		value = parse_0x(output.split(b":")[1])
		return value

	def get_esp_offset(self, offset):
		"""Get value of esp+offset dereferenced"""
		cmd = bytes("x/w $esp+%s" % hex(offset), encoding='utf-8')
		output = self.send_cmd(cmd)
		value = parse_0x(output.split(b":")[1])
		return value

	def get_register_value(self, register):
		"""Get the value of a register"""
		cmd = "p $%s" % register
		output = self.send_cmd(bytes(cmd, encoding='utf-8'))
		value = parse_0x(output.split(b"=")[1].split(RECV_PROMPT)[0])
		return value


	def send_input(self):
		"""Send input to the target process"""
		target_input = self.gen_input()
		self.inputs.append(target_input)
		self.target.sendline(target_input)

	def gen_input(self):
		"""Generate input to send"""
		if self.architecture == "64":
			ptr_size = 8
		else:
			ptr_size = 4
		if self.input_size < 10000:
			self.input_size = self.input_size * 10

		current_size = 0
		current_input = b""
		while current_size != self.input_size:
			if current_size < self.input_size:
				current_input += self.first_byte.to_bytes(length=1, byteorder='little')*(ptr_size - 1) 
				current_input += self.second_byte.to_bytes(length=1, byteorder='little')
				self.increment_bytes()
				current_size += ptr_size

			elif current_size > self.input_size:
				offset = current_size - self.input_size
				current_input = current_input[0:-offset]
				current_size = self.input_size

		return current_input

	def increment_bytes(self):
		"""Increment the bytes used in input"""
		max_byte = 0x7e
		min_byte = 0x21

		self.second_byte = self.second_byte + 1
		if self.second_byte >= max_byte:
			self.second_byte = min_byte
			self.first_byte += 1


	def reset_input(self):
		"""Reset the bytes used in input"""
		self.first_byte = 0x21
		self.second_byte = 0x21

	def get_output(self):
		"""Get output from target process, and check for crash"""
		try:
			has_crashed = False
			output = self.fetch_output()
			decoded_output = output.decode("utf-8")
			if self.inputs != []:
				has_crashed = "real as" in decoded_output
		except:
			return False
		if has_crashed:
			self.got_crash()
		output = output.split(b"\n\nThat's what")[0]

		if b"SIGSEGV" in output:
			self.got_crash()
		if "SIGSEGV" in output.decode("utf-8"):
			self.got_crash()
		return output

	@timeout(1)
	def fetch_output(self):
		"""Purely grab output from target process"""
		return self.target.recvuntil(RECV_PROMPT, timeout=TIMEOUT_SECONDS)

	def check_offset_x64(self, value, check_value, offset):
		"""Check offset for fmt strings for x64 binaries"""
		current_byte = 0
		single_byte = get_nth_byte(check_value, current_byte)
		possible_match = False
		for i in range(0, 8):
			nth_byte = get_nth_byte(value, i)
			if single_byte == nth_byte:
				possible_match = True
				current_byte += 1
				single_byte = get_nth_byte(check_value, current_byte)
			else:
				possible_match = False

		first_place_bytes = current_byte
		if possible_match:
			offset = offset - (8 * 6)
			value = self.get_rsp_offset(offset + 8)
			i = 0
			while (current_byte < 8) and (i < 8) and (possible_match):
				nth_byte = get_nth_byte(value, i)
				if single_byte == nth_byte:
					possible_match = True
					current_byte += 1
					single_byte = get_nth_byte(check_value, current_byte)
				else:
					possible_match = False
				i += 1
		if possible_match:
			return first_place_bytes
		return None

	def check_offset_x86(self, value, check_value, offset):
		"""Check offset for fmt strings for x86 binaries"""
		current_byte = 0
		single_byte = get_nth_byte(check_value, current_byte)
		possible_match = False
		for i in range(0, 4):
			nth_byte = get_nth_byte(value, i)
			if single_byte == nth_byte:
				possible_match = True
				current_byte += 1
				single_byte = get_nth_byte(check_value, current_byte)
			else:
				possible_match = False

		first_place_bytes = current_byte
		if possible_match:
			value = self.get_esp_offset(offset + 4)
			i = 0
			while (current_byte < 4) and (i < 4) and (possible_match):
				nth_byte = get_nth_byte(value, i)
				if single_byte == nth_byte:
					possible_match = True
					current_byte += 1
					single_byte = get_nth_byte(check_value, current_byte)
				else:
					possible_match = False
				i += 1
		if possible_match:
			return first_place_bytes
		return None

	def get_string_at(self, address):
		"""Get string stored at memory location"""
		cmd = bytes("x/s %s" % hex(address), encoding='utf-8')
		output = self.send_cmd(cmd)
		output = b":".join(output.split(b":")[1:])
		string = output.split(b'"')[1]
		return string

	def get_esp(self):
		"""Get the value pointed to by esp"""
		output = self.send_cmd(b"x/w $esp")
		value = parse_0x(output.split(b":")[1])
		return value

	def get_rdi_string(self):
		"""Get the string pointed to by rdi"""
		output = self.send_cmd(b"x/s $rdi")
		output = b":".join(output.split(b":")[1:])
		string = output.split(b'"')[1]
		return string

	def get_value_at(self, address):
		"""Get value pointed to by address"""
		if self.architecture == "32":
			cmd = "x/w %s" % address
		elif self.architecture == "64":
			cmd = "x/g %s" % address
		output = self.send_cmd(bytes(cmd, encoding='utf-8'))
		value = parse_0x(output.split(b":")[1])
		return value

	def get_rsp_address(self):
		"""Get the value of rsp"""
		output = self.send_cmd(b"p $rsp")
		output = output.split(b"=")[1]
		output = output.split(RECV_PROMPT)[0]
		value = parse_0x(output)
		return value

	def get_esp_address(self):
		"""Get the value of esp"""
		output = self.send_cmd(b"p $esp")
		value = parse_0x(output.split(b"=")[1].split(RECV_PROMPT)[0])
		return value

	def get_main(self):
		"""Get the address of the main function"""
		back_trace = self.send_cmd(b"backtrace")
		back_trace_lines = back_trace.split(b"\n")
		for line in back_trace_lines:
			if b"__libc_start_main" in line:
				address = line.split(b"=0x")[1].split(b",")[0].decode(encoding='utf-8')
				main = "0x%s" % (address)
				main = int(main, 0x10)
				return main
		return None

	def got_crash(self):
		"""Do reporting for crash"""
		found_crash_cause = False
		return_address = self.get_return_address()
		if return_address is None:
			return

		if not self.is_mapped_memory(return_address) and not found_crash_cause:

			reveresed_return_address = self.reverse_int(return_address)
			is_from_input, which_input, overflow_ret_offset = self.is_value_from_input(reveresed_return_address)
			if is_from_input:

				found_crash_cause = True
				self.log_stack(overflow_ret_offset)
				offset = overflow_ret_offset
		if not found_crash_cause:
			current_instruction_pointer_value = self.get_current_instruction_pointer_value()
			current_instruction_pointer_value = self.reverse_int(current_instruction_pointer_value)
			is_from_input, which_input, call_input_offset = self.is_value_from_input(current_instruction_pointer_value)
			if is_from_input:
				self.report_call_input(call_input_offset, which_input)
				offset = call_input_offset

		for analysis in self.crash_analysis:
			if analysis[0] == "stackInfoleak":
				stack_leak = analysis[1]
				leak_offset_from_start = stack_leak[1]
				return_address_location = self.get_return_address_location()
				return_address_offset_from_start = return_address_location - self.stack["start"]
				ret_start_offset = return_address_offset_from_start - leak_offset_from_start
				infoleak_output = stack_leak[2]
				if b"0x" in infoleak_output:
					string = self.get_strings_before_after(infoleak_output)
				else:
					string = analysis[2]

				self.report_infoleak("stack", string, ret_start_offset)
				sys.exit(0)
			elif analysis[0] == "infoleak":
				leak = analysis[1]
				region = leak[0]
				offset = leak[1]
				infoleak_output = leak[2]
				string = self.get_strings_before_after(infoleak_output)
				self.report_infoleak(region, string, offset)

			elif analysis[0] == "check32_main_offset":
				if output_file is not None:
					output = open(output_file, "w")
					pickle.dump(offset, output)
					output.close()
				sys.exit(0)
		sys.exit(0)

	def get_pie_rw(self):
		"""Get a pie region of memory that is read/writeable"""
		mem_mappings = self.send_cmd(b"vmmap").split(b"\n")[2:-1]

		target_binary_bytes = bytes(self.target_binary, encoding="utf-8")
		for line in mem_mappings:
			if (b"rw" in line) and (target_binary_bytes in line):
				address = parse_0x(line.split(b" ")[0])

		while not self.does_point_to_zero(address):
			address = address + 8

		if self.output_file is not None:
			output = open(self.output_file, "wb")
			pickle.dump(address, output)
			output.close()

	def does_point_to_zero(self, address):
		"""See if a ptr points to zero"""
		cmd = "x/x %s" % hex(address)
		output = self.send_cmd(bytes(cmd, encoding='utf-8'))
		value = output.split(b"\n")[0].split(b":")[1]
		if parse_0x(value) == 0:
			return True
		return False

	def reverse_int(self, value):
		"""Reverse an integer"""

		# Grab the architecture size
		ptr_size = self.get_ptr_size()

		# Iterate through each byte, anding to grab the value
		return_value = 0x00
		for i in range(0, ptr_size):
			current_byte = ((value & (0xff << (i*8))) >> (i*8))
			return_value = return_value | (current_byte << (((ptr_size - 1) - i)*8))
		return return_value

	def get_ptr_size(self):
		"""Get the size of a memory address for the arch"""
		if self.architecture == "64":
			ptr_size = 8
		else:
			ptr_size = 4
		return ptr_size

	def get_strings_before_after(self, string):
		"""Get strings before/after infoleak"""
		index = self.saved_outputs.index(string)

		if len(self.saved_outputs) == 1:
			before_string = self.saved_outputs[0].split(string)[0]
			after_string = self.saved_outputs[0].split(string)[0]
			output_string = before_string + b"%p" + after_string
			return output_string

		found_beginning = False
		before_string = b""
		while (index > -1) and not found_beginning:
			index = index - 1
			before_string = self.saved_outputs[index] + before_string
			if len(before_string) > 5:
				found_beginning = True

		index = self.saved_outputs.index(string)
		found_end = False
		after_string = b""
		max_index = len(self.saved_outputs) - 1
		while (index <= max_index) and not found_end:
			index = index + 1
			after_string = after_string + self.saved_outputs[index]
			if len(after_string) > 5:
				found_end = True

		output_string = before_string + b"%p" + after_string
		return output_string

	def get_return_address(self):
		"""Get the saved return address value"""
		if self.architecture == "64":
			register_string = b"saved rip = "
		else:
			register_string = b"saved eip = "

		frame_output = self.send_cmd(b"info frame").split(b"\n")

		for line in frame_output:
			if register_string in line:
				return_address = line.split(register_string)[1]
				return_address = parse_0x(return_address)
				return return_address

	def get_return_address_location(self):
		"""Get the saved return address location"""
		if self.architecture == "64":
			register_string = b"rip at "
		else:
			register_string = b"eip at "
		frame_output = self.send_cmd(b"info frame").split(b"\n")
		for line in frame_output:
			if register_string in line:
				return_address_location = line.split(register_string)[1]
				return_address_location = parse_0x(return_address_location)
				return return_address_location

	def get_current_instruction_pointer_value(self):
		"""Get the current instruction ptr value"""
		if self.architecture == "64":
			output = self.send_cmd(b"x/g $rip")
			output = output.split(b":")[1]
			instruction_value = parse_0x(output)
			return instruction_value
		elif self.architecture == "32":
			output = self.send_cmd(b"x/w $eip")
			output = output.split(b":")[1]
			instruction_value = parse_0x(output)
			return instruction_value

	def send_cmd(self, cmd):
		"""Send a gdb command, return the output"""
		self.target.sendline(cmd)
		return self.target.recvuntil(RECV_PROMPT, timeout=TIMEOUT_SECONDS)

	def setup(self):
		"""Run the setup for the dynamic analyzer"""
		self.target = process(["gdb", ("%s" % self.target_binary)])

		self.target.sendline(b"set extended-prompt %b" % RECV_PROMPT)

		self.target.recvuntil(RECV_PROMPT, timeout=TIMEOUT_SECONDS)

		self.send_cmd(b"catch syscall read write")

		silent_commands = b"commands\nsilent\necho \\n\\nThat's what you do best\\n\\n\nend"
		self.send_cmd(silent_commands)

		self.send_cmd(b"catch signal SIGSEGV")
		silent_commands = b"commands\nsilent\necho \\n\\nreal as ever\\n\\n\nend"

		self.send_cmd(silent_commands)

		self.get_architecture()

		self.target.sendline(b"r")

		self.target.recvuntil(RECV_PROMPT, timeout=TIMEOUT_SECONDS).split(b"\n\nThat's what")

		self.target.sendline(b"c")

		self.target.recvuntil(b"Continuing.\n", timeout=TIMEOUT_SECONDS)

	def query_memory_regions(self):
		"""Enumerate the addresses for the various memory regions"""
		vmmap_output = self.send_cmd(b"vmmap")
		mem_mappings = vmmap_output.split(b"\n")[1:-1]
		for line in mem_mappings:
			line_parts = line.split(b" ")
			if b"stack" in line_parts[4]:
				area_start = int(line_parts[0], 16)
				area_end   = int(line_parts[1], 16)
				adjust_mem_region(self.stack, area_start, area_end)
			if b"libc" in line_parts[4] and b"libc-exploit-dev" not in line_parts[4]:
				area_start = int(line_parts[0], 16)
				area_end   = int(line_parts[1], 16)
				adjust_mem_region(self.libc, area_start, area_end)
			if bytes(self.target_binary, encoding='utf-8') in line_parts[4]:
				area_start = int(line_parts[0], 16)
				area_end   = int(line_parts[1], 16)
				adjust_mem_region(self.pie, area_start, area_end)

	def is_mapped_memory(self, address):
		"""Check if an address is within the mapped memory bounds"""
		if self.libc["end"] >= address >= self.libc["start"]:
			return True
		if self.stack["end"] >= address >= self.stack["start"]:
			return True
		if self.pie["end"] >= address >= self.pie["start"]:
			return True
		return False

	def is_stack_address(self, address):
		"""Check if a memory address if from the stack"""
		if self.stack["end"] >= address >= self.stack["start"]:
			return True
		return False

	def is_libc_address(self, address):
		"""Check if a memory address if from libc"""
		if self.libc["end"] >= address >= self.libc["start"]:
			return True
		return False

	def is_pie_address(self, address):
		"""Check if a memory address if from the binary"""
		if self.pie["end"] >= address >= self.pie["start"]:
			return True
		return False

	def process_infoleak(self, infoleak):
		"""Prepare an infoleak for further analysis"""
		for mem_region in self.mem_regions.values():
			if mem_region["end"] >= infoleak >= mem_region["start"]:
				region = mem_region["region"]
				offset = infoleak - mem_region["start"]
				return [region, offset]
		return None

	def process_output(self, output):
		"""Analyze the output"""
		output = strip_continuing(output)
		if output is None:
			return

		output_len = len(output)
		if output_len == 0:
			return

		if b"SIGSEGV" in output:
			self.got_crash()

		if b"exited" in output:
			return

		if (b"0x" in output):


			if b"0x" not in output and b"7f" in output:
				index = output.index(b"7f")
				output = output[:index] + b"0x" + output[index:]
			has_number = does_string_have_numbers(output)
			if not has_number:
				self.saved_outputs.append(output)
				return

			self.query_memory_regions()
			value = parse_0x(output)
			hex_value = hex(value)


			if not self.is_mapped_memory(value):
				self.saved_outputs.append(output)
				return

			infoleak = self.process_infoleak(value)
			infoleak.append(output)

			if self.is_stack_address(value):
				self.crash_analysis.append(["stackInfoleak", infoleak])

			else:
				self.crash_analysis.append(["infoleak", infoleak])

			self.saved_outputs.append(output)
			return

		hex_strings = grab_hex_strings(output)
		if hex_strings != []:
			self.query_memory_regions()
			for value in hex_strings:
				if not self.is_mapped_memory(value):
					continue

				hex_value = hex(value).replace("0x", "")
				hex_value = bytes(hex_value, encoding="utf-8")
				if hex_value not in output:
					continue

				output_pieces = output.split(hex_value)
				infoleak = self.process_infoleak(value)
				infoleak.append(output)
				fmt_string = output.replace(hex_value, b"%p")

				if self.is_stack_address(value):
					self.crash_analysis.append(["stackInfoleak", infoleak, fmt_string])
				else:
					self.crash_analysis.append(["infoleak", infoleak, fmt_string])

				self.saved_outputs.append(output)
				return
		self.saved_outputs.append(output)

	def is_value_from_input(self, value):
		"""See if a value is from our input"""
		is_from_input = False
		which_input 	= False
		offset		= False
		string = None

		if isinstance(value, int):
			string = int_to_string(value)

		if isinstance(value, str):
			string = string.strip("\n")

		if string is None:
			return is_from_input, which_input, offset

		for i in range(0, len(self.inputs)):
			if string in self.inputs[i]:
				is_from_input = True
				which_input = i
				offset = self.inputs[i].index(string)

		return is_from_input, which_input, offset

	def report_infoleak(self, region, string, leak_offset):
		"""Report an infoleak bug"""
		if not self.report_bugs:
			return

		infoleak_bug = {}
		infoleak_bug["type"] = "infoleak"
		infoleak_bug["function"] = None
		infoleak_bug["callingFunction"] = None
		infoleak_bug["address"] = None
		infoleak_bug["memoryRegion"] = region
		infoleak_bug["string"] = string.decode('utf-8')
		infoleak_bug["offset"] = leak_offset
		infoleak_bug["fmtIndex"] = 0

		if self.output_file is not None:
			output = open(self.output_file, "wb")
			pickle.dump(infoleak_bug, output)
			output.close()
		print("+-------------------------------------------------------------------------+\n|								 Infoleak								|\n+-------------------------------------------------------------------------+")
		print("Region:\t\t%s" % str(infoleak_bug["memoryRegion"]))
		print("String:\t\t%s" % str(infoleak_bug["string"]))
		print("\n\n\n\n")



	def report_call_input(self, offset, inp_num):
		"""Report a call input bug"""

		if not self.report_bugs:
			return

		function = None
		address = None
		calling_function = None

		call_input_bug = {}
		call_input_bug["type"] = "callInput"
		call_input_bug["function"] = function
		call_input_bug["callingFunction"] = calling_function
		call_input_bug["address"] = address
		call_input_bug["offset"] = offset
		call_input_bug["inpNum"] = inp_num


		self.bug_found = True

		if self.output_file is not None:
			output = open(self.output_file, "wb")
			pickle.dump(call_input_bug, output)
			output.close()
		print("+-------------------------------------------------------------------------+\n|								Call Input							   |\n+-------------------------------------------------------------------------+")
		print("Offset:\t\t%s" % str(call_input_bug["offset"]))
		print("\n\n\n\n")

	def log_stack(self, offset):
		"""Report a stack buffer overflow bug"""

		if not self.report_bugs:
			return

		function = None

		address = None
		calling_function = None
		overwriteable_values = [offset, "return_address"]
		self.bug_found = True

		bof_bug = {}
		bof_bug["type"] = "stack"
		bof_bug["function"] = None
		bof_bug["callingFunction"] = calling_function
		bof_bug["address"] = None
		bof_bug["overwriteableVars"] = overwriteable_values
		bof_bug["checks"] = []
		bof_bug["calledPtrs"] = []
		bof_bug["inpType"] = "stdin"
		bof_bug["writeSize"] = None


		if self.output_file is not None:
			output = open(self.output_file, "wb")
			pickle.dump(bof_bug, output)
			output.close()
		else:
			print("+-------------------------------------------------------------------------+\n|						  Stack Buffer Overflow						  |\n+-------------------------------------------------------------------------+")
			print("Overwriteable Values:\t\t%s" % str(bof_bug["overwriteableVars"]))
			print("Input type:\t\t\t%s" % str(bof_bug["inpType"]))
			print("\n\n\n\n")

	def output_to_file(self, data):
		"""Output data to output file"""
		if self.output_file is not None:
			output = open(self.output_file, "wb")
			pickle.dump(data, output)
			output.close()

	def get_architecture(self):
		"""Get the architecture for binary"""
		output = self.send_cmd(b"show architecture")
		parsed_output = output.split(b"architecture is set automatically ")[1].split(b"\n")[0]
		if b"64" in parsed_output:
			self.architecture = "64"
		elif b"i386":
			self.architecture = "32"
		else:
			print("Not supported architecture")
			sys.exit(0)

	def run_cmd(self):
		"""Run a dynamic analyzer command"""
		if self.cmd is None:
			return

		cmd = self.cmd
		if cmd == "sanity_check":
			print("I'm not insane")
			sys.exit(0)

		elif cmd == "get_pie_rw":
			self.target.sendline(b"")
			self.target.recvuntil(RECV_PROMPT, timeout=TIMEOUT_SECONDS)
			self.get_pie_rw()
			sys.exit(0)

		elif "check32_offset_main" in cmd:
			address = cmd.split(":")[1]
			address = int(address, 16)

			# Clear all breakpoints
			self.send_cmd(b"delete breakpoints")


			if "Pie" not in cmd:
				cmd = bytes("break *%s" % hex(address), encoding='utf-8')

			else:
				cmd = bytes("pie break *%s" % hex(address), encoding='utf-8')

			self.send_cmd(cmd)

			self.target.sendline(b"continue")
			self.target.recvuntil(RECV_PROMPT, timeout=TIMEOUT_SECONDS)

			saved_eip = self.get_return_address_location()

			self.query_memory_regions()


			stack_argument, offset = self.get_first_stack_ptr()

			if saved_eip is None or stack_argument is None:
				sys.exit(0)

			offset = saved_eip - stack_argument

			self.output_to_file(offset)
			sys.exit(0)

		elif cmd == "get_main":
			main = self.get_main()
			while main is None:
				self.send_cmd(b"c")
				main = self.get_main()

			main = hex(main)

			self.output_to_file(main)
			sys.exit(0)

		elif "printfOffset64" in cmd:
			address = cmd.split(":")[1]
			address = int(address, 16)

			# Clear all breakpoints
			self.send_cmd(b"delete breakpoints")

			if "Pie" in cmd:
				cmd = "pie break *%s" % hex(address)
			else:
				cmd = "break *%s" % hex(address)
			self.send_cmd(bytes(cmd, encoding='utf-8'))

			self.target.sendline(b"continue")
			self.send_cmd(b"15935728")

			offset = 0
			value = 0x0
			i = 0
			while value != 0x3832373533393531:
				value = self.get_rsp_offset(offset)
				shifted_offset_places = self.check_offset_x64(value, 0x3832373533393531, offset)
				if shifted_offset_places is not None:
					offset += 8
					break
				offset += 8
				i += 1
				if i == 21:
					sys.exit(0)

			stack_spot_offset = int(offset / 8) - 1
			stack_spot_offset += 6

			string = self.get_rdi_string()

			offset = string.index(b"15935728")

			if shifted_offset_places is None:
				shifted_offset_places = 0

			self.output_to_file([stack_spot_offset, offset, shifted_offset_places])
			sys.exit(0)

		elif "printfOffset32" in cmd:

			address = cmd.split(":")[1]
			address = int(address, 16)

			# Clear all breakpoints
			self.send_cmd(b"delete breakpoints")

			if "Pie" in cmd:
				cmd = "pie break *%s" % hex(address)
			else:
				cmd = "break *%s" % hex(address)
			self.send_cmd(bytes(cmd, encoding='utf-8'))

			self.target.sendline(b"continue")
			self.send_cmd(b"15935728")

			offset = 0
			value = 0x0
			i = 0
			while value != 0x33393531:
				value = self.get_esp_offset(offset)
				shifted_offset_places = self.check_offset_x86(value, 0x33393531, offset)
				if shifted_offset_places is not None:
					offset += 4
					break

				offset += 4
				i += 1

			stack_spot_offset = int(offset / 4) - 1

			esp_value = self.get_esp()
			string = self.get_string_at(esp_value)

			offset = string.index(b"15935728")

			if shifted_offset_places is None:
				shifted_offset_places = 0

			self.output_to_file([stack_spot_offset, offset, shifted_offset_places])
			sys.exit(0)

		elif "printStackOffset" in cmd:
			address = cmd.split(":")[1]
			address = int(address, 16)

			# Clear all breakpoints
			self.send_cmd(b"delete breakpoints")

			if "Pie" in cmd:
				cmd = "pie break *%s" % hex(address)
			else:
				cmd = "break *%s" % hex(address)

			self.send_cmd(bytes(cmd, encoding='utf-8'))
			self.target.sendline(b"continue")
			self.send_cmd(b"15935728")

			ret_address_location = self.get_return_address_location()
			if self.architecture == "64":
				saved_base_ptr = ret_address_location - 8
			elif self.architecture == "32":
				saved_base_ptr = ret_address_location - 4

			saved_base_value = self.get_value_at(saved_base_ptr)

			stack_offset_to_ret_address = ret_address_location - saved_base_value

			if self.architecture == "64":
				rsp_address = self.get_rsp_address()
				offset = int((saved_base_ptr - rsp_address) / 8) + 6
			elif self.architecture == "32":
				esp_address = self.get_esp_address()
				offset = int((saved_base_ptr - esp_address) / 4)

			self.output_to_file([offset, stack_offset_to_ret_address])
			sys.exit(0)

		elif "printLibcOffset" in cmd:
			address = cmd.split(":")[1]
			address = int(address, 16)

			# Clear all breakpoints
			self.send_cmd(b"delete breakpoints")

			if "Pie" in cmd:
				cmd = "pie break *%s" % hex(address)
			else:
				cmd = "break *%s" % hex(address)

			self.send_cmd(bytes(cmd, encoding='utf-8'))

			self.target.sendline(b"continue")

			self.send_cmd(b"15935728")


			self.query_memory_regions()

			if self.architecture == "32":
				value, offset = self.get_first_libc_ptr()
				fs_offset = int(offset / 4)
				offset_to_base = value - self.libc["start"]

			elif self.architecture == "64":
				rsi_value = self.get_register_value("rsi")
				rdx_value = self.get_register_value("rdx")
				rcx_value = self.get_register_value("rcx")
				r8_value = self.get_register_value("r8")
				r9_value = self.get_register_value("r9")
				if self.is_libc_address(rsi_value):
					fs_offset = 1
					offset_to_base = rsi_value - self.libc["start"]

				elif self.is_libc_address(rdx_value):
					fs_offset = 2
					offset_to_base = rdx_value - self.libc["start"]

				elif self.is_libc_address(rcx_value):
					fs_offset = 3
					offset_to_base = rcx_value - self.libc["start"]

				elif self.is_libc_address(r8_value):
					fs_offset = 4
					offset_to_base = r8_value - self.libc["start"]

				elif self.is_libc_address(r9_value):
					fs_offset = 5
					offset_to_base = r9_value - self.libc["start"]

				else:
					value, offset = self.get_first_libc_ptr()
					fs_offset = int(offset / 8) + 6
					offset_to_base = value - self.libc["start"]

			self.output_to_file([fs_offset, offset_to_base])
			sys.exit(0)

		elif "printPieOffset" in cmd:
			address = cmd.split(":")[1]
			address = int(address, 16)

			# Clear all breakpoints
			self.send_cmd(b"delete breakpoints")

			if "Pie" in cmd:
				cmd = "pie break *%s" % hex(address)
			else:
				cmd = "break *%s" % hex(address)

			self.send_cmd(bytes(cmd, encoding='utf-8'))

			self.target.sendline(b"continue")

			self.send_cmd(b"15935728")


			self.query_memory_regions()

			if self.architecture == "32":
				value, offset = self.get_first_pie_ptr()
				fs_offset = int(offset / 4)
				offset_to_base = value - self.pie["start"]

			elif self.architecture == "64":
				rsi_value = self.get_register_value("rsi")
				rdx_value = self.get_register_value("rdx")
				rcx_value = self.get_register_value("rcx")
				r8_value = self.get_register_value("r8")
				r9_value = self.get_register_value("r9")
				if self.is_pie_address(rsi_value):
					fs_offset = 1
					offset_to_base = rsi_value - self.pie["start"]

				elif self.is_pie_address(rdx_value):
					fs_offset = 2
					offset_to_base = rdx_value - self.pie["start"]

				elif self.is_pie_address(rcx_value):
					fs_offset = 3
					offset_to_base = rcx_value - self.pie["start"]

				elif self.is_pie_address(r8_value):
					fs_offset = 4
					offset_to_base = r8_value - self.pie["start"]

				elif self.is_pie_address(r9_value):
					fs_offset = 5
					offset_to_base = r9_value - self.pie["start"]

				else:
					value, offset = self.get_first_pie_ptr()
					fs_offset = int(offset / 8) + 6
					offset_to_base = value - self.pie["start"]

			self.output_to_file([fs_offset, offset_to_base])
			sys.exit(0)

'''
+-----------------------------------------------------------+
|						 Main Function				        |
+-----------------------------------------------------------+
'''

if __name__ == "__main__":
	"""Our main function"""
	parser = argparse.ArgumentParser(description = "Anaylzer for binaries using gdb")

	parser.add_argument("-b", metavar="-B", type=str, help="The Bianry to analyze", default = None)
	parser.add_argument("-o", metavar="-O", type=str, help="The output file", default = None)
	parser.add_argument("-c", metavar="-C", type=str, help="Give command to look for specific thing", default=None)

	cmd_args = parser.parse_args()

	dynamic_analyzer = DynamicAnalyzer()

	dynamic_analyzer.target_binary = cmd_args.b
	dynamic_analyzer.output_file = cmd_args.o
	dynamic_analyzer.cmd = cmd_args.c


	# Check to ensure we have a binary
	if dynamic_analyzer.target_binary is None:
		help_function()

	print("\n\nRunning Dynamic Analyzer\n\n")

	for i in range(0, 5):
		dynamic_analyzer.setup()
		dynamic_analyzer.main_loop()