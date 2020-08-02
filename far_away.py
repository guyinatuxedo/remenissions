"""Add gdb commands for exploit verification"""

SYSTEM_STRING = ["flag", "cat", "sh", "bash"]
PRINT_STRINGS = ["flag{"]

CALLING_CONVENETION_X64 = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

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

putcharString = ""

def parse_0x(string):
	"""Parse string for substring with 0x start"""
	start_index = string.find("0x")

	string_len = len(string)
	index = start_index + 2
	found_end = False
	while not found_end:

		if ord(string[index]) in HEX_CHARS:
			index = index + 1
			if index >= (string_len - 1):
				found_end = True
		else:
			found_end = True

	hex_string = string[start_index:index + 1]
	hex_value = int(hex_string, 16)

	return hex_value

def contains(check_list, string):
	"""See if a list contains a portion of a string"""
	for i in check_list:
		if i in string:
			return True
	return False

def contains_list(check_list, input_list):
	"""Check if a list contains an element of another"""
	for inp in input_list:
		for check in check_list:
			if check in inp:
				return True
	return False

def pwned():
	"""Output success to output file"""
	pwned_file = open("pwned", "w")
	pwned_file.write("pwned\n")
	pwned_file.close()
	gdb.execute('q')

def not_pwned():
	"""Output failure to output file"""
	try:
		pwned_file = open("rip", "w")
		pwned_file.write("rip\n")
		pwned_file.close()
	except:
		print("output file already exists")
	gdb.execute('q')


def get_top_stack_32():
	"""Get the argument for 32 bit function"""
	value = gdb.execute("x/w $esp+0x4", False, True)
	value = value.split("\n")[0]
	value = value.split(":")[1]
	value = int(value, 16)
	return value

def get_first_arg_32():
	"""Get the argument for 32 bit function as string"""
	address_arg = gdb.execute("x/w $esp+0x4", False, True).split(":	")[1]
	argument = gdb.execute("x/s %s" % address_arg, False, True)
	return argument

def get_syscall_first_arg_32():
	"""Get the argument for 32 bit syscall"""
	address_arg = gdb.execute("x/w $esp", False, True).split(":	")[1]
	argument = gdb.execute("x/s %s" % address_arg, False, True)
	return argument

def get_first_arg_64():
	"""Get the argument for 64 bit function as string"""
	argument = gdb.execute("x/s $rdi", False, True)
	return argument

def get_syscall_first_arg_64():
	"""Get the argument for 64 bit syscall"""
	return get_first_arg_64()

def get_string_args_64(num_args):
	"""Get the arguments for 64 bit function call as string"""
	args = []
	if num_args > len(CALLING_CONVENETION_X64) - 1:
		num_args = len(CALLING_CONVENETION_X64) - 1
	for i in range(0, num_args):
		register = CALLING_CONVENETION_X64[i]
		args.append(gdb.execute("x/s $%s" % register, False, True))
	return args

def get_string_args_32(num_args):
	"""Get the arguments for 32 bit function call as string"""
	args = []
	for i in range(0, num_args):
		gdb.execute("x/x $esp+%d" % ((i+1)*4))
		address_arg = gdb.execute("x/w $esp+%d" % ((i+1)*4), False, True).split(":	")[1]
		argument = gdb.execute("x/s %s" % address_arg, False, True)
		args.append(argument)
	return args

def get_rdi_int():
	"""Get the value of rdi"""
	rdi_string = gdb.execute("p $rdi", False, True).split(" ")[-1]
	rdi_value = int(rdi_string, 16)
	return rdi_value

def analyze_system(arch):
	"""Analyze a call to 'system' to see if exploit worked"""
	if arch == "amd64":
		argument = get_first_arg_64()
		#argument = gdb.execute("x/s $rdi", False, True)
		if contains(SYSTEM_STRING, argument):
			pwned()
			return

	elif arch == "i386":
		argument = get_first_arg_32()
		if contains(SYSTEM_STRING, argument):
			pwned()
			return

def analyze_syscall(arch):
	"""Analyze a syscall to see if exploit worked"""
	if arch == "i386":
		previous_cmd = gdb.execute("x/i $eip-2", False, True)
		if "int" and "0x80" in previous_cmd:
			argument = get_syscall_first_arg_32()

			if contains(SYSTEM_STRING, argument):
				pwned()
		else:
			return False

	elif arch == "amd64":
		previous_cmd = gdb.execute("x/i $rip-2", False, True)
		if "syscall" in previous_cmd:
			argument = get_syscall_first_arg_64()
			if contains(SYSTEM_STRING, argument):
				pwned()
		else:
			return False

def analyze_putchar(arch):
	"""Analyze a call to 'putchar' to see if exploit worked"""
	global putcharString
	if arch == "amd64":
		argument = get_rdi_int()
		if putcharString[-1:] != chr(argument):
			putcharString += chr(argument)
		if contains(PRINT_STRINGS, putcharString):
			pwned()
	elif arch == "i386":
		argument = get_top_stack_32()
		if putcharString[-1:] != chr(argument):
			putcharString += chr(argument)
		if contains(PRINT_STRINGS, putcharString):
			pwned()
	return False


def analyze_puts(arch):
	"""Analyze a call to 'puts' to see if exploit worked"""
	if arch == "amd64":
		argument = get_first_arg_64()
		if contains(PRINT_STRINGS, argument):
			pwned()

	elif arch == "i386":
		argument = get_first_arg_32()
		if contains(PRINT_STRINGS, argument):
			pwned()

def analyze_printf(arch):
	"""Analyze a call to 'printf' to see if exploit worked"""
	if arch == "amd64":
		argument = get_first_arg_64()
		num_args = argument.count("%") + 1
		arguments = get_string_args_64(num_args)
		if contains_list(PRINT_STRINGS, arguments):
			pwned()

	elif arch == "i386":
		argument = get_first_arg_32()
		num_args = argument.count("%") + 1
		arguments = get_string_args_32(num_args)
		if contains_list(PRINT_STRINGS, arguments):
			pwned()

def run_analysis(inp, arch):
	"""Run the analysis on a function call or syscall"""
	functions = ANALYSIS_FUNCTIONS.keys()
	for function in functions:
		if function in inp:
			ANALYSIS_FUNCTIONS[function](arch)
		else:
			analysis = ANALYSIS_FUNCTIONS["syscall"](arch)
	if not analysis:
		return False
	else:
		return True

ANALYSIS_FUNCTIONS = {
						"puts":analyze_puts,
						"printf":analyze_printf,
						"system":analyze_system,
						"syscall":analyze_syscall,
						"putchar":analyze_putchar
					}

class GetLibcPutsAddress(gdb.Command):
	"""Class for 'get_libc_puts_address' command, outputs puts address to file"""

	def __init__(self):
		"""Initialize the class"""
		super(GetLibcPutsAddress, self).__init__("get_libc_puts_address", gdb.COMMAND_DATA)

	def invoke(self, arg, from_tty):
		"""Function where code for the command is stored"""
		arch_output = gdb.execute("show architecture", False, True)

		if "x86-64" in arch_output:
			arch = "amd64"
		elif "currently i386" in arch_output:
			arch = "i386"
		puts_address_output = gdb.execute("print puts", False, True)
		puts_address = parse_0x(puts_address_output)

		output_file = open("far-cry", "w")
		output_file.write(hex(puts_address))
		output_file.close()

		gdb.execute("q")


class VerifyExploitStatic(gdb.Command):
	"""Class for 'verify_exploit_static' command, handles exploit verification for statically linked"""
	def __init__(self):
		"""Initialize the class"""
		super(VerifyExploitStatic, self).__init__("verify_exploit_static", gdb.COMMAND_DATA)

	def invoke(self, arg, from_tty):
		"""Function where code for the command is stored"""
		arch_output = gdb.execute("show architecture", False, True)


		if "x86-64" in arch_output:
			arch = "amd64"
		elif "currently i386" in arch_output:
			arch = "i386"

		gdb.execute("catch syscall execve")
		gdb.execute("c")

		loops = 0
		try:
			while True:
				if arch == "amd64":
					instruction = gdb.execute("x/i $rip", False, True)
				elif arch == "i386":
					instruction = gdb.execute("x/i $eip", False, True)

				analysis_check = run_analysis(instruction, arch)

				if not analysis_check:
					back_trace = gdb.execute("bt", False, True)
					called_function = back_trace.split("\n")[0]
					analysis_check = run_analysis(called_function, arch)

				gdb.execute("c")
				loops += 1
		except:
			not_pwned()

class VerifyExploit(gdb.Command):
	"""Class for 'verify_exploit' command, handles most exploit verification"""
	def __init__(self):
		"""Initialize the class"""
		super(VerifyExploit, self).__init__("verify_exploit", gdb.COMMAND_DATA)

	def invoke(self, arg, from_tty):
		"""Function where code for the command is stored"""
		arch_output = gdb.execute("show architecture", False, True)
		if "x86-64" in arch_output:
			arch = "amd64"
		elif "currently i386" in arch_output:
			arch = "i386"

		gdb.execute("catch syscall execve")

		gdb.execute("b *system")


		gdb.execute("b *printf")
		gdb.execute("b *puts")
		gdb.execute("b *putchar")

		gdb.execute("c")


		loops = 0

		try:
			while True:
				if arch == "amd64":
					instruction = gdb.execute("x/i $rip", False, True)
				elif arch == "i386":
					instruction = gdb.execute("x/i $eip", False, True)

				analysis_check = run_analysis(instruction, arch)

				if not analysis_check:
					back_trace = gdb.execute("bt", False, True)
					called_function = back_trace.split("\n")[0]
					analysis_check = run_analysis(called_function, arch)
				gdb.execute("c")
				loops += 1
		except:
			not_pwned()

# This registers our class to the gdb runtime at "source" time.
VerifyExploit()
VerifyExploitStatic()
GetLibcPutsAddress()
