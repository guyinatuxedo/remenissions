# Our imported libraries
import ghidra.program.model.pcode.PcodeOp
import argparse
import pickle
import sys
import os

'''
+-----------------------------------------------------------+
|                    Vuln Detection Checks                  |
+-----------------------------------------------------------+
'''

def analyze_gets(static_analyzer, function):
	# Check all of the references to the function, find the one that is a call
	references_to = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint())
	for reference in references_to:
		reference_type = str(reference.getReferenceType())
		if (reference_type != "UNCONDITIONAL_CALL"):
			continue

		address, call_pcodes, calling_function = static_analyzer.process_reference(reference)

		# Iterate through the pcodes for the function reference, find the one that is a function call
		for call_pcode in call_pcodes:
			if call_pcode.getOpcode() != ghidra.program.model.pcode.PcodeOp.CALL:
				continue

			# Check if it is a bug
			# An actual function call to gets() will always be a vuln
			offset = static_analyzer.stack_offset_from_varnode(call_pcode.getInput(1))
			static_analyzer.log_stack(function, calling_function, address, offset, "stdin")

def analyze_read(static_analyzer, function):
	references_to = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint())
	for reference in references_to:
		if str(reference.getReferenceType()) != "UNCONDITIONAL_CALL":
			continue
		address, call_pcodes, calling_function = static_analyzer.process_reference(reference)
		for call_pcode in call_pcodes:
			if call_pcode.getOpcode() != ghidra.program.model.pcode.PcodeOp.CALL:
				continue

			buff = call_pcode.getInput(2)
			size = call_pcode.getInput(3).getOffset()
			offset = static_analyzer.stack_offset_from_varnode(buff)

			# Check if we can overflow it
			if check_overflow(calling_function, offset, size) == True:
				static_analyzer.log_stack(function, calling_function, address, offset, "stdin", size)
			# If it isn't a buffer overflow, mark it as an input
			else:
				static_analyzer.log_input(function, calling_function, address, offset, "stdin", size)

def analyze_fgets(static_analyzer, function):
	references_to = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint())
	for reference in references_to:
		if str(reference.getReferenceType()) != "UNCONDITIONAL_CALL":
			continue
		address, call_pcodes, calling_function = static_analyzer.process_reference(reference)

		for call_pcode in call_pcodes:
			if call_pcode.getOpcode() != ghidra.program.model.pcode.PcodeOp.CALL:
				continue
			buff = call_pcode.getInput(1)
			size = call_pcode.getInput(2).getOffset()

			offset = static_analyzer.stack_offset_from_varnode(buff)

			if check_overflow(calling_function, offset, size) == True:
				static_analyzer.log_stack(function, calling_function, address, offset, "stdin", size)
			# If it isn't a buffer overflow, mark it as an input				
			else:
				static_analyzer.log_input(function, calling_function, address, offset, "stdin", size)

def analyze_scanf(static_analyzer, function):
	references_to = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint())	
	for reference in references_to:
		if str(reference.getReferenceType()) != "UNCONDITIONAL_CALL":
			continue
		address, call_pcodes, calling_function = static_analyzer.process_reference(reference)

		for call_pcode in call_pcodes:
			if call_pcode.getOpcode() != ghidra.program.model.pcode.PcodeOp.CALL:
				continue
			inps = call_pcode.getInputs()
			string = static_analyzer.get_string(call_pcode.getInput(1))
			buff = call_pcode.getInput(2)
			offset = static_analyzer.stack_offset_from_varnode(buff)

			# Check the format string, to see how much data we can scan in
			size = check_scanf_fmt_string(string)
			if size == True:
				static_analyzer.log_stack(function, calling_function, address, offset, "stdin")
			else:
				if check_overflow(calling_function, offset, size) == True:
					static_analyzer.log_stack(function, calling_function, address, offset, "stdin", size)
				# If it isn't a buffer overflow, mark it as an input		
				else:
					static_analyzer.log_input(function, calling_function, address, offset, "stdin", size)

def analyze_fscanf(static_analyzer, function):
	references_to = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint())
	for reference in references_to:
		if str(reference.getReferenceType()) != "UNCONDITIONAL_CALL":
			continue
		address, call_pcodes, calling_function = static_analyzer.process_reference(reference)

		for call_pcode in call_pcodes:
			if call_pcode.getOpcode() != ghidra.program.model.pcode.PcodeOp.CALL:
				continue
			inps = call_pcode.getInputs()
			string = static_analyzer.get_string(call_pcode.getInput(2))
			buff = call_pcode.getInput(3)
			offset = static_analyzer.stack_offset_from_varnode(buff)

			# Check the format string, to see how much data we can scan in
			size = check_scanf_fmt_string(string)
			if size == True:
				static_analyzer.log_stack(function, calling_function, address, offset, "stdin")
			else:
				if check_overflow(calling_function, offset, size) == True:
					static_analyzer.log_stack(function, calling_function, address, offset, "stdin", size)
				else:
					static_analyzer.log_input(function, calling_function, address, offset, "stdin", size)

def analyze_fread(static_analyzer, function):
	references_to = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint())
	for reference in references_to:

		if str(reference.getReferenceType()) != "UNCONDITIONAL_CALL":
			continue
		address, call_pcodes, calling_function = static_analyzer.process_reference(reference)

		for call_pcode in call_pcodes:
			if call_pcode.getOpcode() != ghidra.program.model.pcode.PcodeOp.CALL:
				continue
			buff = call_pcode.getInput(1)
			size = call_pcode.getInput(2).getOffset() * call_pcode.getInput(3).getOffset()
			offset = static_analyzer.stack_offset_from_varnode(buff)

			if check_overflow(calling_function, offset, size) == True:
				static_analyzer.log_stack(function, calling_function, address, offset, "stdin", size)
			else:
				static_analyzer.log_input(function, calling_function, address, offset, "stdin", size)

def analyze_strcpy(static_analyzer, function):
	references_to = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint())
	for reference in references_to:
		reference_type = str(reference.getReferenceType())
		if (reference_type != "UNCONDITIONAL_CALL"):
			continue

		address, call_pcodes, calling_function = static_analyzer.process_reference(reference)
		for call_pcode in call_pcodes:
			if call_pcode.getOpcode() != ghidra.program.model.pcode.PcodeOp.CALL:
				continue

			# Get the source, and destination
			destination = call_pcode.getInput(1)
			source = call_pcode.getInput(2)

			source_stack_offset = static_analyzer.stack_offset_from_varnode(source)
			furthest_stack_variable = get_furthest_stack_varaible(calling_function)

			# Check that the input is coming from a value not from this stack frame
			# Reason for it being
			# In a lot of instances, this check is essentially seeing if it's coming from argv
			# Which is on the stack, but the offset will be outside of the current stack frame
			# This check doesn't verify that the input is from argv, just that it's a possibillity

			if (source_stack_offset > furthest_stack_variable) or (source_stack_offset == False):
				destination_offset = static_analyzer.stack_offset_from_varnode(destination)
				offset = static_analyzer.stack_offset_from_varnode(destination)
				static_analyzer.log_stack(function, calling_function, address, offset, "argv")


def analyze_strncpy(static_analyzer, function):
	references_to = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint())
	for reference in references_to:
		reference_type = str(reference.getReferenceType())
		if (reference_type != "UNCONDITIONAL_CALL"):
			continue
		address, call_pcodes, calling_function = static_analyzer.process_reference(reference)

		for call_pcode in call_pcodes:
			if call_pcode.getOpcode() != ghidra.program.model.pcode.PcodeOp.CALL:
				continue

			destination = call_pcode.getInput(1)
			source = call_pcode.getInput(2)
			size = call_pcode.getInput(3).getOffset()
			furthest_stack_variable = get_furthest_stack_varaible(calling_function)
			source_stack_offset = static_analyzer.stack_offset_from_varnode(source)
			furthest_stack_variable = get_furthest_stack_varaible(calling_function)
			destination_offset = static_analyzer.stack_offset_from_varnode(destination)

			# Check to see if the input could be from argv, and continue if not
			if (source_stack_offset <= furthest_stack_variable):
				continue

			# Check for an overflow
			if check_overflow(calling_function, destination_offset, size) == True:
				destination_offset = static_analyzer.stack_offset_from_varnode(destination)
				offset = static_analyzer.stack_offset_from_varnode(destination)
				static_analyzer.log_stack(function, calling_function, address, offset, "argv")


def analyze_printf(static_analyzer, function):
	references_to = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint())
	for reference in references_to:
		if str(reference.getReferenceType()) != "UNCONDITIONAL_CALL":
			continue

		address, call_pcodes, calling_function = static_analyzer.process_reference(reference)
		for call_pcode in call_pcodes:
			if call_pcode.getOpcode() != ghidra.program.model.pcode.PcodeOp.CALL:
				continue

			# Check if the number of arguments to the function is 1
			# Which would correspond to a fmt string
			num_inputs = len(call_pcode.getInputs())
			if num_inputs == 2:
				stack_offset = static_analyzer.stack_offset_from_varnode(call_pcode.getInput(1))
				static_analyzer.log_fmt_string(function, calling_function, address, stack_offset)

			# Get the string argument to printf
			inps = call_pcode.getInputs()
			string = static_analyzer.get_string(inps[1])
			if string == None:
				continue

			# Parse out the format strings to it
			fmt_strings = parse_fmt_strings(string)
			for i in range(0, len(fmt_strings)):
				# Check to continue if the format string is not to a memory pointer (%p)
				if ("p" not in fmt_strings[i]):
					continue

				# Check the memory region of the leaked value
				varnodeAdr = inps[i+2]
				offset = offset_from_varnode(varnodeAdr)
				if offset is not None:
					offset = offset & 0xfffeffff
				addressRegion = check_address_region(offset, calling_function)

				if (addressRegion == "pie-stack"):
					# In this situation, a bit ambigous if it's either pie or stack, so just log as both
					# It will lead to a performance hit as result of attempting attacks that won't succeed
					# but will lead to more challenges being able to be solved
					offset = offset_from_varnode(varnodeAdr)
					static_analyzer.log_infoleak(function, address, string, offset, i, "pie")	
					offset = static_analyzer.stack_offset_from_varnode(varnodeAdr)
					static_analyzer.log_infoleak(function, address, string, offset, i, "stack")	
					continue

				if addressRegion == "stack":
					offset = static_analyzer.stack_offset_from_varnode(varnodeAdr)
					if (offset != False):
						# Log a stack infoleak
						static_analyzer.log_infoleak(function, address, string, offset, i, addressRegion)	
						continue

				# Log it as either libc or pie
				if addressRegion == "libc":
					symbol = get_symbol(offset)
					if symbol != None:
						static_analyzer.log_infoleak(function, address, string, symbol, i, addressRegion)											
					else:
						static_analyzer.log_infoleak(function, address, string, offset, i, addressRegion)	
				elif addressRegion == "pie":
					static_analyzer.log_infoleak(function, address, string, offset, i, addressRegion)	


'''
+-----------------------------------------------------------+
|                   Win Function Detection                  |
+-----------------------------------------------------------+
'''

def check_win_system(static_analyzer, function):
	check_win_single_arg(static_analyzer,SYS_WIN_ARGS, function)

def check_win_execve(static_analyzer, function):
	check_win_single_arg(static_analyzer,SYS_WIN_ARGS, function)

def check_win_open(static_analyzer, function):
	check_win_single_arg(static_analyzer,OPEN_WIN_ARGS, function)

def check_win_fopen(static_analyzer, function):
	check_win_single_arg(static_analyzer,OPEN_WIN_ARGS, function)

# Here I check if the function's argument has the desired strings
def check_win_single_arg(static_analyzer, winStrings, function):
	references_to = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint())
	for reference in references_to:

		if str(reference.getReferenceType()) != "UNCONDITIONAL_CALL":
			continue	
		address, call_pcodes, calling_function = static_analyzer.process_reference(reference)
		for call_pcode in call_pcodes:
			if call_pcode.getOpcode() != ghidra.program.model.pcode.PcodeOp.CALL:
				continue
			string = static_analyzer.get_string(call_pcode.getInput(1))
			if string == "":
				# This is for when death stranding can't find the string
				static_analyzer.possible_alt_win_funcs.append(address_to_hex(getFunctionContaining(reference.getFromAddress()).getEntryPoint()))
				continue
			# Check if the string argument contains the desired strings
			static_analyzer.check_string(string, winStrings, reference)	

'''
+-----------------------------------------------------------+
|                      Bug Construction                     |
+-----------------------------------------------------------+
'''

def construct_stack_bug(function, calling_function, address, overwriteable_vars, checks, calledPtrs, inpType, writeSize):
	stack_bug = {}
	stack_bug["type"] = "stack"
	stack_bug["function"] = function
	stack_bug["callingFunction"] = calling_function
	stack_bug["address"] = address
	stack_bug["overwriteableVars"] = overwriteable_vars
	stack_bug["checks"] = checks
	stack_bug["calledPtrs"] = calledPtrs
	stack_bug["inpType"] = inpType
	stack_bug["writeSize"] = writeSize
	return stack_bug

def construct_infoleak_bug(function, callingFunction, address, memoryRegion, string, offset, fmtIndex):
	infoleak_bug = {}
	infoleak_bug["type"] = "infoleak"
	infoleak_bug["function"] = function
	infoleak_bug["callingFunction"] = callingFunction
	infoleak_bug["address"] = address
	infoleak_bug["memoryRegion"] = memoryRegion
	infoleak_bug["string"] = string
	infoleak_bug["offset"] = offset
	infoleak_bug["fmtIndex"] = fmtIndex
	return infoleak_bug

def construct_possible_fmt_string(name, calling_function_name, address, stack_offset):
	possible_fmt_string_bug = {}
	possible_fmt_string_bug["type"] = "possibleFmtString"
	possible_fmt_string_bug["function"] = name
	possible_fmt_string_bug["callingFunction"] = calling_function_name
	possible_fmt_string_bug["address"] = address
	possible_fmt_string_bug["stackOffset"] = stack_offset
	return possible_fmt_string_bug

def construct_input(name, calling_function_name, address, stack_offset, checks, calledPtrs, inpType, writeSize):
	inp = {}
	inp["type"] = "input"
	inp["function"] = name
	inp["callingFunction"] = calling_function_name
	inp["address"] = address
	inp["stackOffset"] = stack_offset
	inp["checks"] = checks
	inp["calledPtrs"] = calledPtrs
	inp["inpType"] = inpType
	inp["writeSize"] = writeSize
	return inp

'''
+-----------------------------------------------------------+
|                      General Utillity                     |
+-----------------------------------------------------------+
'''

# These are more generic helpfer functions that didn't fit into a different category

# Convert a string address to hex
def address_to_hex(addr):
	return int("0x" + str(addr), 16)

# Check if a list of strings exists inside a string
def check_string_bool(string, target_strings):
	for arg in target_strings:
		if arg in string:
			return True
	return False

# Get the next instruction after an address
def get_next_ins(address):
	insSize = len(getInstructionAt(toAddr(address)).getBytes())
	next_adr = address + insSize + 1
	return next_adr

# Helper function to check if there is an overflow
def check_overflow(calling_function, stack_offset, size):
	stack_vars = parse_stack_vars(calling_function)
	write_until = stack_offset - size
	last_var = get_last_variable(stack_vars)
	if (len(stack_vars) == 1) and (size > stack_offset):
		return True
	for stack_var in stack_vars:
		if stack_var < stack_offset and stack_var > write_until:
			return True
	if stack_offset == last_var and (size > stack_offset):
		return True
	return False

# A fucntion to get the address being jumped to in a conditional
def process_branch(pcode):
	opCode = pcode.getOpcode()
	if (opCode == ghidra.program.model.pcode.PcodeOp.CBRANCH) or (opCode == ghidra.program.model.pcode.PcodeOp.BRANCH):
		address = pcode.getInput(0).getOffset()
		if address != None:
			return address, True
	return False, False

# Get the constant, and the variable arguments from a compare
def parse_cmp_varnodes(varnodes):
	if varnodes[0].isConstant() == True:
		return varnodes[1], varnodes[0]
	else:
		return varnodes[0], varnodes[1]

'''
+-----------------------------------------------------------+
|                     pcodes Functionallity                 |
+-----------------------------------------------------------+
'''

# A function to generate a list of opcodes
def count_ops(pcode_ops):
	x = []
	for i in pcode_ops:
		x.append(i)
	return x

# These next functions assist with finding pcode blocks
def get_closest_block(address, pcode_blocks):
	likely_block = None
	smallest_offset = 99999
	address = address_to_hex(address)
	for block in pcode_blocks:
		startAdr = address_to_hex(block.getStart())
		if address < startAdr:
			offset = startAdr - address
			if offset < smallest_offset:
				likely_block = block
	return likely_block

def get_block_w_addr(address, pcode_blocks):
	for pcode_block in pcode_blocks:
		if pcode_block.contains(address) == True:
			return pcode_block
	return get_closest_block(address, pcode_blocks)

def get_next_block(block, pcode_blocks):
	next_adr = get_next_ins(address_to_hex(block.getStop()))
	return get_block_w_addr(toAddr(next_adr), pcode_blocks)

'''
+-----------------------------------------------------------+
|              Varnode / String Functionallity              |
+-----------------------------------------------------------+
'''

# This will parse a string, and return a list of all of the format strings in it
def parse_fmt_strings(string):
	fmt_strings = []
	for i in range(0, len(string)):
		if string[i] == "%":
			c = i + 1
			while string[c] not in FMT_TYPES:
				c += 1
			fmt_strings.append(string[i:c + 1])
			i = c
	return fmt_strings

# Checkk a scanf string, to see how many bytes we can scan in
# Currently only support for "%s" strings, like "%s" and "%20s"
def check_scanf_fmt_string(string):
	if string == "":
		return True
	fmt_str = parse_fmt_strings(string)
	fmt_str = fmt_str[0]

	if "s" in fmt_str:
		if len(fmt_str) == 2:
			return True
		else:
			fmt_str = fmt_str[1:-1]
			return int(fmt_str)
	else:
		return 0

# This function here is used when an argument, is a ptr, to a ptr, to a ptr (etc), to a string
# It will essentially dereference a memory address, until it gets something that is not a ptr
def rec_get_string(data):
	if "addr" in str(data):
		data = data[5:]
		if toAddr(int(data, 16)).isMemoryAddress() == True:	
			data = getDataAt(toAddr(data))
			return str(rec_get_string(data))	
	else:
		return data


'''
+-----------------------------------------------------------+
|                Memory Region Functionallity               |
+-----------------------------------------------------------+
'''

# Get the offset from the varnode, in the pie memeory region
def pie_offset_from_varnode(varnode):
	varnode_def = varnode.getDef()
	if varnode_def == None:
		return varnode.getOffset()
	inps = varnode_def.getInputs()
	for inp in inps:
		if inp.isConstant() == True:
			if inp.getOffset() > 0:
				return inp.getOffset()

# Basic functionallity for getting an offset from a a varnode
def offset_from_varnode(varnode):
	dec_varnode = varnode.getDef()
	if dec_varnode != None:
		dec_inputs = dec_varnode.getInputs()
		min_addr = address_to_hex(currentProgram.getMinAddress())

		for inp in dec_inputs:
			if inp.isConstant() == True:
				offset = int(abs(inp.getOffset()))
				if offset >= min_addr and offset != 0:
					return offset
	else:
		return int(abs(varnode.getOffset()))


# Function to rename certain functions
def rename_functions(plt_funcs):
	plt_funcs_reversed = dict([[x, y] for y, x in plt_funcs.items()])
	function = getFirstFunction()
	while function is not None:
		func_entry = int("0x%s" % str(function.getEntryPoint()), 16)
		if func_entry in plt_funcs.values():
			func_name = str(plt_funcs_reversed[func_entry])
			if (func_name in WIN_FUNCS.keys()) or (func_name in TARGET_FUNCTIONS.keys()):
				function.setName(func_name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
		function = getFunctionAfter(function)

# Function to rebase the memory regions, by subtracting a value
def rebase_minus_offset(offset):
	blocks = currentProgram.getMemory().getBlocks()
	try:
		for block in blocks:
			start_adr = address_to_hex(block.getStart())
			if (start_adr - offset) > 0:
				new_start_adr = start_adr - offset
				currentProgram.getMemory().moveBlock(block, toAddr(new_start_adr), monitor) 
	except:
		return
# Function to rebase the memory regions, by adding a value
def rebase_plus_offset(offset):
	blocks = currentProgram.getMemory().getBlocks()
	try:
		for block in blocks:
			startAdr = address_to_hex(block.getStart())
			#if (startAdr - offset) > 0:
			newStartAdr = startAdr + offset
			currentProgram.getMemory().moveBlock(block, toAddr(newStartAdr), monitor) 
	except:
		return

# Function to generate the rebased address
def rebase_ghidra_pie(offset):
	if (offset & 0x100000):
		return offset & 0xffffffffffefffff
	return offset 

# Function to get the range of a function's stack frame
def get_stack_range(function):
	stack_vars = []
	for i in function.getStackFrame().getLocals():
		stack_vars.append(abs(i.getStackOffset()))
	stack = {}
	stack["end"] = max(stack_vars)
	stack["begin"] = min(stack_vars)
	return stack

# Check what memory region an address is in
def check_address_region(address, calling_function):
	blocks = currentProgram.getMemory().getBlocks()
	got_begin, got_end = get_got_bounds(blocks)
	pie_begin, pie_end = get_pie_bounds(blocks)

	stackRange = get_stack_range(calling_function)

	# This happens when pie is enabled, we're not sure which region it is from
	if (address >= pie_begin) and (address <= pie_end) and (address >= stackRange["begin"]) and (address <= stackRange["end"]):
		return "pie-stack"

	if ((address >= got_begin) and (address <= got_end)):
		return "libc"

	elif (address >= pie_begin) and (address <= pie_end):
		return "pie"

	else:
		return "stack"

# Get the range of addresses for the pie segment
def get_pie_bounds(blocks):
	bounds = []
	begin = int(str(blocks[0].getStart()), 16)
	end = 0
	try:
		i = 0
		while True:
			end = int(str(blocks[i].getEnd()), 16)
			i += 1
	except:
		return begin, end

# Get the addresses of where the got table is
def get_got_bounds(blocks):
	for block in blocks:
		if block.getName() == "EXTERNAL":
			start = address_to_hex(block.getStart())
			end = address_to_hex(block.getEnd())
			return start, end

# Check if address is a valid pie address, by grabbing the value at it
# If it's something like a stack address, then it will only have a value at one time, and thus fail
def is_valid_pie_address(address):
	try:
		getByte(toAddr(address))
		return True
	except:
		return False

# Function to get the stack variable farthest from the return address
def get_furthest_stack_varaible(function):
	variables = function.getLocalVariables()
	highest_variable = 0
	for variable in variables:
		current_variable = variable.getStackOffset()
		current_variable = abs(current_variable)
		if current_variable > highest_variable:
			highest_variable = current_variable
	return highest_variable

# Get the function that corresponds to an address
def get_symbol(address):
	function = getFirstFunction()
	while function != None:
		if address_to_hex(function.getEntryPoint()) == address:
			func_name = str(function.getName())
			return func_name
		function = getFunctionAfter(function)
	return None

# A function to check if a function is a Got entry
def check_got(function):
	calling_functions = function.getCallingFunctions(monitor)
	if (len(calling_functions) == 1):
		for i in calling_functions:
			if str(i) == function.getName():
				return True
	return False

# A function to just return the last item in a list
def get_last_variable(stack_variables):
	x = None
	for stack_var in stack_variables:
		x = stack_var
	return x

# Grab a list of stack variables from a function
def parse_stack_vars(callingFunction):
	stack_layout = callingFunction.getStackFrame()
	stack_locals = stack_layout.getLocals()
	stack_vars = []
	for stack_local in stack_locals:
		 stack_vars.append(int(abs(stack_local.getStackOffset())))
	return stack_vars

class StaticAnalyzer():
	def __init__(self):
		self.orig_got_start = None
		self.orig_got_end = None

		self.pie_enabled = False

		self.arch = None

		self.output_file = None
		self.win_conds_output_file = None

		self.decomp = None

		self.alt_win_funcs = []
		self.possible_alt_win_funcs = []

	# Check if a list of substrings is present in a larger string
	# Used to determine alternate win conditions
	def check_string(self, string, target_strings, reference):
		for arg in target_strings:
			if arg in string:
				self.alt_win_funcs.append(address_to_hex(getFunctionContaining(reference.getFromAddress()).getEntryPoint()))			


	def get_arch(self):
		current_arch = str(currentProgram.getLanguage())
		if "32" in current_arch:
			self.arch = "i386"
		else:
			self.arch = "amd64"

	def setup_decompiler(self):
		options = ghidra.app.decompiler.DecompileOptions()
		self.decomp = ghidra.app.decompiler.DecompInterface()
		self.decomp.setOptions(options)
		self.decomp.toggleCCode(True)
		self.decomp.toggleSyntaxTree(True)
		self.decomp.setSimplificationStyle("decompile")
		self.decomp.openProgram(currentProgram)

	# Check for alternate win conditions
	def check_win_conditions(self):
		function = getFirstFunction()
		while function is not None:
			func_name = function.getName()
			if func_name in WIN_FUNCS.keys():
				if check_got(function) == False:
					WIN_FUNCS[func_name](self, function)
			function = getFunctionAfter(function)
		self.report_alt_win_conditions()

	# Check for vulnerabillities
	def check_target_functions(self):
		function = getFirstFunction()
		while function is not None:
			func_name = function.getName()
			if func_name in TARGET_FUNCTIONS.keys():
				if check_got(function) == False:
					TARGET_FUNCTIONS[func_name](self, function)
			function = getFunctionAfter(function)




	'''
	+-----------------------------------------------------------+
	|                          Reporting                        |
	+-----------------------------------------------------------+
	'''

	def log_stack(self, function, calling_function, address, stack_offset, inpType, writeSize = None):
		name = function.getName()
		stack_vars = parse_stack_vars(calling_function)
		calling_function = getFunctionContaining(toAddr(address))
		calling_function_name = calling_function.getName()

		checks, calledPtrs = self.check_stack(address)

		overwriteable_vars = []
		if writeSize == None:
			for stack_var in stack_vars:
				if stack_var <= stack_offset:
					overwriteable_vars.append(stack_var)

			overwriteable_vars.append("return_address")
			stack_bug = construct_stack_bug(name, calling_function_name, address, overwriteable_vars, checks, calledPtrs, inpType, None)
			self.report(stack_bug)
		else:
			# Can reach return address
			if writeSize > stack_offset:	
				for stack_var in stack_vars:
					if stack_var <= stack_offset:
						overwriteable_vars.append(stack_var)
				overwriteable_vars.append("return_address")
				stack_bug = construct_stack_bug(name, calling_function_name, address, overwriteable_vars, checks, calledPtrs, inpType, writeSize - stack_offset)
				self.report(stack_bug)

			else:
				# Can't reach return address
				write_until = stack_offset - writeSize
				xbytes = writeSize
				for stack_var in stack_vars:
					if stack_var <= stack_offset and stack_var > write_until:
						overwriteable_vars.append(stack_var)
				stack_bug = construct_stack_bug(name, calling_function_name, address, overwriteable_vars, checks, calledPtrs, inpType, writeSize)
				self.report(stack_bug)

	def log_input(self, function, callingFunction, address, stack_offset, inpType, writeSize):
		name = function.getName()
		stack_vars = parse_stack_vars(callingFunction)
		callingFunction = getFunctionContaining(toAddr(address))
		calling_function_name = callingFunction.getName()

		# Check for called ptrs / checks
		checks, calledPtrs = self.check_stack(address)

		inp = construct_input(name, calling_function_name, address, stack_offset, checks, calledPtrs, inpType, writeSize)
		self.report_file(inp)

	def log_infoleak(self, function, address, string, offset, fmtIndex, memoryRegion):
		name = function.getName()
		callingFunction = getFunctionContaining(toAddr(address))
		calling_function_name = callingFunction.getName()

		infoleak_bug = construct_infoleak_bug(name, calling_function_name, address, memoryRegion, string, offset, fmtIndex)
		self.report(infoleak_bug)

	def log_fmt_string(self, function, callingFunction, address, stack_offset):
		name = function.getName()
		stack_vars = parse_stack_vars(callingFunction)
		callingFunction = getFunctionContaining(toAddr(address))
		calling_function_name = callingFunction.getName()

		possible_fmt_string_bug = construct_possible_fmt_string(name, calling_function_name, address, stack_offset)
		self.report(possible_fmt_string_bug)

	# Function to report alternate win condition
	def report_alt_win_conditions(self):
			# Print newlines for nice output formatting
			print("\n\n\n\n")

			# Our output file, for alternate win conditions
			if self.win_conds_output_file != None:

				# Our output file, for alternate win conditions
				if os.path.exists(self.win_conds_output_file):

					# Our output file, for alternate win conditionsFile):
					os.remove(self.win_conds_output_file)

				outputFile = open(self.win_conds_output_file, "w")

				pickle.dump(self.alt_win_funcs, outputFile)
				pickle.dump(self.possible_alt_win_funcs, outputFile)

				outputFile.close()

			if not (self.alt_win_funcs == self.possible_alt_win_funcs == []):
				print("+-------------------------------------------------------------------------+\n|                         Alternate Win Functions                         |\n+-------------------------------------------------------------------------+")
				print("Alternate Win Function Addresses: \t\t%s" % str(self.alt_win_funcs))
				print("Possible Alternate Win Function Addresses: \t%s" % str(self.possible_alt_win_funcs))
				print("\n\n\n\n")

	def report_file(self, data):
		if os.path.exists(self.output_file):
			output = open(self.output_file, "a")
		else:
			output = open(self.output_file, "w")
		pickle.dump(data, output)
		output.close()

	def report(self, bug):
		if self.output_file != None:
			self.report_file(bug)

		if bug["type"] == "stack":
			print("+-------------------------------------------------------------------------+\n|                          Stack Buffer Overflow                          |\n+-------------------------------------------------------------------------+")
			print("Function:\t\t\t%s" % bug["function"])
			print("Calling Function:\t\t%s" % str(bug["callingFunction"]))
			print("Address:\t\t\t%s" % hex(bug["address"]))
			print("Overwriteable Values:\t\t%s" % str(bug["overwriteableVars"]))
			print("Additional Cmps:\t\t%s" % str(bug["checks"]))
			print("Indirect Calls:\t\t\t%s" % str(bug["calledPtrs"]))
			print("Input type:\t\t\t%s" % str(bug["inpType"]))
			if bug["writeSize"] != None:
				if "return_address" in bug["overwriteableVars"]:
					print("Writeable Space starting at Return Address:\t\t%s" % hex(bug["writeSize"]))
				else:
					print("Writeable Space:\t\t%s" % hex(bug["writeSize"]))
			else:
				print("Write as much as you want.")		
			print("\n\n\n\n")
		
		elif bug["type"] == "infoleak":
			print("+-------------------------------------------------------------------------+\n|                                Infoleak                                 |\n+-------------------------------------------------------------------------+")			
			print("Function:\t\t\t%s" % bug["function"])
			print("Calling Function:\t\t%s" % bug["callingFunction"])
			print("Address:\t\t\t%s"  % hex(bug["address"]))
			print("Memory Region:\t\t\t%s" % bug["memoryRegion"])
			print("String:\t\t\t\t%s"   % bug["string"])
			print("Offset:\t\t\t\t%s" % str(bug["offset"]))
			print("Fmt Str Index:\t\t\t" + str(bug["fmtIndex"]))
			print("\n\n\n\n")

		elif bug["type"] == "possibleFmtString":
			print("+-------------------------------------------------------------------------+\n|                            Possible Fmt String                          |\n+-------------------------------------------------------------------------+")	
			print("Function:\t\t\t%s" % bug["function"])
			print("Calling Function:\t\t%s" % bug["callingFunction"])
			print("Address:\t\t\t%s"  % hex(bug["address"]))
			print("Stack Offset:\t\t\t%s" % str(bug["stackOffset"]))
			print("\n\n\n\n")

		elif bug["type"] == "input":
			print("+-------------------------------------------------------------------------+\n|                                  Input                                  |\n+-------------------------------------------------------------------------+")
			print("Function:\t\t\t%s" % bug["function"])
			print("Calling Function:\t\t%s" % str(bug["callingFunction"]))
			print("Address:\t\t\t%s" % hex(bug["address"]))
			print("Stack Offset:\t\t\t%s" % str(bug["stackOffset"]))
			print("Additional Cmps:\t\t%s" % str(bug["checks"]))
			print("Indirect Calls:\t\t\t%s" % str(bug["calledPtrs"]))
			print("Input type:\t\t\t%s" % str(bug["inpType"]))
			print("Writeable Space:\t\t%s" % hex(bug["writeSize"]))
			print("\n\n\n\n")

	'''
	+-----------------------------------------------------------+
	|                           Pcodes                          |
	+-----------------------------------------------------------+
	'''

	# Helper function to get some desired values from a reference
	def process_reference(self, reference):
		address = reference.getFromAddress()
		call_pcodes = self.pcodesFromAddress(address)
		calling_function = getFunctionContaining(address)
		address = address_to_hex(address)
		return address, call_pcodes, calling_function

	# A function to get pcodes from an address
	def pcodesFromAddress(self, address):
		calling_function = getFunctionContaining(address)
		decompilation = self.decomp.decompileFunction(calling_function, self.decomp.getOptions().getDefaultTimeout(), getMonitor())
		high_function = decompilation.getHighFunction()
		Pcode_ops = high_function.getPcodeOps(address)
		return Pcode_ops



	'''
	+-----------------------------------------------------------+
	|                      Branch Analysis                      |  
	+-----------------------------------------------------------+
	'''

	# A function to get the pcodes of a code path, from an address
	def get_path_from_address(self, address):
		address = toAddr(address)
		function = getFunctionContaining(address)
		decompilation = self.decomp.decompileFunction(function, self.decomp.getOptions().getDefaultTimeout(), getMonitor())
		highFunction = decompilation.getHighFunction()
		pcode_blocks	 = highFunction.getBasicBlocks()
		working_block = get_block_w_addr(address, pcode_blocks)
		pcodes = []
		while working_block != False:
			iterator = working_block.getIterator()
			for pcode in iterator:
				pcodes.append(pcode)
				if pcode.getOpcode() == ghidra.program.model.pcode.PcodeOp.RETURN:
					return pcodes
				if pcode.getOpcode() == ghidra.program.model.pcode.PcodeOp.BRANCH:
					jmpAddress, cnd = process_branch(pcode)
					return pcodes + self.get_path_from_address(jmpAddress)
			working_block = get_next_block(working_block, pcode_blocks)
		return pcodes

	# A function to get the pcodes of a code path, from pcodes
	def get_path_from_pcodes(self, passedPcodes, highFunction):
		pcode_blocks	= highFunction.getBasicBlocks()
		pcodes = []
		for pcode in passedPcodes:
				pcodes.append(pcode)
				if pcode.getOpcode() == ghidra.program.model.pcode.PcodeOp.RETURN:
					return pcodes
				if pcode.getOpcode() == ghidra.program.model.pcode.PcodeOp.BRANCH:
					jmpAddress, cnd = process_branch(pcode)
					return pcodes + self.get_path_from_address(jmpAddress)


	'''
	0:	Want to pass
	1:	Don't want to pass
	2:	idk
	'''

	# The function which checks a pcodes branch, to see if want to take it
	def check_branch(self, pcodesBranch):
		for pcode in pcodesBranch:
			if pcode.getOpcode() == ghidra.program.model.pcode.PcodeOp.CALL:
				funcAddr = pcode.getInput(0).getOffset()
				func_name = getFunctionContaining(toAddr(funcAddr)).getName()
				if funcAddr in self.alt_win_funcs:
					return 0
				elif func_name in WIN_FUNC_STRINGS.keys():
					string = self.get_string(pcode.getInput(1))
					if check_string_bool(string, WIN_FUNC_STRINGS[func_name]) == True:
						return 0
				elif func_name in LOOSE_FUNCS:
					return 1
				else:
					return 2

	# A function which analyzes a compare, and models it
	def process_cmp(self, pcodeOps, i, branchType, highFunction):
		variableInput, constantInput = parse_cmp_varnodes(pcodeOps[i].getInputs())

		size = constantInput.getSize()

		value = int(constantInput.getOffset())
		if value < 0:
			value = value + 0x10000000000000000
		stack_offset = abs(int(variableInput.getOffset()))

		cbranchIndex = i
		while pcodeOps[cbranchIndex].getOpcode() != ghidra.program.model.pcode.PcodeOp.CBRANCH:
			cbranchIndex += 1

		jmpAddress, cnd = process_branch(pcodeOps[cbranchIndex])

		if jmpAddress != False:

			pcodesBranch = self.get_path_from_address(jmpAddress)
			pcodesNoBranch = self.get_path_from_pcodes(pcodeOps[cbranchIndex + 1:], highFunction)

			passOutcome = self.check_branch(pcodesBranch)
			negativeOutcome = self.check_branch(pcodesNoBranch)

			desiredOutcome = None

			if passOutcome == negativeOutcome:
				desiredOutcome = 2

			elif passOutcome == 0 and (negativeOutcome == 1 or negativeOutcome == 2):
				desiredOutcome = 0

			elif (passOutcome == 1 or passOutcome == 2) and negativeOutcome == 0:
				desiredOutcome = 1

			else:
				desiredOutcome = 2


			check = {}
			check["stackOffset"] = stack_offset
			check["value"] = value
			check["branchType"] = branchType
			check["size"] = size
			check["desiredOutcome"] = desiredOutcome

			return check

	# A function which checks an input, for indirect pointers and compares
	def check_stack(self, address):
		address = toAddr(address)
		function = getFunctionContaining(address)
		decompilation = self.decomp.decompileFunction(function, self.decomp.getOptions().getDefaultTimeout(), getMonitor())

		highFunction = decompilation.getHighFunction()
		pcodeOps = highFunction.getPcodeOps()
		callPcodeOps = highFunction.getPcodeOps(address)

		matchingOps = 0
		callOps = count_ops(callPcodeOps)

		cmps = []

		calledPtrs = []

		pcodeOps = count_ops(pcodeOps)

		for i in range(0, len(pcodeOps)):
			if matchingOps < len(callOps):
				if pcodeOps[i] in callOps:
					matchingOps += 1
				else:
					matchingOps = 0
			else:
				# Check for compare opcodes
				if pcodeOps[i].getOpcode() == ghidra.program.model.pcode.PcodeOp.INT_EQUAL:
					check = self.process_cmp(pcodeOps, i, ghidra.program.model.pcode.PcodeOp.INT_EQUAL, highFunction)
					cmps.append(check)
				elif pcodeOps[i].getOpcode() == ghidra.program.model.pcode.PcodeOp.INT_NOTEQUAL:
					check = self.process_cmp(pcodeOps, i, ghidra.program.model.pcode.PcodeOp.INT_NOTEQUAL, highFunction)
					cmps.append(check)

				elif pcodeOps[i].getOpcode() == ghidra.program.model.pcode.PcodeOp.INT_LESS:
					check = self.process_cmp(pcodeOps, i, ghidra.program.model.pcode.PcodeOp.INT_LESS, highFunction)
					cmps.append(check)

				elif pcodeOps[i].getOpcode() == ghidra.program.model.pcode.PcodeOp.INT_LESSEQUAL:
					check = self.process_cmp(pcodeOps, i, ghidra.program.model.pcode.PcodeOp.INT_LESSEQUAL, highFunction)
					cmps.append(check)

				elif pcodeOps[i].getOpcode() == ghidra.program.model.pcode.PcodeOp.INT_SLESS:
					check = self.process_cmp(pcodeOps, i, ghidra.program.model.pcode.PcodeOp.INT_SLESS, highFunction)
					cmps.append(check)

				elif pcodeOps[i].getOpcode() == ghidra.program.model.pcode.PcodeOp.INT_SLESSEQUAL:
					check = self.process_cmp(pcodeOps, i, ghidra.program.model.pcode.PcodeOp.INT_SLESSEQUAL, highFunction)
					cmps.append(check)		

				# Check for an indirect call opcode 
				elif pcodeOps[i].getOpcode() == ghidra.program.model.pcode.PcodeOp.CALLIND:
					inpVarnode = pcodeOps[i].getInput(0)
					if inpVarnode.isAddrTied() == True:
						offset = abs(int(inpVarnode.getOffset()))
						calledPtrs.append(offset)
		return cmps, calledPtrs

	'''
	+-----------------------------------------------------------+
	|                     String Manipulation                   |
	+-----------------------------------------------------------+
	'''

	# Function to get the string designated by a varnode
	def get_string(self, varnode):
		if varnode == None:
			return ""
		if varnode.isRegister() == False and self.arch == "amd64":	

			# Check if it is a stack address
			try:
				stringAddress = self.stack_offset_from_varnode(varnode)
				getByte(toAddr(stringAddress))

			# Check if PIE Address
			except:
				try:
					stringAddress = pie_offset_from_varnode(varnode)
					getByte(toAddr(stringAddress))
				except:
					return ""

			string = str(getDataAt(toAddr(stringAddress)))
			string = rec_get_string(string)

			if string != "None":
				string = string.split('"')[1]
			else:
				string = ""
				currentChar = getByte(toAddr(stringAddress))
				# Get string one byte at a time
				while currentChar != 0:
					string += chr(currentChar)
					stringAddress += 1
					currentChar = getByte(toAddr(stringAddress))
			return string
	
		elif varnode.isRegister() == False and self.arch == "i386":
			string = None
			try:
				sourceVarnode = varnode.getDef()
				i = 0
				varnodeInps = sourceVarnode.getInputs()
				while string == None:
					if i > (len(varnodeInps) - 1):
					# Could not identify input
						return ""
					stringAddress = sourceVarnode.getInputs()[i].getOffset()
					try:
						string = getByte(toAddr(stringAddress))
					except:
						try:
							string = self.get_string(toAddr(stringAddress))
						except:
							string = None
					i += 1
			except:
				try:
					stringAddress = varnode.getOffset()
				except:
					print("\n\nCan't get string address\n\n")

			string = ""
			stringAddress = self.check_recursive_address(stringAddress)
			currentChar = getByte(toAddr(stringAddress))
			# Get string one byte at a time
			while currentChar != 0:
				string += chr(currentChar)
				stringAddress += 1
				currentChar = getByte(toAddr(stringAddress))
			string = str(string)
			return string
		else:
			return ""

	# This is used in situations where you have something like a ptr, to a ptr, to a ptr
	# Basically just defeferences ptrs, until it reaches the end
	def check_recursive_address(self, address):
		try:
			if is_valid_pie_address(address) == True:
				ptr = self.get_ptr_from_address(address)
				while is_valid_pie_address(ptr) == True:
					address = ptr
					ptr = self.get_ptr_from_address(ptr)
			return address
		except:
			return address

	# Dereference ptr and get the value, one byte at a time
	def get_ptr_from_address(self, address):
		if self.arch == "amd64":
			ptr_size = 8
		elif self.arch == "i386":
			ptr_size = 4
		ptr = 0
		for i in range(0, ptr_size):
			byte = getByte(toAddr(address + i))
			if byte < 0:
				byte = 0x100 + byte
			ptr = ptr | (byte << (i*8))
		return ptr


	# Get the stack offset from a varnode, in the stack memory region
	def stack_offset_from_varnode(self, varnode):
		try:
			dec_varnode = varnode.getDef()
			dec_inputs = dec_varnode.getInputs()

			if self.arch == "i386":
				for inp in dec_inputs:
					if inp.isConstant() == True:
						offset = 0x100000000 - int(abs(inp.getOffset()))
						if (offset != 0x100000000):
							return offset
				return False
			else:
				offset = None
				for inp in dec_inputs:
					if inp.isConstant() == True:
						offset = int(abs(inp.getOffset()))
						if offset != 0:
							return offset

				# This is to deal with some edge cases
				# Where the exact offset is specified a declaration before, the initial declaration
				if offset == None:
					initialDeclare = inp.getDef()
					if initialDeclare != None:
						initalVarnode = initialDeclare.getInput(1)
						if initalVarnode != None:
							offset = initalVarnode.getOffset()
							if offset != None and offset != 0:
								offset = int(abs(offset))
								return offset
			return False
		except:
			return False


'''
+-----------------------------------------------------------+
|                         Constants                         |
+-----------------------------------------------------------+
'''

# The strings we check for as an agrument to system
SYS_WIN_ARGS = ["sh", "cat"]

# The strings we check for as an argument to open
OPEN_WIN_ARGS = ["flag", "key"]

# A dictionary top map function names to their corresponding list of win string args
WIN_FUNC_STRINGS = {"open":SYS_WIN_ARGS, "fopen":OPEN_WIN_ARGS, "system":OPEN_WIN_ARGS}

# A list of format string strings
FMT_TYPES = ["d", "i", "u", "iof", "F", "e", "E", "g", "G", "x", "X", "o", "s", "c", "p", "a", "A", "n"]

# A list of functions designated as "loosing" the challenge
LOOSE_FUNCS = ["exit"]

# A list of the functions we check for alternate win conditions
WIN_FUNCS = {	
				"open" : check_win_open, 
				"fopen" : check_win_fopen, 
				"system" : check_win_system, 
				"execve" : check_win_execve
			}

# A list of the target functions, we check for bugs / inputs
TARGET_FUNCTIONS = {	
					"gets":				analyze_gets, 
					"read":				analyze_read, 
					"fgets":			analyze_fgets, 
					"__isoc99_scanf":	analyze_scanf, 
					"scanf":			analyze_scanf, 
					"printf":			analyze_printf, 
					"strcpy":			analyze_strcpy,
					"strncpy":			analyze_strncpy,
					"fread":			analyze_fread,
					"fscanf":			analyze_fscanf,
					"__isoc99_fscanf":	analyze_fscanf
					}

'''
+-----------------------------------------------------------+
|                        Main Function                      |
+-----------------------------------------------------------+
'''

if __name__ == "__main__":
	static_analyzer = StaticAnalyzer()

	# Get the architecture
	static_analyzer.get_arch()

	# Parse out the arguments
	args = getScriptArgs()

	# Assign the output file for vulns / inputs
	if len(args) > 0:
		static_analyzer.output_file = str(args[0])

	# Assign the output file for alternate win conditions
	if len(args) > 1:
		# Our output file, for alternate win conditions
		static_analyzer.win_conds_output_file = str(args[1])

	# This argument is for when we have to deal with PIE
	if len(args) > 2:
		# Specify PIE is enabled
		static_analyzer.pie_enabled = True

		pie_arg = args[2]
		rebased = False

		# This is for renaming functions to their names, that we have symbols for
		# Ghidra has issues naming functions for 32 bit binaries with PIE enabled
		if (pie_arg != "rebase"):
			plt_funcs_file_name = str(args[2])
			plt_funcs_file = open( plt_funcs_file_name, "rb")
			plt_funcs = pickle.load(plt_funcs_file)
			rename_functions(plt_funcs)

		# Rebase everything in the binary segment to `0x0`
		rebased = True
		if static_analyzer.arch == "i386":
			rebase_minus_offset(0x10000)
		elif static_analyzer.arch == "amd64":
			rebase_minus_offset(0x100000)
	
	# Setup the decompiler
	static_analyzer.setup_decompiler()

	# Check for alternate win conditions
	static_analyzer.check_win_conditions()

	# Check the target functions for bugs / inputs
	static_analyzer.check_target_functions()