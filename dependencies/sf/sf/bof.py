"""Module for generating buffer overflow payloads."""


def gen_fodder_byte():
	"""Generate a fodder byte"""
	return b"0"

def check_arg_type(argument, arg_typ: type):
	"""Check the type of an argument"""
	if not isinstance(argument, arg_typ):
		raise TypeError("Argument must be %s" % str(arg_typ))

def int_size(value: int):
	"""Get the size of an integer"""
	size = 0
	while value != 0:
		size += 1
		value = value >> 8
	return size

def int_byte_string(value: int, size: int, little_endian: bool = True):
	"""Convert an integer to a byte string"""
	if little_endian:
		byte_string = value.to_bytes(size, 'little')
	else:
		byte_string = value.to_bytes(size, 'big')
	return byte_string

def get_arch_arg(kwargs: dict) -> int:
	""" get architecutre from argument """
	if "arch" not in kwargs:
		raise ValueError("Arch must be specified")
	arch = kwargs.get("arch")
	if isinstance(arch, int):
		if arch == 64:
			return 64
		if arch  in (32, 86):
			return 32
		raise ValueError("arch as int must be either 32 or 64")
	if isinstance(arch, str):
		if ("86" in arch) or ("32" in arch):
			return 32
		if "64" in arch:
			return 64
		raise ValueError("arch as str must be either '32' or '64'")
	raise TypeError("arch must be either str or int")

def get_int_arg(arg: str, kwargs: dict):
	""" helper function to get integer value from kwargs """
	arg_value = kwargs.get(arg)
	if arg_value is not None:
		if isinstance(arg_value, int):
			return arg_value
		raise TypeError("%s must be int" % arg)
	return None

class BufferOverflow:
	"""Class for the Buffer Overflow Payload Generator"""
	def __init__(self, **kwargs):
		"""Initialize Payload Generator"""

		self.return_address = None
		self.lowest_offset = None
		self.highest_offset = None
		self.default_byte = None
		self.byte_function = None
		self.ret = None
		self.arch = get_arch_arg(kwargs)
		self.start_of_input = get_int_arg("start", kwargs)
		ret_int = get_int_arg("ret", kwargs)
		if ret_int is not None:
			self.set_ret(ret_int)
		self.values = {}
		self.bases = {}
		self.fill = False

	def get_arch_ptr_size(self):
		"""Get the ptr size from an architecture"""
		if self.arch == 32:
			size = 4
		if self.arch == 64:
			size = 8
		return size

	def check_offset_add(self, new_offset: int):
		"""Check the offset we are placing a byte at"""
		if not isinstance(new_offset, int):
			raise TypeError("Offset must be integer")

		#if new_offset <= 0:
		#	raise ValueError("Offset must be greater than 0.")

		# Check if this is the lowest / highest specified byte
		if self.lowest_offset is None or self.highest_offset is None:
			self.lowest_offset = new_offset
			self.highest_offset = new_offset

		else:
			if new_offset < self.lowest_offset:
				self.lowest_offset = new_offset

			if new_offset > self.highest_offset:
				self.highest_offset = new_offset

		if isinstance(self.start_of_input, int):
			# Check to ensure this offset is within the bounds of our payload
			if new_offset > self.start_of_input:
				raise ValueError("Value is higher than the start of the input.")

		# Check if we already have a byte at this offset
		if new_offset in self.values:
			raise ValueError("Offset already specified")

	# These are the functions for adding values to the payload

	def add_byte(self, offset: int, byte_value: bytes):
		"""Add a single byte to the payload"""
		self.check_offset_add(offset)
		self.values[offset] = byte_value

	def add_bytes(self, offset: int, byte_values: bytes):
		"""Add a byte string to the payload"""
		check_arg_type(byte_values, bytes)

		for i in range(0, len(byte_values)):
			self.add_byte(offset - i, byte_values[i])

	def add_int(self, offset: int, int_value: int, little_endian: bool = True):
		"""Add an integer to the payload, size of ptr arch"""
		check_arg_type(int_value, int)

		size = self.get_arch_ptr_size()
		byte_string = int_byte_string(int_value, size, little_endian)
		for i in range(0, size):
			self.add_byte(offset - i, byte_string[i])

	def add_int32(self, offset: int, int_value: int, base: str = ""):
		"""Add a 32 bit integer to the payload"""
		check_arg_type(int_value, int)
		check_arg_type(base, str)

		base_value = self.get_base_value(base)

		int_value += base_value
		byte_string = int_byte_string(int_value, 4)
		for i in range(0, 4):
			self.add_byte(offset - i, byte_string[i])

	def add_int64(self, offset: int, int_value: int, base: str = ""):
		"""Add a 64 bit integer to the payload"""

		check_arg_type(int_value, int)
		check_arg_type(base, str)

		base_value = self.get_base_value(base)

		int_value += base_value
		byte_string = int_byte_string(int_value, 8)
		for i in range(0, 8):
			self.add_byte(offset - i, byte_string[i])

	def add_int_var(self, offset: int, int_value: int, little_endian: bool = True):
		"""Add a variable length non-zero integer to the payload"""

		check_arg_type(int_value, int)

		value_size = int_size(int_value)

		if value_size <= 0:
			raise ValueError("Variable length integer must contain non-zero bytes.")

		byte_string = int_byte_string(int_value, value_size, little_endian)
		for i in range(0, value_size):
			self.add_byte(offset - i, byte_string[i])

	def add_base_value(self, offset: int, int_value: int, base: str, little_endian: bool = True):
		check_arg_type(offset, int)
		check_arg_type(int_value, int)
		check_arg_type(base, int)

		if base not in self.bases.keys():
			raise ValueError("Base not specified yet, specify with add_base()")

		int_value += self.bases[base]

		value_size = int_size(int_value)
		byte_string = int_byte_string(int_value, value_size, little_endian)
		for i in range(0, value_size):
			self.add_byte(offset - i, byte_string[i])

	def add_base(self, base: str, base_value: int):
		"""Specify a new base"""
		check_arg_type(base, str)
		check_arg_type(base_value, int)

		self.bases[base] = base_value	

	# These are the functions for setting properties of the payload

	def set_input_start(self, start: int):
		"""Specify the start of your input"""
		check_arg_type(start, int)

		# Check to see if there is a specified byte past the new start
		if self.highest_offset is not None:
			if start < self.highest_offset:
				raise ValueError("New start is below specified stack values.")

		self.start_of_input = start

	def set_ret(self, return_address: int, base: str = ""):
		"""Specify the value of the return address"""
		#check_arg_type(return_address, int)

		base_value = self.get_base_value(base)


		if not isinstance(return_address, int):
			raise TypeError("Return address must be integer")

		if not isinstance(base, str):
			raise TypeError("Base must be string")		
		
		base_value = self.get_base_value(base)	

		return_address_value = return_address + base_value

		if self.arch == 32:
			self.add_int32(0x0, return_address_value)
		else:
			self.add_int64(0x0, return_address_value)

	def add_rop_chain(self, rop_chain: list, base: str = ""):
		if not isinstance(rop_chain, list):
			raise TypeError("rop_chain must be type list")

		if not isinstance(base, str):
			raise TypeError("Base must be string")

		rebase_value_all = self.get_base_value(base)

		offset = 0

		if self.arch == 32:
			add_offset = 4
		else:
			add_offset = 8

		for rop_gadget in rop_chain:
			if isinstance(rop_gadget, int):
				if self.arch == 32:
					self.add_int32(offset, rop_gadget)
				else:
					self.add_int64(offset, rop_gadget)
			elif isinstance(rop_gadget, list):
				if rebase_value_all != 0:
					raise ValueError("Already specified base_value for all")
				if len(rop_gadget) != 2:
					raise ValueError("gadget list must be len 2")
				if not isinstance(rop_gadget[0], int):
					raise TypeError("first must be int")
				if not isinstance(rop_gadget[1], str):
					raise TypeError("second must be str")

				base_value = self.get_base_value(rop_gadget[1])
				gadget_address = base_value + rop_gadget[0]
				if self.arch == 32:
					self.add_int32(offset, gadget_address)
				else:
					self.add_int64(offset, gadget_address)
			elif isinstance(rop_gadget, bytes):
				bytes_len = len(rop_gadget)
				remainder = bytes_len % add_offset
				rop_gadget += gen_fodder_byte()*remainder
				additional_offset = len(rop_gadget) - add_offset
				self.add_bytes(offset, rop_gadget)
				offset -= additional_offset
			else:
				raise TypeError("Must be int or list")
			offset -= add_offset

	def set_default_byte(self, default_byte: bytes):
		"""Specify the default byte"""
		check_arg_type(default_byte, bytes)

		if len(default_byte) != 1:
			raise ValueError("Default Byte must be 1 byte long")

		self.default_byte = default_byte

	def set_byte_function(self, function):
		"""Set the function which generates default byte"""
		if not callable(function):
			raise TypeError("Byte Function must be callable")

		self.byte_function = function


	def fill_payload(self, fill=True):
		"""Specify if the exploit will be filled to ret address"""		
		if not isinstance(fill, bool):
			raise TypeError("Argument fill must be bool")
		self.fill = fill

	def get_base_value(self, base):
		if not isinstance(base, str):
			raise TypeError("Base must me str")

		if base == "":
			base_value = 0

		else:
			if base not in self.bases.keys():
				raise ValueError("Base not specified yet, specify with add_base()")		
			else:
				base_value = self.bases[base]	

		return base_value

	def generate_payload(self):
		"""Generate the buffer overflow payload"""
		if self.start_of_input is None:
			raise ValueError("Start of input must be specified")

		if self.default_byte is None:
			self.default_byte = gen_fodder_byte()

		lowest_offset = self.lowest_offset
		if self.ret is None and not self.fill:
			if self.lowest_offset is None:
				raise ValueError("No Values specified")
			lowest_offset = self.lowest_offset

		payload = b""

		for i in range(self.start_of_input, lowest_offset - 1, -1):
			if i not in self.values:
				if self.byte_function is None:
					payload += self.default_byte
				else:
					payload += self.byte_function()
			else:
				payload += self.values[i].to_bytes(1, 'little')

		#if self.ret is None:
		#	return payload

		#if isinstance(self.ret, bytes):
		#	payload += self.ret

		#elif isinstance(self.ret, list):
		#	for ret_addresses in self.ret:
		#		payload += ret_addresses

		return payload
