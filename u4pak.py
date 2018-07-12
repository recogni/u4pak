#!/usr/bin/env python
# coding=UTF-8
#
# Copyright (c) 2014 Mathias Panzenböck
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from __future__ import with_statement, division, print_function

import os
import sys
import hashlib
import zlib

from struct import unpack as st_unpack, pack as st_pack
from collections import OrderedDict, namedtuple
from io import DEFAULT_BUFFER_SIZE
from binascii import hexlify

__all__ = 'read_index'

class Pak(object):
	__slots__ = ('version', 'index_offset', 'index_size', 'footer_offset', 'index_sha1', 'mount_point', 'records')

	def __init__(self,version,index_offset,index_size,footer_offset,index_sha1,mount_point=None,records=None):
		self.version       = version
		self.index_offset  = index_offset
		self.index_size    = index_size
		self.footer_offset = footer_offset
		self.index_sha1    = index_sha1
		self.mount_point   = mount_point
		self.records       = records or []

	def __len__(self):
		return len(self.records)

	def __iter__(self):
		return iter(self.records)

	def __repr__(self):
		return 'Pak(version=%r, index_offset=%r, index_size=%r, footer_offset=%r, index_sha1=%r, mount_point=%r, records=%r)' % (
			self.version, self.index_offset, self.index_size, self.footer_offset, self.index_sha1, self.mount_point, self.records)

	def print_list(self,details=False,delim="\n",sort_func=None,out=sys.stdout):
		records = self.records

		if details:
			size_to_str = str

			count = 0
			sum_size = 0
			out.write("    Offset        Size  Compr-Method  Compr-Size  SHA1                                      Name%s" % delim)
			for record in records:
				size  = size_to_str(record.uncompressed_size)
				sha1  = hexlify(record.sha1).decode('latin1')
				cmeth = record.compression_method

				if cmeth == COMPR_NONE:
					out.write("%10u  %10s             -           -  %s  %s%s" % (
						record.data_offset, size, sha1, record.filename, delim))
				else:
					out.write("%10u  %10s  %12s  %10s  %s  %s%s" % (
						record.data_offset, size, COMPR_METHOD_NAMES[cmeth],
						size_to_str(record.compressed_size), sha1,
						record.filename, delim))
				count += 1
				sum_size += record.uncompressed_size
			out.write("%d file(s) (%s) %s" % (count, size_to_str(sum_size), delim))
		else:
			for record in records:
				out.write("%s%s" % (record.filename, delim))

COMPR_NONE        = 0x00
COMPR_ZLIB        = 0x01
COMPR_BIAS_MEMORY = 0x10
COMPR_BIAS_SPEED  = 0x20

COMPR_METHOD_NAMES = {
	COMPR_NONE: 'none',
	COMPR_ZLIB: 'zlib',
	COMPR_BIAS_MEMORY: 'bias memory',
	COMPR_BIAS_SPEED:  'bias speed'
}

class Record(namedtuple('RecordBase', [
	'filename', 'offset', 'compressed_size', 'uncompressed_size', 'compression_method',
	'timestamp', 'sha1', 'compression_blocks', 'encrypted', 'compression_block_size'])):

	def read(self,data,offset,size):
		if self.compression_method == COMPR_NONE:
			uncompressed_size = self.uncompressed_size

			if offset >= uncompressed_size:
				return bytes()

			i = self.data_offset + offset
			j = i + min(uncompressed_size - offset, size)
			return data[i:j]
		else:
			raise NotImplementedError('decompression is not implemented yet')

	@property
	def data_offset(self):
		return self.offset + self.header_size

	@property
	def alloc_size(self):
		return self.header_size + self.compressed_size

	@property
	def index_size(self):
		name_size = 4 + len(self.filename.replace(os.path.sep,'/').encode('utf-8')) + 1
		return name_size + self.header_size

class RecordV1(Record):
	def __new__(cls, filename, offset, compressed_size, uncompressed_size, compression_method, timestamp, sha1):
		return Record.__new__(cls, filename, offset, compressed_size, uncompressed_size,
		                      compression_method, timestamp, sha1, None, False, None)

	@property
	def header_size(self):
		return 56

class RecordV2(Record):
	def __new__(cls, filename, offset, compressed_size, uncompressed_size, compression_method, sha1):
		return Record.__new__(cls, filename, offset, compressed_size, uncompressed_size,
		                      compression_method, None, sha1, None, False, None)

	@property
	def header_size(self):
		return 48

class RecordV3(Record):
	def __new__(cls, filename, offset, compressed_size, uncompressed_size, compression_method, sha1,
	             compression_blocks, encrypted, compression_block_size):
		return Record.__new__(cls, filename, offset, compressed_size, uncompressed_size,
		                      compression_method, None, sha1, compression_blocks, encrypted,
		                      compression_block_size)

	@property
	def header_size(self):
		size = 53
		if self.compression_method != COMPR_NONE:
			size += len(self.compression_blocks) * 16
		return size

def read_path(stream):
	path_len, = st_unpack('<I',stream.read(4))
	return stream.read(path_len).rstrip(b'\0').decode('utf-8').replace('/',os.path.sep)

def read_record_v1(stream, filename):
	return RecordV1(filename, *st_unpack('<QQQIQ20s',stream.read(56)))

def read_record_v2(stream, filename):
	return RecordV2(filename, *st_unpack('<QQQI20s',stream.read(48)))

def read_record_v3(stream, filename):
	offset, compressed_size, uncompressed_size, compression_method, sha1 = \
		st_unpack('<QQQI20s',stream.read(48))

	if compression_method != COMPR_NONE:
		block_count, = st_unpack('<I',stream.read(4))
		blocks = st_unpack('<%dQ' % (block_count * 2), stream.read(16 * block_count))
		blocks = [(blocks[i], blocks[i+1]) for i in xrange(0, block_count * 2, 2)]
	else:
		blocks = None

	encrypted, compression_block_size = st_unpack('<BI',stream.read(5))

	return RecordV3(filename, offset, compressed_size, uncompressed_size, compression_method,
	                sha1, blocks, encrypted != 0, compression_block_size)

def read_index(stream):
	stream.seek(-44, 2)
	footer_offset = stream.tell()
	footer = stream.read(44)
	magic, version, index_offset, index_size, index_sha1 = st_unpack('<IIQQ20s',footer)

	if magic != 0x5A6F12E1:
		raise ValueError('illegal file magic: 0x%08x' % magic)

	if version == 1:
		read_record = read_record_v1

	elif version == 2:
		read_record = read_record_v2

	elif version == 3:
		read_record = read_record_v3

	elif version == 4:
		read_record = read_record_v3

	else:
		raise ValueError('unsupported version: %d' % version)

	if index_offset + index_size > footer_offset:
		raise ValueError('illegal index offset/size')

	stream.seek(index_offset, 0)

	mount_point = read_path(stream)
	entry_count = st_unpack('<I',stream.read(4))[0]

	pak = Pak(version, index_offset, index_size, footer_offset, index_sha1, mount_point)

	for i in xrange(entry_count):
		filename = read_path(stream)
		record   = read_record(stream, filename)
		pak.records.append(record)

	if stream.tell() > footer_offset:
		raise ValueError('index bleeds into footer')

	return pak

def main(argv):
	import argparse

	parser = argparse.ArgumentParser(description='list Unreal Engine 4 .pak archives')

	subparsers = parser.add_subparsers(metavar='command')

	list_parser = subparsers.add_parser('list',help='list archive contens')
	list_parser.set_defaults(command='list')
	list_parser.add_argument('-d','--details',action='store_true',default=False,
		help='print file offsets and sizes')
	list_parser.add_argument('archive', help='Unreal Engine 4 .pak archive')

	args = parser.parse_args(argv)

	if args.command == 'list':
		with open(args.archive,"rb") as stream:
			pak = read_index(stream)
			pak.print_list(args.details,'\n',None,sys.stdout)

	else:
		raise ValueError('unknown command: %s' % args.command)

if __name__ == '__main__':
	try:
		main(sys.argv[1:])
	except (ValueError, NotImplementedError, IOError) as exc:
		sys.stderr.write("%s\n" % exc)
		sys.exit(1)
