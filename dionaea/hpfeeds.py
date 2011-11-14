#********************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2010  Mark Schloesser
#* 
#* This program is free software; you can redistribute it and/or
#* modify it under the terms of the GNU General Public License
#* as published by the Free Software Foundation; either version 2
#* of the License, or (at your option) any later version.
#* 
#* This program is distributed in the hope that it will be useful,
#* but WITHOUT ANY WARRANTY; without even the implied warranty of
#* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#* GNU General Public License for more details.
#* 
#* You should have received a copy of the GNU General Public License
#* along with this program; if not, write to the Free Software
#* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#* 
#* 
#*             contact nepenthesdev@gmail.com  
#*
#*******************************************************************************/

from dionaea.core import ihandler, incident, g_dionaea, connection
from dionaea.util import sha512file

import os
import logging
import struct
import hashlib
import json

logger = logging.getLogger('hpfeeds')
logger.setLevel(logging.DEBUG)

def DEBUGPERF(msg):
	print(msg)
logger.debug = DEBUGPERF
logger.critical = DEBUGPERF

BUFSIZ = 16384

OP_ERROR        = 0
OP_INFO         = 1
OP_AUTH         = 2
OP_PUBLISH      = 3
OP_SUBSCRIBE    = 4

MAXBUF = 1024**2
SIZES = {
	OP_ERROR: 5+MAXBUF,
	OP_INFO: 5+256+20,
	OP_AUTH: 5+256+20,
	OP_PUBLISH: 5+MAXBUF,
	OP_SUBSCRIBE: 5+256*2,
}

CAPTURECHAN = 'dionaea.capture'
DCECHAN = 'dionaea.dcerpcrequests'
SCPROFCHAN = 'dionaea.shellcodeprofiles'
UNIQUECHAN = 'mwbinary.dionaea.sensorunique'

class BadClient(Exception):
        pass

# packs a string with 1 byte length field
def strpack8(x):
	if isinstance(x, str): x = x.encode('latin1')
	return struct.pack('!B', len(x)%0xff) + x

# unpacks a string with 1 byte length field
def strunpack8(x):
	l = x[0]
	return x[1:1+l], x[1+l:]
	
def msghdr(op, data):
	return struct.pack('!iB', 5+len(data), op) + data
def msgpublish(ident, chan, data):
	return msghdr(OP_PUBLISH, strpack8(ident) + strpack8(chan) + data)
def msgsubscribe(ident, chan):
	if isinstance(chan, str): chan = chan.encode('latin1')
	return msghdr(OP_SUBSCRIBE, strpack8(ident) + chan)
def msgauth(rand, ident, secret):
	hash = hashlib.sha1(bytes(rand)+secret).digest()
	return msghdr(OP_AUTH, strpack8(ident) + hash)

class FeedUnpack(object):
	def __init__(self):
		self.buf = bytearray()
	def __iter__(self):
		return self
	def __next__(self):
		return self.unpack()
	def feed(self, data):
		self.buf.extend(data)
	def unpack(self):
		if len(self.buf) < 5:
			raise StopIteration('No message.')

		ml, opcode = struct.unpack('!iB', self.buf[:5])
		if ml > SIZES.get(opcode, MAXBUF):
			raise BadClient('Not respecting MAXBUF.')

		if len(self.buf) < ml:
			raise StopIteration('No message.')

		data = self.buf[5:ml]
		del self.buf[:ml]
		return opcode, data

class hpclient(connection):
	def __init__(self, server, port, ident, secret):
		logger.debug('hpclient init')
		connection.__init__(self, 'tcp')
		self.unpacker = FeedUnpack()
		self.ident, self.secret = ident.encode('latin1'), secret.encode('latin1')

		self.connect(server, port)
		self.timeouts.reconnect = 10.0
		self.sendfiles = []
		self.filehandle = None

	def handle_established(self):
		logger.debug('hpclient established')

	def handle_io_in(self, indata):
		self.unpacker.feed(indata)

		# if we are currently streaming a file, delay handling incoming messages
		if self.filehandle:
			return len(indata)

		try:
			for opcode, data in self.unpacker:
				logger.debug('hpclient msg opcode {0} data {1}'.format(opcode, data))
				if opcode == OP_INFO:
					name, rand = strunpack8(data)
					logger.debug('hpclient server name {0} rand {1}'.format(name, rand))
					self.send(msgauth(rand, self.ident, self.secret))

				elif opcode == OP_PUBLISH:
					ident, data = strunpack8(data)
					chan, data = strunpack8(data)
					logger.debug('publish to {0} by {1}: {2}'.format(chan, ident, data))

				elif opcode == OP_ERROR:
					logger.debug('errormessage from server: {0}'.format(data))
				else:
					logger.debug('unknown opcode message: {0}'.format(opcode))
		except BadClient:
			logger.critical('unpacker error, disconnecting.')
			self.close()

		return len(indata)

	def handle_io_out(self):
		if self.filehandle:
			self.sendfiledata()

	def publish(self, channel, **kwargs):
		self.send(msgpublish(self.ident, channel, json.dumps(kwargs).encode('latin1')))

	def sendfile(self, filepath):
		# does not read complete binary into memory, read and send chunks
		if not self.filehandle:
			self.sendfileheader(i.file)
			self.sendfiledata()
		else: self.sendfiles.append(filepath)

	def sendfileheader(self, filepath):
		self.filehandle = open(filepath, 'rb')
		fsize = os.stat(filepath).st_size
		headc = strpack8(self.ident) + strpack8(UNIQUECHAN)
		headh = struct.pack('!iB', 5+len(headc)+fsize, OP_PUBLISH)
		self.send(headh + headc)

	def sendfiledata(self):
		tmp = self.filehandle.read(BUFSIZ)
		if not tmp:
			if self.sendfiles:
				fp = self.sendfiles.pop(0)
				self.sendfileheader(fp)
			else:
				self.filehandle = None
				self.handle_io_in(b'')
		else:
			self.send(tmp)

	def handle_timeout_idle(self):
		pass

	def handle_disconnect(self):
		return 1

	def handle_error(self, err):
		logger.debug('handle_err {0}'.format(err))
		return False

class hpfeedihandler(ihandler):
	def __init__(self, config):
		logger.debug('hpfeedhandler init')
		self.client = hpclient(config['server'], int(config['port']), config['ident'], config['secret'])
		ihandler.__init__(self, '*')

	def __del__(self):
		#self.client.close()
		pass

	def handle_incident(self, i):
		pass
		
	def handle_incident_dionaea_download_complete_unique(self, i):
		logger.debug('unique complete, publishing md5 {0}, path {1}'.format(i.md5hash, i.file))
		self.client.sendfile(i.file)

	def handle_incident_dionaea_download_complete_hash(self, i):
		sha512 = sha512file(i.file)
		self.client.publish(CAPTURECHAN, saddr=i.con.remote.host, 
			sport=str(i.con.remote.port), daddr=i.con.local.host,
			dport=str(i.con.local.port), md5=i.md5hash, sha512=sha512,
			url=i.url
		)

	def handle_incident_dionaea_modules_python_smb_dcerpc_request(self, i):
		self.client.publish(DCECHAN, uuid=i.uuid, opnum=i.opnum,
			saddr=i.con.remote.host, sport=str(i.con.remote.port),
			daddr=i.con.local.host, dport=str(i.con.local.port),
		)

	def handle_incident_dionaea_module_emu_profile(self, icd):
		self.client.publish(SCPROFCHAN, profile=icd.profile)
