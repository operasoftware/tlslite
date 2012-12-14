"""Classes representing TLS messages."""

from utils.compat import *
from utils.cryptomath import *
from errors import *
from utils.codec import *
from constants import *
from X509 import X509
from X509CertChain import X509CertChain
import TestHandshake

import sha
import md5

class RecordHeader3:
	def __init__(self):
		self.type = 0
		self.version = (0,0)
		self.length = 0
		self.ssl2 = False

	def create(self, version, type, length):
		self.type = type
		self.version = version
		self.length = length
		return self

	def write(self):
		w = Writer(5)
		w.add(self.type, 1)
		w.add(self.version[0], 1)
		w.add(self.version[1], 1)
		w.add(self.length, 2)
		return w.bytes

	def parse(self, p):
		self.type = p.get(1)
		self.version = (p.get(1), p.get(1))
		self.length = p.get(2)
		self.ssl2 = False
		return self

class RecordHeader2:
	def __init__(self):
		self.type = 0
		self.version = (0,0)
		self.length = 0
		self.ssl2 = True

	def parse(self, p):
		first_byte =p.get(1) 
		if first_byte <128:
			raise SyntaxError()
		first_byte = first_byte & 0x7f
		self.type = ContentType.handshake
		self.version = (2,0)
		self.length = (first_byte<<8) | p.get(1)
		return self


class Msg:
	def preWrite(self, trial):
		if trial:
			w = Writer()
		else:
			length = self.write(True)
			w = Writer(length)
		return w

	def postWrite(self, w, trial):
		if trial:
			return w.index
		else:
			return w.bytes

class Alert(Msg):
	def __init__(self):
		self.contentType = ContentType.alert
		self.level = 0
		self.description = 0

	def create(self, description, level=AlertLevel.fatal):
		self.level = level
		self.description = description
		return self

	def parse(self, p):
		p.setLengthCheck(2)
		self.level = p.get(1)
		self.description = p.get(1)
		p.stopLengthCheck()
		return self

	def write(self):
		w = Writer(2)
		w.add(self.level, 1)
		w.add(self.description, 1)
		return w.bytes


class HandshakeMsg(Msg):
	def preWrite(self, handshakeType, trial):
		if trial:
			w = Writer()
			w.add(handshakeType, 1)
			w.add(0, 3)
		else:
			length = self.write(True)
			w = Writer(length)
			w.add(handshakeType, 1)
			w.add(length-4, 3)
		return w


class HelloRequest(HandshakeMsg):
	def __init__(self):
		self.contentType = ContentType.handshake

	def create(self):
		return self

	def parse(self, p):
		p.startLengthCheck(3)
		p.stopLengthCheck()
		return self

	def write(self, trial=False):
		w = HandshakeMsg.preWrite(self, HandshakeType.hello_request, trial)
		return HandshakeMsg.postWrite(self, w, trial)


class ClientHello(HandshakeMsg):
	def __init__(self, ssl2=False):
		self.contentType = ContentType.handshake
		self.ssl2 = ssl2
		self.client_version = (0,0)
		self.random = createByteArrayZeros(32)
		self.session_id = createByteArraySequence([])
		self.cipher_suites = []		 # a list of 16-bit values
		self.certificate_types = [CertificateType.x509]
		self.compression_methods = []   # a list of 8-bit values
		self.srp_username = None		# a string
		self.servername = None
		self.use_extensions = False
		self.support_renego = False
		self.use_renego = False
		self.renego_bytes = None
		self.renego_error = False
		self.send_certstatus = True
		self.responders = None
		self.ocsp_extensions = None
		self.session_ticket = None

	def create(self, version, random, session_id, cipher_suites,
			   certificate_types=None, srp_username=None, 
			   servername = None, use_extensions = False,
			   use_renego = False, renego_bytes = None, 
			   send_certstatus=False, renegotiating = False, 
			   session_ticket=None,
			   renego_both=False,
			   extra_action_set = None,
			   extra_action_dict = None
			   ):
		self.client_version = version
		self.random = random
		self.session_id = session_id
		self.cipher_suites = cipher_suites
		self.certificate_types = certificate_types
		self.compression_methods = [0]
		self.srp_username = srp_username
		self.servername = servername
		self.use_extensions = use_extensions
		self.use_renego = use_renego
		self.renego_bytes = renego_bytes
		self.renego_error = False
		self.send_certstatus = send_certstatus
		if self.use_renego and (renego_both or (not renegotiating and (not use_extensions or (isinstance(use_extensions, list) and IndividualExtensionsTested.RENEGO not in use_extensions)))):
			self.cipher_suites.insert(0, CipherSuite.TLS_RENEGO_PROTECTION_REQUEST)
		self.session_ticket = session_ticket
		self.extra_action_set = extra_action_set if extra_action_set else set()
		self.extra_action_dict = extra_action_dict if extra_action_dict else dict()

		return self

	def parse(self, p):
		if self.ssl2:
			self.client_version = (p.get(1), p.get(1))
			cipherSpecsLength = p.get(2)
			sessionIDLength = p.get(2)
			randomLength = p.get(2)
			self.cipher_suites = p.getFixList(3, int(cipherSpecsLength/3))
			self.session_id = p.getFixBytes(sessionIDLength)
			self.random = p.getFixBytes(randomLength)
			if len(self.random) < 32:
				zeroBytes = 32-len(self.random)
				self.random = createByteArrayZeros(zeroBytes) + self.random
			self.compression_methods = [0]#Fake this value

			#We're not doing a stopLengthCheck() for SSLv2, oh well..
		else:
			p.startLengthCheck(3)
			self.client_version = (p.get(1), p.get(1))
			self.random = p.getFixBytes(32)
			self.session_id = p.getVarBytes(1)
			self.cipher_suites = p.getVarList(2, 2)
			self.compression_methods = p.getVarList(1, 1)
			if not p.atLengthCheck():
				totalExtLength = p.get(2)
				soFar = 0
				while soFar != totalExtLength:
					extType = p.get(2)
					extLength = p.get(2)
					if extType == 6:
						self.srp_username = bytesToString(p.getVarBytes(1))
					elif extType == 7:
						self.certificate_types = p.getVarList(1, 1)
					elif extType == 5:
						status_type = p.get(1)
						if  status_type == CertificateStatusType.OCSP:
							self.send_certstatus = True
							self.responders = []
							responder_length = p.get(2)
							index = 0
							while index != responder_length:
								bytes = p.getVarBytes(2)
								self.responders.append(bytes)
								index += len(bytes)+2
							self.ocsp_extensions = p.getVarBytes(2)
					elif extType == 0xff01 :
						ri_len = p.get(1)
						if extLength != ri_len +1:
							self.renego_error = True
						else:
							self.support_renego = True
							if ri_len > 0:
								self.renego_bytes = p.getFixBytes(ri_len)
							else:
								self.renego_bytes = None 
					else:
						p.getFixBytes(extLength)
					soFar += 4 + extLength
			p.stopLengthCheck()
		return self

	def write(self, trial=False):
		w = HandshakeMsg.preWrite(self, HandshakeType.client_hello, trial)
		w.add(self.client_version[0], 1)
		w.add(self.client_version[1], 1)
		w.addFixSeq(self.random, 1)
		w.addVarSeq(self.session_id, 1, 1)
		w.addVarSeq(self.cipher_suites, 2, 2)
		w.addVarSeq(self.compression_methods, 1, 1)

		if self.use_extensions:
			extLength = 0
			use_servername = True
			use_cert_status = True
			use_renego_extension = True
			use_session_ticket = True
			use_sig_alg = (self.client_version >= (3,3))
			min_length = None
			if isinstance(self.use_extensions, list):
				use_servername = IndividualExtensionsTested.SERVERNAME in self.use_extensions
				use_cert_status = IndividualExtensionsTested.CERTSTATUS in self.use_extensions
				use_renego_extension = IndividualExtensionsTested.RENEGO in self.use_extensions
				use_session_ticket = IndividualExtensionsTested.SESSIONTICKET in self.use_extensions
				use_sig_alg = use_sig_alg and (IndividualExtensionsTested.SIGNATURE_ALGS in self.use_extensions)
			if use_servername and (not 	any(x not in "0123456789." for x in self.servername) or self.servername[0] == "["):
				use_servername = False
				
			if self.servername and use_servername:
				extLength += 4 + 5 + len(self.servername)
			if self.certificate_types and self.certificate_types != \
					[CertificateType.x509]:
				extLength += 5 + len(self.certificate_types)
			if self.srp_username:
				extLength += 5 + len(self.srp_username)
			if self.use_renego and use_renego_extension:
				extLength += 5
				if self.renego_bytes:
					if len(self.renego_bytes)>255:
						raise
					extLength += len(self.renego_bytes)
					
			if use_session_ticket:
				extLength += 4
				if self.session_ticket:
					extLength += len(self.session_ticket)
			if use_sig_alg:
				extLength += 4 +10
					
			if self.send_certstatus and use_cert_status:
				extLength += 4+1+4
				
			use_min_length = self.extra_action_dict.get(TestHandshake.EXTRA_CH_MIN_LEN,0)
			if extLength + w.index -4 +2 < use_min_length:
				min_length = max(use_min_length - (extLength + w.index -4 +2) -4, 0)
				extLength += 4+min_length
			
			if extLength > 0:
				w.add(extLength, 2)
	
			if self.servername and use_servername:
				w.add(0,2) #ext type
				w.add(5+len(self.servername),2) #payload len
				w.add(3+len(self.servername),2) #payload len
				w.add(0,1) #hostname type
				w.addVarSeq(stringToBytes(self.servername),1,2) #hostname

			if self.certificate_types and self.certificate_types != \
					[CertificateType.x509]:
				w.add(7, 2)
				w.add(len(self.certificate_types)+1, 2)
				w.addVarSeq(self.certificate_types, 1, 1)
			if self.srp_username:
				w.add(6, 2)
				w.add(len(self.srp_username)+1, 2)
				w.addVarSeq(stringToBytes(self.srp_username), 1, 1)
			if self.use_renego and use_renego_extension:
				w.add(0xff01, 2)
				w.add(1+(len(self.renego_bytes) if self.renego_bytes else 0), 2)
				if self.renego_bytes:
					w.addVarSeq(stringToBytes(self.renego_bytes),1,1)
				else:
					w.add(0, 1)
			if self.send_certstatus and use_cert_status:
				w.add(5, 2)
				w.add(1+2+2, 2)
				w.add(CertificateStatusType.OCSP, 1)
				w.add(0, 2) # responders
				w.add(0, 2) # extensions
			if use_session_ticket:
				w.add(35, 2)
				if self.session_ticket:
					w.addVarSeq(stringToBytes(self.session_ticket), 1,2)
				else:
					w.add(0,2)
			if use_sig_alg:
				w.add(13, 2)
				w.add(10, 2)
				w.add(8, 2)
				w.add(4, 1)
				w.add(1, 1)
				w.add(2, 1)
				w.add(1, 1)
				w.add(1, 1)
				w.add(1, 1)
				w.add(2, 1)
				w.add(2, 1)

			if min_length != None:
				w.add(0xffff,2)
				w.add(min_length,2)
				if min_length:
					w.addFixSeq([0xff]*min_length, 1)
					
		return HandshakeMsg.postWrite(self, w, trial)


class ServerHello(HandshakeMsg):
	def __init__(self):
		self.contentType = ContentType.handshake
		self.server_version = (0,0)
		self.random = createByteArrayZeros(32)
		self.session_id = createByteArraySequence([])
		self.cipher_suite = 0
		self.certificate_type = CertificateType.x509
		self.compression_method = 0
		self.use_renego = False;
		self.support_renego = False
		self.renego_error = False
		self.renego_bytes = None
		self.signal_SNI = False
		self.cert_status_ext_received = False
		self.session_ticket_ext_received = False

	def create(self, version, random, session_id, cipher_suite,
			   certificate_type, use_renego=False, renego_bytes=None):
		self.server_version = version
		self.random = random
		self.session_id = session_id
		self.cipher_suite = cipher_suite
		self.certificate_type = certificate_type
		self.compression_method = 0
		self.use_renego = use_renego;
		self.support_renego = False
		self.renego_error = False
		self.renego_bytes = renego_bytes
		self.signal_SNI = False
		self.cert_status_ext_received = False
		self.session_ticket_ext_received = False
		return self

	def parse(self, p):
		p.startLengthCheck(3)
		self.server_version = (p.get(1), p.get(1))
		self.random = p.getFixBytes(32)
		self.session_id = p.getVarBytes(1)
		self.cipher_suite = p.get(2)
		self.compression_method = p.get(1)
		if not p.atLengthCheck():
			totalExtLength = p.get(2)
			soFar = 0
			while soFar != totalExtLength:
				extType = p.get(2)
				extLength = p.get(2)
				if extType == 0:
					self.signal_SNI = True
				elif extType == 7:
					self.certificate_type = p.get(1)
				elif extType == 0xff01 :
					ri_len = p.get(1)
					if extLength != ri_len +1:
						self.renego_error = True
					else:
						self.support_renego = True
						if ri_len > 0:
							self.renego_bytes = p.getFixBytes(ri_len)
						else:
							self.renego_bytes = None 
						
				elif extType == 5:
					self.cert_status_ext_received =True
				elif extType == 35:
					self.session_ticket_ext_received = True
				else:
					p.getFixBytes(extLength)
				soFar += 4 + extLength
		p.stopLengthCheck()
		return self

	def write(self, trial=False):
		w = HandshakeMsg.preWrite(self, HandshakeType.server_hello, trial)
		w.add(self.server_version[0], 1)
		w.add(self.server_version[1], 1)
		w.addFixSeq(self.random, 1)
		w.addVarSeq(self.session_id, 1, 1)
		w.add(self.cipher_suite, 2)
		w.add(self.compression_method, 1)

		extLength = 0
		if self.certificate_type and self.certificate_type != \
				CertificateType.x509:
			extLength += 5

		if self.use_renego:
			extLength += 5
			if self.renego_bytes:
				if len(self.renego_bytes)>255:
					raise
				extLength += len(self.renego_bytes)

		if extLength != 0:
			w.add(extLength, 2)

		if self.certificate_type and self.certificate_type != \
				CertificateType.x509:
			w.add(7, 2)
			w.add(1, 2)
			w.add(self.certificate_type, 1)

		if self.use_renego:
			w.add(0xff01, 2)
			w.add(1+(len(self.renego_bytes) if self.renego_bytes else 0), 2)
			if self.renego_bytes:
				w.addVarSeq(stringToBytes(self.renego_bytes),1,1)
			else:
				w.add(0, 1)

		return HandshakeMsg.postWrite(self, w, trial)

class Certificate(HandshakeMsg):
	def __init__(self, certificateType):
		self.certificateType = certificateType
		self.contentType = ContentType.handshake
		self.certChain = None

	def create(self, certChain):
		self.certChain = certChain
		return self

	def parse(self, p):
		p.startLengthCheck(3)
		if self.certificateType == CertificateType.x509:
			chainLength = p.get(3)
			index = 0
			certificate_list = []
			while index != chainLength:
				certBytes = p.getVarBytes(3)
				x509 = X509()
				x509.parseBinary(certBytes)
				certificate_list.append(x509)
				index += len(certBytes)+3
			if certificate_list:
				self.certChain = X509CertChain(certificate_list)
		elif self.certificateType == CertificateType.cryptoID:
			s = bytesToString(p.getVarBytes(2))
			if s:
				try:
					import cryptoIDlib.CertChain
				except ImportError:
					raise SyntaxError(\
					"cryptoID cert chain received, cryptoIDlib not present")
				self.certChain = cryptoIDlib.CertChain.CertChain().parse(s)
		else:
			raise AssertionError()

		p.stopLengthCheck()
		return self

	def write(self, trial=False):
		w = HandshakeMsg.preWrite(self, HandshakeType.certificate, trial)
		if self.certificateType == CertificateType.x509:
			chainLength = 0
			if self.certChain:
				certificate_list = self.certChain.x509List
			else:
				certificate_list = []
			#determine length
			for cert in certificate_list:
				bytes = cert.writeBytes()
				chainLength += len(bytes)+3
			#add bytes
			w.add(chainLength, 3)
			for cert in certificate_list:
				bytes = cert.writeBytes()
				w.addVarSeq(bytes, 1, 3)
		elif self.certificateType == CertificateType.cryptoID:
			if self.certChain:
				bytes = stringToBytes(self.certChain.write())
			else:
				bytes = createByteArraySequence([])
			w.addVarSeq(bytes, 1, 2)
		else:
			raise AssertionError()
		return HandshakeMsg.postWrite(self, w, trial)

class CertificateRequest(HandshakeMsg):
	def __init__(self, version):
		self.contentType = ContentType.handshake
		self.certificate_types = []
		self.supported_signature_algs = []
		self.supported_signature_algs_anabled = (version >= (3,3))
		#treat as opaque bytes for now
		self.certificate_authorities = createByteArraySequence([])

	def create(self, certificate_types, certificate_authorities, sig_algs = [], version=(3,0)):
		self.certificate_types = certificate_types
		self.supported_signature_algs = sig_algs
		self.supported_signature_algs_anabled = (version >= (3,3))
		self.certificate_authorities = certificate_authorities
		return self

	def parse(self, p):
		p.startLengthCheck(3)
		self.certificate_types = p.getVarList(1, 1)
		if self.supported_signature_algs_anabled:
			self.supported_signature_algs = p.getVarList(2, 2)
		self.certificate_authorities = p.getVarBytes(2)
		p.stopLengthCheck()
		return self

	def write(self, trial=False):
		w = HandshakeMsg.preWrite(self, HandshakeType.certificate_request,
								  trial)
		w.addVarSeq(self.certificate_types, 1, 1)
		if self.supported_signature_algs:
			w.addVarSeq(self.supported_signature_algs, 2, 2)
			
		w.addVarSeq(self.certificate_authorities, 1, 2)
		return HandshakeMsg.postWrite(self, w, trial)

class ServerKeyExchange(HandshakeMsg):
	def __init__(self, cipherSuite):
		self.cipherSuite = cipherSuite
		self.contentType = ContentType.handshake
		self.srp_N = 0L
		self.srp_g = 0L
		self.srp_s = createByteArraySequence([])
		self.srp_B = 0L
		self.dh_p = 0L
		self.dh_g = 0L
		self.dh_Ys = 0L
		self.signature = createByteArraySequence([])

	def createSRP(self, srp_N, srp_g, srp_s, srp_B):
		self.srp_N = srp_N
		self.srp_g = srp_g
		self.srp_s = srp_s
		self.srp_B = srp_B
		return self

	def createDH(self, dh_p, dh_g, dh_Ys):
		self.dh_g = dh_g
		self.dh_p = dh_p
		self.dh_Ys = dh_Ys
		return self

	def parse(self, p):
		p.startLengthCheck(3)
		if self.cipherSuite in CipherSuite.srpSuites:
			self.srp_N = bytesToNumber(p.getVarBytes(2))
			self.srp_g = bytesToNumber(p.getVarBytes(2))
			self.srp_s = p.getVarBytes(1)
			self.srp_B = bytesToNumber(p.getVarBytes(2))
			if self.cipherSuite in CipherSuite.srpRsaSuites:
				self.signature = p.getVarBytes(2)
		elif self.cipherSuite in CipherSuite.dheSuites:
			self.dh_p = bytesToNumber(p.getVarBytes(2))
			self.dh_g = bytesToNumber(p.getVarBytes(2))
			self.dh_Ys = bytesToNumber(p.getVarBytes(2))
			if self.cipherSuite not in CipherSuite.anonSuites:
				self.signature = p.getVarBytes(2)
			
		p.stopLengthCheck()
		return self

	def write(self, trial=False):
		w = HandshakeMsg.preWrite(self, HandshakeType.server_key_exchange,
								  trial)
		if self.cipherSuite in CipherSuite.srpSuites:
			w.addVarSeq(numberToBytes(self.srp_N), 1, 2)
			w.addVarSeq(numberToBytes(self.srp_g), 1, 2)
			w.addVarSeq(self.srp_s, 1, 1)
			w.addVarSeq(numberToBytes(self.srp_B), 1, 2)
			if self.cipherSuite in CipherSuite.srpRsaSuites:
				w.addVarSeq(self.signature, 1, 2)
		else:
			w.addVarSeq(numberToBytes(self.dh_p), 1, 2)
			w.addVarSeq(numberToBytes(self.dh_g), 1, 2)
			w.addVarSeq(numberToBytes(self.dh_Ys), 1, 2)
			if self.cipherSuite not in CipherSuite.anonSuites:
				w.addVarSeq(self.signature, 1, 2)
			
		return HandshakeMsg.postWrite(self, w, trial)

	def hash(self, clientRandom, serverRandom):
		oldCipherSuite = self.cipherSuite
		self.cipherSuite = None
		try:
			bytes = clientRandom + serverRandom + self.write()[4:]
			s = bytesToString(bytes)
			return stringToBytes(md5.md5(s).digest() + sha.sha(s).digest())
		finally:
			self.cipherSuite = oldCipherSuite

class ServerHelloDone(HandshakeMsg):
	def __init__(self):
		self.contentType = ContentType.handshake

	def create(self):
		return self

	def parse(self, p):
		p.startLengthCheck(3)
		p.stopLengthCheck()
		return self

	def write(self, trial=False):
		w = HandshakeMsg.preWrite(self, HandshakeType.server_hello_done, trial)
		return HandshakeMsg.postWrite(self, w, trial)

class ClientKeyExchange(HandshakeMsg):
	def __init__(self, cipherSuite, version=None):
		self.cipherSuite = cipherSuite
		self.version = version
		self.contentType = ContentType.handshake
		self.srp_A = 0
		self.encryptedPreMasterSecret = createByteArraySequence([])

	def createSRP(self, srp_A):
		self.srp_A = srp_A
		return self

	def createRSA(self, encryptedPreMasterSecret):
		self.encryptedPreMasterSecret = encryptedPreMasterSecret
		return self

	def parse(self, p):
		p.startLengthCheck(3)
		if self.cipherSuite in CipherSuite.srpSuites + \
							   CipherSuite.srpRsaSuites:
			self.srp_A = bytesToNumber(p.getVarBytes(2))
		elif self.cipherSuite in CipherSuite.rsaSuites:
			if self.version in ((3,1), (3,2)):
				self.encryptedPreMasterSecret = p.getVarBytes(2)
			elif self.version == (3,0):
				self.encryptedPreMasterSecret = \
					p.getFixBytes(len(p.bytes)-p.index)
			else:
				raise AssertionError()
		else:
			raise AssertionError()
		p.stopLengthCheck()
		return self

	def write(self, trial=False):
		w = HandshakeMsg.preWrite(self, HandshakeType.client_key_exchange,
								  trial)
		if self.cipherSuite in CipherSuite.srpSuites + \
							   CipherSuite.srpRsaSuites:
			w.addVarSeq(numberToBytes(self.srp_A), 1, 2)
		elif self.cipherSuite in CipherSuite.rsaSuites:
			if self.version in ((3,1), (3,2), (3,3)):
				w.addVarSeq(self.encryptedPreMasterSecret, 1, 2)
			elif self.version == (3,0):
				w.addFixSeq(self.encryptedPreMasterSecret, 1)
			else:
				raise AssertionError()
		else:
			raise AssertionError()
		return HandshakeMsg.postWrite(self, w, trial)

class CertificateVerify(HandshakeMsg):
	def __init__(self):
		self.contentType = ContentType.handshake
		self.signature = createByteArraySequence([])

	def create(self, signature):
		self.signature = signature
		return self

	def parse(self, p):
		p.startLengthCheck(3)
		self.signature = p.getVarBytes(2)
		p.stopLengthCheck()
		return self

	def write(self, trial=False):
		w = HandshakeMsg.preWrite(self, HandshakeType.certificate_verify,
								  trial)
		w.addVarSeq(self.signature, 1, 2)
		return HandshakeMsg.postWrite(self, w, trial)

class ChangeCipherSpec(Msg):
	def __init__(self):
		self.contentType = ContentType.change_cipher_spec
		self.type = 1

	def create(self):
		self.type = 1
		return self

	def parse(self, p):
		p.setLengthCheck(1)
		self.type = p.get(1)
		p.stopLengthCheck()
		return self

	def write(self, trial=False):
		w = Msg.preWrite(self, trial)
		w.add(self.type,1)
		return Msg.postWrite(self, w, trial)


class Finished(HandshakeMsg):
	def __init__(self, version):
		self.contentType = ContentType.handshake
		self.version = version
		self.verify_data = createByteArraySequence([])

	def create(self, verify_data):
		self.verify_data = verify_data
		return self

	def parse(self, p):
		p.startLengthCheck(3)
		if self.version == (3,0):
			self.verify_data = p.getFixBytes(36)
		elif self.version in ((3,1), (3,2), (3,3)):
			self.verify_data = p.getFixBytes(12)
		else:
			raise AssertionError()
		p.stopLengthCheck()
		return self

	def write(self, trial=False):
		w = HandshakeMsg.preWrite(self, HandshakeType.finished, trial)
		w.addFixSeq(self.verify_data, 1)
		return HandshakeMsg.postWrite(self, w, trial)

class ApplicationData(Msg):
	def __init__(self):
		self.contentType = ContentType.application_data
		self.bytes = createByteArraySequence([])

	def create(self, bytes):
		self.bytes = bytes
		return self

	def parse(self, p):
		self.bytes = p.bytes
		return self

	def write(self):
		return self.bytes

class CertificateStatus(HandshakeMsg):
	def __init__(self):
		self.contentType = ContentType.handshake
		self.statusType = CertificateStatusType.OCSP
		self.ocspRepsonse = createByteArraySequence([])

	def create(self, response):
		self.ocspRepsonse = response
		return self

	def parse(self, p):
		p.startLengthCheck(3)
		self.statusType = p.get(1)
		self.ocspRepsonse = p.getVarBytes(3)
		p.stopLengthCheck()
		return self

	def write(self, trial=False):
		w = HandshakeMsg.preWrite(self, HandshakeType.certificate_status,
								  trial)
		w.add(self.statusType, 1)
		w.addVarSeq(self.ocspRepsonse, 1, 3)
		return HandshakeMsg.postWrite(self, w, trial)


class NewSessionTicket(HandshakeMsg):
	def __init__(self):
		self.contentType = ContentType.handshake
		self.expiryHint = 0
		self.session_ticket = createByteArraySequence([])

	def create(self, hint, ticket):
		self.expiryHint = hint
		self.session_ticket = ticket
		return self

	def parse(self, p):
		p.startLengthCheck(3)
		self.expiryHint = p.get(4)
		self.session_ticket = p.getVarBytes(2)
		p.stopLengthCheck()
		return self

	def write(self, trial=False):
		w = HandshakeMsg.preWrite(self, HandshakeType.new_session_ticket,
								  trial)
		w.add(self.expiryHint, 4)
		w.addVarSeq(self.session_ticket, 1, 2)
		return HandshakeMsg.postWrite(self, w, trial)
