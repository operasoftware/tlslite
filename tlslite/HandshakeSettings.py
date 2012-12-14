"""Class for setting handshake parameters."""

from constants import CertificateType
from utils import cryptomath
from utils import cipherfactory

class HandshakeSettings:
	"""This class encapsulates various parameters that can be used with
	a TLS handshake.
	@sort: minKeySize, maxKeySize, cipherNames, certificateTypes,
	minVersion, maxVersion

	@type minKeySize: int
	@ivar minKeySize: The minimum bit length for asymmetric keys.

	If the other party tries to use SRP, RSA, or Diffie-Hellman
	parameters smaller than this length, an alert will be
	signalled.  The default is 1023.

	@type maxKeySize: int
	@ivar maxKeySize: The maximum bit length for asymmetric keys.

	If the other party tries to use SRP, RSA, or Diffie-Hellman
	parameters larger than this length, an alert will be signalled.
	The default is 8193.

	@type cipherNames: list
	@ivar cipherNames: The allowed ciphers, in order of preference.

	The allowed values in this list are 'aes256', 'aes128', '3des', and
	'rc4'.  If these settings are used with a client handshake, they
	determine the order of the ciphersuites offered in the ClientHello
	message.

	If these settings are used with a server handshake, the server will
	choose whichever ciphersuite matches the earliest entry in this
	list.

	NOTE:  If '3des' is used in this list, but TLS Lite can't find an
	add-on library that supports 3DES, then '3des' will be silently
	removed.

	The default value is ['aes256', 'aes128', '3des', 'rc4'].

	@type certificateTypes: list
	@ivar certificateTypes: The allowed certificate types, in order of
	preference.

	The allowed values in this list are 'x509' and 'cryptoID'.  This
	list is only used with a client handshake.  The client will
	advertise to the server which certificate types are supported, and
	will check that the server uses one of the appropriate types.

	NOTE:  If 'cryptoID' is used in this list, but cryptoIDlib is not
	installed, then 'cryptoID' will be silently removed.

	@type minVersion: tuple
	@ivar minVersion: The minimum allowed SSL/TLS version.

	This variable can be set to (3,0) for SSL 3.0, (3,1) for
	TLS 1.0, or (3,2) for TLS 1.1.  If the other party wishes to
	use a lower version, a protocol_version alert will be signalled.
	The default is (3,0).

	@type maxVersion: tuple
	@ivar maxVersion: The maximum allowed SSL/TLS version.

	This variable can be set to (3,0) for SSL 3.0, (3,1) for
	TLS 1.0, or (3,2) for TLS 1.1.  If the other party wishes to
	use a higher version, a protocol_version alert will be signalled.
	The default is (3,2).  (WARNING: Some servers may (improperly)
	reject clients which offer support for TLS 1.1.  In this case,
	try lowering maxVersion to (3,1)).
	"""
	def __init__(self):
		self.minKeySize = 512
		self.maxKeySize = 8193
		self.cipherNames = ["aes256", "aes128", "3des", "rc4"]
		self.cipherImplementations = ["cryptlib", "openssl", "pycrypto",
									  "python"]
		self.certificateTypes = ["x509", "cryptoID"]
		self.minVersion = (3,0)
		self.maxVersion = (3,3)
		self.record_versions = (3,0)
		self.ciphersuites = None 
		self.premaster_version_correct = True
		self.send_extensions = True
		self.send_renego_extensions = False
		self.send_renego_extension_and_scsv = False
		self.send_swapped_hello_versions = False # In Client Hello send the hello version in the record field, and a lower in the client hello
		
		self.just_test_cipher = False
		self.extra_padding_bytes = 0
		
		self.use_fake_renego_indication=False
		self.start_fake_renego_indication=False
		
		self.force_premaster_version = None
		self.renegotiation_settings = None
		self.renegotiation_new_session = False
		self.refuse_renegotiation = False
		
		self.use_no_cert_alert = False
		
		self.extra_action_set = set();
		self.extra_action_dict = dict();

	#Filters out options that are not supported
	def _filter(self):
		other = HandshakeSettings()
		other.minKeySize = self.minKeySize
		other.maxKeySize = self.maxKeySize
		other.cipherNames = self.cipherNames
		other.cipherImplementations = self.cipherImplementations
		other.certificateTypes = self.certificateTypes
		other.minVersion = self.minVersion
		other.maxVersion = self.maxVersion
		other.record_versions = self.record_versions
		other.ciphersuites = self.ciphersuites 
		other.premaster_version_correct = self.premaster_version_correct
		other.send_extensions = self.send_extensions
		other.send_renego_extensions = self.send_renego_extensions
		other.send_renego_extension_and_scsv = self.send_renego_extension_and_scsv 
		other.send_swapped_hello_versions = self.send_swapped_hello_versions
		other.just_test_cipher = self.just_test_cipher
		other.extra_padding_bytes = self.extra_padding_bytes
		other.use_fake_renego_indication= self.use_fake_renego_indication
		other.start_fake_renego_indication= self.start_fake_renego_indication
		other.force_premaster_version = self.force_premaster_version
		other.renegotiation_new_session = self.renegotiation_new_session
		other.refuse_renegotiation = self.refuse_renegotiation
		other.use_no_cert_alert = self.use_no_cert_alert
		
		other.extra_action_set = self.extra_action_set;
		other.extra_action_dict = self.extra_action_dict;

		if self.renegotiation_settings:
			other.renegotiation_settings = self.renegotiation_settings._filter()

		if not cipherfactory.tripleDESPresent:
			other.cipherNames = [e for e in self.cipherNames if e != "3des"]
		if len(other.cipherNames)==0:
			raise ValueError("No supported ciphers")

		try:
			import cryptoIDlib
		except ImportError:
			other.certificateTypes = [e for e in self.certificateTypes \
									  if e != "cryptoID"]
		if len(other.certificateTypes)==0:
			raise ValueError("No supported certificate types")

		if not cryptomath.cryptlibpyLoaded:
			other.cipherImplementations = [e for e in \
				self.cipherImplementations if e != "cryptlib"]
		if not cryptomath.m2cryptoLoaded:
			other.cipherImplementations = [e for e in \
				other.cipherImplementations if e != "openssl"]
		if not cryptomath.pycryptoLoaded:
			other.cipherImplementations = [e for e in \
				other.cipherImplementations if e != "pycrypto"]
		if len(other.cipherImplementations)==0:
			raise ValueError("No supported cipher implementations")

		if other.minKeySize<512:
			raise ValueError("minKeySize too small")
		if other.minKeySize>16384:
			raise ValueError("minKeySize too large")
		if other.maxKeySize<512:
			raise ValueError("maxKeySize too small")
		if other.maxKeySize>16384:
			raise ValueError("maxKeySize too large")
		for s in other.cipherNames:
			if s not in ("aes256", "aes128", "rc4", "3des"):
				raise ValueError("Unknown cipher name: '%s'" % s)
		for s in other.cipherImplementations:
			if s not in ("cryptlib", "openssl", "python", "pycrypto"):
				raise ValueError("Unknown cipher implementation: '%s'" % s)
		for s in other.certificateTypes:
			if s not in ("x509", "cryptoID"):
				raise ValueError("Unknown certificate type: '%s'" % s)

		if other.minVersion > other.maxVersion:
			raise ValueError("Versions set incorrectly")

		if not other.minVersion in ((3,0), (3,1), (3,2), (3,3)):
			raise ValueError("minVersion set incorrectly")

		if not other.maxVersion in ((3,0), (3,1), (3,2), (3,3), (3,4), (3,11), (4,1)):
			raise ValueError("maxVersion set incorrectly")

		return other

	def _getCertificateTypes(self):
		l = []
		for ct in self.certificateTypes:
			if ct == "x509":
				l.append(CertificateType.x509)
			elif ct == "cryptoID":
				l.append(CertificateType.cryptoID)
			else:
				raise AssertionError()
		return l
