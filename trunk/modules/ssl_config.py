"Find SSL server configuration issues"
import os, re, sys, select, socket, string, urlparse
if __name__ == '__main__': sys.path.append('..')
from pmcheck import *
from pmutil import *

try:
	from OpenSSL import SSL
except ImportError:
	loaderror = True

# Portions adapted from code written by David Thiel <david@isecpartners.com>

class ssl_config(netcheck):
	"Find SSL server configuration issues"
	def __init__(self):
		netcheck.__init__(self)
		self.checked_hosts = []

		if loaderror: return

		if os.getenv('https_proxy'):
			self.open_ssl = self.proxy_conn_open
		else:
			self.open_ssl = self.conn_open

		# http://httpd.apache.org/docs/2.0/mod/mod_ssl.html#sslciphersuite
		self.ciphers = [("HIGH", True, "High strength ciphers"),
			("MED", False, "Medium strength ciphers"),
			("LOW", False, "Low strength ciphers"),
			("EXP", False, "Export strength ciphers"),
			("EXPORT40", False, "40 bit Export strength ciphers"),
			("eNULL", False, "eNULL null cipher"),
			("aNULL", False, "aNULL null cipher"),
			("aDH", False, "aDH anonymous DH cipher")
		]

		self.methods = [(SSL.TLSv1_METHOD, True, "TLS protocol"),
			(SSL.SSLv3_METHOD, True, "SSLv3 protocol"),
			(SSL.SSLv2_METHOD, False, "SSLv2 protocol")
		]

	def check_ssl_err(self, e):
		# XXX: we're ignoring errors because they're likely things
		#      like no cipher match, which is expected
		#print '[x] error in ssl_config:proxy_conn_open %s' % e
		pass

	def conn_open(self, host, port, cipherlist=None):
		try:
			ctx = SSL.Context(SSL.SSLv23_METHOD)
			if cipherlist:
				ctx.set_cipher_list(cipherlist)
			sock = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
			sock.connect((host, int(port)))
			return sock
		except SSL.Error, e:
			self.check_ssl_err(e)
		except socket.error: print '[x] ssl_config: error connecting to %s' % host
		return None

	def proxy_conn_open(self, host, port, cipherlist=None):
		try:
			proxy = self.parse_proxy(os.environ['https_proxy'])
			if not proxy: return False
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect(proxy)
			connectreq = 'CONNECT %s:%s HTTP/1.0\r\n\r\n' % (host, port)
			s.send(connectreq)
			s.recv(1024)
			ctx = SSL.Context(SSL.SSLv23_METHOD)
			if cipherlist:
				ctx.set_cipher_list(cipherlist)
			sock = SSL.Connection(ctx, s)
			sock.set_connect_state()
			return sock
		except SSL.Error, e:
			self.check_ssl_err(e)
		except socket.error: print '[x] ssl_config: error connecting to %s' % host
		return None

	def check_ciphers(self, host, port):
		for cipher, desired, desc in self.ciphers:
			try:
				sock = self.open_ssl(host, port, cipherlist=cipher)
				if not sock: continue
				sock.send("\n")
				if not desired:
					u = 'https://' + host + ':'+str(port)
					desc = "[*] SSL Config issue %s: %s" % (u, desc)
					self.add_single(desc)
				sock.shutdown()
				sock.close()
			except SSL.Error, e:
				self.check_ssl_err(e)
			except socket.error: print '[x] ssl_config: error connecting to %s' % host

	def check_methods(self, host, port):
		for method, desired, desc in self.methods:
			try:
				sock = self.open_ssl(host, port)
				if not sock: continue
				sock.send("\n")
				servercert = sock.get_peer_certificate()
				if not desired:
					u = 'https://' + host + ':'+str(port)
					desc = "[*] SSL Config issue %s: %s" % (u, desc)
					self.add_single(desc)
				sock.shutdown()
				sock.close()
			except SSL.Error, e:
				self.check_ssl_err(e)
			except socket.error: print '[x] ssl_config: error connecting to %s' % host

	def proxy_check_key(self, host, port):
		# POC for proxy_conn_open
		try:
			proxy = self.parse_proxy(os.environ['https_proxy'])
			if not proxy: return False
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect(proxy)
			connectreq = 'CONNECT %s:%s HTTP/1.0\r\n\r\n' % (host, port)
			s.send(connectreq)
			s.recv(1024)
			ctx = SSL.Context(SSL.SSLv23_METHOD)
			sock = SSL.Connection(ctx, s)
			sock.set_connect_state()
			sock.send("\n")
			servercert = sock.get_peer_certificate()
			keylen = servercert.get_pubkey().bits()
			u = 'https://' + host + ':'+str(port)
			if keylen < 1024:
				desc = "[*] SSL Config issue %s: %s" % (u, "Key is < 1024 bits")
				self.add_single(desc)
			#else: print "%s:%s keylen %d" % (host, port, keylen)
			if servercert.has_expired():
				desc = "[*] SSL Config issue %s: %s" % (u, "Cert has expired")
				self.add_single(desc)
		except SSL.Error, e:
			self.check_ssl_err(e)
		except socket.error: print '[x] ssl_config: error connecting to %s' % host

	def check_key(self, host, port):
		try:
			sock = self.open_ssl(host, port)
			if not sock: return
			sock.send("\n")
			servercert = sock.get_peer_certificate()
			keylen = servercert.get_pubkey().bits()
			u = 'https://' + host + ':'+str(port)
			if keylen < 1024:
				desc = "[*] SSL Config issue %s: %s" % (u, "Key is < 1024 bits")
				self.add_single(desc)
			if servercert.has_expired():
				desc = "[*] SSL Config issue %s: %s" % (u, "Cert has expired")
				self.add_single(desc)
		except SSL.Error, e:
			self.check_ssl_err(e)
		except socket.error: print '[x] ssl_config: error connecting to %s' % host

	def parse_proxy(self, proxy):
		m = re.search(r'(http[s]{0,1}://){0,1}(\w+[.\w]*)(:(\d+)){0,1}(/){0,1}(.*)', proxy, re.I)
		if m:
			host = m.group(2)
			port = m.group(4)
			if not port: port = '8008'
			return (host, int(port))
		return None

	# XXX - kill after a reasonable interval
	def run(self, pmd):
		if loaderror:
			return

		end = len(pmd.Transactions)
		for t in pmd.Transactions[self.lasttransaction:end]:
			if((t['proto'] == 'https') and (t['server'] not in self.checked_hosts)):
				self.check_key(t['hostname'], t['port'])
				self.check_methods(t['hostname'], t['port'])
				self.check_ciphers(t['hostname'], t['port'])
				self.checked_hosts.append(t['server'])
		self.lasttransaction = end

if __name__ == '__main__':
	if 'https_proxy' in os.environ:
		del os.environ['https_proxy']

	sc = ssl_config()

	print 'Testing bitland.net, no proxy'
	sc.check_key('bitland.net', 443)
	sc.check_methods('bitland.net', 443)
	sc.check_ciphers('bitland.net', 443)

	os.environ['https_proxy'] = 'localhost:8111'
	print 'Testing gmail.google.com, with proxy %s' % os.environ['https_proxy']
	sc.check_key('gmail.google.com', 443)
	sc.check_methods('gmail.google.com', 443)
	sc.check_ciphers('gmail.google.com', 443)
	del os.environ['https_proxy']

	sc.show_all()
