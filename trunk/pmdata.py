# ProxMon - Monitors proxies to automate web application penetration tests
# Copyright (C) 2007, Jonathan Wilkins - See accompanying LICENSE for info
"""
Datastore populated by proxy log parsers and consumed by modules
"""
import md5, base64, sha, re, urllib

b64padding = ['==', '--', '$$']
hashlengths = [16, 32, 24, 48] # 128 bit is 16 binary, 32 in hex
							   # 192 bit is 24 binary, 48 in hex
b64charset = r"[\w!-.+/*!=]"
hexcharset = r"[ABCDEF\d]"

def md5sum(data):
	m = md5.new(data)
	return m.hexdigest()

def sha1sum(data):
	s = sha.new(data)
	return s.hexdigest()

# A series of base64 decodes to handle all of the weird variants commonly seen
# stock: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
#        padding: =
# variants sub +/ to !-. _-, ._, *! and sub = to -, $ or have no padding
def b64d(s):
	return base64.b64decode(s)

def b64d_urldecode(s):
	return base64.urlsafe_b64decode(urllib.unquote(s))

def b64d_url(s):
	return base64.urlsafe_b64decode(s)

def b64d_regex(s):
	return base64.b64decode(s, '!-')

def b64d_xml1(s):
	return base64.b64decode(s, '_-')

def b64d_xml2(s):
	return base64.b64decode(s, '._')

def b64d_misc1(s):
	return base64.b64decode(s, '*!')

def b64d_nopad(s):
	if s[-1] != s[-2]:
		return base64.b64decode(s+'==')

class pmdata(object):
	b64tryharder = False
	b64confirm = False
	b64confirmed = {}

	def b64opts(self, tryhard, confirm):
		if tryhard: self.b64tryharder = True
		if confirm: self.b64confirm = True

	def add(self, key, data, dest):
		print "[d] Adding %s" % (key)
		if key == '': return
		# see if it's likely b64 encoded (scans for characters not used in b64)
		if not re.search(b64charset, key):
			newkey = tmpkey = False
			doit = False
			keyend1 = key[-2:]
			keyend2 = urllib.unquote(key[-6:])
			keyend3 = key[-1:]
			if keyend1 in b64padding:
				newkey = ''.join([key[:-2], '=='])
				#print "[d] newkey %s" % newkey
			elif keyend2 in b64padding:
				newkey = ''.join([urllib.unquote(key)[:-2], '=='])
				#print "[d] newkey urlenc %s" % newkey
			elif self.b64tryharder:
				if keyend3 in ['=', '-']:
					newkey = ''.join([key[:-1], '=='])
				elif urllib.unquote(keyend3) in ['=', '-']:
					newkey = ''.join([urllib.unquote(key)[:-1], '=='])
			elif self.b64confirm:
				if key in self.b64confirmed:
					doit = self.b64confirmed[key]
				else:
					tmpkey = urllib.unquote(key)
					if len(tmpkey) < 2:
						tmpkey = ''.join([tmpkey, '=='])
					elif tmpkey[-1] in ['=','-'] and tmpkey[-2] != tmpkey[-1]:
						tmpkey = ''.join([tmpkey[:-1], '=='])
					else:
						tmpkey = ''.join([tmpkey, '=='])
					try:
						ask = "[?] (Y/N) Base64 decode:\n  %s\n  --to--\n  %s? " % (urllib.unquote(key),
											urllib.quote(base64.b64decode(tmpkey)))
						resp = raw_input(ask)
						if resp in ['Y', 'y']: doit = True
						else: doit = False
					except:
						doit = False
					self.b64confirmed[key] = doit

			if self.b64confirm and doit:
				newkey = tmpkey

			if newkey:
				for f in [b64d, b64d_urldecode, b64d_url, 
						  b64d_regex, b64d_xml1, b64d_xml2, b64d_misc1]:
					try:
						dec = f(newkey)
						if not dec: 
							#print "[d] not dec"
							continue
						#dec = urllib.quote(dec) # XXX should this be escaped?
						if dec in dest: 
							print "[d] added b64d to existing: %s" % dec
							dest[dec].append(data)
							break
						else: 
							print "[d] added b64d to new: %s" % dec
							dest[dec] = [data]
							break
					except TypeError, e: 
						if e.message == 'Incorrect padding': pass

			# XXX handle b64d_nopad - will work on most strings, but result is
			#     generally wrong
			# XXX short strings tend not to have padding? - check b64 spec!

		# key already exists
		if key in dest: 
			if type(dest[key]) == list:
				dest[key].append(data)
			elif type(dest[key]) == str:  # pointer to unhashed
				redir = dest[key]
				#print "dest[key] is a str (key %s), appending at redir %s" % (key, redir)
				dest[redir].append(data)
			else:
				print '[x] unexpected error in pmdata.add()'
				print '    type is: %s, value %s' % (type(dest[key]), dest[key])
		# key doesn't exist
		else: dest[key] = [data]

		# try hashing the value and see if the hash matches anything we've seen
		for f in [md5sum, sha1sum]:
			h = f(key)
			if not h: continue
			if h in dest and type(dest[h]) == list:
				dest[key].extend(dest[h])
				del dest[h]
				dest[h] = key

		# if the value is the same length as a hash, add to PossibleHashes
		keylen = len(key)
		if keylen in hashlengths:
			if keylen == 16 or keylen == 24 or not re.search(hexcharset, key):
				if key in self.PossibleHashes:
					self.PossibleHashes[key].append(data)
				else:
					self.PossibleHashes[key] = [data]

		# XXX if a subsection of a value is the same format as a basic b64
		#     block, flag it.

	def __init__(self):
		self.Transactions = []

		self.SetCookies = []
		self.SentCookies = []
		self.QueryStrings = []
		self.PostParams = []

		self.SetCookieValues = {}
		self.SetCookieSSLValues = {}
		self.SetCookieSecureValues = {}
		self.SentCookieValues = {}
		self.AllCookieValues = {}

		self.QueryStringValues = {}
		self.PostParamValues = {}

		self.ClearValues = {}
		self.SSLValues = {}
		self.AllValues = {}

		self.PossibleHashes = {}

	def add_setcookie(self, c):
		"""
		Set cookie headers contain a single cookie, parse this and add
		the contents to the various cookie dictionaries

		@param c: A cookie
		"""
		self.SetCookies.extend([c])
		nv = {}
		nv['name'] = c['name']
		nv['httpparams'] = c['httpparams']
		nv['type'] = 'setcookie'
		# XXX - do other cookie params

		self.add(c['value'], nv, self.SetCookieValues)
		self.add(c['value'], nv, self.AllCookieValues)
		self.add(c['value'], nv, self.AllValues)

		if c['httpparams']['proto'] == 'https':
			self.add(c['value'], nv, self.SetCookieSSLValues)
			self.add(c['value'], nv, self.SSLValues)
		else:
			self.add(c['value'], nv, self.ClearValues)

		if 'secure' in c:
			self.add(c['value'], nv, self.SetCookieSecureValues)

	def add_sentcookie(self, c):
		"""
		Add a cookie that was sent by a client

		@param c: A cookie
		"""
		self.SentCookies.extend([c])
		nv = {}
		nv['name'] = c['name']
		nv['httpparams'] = c['httpparams']
		nv['type'] = 'sentcookie'

		self.add(c['value'], nv, self.SentCookieValues)
		self.add(c['value'], nv, self.AllCookieValues)
		self.add(c['value'], nv, self.AllValues)

		if c['httpparams']['proto'] == 'https':
			self.add(c['value'], nv, self.SSLValues)
		else:
			self.add(c['value'], nv, self.ClearValues)

	def add_querystring(self, qs):
		# gets passed a single value
		self.QueryStrings.extend([qs])
		nv = {}
		nv['name'] = qs['name']
		nv['httpparams'] = qs['httpparams']
		nv['type'] = 'qs'

		self.add(qs['value'], nv, self.QueryStringValues)
		self.add(qs['value'], nv, self.AllValues)

		if qs['httpparams']['proto'] == 'https':
			self.add(qs['value'], nv, self.SSLValues)
		else:
			self.add(qs['value'], nv, self.ClearValues)

	def add_postparam(self, pp):
		# gets passed a single value
		self.PostParams.extend([pp])
		nv = {}
		nv['name'] = pp['name']
		nv['httpparams'] = pp['httpparams']
		nv['type'] = 'post'

		self.add(pp['value'], nv, self.PostParamValues)
		self.add(pp['value'], nv, self.AllValues)
		if pp['httpparams']['proto'] == 'https':
			self.add(pp['value'], nv, self.SSLValues)
		else:
			self.add(pp['value'], nv, self.ClearValues)

	def add_transactions(self, trans):
		"""
		Adds a list of transactions to Transactions

		@param trans: The transaction
		"""
		self.Transactions.extend([trans])

	def find_value(self, key, source):
		if type(source[key]) == list:
			return source[key]
		elif type(source[key]) == str:
			return source[source[key]]

if __name__ == '__main__':
	print '[*] Testing B64 stuff'

	b64strings= [
		'dGVzdDAx',
		'YXNkZmFzZGY=',
		'YXNkZmFzZGZhc2RmYXNkZg==']
	
	for s in b64strings:
		for f in [b64d]:
			if base64.b64encode(f(s)) != f(s):
				print "error with %s" % s
