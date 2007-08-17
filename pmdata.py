# ProxMon - Monitors proxies to automate web application penetration tests
# Copyright (C) 2007, Jonathan Wilkins - See accompanying LICENSE for info
"""
Datastore populated by proxy log parsers and consumed by modules
"""
import md5, base64, sha, re, urllib, logging

hashlengths = [16, 32, 20, 40, 24, 48, 32, 64] 
							   # 128 bit is 16 binary, 32 hex (MD5)
							   # 160 bit is 20 binary, 40 hex (SHA-1)
							   # 192 bit is 24 binary, 48 hex (TIGER)
							   # 256 bit is 32 binary, 64 hex (SHA-256)
nonhexchars = r"[^A-Fa-f\d]"   # regex

log = logging.getLogger("proxmon")
vallog = logging.getLogger("pxmvalues")
vallog.setLevel(logging.DEBUG)
vallog.addHandler(logging.FileHandler('values.pxm', 'wb+'))

def hashformat(s):
	if len(s) in hashlengths and not re.search(nonhexchars, s):
		return True

def md5sum(data):
	m = md5.new(data)
	return m.hexdigest()

def sha1sum(data):
	s = sha.new(data)
	return s.hexdigest()

# A series of base64 decodes to handle all of the weird variants commonly seen
# stock: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
#        padding: =
# variants sub +/ to !-. _-, ._, *! and pad with - or $ or have no padding
# relevant RFC's: 989, 2152, 2440, 4648
def b64d(s):
	d = base64.b64decode(s)
	e = base64.b64encode(d)
	vallog.debug("  Trying b64d: %s -> %s" % (s, e))
	if s == e: return d

def b64d_url(s):
	d = base64.b64decode(s, '-_')
	e = base64.b64encode(d, '-_')
	vallog.debug("  Trying b64d_url: %s -> %s" % (s, e))
	if s == e: return d

def b64d_regex(s):
	d = base64.b64decode(s, '!-')
	e = base64.b64encode(d, '!-')
	vallog.debug("  Trying b64d_regex: %s -> %s" % (s, e))
	if s == e: return d

def b64d_xml1(s):
	d = base64.b64decode(s, '_-')
	e = base64.b64encode(d, '_-')
	vallog.debug("  Trying b64d_xml1: %s -> %s" % (s, e))
	if s == e: return d

def b64d_xml2(s):
	d = base64.b64decode(s, '._')
	e = base64.b64encode(d, '._')
	vallog.debug("  Trying b64d_xml2: %s -> %s" % (s, e))
	if s == e: return d

def b64d_misc1(s):
	d = base64.b64decode(s, '*!')
	e = base64.b64encode(d, '*!')
	vallog.debug("  Trying b64d_misc1: %s -> %s" % (s, e))
	if s == e: return d

def b64normalize(s):
	f = r"([A-Za-z\d+/!\-_.*]{2,})([=$]*)" # regex, no %, use on unquoted
	if len(s) < 2:
		vallog.debug("b64n_skip: Too short")
		return
	m = re.search(f, s)
	if m: 
		if not len(m.group()) == len(s):
			vallog.debug(" b64n_skip: match != whole string %s" % s)
			return

		if len(m.group(2)) == 2:  # if there are two pad chars, they must match
			if not m.group(2)[0] == m.group(2)[1]:
				vallog.debug(" b64n_skip: two mismatched pad chars : %s" % s)
				return

		# get rid of short matches w/o pad since stuff like 'true' will decode
		if len(m.group()) < 5 and (len(m.group(2)) < 1 or m.group()[-1] == '-'):
			vallog.debug(" b64n_skip: short match w/ no pad (%s)", m.group())
			return

		vallog.debug(" key is b64 format (%s)" % s)
		# have to handle '-' padding separately since it's valid in non-pad
		if m.group(1)[-2] == '-':
			return m.group(1)[:-2] + '=='
		if m.group(1)[-2] == '-':
			return m.group(1)[:-1] + '='
		return m.group(1) + "=" * len(m.group(2))
	vallog.debug(" b64n_skip: regex not matched (%s)" % m.group())

class pmdata(object):
	b64tryharder = False
	b64confirm = False
	b64confirmed = {}

	def b64opts(self, tryhard, confirm):
		if tryhard: self.b64tryharder = True
		if confirm: self.b64confirm = True

	def add(self, key, data, dest):
		if key == '':
			log.debug("Not adding empty key")
			return

		log.debug("Adding %s" % (key))
		vallog.warn('----------------')
		vallog.warn('key: %s' % key)
		# see if it's likely b64 encoded (scans for characters not used in b64)
		unquotedkey = urllib.unquote(key)
		normalizedkey = b64normalize(unquotedkey)
		if normalizedkey and not hashformat(unquotedkey):
			doit = True
			if self.b64confirm:
				if key in self.b64confirmed:
					doit = self.b64confirmed[key]
				else:
					try:
						ask = "[?] (Y/N) Base64 decode:\n%s\nto\n%s" % (
							unquotedkey, 
							urllib.quote(base64.b64decode(unquotedkey)))
						resp = raw_input(ask)
						if resp not in ['Y', 'y']: doit = False
					except: doit = False
					self.b64confirmed[key] = doit

			if doit:
				b64success = False
				for f in [b64d, b64d_url, b64d_regex, 
							b64d_xml1, b64d_xml2, b64d_misc1]:
					try:
						dec = f(normalizedkey)
						if not dec: 
							continue
						else:
							# get rid of things that have a bad UPPER lower ratio
							upperc = len(re.findall(r'[A-Z]', normalizedkey))
							lowerc = len(re.findall(r'[a-z]', normalizedkey))
							if not (lowerc and upperc):
								vallog.debug(" upper or lower is 0 - %s" % normalizedkey)
								continue
							r1 = float(upperc/lowerc)
							r2 = float(lowerc/upperc)
							vallog.debug(" upper/lower is %.03f, "
										 "lower/upper is %.03f - %s" % (
									r1, r2, normalizedkey))
							if max(r1, r2) > 3:
								vallog.debug(" bad ratio - %s" % normalizedkey)
								continue
							key = urllib.quote(dec)
							log.debug("b64 decoded decoded: %s -> %s" % (
									normalizedkey, key))
							vallog.warn("    decoded: %s -> %s" % (
									normalizedkey, key))
							b64success = True
							break
					except TypeError, e: 
						if e.message == 'Incorrect padding': pass
				if not b64success:
					log.debug("Couldn't b64 decode")
					vallog.warn("    Couldn't b64 decode %s", normalizedkey)

		# key already exists
		if key in dest: 
			if type(dest[key]) == list:
				dest[key].append(data)
			elif type(dest[key]) == str:  # pointer to unhashed
				redir = dest[key]
				#log.warn("dest[key] is a str (key %s), appending at redir %s" % (key, redir))
				dest[redir].append(data)
			else:
				log.warn('[x] unexpected error in pmdata.add()')
				log.warn('    type is: %s, value %s' % (type(dest[key]), dest[key]))
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
			if keylen == 16 or keylen == 24 or not re.search(nonhexchars, key):
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
