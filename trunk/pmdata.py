# ProxMon - Monitors proxies to automate web application penetration tests
# Copyright (C) 2007, Jonathan Wilkins - See accompanying LICENSE for info
"""
Datastore populated by proxy log parsers and consumed by modules
"""
import md5, base64, sha, re

def md5sum(data):
	m = md5.new(data)
	return m.hexdigest()

def sha1sum(data):
	s = sha.new(data)
	return s.hexdigest()

# A series of base64 decodes to handle all of the weird variants commonly seen
# stock: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
#        padding: =
	# misc: no padding
	# others: padding - instead of =
def b64d(data):
	return base64.standard_b64decode(data)

def b64d_url(data):
	return base64.urlsafe_b64decode(data)

def b64d_regex(data):
	return base64.b64decode(data, '!-')

def b64d_xml1(data):
	return base64.b64decode(data, '_-')

def b64d_xml2(data):
	return base64.b64decode(data, '._')

def b64d_miscpad1(data):
	if data[-2:] == '--':
		return base64.b64decode(re.sub('-','=', data))

def b64d_nopad(data):
	if data[-1] != data[-2]:
		return base64.b64decode(data+'==')

class pmdata(object):
	def add(self, key, data, dest):
		# see if it's b64 encoded and handle
		if key[-2:] == '--' or key[-2:] == '==':
			for f in [b64d, b64d_url, b64d_regex, b64d_xml1, b64d_xml2, 
					  b64d_miscpad1]:
				try:
					dec = f(key)
					if not dec: continue
					if dec in dest: dest[dec].append(data)
					else: dest[dec] = [data]
				except TypeError, e: 
					if e.message == 'Incorrect padding': pass

		# XXX handle b64d_nopad - will work on most strings, but result is
		# generally wrong

		# key already exists
		if key in dest: 
			if type(dest[key]) == list:
				dest[key].append(data)
			elif type(dest[key]) == str:
				redir = dest[key]
				print "dest[key] is a str (key %s), appending at redir %s" % (key, redir)
				dest[redir].append(data)
			else:
				print '[x] unexpected error in pmdata.add()'
				print '    type is: %s, value %s' % (type(dest[key]), dest[key])
		# key doesn't exist
		else: dest[key] = [data]

		# try hashing the value and see if the hash matches anything we've seen
		for f in [md5sum, sha1sum, base64.b64encode]:
			h = f(key)
			if not h: continue
			if h in dest and type(dest[h]) == list:
				dest[key].extend(dest[h])
				del dest[h]
				dest[h] = key


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

	def find_value(self, value):
		pass
