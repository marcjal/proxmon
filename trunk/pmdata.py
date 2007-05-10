# ProxMon - Monitors proxies to automate web application penetration tests
# Copyright (C) 2007, Jonathan Wilkins - See accompanying LICENSE for info
"""
Datastore populated by proxy log parsers and consumed by modules
"""
import md5, base64, sha

def md5sum(data):
	m = md5.new(data)
	return m.digest()

def sha1sum(data):
	s = sha.new(data)
	return s.digest()

class pmdata(object):
	def add(self, key, data, dest):
		if key in dest: dest[key].append(data)
		else: dest[key] = [data]
		# XXX - Finish/fix this
		#     - do a move instead?
		#     - pointer records?
		#for f in [md5sum, sha1sum, base64.b64encode]:
		#	if f(key) in dest:
		#		for k in dest[f(key)]:
		#			if k not in dest[key]:
		#				dest[key].extend(dest[f(key)])
		#for f in [base64.b64decode]:
		#	try:
		#		if f(key) in dest:
		#			for k in dest[key]:
		#				if k not in dest[f(key)]:
		#					dest[f(key)].extend(dest[key])
		#	except: pass

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
		self.SecureValues = {} # XXX: rename to SSLValues?
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
			self.add(c['value'], nv, self.SecureValues)
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
			self.add(c['value'], nv, self.SecureValues)
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
			self.add(qs['value'], nv, self.SecureValues)
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
			self.add(pp['value'], nv, self.SecureValues)
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
