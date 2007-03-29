# ProxMon - Monitors proxies to automate web application penetration tests
# Copyright (C) 2007, Jonathan Wilkins - See accompanying LICENSE for info
"""
Datastore populated by proxy log parsers and consumed by modules
"""
class pmdata(object):
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

		if c['value'] in self.SetCookieValues:
			self.SetCookieValues[c['value']].append(nv)
		else:
			self.SetCookieValues[c['value']] = [nv]

		if c['value'] in self.AllCookieValues:
			self.AllCookieValues[c['value']].append(nv)
		else:
			self.AllCookieValues[c['value']] = [nv]

		if c['value'] in self.AllValues:
			self.AllValues[c['value']].append(nv)
		else:
			self.AllValues[c['value']] = [nv]

		if c['httpparams']['proto'] == 'https':
			if c['value'] in self.SetCookieSSLValues:
				self.SetCookieSSLValues[c['value']].append(nv)
			else:
				self.SetCookieSSLValues[c['value']] = [nv]
			if c['value'] in self.SecureValues:
				self.SecureValues[c['value']].append(nv)
			else:
				self.SecureValues[c['value']] = [nv]
		else:
			if c['value'] in self.ClearValues:
				self.ClearValues[c['value']].append(nv)
			else:
				self.ClearValues[c['value']] = [nv]

		if 'secure' in c:
			if c['value'] in self.SetCookieSecureValues:
				self.SetCookieSecureValues[c['value']].append(nv)
			else:
				self.SetCookieSecureValues[c['value']] = [nv]

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

		if c['value'] in self.SentCookieValues:
			self.SentCookieValues[c['value']].append(nv)
		else:
			self.SentCookieValues[c['value']] = [nv]

		if c['value'] in self.AllCookieValues:
			self.AllCookieValues[c['value']].append(nv)
		else:
			self.AllCookieValues[c['value']] = [nv]

		if c['value'] in self.AllValues:
			self.AllValues[c['value']].append(nv)
		else:
			self.AllValues[c['value']] = [nv]

		if c['httpparams']['proto'] == 'https':
			if c['value'] in self.SecureValues:
				self.SecureValues[c['value']].append(nv)
			else:
				self.SecureValues[c['value']] = [nv]
		else:
			if c['value'] in self.ClearValues:
				self.ClearValues[c['value']].append(nv)
			else:
				self.ClearValues[c['value']] = [nv]


	def add_querystring(self, qs):
		# gets passed a single value
		self.QueryStrings.extend([qs])
		nv = {}
		nv['name'] = qs['name']
		nv['httpparams'] = qs['httpparams']
		nv['type'] = 'qs'

		if qs['value'] in self.QueryStringValues:
			self.QueryStringValues[qs['value']].append(nv)
		else:
			self.QueryStringValues[qs['value']] = [nv]

		if qs['value'] in self.AllValues:
			self.AllValues[qs['value']].append(nv)
		else:
			self.AllValues[qs['value']] = [nv]

		if qs['httpparams']['proto'] == 'https':
			if qs['value'] in self.SecureValues:
				self.SecureValues[qs['value']].append(nv)
			else:
				self.SecureValues[qs['value']] = [nv]
		else:
			if qs['value'] in self.ClearValues:
				self.ClearValues[qs['value']].append(nv)
			else:
				self.ClearValues[qs['value']] = [nv]


	def add_postparam(self, pp):
		# gets passed a single value
		self.PostParams.extend([pp])
		nv = {}
		nv['name'] = pp['name']
		nv['httpparams'] = pp['httpparams']
		nv['type'] = 'post'

		if pp['value'] in self.PostParamValues:
			self.PostParamValues[pp['value']].append(nv)
		else:
			self.PostParamValues[pp['value']] = [nv]

		if pp['value'] in self.AllValues:
			self.AllValues[pp['value']].append(nv)
		else:
			self.AllValues[pp['value']] = [nv]

		if pp['httpparams']['proto'] == 'https':
			if pp['value'] in self.SecureValues:
				self.SecureValues[pp['value']].append(nv)
			else:
				self.SecureValues[pp['value']] = [nv]
		else:
			if pp['value'] in self.ClearValues:
				self.ClearValues[pp['value']].append(nv)
			else:
				self.ClearValues[pp['value']] = [nv]


	def add_transactions(self, trans):
		"""
		Adds a list of transactions to Transactions

		@param trans: The transaction
		"""
		self.Transactions.extend([trans])

	def find_value(self, value):
		pass
