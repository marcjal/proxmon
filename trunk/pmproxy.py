# ProxMon - Monitors proxies to automate web application penetration tests
# Copyright (C) 2007, Jonathan Wilkins - See accompanying LICENSE for info
loaderror = False

class pmproxy(object):
	"""
	Base class for proxies

	These are the functions that have to be implemented for a new
	proxy to function with the framework
	"""
	proxy_name = 'Unknown (set proxy_name)'
	def sessions(self, where):
		"""
		Get a list of all known sessions

		@param where: location to look (path, database name, etc),
		None to use default
		@return: list of sessions
		"""
		return []

	def session_info(self, where, name):
		"""
		Get information on the specified session

		@return: dictionary
		"""
		# dict must contain:
		# - date/age of session
		# - session active?
		# - list of transactions
		#   - IDs w/request lines and status lines
		# - list of domains seen
		return {}

	def get(self, session, tinfo):
		"""
		Get a specific transaction

		@return: dict
		"""
		return {}

	def get_next(self, session):
		"""
		Get the next transaction

		@return: dict
		"""
		return {}
