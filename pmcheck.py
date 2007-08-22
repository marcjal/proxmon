# ProxMon - Monitors proxies to automate web application penetration tests
# Copyright (C) 2007, Jonathan Wilkins - See accompanying LICENSE for info
"""
Contains the base check classes (check, netcheck, postruncheck)
"""
import os, sys, logging
import pdb
import config
from pmutil import *

loaderror = False

log = logging.getLogger("proxmon")

class check(object):
	"""
	Check base class
	"""
	def __init__(self):
		self.results = []
		self.lastreported = 0
		self.lasttransaction = 0
		self.verbosity = 0
		self.cfg = self.load_config()
		self.enabled = True

	def clear(self):
		"""
		Clear all results and reset lastreported and lasttransaction
		"""
		self.results = []
		self.lastreported = 0
		self.lasttransaction = 0

	def set_verbosity(self, verbosity):
		"""
		Sets the level of information displayed by the check"

		@param verbosity: 0 = default, 1=verbose, 2=debug
		@type verbosity: int
		"""
		self.verbosity = verbosity

	def config_loaded(self):
		"""
		Checks if a config file has been loaded and prints an error if not

		Call this at the top of each function if a cfg file is required
		"""
		if self.cfg:
			return True
		if sys._getframe(1).f_code.co_name == '__init__':
			log.warn('%s: Required configuration not found, skipping ...' %
							self.__module__)
		return False

	def load_config(self):
		"""
		Auto-loads the appropriate configuration file for the module

		Config file should have the same name as the python file, with
		.cfg instead of .py
		"""
		basepath = os.path.dirname(os.path.abspath(sys.argv[0]))
		cfgfilename = basepath + os.path.sep
		cfgfilename += os.path.join('modules', self.__module__ + '.cfg')
		if os.path.exists(cfgfilename):
			try:
				return config.Config(cfgfilename)
			except config.ConfigFormatError, e:
				log.error("Error parsing config file: %s %s" % (cfgfilename, e))
		return None

	def show_all(self):
		"""
		Show all results
		"""
		end = len(self.results)
		resbyres = {}
		for r in self.results[:end]:
			if r['result'] in resbyres:
				resbyres[r['result']].append(r)
			else:
				resbyres[r['result']] = [r]

		for r in resbyres:
			if self.verbosity or len(resbyres[r]) < 5:
				resstr = ', '.join([str(s['id']) for s in resbyres[r]])
				if resstr == '0': cmsg("%s" % (r))
				else: cmsg("%s (TIDs: %s)" % (r, resstr))
				if self.verbosity and 'verbose' in resbyres[r][0]:
					log.info(resbyres[r][0]['verbose'].strip())
			else:
				resstr = ', '.join([str(s['id']) for s in resbyres[r][:9]])
				cmsg("%s (TIDs: %s, ...)" % (r, resstr))
		self.lastreported = end

	def show_new(self):
		"Show only results that haven't been displayed before"
		last = len(self.results)
		if last > self.lastreported:
			for r in self.results[self.lastreported:last+1]:
				cmsg(r['result'] + ' (TID: ' + str(r['id']) + ')')
				if self.verbosity:
					if 'verbose' in r: cmsg(r['verbose'])
			self.lastreported = last

	def add_single(self, desc, id=0, verbose=None, module=None, value=None):
		"""
		Add a single result to the datastore
		
		@param desc: Description of the issue
		@keyword id: Transaction ID that contains the issue (if any)
		@keyword verbose: Verbose description of the problem, generally 
			partial content from the transaction
		@keyword module: Name of the module that generated the result
		@keyword value: Specific value that is the problem
		"""
		res = {}
		res['result'] = desc
		res['id'] = id
		if module:  res['module']  = module
		if value:   res['value']   = value
		if verbose: res['verbose'] = verbose
		self.add([res])

	def add(self, items):
		"""
		Add a list of new unique results

		@param items: list of results
		"""
		for i in items:
			if i not in self.results:
				self.results.append(i)

	def rl_parse(self, line, info):
		"Called by the transaction processor on the first line of each request"
		pass

	def req_hl_parse(self, line, info):
		"Called by the transaction processor on all request headers"
		pass

	def req_body_parse(self, body, info):
		"Called by the transaction processor on each complete request body"
		pass

	def sl_parse(self, line, info):
		"Called by the transaction processor on the first line of each response"
		pass

	def resp_hl_parse(self, line, info):
		"Called by the transaction processor on each response header"
		pass

	def resp_body_parse(self, body, info):
		"Called by the transaction processor to parse the whole response body"
		pass

	def run(self, pmd):
		"Called by scan() or tail() once each transaction has been fully added to pmd"
		pass

	def report(self, pmd):
		"Full report run at the end of session, mainly used by postrunchecks"
		pass

class netcheck(check):
	"Base class for all checks that do network stuff"
	def __init__(self):
		check.__init__(self)
		self.proxy = None

	def set_proxy(self, proxy):
		"For those network checks that don't check the environment"
		self.proxy = proxy 

class postruncheck(check):
	"Base class for report modules"
	def __init__(self):
		check.__init__(self)

	def show_all(self):
		"Overriding because postrunchecks shouldn't output until the end"
		pass

	def show_new(self):
		"Overriding because postrunchecks shouldn't output until the end"
		pass

	def report(self, pmd):
		"Main output method called for postrunchecks"
		pass
