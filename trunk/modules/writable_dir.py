"Find directories writable via PUT"
from pmcheck import *
from pmutil import *
try:
	import urltesting
except ImportError:
	loaderror = True

class writable_dir(netcheck):
	"Find directories writable via PUT"
	def __init__(self):
		netcheck.__init__(self)
		self.checked_dirs_by_host = {}

	def run(self, pmd):
		end = len(pmd.Transactions)
		for t in pmd.Transactions[self.lasttransaction:end]:
			dirs = implied_dirs(t['path'])
			for d in dirs:
				if self.verbosity > 1: print self.__doc__ + ": testing " + d + " on " + t['server']
				if t['server'] in self.checked_dirs_by_host:
					if d in self.checked_dirs_by_host[t['server']]:
						continue
				if urltesting.allows_upload(t['proto']+'://'+t['server']+d):
					desc = 'Upload to %s on %s succeeded' % (d, t['server'])
					self.add_single(desc)
				if t['server'] in self.checked_dirs_by_host:
					self.checked_dirs_by_host[t['server']].append(d)
				else:
					self.checked_dirs_by_host[t['server']] = [d]
		self.lasttransaction = end


