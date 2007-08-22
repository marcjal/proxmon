"Find directories that allow directory listing"
from pmcheck import *
from pmutil import *
try:
	import urltesting
except ImportError:
	loaderror = True

class dir_listing(netcheck):
	"Find directories that allow directory listing"
	def __init__(self):
		netcheck.__init__(self)
		self.checked_dirs_by_server = {}

	def run(self, pmd):
		end = len(pmd.Transactions)
		for t in pmd.Transactions[self.lasttransaction:end]:
			dirs = implied_dirs(t['path'])
			for d in dirs:
				if t['server'] in self.checked_dirs_by_server:
					if d in self.checked_dirs_by_server[t['server']]:
						continue
				if urltesting.gives_directory_listing(t['proto']+'://'+t['server']+d):
					desc = 'Listing of %s on %s succeeded' % (d, t['server'])
					self.add_single(desc)
				if t['server'] in self.checked_dirs_by_server:
					self.checked_dirs_by_server[t['server']].append(d)
				else:
					self.checked_dirs_by_server[t['server']] = [d]
		self.lasttransaction = end
