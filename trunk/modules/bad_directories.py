"Search for common undesirable directories"
from pmcheck import *
from pmutil import *
try:
	import urltesting
except ImportError:
	loaderror = True

class bad_directories(netcheck):
	"Find common undesirable directories"
	def __init__(self):
		netcheck.__init__(self)
		self.checked_dirs_by_host = {}
		if self.config_loaded():
			self.bad_dirs = self.cfg['bad_dirs']

	def run(self, pmd):
		if not self.cfg: return

		end = len(pmd.Transactions)
		for t in pmd.Transactions[self.lasttransaction:end]:
			dirs = implied_dirs(t['path'])
			for d in dirs:
				for b in self.bad_dirs:
					bd = d + b + '/'
					url = t['proto']+'://'+t['server']+bd
					if t['server'] in self.checked_dirs_by_host:
						if bd in self.checked_dirs_by_host[t['server']]:
							continue
					log.debug("Trying %s" % url)
					if urltesting.url_exists(url):
						desc = 'Bad directory found: %s on %s' % (bd, t['server'])
						self.add_single(desc)
					if t['server'] in self.checked_dirs_by_host:
						self.checked_dirs_by_host[t['server']].append(bd)
					else:
						self.checked_dirs_by_host[t['server']] = [bd]
		self.lasttransaction = end
