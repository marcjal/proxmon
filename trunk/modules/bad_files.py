"Find files that indicate common vulnerabilities"
from pmcheck import *
from pmutil import *
try:
	import urltesting
except ImportError:
	loaderror = True

class bad_files(netcheck):
	"Find files that indicate common vulnerabilities"
	def __init__(self):
		netcheck.__init__(self)
		self.checked_dirs_by_host = {}
		if self.config_loaded():
			self.bad_files = self.cfg['bad_files']

	def run(self, pmd):
		if not self.cfg: return
		end = len(pmd.Transactions)
		for t in pmd.Transactions[self.lasttransaction:end]:
			dirs = implied_dirs(t['path'])
			for d in dirs:
				for b in self.bad_files:
					bd = d + b['file']
					if t['server'] in self.checked_dirs_by_host:
						if bd in self.checked_dirs_by_host[t['server']]:
							continue
					if urltesting.file_contains(t['proto']+'://'+t['server']+bd, b['text']):
						desc = 'Bad file found: %s on %s' % (bd, t['server'])
						verbose = '%s found: %s' % (b['file'], b['desc'])
						self.add_single(desc, verbose=verbose)
					if t['server'] in self.checked_dirs_by_host:
						self.checked_dirs_by_host[t['server']].append(bd)
					else:
						self.checked_dirs_by_host[t['server']] = [bd]
		self.lasttransaction = end
