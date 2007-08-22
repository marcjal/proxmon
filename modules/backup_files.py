"Search for common backup file extensions"
from pmcheck import *
from pmutil import *
try:
	import urltesting
except ImportError:
	loaderror = True

class backup_files(netcheck):
	"Find backup versions of files"
	def __init__(self):
		netcheck.__init__(self)
		self.checked_paths_by_host = {}
		if self.config_loaded():
			self.backup_exts = self.cfg['backup_exts']

	def run(self, pmd):
		if not self.cfg: return

		end = len(pmd.Transactions)
		for t in pmd.Transactions[self.lasttransaction:end]:
			p = t['path']
			if p[-1] == '/': b = p + 'index'
			else:
				dotindex = p.rfind('.')
				slashindex = p.rfind('/')
				if dotindex > -1 and dotindex > slashindex:
					b = p[:dotindex]
				else: b = p
			for e in self.backup_exts:
				if e[0] == '.':
					bf = b + e
				else:
					bf = p + e
				#log.debug("bf: %s" % bf)
				url = t['proto']+'://'+t['server']+bf
				if t['server'] in self.checked_paths_by_host:
					if bf in self.checked_paths_by_host[t['server']]:
						continue
				log.debug("Trying %s" % url)
				if urltesting.url_exists(url):
					desc = 'Backup file found: %s on %s' % (bf, t['server'])
					self.add_single(desc)
				if t['server'] in self.checked_paths_by_host:
					self.checked_paths_by_host[t['server']].append(bf)
				else:
					self.checked_paths_by_host[t['server']] = [bf]
		self.lasttransaction = end
