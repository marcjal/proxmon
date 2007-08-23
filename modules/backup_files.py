"Search for common backup file extensions"
import threading
from pmcheck import *
from pmutil import *
try:
	import urltesting
except ImportError:
	loaderror = True

class checkit(threading.Thread):
	def __init__(self, t, checked, exts, results):
		threading.Thread.__init__(self)
		
		self.results = results
		self.checked_paths_by_host = checked
		self.backup_exts = exts
		self.t = t

	def run(self):
		t = self.t
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
				self.results.append(desc)
			if t['server'] in self.checked_paths_by_host:
				self.checked_paths_by_host[t['server']].append(bf)
			else:
				self.checked_paths_by_host[t['server']] = [bf]


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
		results = []
		tlist = []
		# XXX this will break if there are too many threads to be
		# created.  
		for t in pmd.Transactions[self.lasttransaction:end]:
			c = checkit(t, self.checked_paths_by_host, 
						self.backup_exts, results)
			tlist.append(c)
			c.start()
		for t in tlist:
			t.join()
		for r in results:
			self.add_single(r)
		self.lasttransaction = end

