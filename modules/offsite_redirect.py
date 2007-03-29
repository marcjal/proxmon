"Find offsite redirects"
import re
from pmcheck import *

class offsite_redirect(check):
	"Find offsite redirects"

	# XXX: add body parsers to find meta-refresh redirects and so forth
	def run(self, pmd):
		end = len(pmd.Transactions)
		for t in pmd.Transactions[self.lasttransaction:end]:
			if 'location' in t and 'host' in t:
				if not (299 < t['code'] < 400): continue
				m = re.match(r"^http[s]*://([^:/]+)[:/].*", t['location'], re.I)
				if m and t['host'] != m.group(1):
					desc = '[*] Offsite redirect: %s to %s' % (t['url'], t['location'])
					self.add_single(desc, id=t['id'])
		self.lasttransaction = end
