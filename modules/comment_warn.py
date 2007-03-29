"Find interesting comments"
import re, cStringIO, pdb
from pmcheck import *
from pmutil import *

class interesting_comments(check):
	"Find interesting comments"

	def __init__(self):
		check.__init__(self)
		if self.config_loaded():
			self.warn_rx = '\W('+'|'.join(self.cfg['warn_strings'])+')\W'

	def resp_body_parse(self, body, t):
		if not self.cfg: return
		if binary_response(t): return

		for c in comment_rx:
			cp = re.compile(c, re.MULTILINE)
			for cm in cp.finditer(body):
				sp = re.compile(self.warn_rx, re.IGNORECASE)
				sm = sp.search(cm.group())
				if sm:
					desc = '[*] Interesting comment: %s in %s' % (
							sm.group(1).strip(),t['url'])
					len = cm.group()[sm.span()[0]:].find('\n')
					if (len > 50 or len < 0): len = 50
					vdesc = cm.group()[sm.span()[0]:sm.span()[0]+len]
					self.add_single(desc, verbose=vdesc, id=t['id'])
