"Find HTTP Basic or Digest Authentication usage"
from pmcheck import *
import re, base64

class http_auth(check):
	"Find HTTP Basic or Digest Authentication usage"

	def req_hl_parse(self, l, t):
		m = re.search('^Authorization:\sBasic (.*)', l, re.IGNORECASE)
		if m:
			desc = "Basic auth seen: %s" %  base64.decodestring(m.group(1))
			vdesc = 'Encoded version: %s' % (l.strip())
			self.add_single(desc, id=t['id'], verbose=vdesc)
		elif re.search('^Authorization:\sDigest', l, re.IGNORECASE):
			desc = "Digest auth seen: %s" % (l.strip())
			self.add_single(desc, id=t['id'])
