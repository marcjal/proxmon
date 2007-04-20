"Find cookies with the secure flag that also get sent cleartext"
from pmcheck import *
from pmutil import *

class secure_cookie_sent_clear(check):
	"Find cookies with the secure flag that also get sent cleartext"

	def run(self, pmd):
		for s in pmd.SetCookieSecureValues:
			if s in trivial_values: continue
			if s in pmd.ClearValues:
				for x in pmd.ClearValues[s]:
					desc = "[*] Secure cookie value sent clear: %s" % s
					id = x['httpparams']['id']
					self.add_single(desc, id=id)
