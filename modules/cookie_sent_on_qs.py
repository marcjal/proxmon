"Find cookie values that also are sent on the query string"
from pmcheck import *
from pmutil import *

class cookie_sent_on_qs(check):
	"Find cookie values that also are sent on the query string"

	def run(self, pmd):
		for cv in pmd.AllCookieValues:
			if cv in trivial_values:
				continue
			if cv in pmd.QueryStringValues:
				for qv in pmd.QueryStringValues[cv]:
					# If the setcookie was originally over SSL or had
					# the Secure flag, note that
					flags = ''
					if cv in pmd.SetCookieSecureValues:
						flags = ' (Secure)'
					if cv in pmd.SetCookieSSLValues:
						if flags == '': flags = ' (SSL)'
						else: flags = flags[:-1] + ', SSL)'
					desc = "[*] Cookie value seen on QS: %s%s" % (cv, flags)
					self.add_single(desc, id=qv['httpparams']['id'])
