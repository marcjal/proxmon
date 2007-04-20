from pmcheck import *
from pmutil import *
from BeautifulSoup import BeautifulSoup
import pdb

class nop(check):
	"Finds password input fields on non-ssl pages"

	def resp_body_parse(self, body, t):
		if binary_response(t): return
		if t['proto'] != 'http': return

		try:
			soup = BeautifulSoup(body)
			for i in soup.findAll('input'):
				for n,v in i.attrs:
					if n.lower() == 'type':
						if v.lower() == 'password':
							desc = "[*] Non-SSL password entry field on %s" % (
									t['url'])
							id = t['id']
							self.add_single(desc, id=id)
		except:
			pass
