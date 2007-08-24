from pmcheck import *
from pmutil import *
from transaction import * # XXX move referenced functions to pmutil
from BeautifulSoup import BeautifulSoup
import pdb

class insecure_references(check):
	"Finds insecure references to content"

	def resp_body_parse(self, body, t):
		if binary_response(t): return

		try:
			soup = BeautifulSoup(body)
			for i in soup.findAll('script'):
				for n,v in i.attrs:
					if n.lower() == 'src':
						# HTTPS loads HTTP
						if t['url'][:5] == 'https' and v.lower()[:5] == 'http:':
							desc = "Insecure JavaScript reference: Secure page %s loads %s" % (t['url'], v)
							self.add_single(desc, id=t['id'])

						# External Load
						if v.lower()[:4] == 'http':
							srchost = get_hostname(t['url'])
							refhost = get_hostname(v.lower())
							if srchost != refhost:
								desc = "Insecure JavaScript reference: %s loads %s" % (t['url'], v)
								id = t['id']
								self.add_single(desc, id=id)
		except:
			pass
