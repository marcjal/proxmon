"Find values sent to other domains"
from pmcheck import *
from pmutil import *

class value_sent_thirdparty(check):
	"Find values sent to other domains"

	def run(self, pmd):
		for k in pmd.AllValues:
			if k in trivial_values: continue
			domains = {}
			for v in pmd.AllValues[k]:
				d = v['httpparams']['domain']
				if d in domains:
					domains[d].append(v)
				else:
					domains[d] = [v]

			if len(domains) > 1:
				for d in domains:
					for x in xrange(len(domains[d])):
						desc = "[*] Value (%s) sent to multiple domains: %s" % (k, d)
						self.add_single(desc, domains[d][x]['httpparams']['id'])
