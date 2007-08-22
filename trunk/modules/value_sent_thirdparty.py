"Find values sent to other domains"
from pmcheck import *
from pmutil import *

class value_sent_thirdparty(check):
	"Find values sent to other domains"

	def run(self, pmd):
		for k in pmd.AllValues:
			if k in trivial_values: continue
			domains = {}
			for v in pmd.find_value(k, pmd.AllValues):
				d = v['httpparams']['domain']
				if d in domains:
					domains[d].append(v)
				else:
					domains[d] = [v]

			if len(domains) > 1:
				all = ""
				for d in domains:
					tidlist = []
					for x in xrange(len(domains[d])):
						tidlist.append(domains[d][x]['httpparams']['id'])
					all += "%s (TIDs: %s), " % (d, ','.join(tidlist))

				desc = "Value (%s) sent to multiple domains: %s" % (k, all)
				self.add_single(desc)
