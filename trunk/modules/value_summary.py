"Summarize Values"
from pmcheck import *
from pmutil import *
import pdb

# Value Summaries
class value_summary(postruncheck):
	"Summarize value information"

	def __init__(self):
		postruncheck.__init__(self)
		if self.config_loaded():
			self.interesting_names = self.cfg['interesting_names']

	def summarize_values(self, pmd):
		"Print a one line summary of the value"
		cmsg("Listing unique values")
		for v in pmd.AllValues:
			if (len(v) > 40) and not self.verbosity: suffix = " ..."
			else: suffix = v[40:]
			cmsg("value: %s%s" % (v[:40], suffix))

	def interesting_values(self, pmd):
		"Point out interesting value names and strings"
		for v in pmd.AllValues:
			# dict check to deal with pointer records from hashes
			if isinstance(pmd.AllValues[v], list):
				for i in xrange(len(pmd.AllValues[v])):
					name = pmd.AllValues[v][i]['name']
					if name in self.interesting_names:
						cmsg("Interesting value name: %s (%s in TID %s)" % (
							name, v, pmd.AllValues[v][i]['httpparams']['id']))

	def report(self, pmd):
		if not self.cfg: return

		cmsg('-' * 40)
		cmsg("Saw %d unique values in %d conversations" % (
				len(pmd.AllValues), len(pmd.Transactions)))

		if self.verbosity:
			cmsg('-'*40)
			self.summarize_values(pmd)

		cmsg('-'*40)
		self.interesting_values(pmd)
