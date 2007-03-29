"Find values set over SSL that later go cleartext"
from pmcheck import *
from pmutil import *

class ssl_val_sent_clear(check):
	"Find values set over SSL that later go cleartext"

	def run(self, pmd):
		for sv in pmd.SecureValues:
			if sv in trivial_values: continue
			if sv in pmd.ClearValues:
				for cv in pmd.ClearValues[sv]:
					fsv = pmd.SecureValues[sv][0]
					if fsv['type'] == 'sentcookie': continue
					desc = "[*] Value set over SSL sent clear: " \
						"value %s (set by %s in %s) seen as %s %s " \
						"(sent to %s)" % (sv, fsv['httpparams']['server'], 
						fsv['type'], cv['name'], cv['type'], 
						cv['httpparams']['server'])
					id = cv['httpparams']['id']
					self.add_single(desc, id=id)


