"Identify frameworks and scripts in use by server"
import re, cStringIO
from pmcheck import *
from pmutil import *
import pdb
try:
	import BeautifulSoup
except ImportError:
	loaderror = True

class id_framework_passive(check):
	"Identify frameworks and scripts in use by server"

	def __init__(self):
		check.__init__(self)
		if not self.config_loaded(): return
		self.fwinfo = self.cfg['framework_info']

	def resp_hl_parse(self, line, t):
		if not self.config_loaded(): return
		for f in self.fwinfo:
			if 'rhl' in f:
				m = re.search(f['rhl'], line)
				if m:
					if 'rhlver' in f:
						ver = re.search(f['rhlver'], line)
						if ver: ver = '/' + ver.group(1)
						else: ver = ''
					else: ver = ''
					desc = 'IDed framework: %s is using %s%s (%s)' % (
							t['server'], f['name'], ver, f['url'])
					self.add_single(desc) # skip TID because this gets noisy

	def resp_body_parse(self, body, t):
		if not self.config_loaded(): return
		if binary_response(t): return

		# XXX: make this more accurate
		# figure out if it's html or javascript
		# if html, for c in html_comment_rx: if bodyhtml in f
		#   then blank out everything not in script tags and do below
		# if javascript, for c in js_comment_rx: if bodyjs in f
		# XXX: need to remove strings first ( "http:// ...")
		# TODO - XXX - id generic technologies including calls to XMLHTTPRequest, SOAP

		for c in comment_rx:
			p = re.compile(c, re.MULTILINE)
			for m in p.finditer(body):
				for f in self.fwinfo:
					if 'body' not in f: break
					if re.search(f['body'], m.group(), re.IGNORECASE):
						if f['bodyver']:
							ver = re.search(f['bodyver'], m.group())
							if ver: ver = '/'+ver.group(1)
							else: ver=''
						else: ver = ''
						desc = 'IDed framework: %s is using %s%s (%s)' % (
								t['server'], f['name'], ver, f['url'])
						self.add_single(desc, id=t['id'])

