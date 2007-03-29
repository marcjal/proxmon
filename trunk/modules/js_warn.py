"Find dangerous functions in JavaScript code"
from pmcheck import *
from pmutil import *
import re
import cStringIO

def linerepl(match):
	count = len(re.findall(r'\n', match.group()))
	return "\n"*count

class js_warn(check):
	"Find dangerous functions in JavaScript code"
	def __init__(self):
		check.__init__(self)
		if not self.config_loaded(): return
		self.dangerous = self.cfg['dangerous']

	def resp_body_parse(self, body, t):
		if not self.config_loaded(): return

		# XXX: need better heuristic for JS code
		if binary_response(t): return

		# XXX: if it's html, blank out everything outside of <script> tags

		# XXX: remove strings

		# blank out commented ranges
		body = re.sub(js_comment_rx[0], linerepl, body) # /* */ comments
		body = re.sub(js_comment_rx[1], "\n", body)     # // comments
		# XXX: fix this to handle <!--[if gte IE 4]> (downlevel hidden blocks)

		conststr = r'''["'][^'"]*?['"]'''
		conststrp = re.compile(conststr)
		for f in self.dangerous:
			s = r"\b%s\s*\(.+\)" % f
			p = re.compile(s)
			linenum = 1
			for line in cStringIO.StringIO(body).readlines():
				for m in p.findall(line):
					# ignore if it's a constant string
					if len(conststrp.findall(m)) != 1:
						desc = '[*] Unsafe JavaScript found: %s at %s:%d' % (
							f, t['url'], linenum)
						vlen = m.find('\n')
						if (vlen>60 or vlen<0): m = m[:60] + ' ...'
						self.add_single(desc, id=t['id'], verbose=m)
				linenum += 1
