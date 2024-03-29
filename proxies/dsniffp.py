import glob, pdb, re, sys, time, logging
if __name__ == '__main__': sys.path.append('..')
from pmutil import *
from pmproxy import *
from transaction import *

log = logging.getLogger("proxmon")

try:
	import dsniff
	from dsniff.lib import http
	import event
	loaderror = False
except ImportError:
	log.error('Error importing dsniff')
	loaderror = True

if not loaderror and sys.platform != 'cygwin':
	class saver(http.HttpParser):
		def __init__(self, flow):
			super(saver, self).__init__(self)
			self.flow = flow
			self.data = ''

	class pmdsniffh(dsniff.Handler):
		def setup(self):
			#log.info("pmdsniffh.setup")
			self.transactions = []
			self.curid = 0
			self.subscribe('service', 'http', self.recv_flow)

		def recv_flow(self, f):
			if f.state == dsniff.FLOW_START:
				f.client.save = saver(f)
				f.server.save = saver(f)
			elif f.state == dsniff.FLOW_CLIENT_DATA:
				f.client.save.data += f.client.data
				#log.info(f.client.save.data)
			elif f.state == dsniff.FLOW_SERVER_DATA:
				f.server.save.data += f.server.data
				#log.info(f.server.save.data)

				if chk_fmt(f.server.save.data) and chk_fmt(f.client.save.data):
					t = {}
					t['id'] = self.curid
					t['source'] = 'dsniffp'
					self.curid += 1
					t['request'] = f.client.save.data
					t['response'] = f.server.save.data
					self.transactions.append(t)

	class pmdsniff(pmproxy):
		"Fake dsniff as a proxy"
		proxy_name = "dsniffp"
		handler = None
		subclasses = None

		def __init__(self, iface):
			if sys.platform in ('darwin', 'win32'):
				os.putenv('EVENT_NOKQUEUE', '1')
				os.putenv('EVENT_NOPOLL', '1')

			dsniff.config['pcap'] = {}
			dsniff.config['pcap']['interfaces'] = [iface]

			if not self.subclasses:
				subclasses = dsniff.find_subclasses(dsniff.Handler, __import__('dsniffp'))
				if not subclasses:
					raise RuntimeError, 'no Handler subclasses found'

			event.init() # ordering of this matters

			self.handler = pmdsniffh()
			self.handler.setup()

		def sessions(self, where):
			"""
			If where is None, live capture: one session
			Check it as an interface name: one session
			Check if it's a dir: multiple sessions
			Check if it's a file: single session
			"""
			# TODO: implement above logic, for now everything's live
			sl = []
			sl.append(self.session_info(where, None))
			return sl

		def session_info(self, where, name):
			"""
			Ignore name, only where counts
			"""
			session = {}
			session['id'] = 'dsniff'
			session['nickname'] = 'dsniff'
			session['domains'] = ['live.capture']
			session['transactions'] = []
			session['date'] = time.time()
			session['seentids'] = []
			session['active'] = True
			return session

		def get(self, session, tinfo):
			return None

		def get_next(self, session):
			event.loop(1) # EVLOOP_ONCE
			#log.info('pmdsniff.get_next: ' + str(self.handler.transactions))
			if self.handler and len(self.handler.transactions):
				#log.info('pmdsniff.get_next: transactions is %d long' % (
				#			len(self.handler.transactions)))
				for t in self.handler.transactions:
					if t['id'] not in session['seentids']:
						if not (t['request'] or t['response']): continue
						#log.debug(t)
						session['seentids'].append(t['id'])
						session['transactions'].append(t)
						return t
			return None


	if __name__ == '__main__':
		print "__name__ == __main__"
		dsniff.main()
