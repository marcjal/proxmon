import glob, pdb, re, sys, time
if __name__ == '__main__': sys.path.append('..')
from pmutil import *
from pmproxy import *
from transaction import *

try:
	import dsniff
	from dsniff.lib import http
	import event
	loaderror = False
except ImportError:
	print 'Error importing dsniff'
	loaderror = True

if not loaderror and sys.platform != 'cygwin':
	class saver(http.HttpParser):
		serverdata = None
		clientdata = None

	class pmdsniffh(dsniff.Handler):
		def setup(self):
			#print "pmdsniffh.setup"
			self.transactions = []
			self.curid = 0
			self.subscribe('service', 'http', self.recv_flow)

		def recv_flow(self, f):
			#print 'pmdsniffh.recv_flow'
			if f.state == dsniff.FLOW_START:
				f.save['http'] = saver(f)
			elif f.state == dsniff.FLOW_CLIENT_DATA:
				f.save['http'].feed(f.client.data)
				if f.save['http'].clientdata:
					f.save['http'].clientdata += f.client.data
				else:
					f.save['http'].clientdata = f.client.data[:]
				r = re.search(r'([^\n]+)([^\n]*)(.*)', f.client.data) # XXX: improve
				if r:
					m = r.group(1).split(' ')
					if m[0] in http.HttpParser.methods:
						print "Client Request:"
						print r.group(1)
						print r.group(2)
				#print f.save['http'].clientdata
			elif f.state == dsniff.FLOW_SERVER_DATA:
				f.save['http'].feed(f.server.data)
				if f.save['http'].serverdata:
					f.save['http'].serverdata += f.server.data
				else:
					f.save['http'].serverdata = f.server.data[:]
				# XXX: figure out if it's complete and add to transactions
				t = {}
				t['id'] = self.curid
				self.curid += 1
				t['request'] = f.save['http'].clientdata
				t['response'] = f.save['http'].serverdata
				self.transactions.append(t)
				#print f.save['http'].serverdata
				r = re.search(r'([^\n]+)([^\n]*)(.*)', f.server.data) # XXX: improve
				if r:
					if r.group(1).startswith('HTTP'):
						print "Server Response:"
						print r.group(1)
						print r.group(2)
			#elif f.state == dsniff.FLOW_END:

	class pmdsniff(pmproxy):
		"Fake dsniff as a proxy"
		proxy_name = "dsniffp"
		handler = None
		subclasses = None

		def __init__(self):
			if sys.platform in ('darwin', 'win32'):
				os.putenv('EVENT_NOKQUEUE', '1')
				os.putenv('EVENT_NOPOLL', '1')

			dsniff.config['pcap'] = {}
			#dsniff.config['pcap']['interfaces'] = ['eth3']  # eth3 = bridge
			dsniff.config['pcap']['interfaces'] = ['eth1'] # eth1 = ethernet

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
			#print 'pmdsniff.get_next: ' + str(self.handler.transactions)
			if self.handler and len(self.handler.transactions):
				#print 'pmdsniff.get_next: transactions is %d long' % (
				#			len(self.handler.transactions))
				for t in self.handler.transactions:
					if t['id'] not in session['seentids']:
						if not (t['request'] or t['response']): continue
						print t
						session['seentids'].append(t['id'])
						session['transactions'].append(t)
						return t
			return None


	if __name__ == '__main__':
		print "__name__ == __main__"
		dsniff.main()
