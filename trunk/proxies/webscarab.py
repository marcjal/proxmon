"""
Code to support the WebScarab proxy
"""
import os, pdb, re, sys, logging
from os.path import join as opjoin
from os.path import exists as opexists
from pmutil import *
from pmproxy import *
from transaction import *

log = logging.getLogger("proxmon")

class webscarab(pmproxy):
	"WebScarab proxy code"
	_sessioncache = None
	tid = 0
	verbosity = 0
	proxy_name = 'WebScarab' # @var proxy_name: Name to display when loading

	def sessions(self, where):
		"""
		Get a list of sessions available in the provided location
		If the provided location is a session directory, figure that out

		@return: C{list} of C{session_info} C{dict}s
		"""
		if self._sessioncache: return self._sessioncache
		sl = []
		if not where: where = self.get_tmpdir()
		if not where: return None
		if not opexists(where): return None
		if opexists(opjoin(where, 'conversations')):
			return [self.session_info(where, '')]
		for d in os.listdir(where):
			if (re.search(r"^webscarab(\d+).tmp", d) or
				opexists(opjoin(where, d, 'conversations'))):
				sl.append(self.session_info(where, d))
		self._sessioncache = sl
		return sl

	def session_info(self, where, name):
		"""
		Get information on the specified session

		If where is '', will auto try the webscarab temp dir
		If where is not '', will try session nicknames 
		@param where: directory name where the sessions are located
		@param name: specific name of subdirectory containing desired session

		@return: C{dict} containing id, domains, transactions, date, seentids
			and whether the session is currently active
		"""
		if not where: where = self.get_tmpdir()
		if not opexists(opjoin(where, name)):
			wstmp = 'webscarab%s.tmp' % name
			if not opexists(opjoin(where, wstmp)):
				return {}
			name = wstmp
		session = {}
		wsdir = opjoin(where, name)
		session['id'] = wsdir
		m = re.search(r'webscarab(\d+).tmp', wsdir)
		if m:
			session['nickname'] = m.group(1)
		elif wsdir.rfind(os.sep) > -1:
			session['nickname'] = wsdir[wsdir.rfind(os.sep):]
		session['domains'] = self.domains_in_dir(wsdir)
		session['transactions'] = self.transactions(wsdir)
		session['date'] = os.path.getctime(wsdir)
		session['seentids'] = []
		if os.path.exists(opjoin(wsdir, 'conversationlog')):
			session['active'] = False
		else:
			session['active'] = True
		return session

	def get(self, session, tinfo):
		t = {}
		t['id'] = tinfo['id']
		t['source'] = self.proxy_name
		t['request'] = open(opjoin(session['id'], 'conversations', 
							tinfo['id']+'-request'),'rb').read()
		t['response'] = open(opjoin(session['id'], 'conversations',
							tinfo['id']+'-response'), 'rb').read()
		# XXX: this needs to verify that the transaction are actually complete
		session['seentids'].append(tinfo['id'])
		return t

	def get_next(self, session):
		for f in os.listdir(opjoin(session['id'], 'conversations')):
			m = re.search(r'(\d+)-request$', f)
			if m:
				if m.group(1) in session['seentids']: continue
				else:
					t = self._get_transaction(session['id'], m.group(1))
					if t:
						session['transactions'].append(t)
		for t in session['transactions']:
			# NOTE: don't block to ensure order, failed sessions will leave gaps
			if t['id'] in session['seentids']: continue
			return self.get(session, t)
		return False

	# -------- Helper functions below ------------
	def transactions(self, wsdir):
		tl = []
		for f in os.listdir(opjoin(wsdir, 'conversations')):
			m = re.search(r'(\d+)-request$', f)
			if m:
				t = self._get_transaction(wsdir, m.group(1))
				if t:
					tl.append(t)
		tl.sort(lambda x, y: int(x['id']) - int(y['id']))
		return tl

	def _get_transaction(self, wsdir, tid):
		t = {}
		t['id'] = tid
		t['dir'] = opjoin(wsdir, 'conversations')
		reql = self.get_reqline(t['dir'], t['id'])
		respl = self.get_statusline(t['dir'], t['id'])
		if (reql and respl):
			t.update(reql)
			t.update(respl)
			return t
		return None

	def get_tmpdir(self):
		"Determine the default WebScarab temp directory"
		tmpdir = None
		if sys.platform == 'win32':
			tmpdir = opjoin(os.getenv('HOMEDRIVE'), os.getenv('HOMEPATH'), 'Local Settings\\Temp')
		elif sys.platform == 'cygwin':
			drive = os.environ.get('HOMEDRIVE')[:1].lower()
			username = os.environ.get('USERNAME') # Works on cygwin and win32
			tmpdir = '/cygdrive/'+drive+'/Documents and Settings/'+username+'/Local Settings/Temp'
		elif sys.platform == 'darwin':
			tmpdir = '/tmp' # WebScarab for Mac http://research.corsaire.com/tools
		else:
			for f in os.listdir('/tmp'):
				if re.search("webscarab[\d]+.tmp", f):
					tmpdir = '/tmp'
			for f in os.listdir('/var/tmp'):
				if re.search("webscarab[\d]+.tmp", f):
					tmpdir = '/var/tmp' # OWASP/PacketFocus LabRat 0.8 and FreeBSD
		return tmpdir

	def get_reqline(self, wsdir, tid):
		f = open(opjoin(wsdir, tid+'-request'), 'rb')
		rl = parsereqline(f.readline())
		return rl

	def get_statusline(self, wsdir, tid):
		f = open(opjoin(wsdir, tid+'-response'), 'rb')
		sl = parserespline(f.readline())
		return sl

	def domains_in_dir(self, dir):
		"Build a list of domains seen in a WebScarab conversations directory"
		domains = []

		for root, dirs, files in os.walk(dir):
			for fn in files:
				if re.search("-request$", fn):
					f = open(opjoin(root, fn), 'rb')
					rp = parsereqline(f.readline())
					if rp == None:
						return ''
					domains.append(rp['domain'])
		d = sortuniq(domains)
		return d

	def get_latest_ws_tempdir(self):
		latest = None

		tmpdir = get_tmpdir()
		if tmpdir == None:
			log.error("Couldn't get user temp dir, exiting")
			return None

		if self.verbosity > 1: 
			cmsg('[d] get_latest_ws_tempdir: searching %s' % tmpdir)

		# Select most recently created directory
		for root, dirs, files in os.walk(tmpdir):
			for d in dirs:
				if re.search("^webscarab", d):
					if latest == None:
						latest = opjoin(root, d)
					else:
						if os.path.getctime(opjoin(root, d)) > os.path.getctime(latest):
							latest = opjoin(root, d)
		return latest

	def list_ws_tempdirs(self):
		tmpdir = get_tmpdir()
		if tmpdir == None:
			log.error("[*] Couldn't get user temp dir, exiting")
			return

		cmsg("Finding WebScarab temporary directories in \n%s" % tmpdir)
		wsdirs = {}
		for root, dirs, files in os.walk(tmpdir):
			for d in dirs:
				if re.search("^webscarab", d):
					wsdirs[opjoin(root, d)] = domains_in_dir(opjoin(root, d))
					cmsg("%s contains:\n\t%s" % (d, wsdirs[opjoin(root, d)]))

		if len(wsdirs.keys()) == 0:
			cmsg("No WebScarab temporary directories found")


