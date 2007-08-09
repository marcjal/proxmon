#!/usr/bin/env python
# ProxMon - Monitors proxies to automate web application penetration tests
# Copyright (C) 2007, Jonathan Wilkins - See accompanying LICENSE for info
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# XXX - Beta version
# TODO before release:
#  - b64 and hash stuff needs more testing
#  - dsniff needs testing
#
"""
ProxMon parses proxy logs and reports on common web application weaknesses

Consult accompanying README and proxmon.pdf for documentation

Portions adapted from code written by:
	- Jesse Burns <jesse[at]isecpartners[dot]com>
	- David Thiel <david[at]isecpartners[dot]com>

@organization: www.isecpartners.com
@sort: main, scan, tail, parsetrans
"""
__version__ = '1.0.19'
__author__ = 'Jonathan Wilkins'
__contact__ = 'jwilkins[at]isecpartners[dot]com'
__copyright__ = '(c) 2006, 2007, Information Security Partners LLC.'
__license__ = 'GPL'

import os, re, sys, pdb, httplib, urllib, urllib2, cookielib
import socket, time, string
import cStringIO as StringIO
import BeautifulSoup
from optparse import OptionParser
from time import sleep
from os.path import exists as opexists
from os.path import join as opjoin
from pmcheck import *
from pmutil import *
from pmdata import *
from pmproxy import *
from transaction import *

try:
	import debug # Newsh's debug library
except ImportError:
	pass

Verbosity = 0
TIDs = None
Count = 0
ProxCJ = None
Extract = False

FNTrans = list(string.maketrans('', ''))
okfnchars = string.digits + string.ascii_letters + '._&%()!-[]+='
for x in xrange(256):
	if chr(x) not in okfnchars: FNTrans[x] = '_'
FNTrans = ''.join(FNTrans)

def parsetrans(t, checks, pmd, urlfilter):
	"""
	Parse a full HTTP transaction

	@param t: a dictionary containing an id, the request and the response
		The request and response should be strings containing the whole req/resp
	@param checks: a list of check instance to run
	@param pmd: the datastore object
	@param urlfilter: the filter to use when choosing transactions to process
	@return: False indicates transaction error, None indicates filter not matched
	"""
	global ProxCJ
	# XXX - this needs to determine whether a transaction on disk is complete
	# To do this, check that you have the end of headers and once you have 
	# the end of headers, confirm the content length
	# if these are incorrect/absent, throw trans back and try again later

	if TIDs:
		if t['id'] not in TIDs: return None

	tinfo = {'id': t['id']}
	if not (chk_fmt(t['request'])and chk_fmt(t['response'])): return False
	if parserequest(t['request'], checks, tinfo, pmd, urlfilter):
		if parseresponse(t['response'], checks, tinfo, pmd, urlfilter):
			pmd.add_transactions(tinfo)
			ProxCJ.update(t['request'], t['response'])
			if Extract: extract_trans(tinfo)
			return True
	return False

def extract_trans(t):
	if not 199 < int(t['code']) < 300: return
	if not 'respbody' in t: return
	if not t['respbody']: return
	try:
		if not opexists(Extract): os.mkdir(Extract)
		pdir = opjoin(Extract, t['hostname']+'_'+t['port'])
		if not opexists(pdir):
			os.mkdir(pdir)
		os.makedirs(opjoin(pdir, t['dir'][1:]))
	except OSError, e:
		if e.errno != 17:
			print 'Error: ' + e.strerror

	fn = t['file'].rsplit('.', 1)
	if len(fn[0]) > 30:
		fn[0] = fn[0][:30]
	outfn = opjoin(pdir, t['dir'][1:], fn[0].translate(FNTrans))
	outfn += '.'+ str(t['id'])
	if len(fn) > 1:
		if len(fn[1]) > 10:
			fn[1] = fn[1][:10]
		outfn += '.' + fn[1].translate(FNTrans)
	#print 'extract_trans: writing to '+ outfn
	f = open(outfn, 'wb')
	f.write(t['respbody'])
	f.close()

def scan(wproxy, session, checks, pmd, urlfilter):
	"""
	Parse all transactions in a given directory

	@param wproxy: pmproxy subclass
	@param session: dict containing session details
	@param checks: list of check instances
	@param pmd: proxmon datastore
	@param urlfilter: url to match when processing transactions
	"""
	global Count

	for t in session['transactions']:
		rawt = wproxy.get(session, t)
		if parsetrans(rawt, checks, pmd, urlfilter):
			Count += 1

	for c in checks:
		if Verbosity > 1: print '[d] scan: running check ' + c.__doc__
		c.run(pmd)
		c.show_all()

def tail(wproxy, session, checks, pmd, urlfilter):
	"""
	Monitor a directory for new transactions

	@param wproxy: pmproxy subclass
	@param session: dict containing session details
	@param checks: list of check instances
	@param pmd: proxmon datastore
	@param urlfilter: url to match when processing transactions
	"""
	global Count

	print '[*] Monitoring %s' % session['id']
	print '[*] Parsing existing conversations ...'
	scan(wproxy, session, checks, pmd, urlfilter)
	print '[*] Parsed %d existing conversations' % Count

	if not session['active']:
		print '[*] Session is not active, no point in monitoring'
		return

	print '[*] Entering monitor mode ...'
	while(True):
		didsomething = False
		rawt = wproxy.get_next(session)
		if rawt:
			if parsetrans(rawt, checks, pmd, urlfilter):
				Count += 1
			didsomething = True
		else:
			sleep(1)

		if didsomething:
			for c in checks:
				if Verbosity > 1: print '[d] tail: running check ' + c.__doc__
				c.run(pmd)
				c.show_new()

def load_proxies(interface):
	"""
	Load all available proxy datasource handlers
	"""
	# XXX: abspath doesn't return absolute path on win32 - Yay.
	# XXX: figure out a better way
	#if sys.platform == 'cygwin':
	#	modpath = os.path.abspath(os.path.dirname(sys.argv[0])+os.sep+'proxies')
	#if sys.platform == 'win32':
	#	modpath = os.path.join(r".\proxies") # XXX - hack
	#else:
	#	modpath = './proxies/'
	modpath = os.path.dirname(os.path.abspath(sys.argv[0]))+os.sep+'proxies'
	sys.path.append(modpath)

	modfiles = filter(lambda f: f.endswith('.py'), os.listdir(modpath))
	modnames = map(lambda n: os.path.splitext(n)[0], modfiles)
	for m in modnames:
		if m == '__init__': continue
		mod = __import__(m)
		if mod.loaderror:
			print "[x] Needed module not found, disabling %s" % mod.__file__

	proxylist = []
	proxylist.extend(pmproxy.__subclasses__())

	proxies = {}
	print '[*] Loading support for:',
	for p in proxylist:
		if p not in [pmproxy]:
			print p.proxy_name,
			try:
				if p.proxy_name == 'dsniffp':
					print "(interface %s)" % interface,
					proxies[p.__module__] = p(interface)
				else:
					proxies[p.__module__] = p()
			except:
				print "\n[x] Error loading, (if dsniffp, check interface name)",
	print

	return proxies


def load_checks(loadreg, loadnet, loadpostrun, exclude=[]):
	"""
	Load specified types of checks

	@param loadreg: Load regular checks
	@param loadnet: Load online checks
	@param loadpostrun: Load postrun checks
	@return: A list of check instances
	"""
	# XXX - abspath doesn't return absolute path on win32 - Yay.
	#if sys.platform[:6] == 'cygwin':
	#	modpath = os.path.abspath(os.path.dirname(sys.argv[0])+os.sep+'modules')
	if sys.platform == 'win32':
		modpath = os.path.join(".\\modules") # XXX - hack
	else:
		modpath = './modules/'
	modpath = os.path.dirname(os.path.abspath(sys.argv[0]))+os.sep+'modules'
	sys.path.append(modpath)

	modfiles = filter(lambda f: f.endswith('.py'), os.listdir(modpath))
	modnames = map(lambda n: os.path.splitext(n)[0], modfiles)
	for m in modnames:
		if m == '__init__': continue
		if m in exclude: continue
		mod = __import__(m)
		if mod.loaderror:
			print "[x] Needed module not found, not loading %s" % mod.__file__

	checklist = []
	if loadreg: checklist.extend(check.__subclasses__())
	if loadnet: checklist.extend(netcheck.__subclasses__())
	if loadpostrun: checklist.extend(postruncheck.__subclasses__())

	checks = []
	for c in checklist:
		loadit = True
		if c not in [check, netcheck, postruncheck]:
			if issubclass(c, netcheck):
				if not loadnet:
					loadit = False
			if loadnet and not (loadreg or loadpostrun):
				if not issubclass(c, netcheck):
					loadit = False
			if loadit:
				print ' - ' + c.__doc__
				checks.append(c())

	return checks

def opt_gettidlist(option, opt, value, parser):
	"Parse a list of transaction id's"
	tl = []
	for a in parser.rargs:
		if a[0] == '-': break
		if a.find(',') > 0:
			tl.extend(map(str.strip, a.split(',')))
		else:
			tl = [a.strip()]
	if len(tl):
		tids = []
		for t in tl:
			tids.append(t)
		setattr(parser.values, option.dest, tids)

class tfake_addbase:
	def __init__(self, fp):
		pass

	def __repr__(self):
		return 'tfake_addbase'

	def close(self):
		pass

class tfake_addinfourl(tfake_addbase):
	def __init__(self, fp, headers, url):
		tfake_addbase.__init__(self, fp)
		self.headers = headers
		self.url = url

	def info(self):
		return self.headers

	def geturl(self):
		return self.url

class tfake_response(httplib.HTTPResponse):
	def __init__(self, respstr, debuglevel=0, strict=0, method=None):
		self.fp = StringIO.StringIO(respstr[:])

		self.debuglevel = debuglevel
		self.strict = strict
		self._method = method

		self.msg = None
		self.headers = None

		self.version = 'UNKNOWN'
		self.status = 'UNKNOWN'
		self.reason = 'UNKNOWN'

		self.chunked = 'UNKNOWN'
		self.chunk_left = 'UNKNOWN'
		self.length = 'UNKNOWN'
		self.will_close = 'UNKNOWN'

	def info(self):
		return self.headers

class proxy_cookiejar(object):
	_cj = None

	def __init__(self):
		self._cj = cookielib.MozillaCookieJar('proxmon.cj')
		self._cj._now = time.time()

	def update(self, request, response):
		reqf = StringIO.StringIO(request)
		reql = reqf.readline().split(" ")

		l = reqf.readline()
		headers = {}
		while l != ('' or '\r\n'):
			(h, v) = l.split(":", 1)
			headers[h] = v
			l = reqf.readline()

		# XXX: fake https as http?
		req = urllib2.Request(reql[1], None, headers)
		res = tfake_response(response)
		res.begin()
		res.status = 200
		res.close()
		res2 = tfake_addinfourl(res, res.msg, req.get_full_url())

		self._cj._now = time.time()
		self._cj.extract_cookies(res2, req)
		# fix expiry
		for d in self._cj._cookies:
			for p in self._cj._cookies[d]:
				for n in self._cj._cookies[d][p]:
					c = self._cj._cookies[d][p][n]
					c.expires = time.time() + 60*60*24*365
		self._cj.save(ignore_discard=True, ignore_expires=True)

def main(prog, *args):
	global ProxCJ, Verbosity, TIDs, Count, Extract

	print '[*] starting ProxMon v%s (%s)' % (__version__, 
				'http://www.isecpartners.com')
	print '[*] Copyright (C) 2007, Jonathan Wilkins, iSEC Partners Inc.'
	print '[*] Proxmon comes with ABSOLUTELY NO WARRANTY;'
	print '[*] This is free software, and you are welcome to redistribute it'
	print '[*] under certain conditions; see accompanying file LICENSE for '
	print '[*] details on warranty and redistribution details.'

	optp = OptionParser(usage="%prog [options]")
	optp.add_option('-1', '--once', action='store_true', dest='runonce', 
			help='Only run once, instead of continually scanning the directory')
	optp.add_option('-A', '--all', action='store_true', dest='all', 
			help='Process all sessions in the provided location')
	optp.add_option('-b', '--base64', action='store_true', dest='base64', 
			help='Try harder to do base64 decodes')
	optp.add_option('-B', '--base64confirm', action='store_true', 
			dest='base64confirm', 
			help='Be aggressive, but let the user confirm')
	optp.add_option('-c', '--cookies', dest='cookies', action='store_true',
			help='Show cookie summary information')
	optp.add_option('-d', '--datasource', dest='datasource', 
			help='Directory to scan')
	optp.add_option('-f', '--filter', dest='filter', default='',
			help='Filter transactions.  Only include transactions where the URL'
			' contains the provided string')
	optp.add_option('-i', '--interface', dest='interface', default='eth0',
			help='Specify which interface pcap will listen on')
	optp.add_option('-l', '--list', action='store_true', dest='list',
			help='List available sessions')
	optp.add_option('-o', '--online', action='store_true', dest='online', 
			help="Perform active network checks")
	optp.add_option('-O', '--onlineonly', action='store_true', dest='onlineonly',
			help="Only perform active network checks")
	optp.add_option('-P', '--pause', action='store_true', dest='pause',
			help="Pause at the end of the run, useful mainly under Windows")
	optp.add_option('-p', '--proxy', dest='proxy', default=None,
			help="Specify proxy url")
	optp.add_option('-q', '--qs', action='store_true', dest='qs',
			help='Show query string summary information')
	optp.add_option('-s', '--session', dest='session', default=None,
			help='Use specified session')
	optp.add_option('-t', '--tid', dest='tid', default=None, action='callback', 
			callback=opt_gettidlist,
			help="Only process specified transaction id's")
	optp.add_option('-v', '--verbose', action='count', dest='verbosity', 
			help='Verbose output, use multiple times to increase', default=0)
	optp.add_option('-V', '--version', action='store_true', dest='version', 
			help='Display version information')
	optp.add_option('-w', '--which', dest='which', default='webscarab',
			help='Specify kind of proxy logs you want to parse')
	optp.add_option('-x', '--extract', dest='extract', default=None, # XXX: finish
			help='Extract files to the specified directory')
	(opts, oargs) = optp.parse_args()

	Verbosity = opts.verbosity
	if Verbosity > 1: print '[d] main: verbosity: '+str(Verbosity)

	# increase recursion depth for hash stuff in pmdata
	sys.setrecursionlimit(2500)

	if opts.version:
		print "ProxMon version %s" % __version__
		return

	if opts.extract:
		Extract = opts.extract

	# Check imported package versions
	if BeautifulSoup.__version__ < '3.0.3':
		print '[x] Old version of BeautifulSoup found, good luck ..'

	proxies = load_proxies(opts.interface)
	ProxCJ = proxy_cookiejar()

	try:
		wp = proxies[opts.which]
	except KeyError:
		print '[x] %s not yet supported' % opts.which
		return

	if opts.list:
		print '[*] Listing known sessions:'
		for s in wp.sessions(opts.datasource):
			if s['nickname']:
				name = s['nickname']
			else:
				name = s['id']
			print '\nSession %s contains:' % name
			for d in s['domains']:
				count = 0
				if 'transactions' in s:
					for t in s['transactions']:
						if t['domain'] == d:
							count +=1 
				print '\t%s (%d)' % (d, count)
		return

	# autodetects all decendants of check class in modules subdirectory
	print "[*] Loading Checks ... "
	excludes = []
	if not opts.cookies: excludes.append('cookie_summary')
	if not opts.qs: excludes.append('query_summary')
	if opts.onlineonly:
		checks = load_checks(False, True, False, excludes)
	else:
		checks = load_checks(True, opts.online, True, excludes)
	print '[*] %d checks loaded' % len(checks)

	# Most netcheck modules just use these environment settings
	if opts.proxy:
		os.environ['http_proxy'] = os.environ['https_proxy'] = opts.proxy

	# Pass on configuration details to modules, XXX - needs improvement
	for c in checks:
		if isinstance(c, check):
			c.set_verbosity(opts.verbosity)
		if isinstance(c, netcheck):
			c.set_proxy(opts.proxy) # for checks that don't use proxy env

	if opts.session:
		opts.session = wp.session_info(opts.datasource, opts.session)
	else:
		print '[*] Finding available sessions ...'
		session = None
		latest = 0
		sessions = wp.sessions(opts.datasource)
		if sessions: 
			for s in sessions:
				if s and s['date'] > latest:
					latest = s['date']
					session = s
			opts.session = session

	# if we still don't have a session defined, quit
	if not opts.session:
		print '[*] No sessions found, exiting ...'
		return

	if opts.tid:
		TIDs = opts.tid
		TIDs.sort()
		print '[*] Only processing TIDs: ' + ', '.join(str(t) for t in TIDs)

	if opts.all:
		try:
			sl = wp.sessions(opts.datasource)
			print '[*] Running on all available sessions (%d total)' % len(sl)
			sc = tt = 0
			for s in sl:
				Count = 0
				sc += 1
				pmd = pmdata()
				for c in checks:
					c.clear()
				print '\n[*] Processing %s' % s['nickname']
				print '\t(%s)' % s['id']
				if not len(s['transactions']):
					print "[*] 0 transactions to process"
					continue
				print '\tWith transactions from: ' + ', '.join(s['domains'])
				scan(wp, s, checks, pmd, opts.filter)
				print '[*] %d transactions processed' % Count
				tt += Count
				for c in checks:
					c.report(pmd)
				print
		except KeyboardInterrupt:
			print "[*] Stopping at user's request, %d transactions parsed" % tt
		print "[*] %d transactions in %d sessions processed" % (tt, sc)
		return

	try:
		pmd = pmdata()
		if opts.base64 or opts.base64confirm:
			pmd.b64opts(opts.base64, opts.base64confirm)

		if opts.datasource:
			print '[*] Processing session %s in %s' % (opts.session['id'], 
														opts.datasource)
		else:
			print '[*] Processing session %s' % opts.session['id']

		if opts.runonce:
			print "[*] Running one time"
			scan(wp, opts.session, checks, pmd, opts.filter)
			print '[*] Parsed %d transactions' % (Count)
		else:
			print "[*] Running in monitor mode"
			tail(wp, opts.session, checks, pmd, opts.filter)
	except KeyboardInterrupt:
		print "[*] Stopping at user's request, %d transactions parsed" % Count

	# Post run stuff
	for c in checks:
		c.report(pmd)

	# XXX - write everything out to a report

	if opts.pause:
		raw_input("[*] Finished, press enter to exit ...")

if __name__ == '__main__':
	# ---- normal ----
	main(sys.argv[0], *sys.argv[1:])
	# ---- hotshot ----
	#import hotshot
	#from hotshot import stats
	#prof = hotshot.Profile('proxmon.pstat')
	#prof.runcall(main, sys.argv[0], *sys.argv[1:])
	#prof.close()
	#s = stats.load('proxmon.prof')
	#s.strip_dirs()
	#s.sort_stats("cumulative")
	#s.print_stats(20)
	#s.print_callers(20)
	#print '-' * 40
	#s.sort_stats("time", 'calls')
	#s.print_stats(20)
	#s.print_callers(20)
	#print '-' * 40
	#s.sort_stats('time', "nfl")
	#s.print_stats()
	#s.print_callers()
	# ---- cProfile/profile ----
	#if sys.version[:3] == '2.5':
	#	import cProfile as profile
	#else:
	#	import profile
	#profile.run('main(sys.argv[0], *sys.argv[1:])', 'proxmon.pstat')
