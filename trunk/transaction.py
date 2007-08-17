# ProxMon - Monitors proxies to automate web application penetration tests
# Copyright (C) 2007, Jonathan Wilkins - See accompanying LICENSE for info
"""
Generic Transaction processing routines
"""
import os, re, sys, gzip, zlib, pdb, logging
import cStringIO as StringIO
from urlparse import urlparse
from pmutil import *

log = logging.getLogger("proxmon")

def chk_fmt(s):
	httpver = ['HTTP/0.9', 'HTTP/1.0', 'HTTP/1.1']
	if not s: return False
	r = re.search(r'([^\n]+)([^\n]*)(.*)', s, re.DOTALL|re.MULTILINE)
	if r:
		first = re.match(r'[^\n]+', s).group()
		parts = re.split(r'\s', first, 3)
		if len(parts) < 2:
			return False
		if parts[0].upper() in httpver:
			# response
			return True
		if len(parts) > 2 and parts[2].upper() in httpver:
			# request
			return True
	return False

# Line parsing routines
def get_sentcookies(l, t, pmd):
	m = re.match("^Cookie:\s*(.+)$", l, re.IGNORECASE) # regex due to case
	if m:
		cookies = parse_sent_cookies(m.group(1))
		for c in cookies:
			c['httpparams'] = t
			pmd.add_sentcookie(c)
		if 'sentcookies' in t:
			t['sentcookies'].extend([cookies])
		else:
			t['sentcookies'] = cookies
		log.info("get_sentcookies: %s" % l)

# Was fetch_cookies in webapp2.py
def get_setcookie(l, t, pmd):
	m = re.match("^Set-Cookie:\s*(.+)$", l, re.IGNORECASE)
	if m:
		cookie = parse_set_cookie(m.group(1))
		if cookie: cookie['httpparams'] = t
		if 'setcookies' in t:
			t['setcookies'].append(cookie)
		else:
			t['setcookies'] = [cookie]
		pmd.add_setcookie(cookie)
		log.info("get_set_cookie: %s" % l)

def get_querystring(s):
	"""Extract the query string portion of an URL

	@param s: URL in http://host:port/path?qs format"""
	if s.find('?') == -1:
		if s.find('&') == -1:
			return ''
		else:
			return s[s.find('&')+1:]
	else:
		return s[s.find('?')+1:]

def get_querystring_parts(s):
	"""Creates a list of value dicts

	param s: Full query string"""
	qsil = []

	for i in s.split("&"):
		qsi = {}
		if i != '':
			if i.find('=') > -1:
				qsi["name"], qsi["value"] = i.split('=', 1)
			else:
				# NOTE: This is not RFC compliant, but some sites do this
				qsi["name"] = i
				qsi["value"] = 'True'
			qsil.append(qsi)
	return qsil

def get_hostname(s):
	"""Extract the hostname from the URL

	@param s: String containing an URL"""
	si = s.find("//") + 2
	ei = s[si:].find(":")
	if si == -1 or ei == -1:
		return None
	return s[si:ei+si]

def get_domain(s):
	"""Extract the domain portion of a hostname

	@param s: string with a hostname"""
	hns = s.split(".")
	if len(hns) == 1:
		return hns[0]
	tld = hns[len(hns)-1]
	if tld in ['com', 'net', 'org', 'info', 'biz', 'aero', 'cat', 'coop',
				'jobs', 'mobi', 'museum', 'name', 'pro', 'tel', 'travel',
				'gov', 'mil', 'edu', 'int']:
		return hns[len(hns)-2]+"."+hns[len(hns)-1]
	else:
		return hns[len(hns)-3]+"."+hns[len(hns)-2]+"."+hns[len(hns)-1]

def get_port(s):
	i = urlparse(s)
	return i[1][i[1].find(':')+1:]

def get_proto(s):
	i = urlparse(s)
	return i[0]

def get_path(s):
	i = urlparse(s)
	return i[2]

def parsereqline(l):
	"""Parse the initial line of a request and build a dict with relevant values

	@param l: string containing the full request line"""
	rp = {}

	rl = l.split(" ") # XXX - what about other whitespace? use re.split instead?
	if len(rl) == 3:
		# WebScarab will add HTTP/0.9 in the request line and translate to 1.1
		if rl[2].strip().upper() in ['HTTP/1.0', 'HTTP/1.1', 'HTTP/0.9']:
			rl[2] = rl[2].strip().upper()
			rp['method'] = rl[0] # HTTP/1.0 RFC defines GET, HEAD, POST
			rp['url'] = rl[1]
			rp['version'] = rl[2]
			rp['proto'] = get_proto(rl[1])
			rp['path'] = get_path(rl[1])
			slashidx = rp['path'].rfind('/') 
			if slashidx > -1:
				if slashidx == len(rp['path'])-1:
					rp['dir'] = rp['path']
					rp['file'] = 'index.html'
				elif slashidx == 0:
					rp['dir'] = '/'
					rp['file'] = rp['path'][1:]
				else:
					rp['dir'] = rp['path'][:rp['path'].rfind('/')]
					rp['file'] = rp['path'][rp['path'].rfind('/')+1:]
			rp['hostname'] = get_hostname(rl[1])
			rp['port'] = get_port(rl[1])
			if rp['hostname'] and rp['port']: 
				rp['server'] = rp['hostname'] + ':' + rp['port']
			if rp['hostname']:
				rp['domain'] = get_domain(rp['hostname'])
			rp['qsf'] = get_querystring(rl[1])
			rp['qs'] = get_querystring_parts(rp['qsf'])
			return rp
	return None

def parserespline(l):
	"""
	Parse the first line of the response and return a dict with relevant values

	@param l: status line string
	"""
	resp = {}
	sl = l.split(" ", 2) # XXX - what about other whitespace like tabs?
	if len(sl) == 3:
		# HTTP/1.0, HTTP/1.1 or later
		ver = sl[0].upper()
		if ver in ['HTTP/1.0', 'HTTP/1.1']:
			resp['version'] = ver
			resp['code'] = sl[1]
			resp['message'] = sl[2].strip()
			return resp
	return None

def parserequest(data, checks, t, pmd, urlfilter, hostfilter):
	"""
	Parse a request

	Needs a full request in the form of a string in data (request line, headers and body)
	"""
	try:
		if not data: return False
		reqbody = None
		log.info("parserequest: Trying %s" % t['id'])
		t['rawreq'] = data
		req = StringIO.StringIO(data)

		# Handle request line
		l = req.readline()
		rlinfo = parsereqline(l)
		if not rlinfo:
			log.warn("[x] Invalid HTTP request line (TID: %s)" % t['id'])
			return False
		t.update(rlinfo)

		# Filter stuff
		if t['hostname'].find(hostfilter) < 0:
			log.info("parserequest: Skipped %s (filtered - %s didn't contain %s)" % (t['id'], t['hostname'], hostfilter))
			return None
		else: 
			log.info("parserequest: Processing %s (hostname %s matched %s or null filter)" % (t['id'], t['hostname'], hostfilter))
		if t['url'].find(urlfilter) < 0:
			log.info("parserequest: Skipped %s (filtered - %s didn't contain %s)" % (t['id'], t['url'], urlfilter))
			return None
		else: 
			log.info("parserequest: Processing %s (url %s matched %s or null filter)" % (t['id'], t['url'], urlfilter))

		for qs in t['qs']:
			qst = qs.copy()
			qst['httpparams'] = t
			pmd.add_querystring(qst)

		for c in checks:
			c.rl_parse(l, t)

		# Handle request headers
		while l != '\r\n': # XXX - will webscarab ever just do \n?
			l = req.readline()
			if l == '':
				log.warn("parserequest: Skipped %s, headers didn't end" % t['id'])
				return None
			get_sentcookies(l, t, pmd)
			m = re.search(r"^Host:\s(.*)", l, re.IGNORECASE)
			if m: 
				t['host'] = m.group(1).strip()
				if not t['port']: t['port'] = '80'
				t['hostname'] = t['host']
				if 'server' not in t:
					t['server'] = t['hostname'] + ':' + t['port']
				if 'domain' not in t:
					t['domain'] = get_domain(t['hostname'])
				# XXX: only update server/hostname info if numeric

			for c in checks:
				c.req_hl_parse(l, t)

		# Handle body
		#       HTTP/1.0 only allows body content for POST and PUT
		#       HTTP/1.1 allows body for all methods
		# XXX - What does a body mean in 1.1 for GET/etc?
		reqbody = req.read()
		if(reqbody):
			if t['method'] == "POST":
				t['postparams'] = get_querystring_parts(reqbody)
				for pp in t['postparams']:
					ppt = pp.copy()
					ppt['httpparams'] = t
					pmd.add_postparam(ppt)

			for c in checks:
				c.req_body_parse(reqbody, t)

	except IOError, e:
		if e:
			if e.strerror == 'No such file or directory':
				log.warn('Skipping nonexistent transaction %s' % t['id'])
			else:
				log.info('parserequest: error processing TID %s, %s' % (t['id'], e.strerror))
		else:
			log.warn("parserequest: error processing TID %s" % (t['id']))
		return False
	return True

def parseresponse(data, checks, t, pmd):
	"""
	Parse a response

	Needs a full response in the form of a string in data (status line, headers and body)
	"""
	try:
		log.info("parseresponse: Trying " + t['id'])
		respbody = None
		gzipped = False
		deflated = False
		chunked = False
		resp = StringIO.StringIO(data)

		t['rawresp'] = data

		# Status line
		l = resp.readline()
		sl = parserespline(l)
		if not sl:
			log.warn("Invalid HTTP status line (Trans: %s)" % t['id'])
		t.update(sl)
		for c in checks:
			c.sl_parse(l, t)

		# Response headers
		while l != '\r\n':
			l = resp.readline()
			if l == '':
				log.warn("parseresponse: Skipped %s, headers didn't end" % t['id'])
				return None
			get_setcookie(l, t, pmd)
			m = re.search(r"^Content-Type:\s(.*)", l, re.IGNORECASE)
			if m: t['respcontenttype'] = m.group(1).strip()
			m = re.search(r"^Content-Length:\s(\d+)", l, re.IGNORECASE)
			if m: t['respcontentlen'] = int(m.group(1).strip())
			m = re.search(r"^Location:\s(.*)", l, re.IGNORECASE)
			if m: t['location'] = m.group(1).strip()
			for c in checks:
				c.resp_hl_parse(l, t)
			if l.lower().strip() == "content-encoding: gzip": gzipped = True
			if l.lower().strip() == "content-encoding: x-gzip": gzipped = True
			if l.lower().strip() == "content-encoding: deflate": deflated = True
			if l.lower().strip() == "transfer-encoding: chunked": chunked = True

		# Response body parsing
		if deflated or gzipped:
			s = resp.read()
			if not len(s): raise IOError
			if 'respcontentlen' in t:
				if len(s) != t['respcontentlen']:
					return False
					log.info("[x] parseresponse: Content-Length %d doesn't match data read %d" % (t['respcontentlen'], len(s)))
					#print '\tT: %s' % t
					#pdb.set_trace()
					# XXX: should give a hard error?
		if deflated: 
			# XXX - Tested, need to clean up entry in test suite
			try:
				df = StringIO.StringIO(zlib.decompress(s))
				respbody = df.read()
			except:
				try:
					df = StringIO.StringIO(zlib.decompress(s, -15))
					respbody = df.read()
				except:
					gzipped = True
		if gzipped and not t['url'].endswith('.gz'):
			try:
				if not chunked:
					gz = gzip.GzipFile('', 'rb', 9, StringIO.StringIO(s))
					respbody = gz.read()
				else:
					pass # XXX - handle chunked
			except: 
				raise IOError
		if not (deflated or gzipped):
			respbody = resp.read()

		if(respbody):
			for c in checks:
				log.info("parseresponse: respbody check %s" % c.__doc__)
				c.resp_body_parse(respbody, t)
			t['respbody'] = respbody

	except IOError:
		# XXX: should do something to mark t as bad?
		log.warn("[x] parseresponse: error proessing TID %s" % (t['id']))
		return False

	return True

if __name__ == '__main__':
	req1 = '''GET http://www.isecpartners.com:80/?foobar=secret1 HTTP/1.1
Host: www.isecpartners.com
User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.1) Gecko/20061204 Firefox/2.0.0.1
Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5
Accept-Language: en-us,en;q=0.5
Accept-Encoding: gzip,deflate
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7
Keep-Alive: 300
Proxy-Connection: keep-alive

'''

	req2 = '''GET / HTTP/1.0

'''

	req3 = None
	req4 = ''
	req5 = 'GET /'

	resp1 = '''HTTP/1.1 403 Forbidden
Date: Thu, 29 Mar 2007 20:43:51 GMT
Server: Apache
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<HTML><HEAD>
<TITLE>403 Forbidden</TITLE>
</HEAD><BODY>
<H1>Forbidden</H1>
You don't have permission to access /
on this server.<P>
</BODY></HTML>'''


	resp2 = '''HTTP/1.0 200 OK

asdf'''

	print chk_fmt(req1)
	print chk_fmt(req2)
	print chk_fmt(req3)
	print chk_fmt(req4)
	print chk_fmt(req5)
	print chk_fmt(resp1)
	print chk_fmt(resp2)
