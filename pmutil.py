# ProxMon - Monitors proxies to automate web application penetration tests
# Copyright (C) 2007, Jonathan Wilkins - See accompanying LICENSE for info
"""
Various utility functions used by both proxmon and modules
"""

import os, re, sys
import md5, sha, base64
import logging

trivial_values = ['', 'False', 'True', 'true', 'false',
					'yes', 'no', 'Yes', 'No', 'YES', 'NO',
					'en-us', 'en-US', 'en_US', 'en', 'us',
					'utf-8', 'UTF-8', 'firefox-a', '32-bit', '420', '1.5', 
					'640x480', '800x600', '1024x768', '1400x1050', '1600x1200',
					'640', '768', '800', '1024', '1050', '1200', '1400', '1600',
					'-', '/', '\\'
				 ]
trivial_values.extend(map(str, range(-101,101)))
trivial_values.extend(map(chr, range(ord('A'), ord('Z')+1)))
trivial_values.extend(map(chr, range(ord('a'), ord('z')+1)))

hashlengths = [16, 32, 20, 40, 24, 48, 32, 64] 
							   # 128 bit is 16 binary, 32 hex (MD5)
							   # 160 bit is 20 binary, 40 hex (SHA-1)
							   # 192 bit is 24 binary, 48 hex (TIGER)
							   # 256 bit is 32 binary, 64 hex (SHA-256)
nonhexchars = r"[^A-Fa-f\d]"   # regex

js_comment_rx =   [r"/\*[^*]*\*+([^/*][^*]*\*+)*/", # /* */
				   r"//[^\n]*\n"]                   # //
html_comment_rx = [r"\<!\s*--(.*?)(--\s*\>)"]       # HTML comment
comment_rx = js_comment_rx + html_comment_rx

log = logging.getLogger("proxmon")
vallog = logging.getLogger("pxmvalues")

def cmsg(msg, *args, **kwargs):
	logging.getLogger("proxmon").log(60, msg, *args, **kwargs)

def parse_set_cookie(header):
	"""Converts a Set-Cookie header into a dict of Path, Domain, name and value
	From Jesse's code, was originally named cookie_found

	@param header: String, not including the Set-Cookie: part"""
	cookie = {}

	parts = header.split(';')
	for part in parts:
		comp = part.split("=", 1)
		if (len(comp) == 2):
			k, v = comp
			if not 'name' in cookie:
				cookie['name'] = k.strip().lower() # case insensitive - RFC2965-s3.1
				cookie['value'] = v.strip()
			else:
				cookie[k.strip().lower()] = v.strip()
		else:
			if not 'name' in cookie:
				return None
			else:
				cookie[comp[0].strip().lower()] = True
	if not 'name' in cookie:
		return None
	else:
		return cookie

def parse_sent_cookies(header):
	"""Converts a Cookie: header into a list of cookie dicts with name,
	value and httpparams

	@param header: String, not including Cookie: part"""
	cookielist = []

	cookies = [c for c in header.strip().split(';') if c != '']
	for c in cookies:
		comp = c.split('=', 1)
		if len(comp) == 2:
			cookie = {}
			k, v = comp
			# cookie names are case insensitive - RFC2965 Section 3.1
			cookie["name"] = k.strip().lower()
			cookie["value"] = v.strip()
			cookielist.append(cookie)
		else:
			log.error("[x] parse_sent_cookie: cookie has >< 2 parts %s", c)
			return []
	return cookielist

def hashformat(s):
	if len(s) in hashlengths and not re.search(nonhexchars, s):
		return True

def md5sum(data):
	m = md5.new(data)
	return m.hexdigest()

def sha1sum(data):
	s = sha.new(data)
	return s.hexdigest()

# A series of base64 decodes to handle all of the weird variants commonly seen
# stock: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
#        padding: =
# variants sub +/ to !-. _-, ._, *! and pad with - or $ or have no padding
# relevant RFC's: 989, 2152, 2440, 4648
def b64d(s):
	d = base64.b64decode(s)
	e = base64.b64encode(d)
	vallog.debug("  Trying b64d: %s -> %s" % (s, e))
	if s == e: return d

def b64d_url(s):
	d = base64.b64decode(s, '-_')
	e = base64.b64encode(d, '-_')
	vallog.debug("  Trying b64d_url: %s -> %s" % (s, e))
	if s == e: return d

def b64d_regex(s):
	d = base64.b64decode(s, '!-')
	e = base64.b64encode(d, '!-')
	vallog.debug("  Trying b64d_regex: %s -> %s" % (s, e))
	if s == e: return d

def b64d_xml1(s):
	d = base64.b64decode(s, '_-')
	e = base64.b64encode(d, '_-')
	vallog.debug("  Trying b64d_xml1: %s -> %s" % (s, e))
	if s == e: return d

def b64d_xml2(s):
	d = base64.b64decode(s, '._')
	e = base64.b64encode(d, '._')
	vallog.debug("  Trying b64d_xml2: %s -> %s" % (s, e))
	if s == e: return d

def b64d_misc1(s):
	d = base64.b64decode(s, '*!')
	e = base64.b64encode(d, '*!')
	vallog.debug("  Trying b64d_misc1: %s -> %s" % (s, e))
	if s == e: return d
	if s[-1] == '=' and s[:-1] == e: return d
	if s[-2] == '=' and s[:-2] == e: return d

def b64normalize(s):
	f = r"([A-Za-z\d+/!\-_.*]{2,})([=$]*)" # regex, no %, use on unquoted
	if len(s) < 2:
		vallog.debug("b64n_skip: Too short")
		return
	m = re.search(f, s)
	if m: 
		if not len(m.group()) == len(s):
			vallog.debug(" b64n_skip: match != whole string %s" % s)
			return

		if len(m.group(2)) == 2:  # if there are two pad chars, they must match
			if not m.group(2)[0] == m.group(2)[1]:
				vallog.debug(" b64n_skip: two mismatched pad chars : %s" % s)
				return

		# get rid of short matches w/o pad since stuff like 'true' will decode
		if len(m.group()) < 13 and (len(m.group(2)) < 1 or m.group()[-1] != '-'):
			vallog.debug(" b64n_skip: short match w/ no pad (%s)", m.group())
			return

		vallog.debug(" key is b64 format (%s)" % s)
		# have to handle '-' padding separately since it's valid in non-pad
		if m.group(1)[-2] == '-':
			return m.group(1)[:-2] + '=='
		if m.group(1)[-1] == '-':
			return m.group(1)[:-1] + '='
		return m.group(1) + "=" * len(m.group(2))
	vallog.debug(" b64n_skip: regex not matched (%s)" % s)


def implied_dirs(p):
	"""
	Generate a list of directories implied by the path provided
	eg.  /foo/bar/baz/ gives /foo/, /foo/bar/, /foo/ and /

	@param p: The path
	"""
	# If http://foo.com/bar.html is a directory there will be
	# a redirect and the new path will include a trailing /
	results = []
	while(p.rfind('/') > 0):
		p = p[:p.rfind('/')]
		r = p
		if r[-1] != '/':
			r+='/'
		if r not in results:
			results.append(r)
	if '/' not in results:
		results.append('/')
	return results

def binary_response(t):
	"""
	Determine whether the specified transaction has a binary response
	by looking at the Content-Type and also the extension of the 
	returned file

	@param t: A transaction
	"""
	# XXX - add more here 
	try:
		if t['respcontenttype'] in ['application/x-javascript']:
			return False
		if t['respcontenttype'] in ['application/x-java-vm']:
			return True
		if t['respcontenttype'] in ['application/octet-stream']:
			return True
		ctype, subtype = t['respcontenttype'].split('/')
		if ctype in ['image']:
			return True
		if ctype in ['text']:
			return False
	except KeyError:
		pass

	ext = t['url'][t['url'].rfind('.')+1:]
	if ext.lower() in ['jar', 'zip', 'tar', 'gz', 'jpg', 'gif', 'png', 'swf']:
		return True

def sortuniq(l):
	"""
	Takes a list, and returns it after removing duplicates and sorting

	@param l: The list
	"""
	su = list(set(l))
	su.sort()
	return su

def cookies_by_name(sack):
	"Takes a dict of cookies and returns a new dict keyed by cookie name"
	result = {}
	for cookie in sack:
		name = cookie["name"]
		try: result[name].append(cookie)
		except: result[name] = [cookie]
	return result

def uniq_cookies(cookies):
	"Uniques the cookie dictionary"
	uc = {}
	for c in cookies:
		try: uc[c['name']] += 1
		except KeyError: uc[c['name']] = 1
	cn = uc.keys()
	cn.sort()
	return cn
