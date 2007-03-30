# ProxMon - Monitors proxies to automate web application penetration tests
# Copyright (C) 2007, Jonathan Wilkins - See accompanying LICENSE for info
"""
Various utility functions used by both proxmon and modules
"""

import os, re, sys

trivial_values = ['', 'False', 'True', 'true', 'false', 
					'en-us', 'en-US', 'en_US', 'en', 'us',
					'utf-8', 'UTF-8', 'firefox-a', '32-bit', '420', '1.5', 
					'640x480', '800x600', '1024x768', '1400x1050', '1600x1200',
					'640', '768', '800', '1024', '1050', '1200', '1400', '1600',
					'-', '/', '\\'
				 ]
trivial_values.extend(map(str, range(-1,101)))
trivial_values.extend(map(chr, range(ord('A'), ord('Z')+1)))
trivial_values.extend(map(chr, range(ord('a'), ord('z')+1)))

js_comment_rx =   [r"/\*[^*]*\*+([^/*][^*]*\*+)*/", # /* */
				   r"//[^\n]*\n"]                   # //
html_comment_rx = [r"\<!\s*--(.*?)(--\s*\>)"]       # HTML comment
comment_rx = js_comment_rx + html_comment_rx

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
			print "[x] parse_sent_cookie: cookie has >< 2 parts" 
			return []
	return cookielist

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
