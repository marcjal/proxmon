# URLTesting library
# Copyright (C) 2005-2007, Jesse Burns. See accompanying LICENSE for info
# Written by Jesse Burns <jesse@isecpartners.com>
# Additions by Jonathan Wilkins <jwilkins@isecpartners.com>
"""
Performs testing on urls to determine if they provide directory listings
or allow uploading of data with HTTP PUT and assorted support functions
"""
import urlparse, StringIO, os, sys, re, time, sha
import pycurl

DEBUG = False

# internal - create a curl object, with an associated output string,
# no interest in SSL certificate validity or following redirects and
# a 30 second timeout
def get_curl():
	curl = pycurl.Curl()
	output = StringIO.StringIO()
	curl.setopt(pycurl.COOKIEFILE, 'proxmon.cj')
	curl.setopt(pycurl.WRITEFUNCTION, output.write)
	curl.setopt(pycurl.SSL_VERIFYHOST, 0)
	curl.setopt(pycurl.SSL_VERIFYPEER, 0)
	curl.setopt(pycurl.TIMEOUT, 30)
	return (curl, output)

def url_exists(url):
	not_found = ['not found on this server', 'file not found']
	(c, b) = get_curl()
	c.setopt(pycurl.URL, url)
	try: c.perform()
	except: return False
	if 199 < c.getinfo(c.HTTP_CODE) < 300:
		# XXX - check it's not really a 404 by scanning body
		for x in not_found:
			if re.search(x, b.getvalue(), re.IGNORECASE):
				return False
		return True

def file_contains(url, string):
	(c, b) = get_curl()
	c.setopt(pycurl.URL, url)
	try: c.perform()
	except: return False
	if 199 < c.getinfo(c.HTTP_CODE) < 300:
		if re.search(string, b.getvalue(), re.IGNORECASE):
			return True
	return False

def allows_upload(url):
	filename = 'isec-tst.txt'
	filecontent = """Test File - if this file exists, the directory it is contained
in is writable, which may not be desirable.  It is suggested
that the administrator review the directory permissions."""

	if(url_exists(url + filename)): # add hashcode at end and retry
		filename += "." + sha.new(str(time.time())).hexdigest()

	(c, b) = get_curl()
	c.setopt(pycurl.URL, url + filename)
	c.setopt(pycurl.UPLOAD, 1)
	c.setopt(pycurl.READFUNCTION, StringIO.StringIO(filecontent).read)
	filesize = len(filecontent)
	c.setopt(pycurl.INFILESIZE, filesize)
	try: c.perform()
	except: return False
	if (c.getinfo(c.HTTP_CODE) > 199 and c.getinfo(c.HTTP_CODE) < 300):
		# download file to confirm upload actually worked
		(c, b) = get_curl()
		c.setopt(pycurl.URL, url+filename)
		try: c.perform()
		except: return False
		if b.getvalue() == filecontent: return True
		else: return False
	if (DEBUG):
		print c.getinfo(c.HTTP_CODE), url
	return False

# heuristically determines if the page resulting from accessing this
# url is actually a directory listing.
def gives_directory_listing(url):
	# these strings must be present for a page to be judged a directory listing
	dir_substrings = ['Index of ', 'Parent Directory', 'Last modified']
	# had included substring [DIR] but found it was not included in some mac web
	# server directory listings

	(c, b) = get_curl()
	c.setopt(pycurl.URL, url)
	try: c.perform()
	except: return False
	if (c.getinfo(c.HTTP_CODE) == 200):
		for x in dir_substrings:
			if (b.getvalue().find(x) >= 0): # required substring not found
				return True
	return False

if __name__ == '__main__':
	t = ['http://google.com/', 'http://tod.rutech.ru/Daemon/',
#		'http://www.microsoft.com/', 'http://www.yahoo.com',
#		'http://www.globeandmail.com', 'http://crl.thawte.com/',
#		'http://www.ucalgary.ca/~hclarke/', 'http://www.isecpartners.com/picts/',
#		'http://www.isecpartners.com/', 'https://www.isecpartners.com/',
#		'https://www.isecpartners.com/picts/', 'http://www.google.com/',
#		'http://www.cnn.com', 'http://hdf.ncsa.uiuc.edu/HDF5/doc/PSandPDF/',
		'http://www.google.com/nl/intl/_vti_bin',
		'http://www.umich.edu/~archive/mac/']

	print "Directory Listing Test"
	for url in t:
		print '\t' + url + ' returned ' + str(gives_directory_listing(url))
	print "HTTP PUT test"
	for url in ['http://scratch.bitland.net/put/', 'http://scratch.bitland.net/']:
		print '\t' + url + ' returned ' + str(allows_upload(url))
	print "Url exists"
	for url in t:
		print '\t' + url + ' returned ' + str(url_exists(url))
